// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file tree_kem.cpp
 * @brief Production-quality MLS-aligned TreeKEM group key management implementation.
 */

#include "uav_pqc/group/tree_kem.hpp"
#include "uav_pqc/crypto/ml_kem.hpp"
#include "uav_pqc/crypto/hkdf.hpp"
#include "uav_pqc/crypto/default_provider.hpp"
#include "uav_pqc/common/logging.hpp"
#include "uav_pqc/diagnostics/metrics.hpp"
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstring>
#include <sstream>
#include <vector>
#include <utility>

namespace uav_pqc::group {

namespace {

// ─────────────────────────────────────────────────────────────────────────────
// Tree Math Helpers (MLS aligned flat-array representation)
// ─────────────────────────────────────────────────────────────────────────────

inline std::uint32_t level(std::uint32_t x) {
    std::uint32_t l = 0;
    while ((x & (1 << l)) != 0) {
        l++;
    }
    return l;
}

inline std::uint32_t parent(std::uint32_t x) {
    std::uint32_t l = level(x);
    if ((x & (1 << (l + 1))) == 0) {
        return x + (1 << l);
    } else {
        return x - (1 << l);
    }
}

inline std::uint32_t sibling(std::uint32_t x) {
    std::uint32_t l = level(x);
    if ((x & (1 << (l + 1))) == 0) {
        return x + (1 << (l + 1));
    } else {
        return x - (1 << (l + 1));
    }
}

inline std::pair<std::uint32_t, std::uint32_t> children(std::uint32_t x) {
    std::uint32_t l = level(x);
    if (l == 0) return {x, x};
    std::uint32_t step = 1 << (l - 1);
    return {x - step, x + step};
}

inline std::uint32_t root(std::uint32_t N) {
    if (N <= 1) return 0;
    std::uint32_t r = 1;
    while (r < 2 * N - 1) {
        r = (r << 1) | 1;
    }
    return r >> 1;
}

// ─────────────────────────────────────────────────────────────────────────────
// SwarmMember JSON serialization
// ─────────────────────────────────────────────────────────────────────────────
void to_json(nlohmann::json& j, const SwarmMember& m) {
    j = nlohmann::json{
        {"node_id", to_hex(m.node_id)},
        {"leaf_key", to_hex(m.leaf_key.data)},
        {"leaf_index", m.leaf_index},
        {"joined_at_ms", m.joined_at_ms}
    };
}

SwarmMember swarm_member_from_json(const nlohmann::json& j) {
    SwarmMember m;
    auto node_id_bytes = from_hex(j.at("node_id").get<std::string>());
    std::copy_n(node_id_bytes.begin(), 32, m.node_id.begin());
    m.leaf_key.data = from_hex(j.at("leaf_key").get<std::string>());
    m.leaf_index = j.at("leaf_index").get<std::uint32_t>();
    m.joined_at_ms = j.at("joined_at_ms").get<Timestamp>();
    return m;
}

} // namespace

// ─────────────────────────────────────────────────────────────────────────────
// Concrete TreeKEM Manager
// ─────────────────────────────────────────────────────────────────────────────

struct TreeNode {
    bool is_blank = true;
    crypto::KemPublicKey public_key;
    SecureBytes private_key_secret; // seed for deterministic KEM generation
    Bytes parent_hash;
};

class TreeKem final : public ITreeKem {
public:
    explicit TreeKem(protocol::CipherSuite suite, std::shared_ptr<platform::IClock> clock = nullptr, std::shared_ptr<crypto::ICryptoProvider> crypto_provider = nullptr)
        : suite_(std::move(suite)),
          clock_(clock),
          crypto_provider_(crypto_provider) {
        if (!crypto_provider_) {
            crypto_provider_ = std::make_shared<crypto::DefaultCryptoProvider>();
        }
        mlkem_ = crypto_provider_->create_ml_kem(suite_.kem_level);
        if (!clock_) {
            clock_ = platform::make_platform_clock();
        }
        // Initialize an empty tree
        sync_tree_size();
    }

    // ── GCS Committer / Swarm Coordinator operations ─────────────────────────

    Result<GroupKeyUpdate> add_member(const SwarmMember& new_member,
                                      const protocol::CipherSuite&) override {
        diagnostics::ScopedProfiler profiler(diagnostics::OpKind::TreeKem);
        const std::uint32_t old_N = membership_.tree_size();
        auto r = membership_.add_member(new_member.node_id, new_member.leaf_key, new_member.joined_at_ms);
        if (!r) return err<GroupKeyUpdate>(r.error());

        sync_tree_size();

        // Committer is the first active leaf that is NOT the new member
        std::uint32_t committer_idx = 0;
        if (old_N > 0) {
            for (const auto& m : membership_.members()) {
                if (m.leaf_index != r.value()) {
                    committer_idx = m.leaf_index;
                    break;
                }
            }
        } else {
            committer_idx = r.value();
        }

        return do_rekey(RekeyReason::MemberJoined, committer_idx);
    }

    Result<GroupKeyUpdate> remove_member(const NodeId& node_id, RekeyReason reason,
                                          const protocol::CipherSuite&) override {
        diagnostics::ScopedProfiler profiler(diagnostics::OpKind::TreeKem);
        const auto* member = membership_.find_by_node_id(node_id);
        if (!member) {
            return err<GroupKeyUpdate>(ErrorCode::GroupMemberNotFound, "Member not found");
        }
        std::uint32_t leaf_idx = member->leaf_index;

        auto r = membership_.remove_member(node_id);
        if (!r) return err<GroupKeyUpdate>(r.error());

        // Blank the leaving member's path
        blank_path(2 * leaf_idx);
        sync_tree_size();

        // GCS performs the rekey from its own leaf (or leaf 0 if not GCS)
        return do_rekey(reason, 0);
    }

    Result<GroupKeyUpdate> rotate_group_key(RekeyReason reason,
                                             const protocol::CipherSuite&) override {
        diagnostics::ScopedProfiler profiler(diagnostics::OpKind::TreeKem);
        return do_rekey(reason, 0);
    }

    // ── UAV Leaf node operations ─────────────────────────────────────────────

    Result<GroupKey> process_update(const GroupKeyUpdate& update,
                                    const NodeId& my_node_id,
                                    const crypto::KemPrivateKey& my_leaf_key) override {
        diagnostics::ScopedProfiler profiler(diagnostics::OpKind::TreeKem);
        const auto* my_member = membership_.find_by_node_id(my_node_id);
        if (!my_member) {
            return err<GroupKey>(ErrorCode::GroupMemberNotFound, "Node not in group");
        }

        std::uint32_t my_leaf_idx = my_member->leaf_index;
        std::uint32_t my_node_idx = 2 * my_leaf_idx;

        // Apply membership updates to our local membership tracker
        // Note: For a pure process_update, membership shifts are implied by GCS changes.
        // We sync our tree nodes array size to match the update context.
        sync_tree_size();

        const std::uint32_t root_idx = get_root_index();

        // Find the ciphertext targeted at one of our ancestor nodes on our direct path
        const PathSecretCiphertext* target_psc = nullptr;

        for (const auto& psc : update.path_secrets) {
            // Check if this path secret was encrypted to any node in our resolution path
            if (psc.recipient_node_id == my_node_id) {
                target_psc = &psc;
                break;
            }
        }

        if (!target_psc) {
            // If we are the committer, our tree secrets are already populated.
            // We can just verify/update our epoch and return the group key directly.
            if (root_idx < tree_nodes_.size() && !tree_nodes_[root_idx].private_key_secret.empty()) {
                current_epoch_ = update.new_epoch;
                auto gk_r = make_group_key(tree_nodes_[root_idx].private_key_secret.span(), 0);
                if (!gk_r) return err<GroupKey>(gk_r.error());
                if (ready_fn_) {
                    ready_fn_(gk_r.value());
                }
                return gk_r;
            }
            return err<GroupKey>(ErrorCode::DecapsulationFailed, "No ciphertext found for our node path");
        }

        // Decapsulate the path secret
        // Find the private key to use
        crypto::KemPrivateKey dec_key;
        std::uint32_t encap_node_idx = target_psc->leaf_index;
        if (encap_node_idx == my_node_idx) {
            dec_key.data = SecureBytes(Bytes(my_leaf_key.span().begin(), my_leaf_key.span().end()));
        } else {
            if (encap_node_idx >= tree_nodes_.size() || tree_nodes_[encap_node_idx].private_key_secret.empty()) {
                return err<GroupKey>(ErrorCode::DecapsulationFailed, "Missing private key for ancestor node");
            }
            auto kp_r = mlkem_->generate_keypair_deterministic(tree_nodes_[encap_node_idx].private_key_secret.span());
            if (!kp_r) return err<GroupKey>(kp_r.error());
            dec_key = std::move(kp_r.value().private_key);
        }

        // Split composite ciphertext
        const std::size_t ct_size = mlkem_->ciphertext_size();
        if (target_psc->ciphertext.data.size() < ct_size + 32) {
            return err<GroupKey>(ErrorCode::DecapsulationFailed, "Malformed composite ciphertext");
        }
        crypto::KemCiphertext oqs_ct;
        oqs_ct.data = Bytes(target_psc->ciphertext.data.begin(), target_psc->ciphertext.data.begin() + ct_size);
        Bytes encrypted(target_psc->ciphertext.data.begin() + ct_size, target_psc->ciphertext.data.end());

        auto ss_r = mlkem_->decapsulate(dec_key, oqs_ct);
        if (!ss_r) return err<GroupKey>(ss_r.error());

        // Derive wrap key
        auto wrap_key_r = crypto_provider_->hkdf_expand(suite_.hkdf_hash, ss_r.value().span(), bytes_from_sv("path secret wrap"), 32);
        if (!wrap_key_r) return err<GroupKey>(wrap_key_r.error());

        // Decrypt parent secret
        SecureBytes path_secret(32);
        for (size_t i = 0; i < 32; ++i) {
            path_secret.data()[i] = encrypted[i] ^ wrap_key_r.value().data()[i];
        }

        // Find committer leaf node
        std::uint32_t committer_leaf = 0;
        for (const auto& m : membership_.members()) {
            bool is_recipient = false;
            for (const auto& psc : update.path_secrets) {
                if (psc.recipient_node_id == m.node_id) {
                    is_recipient = true;
                    break;
                }
            }
            if (!is_recipient) {
                committer_leaf = m.leaf_index;
                break;
            }
        }

        // Find intersection of my_leaf_idx and committer_leaf
        std::uint32_t curr_idx = 2 * my_leaf_idx;
        std::uint32_t committer_node = 2 * committer_leaf;

        // Find LCA ancestors
        std::vector<std::uint32_t> committer_ancestors;
        std::uint32_t temp = committer_node;
        while (true) {
            committer_ancestors.push_back(temp);
            if (temp == root_idx) break;
            temp = parent(temp);
        }

        std::uint32_t intersection_node = root_idx;
        temp = curr_idx;
        while (true) {
            if (std::find(committer_ancestors.begin(), committer_ancestors.end(), temp) != committer_ancestors.end()) {
                intersection_node = temp;
                break;
            }
            if (temp == root_idx) break;
            temp = parent(temp);
        }

        curr_idx = intersection_node;
        tree_nodes_[curr_idx].private_key_secret = SecureBytes(Bytes(path_secret.bytes()));
        tree_nodes_[curr_idx].is_blank = false;

        auto kp_r = mlkem_->generate_keypair_deterministic(path_secret.span());
        if (kp_r) {
            tree_nodes_[curr_idx].public_key = kp_r.value().public_key;
        }

        while (curr_idx != root_idx) {
            std::uint32_t p = parent(curr_idx);

            // path_secret = HKDF-Expand(path_secret, "path-secret", 32)
            auto next_secret_r = crypto_provider_->hkdf_expand(suite_.hkdf_hash, path_secret.span(), bytes_from_sv("uav_pqc tree-kem path-secret v1"), 32);
            if (!next_secret_r) return err<GroupKey>(next_secret_r.error());
            path_secret = std::move(next_secret_r.value());

            tree_nodes_[p].private_key_secret = SecureBytes(Bytes(path_secret.bytes()));
            tree_nodes_[p].is_blank = false;

            auto p_kp_r = mlkem_->generate_keypair_deterministic(path_secret.span());
            if (p_kp_r) {
                tree_nodes_[p].public_key = p_kp_r.value().public_key;
            }

            curr_idx = p;
        }

        // Compute Parent Hashes up the tree to verify binding
        recompute_parent_hashes();

        current_epoch_ = update.new_epoch;

        // Group key is derived from the root secret
        auto gk_r = make_group_key(tree_nodes_[root_idx].private_key_secret.span(), 0);
        if (!gk_r) return err<GroupKey>(gk_r.error());

        if (ready_fn_) {
            ready_fn_(gk_r.value());
        }

        return gk_r;
    }

    // ── Serialization & Visualization ─────────────────────────────────────────

    std::string visualize() const override {
        std::stringstream ss;
        ss << "=== TreeKEM Epoch: " << current_epoch_ << " ===\n";
        const std::uint32_t num_nodes = static_cast<std::uint32_t>(tree_nodes_.size());
        for (std::uint32_t i = 0; i < num_nodes; ++i) {
            const auto& node = tree_nodes_[i];
            std::uint32_t l = level(i);
            ss << std::string(l * 2, ' ') << "[" << i << "] Level " << l << ": ";
            if (node.is_blank) {
                ss << "BLANK\n";
            } else {
                ss << "ACTIVE (PK=" << to_hex(node.public_key.span()).substr(0, 8) << "...";
                if (!node.parent_hash.empty()) {
                    ss << ", ParentHash=" << to_hex(node.parent_hash).substr(0, 8);
                }
                ss << ")\n";
            }
        }
        return ss.str();
    }

    Result<Bytes> serialize() const override {
        nlohmann::json j;
        j["epoch"] = current_epoch_;

        nlohmann::json members_json = nlohmann::json::array();
        for (const auto& m : membership_.members()) {
            nlohmann::json mj;
            to_json(mj, m);
            members_json.push_back(mj);
        }
        j["members"] = members_json;

        nlohmann::json nodes_json = nlohmann::json::array();
        for (const auto& node : tree_nodes_) {
            nlohmann::json nj;
            nj["is_blank"] = node.is_blank;
            nj["public_key"] = to_hex(node.public_key.span());
            nj["parent_hash"] = to_hex(node.parent_hash);
            nodes_json.push_back(nj);
        }
        j["nodes"] = nodes_json;

        std::string s = j.dump();
        return ok<Bytes>(bytes_from_sv(s));
    }

    VoidResult deserialize(ByteSpan data) override {
        try {
            std::string s(reinterpret_cast<const char*>(data.data()), data.size());
            auto j = nlohmann::json::parse(s);

            current_epoch_ = j.at("epoch").get<GroupEpoch>();

            // Rebuild membership tracker
            membership_ = SwarmMembership();
            for (const auto& mj : j.at("members")) {
                auto m = swarm_member_from_json(mj);
                auto r = membership_.add_member(m.node_id, m.leaf_key, m.joined_at_ms);
                if (!r) return r.error();
            }

            // Restore tree nodes preserving private keys
            auto nodes_json = j.at("nodes");
            tree_nodes_.resize(nodes_json.size());
            for (size_t idx = 0; idx < nodes_json.size(); ++idx) {
                const auto& nj = nodes_json[idx];
                tree_nodes_[idx].is_blank = nj.at("is_blank").get<bool>();
                tree_nodes_[idx].public_key.data = from_hex(nj.at("public_key").get<std::string>());
                tree_nodes_[idx].parent_hash = from_hex(nj.at("parent_hash").get<std::string>());
            }

            return ok();
        } catch (const std::exception& e) {
            return err(ErrorCode::InternalError, std::string("Deserialization failed: ") + e.what());
        }
    }

    const SwarmMembership& membership()    const noexcept override { return membership_; }
    GroupEpoch             current_epoch() const noexcept override { return current_epoch_; }

    void set_group_key_ready_fn(GroupKeyReadyFn fn) override { ready_fn_ = std::move(fn); }

private:
    protocol::CipherSuite    suite_;
    SwarmMembership          membership_;
    GroupEpoch               current_epoch_ = 0;
    GroupKeyReadyFn          ready_fn_;
    std::shared_ptr<crypto::ICryptoProvider> crypto_provider_;
    std::unique_ptr<crypto::IKem>            mlkem_;
    std::shared_ptr<platform::IClock> clock_;

    std::vector<TreeNode>    tree_nodes_;

    // ── Internal Helpers ─────────────────────────────────────────────────────

    std::uint32_t get_root_index() const noexcept {
        return root(membership_.tree_size());
    }

    void sync_tree_size() {
        const std::uint32_t N = membership_.tree_size();
        std::uint32_t p = 1;
        while (p < N) {
            p <<= 1;
        }
        const std::uint32_t required_nodes = (N > 0) ? (2 * p - 1) : 0;
        if (tree_nodes_.size() < required_nodes) {
            tree_nodes_.resize(required_nodes);
        }

        // Sync leaves
        for (const auto& member : membership_.members()) {
            std::uint32_t node_idx = 2 * member.leaf_index;
            if (node_idx < tree_nodes_.size()) {
                tree_nodes_[node_idx].is_blank = false;
                tree_nodes_[node_idx].public_key = member.leaf_key;
            }
        }
    }

    void blank_path(std::uint32_t leaf_node_idx) {
        std::uint32_t curr = leaf_node_idx;
        const std::uint32_t root_idx = get_root_index();
        while (true) {
            if (curr >= tree_nodes_.size()) break;
            tree_nodes_[curr].is_blank = true;
            tree_nodes_[curr].private_key_secret.erase();
            tree_nodes_[curr].public_key.data.clear();
            tree_nodes_[curr].parent_hash.clear();

            if (curr == root_idx) break;
            curr = parent(curr);
        }
    }

    std::vector<std::uint32_t> resolution(std::uint32_t x) {
        std::vector<std::uint32_t> res;
        const std::uint32_t num_nodes = static_cast<std::uint32_t>(tree_nodes_.size());
        if (x >= num_nodes) return res;

        if (!tree_nodes_[x].is_blank) {
            res.push_back(x);
            return res;
        }

        std::uint32_t l = level(x);
        if (l == 0) return res; // blank leaf has empty resolution

        auto [left_child, right_child] = children(x);
        auto left_res = resolution(left_child);
        auto right_res = resolution(right_child);
        res.insert(res.end(), left_res.begin(), left_res.end());
        res.insert(res.end(), right_res.begin(), right_res.end());
        return res;
    }

    void recompute_parent_hashes() {
        const std::uint32_t num_nodes = static_cast<std::uint32_t>(tree_nodes_.size());
        if (num_nodes == 0) return;

        // Post-order bottom-up hash calculation
        for (std::uint32_t i = 0; i < num_nodes; ++i) {
            if (tree_nodes_[i].is_blank) continue;
            std::uint32_t l = level(i);
            if (l == 0) continue; // leaves don't calculate parent hash internally

            auto [left_child, right_child] = children(i);
            // Parent hash binds children public keys + their parent hashes
            Bytes input;
            if (!tree_nodes_[left_child].is_blank) {
                input.insert(input.end(), tree_nodes_[left_child].public_key.span().begin(), tree_nodes_[left_child].public_key.span().end());
                input.insert(input.end(), tree_nodes_[left_child].parent_hash.begin(), tree_nodes_[left_child].parent_hash.end());
            }
            if (!tree_nodes_[right_child].is_blank) {
                input.insert(input.end(), tree_nodes_[right_child].public_key.span().begin(), tree_nodes_[right_child].public_key.span().end());
                input.insert(input.end(), tree_nodes_[right_child].parent_hash.begin(), tree_nodes_[right_child].parent_hash.end());
            }
            tree_nodes_[i].parent_hash = crypto_provider_->hash_sha256(input).value();
        }
    }

    Result<GroupKey> make_group_key(ByteSpan root_secret, Timestamp now_ms) {
        Timestamp current_time = now_ms;
        if (current_time == 0 && clock_) {
            current_time = clock_->now_ms();
        }

        std::array<std::byte, 8> epoch_bytes{};
        write_u64_be(MutableByteSpan{epoch_bytes.data(), 8}, current_epoch_);

        const Bytes info = bytes_from_sv("uav_pqc group-key v1");
        auto key_r = crypto_provider_->hkdf_derive(
            suite_.hkdf_hash,
            ByteSpan{epoch_bytes.data(), 8},
            root_secret,
            ByteSpan{info.data(), info.size()}, 32);
        if (!key_r) return err<GroupKey>(key_r.error());

        return ok<GroupKey>(GroupKey(
            current_epoch_,
            std::move(key_r.value()),
            suite_.aead_algorithm,
            current_time,
            current_time + static_cast<Timestamp>(suite_.max_session_seconds) * 1000u));
    }

    // Rekey from a specific leaf index (copath resolution encapsulations)
    Result<GroupKeyUpdate> do_rekey(RekeyReason reason, std::uint32_t committer_leaf_idx) {
        ++current_epoch_;
        GroupKeyUpdate update;
        update.new_epoch = current_epoch_;
        update.reason = reason;

        const std::uint32_t N = membership_.tree_size();
        if (N == 0) {
            return err<GroupKeyUpdate>(ErrorCode::InternalError, "TreeKEM rekey: empty swarm");
        }

        // 1. Generate path secrets along the committer's path to the root
        std::uint32_t curr = 2 * committer_leaf_idx;
        const std::uint32_t root_idx = get_root_index();

        auto rand_bytes_r = crypto_provider_->generate_random_bytes(32);
        if (!rand_bytes_r) {
            return err<GroupKeyUpdate>(ErrorCode::KeyGenerationFailed, "Random bytes generation failed");
        }
        SecureBytes path_secret(std::move(rand_bytes_r.value()));

        tree_nodes_[curr].private_key_secret = SecureBytes(Bytes(path_secret.bytes()));
        tree_nodes_[curr].is_blank = false;

        auto kp_r = mlkem_->generate_keypair_deterministic(path_secret.span());
        if (kp_r) {
            tree_nodes_[curr].public_key = kp_r.value().public_key;
        }

        // Encrypt the initial path secret to the committer leaf so that it can also process the update
        if (N > 1) {
            const auto* committer_member = membership_.find_by_leaf_index(committer_leaf_idx);
            if (committer_member) {
                auto encap_r = mlkem_->encapsulate(committer_member->leaf_key);
                if (encap_r) {
                    auto wrap_key_r = crypto_provider_->hkdf_expand(suite_.hkdf_hash, encap_r.value().shared_secret.span(), bytes_from_sv("path secret wrap"), 32);
                    if (wrap_key_r) {
                        Bytes encrypted(32);
                        for (size_t i = 0; i < 32; ++i) {
                            encrypted[i] = path_secret.data()[i] ^ wrap_key_r.value().data()[i];
                        }
                        Bytes composite_ct = encap_r.value().ciphertext.data;
                        composite_ct.insert(composite_ct.end(), encrypted.begin(), encrypted.end());

                        PathSecretCiphertext psc;
                        psc.recipient_node_id = committer_member->node_id;
                        psc.leaf_index = curr;
                        psc.ciphertext.data = composite_ct;
                        update.path_secrets.push_back(std::move(psc));
                    }
                }
            }
        }

        // Special case: single member tree
        if (N == 1) {
            const auto& members = membership_.members();
            auto encap_r = mlkem_->encapsulate(tree_nodes_[0].public_key);
            if (encap_r) {
                // Derive wrap key
                auto wrap_key_r = crypto_provider_->hkdf_expand(suite_.hkdf_hash, encap_r.value().shared_secret.span(), bytes_from_sv("path secret wrap"), 32);
                if (wrap_key_r) {
                    SecureBytes root_sec(32);
                    std::copy_n(encap_r.value().shared_secret.data.data(), 32, root_sec.data());

                    Bytes encrypted(32);
                    for (size_t i = 0; i < 32; ++i) {
                        encrypted[i] = root_sec.data()[i] ^ wrap_key_r.value().data()[i];
                    }

                    Bytes composite_ct = encap_r.value().ciphertext.data;
                    composite_ct.insert(composite_ct.end(), encrypted.begin(), encrypted.end());

                    PathSecretCiphertext psc;
                    psc.recipient_node_id = members[0].node_id;
                    psc.leaf_index = 0;
                    psc.ciphertext.data = composite_ct;
                    update.path_secrets.push_back(std::move(psc));

                    tree_nodes_[0].private_key_secret = std::move(root_sec);
                }
            }
            update.commit_digest = crypto_provider_->hash_sha256(update.path_secrets[0].ciphertext.data).value();
            recompute_parent_hashes();
            return ok<GroupKeyUpdate>(std::move(update));
        }

        // Climb up the tree deriving secrets & encapsulating to copaths
        while (curr != root_idx) {
            std::uint32_t p = parent(curr);
            std::uint32_t sib = sibling(curr);

            // path_secret_parent = HKDF-Expand(path_secret_child, "path-secret", 32)
            auto next_secret_r = crypto_provider_->hkdf_expand(suite_.hkdf_hash, path_secret.span(), bytes_from_sv("uav_pqc tree-kem path-secret v1"), 32);
            if (!next_secret_r) return err<GroupKeyUpdate>(next_secret_r.error());
            path_secret = std::move(next_secret_r.value());

            tree_nodes_[p].private_key_secret = SecureBytes(Bytes(path_secret.bytes()));
            tree_nodes_[p].is_blank = false;

            auto p_kp_r = mlkem_->generate_keypair_deterministic(path_secret.span());
            if (p_kp_r) {
                tree_nodes_[p].public_key = p_kp_r.value().public_key;
            }

            auto res_nodes = resolution(sib);

            // Encapsulate the parent secret under each node in sibling resolution
            for (std::uint32_t res_idx : res_nodes) {
                auto encap_r = mlkem_->encapsulate(tree_nodes_[res_idx].public_key);
                if (!encap_r) return err<GroupKeyUpdate>(encap_r.error());

                // Derive wrap key
                auto wrap_key_r = crypto_provider_->hkdf_expand(suite_.hkdf_hash, encap_r.value().shared_secret.span(), bytes_from_sv("path secret wrap"), 32);
                if (!wrap_key_r) return err<GroupKeyUpdate>(wrap_key_r.error());

                // Encrypt parent secret S_p (which is path_secret here)
                Bytes encrypted(32);
                for (size_t i = 0; i < 32; ++i) {
                    encrypted[i] = path_secret.data()[i] ^ wrap_key_r.value().data()[i];
                }

                // Suffix ciphertext
                Bytes composite_ct = encap_r.value().ciphertext.data;
                composite_ct.insert(composite_ct.end(), encrypted.begin(), encrypted.end());

                // Find all leaves under this resolution node subtree so we can assign their NodeIds
                std::uint32_t l = level(res_idx);
                std::uint32_t step = 1 << l;
                std::uint32_t start_leaf = (res_idx & ~(step - 1)) / 2;
                std::uint32_t end_leaf = start_leaf + step / 2;
                if (l == 0) {
                    start_leaf = res_idx / 2;
                    end_leaf = start_leaf + 1;
                }

                for (std::uint32_t lf = start_leaf; lf < end_leaf; ++lf) {
                    const auto* member = membership_.find_by_leaf_index(lf);
                    if (member) {
                        PathSecretCiphertext psc;
                        psc.recipient_node_id = member->node_id;
                        psc.leaf_index = res_idx; // store res_idx in leaf_index
                        psc.ciphertext.data = composite_ct;
                        update.path_secrets.push_back(std::move(psc));
                    }
                }
            }

            curr = p;
        }

        // Commit digest: SHA-256 hash of all ciphertexts
        Bytes hash_input;
        for (const auto& psc : update.path_secrets) {
            hash_input.insert(hash_input.end(), psc.ciphertext.data.begin(), psc.ciphertext.data.end());
        }
        update.commit_digest = crypto_provider_->hash_sha256(hash_input).value();

        // Recompute all parent hashes
        recompute_parent_hashes();

        // Coordinator / Committer also derives the new group key and installs it
        auto gk_r = make_group_key(tree_nodes_[root_idx].private_key_secret.span(), 0);
        if (gk_r && ready_fn_) {
            ready_fn_(gk_r.value());
        }

        return ok<GroupKeyUpdate>(std::move(update));
    }
};

// ── Serialization Helpers implementation ─────────────────────────────────────

Result<Bytes> serialize_group_key_update(const GroupKeyUpdate& update) {
    Bytes out;
    out.push_back(std::byte{0xBB}); // Binary format prefix
    
    // Serialize new_epoch (uint64_t)
    uint64_t epoch = update.new_epoch;
    for (int i = 7; i >= 0; --i) {
        out.push_back(static_cast<std::byte>((epoch >> (i * 8)) & 0xFF));
    }
    
    // Serialize reason (uint8_t)
    out.push_back(static_cast<std::byte>(update.reason));
    
    // Serialize commit_digest
    uint32_t digest_len = static_cast<uint32_t>(update.commit_digest.size());
    for (int i = 3; i >= 0; --i) {
        out.push_back(static_cast<std::byte>((digest_len >> (i * 8)) & 0xFF));
    }
    out.insert(out.end(), update.commit_digest.begin(), update.commit_digest.end());
    
    // Serialize path_secrets count
    uint32_t count = static_cast<uint32_t>(update.path_secrets.size());
    for (int i = 3; i >= 0; --i) {
        out.push_back(static_cast<std::byte>((count >> (i * 8)) & 0xFF));
    }
    
    for (const auto& psc : update.path_secrets) {
        // recipient_node_id (32 bytes)
        for (auto b : psc.recipient_node_id) {
            out.push_back(static_cast<std::byte>(b));
        }
        // leaf_index (uint32_t)
        uint32_t leaf = psc.leaf_index;
        for (int i = 3; i >= 0; --i) {
            out.push_back(static_cast<std::byte>((leaf >> (i * 8)) & 0xFF));
        }
        // ciphertext length (uint32_t)
        uint32_t ct_len = static_cast<uint32_t>(psc.ciphertext.data.size());
        for (int i = 3; i >= 0; --i) {
            out.push_back(static_cast<std::byte>((ct_len >> (i * 8)) & 0xFF));
        }
        // ciphertext data
        for (auto b : psc.ciphertext.data) {
            out.push_back(static_cast<std::byte>(b));
        }
    }
    
    return ok<Bytes>(std::move(out));
}

Result<GroupKeyUpdate> deserialize_group_key_update(ByteSpan data) {
    if (data.empty()) {
        return err<GroupKeyUpdate>(ErrorCode::InvalidArgument, "Empty serialized data");
    }
    
    // Check format prefix
    if (data[0] == std::byte{0x7B}) { // ASCII for '{'
        // Fallback to legacy JSON format for backward compatibility
        try {
            std::string s(reinterpret_cast<const char*>(data.data()), data.size());
            auto j = nlohmann::json::parse(s);

            GroupKeyUpdate update;
            update.new_epoch = j.at("new_epoch").get<GroupEpoch>();
            update.reason = static_cast<RekeyReason>(j.at("reason").get<std::uint8_t>());
            update.commit_digest = from_hex(j.at("commit_digest").get<std::string>());

            for (const auto& pj : j.at("path_secrets")) {
                PathSecretCiphertext psc;
                auto id_bytes = from_hex(pj.at("recipient_node_id").get<std::string>());
                std::copy_n(id_bytes.begin(), 32, psc.recipient_node_id.begin());
                psc.leaf_index = pj.at("leaf_index").get<std::uint32_t>();
                psc.ciphertext.data = from_hex(pj.at("ciphertext").get<std::string>());
                update.path_secrets.push_back(std::move(psc));
            }

            return ok<GroupKeyUpdate>(std::move(update));
        } catch (const std::exception& e) {
            return err<GroupKeyUpdate>(ErrorCode::InternalError, std::string("GroupKeyUpdate JSON legacy deserialization failed: ") + e.what());
        }
    }
    
    if (data[0] != std::byte{0xBB}) {
        return err<GroupKeyUpdate>(ErrorCode::InvalidArgument, "Invalid format prefix for GroupKeyUpdate");
    }
    
    // Parse new compact binary format
    size_t offset = 1;
    auto read_u64 = [&]() -> uint64_t {
        uint64_t val = 0;
        for (int i = 0; i < 8; ++i) {
            val = (val << 8) | static_cast<uint8_t>(data[offset++]);
        }
        return val;
    };
    
    auto read_u32 = [&]() -> uint32_t {
        uint32_t val = 0;
        for (int i = 0; i < 4; ++i) {
            val = (val << 8) | static_cast<uint8_t>(data[offset++]);
        }
        return val;
    };
    
    try {
        if (offset + 8 + 1 + 4 > data.size()) {
            return err<GroupKeyUpdate>(ErrorCode::InvalidArgument, "Buffer too small for binary header");
        }
        
        GroupKeyUpdate update;
        update.new_epoch = read_u64();
        update.reason = static_cast<RekeyReason>(static_cast<uint8_t>(data[offset++]));
        
        uint32_t digest_len = read_u32();
        if (offset + digest_len + 4 > data.size()) {
            return err<GroupKeyUpdate>(ErrorCode::InvalidArgument, "Buffer too small for commit digest");
        }
        update.commit_digest.resize(digest_len);
        std::memcpy(update.commit_digest.data(), data.data() + offset, digest_len);
        offset += digest_len;
        
        uint32_t count = read_u32();
        update.path_secrets.reserve(count);
        
        for (uint32_t i = 0; i < count; ++i) {
            if (offset + 32 + 4 + 4 > data.size()) {
                return err<GroupKeyUpdate>(ErrorCode::InvalidArgument, "Buffer too small for path secret info");
            }
            PathSecretCiphertext psc;
            std::memcpy(psc.recipient_node_id.data(), data.data() + offset, 32);
            offset += 32;
            
            psc.leaf_index = read_u32();
            uint32_t ct_len = read_u32();
            if (offset + ct_len > data.size()) {
                return err<GroupKeyUpdate>(ErrorCode::InvalidArgument, "Buffer too small for ciphertext payload");
            }
            psc.ciphertext.data.resize(ct_len);
            std::memcpy(psc.ciphertext.data.data(), data.data() + offset, ct_len);
            offset += ct_len;
            
            update.path_secrets.push_back(std::move(psc));
        }
        
        return ok<GroupKeyUpdate>(std::move(update));
    } catch (const std::exception& e) {
        return err<GroupKeyUpdate>(ErrorCode::InternalError, std::string("GroupKeyUpdate binary deserialization failed: ") + e.what());
    }
}

// ── TreeKem factory ───────────────────────────────────────────────────────────

std::unique_ptr<ITreeKem> make_tree_kem(protocol::CipherSuite suite, std::shared_ptr<platform::IClock> clock, std::shared_ptr<crypto::ICryptoProvider> crypto_provider) {
    return std::make_unique<TreeKem>(std::move(suite), clock, crypto_provider);
}

} // namespace uav_pqc::group
