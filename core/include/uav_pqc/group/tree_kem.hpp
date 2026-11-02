// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file tree_kem.hpp
 * @brief TreeKEM group key management interface.
 *
 * TreeKEM is a binary tree-based group key agreement protocol from the IETF
 * Messaging Layer Security (MLS) standard.  This implementation instantiates
 * the path secret operations with ML-KEM-derived symmetric keys, reducing
 * rekey overhead from O(N) to O(log N) for an N-member swarm.
 *
 * Architecture roles:
 *  - GCS: Acts as the group controller (TreeKEM "Committer").  Handles
 *    Join/Remove operations and distributes encrypted path secrets.
 *  - UAV: Leaf node.  Decapsulates its path secrets, derives the group key,
 *    and uses it for broadcast encryption/decryption.
 *
 * For single-drone missions, the TreeKEM layer is bypassed entirely;
 * the pairwise session key is used for all traffic.
 *
 * The interface is abstract so the protocol layer can inject a mock for
 * testing and the ns-3 simulation can substitute a simplified version.
 *
 * Rekeying triggers (per architecture spec):
 *  - Mission timer expiry
 *  - Member join
 *  - Member leave / compromise
 *  - Profile change
 *  - GCS handover
 */

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"
#include "uav_pqc/crypto/kem.hpp"
#include "uav_pqc/group/group_key.hpp"
#include "uav_pqc/group/membership.hpp"
#include "uav_pqc/protocol/suite.hpp"
#include "uav_pqc/platform/clock.hpp"

#include <functional>
#include <memory>
#include <vector>

namespace uav_pqc::group {

/**
 * @brief Reason code for a rekey event.  Used in GroupKeyUpdate messages.
 */
enum class RekeyReason : std::uint8_t {
    MemberJoined    = 0x01,
    MemberLeft      = 0x02,
    MemberRevoked   = 0x03,
    ProfileChanged  = 0x04,
    TimerExpired    = 0x05,
    GcsHandover     = 0x06,
    ManualRotation  = 0x07,
};

/**
 * @brief Encrypted path-secret update for a single leaf node.
 *
 * Produced by the GCS for each leaf on the updated path.  The recipient
 * decapsulates its entry using its leaf private key to obtain the path secret.
 */
struct PathSecretCiphertext {
    NodeId             recipient_node_id; ///< Target leaf node
    std::uint32_t      leaf_index;        ///< Position in the tree
    crypto::KemCiphertext ciphertext;     ///< ML-KEM ciphertext of the path secret
};

/**
 * @brief A complete group key update package (GCS → all affected nodes).
 *
 * Sent as a GroupKeyUpdate message.  Each recipient finds its entry by
 * NodeId, decapsulates the path secret, re-derives its parent node secrets
 * up to the root, and then derives the new group key from the root secret.
 */
struct GroupKeyUpdate {
    GroupEpoch                         new_epoch;
    RekeyReason                        reason;
    std::vector<PathSecretCiphertext>  path_secrets; ///< One per affected leaf
    Bytes                              commit_digest; ///< SHA-256 of all path secrets
};

/**
 * @brief Abstract TreeKEM interface.
 */
class ITreeKem {
public:
    /// Callback fired on the local node when a new group key becomes active.
    using GroupKeyReadyFn = std::function<void(const GroupKey& key)>;

    ITreeKem()                                 = default;
    ITreeKem(const ITreeKem&)                  = delete;
    ITreeKem& operator=(const ITreeKem&)       = delete;
    ITreeKem(ITreeKem&&) noexcept              = default;
    ITreeKem& operator=(ITreeKem&&) noexcept   = default;
    virtual ~ITreeKem()                         = default;

    // ── GCS-side (Committer) operations ───────────────────────────────────────

    /**
     * @brief Add a new leaf to the tree after a member joins.
     *
     * Generates O(log N) path-secret ciphertexts for all affected nodes.
     *
     * @param new_member  The joining member with its leaf KEM public key.
     * @param suite       Active cipher suite.
     * @return            GroupKeyUpdate package to distribute to the swarm.
     */
    [[nodiscard]] virtual Result<GroupKeyUpdate>
    add_member(const SwarmMember& new_member, const protocol::CipherSuite& suite) = 0;

    /**
     * @brief Remove a leaf from the tree (member left or was revoked).
     *
     * Blanks the removed leaf and generates O(log N) path-secret updates.
     *
     * @param node_id  NodeId of the member to remove.
     * @param reason   Why the member is being removed.
     * @param suite    Active cipher suite.
     */
    [[nodiscard]] virtual Result<GroupKeyUpdate>
    remove_member(const NodeId& node_id, RekeyReason reason,
                  const protocol::CipherSuite& suite) = 0;

    /**
     * @brief Perform a periodic group key rotation (timer-triggered).
     */
    [[nodiscard]] virtual Result<GroupKeyUpdate>
    rotate_group_key(RekeyReason reason, const protocol::CipherSuite& suite) = 0;

    // ── UAV-side (Leaf) operations ─────────────────────────────────────────────

    /**
     * @brief Process an incoming GroupKeyUpdate as a leaf node.
     *
     * Finds this node's PathSecretCiphertext, decapsulates the path secret
     * with this leaf's private key, derives parent secrets to the root,
     * and constructs the new GroupKey.
     *
     * @param update       The received GroupKeyUpdate.
     * @param my_node_id   This UAV's NodeId.
     * @param my_leaf_key  This UAV's current leaf KEM private key.
     */
    [[nodiscard]] virtual Result<GroupKey>
    process_update(const GroupKeyUpdate&     update,
                   const NodeId&             my_node_id,
                   const crypto::KemPrivateKey& my_leaf_key) = 0;

    // ── State ─────────────────────────────────────────────────────────────────

    [[nodiscard]] virtual const SwarmMembership& membership() const noexcept = 0;
    [[nodiscard]] virtual GroupEpoch             current_epoch() const noexcept = 0;

    virtual void set_group_key_ready_fn(GroupKeyReadyFn fn) = 0;

    // ── Serialization & Visualization ─────────────────────────────────────────

    /**
     * @brief Returns a multi-line ascii-art or text visualization of the current tree state.
     */
    [[nodiscard]] virtual std::string visualize() const = 0;

    /**
     * @brief Serialize the active tree state (public keys, blank status, epochs) to bytes.
     */
    [[nodiscard]] virtual Result<Bytes> serialize() const = 0;

    /**
     * @brief Restore the tree state from serialized bytes.
     */
    [[nodiscard]] virtual VoidResult deserialize(ByteSpan data) = 0;
};

// ── Serialization Helpers for GroupKeyUpdate ─────────────────────────────────

[[nodiscard]] Result<Bytes> serialize_group_key_update(const GroupKeyUpdate& update);
[[nodiscard]] Result<GroupKeyUpdate> deserialize_group_key_update(ByteSpan data);

/**
 * @brief Factory function to construct a new TreeKEM instance.
 */
std::unique_ptr<ITreeKem> make_tree_kem(protocol::CipherSuite suite, std::shared_ptr<platform::IClock> clock = nullptr, std::shared_ptr<crypto::ICryptoProvider> crypto_provider = nullptr);

} // namespace uav_pqc::group
