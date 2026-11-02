// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file membership.hpp
 * @brief Swarm membership management for TreeKEM group key operations.
 *
 * Tracks the set of active swarm members and their public keys.
 * The GCS is authoritative for membership; UAVs receive membership updates
 * via authenticated GroupMemberAdd / GroupMemberRemove messages.
 *
 * Used by ITreeKem to determine which nodes receive path-secret updates
 * after a membership change.
 */

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"
#include "uav_pqc/crypto/kem.hpp"

#include <cstdint>
#include <optional>
#include <vector>

namespace uav_pqc::group {

/**
 * @brief A single swarm member entry.
 */
struct SwarmMember {
    NodeId              node_id;        ///< Member's 256-bit identifier
    crypto::KemPublicKey leaf_key;      ///< Member's current leaf KEM public key
    std::uint32_t        leaf_index;    ///< Position in the TreeKEM binary tree
    Timestamp            joined_at_ms;  ///< When this member joined the epoch
};

/**
 * @brief Manages the ordered set of swarm members.
 *
 * Members are indexed by position in the binary tree (leaf_index).
 * Removals leave a hole in the tree; new members fill the leftmost hole
 * before appending to the right.
 */
class SwarmMembership {
public:
    /// Maximum swarm size supported by this implementation (N ≈ 8 per spec).
    static constexpr std::uint32_t kMaxMembers = 256;

    SwarmMembership() = default;
    ~SwarmMembership() = default;

    SwarmMembership(const SwarmMembership&) = default;
    SwarmMembership& operator=(const SwarmMembership&) = default;
    SwarmMembership(SwarmMembership&&) noexcept = default;
    SwarmMembership& operator=(SwarmMembership&&) noexcept = default;

    // ── Membership operations ─────────────────────────────────────────────────

    /**
     * @brief Add a new member to the swarm.
     *
     * Assigns the smallest available leaf_index.
     *
     * @return Assigned leaf_index, or ErrorCode::InternalError if full.
     */
    [[nodiscard]] Result<std::uint32_t>
    add_member(NodeId node_id, crypto::KemPublicKey leaf_key, Timestamp now_ms);

    /**
     * @brief Remove a member by NodeId.
     *
     * The leaf slot is marked vacant for future reuse.
     * Returns ErrorCode::GroupMemberNotFound if the NodeId is not present.
     */
    [[nodiscard]] VoidResult remove_member(const NodeId& node_id);

    /**
     * @brief Update the leaf key for an existing member.
     *
     * Called when a member rotates its leaf key pair as part of a path update.
     */
    [[nodiscard]] VoidResult update_leaf_key(const NodeId& node_id,
                                              crypto::KemPublicKey new_key);

    // ── Lookup ─────────────────────────────────────────────────────────────────

    [[nodiscard]] const SwarmMember* find_by_node_id(const NodeId& id) const noexcept;
    [[nodiscard]] const SwarmMember* find_by_leaf_index(std::uint32_t idx) const noexcept;

    // ── Enumeration ───────────────────────────────────────────────────────────

    [[nodiscard]] std::size_t              size()    const noexcept { return members_.size(); }
    [[nodiscard]] bool                     empty()   const noexcept { return members_.empty(); }
    [[nodiscard]] const std::vector<SwarmMember>& members() const noexcept { return members_; }

    /// Returns the total number of leaf slots (≥ size(); includes vacant slots).
    [[nodiscard]] std::uint32_t tree_size() const noexcept { return next_slot_; }

private:
    std::vector<SwarmMember>        members_;
    std::vector<std::uint32_t>      vacant_slots_;
    std::uint32_t                   next_slot_ = 0;
};

} // namespace uav_pqc::group
