// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file membership.cpp
 * @brief SwarmMembership class implementation.
 */

#include "uav_pqc/group/membership.hpp"
#include <algorithm>

namespace uav_pqc::group {

Result<std::uint32_t> SwarmMembership::add_member(NodeId node_id, crypto::KemPublicKey leaf_key, Timestamp now_ms) {
    if (members_.size() >= kMaxMembers) {
        return err<std::uint32_t>(ErrorCode::InternalError, "Swarm is full");
    }

    std::uint32_t leaf_index = 0;
    if (!vacant_slots_.empty()) {
        auto it = std::min_element(vacant_slots_.begin(), vacant_slots_.end());
        leaf_index = *it;
        vacant_slots_.erase(it);
    } else {
        leaf_index = next_slot_;
        ++next_slot_;
    }

    SwarmMember new_member{
        .node_id = node_id,
        .leaf_key = std::move(leaf_key),
        .leaf_index = leaf_index,
        .joined_at_ms = now_ms
    };

    members_.push_back(std::move(new_member));
    return ok<std::uint32_t>(leaf_index);
}

VoidResult SwarmMembership::remove_member(const NodeId& node_id) {
    auto it = std::find_if(members_.begin(), members_.end(),
                           [&](const SwarmMember& m) { return m.node_id == node_id; });

    if (it == members_.end()) {
        return err(ErrorCode::GroupMemberNotFound, "Member not found");
    }

    vacant_slots_.push_back(it->leaf_index);
    members_.erase(it);
    return ok();
}

VoidResult SwarmMembership::update_leaf_key(const NodeId& node_id, crypto::KemPublicKey new_key) {
    auto it = std::find_if(members_.begin(), members_.end(),
                           [&](const SwarmMember& m) { return m.node_id == node_id; });

    if (it == members_.end()) {
        return err(ErrorCode::GroupMemberNotFound, "Member not found");
    }

    it->leaf_key = std::move(new_key);
    return ok();
}

const SwarmMember* SwarmMembership::find_by_node_id(const NodeId& id) const noexcept {
    auto it = std::find_if(members_.begin(), members_.end(),
                           [&](const SwarmMember& m) { return m.node_id == id; });

    if (it == members_.end()) {
        return nullptr;
    }
    return &(*it);
}

const SwarmMember* SwarmMembership::find_by_leaf_index(std::uint32_t idx) const noexcept {
    auto it = std::find_if(members_.begin(), members_.end(),
                           [&](const SwarmMember& m) { return m.leaf_index == idx; });

    if (it == members_.end()) {
        return nullptr;
    }
    return &(*it);
}

} // namespace uav_pqc::group
