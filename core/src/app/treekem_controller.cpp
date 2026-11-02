// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

#include "uav_pqc/app/treekem_controller.hpp"

namespace uav_pqc::app {

TreeKemController::TreeKemController(protocol::CipherSuite suite, std::shared_ptr<platform::IClock> clock)
    : suite_(suite), clock_(clock) {
    if (!clock_) {
        clock_ = platform::make_platform_clock();
    }
    tree_kem_ = group::make_tree_kem(suite_, clock_);
}

Result<group::GroupKeyUpdate> TreeKemController::register_member(const group::SwarmMember& member) {
    std::lock_guard<std::mutex> lock(mutex_);
    return tree_kem_->add_member(member, suite_);
}

Result<group::GroupKeyUpdate> TreeKemController::revoke_member(const NodeId& node_id, group::RekeyReason reason) {
    std::lock_guard<std::mutex> lock(mutex_);
    return tree_kem_->remove_member(node_id, reason, suite_);
}

Result<group::GroupKeyUpdate> TreeKemController::rotate_keys(group::RekeyReason reason) {
    std::lock_guard<std::mutex> lock(mutex_);
    return tree_kem_->rotate_group_key(reason, suite_);
}

Result<group::GroupKey> TreeKemController::process_group_update(const group::GroupKeyUpdate& update,
                                                             const NodeId& my_node_id,
                                                             const crypto::KemPrivateKey& my_leaf_key) {
    std::lock_guard<std::mutex> lock(mutex_);
    return tree_kem_->process_update(update, my_node_id, my_leaf_key);
}

GroupEpoch TreeKemController::get_epoch() const noexcept {
    return tree_kem_->current_epoch();
}

const group::SwarmMembership& TreeKemController::get_membership() const noexcept {
    return tree_kem_->membership();
}

Result<Bytes> TreeKemController::serialize_tree() const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex_));
    return tree_kem_->serialize();
}

VoidResult TreeKemController::deserialize_tree(ByteSpan data) {
    std::lock_guard<std::mutex> lock(mutex_);
    return tree_kem_->deserialize(data);
}

void TreeKemController::set_group_key_ready_fn(group::ITreeKem::GroupKeyReadyFn fn) {
    std::lock_guard<std::mutex> lock(mutex_);
    tree_kem_->set_group_key_ready_fn(std::move(fn));
}

} // namespace uav_pqc::app
