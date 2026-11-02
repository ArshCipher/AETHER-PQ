// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/group/tree_kem.hpp"
#include "uav_pqc/common/types.hpp"
#include "uav_pqc/platform/clock.hpp"

#include <mutex>
#include <memory>

namespace uav_pqc::app {

/**
 * @brief Abstract TreeKEMController interface.
 */
class ITreeKemController {
public:
    ITreeKemController() = default;
    virtual ~ITreeKemController() = default;

    ITreeKemController(const ITreeKemController&) = delete;
    ITreeKemController& operator=(const ITreeKemController&) = delete;
    ITreeKemController(ITreeKemController&&) noexcept = default;
    ITreeKemController& operator=(ITreeKemController&&) noexcept = default;

    virtual Result<group::GroupKeyUpdate> register_member(const group::SwarmMember& member) = 0;
    virtual Result<group::GroupKeyUpdate> revoke_member(const NodeId& node_id, group::RekeyReason reason) = 0;
    virtual Result<group::GroupKeyUpdate> rotate_keys(group::RekeyReason reason) = 0;
    
    virtual Result<group::GroupKey> process_group_update(const group::GroupKeyUpdate& update,
                                                          const NodeId& my_node_id,
                                                          const crypto::KemPrivateKey& my_leaf_key) = 0;
    virtual GroupEpoch get_epoch() const noexcept = 0;
    virtual const group::SwarmMembership& get_membership() const noexcept = 0;
    virtual Result<Bytes> serialize_tree() const = 0;
    virtual VoidResult deserialize_tree(ByteSpan data) = 0;
    virtual void set_group_key_ready_fn(group::ITreeKem::GroupKeyReadyFn fn) = 0;
};

/**
 * @brief Concrete TreeKEMController class wrapping the group key agreement logic.
 */
class TreeKemController final : public ITreeKemController {
public:
    explicit TreeKemController(protocol::CipherSuite suite, std::shared_ptr<platform::IClock> clock = nullptr);
    ~TreeKemController() override = default;

    Result<group::GroupKeyUpdate> register_member(const group::SwarmMember& member) override;
    Result<group::GroupKeyUpdate> revoke_member(const NodeId& node_id, group::RekeyReason reason) override;
    Result<group::GroupKeyUpdate> rotate_keys(group::RekeyReason reason) override;

    Result<group::GroupKey> process_group_update(const group::GroupKeyUpdate& update,
                                                 const NodeId& my_node_id,
                                                 const crypto::KemPrivateKey& my_leaf_key) override;

    GroupEpoch get_epoch() const noexcept override;
    const group::SwarmMembership& get_membership() const noexcept override;
    Result<Bytes> serialize_tree() const override;
    VoidResult deserialize_tree(ByteSpan data) override;
    void set_group_key_ready_fn(group::ITreeKem::GroupKeyReadyFn fn) override;

private:
    std::mutex mutex_;
    protocol::CipherSuite suite_;
    std::unique_ptr<group::ITreeKem> tree_kem_;
    std::shared_ptr<platform::IClock> clock_;
};

} // namespace uav_pqc::app
