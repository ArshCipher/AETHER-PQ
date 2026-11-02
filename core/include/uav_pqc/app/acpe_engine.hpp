// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/policy/acpe.hpp"
#include "uav_pqc/policy/context.hpp"

#include <mutex>
#include <memory>

namespace uav_pqc::app {

/**
 * @brief Abstract ACPE Engine interface.
 */
class IAcpeEngine {
public:
    IAcpeEngine() = default;
    virtual ~IAcpeEngine() = default;

    IAcpeEngine(const IAcpeEngine&) = delete;
    IAcpeEngine& operator=(const IAcpeEngine&) = delete;
    IAcpeEngine(IAcpeEngine&&) noexcept = default;
    IAcpeEngine& operator=(IAcpeEngine&&) noexcept = default;

    virtual Result<policy::AcpeDecision> evaluate_context(const policy::PolicyContext& ctx) = 0;
    virtual void register_policy_handler(policy::AcpePolicyChangeFn handler) = 0;
    virtual Result<policy::AcpeDecision> get_last_decision() const = 0;
    virtual VoidResult validate_proposed_suite(const protocol::CipherSuite& proposed, const policy::PolicyContext& ctx) const = 0;
    virtual VoidResult load_rules_json(ByteSpan json_bytes) = 0;
    virtual VoidResult load_rules_file(const std::string& filepath) = 0;
    virtual policy::FsmState get_fsm_state() const noexcept = 0;
    virtual policy::RuleBasedAcpe* get_core_engine() const noexcept = 0;
};

/**
 * @brief Concrete ACPE Engine class wrapping the core policy rules.
 */
class AcpeEngine final : public IAcpeEngine {
public:
    AcpeEngine();
    ~AcpeEngine() override = default;

    Result<policy::AcpeDecision> evaluate_context(const policy::PolicyContext& ctx) override;
    void register_policy_handler(policy::AcpePolicyChangeFn handler) override;
    Result<policy::AcpeDecision> get_last_decision() const override;
    VoidResult validate_proposed_suite(const protocol::CipherSuite& proposed, const policy::PolicyContext& ctx) const override;
    VoidResult load_rules_json(ByteSpan json_bytes) override;
    VoidResult load_rules_file(const std::string& filepath) override;
    policy::FsmState get_fsm_state() const noexcept override { return core_engine_->get_fsm_state(); }
    policy::RuleBasedAcpe* get_core_engine() const noexcept override { return core_engine_.get(); }

private:
    std::mutex mutex_;
    std::unique_ptr<policy::RuleBasedAcpe> core_engine_;
};

} // namespace uav_pqc::app
