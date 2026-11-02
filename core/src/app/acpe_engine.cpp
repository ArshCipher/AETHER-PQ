// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

#include "uav_pqc/app/acpe_engine.hpp"

namespace uav_pqc::app {

AcpeEngine::AcpeEngine() {
    core_engine_ = std::make_unique<policy::RuleBasedAcpe>();
}

Result<policy::AcpeDecision> AcpeEngine::evaluate_context(const policy::PolicyContext& ctx) {
    std::lock_guard<std::mutex> lock(mutex_);
    return core_engine_->evaluate(ctx);
}

void AcpeEngine::register_policy_handler(policy::AcpePolicyChangeFn handler) {
    std::lock_guard<std::mutex> lock(mutex_);
    core_engine_->set_policy_change_handler(std::move(handler));
}

Result<policy::AcpeDecision> AcpeEngine::get_last_decision() const {
    return core_engine_->last_decision();
}

VoidResult AcpeEngine::validate_proposed_suite(const protocol::CipherSuite& proposed, const policy::PolicyContext& ctx) const {
    return core_engine_->validate_peer_suite(proposed, ctx);
}

VoidResult AcpeEngine::load_rules_json(ByteSpan json_bytes) {
    std::lock_guard<std::mutex> lock(mutex_);
    return core_engine_->load_rules_json(json_bytes);
}

VoidResult AcpeEngine::load_rules_file(const std::string& filepath) {
    std::lock_guard<std::mutex> lock(mutex_);
    return core_engine_->load_rules_file(filepath);
}

} // namespace uav_pqc::app
