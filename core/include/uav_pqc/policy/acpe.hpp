// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file acpe.hpp
 * @brief Adaptive Cryptographic Policy Engine (ACPE) interface.
 *
 * The ACPE is the central decision-making component of the architecture.
 * It evaluates the PolicyContext and selects:
 *  - The Operating Mode (Classical / Transition / Hybrid / PQC-Only)
 *  - The Cryptographic Profile (Lightweight / Standard / Hardened)
 *  - The complete CipherSuite (KEM level, DSA level, AEAD, rekey interval)
 *
 * ACPE decisions are authenticated by the GCS and delivered to UAVs via
 * ProfileUpdate messages.  UAVs must accept only GCS-authenticated updates
 * to prevent downgrade attacks.
 *
 * The interface is abstract so the concrete engine can be replaced with a
 * mock in tests without affecting the protocol layer.
 */

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/policy/context.hpp"
#include "uav_pqc/policy/profile.hpp"
#include "uav_pqc/protocol/suite.hpp"
#include "uav_pqc/protocol/mode.hpp"

#include <functional>
#include <memory>

namespace uav_pqc::policy {

/**
 * @brief The decision output produced by the ACPE.
 */
struct AcpeDecision {
    protocol::OperatingMode  mode;        ///< Selected operating mode
    CryptographicProfile     profile;     ///< Selected cryptographic profile
    protocol::CipherSuite    suite;       ///< Complete algorithm instantiation
    bool                     rekey_now;   ///< True if an immediate rekey is required
    std::string              rationale;   ///< Human-readable decision explanation (for logs)
    std::uint32_t            rekey_interval_seconds = 0;
    std::uint32_t            session_lifetime_seconds = 0;
    bool                     classical_recommended = false;
    std::uint32_t            telemetry_interval_ms = 1000;
    std::uint32_t            payload_size = 0;
    double                   treekem_rekey_interval_sec = 30.0;
    protocol::OperatingMode  recommended_mode = protocol::OperatingMode::Hybrid;
    std::string              recommendation_reason;
    std::uint64_t            recommendation_timestamp = 0;
    std::uint32_t            recommendation_id = 0;
};

/**
 * @brief Callback type invoked when the ACPE emits a policy change.
 *
 * The new AcpeDecision is passed to the caller.  The caller is responsible
 * for propagating the decision to affected sessions and triggering rekeying.
 */
using AcpePolicyChangeFn = std::function<void(const AcpeDecision& decision)>;

// ── FSM State & Event Enums ──────────────────────────────────────────────────
enum class PolicyState {
    AutomaticPolicy,
    ManualPolicy
};

enum class OperatingState {
    Classical,
    Transition,
    Hybrid,
    PQCOnly
};

enum class OperationalState {
    Normal,
    EmergencyCommunication,
    Shutdown
};

enum class AcpeEvent {
    BatteryChanged,
    ThreatChanged,
    MissionChanged,
    RSSIChanged,
    SINRChanged,
    PacketLossChanged,
    CongestionChanged,
    OperatorOverride,
    OperatorResumeAutomatic,
    HandshakeCompleted,
    SessionExpired,
    TreeKEMUpdated,
    EmergencyDetected
};

struct FsmState {
    PolicyState policy = PolicyState::AutomaticPolicy;
    OperatingState operating = OperatingState::Hybrid;
    OperationalState operational = OperationalState::Normal;
    CryptographicProfile profile = CryptographicProfile::Standard;
    std::string reason = "Initialization";
};

/**
 * @brief Abstract ACPE interface.
 *
 * Two implementations are planned:
 *  1. RuleBasedAcpe — deterministic rules from profile thresholds (this phase)
 *  2. MlAcpe        — ML-driven adaptive policy (future work)
 */
class IAcpe {
public:
    IAcpe()                                = default;
    IAcpe(const IAcpe&)                    = delete;
    IAcpe& operator=(const IAcpe&)         = delete;
    IAcpe(IAcpe&&) noexcept                = default;
    IAcpe& operator=(IAcpe&&) noexcept     = default;
    virtual ~IAcpe()                        = default;

    /**
     * @brief Evaluate the current context and return a policy decision.
     *
     * Called:
     *  - At session establishment (initial mode/profile selection)
     *  - Periodically (timer-driven evaluation)
     *  - On significant events (battery drop, link degradation, swarm change)
     *
     * @param ctx  Current runtime context snapshot.
     * @return     AcpeDecision, or Error if the context is internally inconsistent.
     */
    [[nodiscard]] virtual Result<AcpeDecision> evaluate(const PolicyContext& ctx) = 0;

    /**
     * @brief Register a callback to receive policy-change notifications.
     *
     * The callback is invoked from within evaluate() when the new decision
     * differs from the last decision.
     */
    virtual void set_policy_change_handler(AcpePolicyChangeFn fn) = 0;

    /**
     * @brief Returns the most recently issued decision.
     *
     * Returns ErrorCode::UnsupportedOperation if evaluate() has not been called.
     */
    [[nodiscard]] virtual Result<AcpeDecision> last_decision() const = 0;

    /**
     * @brief Validate that a peer-proposed CipherSuite is acceptable.
     *
     * Called during handshake profile negotiation to enforce downgrade resistance.
     * Returns Ok if acceptable, ErrorCode::DowngradeRejected or
     * ErrorCode::PolicyViolation if not.
     *
     * @param proposed  Suite proposed by the peer or GCS.
     * @param ctx       Current runtime context.
     */
    [[nodiscard]] virtual VoidResult validate_peer_suite(
        const protocol::CipherSuite& proposed,
        const PolicyContext&         ctx) const = 0;

    /**
     * @brief Validate whether a D2D session between UAV-A and UAV-B is authorized under ACPE policy.
     */
    [[nodiscard]] virtual VoidResult authorize_d2d_session(
        const NodeId& initiator,
        const NodeId& target,
        const PolicyContext& ctx) const {
        (void)initiator; (void)target;
        if (ctx.battery_percent > 0 && ctx.battery_percent < 5) {
            return ErrorCode::PolicyViolation; // Low battery emergency shutdown
        }
        return ok();
    }

    // ── Operator Commands for FSM Manual Override ───────────────────────────
    virtual void trigger_operator_override(protocol::OperatingMode mode, CryptographicProfile profile) {}
    virtual void trigger_operator_resume() {}

    // ── Dual Policy Control Interface ────────────────────────────────────────
    virtual void EnableAutomatic() {}
    virtual void DisableAutomatic() {}
    virtual void SetOperatingMode(protocol::OperatingMode mode) {}
    virtual void SetCryptoProfile(CryptographicProfile profile) {}
    virtual void EmergencyOverride() {}
    virtual void ResumeAutomatic() {}
    virtual FsmState get_fsm_state() const noexcept { return FsmState{}; }
};


/**
 * @brief Rule-based ACPE implementation using a deterministic Finite State Machine (FSM).
 */
class RuleBasedAcpe final : public IAcpe {
public:
    explicit RuleBasedAcpe(ProfileParameters lw  = ProfileParameters::lightweight(),
                           ProfileParameters std_ = ProfileParameters::standard(),
                           ProfileParameters hrd  = ProfileParameters::hardened());
    ~RuleBasedAcpe() override = default;

    RuleBasedAcpe(const RuleBasedAcpe&)             = delete;
    RuleBasedAcpe& operator=(const RuleBasedAcpe&)  = delete;
    RuleBasedAcpe(RuleBasedAcpe&&) noexcept         = default;
    RuleBasedAcpe& operator=(RuleBasedAcpe&&) noexcept = default;

    [[nodiscard]] Result<AcpeDecision> evaluate(const PolicyContext& ctx)    override;
    void set_policy_change_handler(AcpePolicyChangeFn fn)                    override;
    [[nodiscard]] Result<AcpeDecision> last_decision() const                 override;
    [[nodiscard]] VoidResult validate_peer_suite(const protocol::CipherSuite& proposed,
                                                  const PolicyContext& ctx) const override;

    [[nodiscard]] const ProfileParameters& lightweight_profile() const noexcept { return lightweight_; }
    [[nodiscard]] const ProfileParameters& standard_profile() const noexcept { return standard_; }
    [[nodiscard]] const ProfileParameters& hardened_profile() const noexcept { return hardened_; }

    void set_lightweight_profile(ProfileParameters params) noexcept { lightweight_ = std::move(params); }
    void set_standard_profile(ProfileParameters params) noexcept { standard_ = std::move(params); }
    void set_hardened_profile(ProfileParameters params) noexcept { hardened_ = std::move(params); }

    // Operator override triggers
    void trigger_operator_override(protocol::OperatingMode mode, CryptographicProfile profile) override;
    void trigger_operator_resume() override;

    // Dual Policy Control Interface
    void EnableAutomatic() override;
    void DisableAutomatic() override;
    void SetOperatingMode(protocol::OperatingMode mode) override;
    void SetCryptoProfile(CryptographicProfile profile) override;
    void EmergencyOverride() override;
    void ResumeAutomatic() override;
    FsmState get_fsm_state() const noexcept override { return current_state_; }

    VoidResult load_rules_json(ByteSpan json_bytes);
    VoidResult load_rules_file(const std::string& filepath);

private:
    struct RuleCondition {
        std::string field;
        std::string op;
        double value = 0.0;
    };
    struct RuleActions {
        std::string profile;
        std::string mode;
        std::uint32_t rekey_interval_seconds = 0;
        std::uint32_t session_lifetime_seconds = 0;
    };
    struct Rule {
        std::vector<RuleCondition> conditions;
        std::string any_or_all = "all";
        RuleActions actions;
    };

    ProfileParameters    lightweight_;
    ProfileParameters    standard_;
    ProfileParameters    hardened_;
    AcpePolicyChangeFn   change_handler_;

    std::vector<Rule>    rules_;
    RuleActions          default_actions_;
    bool                 has_loaded_rules_ = false;

    /// Last decision; nullopt until first evaluate() call.
    mutable std::optional<AcpeDecision> last_decision_;

    // ── FSM State & Transition Table Cache ───────────────────────────────────
    FsmState current_state_;
    mutable std::optional<PolicyContext> last_ctx_;

    // Manual override state values
    protocol::OperatingMode override_mode_ = protocol::OperatingMode::Hybrid;
    CryptographicProfile override_profile_ = CryptographicProfile::Standard;

    // FSM Internal transition method
    void handle_event(AcpeEvent ev, const PolicyContext& ctx);

    [[nodiscard]] CryptographicProfile  select_profile(const PolicyContext& ctx) const noexcept;
    [[nodiscard]] protocol::OperatingMode select_mode(const PolicyContext& ctx,
                                                       CryptographicProfile profile) const noexcept;
    [[nodiscard]] protocol::CipherSuite build_suite(protocol::OperatingMode mode,
                                                     const ProfileParameters& params,
                                                     const PolicyContext& ctx) const;
};

} // namespace uav_pqc::policy
