// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file session_establishment.cpp
 * @brief Concrete session establishment orchestrator.
 *
 * SessionEstablisher is a thin adapter over IHandshake.  It translates
 * the EstablishmentConfig / EstablishmentResult vocabulary into the
 * HandshakeConfig / HandshakeResult vocabulary consumed by the lower layer,
 * and maps HandshakeState → EstablishmentState.
 *
 * All cryptographic work (KEM operations, HKDF, DSA signing/verification)
 * happens inside Handshake.  SessionEstablisher is intentionally free of
 * crypto concerns — it is a pure orchestration adapter.
 */

#include "uav_pqc/protocol/session_establishment.hpp"
#include "uav_pqc/common/logging.hpp"

namespace uav_pqc::protocol {

namespace {

// ─────────────────────────────────────────────────────────────────────────────
// Concrete implementation
// ─────────────────────────────────────────────────────────────────────────────

class SessionEstablisher final : public ISessionEstablisher {
public:
    SessionEstablisher(HandshakeRole role, EstablishmentConfig config, std::shared_ptr<crypto::ICryptoProvider> crypto_provider)
        : state_(EstablishmentState::Idle),
          lifetime_ms_(config.session_lifetime_ms) {
        handshake_ = make_handshake(role, std::move(config.handshake), crypto_provider);
    }

    ~SessionEstablisher() override = default;

    // ── ISessionEstablisher ───────────────────────────────────────────────────

    void set_send_fn(SendFn fn) override {
        // Wrap the EstablishmentState update inside the send callback so that
        // state transitions stay accurate even during synchronous in-process tests.
        send_fn_ = fn;
        handshake_->set_send_fn([this, fn = std::move(fn)](Bytes msg) -> VoidResult {
            auto r = fn(std::move(msg));
            sync_state();
            return r;
        });
    }

    [[nodiscard]] VoidResult start() override {
        if (state_ != EstablishmentState::Idle) {
            return err(ErrorCode::UnsupportedOperation, "Establisher already started");
        }
        state_ = EstablishmentState::Running;
        auto r = handshake_->start();
        sync_state();
        return r;
    }

    [[nodiscard]] VoidResult feed_message(ByteSpan wire_bytes) override {
        if (state_ == EstablishmentState::Complete ||
            state_ == EstablishmentState::Failed) {
            return err(ErrorCode::UnsupportedOperation,
                       "feed_message called on a terminal establisher");
        }
        auto r = handshake_->feed_message(wire_bytes);
        sync_state();
        return r;
    }

    [[nodiscard]] EstablishmentState state() const noexcept override {
        return state_;
    }

    [[nodiscard]] Result<EstablishmentResult> result() override {
        if (state_ != EstablishmentState::Complete) {
            return err<EstablishmentResult>(ErrorCode::UnsupportedOperation,
                                           "Session establishment not complete");
        }
        auto hs_res = handshake_->result();
        if (!hs_res) return hs_res.error();

        HandshakeResult& hr = hs_res.value();

        EstablishmentResult er{
            .session          = std::move(hr.session),
            .peer_node_id     = hr.peer_node_id,
            .negotiated_mode  = hr.negotiated_mode,
            .negotiated_suite = hr.negotiated_suite,
        };

        UAV_PQC_LOG_INFO("protocol.session_establishment",
                         "Session ready — peer={} mode={} suite={}",
                         to_hex(ByteSpan{er.peer_node_id}.first(4)),
                         to_string(er.negotiated_mode),
                         er.negotiated_suite.to_string());

        return ok<EstablishmentResult>(std::move(er));
    }

private:
    /// Propagate HandshakeState → EstablishmentState after each operation.
    void sync_state() noexcept {
        switch (handshake_->state()) {
            case HandshakeState::Complete:
                state_ = EstablishmentState::Complete;
                break;
            case HandshakeState::Failed:
                state_ = EstablishmentState::Failed;
                break;
            default:
                if (state_ == EstablishmentState::Idle) {
                    // First transition out of Idle
                    state_ = EstablishmentState::Running;
                }
                break;
        }
    }

    EstablishmentState          state_;
    [[maybe_unused]] Timestamp  lifetime_ms_; ///< Reserved: future session lifetime cap
    std::unique_ptr<IHandshake> handshake_;
    ISessionEstablisher::SendFn send_fn_; // retained for lifetime management
};

} // namespace

// ─────────────────────────────────────────────────────────────────────────────
// Factory
// ─────────────────────────────────────────────────────────────────────────────

std::unique_ptr<ISessionEstablisher>
make_session_establisher(HandshakeRole role, EstablishmentConfig config, std::shared_ptr<crypto::ICryptoProvider> crypto_provider) {
    return std::make_unique<SessionEstablisher>(role, std::move(config), crypto_provider);
}

} // namespace uav_pqc::protocol
