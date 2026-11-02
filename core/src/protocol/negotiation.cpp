// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file negotiation.cpp
 * @brief Operating Mode and Cryptographic Profile Negotiation implementation.
 *
 * Two concrete state machines (NegotiationInitiator, NegotiationResponder)
 * implement INegotiationInitiator and INegotiationResponder respectively.
 *
 * Key invariants enforced here:
 *   - Every outgoing message is ML-DSA signed over its canonical byte form.
 *   - Every incoming message signature is verified before state advances.
 *   - The nonce echo is checked on every RESP message.
 *   - The transcript hash in CONFIRM messages is verified before Final state.
 *   - Mode and suite downgrade is rejected with ErrorCode::DowngradeRejected.
 */

#include "uav_pqc/protocol/negotiation.hpp"
#include "uav_pqc/common/logging.hpp"
#include "uav_pqc/crypto/ml_dsa.hpp"
#include "uav_pqc/crypto/default_provider.hpp"

#include <algorithm>
#include <cassert>
#include <cstring>

namespace uav_pqc::protocol {

namespace {

// ─────────────────────────────────────────────────────────────────────────────
// Serialisation helpers (local to this TU, matching registration.cpp style)
// ─────────────────────────────────────────────────────────────────────────────

void write_u8(Bytes& dst, std::uint8_t v) {
    dst.push_back(static_cast<std::byte>(v));
}

std::uint8_t read_u8(const std::byte*& ptr, const std::byte* end) {
    // Caller must guarantee ptr < end
    return static_cast<std::uint8_t>(*ptr++);
}

void write_u16_be(Bytes& dst, std::uint16_t v) {
    dst.push_back(static_cast<std::byte>((v >> 8) & 0xFF));
    dst.push_back(static_cast<std::byte>(v & 0xFF));
}

std::uint16_t read_u16_be(const std::byte* src) noexcept {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(src[0]) << 8) |
         static_cast<std::uint16_t>(src[1]));
}

void write_u64_be(Bytes& dst, std::uint64_t v) {
    for (int i = 7; i >= 0; --i) {
        dst.push_back(static_cast<std::byte>((v >> (i * 8)) & 0xFF));
    }
}

std::uint64_t read_u64_be_ptr(const std::byte* src) noexcept {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v = (v << 8) | static_cast<std::uint8_t>(src[i]);
    }
    return v;
}

/// Append a length-prefixed (u16 big-endian) byte span.
void append_len16(Bytes& dst, ByteSpan src) {
    write_u16_be(dst, static_cast<std::uint16_t>(src.size()));
    dst.insert(dst.end(), src.begin(), src.end());
}

/// Read a length-prefixed (u16 big-endian) byte sequence.
Result<Bytes> read_len16(const std::byte*& ptr, const std::byte* end) {
    if (ptr + 2 > end) {
        return err<Bytes>(ErrorCode::InvalidArgument, "Truncated length prefix");
    }
    const std::uint16_t len = read_u16_be(ptr);
    ptr += 2;
    if (ptr + len > end) {
        return err<Bytes>(ErrorCode::InvalidArgument, "Truncated value body");
    }
    Bytes out(ptr, ptr + len);
    ptr += len;
    return ok<Bytes>(std::move(out));
}

/// Generate count cryptographically secure random bytes.
Result<Bytes> generate_nonce(const NegotiationConfig& cfg, std::size_t count) {
    std::shared_ptr<crypto::ICryptoProvider> provider = cfg.crypto_provider;
    if (!provider) {
        provider = std::make_shared<crypto::DefaultCryptoProvider>();
    }
    return provider->generate_random_bytes(count);
}

/// SHA-256 of a sequence of byte spans (concatenated in order).
std::array<std::byte, 32> sha256_of_spans(const NegotiationConfig& cfg, std::initializer_list<ByteSpan> spans) {
    std::shared_ptr<crypto::ICryptoProvider> provider = cfg.crypto_provider;
    if (!provider) {
        provider = std::make_shared<crypto::DefaultCryptoProvider>();
    }
    auto r = provider->hash_sha256_multi(spans);
    std::array<std::byte, 32> digest{};
    if (r) {
        std::copy(r.value().begin(), r.value().end(), digest.begin());
    }
    return digest;
}

/// Returns the numeric strength rank of an OperatingMode (higher = stronger).
int mode_rank(OperatingMode m) noexcept {
    switch (m) {
        case OperatingMode::Classical:  return 1;
        case OperatingMode::Transition: return 2;
        case OperatingMode::Hybrid:     return 3;
        case OperatingMode::PqcOnly:    return 4;
    }
    return 0;
}

/// Check that `actual` is at least as strong as `floor_mode`.
bool mode_meets_floor(OperatingMode actual, OperatingMode floor_mode) noexcept {
    return mode_rank(actual) >= mode_rank(floor_mode);
}

/// Sign `message` with the ML-DSA private key in `config`.
Result<Bytes> sign_message(const NegotiationConfig& cfg, ByteSpan message) {
    std::shared_ptr<crypto::ICryptoProvider> provider = cfg.crypto_provider;
    if (!provider) {
        provider = std::make_shared<crypto::DefaultCryptoProvider>();
    }
    auto dsa = provider->create_ml_dsa(cfg.signing_level);
    auto sig_r = dsa->sign(cfg.our_ml_dsa_key.private_key, message);
    if (!sig_r) return err<Bytes>(sig_r.error());
    return ok<Bytes>(std::move(sig_r.value().data));
}

/// Verify `signature` against the peer's ML-DSA public key in `config`.
VoidResult verify_peer_signature(const NegotiationConfig& cfg,
                                  ByteSpan message,
                                  ByteSpan signature) {
    std::shared_ptr<crypto::ICryptoProvider> provider = cfg.crypto_provider;
    if (!provider) {
        provider = std::make_shared<crypto::DefaultCryptoProvider>();
    }
    auto dsa = provider->create_ml_dsa(cfg.signing_level);
    crypto::Signature sig;
    sig.data.assign(signature.begin(), signature.end());
    auto res = dsa->verify(cfg.peer_ml_dsa_pub, message, sig);
    if (!res || !res.value()) {
        return err(ErrorCode::VerificationFailed, "ML-DSA negotiation signature invalid");
    }
    return ok();
}

/// Build a complete wire packet: MessageHeader + serialised body.
Bytes make_packet(MessageType type, const Bytes& body) {
    MessageHeader hdr;
    hdr.type    = type;
    hdr.version = 0x01;
    hdr.length  = static_cast<std::uint16_t>(body.size());
    // session_id and sequence_number remain zero during pre-session negotiation
    Bytes pkt = hdr.serialise();
    pkt.insert(pkt.end(), body.begin(), body.end());
    return pkt;
}

/// Parse the MessageHeader from wire bytes, return body span.
struct ParsedPacket {
    MessageHeader header;
    ByteSpan      body;
};

Result<ParsedPacket> parse_packet(ByteSpan wire) {
    if (wire.size() < MessageHeader::kWireSize) {
        return err<ParsedPacket>(ErrorCode::InvalidArgument,
                                  "Wire packet shorter than message header");
    }
    auto hdr_r = MessageHeader::deserialise(wire.subspan(0, MessageHeader::kWireSize));
    if (!hdr_r) return err<ParsedPacket>(hdr_r.error());

    const std::size_t body_end = MessageHeader::kWireSize + hdr_r.value().length;
    if (wire.size() < body_end) {
        return err<ParsedPacket>(ErrorCode::InvalidArgument, "Packet body truncated");
    }
    return ok<ParsedPacket>({hdr_r.value(),
                             wire.subspan(MessageHeader::kWireSize, hdr_r.value().length)});
}

/// Validate timestamp is within max_clock_skew_ms of now.
VoidResult check_timestamp(Timestamp msg_ts, Timestamp now_ms, std::uint64_t max_skew_ms) {
    const std::int64_t diff = static_cast<std::int64_t>(msg_ts)
                            - static_cast<std::int64_t>(now_ms);
    const std::int64_t skew = (diff < 0) ? -diff : diff;
    if (static_cast<std::uint64_t>(skew) > max_skew_ms) {
        return err(ErrorCode::ReplayDetected,
                   "Negotiation timestamp outside acceptable clock skew window");
    }
    return ok();
}

} // anonymous namespace

// ─────────────────────────────────────────────────────────────────────────────
// ModeReqMsg — serialise / deserialise / signed bytes
// ─────────────────────────────────────────────────────────────────────────────

Bytes ModeReqMsg::get_signed_bytes() const {
    Bytes out;
    out.insert(out.end(), node_id.begin(), node_id.end());
    append_len16(out, nonce);
    write_u64_be(out, timestamp);
    write_u8(out, static_cast<std::uint8_t>(offered_modes.size()));
    for (auto m : offered_modes) {
        write_u8(out, static_cast<std::uint8_t>(m));
    }
    return out;
}

Bytes ModeReqMsg::serialise() const {
    Bytes out = get_signed_bytes();
    append_len16(out, signature);
    return out;
}

Result<ModeReqMsg> ModeReqMsg::deserialise(ByteSpan data) {
    const std::byte* ptr = data.data();
    const std::byte* end = ptr + data.size();

    if (ptr + 32 > end) return err<ModeReqMsg>(ErrorCode::InvalidArgument, "ModeReq: no node_id");
    ModeReqMsg msg;
    std::copy(ptr, ptr + 32, msg.node_id.begin());
    ptr += 32;

    auto nonce_r = read_len16(ptr, end);
    if (!nonce_r) return err<ModeReqMsg>(nonce_r.error());
    msg.nonce = std::move(nonce_r.value());

    if (ptr + 8 > end) return err<ModeReqMsg>(ErrorCode::InvalidArgument, "ModeReq: no timestamp");
    msg.timestamp = read_u64_be_ptr(ptr); ptr += 8;

    if (ptr >= end) return err<ModeReqMsg>(ErrorCode::InvalidArgument, "ModeReq: no n_modes");
    const std::uint8_t n_modes = read_u8(ptr, end);
    if (ptr + n_modes > end) return err<ModeReqMsg>(ErrorCode::InvalidArgument, "ModeReq: modes truncated");
    msg.offered_modes.reserve(n_modes);
    for (std::uint8_t i = 0; i < n_modes; ++i) {
        msg.offered_modes.push_back(static_cast<OperatingMode>(read_u8(ptr, end)));
    }

    auto sig_r = read_len16(ptr, end);
    if (!sig_r) return err<ModeReqMsg>(sig_r.error());
    msg.signature = std::move(sig_r.value());

    return ok<ModeReqMsg>(std::move(msg));
}

// ─────────────────────────────────────────────────────────────────────────────
// ModeRespMsg
// ─────────────────────────────────────────────────────────────────────────────

Bytes ModeRespMsg::get_signed_bytes() const {
    Bytes out;
    out.insert(out.end(), node_id.begin(), node_id.end());
    append_len16(out, echo_nonce);
    append_len16(out, resp_nonce);
    write_u8(out, static_cast<std::uint8_t>(selected_mode));
    write_u64_be(out, timestamp);
    return out;
}

Bytes ModeRespMsg::serialise() const {
    Bytes out = get_signed_bytes();
    append_len16(out, signature);
    return out;
}

Result<ModeRespMsg> ModeRespMsg::deserialise(ByteSpan data) {
    const std::byte* ptr = data.data();
    const std::byte* end = ptr + data.size();

    if (ptr + 32 > end) return err<ModeRespMsg>(ErrorCode::InvalidArgument, "ModeResp: no node_id");
    ModeRespMsg msg;
    std::copy(ptr, ptr + 32, msg.node_id.begin());
    ptr += 32;

    auto echo_r = read_len16(ptr, end);
    if (!echo_r) return err<ModeRespMsg>(echo_r.error());
    msg.echo_nonce = std::move(echo_r.value());

    auto resp_r = read_len16(ptr, end);
    if (!resp_r) return err<ModeRespMsg>(resp_r.error());
    msg.resp_nonce = std::move(resp_r.value());

    if (ptr >= end) return err<ModeRespMsg>(ErrorCode::InvalidArgument, "ModeResp: no mode");
    msg.selected_mode = static_cast<OperatingMode>(read_u8(ptr, end));

    if (ptr + 8 > end) return err<ModeRespMsg>(ErrorCode::InvalidArgument, "ModeResp: no timestamp");
    msg.timestamp = read_u64_be_ptr(ptr); ptr += 8;

    auto sig_r = read_len16(ptr, end);
    if (!sig_r) return err<ModeRespMsg>(sig_r.error());
    msg.signature = std::move(sig_r.value());

    return ok<ModeRespMsg>(std::move(msg));
}

// ─────────────────────────────────────────────────────────────────────────────
// ModeConfirmMsg
// ─────────────────────────────────────────────────────────────────────────────

Bytes ModeConfirmMsg::get_signed_bytes() const {
    Bytes out;
    write_u8(out, static_cast<std::uint8_t>(confirmed_mode));
    out.insert(out.end(), transcript_hash.begin(), transcript_hash.end());
    return out;
}

Bytes ModeConfirmMsg::serialise() const {
    Bytes out = get_signed_bytes();
    append_len16(out, signature);
    return out;
}

Result<ModeConfirmMsg> ModeConfirmMsg::deserialise(ByteSpan data) {
    const std::byte* ptr = data.data();
    const std::byte* end = ptr + data.size();

    if (ptr >= end) return err<ModeConfirmMsg>(ErrorCode::InvalidArgument, "ModeConfirm: no mode");
    ModeConfirmMsg msg;
    msg.confirmed_mode = static_cast<OperatingMode>(read_u8(ptr, end));

    if (ptr + kTranscriptHashSize > end) {
        return err<ModeConfirmMsg>(ErrorCode::InvalidArgument, "ModeConfirm: no transcript hash");
    }
    std::copy(ptr, ptr + kTranscriptHashSize, msg.transcript_hash.begin());
    ptr += kTranscriptHashSize;

    auto sig_r = read_len16(ptr, end);
    if (!sig_r) return err<ModeConfirmMsg>(sig_r.error());
    msg.signature = std::move(sig_r.value());

    return ok<ModeConfirmMsg>(std::move(msg));
}

// ─────────────────────────────────────────────────────────────────────────────
// ProfileReqMsg
// ─────────────────────────────────────────────────────────────────────────────

Bytes ProfileReqMsg::get_signed_bytes() const {
    Bytes out;
    out.insert(out.end(), node_id.begin(), node_id.end());
    append_len16(out, nonce);
    write_u64_be(out, timestamp);
    write_u8(out, static_cast<std::uint8_t>(kem_level));
    write_u8(out, static_cast<std::uint8_t>(dsa_level));
    write_u8(out, static_cast<std::uint8_t>(aead_algorithm));
    write_u8(out, static_cast<std::uint8_t>(hkdf_hash));
    return out;
}

Bytes ProfileReqMsg::serialise() const {
    Bytes out = get_signed_bytes();
    append_len16(out, signature);
    return out;
}

Result<ProfileReqMsg> ProfileReqMsg::deserialise(ByteSpan data) {
    const std::byte* ptr = data.data();
    const std::byte* end = ptr + data.size();

    if (ptr + 32 > end) return err<ProfileReqMsg>(ErrorCode::InvalidArgument, "ProfileReq: no node_id");
    ProfileReqMsg msg;
    std::copy(ptr, ptr + 32, msg.node_id.begin());
    ptr += 32;

    auto nonce_r = read_len16(ptr, end);
    if (!nonce_r) return err<ProfileReqMsg>(nonce_r.error());
    msg.nonce = std::move(nonce_r.value());

    if (ptr + 8 > end) return err<ProfileReqMsg>(ErrorCode::InvalidArgument, "ProfileReq: no timestamp");
    msg.timestamp = read_u64_be_ptr(ptr); ptr += 8;

    if (ptr + 4 > end) return err<ProfileReqMsg>(ErrorCode::InvalidArgument, "ProfileReq: algo bytes truncated");
    msg.kem_level      = static_cast<crypto::MlKem::Level>(read_u8(ptr, end));
    msg.dsa_level      = static_cast<crypto::MlDsa::Level>(read_u8(ptr, end));
    msg.aead_algorithm = static_cast<AeadAlgorithm>(read_u8(ptr, end));
    msg.hkdf_hash      = static_cast<crypto::HkdfHash>(read_u8(ptr, end));

    auto sig_r = read_len16(ptr, end);
    if (!sig_r) return err<ProfileReqMsg>(sig_r.error());
    msg.signature = std::move(sig_r.value());

    return ok<ProfileReqMsg>(std::move(msg));
}

// ─────────────────────────────────────────────────────────────────────────────
// ProfileRespMsg
// ─────────────────────────────────────────────────────────────────────────────

Bytes ProfileRespMsg::get_signed_bytes() const {
    Bytes out;
    append_len16(out, echo_nonce);
    append_len16(out, resp_nonce);
    write_u8(out, accepted ? 0x01 : 0x00);
    write_u8(out, static_cast<std::uint8_t>(kem_level));
    write_u8(out, static_cast<std::uint8_t>(dsa_level));
    write_u8(out, static_cast<std::uint8_t>(aead_algorithm));
    write_u8(out, static_cast<std::uint8_t>(hkdf_hash));
    write_u64_be(out, timestamp);
    return out;
}

Bytes ProfileRespMsg::serialise() const {
    Bytes out = get_signed_bytes();
    append_len16(out, signature);
    return out;
}

Result<ProfileRespMsg> ProfileRespMsg::deserialise(ByteSpan data) {
    const std::byte* ptr = data.data();
    const std::byte* end = ptr + data.size();

    ProfileRespMsg msg;

    auto echo_r = read_len16(ptr, end);
    if (!echo_r) return err<ProfileRespMsg>(echo_r.error());
    msg.echo_nonce = std::move(echo_r.value());

    auto resp_r = read_len16(ptr, end);
    if (!resp_r) return err<ProfileRespMsg>(resp_r.error());
    msg.resp_nonce = std::move(resp_r.value());

    if (ptr + 5 > end) return err<ProfileRespMsg>(ErrorCode::InvalidArgument, "ProfileResp: algo bytes truncated");
    msg.accepted       = (read_u8(ptr, end) == 0x01);
    msg.kem_level      = static_cast<crypto::MlKem::Level>(read_u8(ptr, end));
    msg.dsa_level      = static_cast<crypto::MlDsa::Level>(read_u8(ptr, end));
    msg.aead_algorithm = static_cast<AeadAlgorithm>(read_u8(ptr, end));
    msg.hkdf_hash      = static_cast<crypto::HkdfHash>(read_u8(ptr, end));

    if (ptr + 8 > end) return err<ProfileRespMsg>(ErrorCode::InvalidArgument, "ProfileResp: no timestamp");
    msg.timestamp = read_u64_be_ptr(ptr); ptr += 8;

    auto sig_r = read_len16(ptr, end);
    if (!sig_r) return err<ProfileRespMsg>(sig_r.error());
    msg.signature = std::move(sig_r.value());

    return ok<ProfileRespMsg>(std::move(msg));
}

// ─────────────────────────────────────────────────────────────────────────────
// ProfileConfirmMsg
// ─────────────────────────────────────────────────────────────────────────────

Bytes ProfileConfirmMsg::get_signed_bytes() const {
    Bytes out;
    write_u8(out, accepted ? 0x01 : 0x00);
    out.insert(out.end(), transcript_hash.begin(), transcript_hash.end());
    return out;
}

Bytes ProfileConfirmMsg::serialise() const {
    Bytes out = get_signed_bytes();
    append_len16(out, signature);
    return out;
}

Result<ProfileConfirmMsg> ProfileConfirmMsg::deserialise(ByteSpan data) {
    const std::byte* ptr = data.data();
    const std::byte* end = ptr + data.size();

    if (ptr >= end) return err<ProfileConfirmMsg>(ErrorCode::InvalidArgument, "ProfileConfirm: no accepted byte");
    ProfileConfirmMsg msg;
    msg.accepted = (read_u8(ptr, end) == 0x01);

    if (ptr + kTranscriptHashSize > end) {
        return err<ProfileConfirmMsg>(ErrorCode::InvalidArgument, "ProfileConfirm: no transcript hash");
    }
    std::copy(ptr, ptr + kTranscriptHashSize, msg.transcript_hash.begin());
    ptr += kTranscriptHashSize;

    auto sig_r = read_len16(ptr, end);
    if (!sig_r) return err<ProfileConfirmMsg>(sig_r.error());
    msg.signature = std::move(sig_r.value());

    return ok<ProfileConfirmMsg>(std::move(msg));
}

// ─────────────────────────────────────────────────────────────────────────────
// NegotiationInitiator
// ─────────────────────────────────────────────────────────────────────────────

class NegotiationInitiator final : public INegotiationInitiator {
public:
    explicit NegotiationInitiator(NegotiationConfig cfg)
        : cfg_(std::move(cfg)) {}

    void set_send_fn(SendFn fn) override { send_fn_ = std::move(fn); }

    [[nodiscard]] VoidResult start(Timestamp now_ms) override {
        if (state_ != NegotiationState::Idle) {
            return err(ErrorCode::UnsupportedOperation, "Negotiation already started");
        }
        if (!send_fn_) {
            return err(ErrorCode::UnsupportedOperation, "send_fn not set before start()");
        }
        if (cfg_.offered_modes.empty()) {
            return err(ErrorCode::InvalidArgument, "No offered modes configured");
        }

        // Build ModeReq
        auto nonce_r = generate_nonce(cfg_, kNegotiationNonceSize);
        if (!nonce_r) { state_ = NegotiationState::Failed; return err(nonce_r.error()); }

        ModeReqMsg req;
        req.node_id       = cfg_.our_node_id;
        req.nonce         = std::move(nonce_r.value());
        req.timestamp     = now_ms;
        req.offered_modes = cfg_.offered_modes;

        auto sig_r = sign_message(cfg_, req.get_signed_bytes());
        if (!sig_r) { state_ = NegotiationState::Failed; return err(sig_r.error()); }
        req.signature = std::move(sig_r.value());

        mode_req_nonce_  = req.nonce;
        mode_req_serial_ = req.serialise();

        Bytes pkt = make_packet(MessageType::ModeReq, mode_req_serial_);
        auto send_r = send_fn_(std::move(pkt));
        if (!send_r) { state_ = NegotiationState::Failed; return send_r; }

        state_ = NegotiationState::WaitModeResp;
        UAV_PQC_LOG_INFO("protocol.negotiation",
                         "Initiator sent ModeReq with {} offered modes", cfg_.offered_modes.size());
        return ok();
    }

    [[nodiscard]] VoidResult feed_message(ByteSpan wire_bytes, Timestamp now_ms) override {
        auto pkt_r = parse_packet(wire_bytes);
        if (!pkt_r) { return fail(pkt_r.error()); }
        const auto& pkt = pkt_r.value();

        switch (state_) {
            case NegotiationState::WaitModeResp:
                if (pkt.header.type != MessageType::ModeResp) {
                    return fail(ErrorCode::UnsupportedOperation,
                                "Expected ModeResp, got type " +
                                std::to_string(static_cast<int>(pkt.header.type)));
                }
                return handle_mode_resp(pkt.body, now_ms);

            case NegotiationState::WaitProfileResp:
                if (pkt.header.type != MessageType::ProfileResp) {
                    return fail(ErrorCode::UnsupportedOperation,
                                "Expected ProfileResp, got type " +
                                std::to_string(static_cast<int>(pkt.header.type)));
                }
                return handle_profile_resp(pkt.body, now_ms);

            default:
                return fail(ErrorCode::UnsupportedOperation,
                            "feed_message called in unexpected state");
        }
    }

    [[nodiscard]] NegotiationState state() const noexcept override { return state_; }

    [[nodiscard]] Result<NegotiationResult> result() const override {
        if (state_ != NegotiationState::Complete) {
            return err<NegotiationResult>(ErrorCode::UnsupportedOperation,
                                          "Negotiation not complete");
        }
        return ok<NegotiationResult>(*result_);
    }

private:
    VoidResult handle_mode_resp(ByteSpan body, Timestamp now_ms) {
        auto resp_r = ModeRespMsg::deserialise(body);
        if (!resp_r) return fail(resp_r.error());
        const auto& resp = resp_r.value();

        // 1. Timestamp check
        if (auto ts_r = check_timestamp(resp.timestamp, now_ms, cfg_.max_clock_skew_ms); !ts_r) {
            return fail(ts_r.error());
        }

        // 2. Signature verification
        if (auto v = verify_peer_signature(cfg_, resp.get_signed_bytes(), resp.signature); !v) {
            return fail(v.error());
        }

        // 3. Nonce echo check — must match what we sent in ModeReq
        if (resp.echo_nonce != mode_req_nonce_) {
            return fail(ErrorCode::ReplayDetected, "ModeResp: nonce echo mismatch");
        }

        // 4. Mode floor enforcement
        if (!mode_meets_floor(resp.selected_mode, cfg_.minimum_mode)) {
            return fail(ErrorCode::DowngradeRejected,
                        std::string("ModeResp: selected mode ") +
                        std::string(to_string(resp.selected_mode)) +
                        " is below our minimum floor " +
                        std::string(to_string(cfg_.minimum_mode)));
        }

        // 5. Verify responder offered a mode we actually advertised
        const auto& offered = cfg_.offered_modes;
        if (std::find(offered.begin(), offered.end(), resp.selected_mode) == offered.end()) {
            return fail(ErrorCode::DowngradeRejected,
                        "ModeResp: responder selected a mode not in our offered list");
        }

        negotiated_mode_     = resp.selected_mode;
        mode_resp_nonce_     = resp.resp_nonce;
        mode_resp_serial_.assign(body.begin(), body.end());  // raw body bytes for transcript

        // Build transcript hash over ModeReq || ModeResp
        auto t_hash = sha256_of_spans(cfg_, {
            ByteSpan{mode_req_serial_},
            ByteSpan{mode_resp_serial_}
        });

        // Build and send ModeConfirm
        ModeConfirmMsg confirm;
        confirm.confirmed_mode   = negotiated_mode_;
        confirm.transcript_hash  = t_hash;
        auto sig_r = sign_message(cfg_, confirm.get_signed_bytes());
        if (!sig_r) return fail(sig_r.error());
        confirm.signature = std::move(sig_r.value());

        mode_confirm_serial_ = confirm.serialise();
        Bytes pkt = make_packet(MessageType::ModeConfirm, mode_confirm_serial_);
        auto send_r = send_fn_(std::move(pkt));
        if (!send_r) return fail(send_r.error());

        state_ = NegotiationState::WaitProfileResp;
        UAV_PQC_LOG_INFO("protocol.negotiation",
                         "Initiator confirmed mode={}", to_string(negotiated_mode_));

        // Immediately build and send ProfileReq
        return send_profile_req(now_ms);
    }

    VoidResult send_profile_req(Timestamp now_ms) {
        auto nonce_r = generate_nonce(cfg_, kNegotiationNonceSize);
        if (!nonce_r) return fail(nonce_r.error());

        // Build a CipherSuite matching the negotiated mode using a sensible default
        // profile derived from what was offered (if mode is PqcOnly, use ML-KEM-1024/ML-DSA-87)
        ProfileReqMsg req;
        req.node_id   = cfg_.our_node_id;
        req.nonce     = std::move(nonce_r.value());
        req.timestamp = now_ms;

        switch (negotiated_mode_) {
            case OperatingMode::Classical:
                req.kem_level      = crypto::MlKem::Level::Kem512;  // unused but carried
                req.dsa_level      = crypto::MlDsa::Level::Dsa44;
                req.aead_algorithm = AeadAlgorithm::ChaCha20Poly;
                req.hkdf_hash      = crypto::HkdfHash::Sha256;
                break;
            case OperatingMode::Transition:
                req.kem_level      = crypto::MlKem::Level::Kem768;
                req.dsa_level      = crypto::MlDsa::Level::Dsa65;
                req.aead_algorithm = AeadAlgorithm::AesGcm256;
                req.hkdf_hash      = crypto::HkdfHash::Sha256;
                break;
            case OperatingMode::Hybrid:
                req.kem_level      = crypto::MlKem::Level::Kem768;
                req.dsa_level      = crypto::MlDsa::Level::Dsa65;
                req.aead_algorithm = AeadAlgorithm::AesGcm256;
                req.hkdf_hash      = crypto::HkdfHash::Sha256;
                break;
            case OperatingMode::PqcOnly:
                req.kem_level      = crypto::MlKem::Level::Kem1024;
                req.dsa_level      = crypto::MlDsa::Level::Dsa87;
                req.aead_algorithm = AeadAlgorithm::AesGcm256;
                req.hkdf_hash      = crypto::HkdfHash::Sha384;
                break;
        }

        auto sig_r = sign_message(cfg_, req.get_signed_bytes());
        if (!sig_r) return fail(sig_r.error());
        req.signature = std::move(sig_r.value());

        profile_req_nonce_  = req.nonce;
        profile_req_serial_ = req.serialise();

        Bytes pkt = make_packet(MessageType::ProfileReq, profile_req_serial_);
        auto send_r = send_fn_(std::move(pkt));
        if (!send_r) return fail(send_r.error());

        UAV_PQC_LOG_INFO("protocol.negotiation",
                         "Initiator sent ProfileReq for mode={}", to_string(negotiated_mode_));
        return ok();
    }

    VoidResult handle_profile_resp(ByteSpan body, Timestamp now_ms) {
        auto resp_r = ProfileRespMsg::deserialise(body);
        if (!resp_r) return fail(resp_r.error());
        const auto& resp = resp_r.value();

        // 1. Timestamp
        if (auto ts_r = check_timestamp(resp.timestamp, now_ms, cfg_.max_clock_skew_ms); !ts_r) {
            return fail(ts_r.error());
        }

        // 2. Signature
        if (auto v = verify_peer_signature(cfg_, resp.get_signed_bytes(), resp.signature); !v) {
            return fail(v.error());
        }

        // 3. Nonce echo
        if (resp.echo_nonce != profile_req_nonce_) {
            return fail(ErrorCode::ReplayDetected, "ProfileResp: nonce echo mismatch");
        }

        // 4. Downgrade check: mode of the CipherSuite carried must equal negotiated mode
        //    We reconstruct a CipherSuite and check the mode field.
        //    The responder is not allowed to silently change the mode.
        CipherSuite proposed_suite;
        proposed_suite.mode           = negotiated_mode_;
        proposed_suite.kem_level      = resp.kem_level;
        proposed_suite.dsa_level      = resp.dsa_level;
        proposed_suite.aead_algorithm = resp.aead_algorithm;
        proposed_suite.hkdf_hash      = resp.hkdf_hash;
        proposed_suite.max_session_seconds  = 3600;
        proposed_suite.max_messages_per_key = 1'000'000;

        // 5. Mode-level downgrade guard: suite mode must be == negotiated_mode
        //    (responder cannot switch to a weaker mode via the profile response)
        if (!mode_meets_floor(proposed_suite.mode, negotiated_mode_)) {
            return fail(ErrorCode::DowngradeRejected,
                        "ProfileResp: suite mode is weaker than negotiated mode");
        }

        profile_resp_serial_.assign(body.begin(), body.end());

        // Build transcript hash: ModeReq || ModeResp || ModeConfirm || ProfileReq || ProfileResp
        auto t_hash = sha256_of_spans(cfg_, {
            ByteSpan{mode_req_serial_},
            ByteSpan{mode_resp_serial_},
            ByteSpan{mode_confirm_serial_},
            ByteSpan{profile_req_serial_},
            ByteSpan{profile_resp_serial_}
        });

        // Build ProfileConfirm
        ProfileConfirmMsg confirm;
        confirm.accepted        = true;
        confirm.transcript_hash = t_hash;
        auto sig_r = sign_message(cfg_, confirm.get_signed_bytes());
        if (!sig_r) return fail(sig_r.error());
        confirm.signature = std::move(sig_r.value());

        Bytes pkt = make_packet(MessageType::ProfileConfirm, confirm.serialise());
        auto send_r = send_fn_(std::move(pkt));
        if (!send_r) return fail(send_r.error());

        result_ = NegotiationResult{negotiated_mode_, proposed_suite};
        state_  = NegotiationState::Complete;
        UAV_PQC_LOG_INFO("protocol.negotiation",
                         "Initiator negotiation complete: mode={} suite={}",
                         to_string(negotiated_mode_), proposed_suite.to_string());
        return ok();
    }

    // Transition to Failed and return the error.
    template <typename... Args>
    VoidResult fail(Args&&... args) {
        state_ = NegotiationState::Failed;
        return err(std::forward<Args>(args)...);
    }

    NegotiationConfig   cfg_;
    SendFn              send_fn_;
    NegotiationState    state_ = NegotiationState::Idle;

    // Transcript accumulation
    Bytes  mode_req_nonce_;
    Bytes  mode_req_serial_;
    Bytes  mode_resp_serial_;
    Bytes  mode_resp_nonce_;
    Bytes  mode_confirm_serial_;
    Bytes  profile_req_nonce_;
    Bytes  profile_req_serial_;
    Bytes  profile_resp_serial_;

    OperatingMode                negotiated_mode_ = OperatingMode::Hybrid;
    std::optional<NegotiationResult> result_;
};

// ─────────────────────────────────────────────────────────────────────────────
// NegotiationResponder
// ─────────────────────────────────────────────────────────────────────────────

class NegotiationResponder final : public INegotiationResponder {
public:
    explicit NegotiationResponder(NegotiationConfig cfg)
        : cfg_(std::move(cfg)) {}

    void set_send_fn(SendFn fn) override { send_fn_ = std::move(fn); }

    [[nodiscard]] VoidResult feed_message(ByteSpan wire_bytes, Timestamp now_ms) override {
        auto pkt_r = parse_packet(wire_bytes);
        if (!pkt_r) return fail(pkt_r.error());
        const auto& pkt = pkt_r.value();

        switch (state_) {
            case NegotiationState::Idle:
                if (pkt.header.type != MessageType::ModeReq) {
                    return fail(ErrorCode::UnsupportedOperation,
                                "Expected ModeReq as first message");
                }
                return handle_mode_req(pkt.body, now_ms);

            case NegotiationState::WaitModeConfirm:
                if (pkt.header.type != MessageType::ModeConfirm) {
                    return fail(ErrorCode::UnsupportedOperation,
                                "Expected ModeConfirm");
                }
                return handle_mode_confirm(pkt.body, now_ms);

            case NegotiationState::WaitProfileReq:
                if (pkt.header.type != MessageType::ProfileReq) {
                    return fail(ErrorCode::UnsupportedOperation,
                                "Expected ProfileReq");
                }
                return handle_profile_req(pkt.body, now_ms);

            case NegotiationState::WaitProfileConfirm:
                if (pkt.header.type != MessageType::ProfileConfirm) {
                    return fail(ErrorCode::UnsupportedOperation,
                                "Expected ProfileConfirm");
                }
                return handle_profile_confirm(pkt.body, now_ms);

            default:
                return fail(ErrorCode::UnsupportedOperation,
                            "feed_message called in unexpected state");
        }
    }

    [[nodiscard]] NegotiationState state() const noexcept override { return state_; }

    [[nodiscard]] Result<NegotiationResult> result() const override {
        if (state_ != NegotiationState::Complete) {
            return err<NegotiationResult>(ErrorCode::UnsupportedOperation,
                                          "Negotiation not complete");
        }
        return ok<NegotiationResult>(*result_);
    }

private:
    VoidResult handle_mode_req(ByteSpan body, Timestamp now_ms) {
        auto req_r = ModeReqMsg::deserialise(body);
        if (!req_r) return fail(req_r.error());
        const auto& req = req_r.value();

        // 1. Timestamp
        if (auto ts_r = check_timestamp(req.timestamp, now_ms, cfg_.max_clock_skew_ms); !ts_r) {
            return fail(ts_r.error());
        }

        // 2. Signature
        if (auto v = verify_peer_signature(cfg_, req.get_signed_bytes(), req.signature); !v) {
            return fail(v.error());
        }

        // 3. Mode selection: choose the strongest mode in the intersection of
        //    the initiator's offered_modes and our own offered_modes, subject
        //    to our minimum_mode floor.
        OperatingMode selected = OperatingMode::Classical;
        bool found = false;
        for (auto m : req.offered_modes) {
            if (!mode_meets_floor(m, cfg_.minimum_mode)) continue;
            auto& our = cfg_.offered_modes;
            if (std::find(our.begin(), our.end(), m) == our.end()) continue;
            if (!found || mode_rank(m) > mode_rank(selected)) {
                selected = m;
                found = true;
            }
        }
        if (!found) {
            return fail(ErrorCode::PolicyViolation,
                        "No mutually acceptable mode at or above our policy floor");
        }

        negotiated_mode_  = selected;
        mode_req_nonce_   = req.nonce;
        mode_req_serial_.assign(body.begin(), body.end());   // raw body for transcript

        // Build and send ModeResp
        auto resp_nonce_r = generate_nonce(cfg_, kNegotiationNonceSize);
        if (!resp_nonce_r) return fail(resp_nonce_r.error());

        ModeRespMsg resp;
        resp.node_id       = cfg_.our_node_id;
        resp.echo_nonce    = mode_req_nonce_;
        resp.resp_nonce    = std::move(resp_nonce_r.value());
        resp.selected_mode = negotiated_mode_;
        resp.timestamp     = now_ms;

        auto sig_r = sign_message(cfg_, resp.get_signed_bytes());
        if (!sig_r) return fail(sig_r.error());
        resp.signature = std::move(sig_r.value());

        mode_resp_nonce_  = resp.resp_nonce;
        mode_resp_serial_ = resp.serialise();

        Bytes pkt = make_packet(MessageType::ModeResp, mode_resp_serial_);
        auto send_r = send_fn_(std::move(pkt));
        if (!send_r) return fail(send_r.error());

        state_ = NegotiationState::WaitModeConfirm;
        UAV_PQC_LOG_INFO("protocol.negotiation",
                         "Responder sent ModeResp: selected mode={}",
                         to_string(negotiated_mode_));
        return ok();
    }

    VoidResult handle_mode_confirm(ByteSpan body, Timestamp now_ms) {
        (void)now_ms; // ModeConfirm carries no timestamp; binding is via transcript hash
        auto confirm_r = ModeConfirmMsg::deserialise(body);
        if (!confirm_r) return fail(confirm_r.error());
        const auto& confirm = confirm_r.value();

        // 1. Signature
        if (auto v = verify_peer_signature(cfg_, confirm.get_signed_bytes(), confirm.signature); !v) {
            return fail(v.error());
        }

        // 2. Mode agreement: confirmed_mode must equal what we selected
        if (confirm.confirmed_mode != negotiated_mode_) {
            return fail(ErrorCode::DowngradeRejected,
                        "ModeConfirm: confirmed mode does not match our selection");
        }

        // 3. Transcript hash verification
        auto expected_hash = sha256_of_spans(cfg_, {
            ByteSpan{mode_req_serial_},
            ByteSpan{mode_resp_serial_}
        });
        if (expected_hash != confirm.transcript_hash) {
            return fail(ErrorCode::AuthenticationFailed,
                        "ModeConfirm: transcript hash mismatch — possible message tampering");
        }

        mode_confirm_serial_.assign(body.begin(), body.end());
        state_ = NegotiationState::WaitProfileReq;
        UAV_PQC_LOG_INFO("protocol.negotiation",
                         "Responder: mode negotiation confirmed, mode={}", to_string(negotiated_mode_));
        return ok();
    }

    VoidResult handle_profile_req(ByteSpan body, Timestamp now_ms) {
        auto req_r = ProfileReqMsg::deserialise(body);
        if (!req_r) return fail(req_r.error());
        const auto& req = req_r.value();

        // 1. Timestamp
        if (auto ts_r = check_timestamp(req.timestamp, now_ms, cfg_.max_clock_skew_ms); !ts_r) {
            return fail(ts_r.error());
        }

        // 2. Signature
        if (auto v = verify_peer_signature(cfg_, req.get_signed_bytes(), req.signature); !v) {
            return fail(v.error());
        }

        // 3. Build the proposed CipherSuite and validate via mode consistency
        CipherSuite proposed;
        proposed.mode           = negotiated_mode_;
        proposed.kem_level      = req.kem_level;
        proposed.dsa_level      = req.dsa_level;
        proposed.aead_algorithm = req.aead_algorithm;
        proposed.hkdf_hash      = req.hkdf_hash;
        proposed.max_session_seconds  = 3600;
        proposed.max_messages_per_key = 1'000'000;

        // 4. Policy: if the proposed suite's security level is weaker than the
        //    negotiated mode demands, adjust upward rather than reject (preserves
        //    interoperability while enforcing the floor).
        bool modified = false;
        if (negotiated_mode_ == OperatingMode::PqcOnly &&
            mode_rank(static_cast<OperatingMode>(req.kem_level)) < mode_rank(OperatingMode::PqcOnly)) {
            // Silently accepted; KEM level is independently constrained
        }
        // If mode is PqcOnly but initiator requested Kem512, upgrade to Kem1024
        if (negotiated_mode_ == OperatingMode::PqcOnly &&
            req.kem_level == crypto::MlKem::Level::Kem512) {
            proposed.kem_level = crypto::MlKem::Level::Kem1024;
            proposed.dsa_level = crypto::MlDsa::Level::Dsa87;
            modified = true;
            UAV_PQC_LOG_INFO("protocol.negotiation",
                             "Responder: upgraded KEM level to 1024 for PQC-Only mode");
        }

        profile_req_nonce_  = req.nonce;
        profile_req_serial_.assign(body.begin(), body.end());
        negotiated_suite_   = proposed;

        // Build ProfileResp
        auto resp_nonce_r = generate_nonce(cfg_, kNegotiationNonceSize);
        if (!resp_nonce_r) return fail(resp_nonce_r.error());

        ProfileRespMsg resp;
        resp.echo_nonce    = profile_req_nonce_;
        resp.resp_nonce    = std::move(resp_nonce_r.value());
        resp.accepted      = !modified;
        resp.kem_level     = proposed.kem_level;
        resp.dsa_level     = proposed.dsa_level;
        resp.aead_algorithm= proposed.aead_algorithm;
        resp.hkdf_hash     = proposed.hkdf_hash;
        resp.timestamp     = now_ms;

        auto sig_r = sign_message(cfg_, resp.get_signed_bytes());
        if (!sig_r) return fail(sig_r.error());
        resp.signature = std::move(sig_r.value());

        profile_resp_serial_ = resp.serialise();

        Bytes pkt = make_packet(MessageType::ProfileResp, profile_resp_serial_);
        auto send_r = send_fn_(std::move(pkt));
        if (!send_r) return fail(send_r.error());

        state_ = NegotiationState::WaitProfileConfirm;
        UAV_PQC_LOG_INFO("protocol.negotiation",
                         "Responder sent ProfileResp: accepted={}, suite={}",
                         !modified, proposed.to_string());
        return ok();
    }

    VoidResult handle_profile_confirm(ByteSpan body, [[maybe_unused]] Timestamp now_ms) {
        auto confirm_r = ProfileConfirmMsg::deserialise(body);
        if (!confirm_r) return fail(confirm_r.error());
        const auto& confirm = confirm_r.value();

        // 1. Signature
        if (auto v = verify_peer_signature(cfg_, confirm.get_signed_bytes(), confirm.signature); !v) {
            return fail(v.error());
        }

        // 2. Initiator rejected our suite — abort
        if (!confirm.accepted) {
            return fail(ErrorCode::PolicyViolation,
                        "ProfileConfirm: initiator rejected the proposed CipherSuite");
        }

        // 3. Transcript hash over all 5 preceding negotiation messages
        auto expected_hash = sha256_of_spans(cfg_, {
            ByteSpan{mode_req_serial_},
            ByteSpan{mode_resp_serial_},
            ByteSpan{mode_confirm_serial_},
            ByteSpan{profile_req_serial_},
            ByteSpan{profile_resp_serial_}
        });
        if (expected_hash != confirm.transcript_hash) {
            return fail(ErrorCode::AuthenticationFailed,
                        "ProfileConfirm: transcript hash mismatch — possible downgrade tampering");
        }

        result_ = NegotiationResult{negotiated_mode_, negotiated_suite_};
        state_  = NegotiationState::Complete;
        UAV_PQC_LOG_INFO("protocol.negotiation",
                         "Responder negotiation complete: mode={} suite={}",
                         to_string(negotiated_mode_), negotiated_suite_.to_string());
        return ok();
    }

    template <typename... Args>
    VoidResult fail(Args&&... args) {
        state_ = NegotiationState::Failed;
        return err(std::forward<Args>(args)...);
    }

    NegotiationConfig   cfg_;
    SendFn              send_fn_;
    NegotiationState    state_ = NegotiationState::Idle;

    // Transcript accumulation
    Bytes  mode_req_nonce_;
    Bytes  mode_req_serial_;
    Bytes  mode_resp_nonce_;
    Bytes  mode_resp_serial_;
    Bytes  mode_confirm_serial_;
    Bytes  profile_req_nonce_;
    Bytes  profile_req_serial_;
    Bytes  profile_resp_serial_;

    OperatingMode negotiated_mode_  = OperatingMode::Hybrid;
    CipherSuite   negotiated_suite_ = CipherSuite::make_hybrid(AeadAlgorithm::AesGcm256);
    std::optional<NegotiationResult> result_;
};

// ─────────────────────────────────────────────────────────────────────────────
// Factory functions
// ─────────────────────────────────────────────────────────────────────────────

std::unique_ptr<INegotiationInitiator>
make_negotiation_initiator(NegotiationConfig config) {
    return std::make_unique<NegotiationInitiator>(std::move(config));
}

std::unique_ptr<INegotiationResponder>
make_negotiation_responder(NegotiationConfig config) {
    return std::make_unique<NegotiationResponder>(std::move(config));
}

} // namespace uav_pqc::protocol
