// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file message.cpp
 * @brief Wire serialization/deserialization implementations for handshake messages.
 */

#include "uav_pqc/protocol/message.hpp"
#include "uav_pqc/diagnostics/metrics.hpp"
#include <cstring>
#include <algorithm>

namespace uav_pqc::protocol {

namespace {

// Helper: write 16-bit big-endian
void write_u16_be(std::byte* dest, std::uint16_t val) noexcept {
    dest[0] = static_cast<std::byte>((val >> 8) & 0xFF);
    dest[1] = static_cast<std::byte>(val & 0xFF);
}

// Helper: read 16-bit big-endian
std::uint16_t read_u16_be(const std::byte* src) noexcept {
    return (static_cast<std::uint16_t>(src[0]) << 8) | static_cast<std::uint16_t>(src[1]);
}

// Helper: write 32-bit big-endian
void write_u32_be(std::byte* dest, std::uint32_t val) noexcept {
    dest[0] = static_cast<std::byte>((val >> 24) & 0xFF);
    dest[1] = static_cast<std::byte>((val >> 16) & 0xFF);
    dest[2] = static_cast<std::byte>((val >> 8) & 0xFF);
    dest[3] = static_cast<std::byte>(val & 0xFF);
}

// Helper: read 32-bit big-endian
std::uint32_t read_u32_be(const std::byte* src) noexcept {
    return (static_cast<std::uint32_t>(src[0]) << 24) |
           (static_cast<std::uint32_t>(src[1]) << 16) |
           (static_cast<std::uint32_t>(src[2]) << 8) |
           static_cast<std::uint32_t>(src[3]);
}

// Append a vector of bytes with a 16-bit length prefix
void append_len16_bytes(Bytes& dest, const Bytes& src) {
    const std::uint16_t len = static_cast<std::uint16_t>(src.size());
    std::byte len_buf[2];
    write_u16_be(len_buf, len);
    dest.push_back(len_buf[0]);
    dest.push_back(len_buf[1]);
    dest.insert(dest.end(), src.begin(), src.end());
}

// Read a vector of bytes with a 16-bit length prefix from a cursor
Result<Bytes> read_len16_bytes(const std::byte*& ptr, const std::byte* end) {
    if (ptr + 2 > end) {
        return err<Bytes>(ErrorCode::InvalidArgument, "Truncated length prefix");
    }
    const std::uint16_t len = read_u16_be(ptr);
    ptr += 2;
    if (ptr + len > end) {
        return err<Bytes>(ErrorCode::InvalidArgument, "Truncated value body");
    }
    Bytes res(ptr, ptr + len);
    ptr += len;
    return ok<Bytes>(std::move(res));
}

} // anonymous namespace

// ── MessageHeader ─────────────────────────────────────────────────────────────

Bytes MessageHeader::serialise() const {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::Serialization);
    Bytes out(kWireSize);
    std::byte* p = out.data();

    p[0] = static_cast<std::byte>(type);
    p[1] = static_cast<std::byte>(version);
    write_u16_be(p + 2, length);
    std::copy(session_id.begin(), session_id.end(), p + 4);
    write_u64_be(MutableByteSpan{p + 20, 8}, sequence_number);

    return out;
}

Bytes UniversalHeader::serialise() const {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::Serialization);
    Bytes out(kWireSize);
    std::byte* p = out.data();

    write_u32_be(p, magic);
    p[4] = static_cast<std::byte>(version);
    p[5] = static_cast<std::byte>(protocol_id);
    p[6] = static_cast<std::byte>(message_type);
    write_u32_be(p + 7, payload_length);
    std::copy(session_id.begin(), session_id.end(), p + 11);
    write_u32_be(p + 27, flags);

    return out;
}

Result<UniversalHeader> UniversalHeader::deserialise(ByteSpan data) {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::Serialization);
    if (data.size() < kWireSize) {
        return err<UniversalHeader>(ErrorCode::InvalidArgument, "Universal Header buffer too small");
    }
    const std::byte* p = data.data();

    UniversalHeader hdr;
    hdr.magic = read_u32_be(p);
    if (hdr.magic != kMagic) {
        return err<UniversalHeader>(ErrorCode::InvalidArgument, "Invalid Universal Header Magic Number");
    }
    hdr.version = static_cast<std::uint8_t>(p[4]);
    hdr.protocol_id = static_cast<ProtocolID>(p[5]);
    hdr.message_type = static_cast<std::uint8_t>(p[6]);
    hdr.payload_length = read_u32_be(p + 7);
    std::copy(p + 11, p + 27, hdr.session_id.begin());
    hdr.flags = read_u32_be(p + 27);

    return ok<UniversalHeader>(hdr);
}

Result<MessageHeader> MessageHeader::deserialise(ByteSpan data) {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::Serialization);
    if (data.size() < kWireSize) {
        return err<MessageHeader>(ErrorCode::InvalidArgument, "Header buffer too small");
    }
    const std::byte* p = data.data();

    MessageHeader hdr;
    hdr.type            = static_cast<MessageType>(p[0]);
    hdr.version         = static_cast<std::uint8_t>(p[1]);
    hdr.length          = read_u16_be(p + 2);
    std::copy(p + 4, p + 20, hdr.session_id.begin());
    hdr.sequence_number = read_u64_be(data.subspan(20, 8));

    return ok<MessageHeader>(hdr);
}

// ── ClientHello ───────────────────────────────────────────────────────────────

Bytes ClientHello::serialise() const {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::Serialization);
    Bytes out;
    out.reserve(32 + 32 + 2 + supported_modes.size() + 4 + 4 + kem_public_key.size() + x25519_public_key.size());

    // node_id
    out.insert(out.end(), node_id.begin(), node_id.end());

    // client_random (exactly 32 bytes or padded/truncated)
    Bytes rnd = client_random;
    rnd.resize(32, std::byte{0});
    out.insert(out.end(), rnd.begin(), rnd.end());

    // supported_modes
    out.push_back(static_cast<std::byte>(supported_modes.size()));
    for (auto m : supported_modes) {
        out.push_back(static_cast<std::byte>(m));
    }

    // kem_public_key
    append_len16_bytes(out, kem_public_key);

    // x25519_public_key
    append_len16_bytes(out, x25519_public_key);

    // protocol_version
    std::byte ver_buf[4];
    write_u32_be(ver_buf, protocol_version);
    out.insert(out.end(), ver_buf, ver_buf + 4);

    return out;
}

Result<ClientHello> ClientHello::deserialise(ByteSpan data) {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::Serialization);
    if (data.size() < 32 + 32 + 1) {
        return err<ClientHello>(ErrorCode::InvalidArgument, "ClientHello too short");
    }
    const std::byte* ptr = data.data();
    const std::byte* end = data.data() + data.size();

    ClientHello ch;

    // node_id
    std::copy(ptr, ptr + 32, ch.node_id.begin());
    ptr += 32;

    // client_random
    ch.client_random.assign(ptr, ptr + 32);
    ptr += 32;

    // supported_modes
    const std::uint8_t mode_count = static_cast<std::uint8_t>(*ptr++);
    if (ptr + mode_count > end) {
        return err<ClientHello>(ErrorCode::InvalidArgument, "ClientHello truncated modes");
    }
    ch.supported_modes.reserve(mode_count);
    for (std::uint8_t i = 0; i < mode_count; ++i) {
        ch.supported_modes.push_back(static_cast<OperatingMode>(*ptr++));
    }

    // kem_public_key
    auto pk_r = read_len16_bytes(ptr, end);
    if (!pk_r) return err<ClientHello>(pk_r.error());
    ch.kem_public_key = std::move(pk_r.value());

    // x25519_public_key
    auto x25519_r = read_len16_bytes(ptr, end);
    if (!x25519_r) return err<ClientHello>(x25519_r.error());
    ch.x25519_public_key = std::move(x25519_r.value());

    // protocol_version
    if (ptr + 4 > end) {
        return err<ClientHello>(ErrorCode::InvalidArgument, "ClientHello truncated version");
    }
    ch.protocol_version = read_u32_be(ptr);
    ptr += 4;

    return ok<ClientHello>(std::move(ch));
}

// ── ServerHello ───────────────────────────────────────────────────────────────

Bytes ServerHello::serialise() const {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::Serialization);
    Bytes out;
    out.reserve(32 + 32 + 1 + 15 + kem_ciphertext.size() + x25519_public_key.size());

    // node_id
    out.insert(out.end(), node_id.begin(), node_id.end());

    // server_random
    Bytes rnd = server_random;
    rnd.resize(32, std::byte{0});
    out.insert(out.end(), rnd.begin(), rnd.end());

    // selected_mode
    out.push_back(static_cast<std::byte>(selected_mode));

    // cipher_suite
    out.push_back(static_cast<std::byte>(cipher_suite.mode));
    out.push_back(static_cast<std::byte>(cipher_suite.kem_level));
    out.push_back(static_cast<std::byte>(cipher_suite.dsa_level));
    out.push_back(static_cast<std::byte>(cipher_suite.aead_algorithm));
    out.push_back(static_cast<std::byte>(cipher_suite.hkdf_hash));

    std::byte max_sec_buf[4];
    write_u32_be(max_sec_buf, cipher_suite.max_session_seconds);
    out.insert(out.end(), max_sec_buf, max_sec_buf + 4);

    std::byte max_msg_buf[8];
    write_u64_be(MutableByteSpan{max_msg_buf, 8}, cipher_suite.max_messages_per_key);
    out.insert(out.end(), max_msg_buf, max_msg_buf + 8);

    // kem_ciphertext
    append_len16_bytes(out, kem_ciphertext);

    // x25519_public_key
    append_len16_bytes(out, x25519_public_key);

    return out;
}

Result<ServerHello> ServerHello::deserialise(ByteSpan data) {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::Serialization);
    if (data.size() < 32 + 32 + 1 + 17) {
        return err<ServerHello>(ErrorCode::InvalidArgument, "ServerHello too short");
    }
    const std::byte* ptr = data.data();
    const std::byte* end = data.data() + data.size();

    ServerHello sh;

    // node_id
    std::copy(ptr, ptr + 32, sh.node_id.begin());
    ptr += 32;

    // server_random
    sh.server_random.assign(ptr, ptr + 32);
    ptr += 32;

    // selected_mode
    sh.selected_mode = static_cast<OperatingMode>(*ptr++);

    // cipher_suite
    sh.cipher_suite.mode           = static_cast<OperatingMode>(*ptr++);
    sh.cipher_suite.kem_level      = static_cast<crypto::MlKem::Level>(*ptr++);
    sh.cipher_suite.dsa_level      = static_cast<crypto::MlDsa::Level>(*ptr++);
    sh.cipher_suite.aead_algorithm = static_cast<AeadAlgorithm>(*ptr++);
    sh.cipher_suite.hkdf_hash      = static_cast<crypto::HkdfHash>(*ptr++);

    sh.cipher_suite.max_session_seconds = read_u32_be(ptr);
    ptr += 4;

    sh.cipher_suite.max_messages_per_key = read_u64_be(ByteSpan{ptr, 8});
    ptr += 8;

    // kem_ciphertext
    auto ct_r = read_len16_bytes(ptr, end);
    if (!ct_r) return err<ServerHello>(ct_r.error());
    sh.kem_ciphertext = std::move(ct_r.value());

    // x25519_public_key
    auto x25519_r = read_len16_bytes(ptr, end);
    if (!x25519_r) return err<ServerHello>(x25519_r.error());
    sh.x25519_public_key = std::move(x25519_r.value());

    return ok<ServerHello>(std::move(sh));
}

// ── AuthMessage ───────────────────────────────────────────────────────────────

Bytes AuthMessage::serialise() const {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::Serialization);
    Bytes out;
    out.reserve(certificate_chain.size() + ml_dsa_signature.size() + ecdsa_signature.size() + 6);

    append_len16_bytes(out, certificate_chain);
    append_len16_bytes(out, ml_dsa_signature);
    append_len16_bytes(out, ecdsa_signature);

    return out;
}

Result<AuthMessage> AuthMessage::deserialise(ByteSpan data) {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::Serialization);
    const std::byte* ptr = data.data();
    const std::byte* end = data.data() + data.size();

    AuthMessage am;

    auto cc_r = read_len16_bytes(ptr, end);
    if (!cc_r) return err<AuthMessage>(cc_r.error());
    am.certificate_chain = std::move(cc_r.value());

    auto ml_r = read_len16_bytes(ptr, end);
    if (!ml_r) return err<AuthMessage>(ml_r.error());
    am.ml_dsa_signature = std::move(ml_r.value());

    auto ec_r = read_len16_bytes(ptr, end);
    if (!ec_r) return err<AuthMessage>(ec_r.error());
    am.ecdsa_signature = std::move(ec_r.value());

    return ok<AuthMessage>(std::move(am));
}

// ── HandshakeFinished ─────────────────────────────────────────────────────────

Bytes HandshakeFinished::serialise() const {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::Serialization);
    Bytes out(32);
    std::copy(verify_data.begin(), verify_data.end(), out.begin());
    return out;
}

Result<HandshakeFinished> HandshakeFinished::deserialise(ByteSpan data) {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::Serialization);
    if (data.size() < 32) {
        return err<HandshakeFinished>(ErrorCode::InvalidArgument, "HandshakeFinished too short");
    }
    HandshakeFinished hf;
    std::copy(data.data(), data.data() + 32, hf.verify_data.begin());
    return ok<HandshakeFinished>(hf);
}

// ── AlertMessage ──────────────────────────────────────────────────────────────

Bytes AlertMessage::serialise() const {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::Serialization);
    Bytes out;
    out.reserve(2 + 2 + description.size());
    out.push_back(static_cast<std::byte>(level));
    out.push_back(static_cast<std::byte>(code));

    const std::uint16_t len = static_cast<std::uint16_t>(description.size());
    std::byte len_buf[2];
    write_u16_be(len_buf, len);
    out.push_back(len_buf[0]);
    out.push_back(len_buf[1]);

    const std::byte* desc_ptr = reinterpret_cast<const std::byte*>(description.data());
    out.insert(out.end(), desc_ptr, desc_ptr + len);

    return out;
}

Result<AlertMessage> AlertMessage::deserialise(ByteSpan data) {
    diagnostics::ScopedProfiler profiler(diagnostics::OpKind::Serialization);
    if (data.size() < 4) {
        return err<AlertMessage>(ErrorCode::InvalidArgument, "AlertMessage too short");
    }
    const std::byte* ptr = data.data();
    const std::byte* end = data.data() + data.size();

    AlertMessage am;
    am.level = static_cast<AlertLevel>(*ptr++);
    am.code  = static_cast<AlertCode>(*ptr++);

    const std::uint16_t len = read_u16_be(ptr);
    ptr += 2;

    if (ptr + len > end) {
        return err<AlertMessage>(ErrorCode::InvalidArgument, "AlertMessage truncated description");
    }
    am.description.assign(reinterpret_cast<const char*>(ptr), len);

    return ok<AlertMessage>(std::move(am));
}

Bytes wrap_packet(ProtocolID id, ByteSpan payload, std::uint8_t msg_type, const SessionId& session_id, std::uint32_t flags) {
    UniversalHeader uhdr{
        .magic = UniversalHeader::kMagic,
        .version = 0x01,
        .protocol_id = id,
        .message_type = msg_type,
        .payload_length = static_cast<std::uint32_t>(payload.size()),
        .session_id = session_id,
        .flags = flags
    };
    Bytes out = uhdr.serialise();
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

} // namespace uav_pqc::protocol
