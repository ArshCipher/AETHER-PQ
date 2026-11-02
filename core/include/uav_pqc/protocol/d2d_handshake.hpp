// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file d2d_handshake.hpp
 * @brief Direct peer-to-peer autonomous PQC key exchange between UAV nodes.
 */

#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/types.hpp"
#include "uav_pqc/crypto/kem.hpp"
#include "uav_pqc/crypto/dsa.hpp"
#include "uav_pqc/session/d2d_session.hpp"

#include <memory>
#include <unordered_map>
#include <mutex>
#include <optional>

namespace uav_pqc::protocol {

struct NodeIdHash {
    std::size_t operator()(const NodeId& id) const noexcept {
        std::size_t hash = 0;
        for (auto b : id) {
            hash = (hash * 31) + static_cast<std::size_t>(b);
        }
        return hash;
    }
};

struct D2DDirectHelloPayload {
    NodeId      initiator_id{};
    NodeId      target_id{};
    Nonce<16>   nonce{};
    Bytes       kem_public_key;
    Bytes       initiator_cert;

    [[nodiscard]] Bytes serialize() const;
    [[nodiscard]] static Result<D2DDirectHelloPayload> deserialize(ByteSpan bytes);
};

struct D2DDirectRespPayload {
    NodeId      target_id{};
    NodeId      initiator_id{};
    SessionId   session_id{};
    Nonce<16>   nonce{};
    Bytes       kem_ciphertext;
    Bytes       target_cert;
    Bytes       signature;

    [[nodiscard]] Bytes serialize() const;
    [[nodiscard]] static Result<D2DDirectRespPayload> deserialize(ByteSpan bytes);
};

struct D2DDirectConfirmPayload {
    NodeId      initiator_id{};
    NodeId      target_id{};
    SessionId   session_id{};
    Bytes       confirm_tag;

    [[nodiscard]] Bytes serialize() const;
    [[nodiscard]] static Result<D2DDirectConfirmPayload> deserialize(ByteSpan bytes);
};

class D2DHandshakeManager {
public:
    D2DHandshakeManager(
        const NodeId& self_id,
        std::shared_ptr<crypto::IKem> kem_engine,
        std::shared_ptr<crypto::IDsa> dsa_engine,
        Bytes self_cert
    );
    ~D2DHandshakeManager() = default;

    /**
     * @brief Step 1 (Initiator): Generate D2DDirectHello payload for target node.
     */
    Result<D2DDirectHelloPayload> initiate_handshake(const NodeId& target_id);

    /**
     * @brief Step 2 (Responder): Process D2DDirectHello, generate D2DDirectResp, and produce active D2DSession.
     */
    Result<std::pair<D2DDirectRespPayload, session::D2DSession>> process_hello(
        const D2DDirectHelloPayload& hello,
        Timestamp now_ms
    );

    /**
     * @brief Step 3 (Initiator): Process D2DDirectResp, decapsulate secret, and produce active D2DSession.
     */
    Result<session::D2DSession> process_resp(
        const D2DDirectRespPayload& resp,
        Timestamp now_ms
    );

private:
    struct PendingState {
        NodeId                  target_id{};
        Nonce<16>               nonce{};
        crypto::KemKeyPair      kem_keypair;
        Timestamp               created_at_ms = 0;
    };

    NodeId self_id_;
    std::shared_ptr<crypto::IKem> kem_engine_;
    std::shared_ptr<crypto::IDsa> dsa_engine_;
    Bytes self_cert_;

    std::mutex mutex_;
    std::unordered_map<NodeId, PendingState, NodeIdHash> pending_handshakes_;
};

} // namespace uav_pqc::protocol
