#pragma once
#include "uav_pqc/common/error.hpp"
#include "uav_pqc/session/session.hpp"
#include "uav_pqc/session/session_cache.hpp"
#include "uav_pqc/group/group_key.hpp"
#include "uav_pqc/common/types.hpp"
#include "uav_pqc/platform/clock.hpp"
#include "uav_pqc/crypto/provider.hpp"

#include <mutex>
#include <unordered_map>
#include <memory>
#include <optional>

namespace uav_pqc::app {

/**
 * @brief Abstract SessionManager interface.
 */
class ISessionManager {
public:
    ISessionManager() = default;
    virtual ~ISessionManager() = default;

    ISessionManager(const ISessionManager&) = delete;
    ISessionManager& operator=(const ISessionManager&) = delete;
    ISessionManager(ISessionManager&&) noexcept = default;
    ISessionManager& operator=(ISessionManager&&) noexcept = default;

    virtual VoidResult add_session(session::Session session, Timestamp now_ms = 0) = 0;
    virtual Result<session::Session*> get_session(const SessionId& id, const NodeId& peer, Timestamp now_ms = 0) = 0;
    virtual void set_group_key(group::GroupKey group_key) = 0;
    virtual const group::GroupKey* get_group_key() const noexcept = 0;
    
    // Encrypt/decrypt group communication
    virtual Result<Bytes> encrypt_group_broadcast(ByteSpan plaintext, ByteSpan aad, std::uint64_t counter) = 0;
    virtual Result<Bytes> decrypt_group_broadcast(ByteSpan ciphertext, ByteSpan aad, std::uint64_t counter) = 0;

    virtual void clear_sessions() = 0;
};

/**
 * @brief Concrete SessionManager class managing session cache, key lookups, and group broadcast keys.
 */
class SessionManager final : public ISessionManager {
public:
    explicit SessionManager(std::shared_ptr<platform::IClock> clock = nullptr, std::size_t cache_capacity = 100, Timestamp session_ttl_ms = 3600000, std::shared_ptr<crypto::ICryptoProvider> crypto_provider = nullptr);
    ~SessionManager() override = default;

    VoidResult add_session(session::Session session, Timestamp now_ms = 0) override;
    Result<session::Session*> get_session(const SessionId& id, const NodeId& peer, Timestamp now_ms = 0) override;
    void set_group_key(group::GroupKey group_key) override;
    const group::GroupKey* get_group_key() const noexcept override;

    Result<Bytes> encrypt_group_broadcast(ByteSpan plaintext, ByteSpan aad, std::uint64_t counter) override;
    Result<Bytes> decrypt_group_broadcast(ByteSpan ciphertext, ByteSpan aad, std::uint64_t counter) override;

    void clear_sessions() override;

private:
    struct SessionIdHash {
        std::size_t operator()(const SessionId& id) const noexcept {
            std::size_t hash = 0;
            for (auto b : id) {
                hash = (hash * 31) + static_cast<std::size_t>(b);
            }
            return hash;
        }
    };

    std::mutex mutex_;
    session::SessionCache cache_;
    std::optional<group::GroupKey> group_key_;
    std::unordered_map<SessionId, session::Session, SessionIdHash> active_sessions_;
    std::shared_ptr<platform::IClock> clock_;
    std::shared_ptr<crypto::ICryptoProvider> crypto_provider_;
};

} // namespace uav_pqc::app
