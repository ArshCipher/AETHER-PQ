// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file channel_emulator.hpp
 * @brief Software-defined network channel emulator for the UAV-PQC simulator.
 *
 * Provides configurable impairment of a virtual link between two nodes without
 * requiring ns-3 or any OS networking stack.  All nine impairment dimensions
 * are supported:
 *
 *   1. Propagation delay  — fixed one-way latency (ms)
 *   2. Transmission delay — serialisation delay from finite bandwidth
 *   3. Jitter             — Gaussian per-packet delay variation
 *   4. Packet loss        — Gilbert-Elliott two-state burst-loss model
 *   5. Duplication        — probabilistic cloning of delivered packets
 *   6. Reordering         — probabilistic delivery-order inversion
 *   7. Congestion         — FIFO queue with configurable depth limit
 *   8. Bandwidth limit    — token-bucket rate shaping (bytes/s)
 *   9. Queue overflow     — tail-drop when the congestion queue is full
 *
 * Profiles are loaded from JSON; five built-in presets are provided
 * (ideal_lan, wifi, 5g, satellite, custom).
 *
 * Thread safety: ChannelEmulator is NOT thread-safe.  The standalone
 * SimulationEngine runs single-threaded, so no locking is required there.
 * If used from multiple threads wrap external to this class.
 */

#include "uav_pqc/common/types.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <optional>
#include <random>
#include <string>
#include <vector>

namespace uav_pqc::transport {

// ─────────────────────────────────────────────────────────────────────────────
// Packet fate enumeration — recorded per packet in the trace log
// ─────────────────────────────────────────────────────────────────────────────

enum class PacketFate : uint8_t {
    Delivered    = 0,  ///< Packet reached the receiver
    Dropped      = 1,  ///< Dropped by the loss model
    QueueOverflow= 2,  ///< Tail-dropped because the congestion queue was full
    Duplicated   = 3,  ///< Packet was delivered AND a duplicate was injected
    Reordered    = 4,  ///< Packet was delivered out of order
};

// ─────────────────────────────────────────────────────────────────────────────
// Per-packet record (optional full trace; disable for large swarm runs)
// ─────────────────────────────────────────────────────────────────────────────

struct PacketRecord {
    uint64_t    seq;               ///< Monotonic per-emulator sequence number
    uint64_t    enqueue_time_ms;   ///< Virtual time when packet was submitted
    uint64_t    deliver_time_ms;   ///< Virtual time when packet was (or would be) delivered
    uint64_t    size_bytes;        ///< Payload size in bytes
    PacketFate  fate;
    double      total_delay_ms;    ///< Actual emulated delay applied (0 if dropped)
    NodeId      src;
    NodeId      dst;
};

// ─────────────────────────────────────────────────────────────────────────────
// Aggregate per-link statistics
// ─────────────────────────────────────────────────────────────────────────────

struct ChannelStats {
    uint64_t packets_enqueued    = 0;
    uint64_t packets_delivered   = 0;
    uint64_t packets_dropped     = 0;   ///< Loss-model drops
    uint64_t packets_overflow    = 0;   ///< Queue-overflow tail-drops
    uint64_t packets_duplicated  = 0;
    uint64_t packets_reordered   = 0;
    uint64_t bytes_enqueued      = 0;
    uint64_t bytes_delivered     = 0;
    uint64_t bytes_dropped       = 0;

    double   min_delay_ms        = 1e18;
    double   max_delay_ms        = 0.0;
    double   sum_delay_ms        = 0.0;  ///< For mean calculation
    double   sum_delay_sq_ms     = 0.0;  ///< For variance / jitter calculation

    /// Computed fields (call finalize() after simulation ends)
    double   avg_delay_ms        = 0.0;
    double   measured_jitter_ms  = 0.0;  ///< √(E[delay²] − E[delay]²)
    double   loss_rate           = 0.0;  ///< packets_dropped / packets_enqueued
    double   effective_throughput_bps = 0.0;

    /// Called once at end of simulation to compute derived fields.
    void finalize(double sim_duration_ms) noexcept;

    /// Serialize to JSON.
    [[nodiscard]] nlohmann::json to_json() const;
};

// ─────────────────────────────────────────────────────────────────────────────
// Channel parameter set
// ─────────────────────────────────────────────────────────────────────────────

struct ChannelParams {
    // ── Delay ─────────────────────────────────────────────────────────────
    double   propagation_delay_ms  = 15.0;   ///< Fixed one-way propagation delay
    double   jitter_stddev_ms      = 2.0;    ///< Gaussian jitter σ (0 = no jitter)

    // ── Bandwidth & transmission delay ────────────────────────────────────
    double   bandwidth_bps         = 54e6;   ///< Link bandwidth (bits/s); 0 = unlimited
    uint64_t queue_max_packets     = 64;     ///< Max packets in congestion queue; 0 = unlimited

    // ── Loss (Gilbert-Elliott two-state model) ────────────────────────────
    // State transitions: Good→Bad with prob p_gb, Bad→Good with prob p_bg.
    // Loss probability in Good state = loss_good; in Bad state = loss_bad.
    // Set p_gb = 0 to degenerate to simple Bernoulli with rate = loss_good.
    double   loss_good             = 0.01;   ///< Loss prob in Good (normal) state
    double   loss_bad              = 0.50;   ///< Loss prob in Bad (burst) state
    double   p_gb                  = 0.005;  ///< Good→Bad transition probability
    double   p_bg                  = 0.10;   ///< Bad→Good transition probability

    // ── Duplication ───────────────────────────────────────────────────────
    double   duplicate_prob        = 0.001;  ///< Probability a delivered pkt is duplicated
    double   duplicate_delay_ms    = 1.0;    ///< Extra delay for duplicate (ms)

    // ── Reordering ────────────────────────────────────────────────────────
    double   reorder_prob          = 0.005;  ///< Probability a packet is held for reorder
    double   reorder_delay_ms      = 5.0;    ///< Extra delay applied to reordered packet

    // ── Trace ─────────────────────────────────────────────────────────────
    bool     enable_trace          = false;  ///< Collect per-packet PacketRecord log

    /// Load from a JSON object.  Missing keys keep their default values.
    static ChannelParams from_json(const nlohmann::json& j);

    /// Serialize to JSON.
    [[nodiscard]] nlohmann::json to_json() const;
};

// ─────────────────────────────────────────────────────────────────────────────
// Named profile factory
// ─────────────────────────────────────────────────────────────────────────────

struct ChannelProfile {
    std::string   name;
    std::string   description;
    ChannelParams params;

    /// Load the named profile from a JSON profiles file.
    /// Throws std::runtime_error if the profile is not found.
    static ChannelProfile load(const std::string& profile_name,
                               const std::string& json_path);

    /// Return a profile from an in-memory JSON document (profiles array).
    static ChannelProfile from_json(const std::string& profile_name,
                                    const nlohmann::json& profiles_doc);

    /// Return a built-in profile by name without touching the filesystem.
    static ChannelProfile builtin(const std::string& profile_name);

    /// Enumerate the five built-in profile names.
    static std::vector<std::string> builtin_names();
};

// ─────────────────────────────────────────────────────────────────────────────
// ChannelEmulator — core impairment engine
// ─────────────────────────────────────────────────────────────────────────────

/**
 * @brief Emulates all nine network impairments on a virtual link.
 *
 * Usage (inside SimulationEngine::route_packet):
 * @code
 *   emulator_.route(src, dst, packet, now_ms(),
 *                   [&](uint64_t delivery_ms, const NodeId& s,
 *                       const NodeId& d, const Bytes& pkt) {
 *                       schedule(delivery_ms, [=]{ deliver(s, d, pkt); });
 *                   });
 * @endcode
 *
 * The delivery_callback is invoked once per packet that survives the loss
 * model (and a second time for duplicates).  The caller is responsible for
 * scheduling the actual delivery at `delivery_ms`.
 */
class ChannelEmulator {
public:
    /// Callback type: (virtual_delivery_time_ms, src, dst, payload)
    using DeliveryCallback = std::function<void(uint64_t delivery_ms,
                                                 const NodeId& src,
                                                 const NodeId& dst,
                                                 const Bytes& payload)>;

    explicit ChannelEmulator(ChannelParams params, uint64_t rng_seed = 42);
    ~ChannelEmulator() = default;

    ChannelEmulator(const ChannelEmulator&)            = delete;
    ChannelEmulator& operator=(const ChannelEmulator&) = delete;
    ChannelEmulator(ChannelEmulator&&)                 = default;
    ChannelEmulator& operator=(ChannelEmulator&&)      = default;

    /**
     * @brief Submit a packet for emulated delivery.
     *
     * Applies all enabled impairments and, for surviving packets, calls
     * @p deliver exactly once (twice for duplicates) with the computed
     * virtual delivery timestamp.
     *
     * @param src       Sender NodeId.
     * @param dst       Receiver NodeId.
     * @param payload   Packet bytes.
     * @param now_ms    Current virtual simulation time (ms).
     * @param deliver   Callback to schedule actual delivery.
     */
    void route(const NodeId& src,
               const NodeId& dst,
               const Bytes&  payload,
               uint64_t      now_ms,
               DeliveryCallback deliver);

    /// Access accumulated statistics (live; finalize() not yet called).
    [[nodiscard]] const ChannelStats& stats() const noexcept { return stats_; }

    /// Finalize statistics after simulation ends.
    void finalize(double sim_duration_ms) noexcept { stats_.finalize(sim_duration_ms); }

    /// Full per-packet trace (empty unless ChannelParams::enable_trace).
    [[nodiscard]] const std::vector<PacketRecord>& trace() const noexcept { return trace_; }

    /// Active parameter set.
    [[nodiscard]] const ChannelParams& params() const noexcept { return params_; }

    /// Replace the parameter set at runtime (e.g., for dynamic channel conditions).
    void set_params(ChannelParams p) noexcept { params_ = std::move(p); }

private:
    // ── Loss model ────────────────────────────────────────────────────────
    [[nodiscard]] bool should_drop() noexcept;

    // ── Delay computation ─────────────────────────────────────────────────
    [[nodiscard]] double compute_delay_ms(std::size_t payload_bytes) noexcept;

    // ── Bandwidth / queue ─────────────────────────────────────────────────
    /// Returns extra delay (ms) to satisfy rate shaping, or -1 if queue full.
    [[nodiscard]] double token_bucket_delay(std::size_t payload_bytes,
                                            uint64_t now_ms) noexcept;

    ChannelParams params_;

    // RNG
    std::mt19937_64                  rng_;
    std::uniform_real_distribution<> uniform_{0.0, 1.0};
    std::normal_distribution<double> normal_{0.0, 1.0};

    // Gilbert-Elliott state (true = Good)
    bool ge_state_good_ = true;

    // Token bucket state
    double   tokens_bytes_    = 0.0;  ///< Current available tokens
    uint64_t last_token_ms_   = 0;    ///< Virtual time of last token replenishment

    // Congestion queue (counts only; not storing payloads — scheduler handles that)
    uint64_t queue_depth_     = 0;

    // Sequence counter
    uint64_t next_seq_        = 0;

    // Statistics
    ChannelStats stats_;

    // Optional full trace
    std::vector<PacketRecord> trace_;
};

} // namespace uav_pqc::transport
