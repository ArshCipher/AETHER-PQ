// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file channel_emulator.cpp
 * @brief Implementation of the software-defined channel emulator.
 */

#include "uav_pqc/transport/channel_emulator.hpp"

#include <algorithm>
#include <cmath>
#include <fstream>
#include <stdexcept>
#include <string>

namespace uav_pqc::transport {

// ─────────────────────────────────────────────────────────────────────────────
// ChannelStats
// ─────────────────────────────────────────────────────────────────────────────

void ChannelStats::finalize(double sim_duration_ms) noexcept {
    if (packets_delivered > 0) {
        avg_delay_ms = sum_delay_ms / static_cast<double>(packets_delivered);
        double variance = (sum_delay_sq_ms / static_cast<double>(packets_delivered))
                          - (avg_delay_ms * avg_delay_ms);
        measured_jitter_ms = (variance > 0.0) ? std::sqrt(variance) : 0.0;
    }

    if (packets_enqueued > 0) {
        loss_rate = static_cast<double>(packets_dropped + packets_overflow)
                    / static_cast<double>(packets_enqueued);
    }

    if (sim_duration_ms > 0.0) {
        effective_throughput_bps = (static_cast<double>(bytes_delivered) * 8.0 * 1000.0)
                                   / sim_duration_ms;
    }

    if (packets_delivered == 0) {
        min_delay_ms = 0.0;
    }
}

nlohmann::json ChannelStats::to_json() const {
    return {
        {"packets_enqueued",        packets_enqueued},
        {"packets_delivered",       packets_delivered},
        {"packets_dropped",         packets_dropped},
        {"packets_overflow",        packets_overflow},
        {"packets_duplicated",      packets_duplicated},
        {"packets_reordered",       packets_reordered},
        {"bytes_enqueued",          bytes_enqueued},
        {"bytes_delivered",         bytes_delivered},
        {"bytes_dropped",           bytes_dropped},
        {"min_delay_ms",            min_delay_ms < 1e17 ? min_delay_ms : 0.0},
        {"max_delay_ms",            max_delay_ms},
        {"avg_delay_ms",            avg_delay_ms},
        {"measured_jitter_ms",      measured_jitter_ms},
        {"loss_rate",               loss_rate},
        {"effective_throughput_bps",effective_throughput_bps},
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// ChannelParams
// ─────────────────────────────────────────────────────────────────────────────

ChannelParams ChannelParams::from_json(const nlohmann::json& j) {
    ChannelParams p;
    auto get = [&](const char* key, auto& field) {
        if (j.contains(key) && !j[key].is_null()) {
            field = j[key].get<std::decay_t<decltype(field)>>();
        }
    };
    get("propagation_delay_ms",  p.propagation_delay_ms);
    get("jitter_stddev_ms",      p.jitter_stddev_ms);
    get("bandwidth_bps",         p.bandwidth_bps);
    get("queue_max_packets",     p.queue_max_packets);
    get("loss_good",             p.loss_good);
    get("loss_bad",              p.loss_bad);
    get("p_gb",                  p.p_gb);
    get("p_bg",                  p.p_bg);
    get("duplicate_prob",        p.duplicate_prob);
    get("duplicate_delay_ms",    p.duplicate_delay_ms);
    get("reorder_prob",          p.reorder_prob);
    get("reorder_delay_ms",      p.reorder_delay_ms);
    get("enable_trace",          p.enable_trace);
    return p;
}

nlohmann::json ChannelParams::to_json() const {
    return {
        {"propagation_delay_ms",  propagation_delay_ms},
        {"jitter_stddev_ms",      jitter_stddev_ms},
        {"bandwidth_bps",         bandwidth_bps},
        {"queue_max_packets",     queue_max_packets},
        {"loss_good",             loss_good},
        {"loss_bad",              loss_bad},
        {"p_gb",                  p_gb},
        {"p_bg",                  p_bg},
        {"duplicate_prob",        duplicate_prob},
        {"duplicate_delay_ms",    duplicate_delay_ms},
        {"reorder_prob",          reorder_prob},
        {"reorder_delay_ms",      reorder_delay_ms},
        {"enable_trace",          enable_trace},
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Built-in profiles (no filesystem required)
// ─────────────────────────────────────────────────────────────────────────────

static nlohmann::json builtin_profiles_json() {
    // clang-format off
    return nlohmann::json::array({
        {
            {"name",        "ideal_lan"},
            {"description", "Zero-impairment 1 Gbps LAN — baseline for correctness tests"},
            {"params", {
                {"propagation_delay_ms", 0.1},
                {"jitter_stddev_ms",     0.0},
                {"bandwidth_bps",        1e9},
                {"queue_max_packets",    256},
                {"loss_good",            0.0},
                {"loss_bad",             0.0},
                {"p_gb",                 0.0},
                {"p_bg",                 1.0},
                {"duplicate_prob",       0.0},
                {"duplicate_delay_ms",   0.0},
                {"reorder_prob",         0.0},
                {"reorder_delay_ms",     0.0},
                {"enable_trace",         false}
            }}
        },
        {
            {"name",        "wifi"},
            {"description", "IEEE 802.11n indoor WiFi — 54 Mbps, 1% loss, 3 ms jitter"},
            {"params", {
                {"propagation_delay_ms", 2.0},
                {"jitter_stddev_ms",     3.0},
                {"bandwidth_bps",        54e6},
                {"queue_max_packets",    64},
                {"loss_good",            0.005},
                {"loss_bad",             0.40},
                {"p_gb",                 0.01},
                {"p_bg",                 0.15},
                {"duplicate_prob",       0.002},
                {"duplicate_delay_ms",   1.5},
                {"reorder_prob",         0.005},
                {"reorder_delay_ms",     4.0},
                {"enable_trace",         false}
            }}
        },
        {
            {"name",        "5g"},
            {"description", "5G NR sub-6 GHz — 100 Mbps, 0.1% loss, 1 ms jitter"},
            {"params", {
                {"propagation_delay_ms", 5.0},
                {"jitter_stddev_ms",     1.0},
                {"bandwidth_bps",        100e6},
                {"queue_max_packets",    128},
                {"loss_good",            0.001},
                {"loss_bad",             0.20},
                {"p_gb",                 0.002},
                {"p_bg",                 0.20},
                {"duplicate_prob",       0.0005},
                {"duplicate_delay_ms",   1.0},
                {"reorder_prob",         0.002},
                {"reorder_delay_ms",     2.0},
                {"enable_trace",         false}
            }}
        },
        {
            {"name",        "satellite"},
            {"description", "GEO satellite link — 600 ms RTT, 10 Mbps, 0.5% loss, 50 ms jitter"},
            {"params", {
                {"propagation_delay_ms", 600.0},
                {"jitter_stddev_ms",     50.0},
                {"bandwidth_bps",        10e6},
                {"queue_max_packets",    32},
                {"loss_good",            0.003},
                {"loss_bad",             0.60},
                {"p_gb",                 0.005},
                {"p_bg",                 0.08},
                {"duplicate_prob",       0.001},
                {"duplicate_delay_ms",   5.0},
                {"reorder_prob",         0.01},
                {"reorder_delay_ms",     50.0},
                {"enable_trace",         false}
            }}
        },
        {
            {"name",        "custom"},
            {"description", "User-defined profile — all values at zero/defaults, override via JSON"},
            {"params", {
                {"propagation_delay_ms", 15.0},
                {"jitter_stddev_ms",     2.0},
                {"bandwidth_bps",        54e6},
                {"queue_max_packets",    64},
                {"loss_good",            0.02},
                {"loss_bad",             0.50},
                {"p_gb",                 0.01},
                {"p_bg",                 0.10},
                {"duplicate_prob",       0.001},
                {"duplicate_delay_ms",   1.0},
                {"reorder_prob",         0.005},
                {"reorder_delay_ms",     5.0},
                {"enable_trace",         false}
            }}
        }
    });
    // clang-format on
}

// ─────────────────────────────────────────────────────────────────────────────
// ChannelProfile
// ─────────────────────────────────────────────────────────────────────────────

ChannelProfile ChannelProfile::load(const std::string& profile_name,
                                    const std::string& json_path) {
    std::ifstream f(json_path);
    if (!f.is_open()) {
        throw std::runtime_error("channel_emulator: cannot open profiles file: " + json_path);
    }
    nlohmann::json doc;
    f >> doc;
    return from_json(profile_name, doc);
}

ChannelProfile ChannelProfile::from_json(const std::string& profile_name,
                                         const nlohmann::json& doc) {
    // doc may be an array of profile objects, or a single object with a
    // top-level "profiles" array.
    const nlohmann::json* arr = nullptr;
    nlohmann::json profiles_holder;
    if (doc.is_array()) {
        arr = &doc;
    } else if (doc.contains("profiles") && doc["profiles"].is_array()) {
        profiles_holder = doc["profiles"];
        arr = &profiles_holder;
    } else {
        throw std::runtime_error("channel_emulator: profiles JSON must be an array or contain a 'profiles' array");
    }

    for (const auto& entry : *arr) {
        if (entry.value("name", std::string{}) == profile_name) {
            ChannelProfile cp;
            cp.name        = profile_name;
            cp.description = entry.value("description", std::string{});
            cp.params      = ChannelParams::from_json(entry.at("params"));
            return cp;
        }
    }
    throw std::runtime_error("channel_emulator: profile '" + profile_name + "' not found in JSON");
}

ChannelProfile ChannelProfile::builtin(const std::string& profile_name) {
    auto doc = builtin_profiles_json();
    return from_json(profile_name, doc);
}

std::vector<std::string> ChannelProfile::builtin_names() {
    return {"ideal_lan", "wifi", "5g", "satellite", "custom"};
}

// ─────────────────────────────────────────────────────────────────────────────
// ChannelEmulator — constructor
// ─────────────────────────────────────────────────────────────────────────────

ChannelEmulator::ChannelEmulator(ChannelParams params, uint64_t rng_seed)
    : params_(std::move(params))
    , rng_(rng_seed)
{
    // Pre-fill token bucket to full capacity (1 MTU worth of tokens)
    tokens_bytes_ = (params_.bandwidth_bps > 0.0)
                        ? (params_.bandwidth_bps / 8.0) * 0.001  // tokens for 1 ms
                        : 0.0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Loss model — Gilbert-Elliott two-state Markov chain
// ─────────────────────────────────────────────────────────────────────────────

bool ChannelEmulator::should_drop() noexcept {
    // State transition
    double u_trans = uniform_(rng_);
    if (ge_state_good_) {
        if (u_trans < params_.p_gb) {
            ge_state_good_ = false;
        }
    } else {
        if (u_trans < params_.p_bg) {
            ge_state_good_ = true;
        }
    }

    double loss_prob = ge_state_good_ ? params_.loss_good : params_.loss_bad;
    return (uniform_(rng_) < loss_prob);
}

// ─────────────────────────────────────────────────────────────────────────────
// Delay computation
// ─────────────────────────────────────────────────────────────────────────────

double ChannelEmulator::compute_delay_ms(std::size_t payload_bytes) noexcept {
    // 1. Propagation delay
    double delay = params_.propagation_delay_ms;

    // 2. Transmission delay (serialisation)
    if (params_.bandwidth_bps > 0.0) {
        double tx_delay_ms = (static_cast<double>(payload_bytes) * 8.0 * 1000.0)
                             / params_.bandwidth_bps;
        delay += tx_delay_ms;
    }

    // 3. Jitter (Gaussian, clamp so total delay ≥ 0)
    if (params_.jitter_stddev_ms > 0.0) {
        double jitter = normal_(rng_) * params_.jitter_stddev_ms;
        delay = std::max(0.0, delay + jitter);
    }

    return delay;
}

// ─────────────────────────────────────────────────────────────────────────────
// Token-bucket rate shaping
// Returns extra queuing delay in ms, or -1.0 if the queue is full (drop).
// ─────────────────────────────────────────────────────────────────────────────

double ChannelEmulator::token_bucket_delay(std::size_t payload_bytes,
                                           uint64_t now_ms) noexcept {
    if (params_.bandwidth_bps <= 0.0) {
        return 0.0; // Unlimited bandwidth
    }

    // Replenish tokens since last call
    double elapsed_ms = static_cast<double>(now_ms - last_token_ms_);
    if (elapsed_ms > 0.0) {
        double new_tokens = (params_.bandwidth_bps / 8.0) * (elapsed_ms / 1000.0);
        // Bucket capacity = 1 second worth of bytes
        double capacity = params_.bandwidth_bps / 8.0;
        tokens_bytes_ = std::min(tokens_bytes_ + new_tokens, capacity);
        last_token_ms_ = now_ms;
    }

    double cost = static_cast<double>(payload_bytes);

    // Check congestion queue capacity
    if (params_.queue_max_packets > 0 && queue_depth_ >= params_.queue_max_packets) {
        return -1.0; // Queue overflow — drop
    }

    // Compute wait time if not enough tokens
    double extra_delay_ms = 0.0;
    if (tokens_bytes_ < cost) {
        double deficit = cost - tokens_bytes_;
        extra_delay_ms = (deficit / (params_.bandwidth_bps / 8.0)) * 1000.0;
        tokens_bytes_ = 0.0;
        queue_depth_++;
    } else {
        tokens_bytes_ -= cost;
    }

    return extra_delay_ms;
}

// ─────────────────────────────────────────────────────────────────────────────
// route() — main emulation entry point
// ─────────────────────────────────────────────────────────────────────────────

void ChannelEmulator::route(const NodeId&     src,
                             const NodeId&     dst,
                             const Bytes&      payload,
                             uint64_t          now_ms,
                             DeliveryCallback  deliver) {
    const uint64_t seq          = next_seq_++;
    const uint64_t size_bytes   = payload.size();

    stats_.packets_enqueued++;
    stats_.bytes_enqueued += size_bytes;

    // ── 1. Congestion queue / bandwidth limit ──────────────────────────────
    double bw_extra_ms = token_bucket_delay(payload.size(), now_ms);
    if (bw_extra_ms < 0.0) {
        // Queue overflow — tail drop
        stats_.packets_overflow++;
        stats_.bytes_dropped += size_bytes;
        if (params_.enable_trace) {
            trace_.push_back(PacketRecord{
                seq, now_ms, now_ms, size_bytes,
                PacketFate::QueueOverflow, 0.0, src, dst
            });
        }
        return;
    }

    // ── 2. Loss model ──────────────────────────────────────────────────────
    if (should_drop()) {
        stats_.packets_dropped++;
        stats_.bytes_dropped += size_bytes;
        if (params_.enable_trace) {
            trace_.push_back(PacketRecord{
                seq, now_ms, now_ms, size_bytes,
                PacketFate::Dropped, 0.0, src, dst
            });
        }
        // Decrement queue depth if a slot was claimed
        if (bw_extra_ms > 0.0 && queue_depth_ > 0) --queue_depth_;
        return;
    }

    // ── 3. Compute delivery delay ──────────────────────────────────────────
    double base_delay_ms = compute_delay_ms(payload.size()) + bw_extra_ms;

    // ── 4. Reordering ─────────────────────────────────────────────────────
    bool reordered = false;
    if (params_.reorder_prob > 0.0 && uniform_(rng_) < params_.reorder_prob) {
        base_delay_ms += params_.reorder_delay_ms;
        reordered = true;
        stats_.packets_reordered++;
    }

    uint64_t delivery_ms = now_ms + static_cast<uint64_t>(std::max(0.0, base_delay_ms));

    // ── 5. Update statistics ───────────────────────────────────────────────
    stats_.packets_delivered++;
    stats_.bytes_delivered += size_bytes;
    stats_.sum_delay_ms    += base_delay_ms;
    stats_.sum_delay_sq_ms += base_delay_ms * base_delay_ms;
    if (base_delay_ms < stats_.min_delay_ms) stats_.min_delay_ms = base_delay_ms;
    if (base_delay_ms > stats_.max_delay_ms) stats_.max_delay_ms = base_delay_ms;

    // Release queue slot on delivery
    if (bw_extra_ms > 0.0 && queue_depth_ > 0) {
        --queue_depth_;
    }

    // ── 6. Trace ───────────────────────────────────────────────────────────
    if (params_.enable_trace) {
        trace_.push_back(PacketRecord{
            seq, now_ms, delivery_ms, size_bytes,
            reordered ? PacketFate::Reordered : PacketFate::Delivered,
            base_delay_ms, src, dst
        });
    }

    // ── 7. Schedule delivery ───────────────────────────────────────────────
    deliver(delivery_ms, src, dst, payload);

    // ── 8. Duplication ────────────────────────────────────────────────────
    if (params_.duplicate_prob > 0.0 && uniform_(rng_) < params_.duplicate_prob) {
        stats_.packets_duplicated++;
        uint64_t dup_delivery_ms = delivery_ms
            + static_cast<uint64_t>(std::max(0.0, params_.duplicate_delay_ms));

        if (params_.enable_trace) {
            trace_.push_back(PacketRecord{
                next_seq_++, now_ms, dup_delivery_ms, size_bytes,
                PacketFate::Duplicated, base_delay_ms + params_.duplicate_delay_ms,
                src, dst
            });
        }
        deliver(dup_delivery_ms, src, dst, payload);
    }
}

} // namespace uav_pqc::transport
