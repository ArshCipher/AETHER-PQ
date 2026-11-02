// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file metrics.hpp
 * @brief Performance profiling and diagnostics engine for UAV-PQC.
 *
 * Instruments every protocol operation to collect CPU execution time, wall-clock
 * time, total memory allocated, heap allocation count, packet size, bytes, and
 * packets transmitted. Output formats supported: CSV, JSON, and Prometheus exposition format.
 */

#include "uav_pqc/common/types.hpp"

#include <chrono>
#include <ctime>
#include <string>
#include <vector>
#include <mutex>
#include <ostream>
#include <memory>

namespace uav_pqc::diagnostics {

// ─────────────────────────────────────────────────────────────────────────────
// Metric / Diagnostic Kind definitions
// ─────────────────────────────────────────────────────────────────────────────

enum class OpKind : std::uint8_t {
    MlKem = 0,
    MlDsa,
    X25519,
    Ecdsa,
    Hkdf,
    AesGcm,
    ChaCha20,
    TreeKem,
    Serialization,
    PacketEncoding,
    PacketDecoding,
    SocketSend,
    SocketReceive,
    SessionCreation,
    Authentication,
    Registration
};

[[nodiscard]] std::string_view op_kind_name(OpKind op) noexcept;

enum class MetricType : std::uint8_t {
    CpuTimeMs = 0,
    WallTimeMs,
    MemoryBytes,
    AllocCount,
    PacketSize,
    BytesTransmitted,
    PacketsTransmitted,
    ProcessCpuTimeMs,
    CpuUtilizationPercent,
    ResidentMemoryKb,
    VirtualMemoryMb,
    ActiveSessionMemoryBytes,
    SessionObjectSizeBytes
};

[[nodiscard]] std::string_view metric_type_name(MetricType type) noexcept;

/**
 * @brief Get current process virtual memory size (VSZ) and resident set size (RSS) in bytes.
 */
void get_process_memory(std::size_t& rss_bytes, std::size_t& vsize_bytes) noexcept;

/**
 * @brief Get current process CPU time (user + system) in seconds.
 */
double get_cpu_time() noexcept;

// ─────────────────────────────────────────────────────────────────────────────
// Scoped Thread-Local Memory Tracking Definitions
// ─────────────────────────────────────────────────────────────────────────────

struct ThreadAllocState {
    bool        tracking = false;
    std::size_t bytes    = 0;
    std::size_t count    = 0;
};

// Thread-local variable exported for operator new to access
extern thread_local ThreadAllocState t_alloc_state;

/**
 * @brief RAII helper to enable/disable heap allocation tracking within a scope.
 */
class ScopedAllocationTracker {
public:
    ScopedAllocationTracker() noexcept;
    ~ScopedAllocationTracker() noexcept;

    ScopedAllocationTracker(const ScopedAllocationTracker&) = delete;
    ScopedAllocationTracker& operator=(const ScopedAllocationTracker&) = delete;

    [[nodiscard]] std::size_t bytes() const noexcept { return t_alloc_state.bytes - start_bytes_; }
    [[nodiscard]] std::size_t count() const noexcept { return t_alloc_state.count - start_count_; }

private:
    bool        prev_tracking_;
    std::size_t start_bytes_;
    std::size_t start_count_;
};

// ─────────────────────────────────────────────────────────────────────────────
// MetricsCollector Context
// ─────────────────────────────────────────────────────────────────────────────

struct MetricSample {
    Timestamp   timestamp_ms;
    OpKind      op;
    MetricType  type;
    double      value;
};

class MetricsCollector {
public:
    static MetricsCollector& get_instance() noexcept;

    MetricsCollector(const MetricsCollector&) = delete;
    MetricsCollector& operator=(const MetricsCollector&) = delete;

    /// Record a raw diagnostic sample. Thread-safe.
    void record(OpKind op, MetricType type, double value) noexcept;

    /// Retrieve all collected samples.
    std::vector<MetricSample> get_samples() const;

    /// Reset collector state.
    void clear() noexcept;

    // ── Export formats ────────────────────────────────────────────────────────

    void export_csv(std::ostream& os) const;
    void export_json(std::ostream& os) const;
    void export_prometheus(std::ostream& os) const;

private:
    MetricsCollector() = default;
    ~MetricsCollector() = default;

    mutable std::mutex        mutex_;
    std::vector<MetricSample> samples_;
};

// ─────────────────────────────────────────────────────────────────────────────
// RAII Scoped Profiler for automatic timing and memory diagnostics
// ─────────────────────────────────────────────────────────────────────────────

class ScopedProfiler {
public:
    explicit ScopedProfiler(OpKind op) noexcept;
    ~ScopedProfiler() noexcept;

    ScopedProfiler(const ScopedProfiler&) = delete;
    ScopedProfiler& operator=(const ScopedProfiler&) = delete;

private:
    OpKind                                             op_;
    std::chrono::high_resolution_clock::time_point     wall_start_;
    double                                             cpu_start_;
    std::size_t                                        rss_start_;
    std::size_t                                        vsize_start_;
    std::unique_ptr<ScopedAllocationTracker>           alloc_tracker_;
};

} // namespace uav_pqc::diagnostics
