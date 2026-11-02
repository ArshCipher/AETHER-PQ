// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file bench_resources.hpp
 * @brief Runtime CPU and memory measurement helpers for Google Benchmark suites.
 *
 * Provides capture_resources() / emit_resource_counters() that snapshot
 * and export the following per-benchmark counters from live OS measurements:
 *
 *   ProcessCpuTimeMs   — process CPU time (user + sys) in milliseconds
 *   WallClockMs        — wall-clock elapsed time in milliseconds
 *   CpuUtilizationPct  — CPU utilisation = cpu_ms / wall_ms × 100
 *   ResidentMemoryKb   — RSS at benchmark end in kibibytes
 *   VirtualMemoryMb    — VSZ at benchmark end in mebibytes
 *   ActiveSessionMemKb — RSS at benchmark end (same source, session context)
 *   SessionObjectSizeBytes — sizeof(T) for session/key structs (passed by caller)
 *
 * No fixed constants, scaling factors, or synthetic formulas are used.
 * All values are read directly from getrusage(2) / mach_task_info(3) / /proc/self/stat.
 */

#include "uav_pqc/diagnostics/metrics.hpp"

#include <benchmark/benchmark.h>
#include <chrono>
#include <cstddef>

namespace bench_detail {

struct ResourceSnapshot {
    double      cpu_s       = 0.0;  ///< process CPU time (user+sys) in seconds
    std::size_t rss_bytes   = 0;    ///< resident set size in bytes
    std::size_t vsize_bytes = 0;    ///< virtual address space size in bytes
    std::chrono::high_resolution_clock::time_point wall;
};

/// Capture a single resource snapshot using live OS APIs.
inline ResourceSnapshot capture_resources() noexcept {
    ResourceSnapshot s;
    s.cpu_s = uav_pqc::diagnostics::get_cpu_time();
    uav_pqc::diagnostics::get_process_memory(s.rss_bytes, s.vsize_bytes);
    s.wall  = std::chrono::high_resolution_clock::now();
    return s;
}

/// Inject measured CPU and memory counters into a benchmark::State.
///
/// @param state              The Google Benchmark state object.
/// @param before             Snapshot taken before the benchmark loop.
/// @param after              Snapshot taken after the benchmark loop.
/// @param session_obj_bytes  Optional: sizeof() of the session/key object under
///                           test.  Pass 0 to omit the SessionObjectSizeBytes counter.
inline void emit_resource_counters(benchmark::State&        state,
                                   const ResourceSnapshot&  before,
                                   const ResourceSnapshot&  after,
                                   double session_obj_bytes = 0.0) noexcept {
    double cpu_ms   = (after.cpu_s - before.cpu_s) * 1000.0;
    double wall_ms  = std::chrono::duration<double, std::milli>(
                          after.wall - before.wall).count();
    double cpu_util = (wall_ms > 0.0) ? (cpu_ms / wall_ms) * 100.0 : 0.0;
    double rss_kb   = static_cast<double>(after.rss_bytes)  / 1024.0;
    double vsz_mb   = static_cast<double>(after.vsize_bytes) / (1024.0 * 1024.0);

    state.counters["ProcessCpuTimeMs"]    = benchmark::Counter(cpu_ms);
    state.counters["WallClockMs"]         = benchmark::Counter(wall_ms);
    state.counters["CpuUtilizationPct"]   = benchmark::Counter(cpu_util);
    state.counters["ResidentMemoryKb"]    = benchmark::Counter(rss_kb);
    state.counters["ActiveSessionMemKb"]  = benchmark::Counter(rss_kb);
    state.counters["VirtualMemoryMb"]     = benchmark::Counter(vsz_mb);
    if (session_obj_bytes > 0.0) {
        state.counters["SessionObjectSizeBytes"] =
            benchmark::Counter(session_obj_bytes);
    }
}

} // namespace bench_detail

// Expose helpers at file scope (no-cost inline wrappers)
using bench_detail::ResourceSnapshot;
using bench_detail::capture_resources;
using bench_detail::emit_resource_counters;
