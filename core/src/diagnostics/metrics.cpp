// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

#include "uav_pqc/diagnostics/metrics.hpp"
#include "uav_pqc/platform/clock.hpp"

#include <algorithm>
#include <new>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <unistd.h>
#include <sys/resource.h>

#if defined(__APPLE__)
#include <mach/mach.h>
#include <mach/task.h>
#endif

namespace uav_pqc::diagnostics {

// Export the thread-local state
thread_local ThreadAllocState t_alloc_state = { false, 0, 0 };

std::string_view op_kind_name(OpKind op) noexcept {
    switch (op) {
        case OpKind::MlKem:           return "MlKem";
        case OpKind::MlDsa:           return "MlDsa";
        case OpKind::X25519:          return "X25519";
        case OpKind::Ecdsa:           return "Ecdsa";
        case OpKind::Hkdf:            return "Hkdf";
        case OpKind::AesGcm:          return "AesGcm";
        case OpKind::ChaCha20:        return "ChaCha20";
        case OpKind::TreeKem:         return "TreeKem";
        case OpKind::Serialization:   return "Serialization";
        case OpKind::PacketEncoding:  return "PacketEncoding";
        case OpKind::PacketDecoding:  return "PacketDecoding";
        case OpKind::SocketSend:      return "SocketSend";
        case OpKind::SocketReceive:   return "SocketReceive";
        case OpKind::SessionCreation: return "SessionCreation";
        case OpKind::Authentication:  return "Authentication";
        case OpKind::Registration:    return "Registration";
    }
    return "Unknown";
}

std::string_view metric_type_name(MetricType type) noexcept {
    switch (type) {
        case MetricType::CpuTimeMs:                return "CpuTimeMs";
        case MetricType::WallTimeMs:               return "WallTimeMs";
        case MetricType::MemoryBytes:              return "MemoryBytes";
        case MetricType::AllocCount:               return "AllocCount";
        case MetricType::PacketSize:               return "PacketSize";
        case MetricType::BytesTransmitted:         return "BytesTransmitted";
        case MetricType::PacketsTransmitted:       return "PacketsTransmitted";
        case MetricType::ProcessCpuTimeMs:         return "ProcessCpuTimeMs";
        case MetricType::CpuUtilizationPercent:    return "CpuUtilizationPercent";
        case MetricType::ResidentMemoryKb:         return "ResidentMemoryKb";
        case MetricType::VirtualMemoryMb:          return "VirtualMemoryMb";
        case MetricType::ActiveSessionMemoryBytes: return "ActiveSessionMemoryBytes";
        case MetricType::SessionObjectSizeBytes:   return "SessionObjectSizeBytes";
    }
    return "Unknown";
}

void get_process_memory(std::size_t& rss_bytes, std::size_t& vsize_bytes) noexcept {
    rss_bytes = 0;
    vsize_bytes = 0;
#if defined(__APPLE__)
    struct mach_task_basic_info info;
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO, (task_info_t)&info, &count) == KERN_SUCCESS) {
        rss_bytes = info.resident_size;
        vsize_bytes = info.virtual_size;
    }
#elif defined(__linux__) || defined(__linux)
    std::ifstream stat_file("/proc/self/stat");
    if (stat_file.good()) {
        std::string dummy;
        for (int i = 0; i < 22; ++i) {
            stat_file >> dummy;
        }
        unsigned long long vsize = 0;
        long long rss_pages = 0;
        stat_file >> vsize;
        stat_file >> rss_pages;
        vsize_bytes = vsize;
        rss_bytes = rss_pages * sysconf(_SC_PAGESIZE);
    }
#endif
}

double get_cpu_time() noexcept {
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        double user = static_cast<double>(usage.ru_utime.tv_sec) + 
                      static_cast<double>(usage.ru_utime.tv_usec) / 1e6;
        double sys  = static_cast<double>(usage.ru_stime.tv_sec) + 
                      static_cast<double>(usage.ru_stime.tv_usec) / 1e6;
        return user + sys;
    }
    return 0.0;
}

// ─────────────────────────────────────────────────────────────────────────────
// ScopedAllocationTracker Implementation
// ─────────────────────────────────────────────────────────────────────────────

ScopedAllocationTracker::ScopedAllocationTracker() noexcept
    : prev_tracking_(t_alloc_state.tracking)
    , start_bytes_(t_alloc_state.bytes)
    , start_count_(t_alloc_state.count)
{
    t_alloc_state.tracking = true;
}

ScopedAllocationTracker::~ScopedAllocationTracker() noexcept {
    t_alloc_state.tracking = prev_tracking_;
}

// ─────────────────────────────────────────────────────────────────────────────
// MetricsCollector Implementation
// ─────────────────────────────────────────────────────────────────────────────

MetricsCollector& MetricsCollector::get_instance() noexcept {
    static MetricsCollector instance;
    return instance;
}

void MetricsCollector::record(OpKind op, MetricType type, double value) noexcept {
    auto clock = platform::make_platform_clock();
    Timestamp now = clock ? clock->now_ms() : 0;

    std::lock_guard<std::mutex> lock(mutex_);
    samples_.push_back(MetricSample{now, op, type, value});
}

std::vector<MetricSample> MetricsCollector::get_samples() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return samples_;
}

void MetricsCollector::clear() noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    samples_.clear();
}

void MetricsCollector::export_csv(std::ostream& os) const {
    os << "TimestampMs,Operation,MetricType,Value\n";
    auto samples = get_samples();
    for (const auto& s : samples) {
        os << s.timestamp_ms << ","
           << op_kind_name(s.op) << ","
           << metric_type_name(s.type) << ","
           << std::fixed << std::setprecision(6) << s.value << "\n";
    }
}

void MetricsCollector::export_json(std::ostream& os) const {
    os << "[\n";
    auto samples = get_samples();
    for (std::size_t i = 0; i < samples.size(); ++i) {
        const auto& s = samples[i];
        os << "  {\n"
           << "    \"timestamp_ms\": " << s.timestamp_ms << ",\n"
           << "    \"op\": \"" << op_kind_name(s.op) << "\",\n"
           << "    \"type\": \"" << metric_type_name(s.type) << "\",\n"
           << "    \"value\": " << std::fixed << std::setprecision(6) << s.value << "\n"
           << "  }" << (i + 1 < samples.size() ? "," : "") << "\n";
    }
    os << "]\n";
}

void MetricsCollector::export_prometheus(std::ostream& os) const {
    // We group metrics into Prometheus timeseries format.
    // e.g. uav_pqc_operation_duration_seconds{op="MlKem", type="cpu"}
    auto samples = get_samples();
    if (samples.empty()) return;

    os << "# HELP uav_pqc_operation_cpu_time_ms CPU execution time in milliseconds\n"
       << "# TYPE uav_pqc_operation_cpu_time_ms gauge\n";
    for (const auto& s : samples) {
        if (s.type == MetricType::CpuTimeMs) {
            os << "uav_pqc_operation_cpu_time_ms{op=\"" << op_kind_name(s.op) << "\"} " << s.value << "\n";
        }
    }

    os << "# HELP uav_pqc_operation_wall_time_ms Wall-clock execution time in milliseconds\n"
       << "# TYPE uav_pqc_operation_wall_time_ms gauge\n";
    for (const auto& s : samples) {
        if (s.type == MetricType::WallTimeMs) {
            os << "uav_pqc_operation_wall_time_ms{op=\"" << op_kind_name(s.op) << "\"} " << s.value << "\n";
        }
    }

    os << "# HELP uav_pqc_operation_memory_bytes Total memory allocated during scope in bytes\n"
       << "# TYPE uav_pqc_operation_memory_bytes gauge\n";
    for (const auto& s : samples) {
        if (s.type == MetricType::MemoryBytes) {
            os << "uav_pqc_operation_memory_bytes{op=\"" << op_kind_name(s.op) << "\"} " << s.value << "\n";
        }
    }

    os << "# HELP uav_pqc_operation_allocations_total Total number of heap allocations\n"
       << "# TYPE uav_pqc_operation_allocations_total counter\n";
    for (const auto& s : samples) {
        if (s.type == MetricType::AllocCount) {
            os << "uav_pqc_operation_allocations_total{op=\"" << op_kind_name(s.op) << "\"} " << s.value << "\n";
        }
    }

    os << "# HELP uav_pqc_packet_size_bytes Size of packets processed\n"
       << "# TYPE uav_pqc_packet_size_bytes gauge\n";
    for (const auto& s : samples) {
        if (s.type == MetricType::PacketSize) {
            os << "uav_pqc_packet_size_bytes{op=\"" << op_kind_name(s.op) << "\"} " << s.value << "\n";
        }
    }

    os << "# HELP uav_pqc_bytes_transmitted_total Total bytes transmitted over socket\n"
       << "# TYPE uav_pqc_bytes_transmitted_total counter\n";
    for (const auto& s : samples) {
        if (s.type == MetricType::BytesTransmitted) {
            os << "uav_pqc_bytes_transmitted_total{op=\"" << op_kind_name(s.op) << "\"} " << s.value << "\n";
        }
    }

    os << "# HELP uav_pqc_packets_transmitted_total Total packets transmitted over socket\n"
       << "# TYPE uav_pqc_packets_transmitted_total counter\n";
    for (const auto& s : samples) {
        if (s.type == MetricType::PacketsTransmitted) {
            os << "uav_pqc_packets_transmitted_total{op=\"" << op_kind_name(s.op) << "\"} " << s.value << "\n";
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ScopedProfiler Implementation
// ─────────────────────────────────────────────────────────────────────────────

ScopedProfiler::ScopedProfiler(OpKind op) noexcept
    : op_(op)
    , wall_start_(std::chrono::high_resolution_clock::now())
    , cpu_start_(get_cpu_time())
    , rss_start_(0)
    , vsize_start_(0)
    , alloc_tracker_(std::make_unique<ScopedAllocationTracker>())
{
    get_process_memory(rss_start_, vsize_start_);
}

ScopedProfiler::~ScopedProfiler() noexcept {
    double cpu_end = get_cpu_time();
    auto wall_end = std::chrono::high_resolution_clock::now();
    std::size_t rss_end = 0;
    std::size_t vsize_end = 0;
    get_process_memory(rss_end, vsize_end);

    // cpu_start_ and cpu_end are in seconds, convert difference to milliseconds
    double cpu_duration = (cpu_end - cpu_start_) * 1000.0;
    double wall_duration = std::chrono::duration<double, std::milli>(wall_end - wall_start_).count();

    double cpu_utilization = 0.0;
    if (wall_duration > 0.0) {
        cpu_utilization = (cpu_duration / wall_duration) * 100.0;
    }

    auto& collector = MetricsCollector::get_instance();
    // Legacy / simple clocks
    collector.record(op_, MetricType::CpuTimeMs, cpu_duration);
    collector.record(op_, MetricType::WallTimeMs, wall_duration);
    
    // New exact process resource measurements
    collector.record(op_, MetricType::ProcessCpuTimeMs, cpu_duration);
    collector.record(op_, MetricType::CpuUtilizationPercent, cpu_utilization);
    collector.record(op_, MetricType::ResidentMemoryKb, static_cast<double>(rss_end) / 1024.0);
    collector.record(op_, MetricType::VirtualMemoryMb, static_cast<double>(vsize_end) / (1024.0 * 1024.0));

    if (alloc_tracker_) {
        collector.record(op_, MetricType::MemoryBytes, static_cast<double>(alloc_tracker_->bytes()));
        collector.record(op_, MetricType::AllocCount, static_cast<double>(alloc_tracker_->count()));
    }
}

} // namespace uav_pqc::diagnostics

// ─────────────────────────────────────────────────────────────────────────────
// Scoped Global operator new/delete overrides
// ─────────────────────────────────────────────────────────────────────────────

void* operator new(std::size_t size) {
    if (uav_pqc::diagnostics::t_alloc_state.tracking) {
        uav_pqc::diagnostics::t_alloc_state.bytes += size;
        uav_pqc::diagnostics::t_alloc_state.count++;
    }
    void* ptr = std::malloc(size);
    if (!ptr) throw std::bad_alloc();
    return ptr;
}

void operator delete(void* ptr) noexcept {
    std::free(ptr);
}

void* operator new[](std::size_t size) {
    if (uav_pqc::diagnostics::t_alloc_state.tracking) {
        uav_pqc::diagnostics::t_alloc_state.bytes += size;
        uav_pqc::diagnostics::t_alloc_state.count++;
    }
    void* ptr = std::malloc(size);
    if (!ptr) throw std::bad_alloc();
    return ptr;
}

void operator delete[](void* ptr) noexcept {
    std::free(ptr);
}
