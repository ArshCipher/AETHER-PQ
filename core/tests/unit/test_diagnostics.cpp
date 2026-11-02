// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

#include <gtest/gtest.h>
#include "uav_pqc/diagnostics/metrics.hpp"
#include <sstream>
#include <memory>

using namespace uav_pqc::diagnostics;

TEST(DiagnosticsTest, ScopedAllocationTracker) {
    // Enable allocation tracking scope
    {
        ScopedAllocationTracker tracker;
        
        // Allocate some memory on the heap
        char* volatile ptr = new char[1024];
        ptr[0] = 'A'; // use it
        delete[] ptr;

        EXPECT_GE(tracker.bytes(), 1024);
        EXPECT_GE(tracker.count(), 1);
    }
}

TEST(DiagnosticsTest, MetricsCollectorRecordAndExport) {
    auto& collector = MetricsCollector::get_instance();
    collector.clear();

    collector.record(OpKind::MlKem, MetricType::CpuTimeMs, 1.25);
    collector.record(OpKind::MlKem, MetricType::MemoryBytes, 2048.0);
    collector.record(OpKind::TreeKem, MetricType::AllocCount, 5.0);

    auto samples = collector.get_samples();
    ASSERT_EQ(samples.size(), 3);

    // Export to CSV
    std::stringstream csv_out;
    collector.export_csv(csv_out);
    std::string csv_str = csv_out.str();
    EXPECT_NE(csv_str.find("TimestampMs,Operation,MetricType,Value"), std::string::npos);
    EXPECT_NE(csv_str.find("MlKem,CpuTimeMs,1.25"), std::string::npos);
    EXPECT_NE(csv_str.find("TreeKem,AllocCount,5.0"), std::string::npos);

    // Export to JSON
    std::stringstream json_out;
    collector.export_json(json_out);
    std::string json_str = json_out.str();
    EXPECT_NE(json_str.find("\"op\": \"MlKem\""), std::string::npos);
    EXPECT_NE(json_str.find("\"type\": \"CpuTimeMs\""), std::string::npos);
    EXPECT_NE(json_str.find("\"value\": 1.250000"), std::string::npos);

    // Export to Prometheus
    std::stringstream prom_out;
    collector.export_prometheus(prom_out);
    std::string prom_str = prom_out.str();
    EXPECT_NE(prom_str.find("uav_pqc_operation_cpu_time_ms{op=\"MlKem\"} 1.25"), std::string::npos);
    EXPECT_NE(prom_str.find("uav_pqc_operation_memory_bytes{op=\"MlKem\"} 2048"), std::string::npos);
    EXPECT_NE(prom_str.find("uav_pqc_operation_allocations_total{op=\"TreeKem\"} 5"), std::string::npos);
}

TEST(DiagnosticsTest, ScopedProfiler) {
    auto& collector = MetricsCollector::get_instance();
    collector.clear();

    {
        ScopedProfiler profiler(OpKind::AesGcm);
        // Do some dummy work
        volatile int x = 0;
        for (int i = 0; i < 10000; ++i) {
            x += i;
        }
        (void)x;
    }

    auto samples = collector.get_samples();
    // Should have recorded at least CpuTimeMs, WallTimeMs, MemoryBytes, AllocCount
    EXPECT_GE(samples.size(), 2);
    bool found_wall = false;
    for (const auto& s : samples) {
        EXPECT_EQ(s.op, OpKind::AesGcm);
        if (s.type == MetricType::WallTimeMs) {
            found_wall = true;
            EXPECT_GT(s.value, 0.0);
        }
    }
    EXPECT_TRUE(found_wall);
}
