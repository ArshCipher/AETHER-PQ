// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
// test_scheduler.cpp — Unit tests for the discrete-event scheduler subsystem

#include "uav_pqc/sim/simulation_context.hpp"
#include <gtest/gtest.h>
#include <vector>
#include <string>

using namespace uav_pqc::sim;

TEST(EventSchedulerTest, BasicScheduling) {
    EventScheduler scheduler(42);
    EXPECT_EQ(scheduler.now_ms(), 0);

    bool fired = false;
    scheduler.schedule(10, [&]() {
        fired = true;
        EXPECT_EQ(scheduler.now_ms(), 10);
    }, "TestEvent");

    EXPECT_EQ(scheduler.pending_count(), 1);
    scheduler.run_until(5);
    EXPECT_FALSE(fired);
    EXPECT_EQ(scheduler.now_ms(), 5);

    scheduler.run_until(15);
    EXPECT_TRUE(fired);
    EXPECT_EQ(scheduler.now_ms(), 15);
    EXPECT_EQ(scheduler.pending_count(), 0);
}

TEST(EventSchedulerTest, EventOrderingAndPriority) {
    EventScheduler scheduler(42);
    std::vector<std::string> order;

    scheduler.schedule(10, [&]() { order.push_back("A_normal"); }, "A_normal", EventPriority::Normal);
    scheduler.schedule(10, [&]() { order.push_back("B_critical"); }, "B_critical", EventPriority::Critical);
    scheduler.schedule(10, [&]() { order.push_back("C_low"); }, "C_low", EventPriority::Low);
    scheduler.schedule(5, [&]() { order.push_back("D_early"); }, "D_early", EventPriority::Normal);

    scheduler.run_all();

    ASSERT_EQ(order.size(), 4);
    EXPECT_EQ(order[0], "D_early");
    EXPECT_EQ(order[1], "B_critical"); // highest priority tie-breaker
    EXPECT_EQ(order[2], "A_normal");
    EXPECT_EQ(order[3], "C_low");
}

TEST(EventSchedulerTest, Cancellation) {
    EventScheduler scheduler(42);
    bool fired = false;

    EventId id = scheduler.schedule(10, [&]() { fired = true; }, "CancelTest");
    EXPECT_TRUE(scheduler.cancel(id));
    EXPECT_FALSE(scheduler.cancel(id)); // already cancelled

    scheduler.run_all();
    EXPECT_FALSE(fired);
}

TEST(EventSchedulerTest, PeriodicEvents) {
    EventScheduler scheduler(42);
    int count = 0;

    EventId id = scheduler.schedule_periodic(10, 5, [&]() {
        count++;
    }, "PeriodicTest");

    scheduler.run_until(10);
    EXPECT_EQ(count, 1);

    scheduler.run_until(20);
    EXPECT_EQ(count, 3); // 10, 15, 20

    scheduler.cancel(id);
    scheduler.run_until(30);
    EXPECT_EQ(count, 3); // should stop firing
}

TEST(TimerManagerTest, BasicTimers) {
    EventScheduler scheduler(42);
    TimerManager timers(scheduler);

    bool fired = false;
    bool expired = false;

    auto handle = timers.retransmit(
        [&]() { fired = true; },
        [&]() { expired = true; },
        1000, 3
    );

    EXPECT_EQ(timers.active_count(TimerKind::Retransmit), 1);
    EXPECT_EQ(timers.total_active(), 1);

    scheduler.run_until(1000);
    EXPECT_TRUE(fired);
    EXPECT_FALSE(expired);
    fired = false;

    scheduler.run_until(2000);
    EXPECT_TRUE(fired);
    EXPECT_FALSE(expired);
    fired = false;

    scheduler.run_until(3000);
    EXPECT_TRUE(fired);
    EXPECT_TRUE(expired); // Hit max 3 fires, should expire
    EXPECT_EQ(timers.stats(TimerKind::Retransmit).expired, 1);
}

TEST(TimelineLoggerTest, OutputFormatting) {
    TimelineLogger logger;
    logger.record(10, "UAV-1", TimelineEventKind::Handshake, "ClientHello");
    logger.record(15, "GCS", TimelineEventKind::Handshake, "ServerHello");
    logger.record(25, "UAV-1", TimelineEventKind::Retransmit, "TimeoutTriggered");

    auto json_out = logger.to_json(50);
    EXPECT_EQ(json_out["sim_duration_ms"], 50);
    EXPECT_EQ(json_out["total_entries"], 3);

    auto ascii_out = logger.to_ascii(10);
    EXPECT_FALSE(ascii_out.empty());
    EXPECT_TRUE(ascii_out.find("UAV-1") != std::string::npos);
    EXPECT_TRUE(ascii_out.find("GCS") != std::string::npos);
}

TEST(SimulationContextTest, ReplayAndLogging) {
    SimulationConfig config;
    config.rng_seed = 100;
    config.auto_log_events = true;
    config.default_node_id = "TEST_NODE";

    SimulationContext ctx(config);

    ctx.schedule_event(100, []() {}, "SimulatedEvent");
    ctx.run_all();

    EXPECT_EQ(ctx.timeline().entry_count(), 1);
    auto first_entry = ctx.timeline().entries()[0];
    EXPECT_EQ(first_entry.time_ms, 100);
    EXPECT_EQ(first_entry.node_id_hex, "TEST_NODE");
    EXPECT_EQ(first_entry.label, "SimulatedEvent");

    // Reset and check timeline cleared
    ctx.reset(100);
    EXPECT_EQ(ctx.timeline().entry_count(), 0);
    EXPECT_EQ(ctx.now_ms(), 0);
}
