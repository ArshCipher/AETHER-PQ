#include <gtest/gtest.h>
#include "uav_pqc/platform/clock.hpp"
#include <thread>

using namespace uav_pqc;
using namespace uav_pqc::platform;

TEST(ClockTest, SystemClockBasic) {
    SystemClock clock;
    
    Timestamp t1 = clock.now_ms();
    Timestamp w1 = clock.wall_clock_ms();
    
    ASSERT_GT(t1, 0);
    ASSERT_GT(w1, 0);
    
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
    
    Timestamp t2 = clock.now_ms();
    Timestamp w2 = clock.wall_clock_ms();
    
    ASSERT_GE(t2, t1);
    ASSERT_GE(w2, w1);
}

TEST(ClockTest, SimulationClockManual) {
    SimulationClock clock(100);
    
    ASSERT_EQ(clock.now_ms(), 100);
    ASSERT_EQ(clock.wall_clock_ms(), 100);
    
    clock.advance_ms(50);
    ASSERT_EQ(clock.now_ms(), 150);
    ASSERT_EQ(clock.wall_clock_ms(), 150);
    
    clock.set_time_ms(500);
    ASSERT_EQ(clock.now_ms(), 500);
    ASSERT_EQ(clock.wall_clock_ms(), 500);
}

TEST(ClockTest, SimulationClockProvider) {
    Timestamp mock_time = 1000;
    SimulationClock clock([&mock_time]() {
        return mock_time;
    });
    
    ASSERT_EQ(clock.now_ms(), 1000);
    ASSERT_EQ(clock.wall_clock_ms(), 1000);
    
    mock_time = 2500;
    ASSERT_EQ(clock.now_ms(), 2500);
    ASSERT_EQ(clock.wall_clock_ms(), 2500);
}
