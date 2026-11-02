// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

#include "uav_pqc/app/event_bus.hpp"

namespace uav_pqc::app {

void EventBus::publish_erased(const std::any& event, std::type_index type) {
    std::vector<std::function<void(const std::any&)>> targets;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = handlers_.find(type);
        if (it != handlers_.end()) {
            targets = it->second;
        }
    }
    for (const auto& handler : targets) {
        handler(event);
    }
}

void EventBus::subscribe_erased(std::type_index type, std::function<void(const std::any&)> handler) {
    std::lock_guard<std::mutex> lock(mutex_);
    handlers_[type].push_back(std::move(handler));
}

} // namespace uav_pqc::app
