// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

#include <any>
#include <functional>
#include <memory>
#include <mutex>
#include <typeindex>
#include <unordered_map>
#include <vector>

namespace uav_pqc::app {

/**
 * @brief Abstract EventBus interface.
 */
class IEventBus {
public:
    IEventBus() = default;
    virtual ~IEventBus() = default;

    IEventBus(const IEventBus&) = delete;
    IEventBus& operator=(const IEventBus&) = delete;
    IEventBus(IEventBus&&) noexcept = default;
    IEventBus& operator=(IEventBus&&) noexcept = default;

    virtual void publish_erased(const std::any& event, std::type_index type) = 0;
    virtual void subscribe_erased(std::type_index type, std::function<void(const std::any&)> handler) = 0;

    template<typename T>
    void publish(const T& event) {
        publish_erased(std::any(event), std::type_index(typeid(T)));
    }

    template<typename T>
    void subscribe(std::function<void(const T&)> handler) {
        subscribe_erased(std::type_index(typeid(T)), [handler](const std::any& event) {
            handler(std::any_cast<const T&>(event));
        });
    }
};

/**
 * @brief Concrete thread-safe EventBus implementation.
 */
class EventBus final : public IEventBus {
public:
    EventBus() = default;
    ~EventBus() override = default;

    void publish_erased(const std::any& event, std::type_index type) override;
    void subscribe_erased(std::type_index type, std::function<void(const std::any&)> handler) override;

private:
    std::mutex mutex_;
    std::unordered_map<std::type_index, std::vector<std::function<void(const std::any&)>>> handlers_;
};

} // namespace uav_pqc::app
