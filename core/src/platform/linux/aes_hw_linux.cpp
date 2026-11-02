// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

/**
 * @file aes_hw.cpp
 * @brief Runtime hardware AES capability detection for Linux and macOS.
 *
 * x86_64: CPUID leaf 1, ECX bit 25 (AES-NI), bit 28 (AVX).
 * aarch64 (Linux): AT_HWCAP from /proc/self/auxv or getauxval(AT_HWCAP) — bit 3 = AES.
 * aarch64 (macOS): Always supported.
 */

#include "uav_pqc/platform/aes_hw.hpp"
#include "uav_pqc/common/logging.hpp"

#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#elif (defined(__aarch64__) || defined(__arm__)) && defined(__linux__)
#include <sys/auxv.h>
#include <asm/hwcap.h>
#ifndef AT_HWCAP2
#define AT_HWCAP2 26
#endif
#ifndef HWCAP2_AES
#define HWCAP2_AES (1 << 0)
#endif
#endif

#include <mutex>
#include <atomic>

namespace uav_pqc::platform {

namespace {

std::once_flag g_detect_flag;
std::atomic<AesCapability> g_capability{AesCapability::None};

void detect_once() noexcept {
    AesCapability cap = AesCapability::None;

#if defined(__x86_64__) || defined(__i386__)
    // CPUID leaf 1 — ECX[25] = AES-NI
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        if (ecx & (1u << 25)) {
            cap = cap | AesCapability::AesNi;
        }
    }
    // Check for VAES via leaf 7 — ECX[9]
    unsigned int leaf7_ebx = 0, leaf7_ecx = 0;
    if (__get_cpuid_count(7, 0, &eax, &leaf7_ebx, &leaf7_ecx, &edx)) {
        if (leaf7_ecx & (1u << 9)) {
            cap = cap | AesCapability::Vaes;
        }
    }

#elif defined(__aarch64__) && defined(__linux__)
    unsigned long hwcap = ::getauxval(AT_HWCAP);
    if (hwcap & HWCAP_AES) {
        cap = cap | AesCapability::ArmCrypto;
    }

#elif defined(__arm__) && defined(__linux__)
    unsigned long hwcap = ::getauxval(AT_HWCAP2);
    if (hwcap & HWCAP2_AES) {
        cap = cap | AesCapability::ArmV7Crypto;
    }
#elif defined(__APPLE__) && defined(__aarch64__)
    // On macOS arm64 (Apple Silicon), AES instructions are always supported.
    cap = cap | AesCapability::ArmCrypto;
#endif

    g_capability.store(cap, std::memory_order_relaxed);

    UAV_PQC_LOG_INFO("platform.aes_hw",
                     "AES capability: AES-NI={} ARMCrypto={} VAES={}",
                     has_capability(cap, AesCapability::AesNi),
                     has_capability(cap, AesCapability::ArmCrypto),
                     has_capability(cap, AesCapability::Vaes));
}

} // anonymous namespace

AesCapability detect_aes_capability() noexcept {
    std::call_once(g_detect_flag, detect_once);
    return g_capability.load(std::memory_order_relaxed);
}

} // namespace uav_pqc::platform
