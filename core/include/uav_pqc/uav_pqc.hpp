// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
#pragma once

/**
 * @file uav_pqc.hpp
 * @brief Convenience umbrella header — includes all public uav_pqc headers.
 *
 * Applications that want the full stack can include only this file.
 * Embedding/firmware targets that need only specific modules should include
 * the individual headers directly (to avoid pulling in spdlog / JSON in
 * translation units where they are not needed).
 */

// ── Foundation ────────────────────────────────────────────────────────────────
#include "uav_pqc/common/types.hpp"
#include "uav_pqc/common/error.hpp"
#include "uav_pqc/common/logging.hpp"
#include "uav_pqc/common/version.hpp"

// ── Platform ──────────────────────────────────────────────────────────────────
#include "uav_pqc/platform/hal.hpp"
#include "uav_pqc/platform/clock.hpp"
#include "uav_pqc/platform/random.hpp"
#include "uav_pqc/platform/aes_hw.hpp"

// ── Cryptographic primitives ──────────────────────────────────────────────────
#include "uav_pqc/crypto/kem.hpp"
#include "uav_pqc/crypto/dsa.hpp"
#include "uav_pqc/crypto/aead.hpp"
#include "uav_pqc/crypto/hkdf.hpp"
#include "uav_pqc/crypto/ml_kem.hpp"
#include "uav_pqc/crypto/ml_dsa.hpp"
#include "uav_pqc/crypto/x25519.hpp"
#include "uav_pqc/crypto/ecdsa_p256.hpp"
#include "uav_pqc/crypto/aes_gcm.hpp"
#include "uav_pqc/crypto/chacha20_poly1305.hpp"
#include "uav_pqc/crypto/hybrid_kem.hpp"

// ── Protocol ──────────────────────────────────────────────────────────────────
#include "uav_pqc/protocol/mode.hpp"
#include "uav_pqc/protocol/suite.hpp"
#include "uav_pqc/protocol/message.hpp"
#include "uav_pqc/protocol/handshake.hpp"

// ── Policy ────────────────────────────────────────────────────────────────────
#include "uav_pqc/policy/profile.hpp"
#include "uav_pqc/policy/context.hpp"
#include "uav_pqc/policy/acpe.hpp"

// ── Session ───────────────────────────────────────────────────────────────────
#include "uav_pqc/session/nonce_manager.hpp"
#include "uav_pqc/session/session.hpp"
#include "uav_pqc/session/session_cache.hpp"

// ── Group / TreeKEM ───────────────────────────────────────────────────────────
#include "uav_pqc/group/membership.hpp"
#include "uav_pqc/group/group_key.hpp"
#include "uav_pqc/group/tree_kem.hpp"

// ── Transport ─────────────────────────────────────────────────────────────────
#include "uav_pqc/transport/channel.hpp"
#include "uav_pqc/transport/fragment.hpp"
#include "uav_pqc/transport/retransmit.hpp"

// ── Identity ──────────────────────────────────────────────────────────────────
#include "uav_pqc/identity/certificate.hpp"
#include "uav_pqc/identity/trust_chain.hpp"
#include "uav_pqc/identity/credential_store.hpp"

// ── Simulation ────────────────────────────────────────────────────────────────
#include "uav_pqc/sim/event_scheduler.hpp"
#include "uav_pqc/sim/timer_manager.hpp"
#include "uav_pqc/sim/timeline_logger.hpp"
#include "uav_pqc/sim/simulation_context.hpp"

// ── Diagnostics ───────────────────────────────────────────────────────────────
#include "uav_pqc/diagnostics/metrics.hpp"
