// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT
// test_profile.cpp — Unit tests for ProfileParameters

#include "uav_pqc/policy/profile.hpp"
#include <gtest/gtest.h>

using namespace uav_pqc;
using namespace uav_pqc::policy;

TEST(ProfileTest, DefaultsHaveCorrectSettings) {
    auto lw = ProfileParameters::lightweight();
    EXPECT_EQ(lw.profile, CryptographicProfile::Lightweight);
    EXPECT_EQ(lw.kem_level, crypto::MlKem::Level::Kem512);
    EXPECT_EQ(lw.dsa_level, crypto::MlDsa::Level::Dsa44);
    EXPECT_TRUE(lw.allow_classical_fallback);

    auto std_prof = ProfileParameters::standard();
    EXPECT_EQ(std_prof.profile, CryptographicProfile::Standard);
    EXPECT_EQ(std_prof.kem_level, crypto::MlKem::Level::Kem768);
    EXPECT_EQ(std_prof.dsa_level, crypto::MlDsa::Level::Dsa65);
    EXPECT_FALSE(std_prof.allow_classical_fallback);

    auto hrd = ProfileParameters::hardened();
    EXPECT_EQ(hrd.profile, CryptographicProfile::Hardened);
    EXPECT_EQ(hrd.kem_level, crypto::MlKem::Level::Kem1024);
    EXPECT_EQ(hrd.dsa_level, crypto::MlDsa::Level::Dsa87);
    EXPECT_FALSE(hrd.allow_classical_fallback);
}

TEST(ProfileTest, ParseFromJsonValid) {
    std::string json_data = R"({
        "profile": "lightweight",
        "rekey_interval_seconds": 120,
        "allow_session_resumption": false,
        "allow_classical_fallback": false
    })";

    Bytes input = bytes_from_sv(json_data);
    auto res = ProfileParameters::from_json(ByteSpan{input.data(), input.size()});
    ASSERT_TRUE(res.has_value());

    auto params = res.value();
    EXPECT_EQ(params.profile, CryptographicProfile::Lightweight);
    EXPECT_EQ(params.rekey_interval_seconds, 120u);
    EXPECT_FALSE(params.allow_session_resumption);
    EXPECT_FALSE(params.allow_classical_fallback);
}

TEST(ProfileTest, ParseFromJsonInvalidFormat) {
    std::string invalid_json = "{ invalid-json }";
    Bytes input = bytes_from_sv(invalid_json);
    auto res = ProfileParameters::from_json(ByteSpan{input.data(), input.size()});
    EXPECT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::InvalidArgument);
}
