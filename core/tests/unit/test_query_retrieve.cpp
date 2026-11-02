// Copyright (c) 2024 UAV-PQC Authors. SPDX-License-Identifier: MIT

#include <gtest/gtest.h>
#include <filesystem>
#include <string>
#include <algorithm>

// Replicate the is_path_safe logic exactly as implemented in uav.cpp
static bool test_is_path_safe(const std::string& requested, const std::string& allowed_root) {
    try {
        std::filesystem::path req_path(requested);
        std::filesystem::path root_path(allowed_root);
        
        // Resolve absolute canonical paths (standard POSIX realpath analog)
        std::filesystem::path req_canon = std::filesystem::weakly_canonical(std::filesystem::absolute(req_path));
        std::filesystem::path root_canon = std::filesystem::weakly_canonical(std::filesystem::absolute(root_path));
        
        auto req_str = req_canon.string();
        auto root_str = root_canon.string();
        
        // Append directory separator to prevent partial folder prefix matching
        if (!root_str.empty() && root_str.back() != std::filesystem::path::preferred_separator) {
            root_str += std::filesystem::path::preferred_separator;
        }
        
        if (req_str.rfind(root_str, 0) != 0) {
            return false;
        }

        // Sensitive credentials and key blocklists
        std::string lower_req = req_str;
        std::transform(lower_req.begin(), lower_req.end(), lower_req.begin(), ::tolower);
        if (lower_req.find("users.json") != std::string::npos ||
            lower_req.find(".key") != std::string::npos ||
            lower_req.find(".pem") != std::string::npos ||
            lower_req.find("private") != std::string::npos ||
            lower_req.find("etc/") != std::string::npos ||
            lower_req.find("proc/") != std::string::npos ||
            lower_req.find("dev/") != std::string::npos) {
            return false;
        }

        return true;
    } catch (...) {
        return false;
    }
}

TEST(SecureQueryTest, ValidPathsInsideSandbox) {
    // Development sandbox root
    EXPECT_TRUE(test_is_path_safe("./uav_media/file.txt", "./uav_media"));
    EXPECT_TRUE(test_is_path_safe("uav_media/nested/image.png", "./uav_media"));
    
    // Production sandbox root
    EXPECT_TRUE(test_is_path_safe("/home/pi/uav_media/video.mp4", "/home/pi/uav_media"));
}

TEST(SecureQueryTest, BlockPathTraversalEscape) {
    // Relative traversal rejection
    EXPECT_FALSE(test_is_path_safe("./uav_media/../config.json", "./uav_media"));
    EXPECT_FALSE(test_is_path_safe("./uav_media/nested/../../users.json", "./uav_media"));
    
    // Absolute traversal attempts
    EXPECT_FALSE(test_is_path_safe("/etc/passwd", "./uav_media"));
    EXPECT_FALSE(test_is_path_safe("/var/log/messages", "/home/pi/uav_media"));
}

TEST(SecureQueryTest, PreventPartialDirectoryPrefixMatching) {
    // Ensure that '/allowed/data2' is not accepted because prefix is '/allowed/data'
    EXPECT_FALSE(test_is_path_safe("./uav_media2/test.txt", "./uav_media"));
    EXPECT_FALSE(test_is_path_safe("/home/pi/uav_medias/test.bin", "/home/pi/uav_media"));
}

TEST(SecureQueryTest, BlocklistSensitiveCredentials) {
    // Block private keys and users database access
    EXPECT_FALSE(test_is_path_safe("./uav_media/users.json", "./uav_media"));
    EXPECT_FALSE(test_is_path_safe("./uav_media/uav_private.key", "./uav_media"));
    EXPECT_FALSE(test_is_path_safe("./uav_media/pki/ca_cert.pem", "./uav_media"));
    EXPECT_FALSE(test_is_path_safe("./uav_media/private_data.txt", "./uav_media"));
    
    // Block system folders
    EXPECT_FALSE(test_is_path_safe("./uav_media/etc/passwd", "./uav_media"));
    EXPECT_FALSE(test_is_path_safe("./uav_media/proc/self/environ", "./uav_media"));
}
