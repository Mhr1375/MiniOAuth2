#include "gtest/gtest.h"
#include "minioauth2.hpp" // To access functions to test

// Test fixture for utility functions if needed, or just plain TEST_F/TEST

TEST(Base64UrlEncodeTest, HandlesEmptyString) {
    EXPECT_EQ(minioauth2::detail::base64_url_encode(""), "");
}

TEST(Base64UrlEncodeTest, EncodesSimpleString) {
    // "Hello" -> "SGVsbG8"
    EXPECT_EQ(minioauth2::detail::base64_url_encode("Hello"), "SGVsbG8");
}

TEST(Base64UrlEncodeTest, EncodesStringRequiringPaddingRemoval) {
    // Standard Base64 for "Man" is "TWFu", no padding, so Base64URL is the same.
    EXPECT_EQ(minioauth2::detail::base64_url_encode("Man"), "TWFu");
    // Standard Base64 for "Ma" is "TWE=", Base64URL is "TWE".
    EXPECT_EQ(minioauth2::detail::base64_url_encode("Ma"), "TWE");
    // Standard Base64 for "M" is "TQ==", Base64URL is "TQ".
    EXPECT_EQ(minioauth2::detail::base64_url_encode("M"), "TQ");
}

TEST(Base64UrlEncodeTest, HandlesURLSpecificCharacters) {
    // Test string with '+' and '/' which should be '-' and '_' in base64url
    // If our input for base64url_encode is raw bytes, it should just encode them.
    // If it were decoding, this would be more relevant. For encoding, any byte is valid input.
    // Let's test with bytes that would be problematic in standard base64 if not URL-safe.
    // Example: The string "?/>" contains characters that might be an issue in URLs or standard base64.
    // Bytes: 0x3f 0x2f 0x3e
    // Standard Base64: Pz4+
    // URL-safe Base64: Pz4-
    // Our function takes raw bytes and produces base64url. So, if input has byte 0xfb then output char is '-'
    // Input: std::string("\xfb\xff\xfe", 3) -> base64: "-_-" (since 0xfb->+, 0xff->/, 0xfe->~ in some variants but we use standard table for values)
    // Let's use a known vector from RFC 4648 for base64url examples
    // For PKCE, verifiers are typically alphanumeric, so complex byte patterns are less common for sha256 input,
    // but the base64url encoder should be robust.
    // For `code_challenge = base64url(sha256(code_verifier))`, the input to base64url is raw binary data.

    std::string binary_input_1 = { (char)0x14, (char)0xfb, (char)0x9c, (char)0x03, (char)0xd9, (char)0x7e };
    EXPECT_EQ(minioauth2::detail::base64_url_encode(binary_input_1), "FPucA9l-"); // Standard: FPucA9l+ 

    std::string binary_input_2 = { (char)0x14, (char)0xfb, (char)0x9c, (char)0x03, (char)0xd9 };
    EXPECT_EQ(minioauth2::detail::base64_url_encode(binary_input_2), "FPucA9k"); // Standard: FPucA9k= 

    std::string binary_input_3 = { (char)0x14, (char)0xfb, (char)0x9c, (char)0x03 };
    EXPECT_EQ(minioauth2::detail::base64_url_encode(binary_input_3), "FPucAw"); // Standard: FPucAw==
}

// TODO: Add tests for base64_url_decode
// TODO: Add tests for generate_random_string (check length, charset, randomness is hard to test deterministically)
// TODO: Add tests for generate_code_challenge (plain and S256, needs SHA256 mock or real impl)
// TODO: Add tests for url_encode/url_decode
// TODO: Add tests for parse_query_params
// TODO: Add tests for build_authorization_request
// TODO: Add tests for build_token_exchange_request
// TODO: Add tests for parse_token_response (if nlohmann/json is enabled) 