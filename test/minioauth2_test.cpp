#define CATCH_CONFIG_MAIN // Provides main() for Catch2
#include <catch2/catch_test_macros.hpp>
#include "minioauth2.hpp"
#include <string>
#include <set>
#include <iostream>

TEST_CASE("Random String Generation", "[random]") {
    std::string s1 = minioauth2::generate_random_string(32);
    std::string s2 = minioauth2::generate_random_string(32);

    REQUIRE(s1.length() == 32);
    REQUIRE(s2.length() == 32);
    REQUIRE(s1 != s2); // Extremely unlikely to be equal

    // Check charset (alphanumeric)
    std::string allowed_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (char c : s1) {
        REQUIRE(allowed_chars.find(c) != std::string::npos);
    }

    REQUIRE(minioauth2::generate_random_string(0).empty());
    REQUIRE(minioauth2::generate_random_string(10).length() == 10);
}

TEST_CASE("URL Encoding/Decoding", "[url]") {
    SECTION("Encoding") {
        REQUIRE(minioauth2::detail::url_encode("hello world") == "hello%20world");
        REQUIRE(minioauth2::detail::url_encode("test@example.com") == "test%40example.com");
        REQUIRE(minioauth2::detail::url_encode("special/:*?<>|") == "special%2F%3A%2A%3F%3C%3E%7C");
        REQUIRE(minioauth2::detail::url_encode("-_.~") == "-_.~" ); // Unreserved characters
        REQUIRE(minioauth2::detail::url_encode("") == "");
    }
    SECTION("Decoding") {
        REQUIRE(minioauth2::detail::url_decode("hello%20world") == "hello world");
        REQUIRE(minioauth2::detail::url_decode("test%40example.com") == "test@example.com");
        REQUIRE(minioauth2::detail::url_decode("special%2F%3A%2A%3F%3C%3E%7C") == "special/:*?<>|");
        REQUIRE(minioauth2::detail::url_decode("-_.~") == "-_.~");
        REQUIRE(minioauth2::detail::url_decode("") == "");
        REQUIRE(minioauth2::detail::url_decode("hello+world") == "hello world"); // + to space
        REQUIRE(minioauth2::detail::url_decode("malformed%") == "malformed%"); // Handle malformed
        REQUIRE(minioauth2::detail::url_decode("malformed%2") == "malformed%2"); // Handle malformed
        REQUIRE_THROWS(minioauth2::detail::url_decode("invalid%FGhex")); // Invalid hex chars
    }
}

TEST_CASE("Base64 URL Encoding/Decoding", "[base64]") {
    SECTION("Encoding") {
        REQUIRE(minioauth2::detail::base64_url_encode("hello") == "aGVsbG8");
        REQUIRE(minioauth2::detail::base64_url_encode("hello world 123") == "aGVsbG8gd29ybGQgMTIz");
        // Test cases from RFC 4648 (Base64url)
        REQUIRE(minioauth2::detail::base64_url_encode("\x14\xfb\x9c\x03\xd9\x7e") == "FPucA9l-");
        REQUIRE(minioauth2::detail::base64_url_encode("\x14\xfb\x9c\x03\xd9") == "FPucA9k");
        REQUIRE(minioauth2::detail::base64_url_encode("\x14\xfb\x9c\x03") == "FPucAw");
        REQUIRE(minioauth2::detail::base64_url_encode("") == "");
    }
    SECTION("Decoding") {
        REQUIRE(minioauth2::detail::base64_url_decode("aGVsbG8").value() == "hello");
        REQUIRE(minioauth2::detail::base64_url_decode("aGVsbG8gd29ybGQgMTIz").value() == "hello world 123");
        REQUIRE(minioauth2::detail::base64_url_decode("FPucA9l-").value() == "\x14\xfb\x9c\x03\xd9\x7e");
        REQUIRE(minioauth2::detail::base64_url_decode("FPucA9k").value() == "\x14\xfb\x9c\x03\xd9");
        REQUIRE(minioauth2::detail::base64_url_decode("FPucAw").value() == "\x14\xfb\x9c\x03");
        REQUIRE(minioauth2::detail::base64_url_decode("").value() == "");
        REQUIRE(minioauth2::detail::base64_url_decode("Invalid!").has_value() == false); // Invalid char '!'
    }
}

TEST_CASE("Query Parameter Parsing", "[query]") {
    std::string q1 = "code=abc&state=xyz123";
    auto p1 = minioauth2::parse_query_params(q1);
    REQUIRE(p1.size() == 2);
    REQUIRE(p1["code"] == "abc");
    REQUIRE(p1["state"] == "xyz123");

    std::string q2 = "error=access_denied&error_description=User+denied+access";
    auto p2 = minioauth2::parse_query_params(q2);
    REQUIRE(p2.size() == 2);
    REQUIRE(p2["error"] == "access_denied");
    REQUIRE(p2["error_description"] == "User denied access"); // Decoded '+'

    std::string q3 = "value=this%20has%20spaces%26stuff";
    auto p3 = minioauth2::parse_query_params(q3);
    REQUIRE(p3.size() == 1);
    REQUIRE(p3["value"] == "this has spaces&stuff"); // Decoded hex

    std::string q4 = "flag1&flag2=&key=value";
    auto p4 = minioauth2::parse_query_params(q4);
    REQUIRE(p4.size() == 3);
    REQUIRE(p4.count("flag1"));
    REQUIRE(p4["flag1"] == ""); // Key only
    REQUIRE(p4.count("flag2"));
    REQUIRE(p4["flag2"] == ""); // Key with empty value
    REQUIRE(p4["key"] == "value");

    std::string q5 = "";
    auto p5 = minioauth2::parse_query_params(q5);
    REQUIRE(p5.empty());

    // Leading '=' or empty segments
    std::string q6 = "=val&key=&" ;
    auto p6 = minioauth2::parse_query_params(q6);
    REQUIRE(p6.size() == 2); // '=val' might be parsed as key="", value="val" or skipped, behavior can vary. Let's assume key="", value="val"
    REQUIRE(p6[""] == "val");
    REQUIRE(p6["key"] == "");
}

// TODO: Add tests for:
// - generate_code_challenge (plain, S256 - needs mock SHA256 or real one)
// - build_authorization_request (check URL components)
// - build_token_exchange_request (check body components)
// - parse_token_response (requires nlohmann/json)
// - parse_jwt_payload (requires nlohmann/json)

int main() {
    // Example test (very basic)
    std::string random_str = minioauth2::generate_random_string(32);
    assert(random_str.length() == 32);
    std::cout << "Basic test passed." << std::endl;
    return 0;
} 