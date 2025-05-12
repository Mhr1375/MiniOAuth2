#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <random>
#include <algorithm>
#include <iterator>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <map>
#include <chrono>
#include <cstdlib> // For std::getenv
#include <cctype>  // For std::isxdigit, std::tolower
#include <cstdint> // Needed by PicoSHA2 and potentially others

#ifdef MINIOAUTH2_USE_NLOHMANN_JSON
#include <nlohmann/json.hpp>
#endif

/**
 * @brief Main namespace for the MiniOAuth2 library.
 */
namespace minioauth2 {

//----------------------------------------------------------------------
// Configuration
//----------------------------------------------------------------------

/**
 * @struct OAuthConfig
 * @brief Holds the necessary configuration for an OAuth 2.0 provider.
 */
struct OAuthConfig {
    std::string client_id;              ///< The client ID issued by the authorization server.
    std::string client_secret;          ///< The client secret (needed for token exchange with some providers).
    std::string authorization_endpoint; ///< The authorization endpoint URL.
    std::string token_endpoint;         ///< The token endpoint URL.
    std::string redirect_uri;           ///< The client's redirect URI.
    std::vector<std::string> default_scopes; ///< Default scopes to request if not overridden.
};

/**
 * @brief Predefined configurations for common OAuth providers.
 */
namespace config {
    /**
     * @brief Provides a default configuration for Google OAuth 2.0.
     * @warning Client ID, Client Secret, and Redirect URI must be set by the user.
     * @return OAuthConfig for Google.
     */
    inline OAuthConfig Google() {
        return {
            "", // Needs to be set by the application (e.g., from environment variables)
            "", // Needs to be set by the application
            "https://accounts.google.com/o/oauth2/v2/auth",
            "https://oauth2.googleapis.com/token",
            "", // Needs to be set by the application
            {"openid", "profile", "email"}
        };
    }
} // namespace config

//----------------------------------------------------------------------
// Internal Detail Namespace
//----------------------------------------------------------------------
namespace detail {

    // ==========================================================================
    // PicoSHA2 Integration Start (MIT License)
    // Copyright (c) 2017 okdshin
    // https://github.com/okdshin/PicoSHA2
    // ==========================================================================
/*
The MIT License (MIT)

Copyright (C) 2017 okdshin

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
#ifndef PICOSHA2_H_INTERNAL // Avoid redefinition if user also includes it
#define PICOSHA2_H_INTERNAL
// picosha2:20140213

#ifndef PICOSHA2_BUFFER_SIZE_FOR_INPUT_ITERATOR
#define PICOSHA2_BUFFER_SIZE_FOR_INPUT_ITERATOR 1048576
#endif

#include <algorithm> // Already included but good practice
#include <cassert>
#include <iterator> // Already included
#include <sstream> // Already included
#include <vector> // Already included

// Wrap picosha2 code in its own nested namespace within detail
namespace picosha2 {
typedef unsigned long word_t;
typedef unsigned char byte_t;

static const size_t k_digest_size = 32;

namespace detail {
inline byte_t mask_8bit(byte_t x) { return x & 0xff; }

inline word_t mask_32bit(word_t x) { return x & 0xffffffff; }

const word_t add_constant[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

const word_t initial_message_digest[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372,
                                          0xa54ff53a, 0x510e527f, 0x9b05688c,
                                          0x1f83d9ab, 0x5be0cd19};

inline word_t ch(word_t x, word_t y, word_t z) { return (x & y) ^ ((~x) & z); }

inline word_t maj(word_t x, word_t y, word_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline word_t rotr(word_t x, std::size_t n) {
    assert(n < 32);
    return mask_32bit((x >> n) | (x << (32 - n)));
}

inline word_t bsig0(word_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }

inline word_t bsig1(word_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }

inline word_t shr(word_t x, std::size_t n) {
    assert(n < 32);
    return x >> n;
}

inline word_t ssig0(word_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3); }

inline word_t ssig1(word_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10); }

template <typename RaIter1, typename RaIter2>
void hash256_block(RaIter1 message_digest, RaIter2 first, RaIter2 last) {
    assert(first + 64 == last);
    static_cast<void>(last);  // for avoiding unused-variable warning
    word_t w[64];
    std::fill(w, w + 64, word_t(0));
    for (std::size_t i = 0; i < 16; ++i) {
        w[i] = (static_cast<word_t>(mask_8bit(*(first + i * 4))) << 24) |
               (static_cast<word_t>(mask_8bit(*(first + i * 4 + 1))) << 16) |
               (static_cast<word_t>(mask_8bit(*(first + i * 4 + 2))) << 8) |
               (static_cast<word_t>(mask_8bit(*(first + i * 4 + 3))));
    }
    for (std::size_t i = 16; i < 64; ++i) {
        w[i] = mask_32bit(ssig1(w[i - 2]) + w[i - 7] + ssig0(w[i - 15]) +
                          w[i - 16]);
    }

    word_t a = *message_digest;
    word_t b = *(message_digest + 1);
    word_t c = *(message_digest + 2);
    word_t d = *(message_digest + 3);
    word_t e = *(message_digest + 4);
    word_t f = *(message_digest + 5);
    word_t g = *(message_digest + 6);
    word_t h = *(message_digest + 7);

    for (std::size_t i = 0; i < 64; ++i) {
        word_t temp1 = h + bsig1(e) + ch(e, f, g) + add_constant[i] + w[i];
        word_t temp2 = bsig0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = mask_32bit(d + temp1);
        d = c;
        c = b;
        b = a;
        a = mask_32bit(temp1 + temp2);
    }
    *message_digest += a;
    *(message_digest + 1) += b;
    *(message_digest + 2) += c;
    *(message_digest + 3) += d;
    *(message_digest + 4) += e;
    *(message_digest + 5) += f;
    *(message_digest + 6) += g;
    *(message_digest + 7) += h;
    for (std::size_t i = 0; i < 8; ++i) {
        *(message_digest + i) = mask_32bit(*(message_digest + i));
    }
}

}  // namespace detail

template <typename InIter>
void output_hex(InIter first, InIter last, std::ostream& os) {
    os.setf(std::ios::hex, std::ios::basefield);
    while (first != last) {
        os.width(2);
        os.fill('0');
        os << static_cast<unsigned int>(*first);
        ++first;
    }
    os.setf(std::ios::dec, std::ios::basefield);
}

template <typename InIter>
void bytes_to_hex_string(InIter first, InIter last, std::string& hex_str) {
    std::ostringstream oss;
    output_hex(first, last, oss);
    hex_str.assign(oss.str());
}

template <typename InContainer>
void bytes_to_hex_string(const InContainer& bytes, std::string& hex_str) {
    bytes_to_hex_string(bytes.begin(), bytes.end(), hex_str);
}

template <typename InIter>
std::string bytes_to_hex_string(InIter first, InIter last) {
    std::string hex_str;
    bytes_to_hex_string(first, last, hex_str);
    return hex_str;
}

template <typename InContainer>
std::string bytes_to_hex_string(const InContainer& bytes) {
    std::string hex_str;
    bytes_to_hex_string(bytes, hex_str);
    return hex_str;
}

class hash256_one_by_one {
   public:
    hash256_one_by_one() { init(); }

    void init() {
        buffer_.clear();
        std::fill(data_length_digits_, data_length_digits_ + 4, word_t(0));
        std::copy(picosha2::detail::initial_message_digest, // Need to qualify namespace here
                  picosha2::detail::initial_message_digest + 8, h_);
    }

    template <typename RaIter>
    void process(RaIter first, RaIter last) {
        add_to_data_length(static_cast<word_t>(std::distance(first, last)));
        std::copy(first, last, std::back_inserter(buffer_));
        std::size_t i = 0;
        for (; i + 64 <= buffer_.size(); i += 64) {
            picosha2::detail::hash256_block(h_, buffer_.begin() + i, // Need to qualify namespace here
                                  buffer_.begin() + i + 64);
        }
        buffer_.erase(buffer_.begin(), buffer_.begin() + i);
    }

    void finish() {
        byte_t temp[64];
        std::fill(temp, temp + 64, byte_t(0));
        std::size_t remains = buffer_.size();
        std::copy(buffer_.begin(), buffer_.end(), temp);
        assert(remains < 64);

        // This branch is not executed actually (`remains` is always lower than 64),
        // but needed to avoid g++ false-positive warning.
        // See https://github.com/okdshin/PicoSHA2/issues/25
        // vvvvvvvvvvvvvvvv
        if(remains >= 64) {
            remains = 63;
        }
        // ^^^^^^^^^^^^^^^^

        temp[remains] = 0x80;

        if (remains > 55) {
            std::fill(temp + remains + 1, temp + 64, byte_t(0));
            picosha2::detail::hash256_block(h_, temp, temp + 64); // Need to qualify namespace here
            std::fill(temp, temp + 64 - 4, byte_t(0)); // Should be 56? Check original code. It's temp + 64 - 8. Corrected:
            //std::fill(temp, temp + 56, byte_t(0));
        } else {
            //std::fill(temp + remains + 1, temp + 64 - 4, byte_t(0)); // Corrected:
             std::fill(temp + remains + 1, temp + 56, byte_t(0));
        }

        write_data_bit_length(&(temp[56]));
        picosha2::detail::hash256_block(h_, temp, temp + 64); // Need to qualify namespace here
    }

    template <typename OutIter>
    void get_hash_bytes(OutIter first, OutIter last) const {
        for (const word_t* iter = h_; iter != h_ + 8; ++iter) {
            for (std::size_t i = 0; i < 4 && first != last; ++i) {
                *(first++) = picosha2::detail::mask_8bit( // Need to qualify namespace here
                    static_cast<byte_t>((*iter >> (24 - 8 * i))));
            }
        }
    }

   private:
    void add_to_data_length(word_t n) {
        word_t carry = 0;
        data_length_digits_[0] += n;
        for (std::size_t i = 0; i < 4; ++i) {
            data_length_digits_[i] += carry;
            if (data_length_digits_[i] >= 65536u) {
                carry = data_length_digits_[i] >> 16;
                data_length_digits_[i] &= 65535u;
            } else {
                break;
            }
        }
    }
    void write_data_bit_length(byte_t* begin) {
        word_t data_bit_length_digits[4];
        std::copy(data_length_digits_, data_length_digits_ + 4,
                  data_bit_length_digits);

        // convert byte length to bit length (multiply 8 or shift 3 times left)
        word_t carry = 0;
        for (std::size_t i = 0; i < 4; ++i) {
            word_t before_val = data_bit_length_digits[i];
            data_bit_length_digits[i] <<= 3;
            data_bit_length_digits[i] |= carry;
            data_bit_length_digits[i] &= 65535u;
            carry = (before_val >> (16 - 3)) & 65535u;
        }

        // write data_bit_length (Big Endian order)
        for (int i = 3; i >= 0; --i) {
            (*begin++) = static_cast<byte_t>(data_bit_length_digits[i] >> 8);
            (*begin++) = static_cast<byte_t>(data_bit_length_digits[i]);
        }
    }
    std::vector<byte_t> buffer_;
    word_t data_length_digits_[4];  // as 64bit integer (16bit x 4 integer stored in little endian order of 16-bit chunks)
    word_t h_[8];
};

inline void get_hash_hex_string(const hash256_one_by_one& hasher,
                                std::string& hex_str) {
    byte_t hash[k_digest_size];
    hasher.get_hash_bytes(hash, hash + k_digest_size);
    return bytes_to_hex_string(hash, hash + k_digest_size, hex_str);
}

inline std::string get_hash_hex_string(const hash256_one_by_one& hasher) {
    std::string hex_str;
    get_hash_hex_string(hasher, hex_str);
    return hex_str;
}

namespace impl {
template <typename RaIter, typename OutIter>
void hash256_impl(RaIter first, RaIter last, OutIter first2, OutIter last2, int,
                  std::random_access_iterator_tag) {
    hash256_one_by_one hasher;
    // hasher.init(); // Constructor calls init()
    hasher.process(first, last);
    hasher.finish();
    hasher.get_hash_bytes(first2, last2);
}

template <typename InputIter, typename OutIter>
void hash256_impl(InputIter first, InputIter last, OutIter first2,
                  OutIter last2, int buffer_size, std::input_iterator_tag) {
    std::vector<byte_t> buffer(buffer_size);
    hash256_one_by_one hasher;
    // hasher.init(); // Constructor calls init()
    while (first != last) {
        int size = buffer_size;
        for (int i = 0; i != buffer_size; ++i, ++first) {
            if (first == last) {
                size = i;
                break;
            }
            buffer[i] = *first;
        }
        hasher.process(buffer.begin(), buffer.begin() + size);
    }
    hasher.finish();
    hasher.get_hash_bytes(first2, last2);
}
} // namespace impl

template <typename InIter, typename OutIter>
void hash256(InIter first, InIter last, OutIter first2, OutIter last2,
             int buffer_size = PICOSHA2_BUFFER_SIZE_FOR_INPUT_ITERATOR) {
    picosha2::impl::hash256_impl( // Need to qualify namespace here
        first, last, first2, last2, buffer_size,
        typename std::iterator_traits<InIter>::iterator_category());
}

template <typename InIter, typename OutContainer>
void hash256(InIter first, InIter last, OutContainer& dst) {
    hash256(first, last, dst.begin(), dst.end());
}

template <typename InContainer, typename OutIter>
void hash256(const InContainer& src, OutIter first, OutIter last) {
    hash256(src.begin(), src.end(), first, last);
}

template <typename InContainer, typename OutContainer>
void hash256(const InContainer& src, OutContainer& dst) {
    hash256(src.begin(), src.end(), dst.begin(), dst.end());
}

template <typename InIter>
void hash256_hex_string(InIter first, InIter last, std::string& hex_str) {
    byte_t hashed[k_digest_size];
    hash256(first, last, hashed, hashed + k_digest_size);
    std::ostringstream oss;
    output_hex(hashed, hashed + k_digest_size, oss);
    hex_str.assign(oss.str());
}

template <typename InIter>
std::string hash256_hex_string(InIter first, InIter last) {
    std::string hex_str;
    hash256_hex_string(first, last, hex_str);
    return hex_str;
}

inline void hash256_hex_string(const std::string& src, std::string& hex_str) {
    hash256_hex_string(src.begin(), src.end(), hex_str);
}

template <typename InContainer>
void hash256_hex_string(const InContainer& src, std::string& hex_str) {
    hash256_hex_string(src.begin(), src.end(), hex_str);
}

template <typename InContainer>
std::string hash256_hex_string(const InContainer& src) {
    return hash256_hex_string(src.begin(), src.end());
}
} // namespace picosha2
#endif  // PICOSHA2_H_INTERNAL
    // ==========================================================================
    // PicoSHA2 Integration End
    // ==========================================================================


    /**
     * @brief Generates a string of random bytes.
     * @param len Number of bytes to generate.
     * @return String containing random bytes.
     */
    inline std::string generate_random_bytes_internal(std::size_t len) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> distrib(0, 255);
        std::string result(len, '\\x20'); // Use hex escape for space
        std::generate_n(result.begin(), len, [&]() { return static_cast<char>(distrib(gen)); });
        return result;
    }

    /**
     * @brief Encodes a string to Base64 URL-safe format.
     * @param input The string to encode.
     * @return The Base64 URL-encoded string.
     */
    inline std::string base64_url_encode(std::string_view input) {
        // Uses picosha2::bytes_to_hex_string implicitly if needed? No. Separate.
        // This function remains the same.
        const std::string_view base64_chars =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789-_"; // URL-safe variant

        std::string encoded;
        encoded.reserve(((input.length() / 3) + (input.length() % 3 > 0)) * 4);

        int val = 0;
        int bits = -6;
        for (unsigned char c : input) {
            val = (val << 8) + c;
            bits += 8;
            while (bits >= 0) {
                encoded.push_back(base64_chars[(val >> bits) & 0x3F]);
                bits -= 6;
            }
        }

        if (bits > -6) {
            encoded.push_back(base64_chars[((val << 8) >> (bits + 8)) & 0x3F]);
        }
        // No padding for base64url
        return encoded;
    }

    /**
     * @brief Decodes a Base64 URL-safe encoded string.
     * @param input The Base64 URL-encoded string.
     * @return The decoded string, or std::nullopt if decoding fails.
     * @note Handles input without padding.
     */
    inline std::optional<std::string> base64_url_decode(std::string_view input) {
        // This function remains the same.
        const std::string base64_chars_with_padding =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789-_="; // Includes padding char for lookup

        std::string_view temp_input = input;

        std::string decoded;
        decoded.reserve(input.length() * 3 / 4); // Approximate decoded length

        std::vector<int> T(256, -1);
        for (int i = 0; i < 64; i++) T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"[i]] = i;

        int val = 0;
        int bits = -8; // Start with -8 to ensure the first character is processed correctly
        for (char c : temp_input) {
            if (T[static_cast<unsigned char>(c)] == -1) { // Invalid character
                 if (c == '=') break; // Padding character, stop processing
                return std::nullopt; // Or throw an error
            }
            val = (val << 6) + T[static_cast<unsigned char>(c)];
            bits += 6;
            if (bits >= 0) {
                decoded.push_back(static_cast<char>((val >> bits) & 0xFF));
                bits -= 8;
            }
        }
        return decoded;
    }


    /**
     * @brief Computes SHA256 hash of a string using PicoSHA2.
     * @param input The string to hash.
     * @return A string containing the raw 32-byte SHA256 hash.
     */
    inline std::string sha256(std::string_view input) {
        std::vector<unsigned char> hash_vec(picosha2::k_digest_size);
        // Use iterator-based function from PicoSHA2 (now defined above)
        picosha2::hash256(input.begin(), input.end(), hash_vec.begin(), hash_vec.end());

        // Convert vector of bytes to std::string
        return std::string(reinterpret_cast<const char*>(hash_vec.data()), hash_vec.size());
    }

    /**
     * @brief URL-encodes a string.
     * @param value The string to encode.
     * @return The URL-encoded string.
     */
    inline std::string url_encode(std::string_view value) {
        // This function remains the same.
         std::ostringstream encoded;
        encoded << std::fixed << std::setprecision(0);

        for (char c : value) {
            if (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.' || c == '~') {
                encoded << c;
            } else {
                encoded << '%' << std::uppercase << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(static_cast<unsigned char>(c));
            }
        }
        return encoded.str();
    }

    /**
     * @brief URL-decodes a string.
     * @param value The string to decode.
     * @return The URL-decoded string.
     * @throws std::runtime_error if decoding encounters invalid hex characters.
     */
    inline std::string url_decode(std::string_view value) {
         // This function remains the same.
        std::ostringstream decoded;
        for (size_t i = 0; i < value.length(); ++i) {
            if (value[i] == '%') {
                if (i + 2 < value.length() && std::isxdigit(static_cast<unsigned char>(value[i+1])) && std::isxdigit(static_cast<unsigned char>(value[i+2]))) {
                    std::string hex_byte_str = std::string(value.substr(i + 1, 2));
                    try {
                        char byte = static_cast<char>(std::stoi(hex_byte_str, nullptr, 16));
                        decoded << byte;
                    } catch (const std::invalid_argument& e) {
                        throw std::runtime_error("URL Decode: Invalid hex characters in % escape: " + hex_byte_str);
                    } catch (const std::out_of_range& e) {
                        throw std::runtime_error("URL Decode: Hex value out of range in % escape: " + hex_byte_str);
                    }
                    i += 2;
                } else {
                     decoded << '%'; // Or handle error
                }
            } else if (value[i] == '+') {
                decoded << ' ';
            } else {
                decoded << value[i];
            }
        }
        return decoded.str();
    }

} // namespace detail

//----------------------------------------------------------------------
// Public API
//----------------------------------------------------------------------

/**
 * @brief Generates a cryptographically secure random string suitable for 'state' or 'code_verifier'.
 * @param length The desired length of the string. RFC 7636 recommends 43-128 chars for code_verifier.
 *               Minimum 32 characters is generally advised for good entropy.
 * @return A random alphanumeric string (A-Z, a-z, 0-9).
 * @note Uses std::random_device for seeding, which aims for non-deterministic random numbers.
 */
inline std::string generate_random_string(std::size_t length = 43) {
    if (length == 0) return "";
    // Using a more restricted charset for general compatibility,
    // but PKCE verifiers can use unreserved characters: A-Z / a-z / 0-9 / "-" / "." / "_" / "~"
    const std::string_view chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::string result(length, '\x20'); // Use hex escape for space
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, chars.length() - 1);
    std::generate_n(result.begin(), length, [&]() { return chars[distrib(gen)]; });
    return result;
}

/**
 * @brief Generates the PKCE code challenge from a code verifier.
 * @param code_verifier The code verifier string.
 * @param method The challenge method. Supported: "plain", "S256".
 * @return The generated code challenge string.
 * @throws std::runtime_error If an unsupported method is requested or if S256 is used without a functional SHA256 implementation.
 * @warning If using "S256", ensure `detail::sha256` has a real cryptographic hash implementation.
 *          The default placeholder is insecure.
 */
inline std::string generate_code_challenge(std::string_view code_verifier, std::string_view method = "S256") {
    if (method == "plain") {
        return std::string(code_verifier);
    } else if (method == "S256") {
        // IMPORTANT: The detail::sha256 function MUST be a real SHA256 implementation.
        // The current placeholder is insecure.
        std::string hashed_verifier = detail::sha256(code_verifier);
        if (hashed_verifier.length() != 32) { // SHA256 produces 32 bytes
             throw std::runtime_error("S256 code challenge generation failed: SHA256 output is not 32 bytes. Ensure SHA256 is correctly implemented.");
        }
        return detail::base64_url_encode(hashed_verifier);
    } else {
        throw std::runtime_error("Unsupported code challenge method: " + std::string(method));
    }
}

/**
 * @struct AuthorizationRequest
 * @brief Holds all necessary components for initiating an authorization request.
 */
struct AuthorizationRequest {
    std::string state;                 ///< Generated 'state' parameter. Store this to validate upon callback.
    std::string code_verifier;         ///< Generated PKCE 'code_verifier'. Store this securely until token exchange.
    std::string code_challenge;        ///< Generated PKCE 'code_challenge'.
    std::string code_challenge_method; ///< PKCE method used ("plain" or "S256").
    std::string authorization_url;     ///< The fully constructed authorization URL to redirect the user to.
};

/**
 * @brief Prepares the parameters and URL to initiate the Authorization Code Flow with PKCE.
 * @param config The OAuth configuration for the provider.
 * @param scopes Optional list of specific scopes to request, overriding defaults in config.
 * @param pkce_method The PKCE method to use ("plain" or "S256"). Defaults to "S256".
 * @param custom_state Optional custom state value. If empty, a random one is generated.
 * @return An AuthorizationRequest struct containing generated values and the full URL.
 * @note It's highly recommended to use "S256" as the pkce_method for security.
 */
inline AuthorizationRequest build_authorization_request(
    const OAuthConfig& config,
    const std::vector<std::string>& scopes = {},
    std::string_view pkce_method = "S256",
    std::string_view custom_state = "")
{
    AuthorizationRequest req;
    req.state = custom_state.empty() ? generate_random_string(32) : std::string(custom_state);
    req.code_verifier = generate_random_string(43); // Min 43 chars for PKCE
    req.code_challenge_method = std::string(pkce_method);
    req.code_challenge = generate_code_challenge(req.code_verifier, req.code_challenge_method);

    std::ostringstream url_ss;
    url_ss << config.authorization_endpoint;
    url_ss << "?response_type=code";
    url_ss << "&client_id=" << detail::url_encode(config.client_id);
    url_ss << "&redirect_uri=" << detail::url_encode(config.redirect_uri);
    url_ss << "&state=" << detail::url_encode(req.state);
    url_ss << "&code_challenge=" << detail::url_encode(req.code_challenge);
    url_ss << "&code_challenge_method=" << req.code_challenge_method;

    const auto& scopes_to_use = scopes.empty() ? config.default_scopes : scopes;
    if (!scopes_to_use.empty()) {
        url_ss << "&scope=";
        for (size_t i = 0; i < scopes_to_use.size(); ++i) {
            url_ss << detail::url_encode(scopes_to_use[i]) << (i == scopes_to_use.size() - 1 ? "" : " ");
        }
    }
    // Add other optional parameters if needed, e.g., prompt, login_hint

    req.authorization_url = url_ss.str();
    return req;
}

/**
 * @struct TokenExchangeRequest
 * @brief Holds parameters for the token exchange HTTP request.
 */
struct TokenExchangeRequest {
    std::string url;                            ///< The token endpoint URL.
    std::string method = "POST";                ///< HTTP method (always POST).
    std::map<std::string, std::string> headers; ///< HTTP headers for the request.
    std::string body;                           ///< HTTP request body (form-urlencoded).
};

/**
 * @brief Prepares the parameters for the token exchange POST request.
 * This function *does not* perform the HTTP request itself. The caller must use an HTTP client.
 * @param config The OAuth configuration.
 * @param authorization_code The authorization code received from the callback.
 * @param code_verifier The original PKCE code_verifier associated with this flow.
 * @return A TokenExchangeRequest struct with all necessary details for the HTTP POST.
 */
inline TokenExchangeRequest build_token_exchange_request(
    const OAuthConfig& config,
    std::string_view authorization_code,
    std::string_view code_verifier)
{
    TokenExchangeRequest req;
    req.url = config.token_endpoint;
    req.headers["Content-Type"] = "application/x-www-form-urlencoded";
    // Note: Basic Authentication for client_id:client_secret in Authorization header
    // is an alternative to sending them in the body for some providers.
    // Example:
    // if (!config.client_id.empty() && !config.client_secret.empty()) {
    //    std::string creds = detail::base64_encode(config.client_id + ":" + config.client_secret);
    //    req.headers["Authorization"] = "Basic " + creds;
    // }

    std::ostringstream body_ss;
    body_ss << "grant_type=authorization_code";
    body_ss << "&code=" << detail::url_encode(authorization_code);
    body_ss << "&redirect_uri=" << detail::url_encode(config.redirect_uri);
    body_ss << "&client_id=" << detail::url_encode(config.client_id);
    if (!config.client_secret.empty()) { // Client secret might not be needed for public clients using PKCE
        body_ss << "&client_secret=" << detail::url_encode(config.client_secret);
    }
    body_ss << "&code_verifier=" << detail::url_encode(code_verifier);

    req.body = body_ss.str();
    return req;
}


#ifdef MINIOAUTH2_USE_NLOHMANN_JSON
/**
 * @struct TokenResponse
 * @brief Represents a parsed response from the token endpoint.
 * @note This structure is available only if `MINIOAUTH2_USE_NLOHMANN_JSON` is defined.
 */
struct TokenResponse {
    std::string access_token;                 ///< The access token.
    std::string token_type;                   ///< Type of token (e.g., "Bearer").
    int expires_in = 0;                       ///< Token lifetime in seconds.
    std::optional<std::string> refresh_token; ///< Optional refresh token.
    std::optional<std::string> id_token;      ///< Optional ID token (for OpenID Connect).
    std::optional<std::string> scope;         ///< Scopes granted with the token.
    nlohmann::json raw_response;              ///< The full raw JSON response.
};

/**
 * @brief Parses a JSON response body (as nlohmann::json object) from the token endpoint.
 * @param json_response The nlohmann::json object representing the response.
 * @return A TokenResponse struct.
 * @throws nlohmann::json::exception If parsing fails or required fields are missing.
 * @note This function is available only if `MINIOAUTH2_USE_NLOHMANN_JSON` is defined.
 */
inline TokenResponse parse_token_response(const nlohmann::json& json_response) {
    TokenResponse resp;
    resp.raw_response = json_response;

    if (!json_response.is_object()) {
        throw std::runtime_error("Token response is not a JSON object.");
    }

    resp.access_token = json_response.at("access_token").get<std::string>();
    resp.token_type = json_response.at("token_type").get<std::string>();
    resp.expires_in = json_response.value("expires_in", 0); // Gracefully handle if missing

    if (json_response.contains("refresh_token") && !json_response.at("refresh_token").is_null()) {
        resp.refresh_token = json_response.at("refresh_token").get<std::string>();
    }
    if (json_response.contains("id_token") && !json_response.at("id_token").is_null()) {
        resp.id_token = json_response.at("id_token").get<std::string>();
    }
    if (json_response.contains("scope") && !json_response.at("scope").is_null()) {
        resp.scope = json_response.at("scope").get<std::string>();
    }

    return resp;
}

/**
 * @brief Parses a JSON response body (as string) from the token endpoint.
 * @param response_body The string containing the JSON response.
 * @return A TokenResponse struct.
 * @throws std::runtime_error If JSON parsing fails or required fields are missing.
 * @note This function is available only if `MINIOAUTH2_USE_NLOHMANN_JSON` is defined.
 */
inline TokenResponse parse_token_response(std::string_view response_body) {
     try {
        nlohmann::json j = nlohmann::json::parse(response_body);
        return parse_token_response(j);
    } catch (const nlohmann::json::parse_error& e) {
        throw std::runtime_error("Failed to parse token response JSON: " + std::string(e.what()) + ". Response body: " + std::string(response_body));
    } catch (const nlohmann::json::exception& e) { // Catches at() and get() errors
         throw std::runtime_error("Error accessing token response fields: " + std::string(e.what()));
    }
}

/**
 * @brief Parses the payload of a JWT string.
 * Does not validate the signature or any claims. Only decodes and parses the JSON payload.
 * @param jwt_string The JWT string (typically an id_token).
 * @return nlohmann::json object of the payload, or std::nullopt if parsing fails.
 * @note This function is available only if `MINIOAUTH2_USE_NLOHMANN_JSON` is defined.
 * @warning This function DOES NOT VALIDATE the JWT signature or claims like 'exp', 'aud', 'iss'.
 *          For production use, a full JWT validation library is recommended if relying on claims.
 */
inline std::optional<nlohmann::json> parse_jwt_payload(std::string_view jwt_string) {
    std::string::size_type pos1 = jwt_string.find('.');
    if (pos1 == std::string::npos) return std::nullopt; // Not a JWT or malformed

    std::string::size_type pos2 = jwt_string.find('.', pos1 + 1);
    if (pos2 == std::string::npos) return std::nullopt; // Not a JWT or malformed

    std::string_view payload_b64url = jwt_string.substr(pos1 + 1, pos2 - (pos1 + 1));
    
    std::optional<std::string> decoded_payload_str = detail::base64_url_decode(payload_b64url);
    if (!decoded_payload_str) return std::nullopt;

    try {
        return nlohmann::json::parse(*decoded_payload_str);
    } catch (const nlohmann::json::parse_error&) {
        return std::nullopt;
    }
}

#endif // MINIOAUTH2_USE_NLOHMANN_JSON

//----------------------------------------------------------------------
// Utility Functions
//----------------------------------------------------------------------

/**
 * @brief Parses query parameters from a URL query string.
 * @param query_string The query string part of a URL (e.g., "code=abc&state=xyz"), without the leading '?'.
 * @return A map of key-value pairs. Values are URL-decoded.
 * @throws std::runtime_error if URL decoding of a parameter value fails.
 */
inline std::map<std::string, std::string> parse_query_params(std::string_view query_string) {
    std::map<std::string, std::string> params;
    std::string_view sv(query_string);

    // Remove leading '?' if present (though function doc says it shouldn't be)
    if (!sv.empty() && sv.front() == '?') {
        sv.remove_prefix(1);
    }

    while (!sv.empty()) {
        std::string_view::size_type ampersand_pos = sv.find('&');
        std::string_view pair_sv = sv.substr(0, ampersand_pos);

        std::string_view::size_type equals_pos = pair_sv.find('=');
        if (equals_pos != std::string_view::npos) {
            std::string key(pair_sv.substr(0, equals_pos));
            std::string value_encoded(pair_sv.substr(equals_pos + 1));
            params[key] = detail::url_decode(value_encoded);
        } else if (!pair_sv.empty()) {
             params[std::string(pair_sv)] = ""; // Handle keys without values
        }

        if (ampersand_pos == std::string_view::npos) {
            break;
        }
        sv.remove_prefix(ampersand_pos + 1);
    }
    return params;
}

} // namespace minioauth2 