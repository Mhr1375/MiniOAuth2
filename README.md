# MiniOAuth2 ![CI Status](https://github.com/YOUR_USERNAME/minioauth2/actions/workflows/ci.yml/badge.svg) <!-- TODO: Replace YOUR_USERNAME -->

A minimal, header-only C++20 / C++17 library for OAuth 2.0 Authorization Code Flow with PKCE, designed for ease of integration, especially with frameworks like CrowCPP.

✨ **Features**

- **Header-only:** Easy integration, just include `minioauth2.hpp`.
- **Modern C++:** Uses C++20 features (configurable to C++17 via CMake option `MINIOAUTH2_CXX_STANDARD`).
- **Zero external runtime dependencies:** Only requires the C++ Standard Library.
- **Optional JSON parsing:** Uses `nlohmann/json` (via CMake option `MINIOAUTH2_USE_NLOHMANN_JSON`) for convenient token response and JWT payload parsing.
- **OAuth 2.0 Compliant:** Implements Authorization Code Grant (RFC 6749).
- **PKCE Support:** Implements PKCE (RFC 7636) with `S256` (recommended, requires SHA256 impl) and `plain` methods.
- **Security Focused:**
    - Secure random string generation for `state` and `code_verifier`.
    - PKCE enforcement prevents authorization code interception.
    - Clear separation between preparing requests and executing them (user provides HTTP client).
- **Helper Functions:**
    - Authorization URL construction.
    - Token exchange request preparation.
    - Query string parsing.
    - Base64 URL encoding/decoding.
    - Basic JWT payload parsing (no validation).
- **Extensible:** Designed to be simple and easy to adapt or extend.
- **Permissively Licensed:** MIT License.

🚀 **Quickstart**

1.  **Integration (using CMake FetchContent):**
    Add this to your `CMakeLists.txt`:
    ```cmake
    include(FetchContent)
    FetchContent_Declare(
        minioauth2
        GIT_REPOSITORY https://github.com/YOUR_USERNAME/minioauth2.git # TODO: Replace
        GIT_TAG main # Or specific release tag
    )
    # Optionally configure MiniOAuth2 options:
    # set(MINIOAUTH2_USE_NLOHMANN_JSON OFF CACHE BOOL "" FORCE)
    # set(MINIOAUTH2_CXX_STANDARD 17 CACHE STRING "" FORCE)
    FetchContent_MakeAvailable(minioauth2)

    # Link your target against the INTERFACE library
    target_link_libraries(your_target PRIVATE minioauth2)
    ```

2.  **Include the header:**
    ```cpp
    #include "minioauth2.hpp"
    ```

3.  **Basic Usage Flow:**
    ```cpp
    #include "minioauth2.hpp"
    #include <iostream>
    #include <string>
    #include <vector>

    int main() {
        // 1. Configure the OAuth provider
        minioauth2::OAuthConfig config = minioauth2::config::Google(); // Or configure manually
        config.client_id = "YOUR_CLIENT_ID";
        config.client_secret = "YOUR_CLIENT_SECRET"; // Optional for public clients with PKCE
        config.redirect_uri = "YOUR_REDIRECT_URI";

        // 2. Build the authorization request (e.g., in your /login handler)
        // Use "S256" (requires SHA256 impl) for production, "plain" is insecure
        minioauth2::AuthorizationRequest auth_req = minioauth2::build_authorization_request(config, {}, "S256"); 

        // IMPORTANT: Store auth_req.state and auth_req.code_verifier securely (e.g., session)
        // Store state -> code_verifier mapping
        std::string stored_state = auth_req.state;
        std::string stored_verifier = auth_req.code_verifier;

        std::cout << "Redirect user to: " << auth_req.authorization_url << std::endl;
        // ... redirect the user ...

        // --- User is redirected back to your callback URI --- 

        // Example callback parameters (replace with actual received values)
        std::string received_query = "code=RECEIVED_CODE&state=" + stored_state; 

        // 3. Parse callback parameters
        auto params = minioauth2::parse_query_params(received_query);
        std::string received_code = params["code"];
        std::string received_state_from_callback = params["state"];

        // 4. Validate state
        if (received_state_from_callback != stored_state) {
            std::cerr << "Error: State mismatch! Possible CSRF attack." << std::endl;
            return 1;
        }

        // Retrieve the stored code_verifier using the validated state
        std::string code_verifier = stored_verifier; 

        // 5. Prepare the token exchange request
        minioauth2::TokenExchangeRequest token_req = minioauth2::build_token_exchange_request(
            config, received_code, code_verifier
        );

        std::cout << "\nPrepare POST request to: " << token_req.url << std::endl;
        std::cout << "Body: " << token_req.body << std::endl;

        // 6. *** Use an HTTP client library to send the POST request ***
        //    (e.g., cpr, cpp-httplib, Boost.Beast)
        //    Send token_req.body with headers including 'Content-Type: application/x-www-form-urlencoded'
        //    to token_req.url
        //    std::string response_body = http_client.post(token_req.url, token_req.body, token_req.headers).text;

        // 7. (Optional) Parse the response (requires nlohmann/json)
        #ifdef MINIOAUTH2_USE_NLOHMANN_JSON
        // Assuming response_body contains the JSON from the token endpoint
        // std::string response_body = R"({"access_token": "abc", "token_type": "Bearer"})"; // Example
        // try {
        //     minioauth2::TokenResponse token_resp = minioauth2::parse_token_response(response_body);
        //     std::cout << "Access Token: " << token_resp.access_token << std::endl;
        //     if (token_resp.id_token) {
        //         auto payload = minioauth2::parse_jwt_payload(*token_resp.id_token);
        //         if(payload) std::cout << "ID Token Payload: " << payload->dump(2) << std::endl;
        //     }
        // } catch (const std::exception& e) {
        //     std::cerr << "Error parsing token response: " << e.what() << std::endl;
        // }
        #endif

        return 0;
    }
    ```

📦 **Integration Guide**

There are two main ways to use MiniOAuth2:

1.  **CMake `FetchContent` (Recommended):** As shown in the Quickstart, this handles downloading and making the library available automatically.
2.  **Manual Include:** Clone the repository or download `include/minioauth2.hpp`. Place it in your project's include paths and simply `#include "minioauth2.hpp"`. If you need JSON support (`MINIOAUTH2_USE_NLOHMANN_JSON`), you'll also need to ensure `nlohmann/json.hpp` is available in your include paths and define `MINIOAUTH2_USE_NLOHMANN_JSON` before including `minioauth2.hpp`.

**Dependencies:**

- C++17 or C++20 compiler.
- Standard Library.
- Optional: [nlohmann/json](https://github.com/nlohmann/json) (v3.x) if `MINIOAUTH2_USE_NLOHMANN_JSON` is enabled (default ON).

**CMake Options:**

- `MINIOAUTH2_CXX_STANDARD`: Set the C++ standard (17 or 20, default: 20).
- `MINIOAUTH2_USE_NLOHMANN_JSON`: Enable/disable nlohmann/json integration (default: ON).
- `MINIOAUTH2_BUILD_EXAMPLES`: Build example applications (default: ON if building MiniOAuth2 directly, OFF if used as subproject).
- `MINIOAUTH2_BUILD_TESTS`: Build tests (default: ON if building MiniOAuth2 directly, OFF if used as subproject).

🔐 **Security Considerations**

- **PKCE Method:** **Always** prefer the `S256` PKCE challenge method over `plain`. This requires a correct SHA256 implementation. The placeholder provided in `detail::sha256` is **insecure** and must be replaced.
- **State Parameter:** Always generate a unique, unpredictable `state` for each authorization request and validate it upon callback to prevent Cross-Site Request Forgery (CSRF).
- **Secure Storage:** The `code_verifier` and the mapping between `state` and `code_verifier` must be stored securely on the server-side (e.g., in an encrypted session cookie, database, or secure cache like Redis) between the redirect and the callback. **The example's `std::map` is insecure.**
- **HTTPS:** Always use HTTPS for your `redirect_uri` and all communication with the OAuth provider. MiniOAuth2 assumes you are handling TLS termination (e.g., via a reverse proxy like Nginx).
- **Client Secrets:** Handle `client_secret` values securely. Do not hardcode them. Load from environment variables or a secure configuration service. For public clients (like desktop or mobile apps), avoid using client secrets if possible and rely solely on PKCE.
- **Token Validation (ID Token):** If using OpenID Connect and receiving an `id_token`, **you must validate it** before trusting its claims. This includes verifying the signature, checking the expiration (`exp`), audience (`aud`), and issuer (`iss`). MiniOAuth2 provides basic payload parsing but **does not perform validation.** Use a dedicated JWT library for proper validation.
- **Transport Security:** Ensure your HTTP client enforces TLS certificate validation when communicating with the token endpoint.
- **SHA256 Implementation:** If providing your own SHA256 implementation, ensure it is correct, well-tested, and resistant to timing attacks if applicable.

🧪 **Examples**

See the `/examples/google_auth/` directory for a sample integration with the Crow C++ framework.
- [Google Auth Example README](./examples/google_auth/README.md)

🤝 **Contributing**

Contributions are welcome! Please feel free to open an issue or submit a pull request.

- Found a bug? [Open an issue](https://github.com/YOUR_USERNAME/minioauth2/issues) <!-- TODO: Replace -->
- Have a feature request? [Open an issue](https://github.com/YOUR_USERNAME/minioauth2/issues)
- Want to contribute code? Fork the repo and [submit a pull request](https://github.com/YOUR_USERNAME/minioauth2/pulls).

📄 **License**

MiniOAuth2 is licensed under the [MIT License](LICENSE).