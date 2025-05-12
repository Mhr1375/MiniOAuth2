# MiniOAuth2

A header-only C++20 library for simplifying the OAuth 2.0 Authorization Code Flow with PKCE, designed with [CrowCpp](https://github.com/CrowCpp/Crow) in mind, but usable independently.

Author: [Mhr1375](https://github.com/Mhr1375)

## Features

*   **Header-Only:** Easy integration, just include `minioauth2.hpp`.
*   **C++20:** Uses modern C++ features.
*   **PKCE Support:** Implements Proof Key for Code Exchange (RFC 7636) using SHA-256 (`S256` method) for enhanced security, especially for public clients (like native apps or SPAs).
*   **Helper Utilities:** Includes functions for generating secure random strings (`state`, `code_verifier`), URL-safe Base64 encoding/decoding, URL encoding/decoding, SHA-256 hashing (via embedded PicoSHA2), and building authorization/token request parameters.
*   **Optional JSON Parsing:** Can use `nlohmann/json` (if `MINIOAUTH2_USE_NLOHMANN_JSON` is defined via CMake) to parse token responses and JWT payloads (ID tokens). **Note:** JWT parsing does *not* validate signatures or claims.
*   **Crow Example:** Includes an example (`examples/google_auth`) demonstrating usage with CrowCpp for a basic Google login flow.

## Dependencies

*   **Core Library:** Requires a C++20 compliant compiler. Optionally uses `nlohmann/json` (fetched via CMake `FetchContent`).
*   **Google Auth Example:**
    *   [CrowCpp](https://github.com/CrowCpp/Crow) (fetched via CMake `FetchContent`).
    *   [cpp-httplib](https://github.com/yhirose/cpp-httplib) (fetched via CMake `FetchContent`) for making HTTP requests.
    *   **OpenSSL:** Required by `cpp-httplib` for HTTPS communication. Must be installed separately on the system and findable by CMake.

## Building

This project uses CMake for building the library (as an INTERFACE target) and the example.

### Prerequisites

1.  **C++20 Compiler:** (e.g., GCC 10+, Clang 10+, MSVC v19.28+).
2.  **CMake:** Version 3.15 or higher.
3.  **Git:** For cloning and fetching dependencies.
4.  **(For Example)** **OpenSSL Development Libraries:**
    *   **Linux (apt):** `sudo apt-get update && sudo apt-get install libssl-dev`
    *   **macOS (brew):** `brew install openssl` (CMake might need hints like `-DOPENSSL_ROOT_DIR=$(brew --prefix openssl)`)
    *   **Windows:**
        *   **Recommended: `vcpkg`**
            1.  Install [vcpkg](https://vcpkg.io/en/getting-started.html).
            2.  Install OpenSSL: `vcpkg install openssl:x64-windows` (or your target triplet).
            3.  Configure CMake with the vcpkg toolchain file:
                ```bash
                cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=[path/to/vcpkg]/scripts/buildsystems/vcpkg.cmake
                ```
        *   **Manual Installation:**
            1.  Download and install pre-compiled binaries (including **development headers and libraries**) from a trusted source (e.g., [Shining Light Productions](https://slproweb.com/products/Win32OpenSSL.html)). Make sure to install the version matching your target architecture (e.g., Win64).
            2.  Configure CMake, telling it where to find OpenSSL:
                ```bash
                cmake -B build -S . -DOPENSSL_ROOT_DIR="C:/path/to/OpenSSL-Win64"
                ```
                (Replace the path with your actual installation directory). CMake should automatically find the includes and libraries within this root directory if the installation layout is standard.

### Build Steps

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/Mhr1375/MiniOAuth2.git # Or your fork's URL
    cd MiniOAuth2
    ```
2.  **Configure CMake:** (Choose ONE of the Windows methods if applicable)
    ```bash
    # Standard (Linux/macOS with OpenSSL installed system-wide or via brew)
    cmake -B build -S . -DMINIOAUTH2_BUILD_EXAMPLE=ON -DMINIOAUTH2_USE_NLOHMANN_JSON=ON

    # Windows with vcpkg
    # cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=[path/to/vcpkg]/scripts/buildsystems/vcpkg.cmake -DMINIOAUTH2_BUILD_EXAMPLE=ON -DMINIOAUTH2_USE_NLOHMANN_JSON=ON

    # Windows with manual OpenSSL install
    # cmake -B build -S . -DOPENSSL_ROOT_DIR="C:/path/to/OpenSSL-Win64" -DMINIOAUTH2_BUILD_EXAMPLE=ON -DMINIOAUTH2_USE_NLOHMANN_JSON=ON
    ```
    *   `-DMINIOAUTH2_BUILD_EXAMPLE=ON`: Builds the `google_auth_example`. (Default is ON)
    *   `-DMINIOAUTH2_USE_NLOHMANN_JSON=ON`: Enables `nlohmann/json` support. (Default is ON)

3.  **Build:**
    ```bash
    cmake --build build
    ```
    *   On Windows with Visual Studio, you might need to specify the configuration: `cmake --build build --config Release` (or `Debug`).

## Running the Google Auth Example

1.  **Set up Google Cloud Credentials:**
    *   Go to the [Google Cloud Console](https://console.cloud.google.com/).
    *   Create a new project or select an existing one.
    *   Go to "APIs & Services" -> "Credentials".
    *   Create new "OAuth client ID" credentials.
    *   Choose "Web application" as the application type.
    *   Add an "Authorized redirect URI": `http://localhost:18080/callback` (This must match the `redirect_uri` used in the code).
    *   Note down your "Client ID" and "Client Secret".

2.  **Set Environment Variables:** Before running the example, set the following environment variables in your terminal:
    *   `GOOGLE_CLIENT_ID`: Your Google Client ID.
    *   `GOOGLE_CLIENT_SECRET`: Your Google Client Secret.
    *   `GOOGLE_REDIRECT_URI`: The redirect URI you configured (`http://localhost:18080/callback`).
    *   **Example (PowerShell):**
        ```powershell
        $env:GOOGLE_CLIENT_ID="YOUR_ID.apps.googleusercontent.com"
        $env:GOOGLE_CLIENT_SECRET="YOUR_SECRET"
        $env:GOOGLE_REDIRECT_URI="http://localhost:18080/callback"
        ```
    *   **Example (Bash/Zsh):**
        ```bash
        export GOOGLE_CLIENT_ID="YOUR_ID.apps.googleusercontent.com"
        export GOOGLE_CLIENT_SECRET="YOUR_SECRET"
        export GOOGLE_REDIRECT_URI="http://localhost:18080/callback"
        ```

3.  **Run the Executable:**
    *   Navigate to the project root directory in your terminal.
    *   Run the compiled example:
        *   **Windows:** `.\\build\\examples\\google_auth\\Debug\\google_auth_example.exe` (or `Release` if built with that config)
        *   **Linux/macOS:** `./build/examples/google_auth/google_auth_example`

4.  **Test the Flow:**
    *   The terminal will show "INFO: Server is running on port 18080".
    *   Open your web browser and go to `http://localhost:18080/login`.
    *   You should be redirected to the Google login page.
    *   Log in and grant the requested permissions (openid, profile, email).
    *   You will be redirected back to `http://localhost:18080/callback`.
    *   Check the terminal where the example is running. It should print the received access token, token type, ID token payload, etc.

    **Note:** The example uses a simple in-memory `std::map` to store the `state` and `code_verifier` between the `/login` and `/callback` requests. This is **not suitable for production** as it's insecure and doesn't handle multiple users or server restarts. A real application would need a proper session management mechanism (e.g., encrypted cookies, server-side session store).

## Running Tests

Unit tests are implemented using GoogleTest (fetched via CMake `FetchContent`).

1.  Ensure the project is configured with testing enabled (default CMake option `MINIOAUTH2_ENABLE_TESTING=ON`).
2.  Build the project as described above. This will also build the `minioauth2_tests` executable.
3.  Run tests using CTest from the build directory:
    ```bash
    cd build
    ctest # Or ctest -C Debug on Windows/Multi-config generators
    ```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

It includes PicoSHA2, which is also distributed under the MIT License.