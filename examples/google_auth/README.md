# MiniOAuth2 Google Authentication Example (Crow)

This example demonstrates how to use the `MiniOAuth2` library with the [Crow C++ microframework](https://github.com/CrowCpp/Crow) to implement a "Login with Google" flow using the OAuth 2.0 Authorization Code Grant with PKCE.

## Features

- Initiates the OAuth flow when visiting `/login`.
- Redirects the user to Google for authentication and consent.
- Handles the callback from Google at `/callback`.
- Retrieves the authorization code and validates the `state` parameter.
- Uses `MiniOAuth2` helpers to prepare the token exchange request.
- **Note:** This example *does not* include an HTTP client to perform the actual token exchange. It only shows how to prepare the request.
- Shows basic parsing of the token response (requires `nlohmann/json`).

## Prerequisites

- A C++20 compliant compiler (GCC, Clang, MSVC).
- CMake (version 3.16 or later).
- Internet connection (for downloading dependencies).
- A Google Cloud Project with OAuth 2.0 credentials.

## Setup

1.  **Google Cloud Credentials:**
    *   Go to the [Google Cloud Console](https://console.cloud.google.com/).
    *   Create a new project or select an existing one.
    *   Navigate to "APIs & Services" > "Credentials".
    *   Click "Create Credentials" > "OAuth client ID".
    *   Choose "Web application" as the application type.
    *   Give it a name (e.g., "MiniOAuth2 Crow Example").
    *   Under "Authorized redirect URIs", add `http://localhost:18080/callback`.
    *   Click "Create".
    *   Copy the **Client ID** and **Client Secret**. You will need them shortly.

2.  **Environment Variables:**
    Set the following environment variables in your terminal before running the example:
    *   `GOOGLE_CLIENT_ID`: Your Google Client ID.
    *   `GOOGLE_CLIENT_SECRET`: Your Google Client Secret.

    **Example (Bash/Zsh):**
    ```bash
    export GOOGLE_CLIENT_ID="YOUR_CLIENT_ID_HERE"
    export GOOGLE_CLIENT_SECRET="YOUR_CLIENT_SECRET_HERE"
    ```

    **Example (PowerShell):**
    ```powershell
    $env:GOOGLE_CLIENT_ID="YOUR_CLIENT_ID_HERE"
    $env:GOOGLE_CLIENT_SECRET="YOUR_CLIENT_SECRET_HERE"
    ```

## Build and Run

1.  **Clone the main `MiniOAuth2` repository (if you haven't already):**
    ```bash
    git clone https://github.com/your-username/minioauth2.git # Replace with actual URL
    cd minioauth2
    ```

2.  **Configure CMake (from the root `minioauth2` directory):**
    This command enables building examples and downloads dependencies (Crow, Asio, nlohmann/json).
    ```bash
    cmake -B build -S . -DMINIOAUTH2_BUILD_EXAMPLES=ON -DMINIOAUTH2_USE_NLOHMANN_JSON=ON
    ```

3.  **Build the project:**
    ```bash
    cmake --build build
    ```
    (On Windows with Visual Studio, you might need to specify the configuration, e.g., `cmake --build build --config Debug` or `Release`)

4.  **Run the example (ensure environment variables are set):**
    The executable will be inside the `build` directory.
    ```bash
    ./build/examples/google_auth/google_auth_example
    ```
    (On Windows, the path might be `./build/examples/google_auth/Debug/google_auth_example.exe` or similar)

5.  **Open your browser** and navigate to `http://localhost:18080`.

6.  Click the "Login with Google" button and follow the Google authentication flow.

7.  After successful authentication and consent, you will be redirected back to the `/callback` endpoint. Since this example lacks an HTTP client, you will see a message indicating that the token exchange request was prepared but not sent.

## Notes

- **Security:** The state/code_verifier storage in this example uses a simple `std::map` with a mutex. **This is not secure or scalable for production.** Use proper server-side session management (e.g., secure cookies, Redis, database) in a real application.
- **HTTP Client:** To complete the flow, you would need to add an HTTP client library (like [cpr](https://github.com/libcpr/cpr), [cpp-httplib](https://github.com/yhirose/cpp-httplib)) to send the `TokenExchangeRequest` prepared by `MiniOAuth2` to Google's token endpoint. 