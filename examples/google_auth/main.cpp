#include "crow.h"
#include "minioauth2.hpp"
#include <iostream>
#include <string>
#include <cstdlib> // std::getenv
#include <map>
#include <mutex>
#include <optional>

// --- Configuration --- 
// Load from environment variables for security
const char* google_client_id_env = std::getenv("GOOGLE_CLIENT_ID");
const char* google_client_secret_env = std::getenv("GOOGLE_CLIENT_SECRET");
const std::string redirect_uri = "http://localhost:18080/callback"; // Must match Google Console config

// --- Temporary State/Verifier Storage --- 
// WARNING: THIS IS HIGHLY INSECURE AND FOR DEMONSTRATION PURPOSES ONLY!
// In a real production environment, you MUST use a secure, server-side session mechanism.
// Options include:
//   - Secure HTTP-only cookies mapping to server-side storage (e.g., Redis, database, secure session middleware).
//   - Encrypted JWTs (if storing state directly in the client, ensure strong encryption and short expiry).
// This simple map has critical flaws for production:
//   - Data loss on server restart.
//   - Memory leaks (no entry expiration or cleanup).
//   - Not scalable across multiple server instances.
//   - Basic mutex only prevents data races, not other session vulnerabilities (e.g., fixation).
std::map<std::string, std::string> state_to_verifier_map;
std::mutex map_mutex; // Basic protection for the map

int main()
{
    if (!google_client_id_env || !google_client_secret_env) {
        std::cerr << "Error: GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables must be set." << std::endl;
        return 1;
    }

    minioauth2::OAuthConfig google_config = minioauth2::config::Google();
    google_config.client_id = google_client_id_env;
    google_config.client_secret = google_client_secret_env;
    google_config.redirect_uri = redirect_uri;

    crow::SimpleApp app;

    CROW_ROUTE(app, "/login")
    ([&](const crow::request& /*req*/, crow::response& res){
        try {
            // 1. Build the authorization request
            auto auth_request = minioauth2::build_authorization_request(google_config);

            // 2. Store state -> code_verifier mapping (INSECURE - use proper sessions! See WARNING above)
            {
                std::lock_guard<std::mutex> lock(map_mutex);
                state_to_verifier_map[auth_request.state] = auth_request.code_verifier;
                // TODO: Implement proper session cleanup/expiration in a real application
            }

            std::cout << "Redirecting user to: " << auth_request.authorization_url << std::endl;

            // 3. Redirect the user
            res.redirect(auth_request.authorization_url);
            res.end();

        } catch (const std::exception& e) {
            std::cerr << "Error during /login: " << e.what() << std::endl;
            res.code = 500;
            res.write("Internal Server Error during login.");
            res.end();
        }
    });

    CROW_ROUTE(app, "/callback")
    ([&](const crow::request& req){
        try {
            // 1. Parse query parameters
            // Get the query string part from the request URL
            std::string query_string;
            size_t q_pos = req.raw_url.find('?');
            if (q_pos != std::string::npos) {
                query_string = req.raw_url.substr(q_pos + 1);
            }
            auto params = minioauth2::parse_query_params(query_string);

            auto code_it = params.find("code");
            auto state_it = params.find("state");
            auto error_it = params.find("error");

            if (error_it != params.end()) {
                std::cerr << "OAuth Error: " << params["error"] << std::endl;
                return crow::response(400, "OAuth provider returned an error: " + params["error"]);
            }

            if (code_it == params.end() || state_it == params.end()) {
                return crow::response(400, "Missing 'code' or 'state' in callback parameters.");
            }

            std::string code = code_it->second;
            std::string received_state = state_it->second;

            // 2. Validate state and retrieve code_verifier (INSECURE - use proper sessions! See WARNING above)
            std::string code_verifier;
            {
                std::lock_guard<std::mutex> lock(map_mutex);
                auto verifier_it = state_to_verifier_map.find(received_state);
                if (verifier_it == state_to_verifier_map.end()) {
                    std::cerr << "Error: Invalid or expired state parameter received." << std::endl;
                    return crow::response(400, "Invalid state parameter.");
                }
                code_verifier = verifier_it->second;
                state_to_verifier_map.erase(verifier_it); // Consume state
            }

            std::cout << "Received callback. Code: " << code << ", State: " << received_state << std::endl;

            // 3. Prepare the token exchange request
            auto token_req = minioauth2::build_token_exchange_request(google_config, code, code_verifier);

            std::cout << "\n--- Preparing Token Exchange Request --- " << std::endl;
            std::cout << "URL: " << token_req.url << std::endl;
            std::cout << "Method: " << token_req.method << std::endl;
            std::cout << "Headers: ";
            for(const auto& pair : token_req.headers) {
                std::cout << pair.first << ": " << pair.second << "; ";
            }
            std::cout << std::endl;
            std::cout << "Body: " << token_req.body << std::endl;
            std::cout << "----------------------------------------\n" << std::endl;

            // 4. *** Perform the Token Exchange POST request ***
            //    This requires an HTTP client library (e.g., cpr, cpp-httplib, boost.beast)
            //    MiniOAuth2 only *prepares* the request parameters.
            std::string token_response_body = ""; // Placeholder
            // Example with a hypothetical HTTP client:
            // HttpClient client;
            // auto http_response = client.post(token_req.url, token_req.body, token_req.headers);
            // if (http_response.status_code == 200) {
            //     token_response_body = http_response.body;
            // } else {
            //     std::cerr << "Token exchange failed: " << http_response.status_code << " Body: " << http_response.body << std::endl;
            //     return crow::response(500, "Failed to exchange token.");
            // }

            // Simulate a successful response for demonstration if no client is available
            // ** REMOVE THIS SIMULATION IN A REAL APPLICATION **
            if (token_response_body.empty() && google_config.client_id == "test_client_id") { // Only simulate for a specific test ID
                 std::cout << "\n--- SIMULATING Token Response --- \n";
                 token_response_body = R"({
                    "access_token": "simulated_access_token_123",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "id_token": "simulated_id_token.abc.xyz",
                    "scope": "openid profile email"
                 })";
                 std::cout << token_response_body << std::endl;
                 std::cout << "----------------------------------\n" << std::endl;
            }
            // ** END SIMULATION **

            if (token_response_body.empty()) {
                std::cerr << "Token exchange skipped (no HTTP client implemented in example)." << std::endl;
                return crow::response(200, "Callback received, but token exchange requires an HTTP client.<br/>Prepared Request:<br/>URL: " + token_req.url + "<br/>Body: " + token_req.body);
            }

            // 5. Parse the token response
            #ifdef MINIOAUTH2_USE_NLOHMANN_JSON
                try {
                    // Explicitly cast to string_view to resolve ambiguity
                    auto token_response = minioauth2::parse_token_response(std::string_view{token_response_body});
                    std::cout << "Access Token: " << token_response.access_token << std::endl;
                    if(token_response.id_token) {
                         std::cout << "ID Token: " << *token_response.id_token << std::endl;
                         // TODO: In production, you MUST validate the ID token (signature, claims, etc.)
                         // Basic parsing is possible, but full validation requires a JWT library.
                    }

                    // 6. (Optional) Use the access token to fetch user info
                    //    Requires another HTTP GET request to Google's userinfo endpoint.
                    //    std::string user_info_url = "https://www.googleapis.com/oauth2/v3/userinfo";
                    //    // auto user_info_response = client.get(user_info_url, {"Authorization: Bearer " + token_response.access_token});
                    //    // Parse user_info_response.body (JSON)
                    std::string user_email = "user@example.com (simulated)"; // Placeholder

                    return crow::response(200, "Login Successful! Welcome, " + user_email);

                } catch (const std::exception& e) {
                    std::cerr << "Failed to parse token response: " << e.what() << std::endl;
                    return crow::response(500, "Failed to parse token response.");
                }
            #else
                 return crow::response(501, "Token parsing requires nlohmann/json. Enable MINIOAUTH2_USE_NLOHMANN_JSON.");
            #endif

        } catch (const std::exception& e) {
             std::cerr << "Error during /callback: " << e.what() << std::endl;
             return crow::response(500, "Internal Server Error during callback.");
        }
    });

    CROW_ROUTE(app, "/")
    ([](){
        return R"(<html><body>
            <h1>MiniOAuth2 Google Example (Crow)</h1>
            <p>Click the button to log in with your Google account.</p>
            <form action="/login" method="get">
                <button type="submit">Login with Google</button>
            </form>
            <p><small>Note: Ensure GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables are set.</small></p>
        </body></html>)";
    });

    // Basic error handling
    // app.handle_upgrade = [&](const crow::request& /*req*/, const crow::response& /*res*/, asio::ip::tcp::socket&& /*sock*/) {}; // Comment out
    // app.handle_after_request = [&](crow::request& req, crow::response& res, crow::routing_params& params) {}; // Comment out for now
    // app.handle_http_error = [&](const crow::request& req, crow::response& res, int status_code) { // Comment out for now

    std::cout << "Server starting on http://localhost:18080" << std::endl;
    std::cout << "Visit http://localhost:18080 to begin." << std::endl;
    std::cout << "Login endpoint: /login" << std::endl;
    std::cout << "Callback endpoint: /callback" << std::endl;

    app.port(18080).multithreaded().run();

    return 0;
} 