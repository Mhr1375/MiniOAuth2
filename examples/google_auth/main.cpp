#include "crow.h"
#include "minioauth2.hpp"
#define CPPHTTPLIB_OPENSSL_SUPPORT // Ensure this is defined before including httplib.h
#include "httplib.h" // Include cpp-httplib
#include <iostream>
#include <string>
#include <cstdlib> // std::getenv
#include <map>
#include <mutex>
#include <optional>
#include <stdexcept> // Include for std::runtime_error
#include <utility> // Include for std::move
#include <regex> // Include for parsing host/path

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
        std::string token_response_body;
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

            // 3. Prepare the token exchange request (using minioauth2)
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

            // 4. *** Perform the Token Exchange POST request using cpp-httplib ***
            std::cout << "Attempting token exchange..." << std::endl;

            // Parse URL to get host and path for httplib::Client
            std::smatch match;
            std::regex url_regex(R"(^(https?):\/\/([^\/]+)(\/.*)?$)");
            std::string url_str = token_req.url;
            std::string host, path;
            if (std::regex_match(url_str, match, url_regex) && match.size() >= 3) {
                host = match[2].str();
                path = match.size() >= 4 ? match[3].str() : "/";
                if (path.empty()) path = "/";
            } else {
                throw std::runtime_error("Could not parse token endpoint URL: " + url_str);
            }
            
            std::cout << "Parsed URL - Host: " << host << ", Path: " << path << std::endl;

            // Create HTTPS client (requires OpenSSL)
            httplib::Client cli(std::string("https://") + host); // Prepend https://
            cli.enable_server_certificate_verification(true); // Recommended for production
            // You might need to configure CA cert path/bundle depending on your system:
            // const char * ca_cert_path = std::getenv("SSL_CERT_FILE");
            // if (ca_cert_path) {
            //     cli.set_ca_cert_path(ca_cert_path);
            // } else {
            //     // Attempt default locations or log a warning
            //     // Example: cli.set_ca_cert_path("./ca-bundle.pem");
            //     std::cout << "Warning: SSL_CERT_FILE env var not set. Using system default CA certs, verification might fail." << std::endl;
            // }

            // Convert map<string, string> headers to httplib::Headers
            httplib::Headers http_headers;
            for(const auto& pair : token_req.headers) {
                http_headers.emplace(pair.first, pair.second);
            }

            // Send POST request
            auto http_res = cli.Post(path.c_str(), http_headers, token_req.body, "application/x-www-form-urlencoded");

            if (!http_res) {
                 // Handle transport errors (connection failed, timeout, etc.)
                 auto err = http_res.error();
                 std::string error_msg = "HTTP request failed: " + httplib::to_string(err);
                 std::cerr << error_msg << std::endl;
                 // Depending on the error, you might check if cli.is_ssl() and provide OpenSSL error details
                 // unsigned long ssl_err = cli.get_openssl_verify_result();
                 // if (ssl_err != X509_V_OK) { ... }
                 throw std::runtime_error(error_msg);
            }

            std::cout << "Token exchange response status: " << http_res->status << std::endl;
            std::cout << "Token exchange response body: " << http_res->body << std::endl;

            if (http_res->status != 200) {
                 std::cerr << "Token exchange failed with status: " << http_res->status << std::endl;
                 throw std::runtime_error("Token exchange failed. Status: " + std::to_string(http_res->status) + ", Body: " + http_res->body);
            }

            token_response_body = http_res->body;

            // 5. Parse the token response (Now using the actual response)
            #ifdef MINIOAUTH2_USE_NLOHMANN_JSON
                try {
                    // Explicitly cast to string_view to resolve ambiguity
                    auto token_response = minioauth2::parse_token_response(std::string_view{token_response_body});
                    std::cout << "Access Token: " << token_response.access_token << std::endl;
                    if(token_response.id_token) {
                         std::cout << "ID Token received." << std::endl;
                        // TODO: Validate ID token!
                        // Try parsing payload (NO VALIDATION)
                        auto payload = minioauth2::parse_jwt_payload(*token_response.id_token);
                        if (payload && payload->contains("email")) {
                           std::string user_email = payload->value("email", "(email not found in ID token)");
                           return crow::response(200, "Login Successful! Welcome, " + user_email + "<br/>(Token parsing successful)");
                        }
                    }

                    return crow::response(200, "Login Successful! Welcome, (Not implemented yet - requires userinfo request)");

                } catch (const nlohmann::json::exception& e) { // More specific catch
                    std::cerr << "Failed to parse token JSON response: " << e.what() << std::endl;
                    return crow::response(500, "Failed to parse token response JSON: " + std::string(e.what()));
                } catch (const std::runtime_error& e) { // Catch other minioauth2 errors
                    std::cerr << "Error processing token response: " << e.what() << std::endl;
                    return crow::response(500, "Error processing token response: " + std::string(e.what()));
                }
            #else
                 return crow::response(501, "Token parsing requires nlohmann/json. Enable MINIOAUTH2_USE_NLOHMANN_JSON.");
            #endif

        } catch (const std::exception& e) {
             std::cerr << "Error during /callback: " << e.what() << std::endl;
             // Avoid leaking sensitive info like full body in production errors
             std::string error_details = e.what();
             return crow::response(500, "Internal Server Error during callback: " + error_details);
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