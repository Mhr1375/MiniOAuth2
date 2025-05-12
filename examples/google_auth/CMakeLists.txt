cmake_minimum_required(VERSION 3.16)

project(GoogleAuthExample CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# --- Dependencies ---
# No need to find_package for MiniOAuth2 when building together
# find_package(MiniOAuth2 REQUIRED) 

include(FetchContent)

# Fetch Asio (standalone) dependency FIRST
FetchContent_Declare(
    asio
    GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
    GIT_TAG asio-1-28-1 # Use a recent stable tag
    GIT_SHALLOW TRUE
    SOURCE_SUBDIR asio/include # Asio headers are in asio/include within the repo
)
FetchContent_MakeAvailable(asio)

# Explicitly set ASIO_INCLUDE_DIR for Crow to find
# Use the known path where FetchContent places the source (relative to top-level build dir)
set(ASIO_INCLUDE_DIR ${CMAKE_BINARY_DIR}/_deps/asio-src/asio/include CACHE PATH "Path to Asio include directory" FORCE)
message(STATUS "ASIO_INCLUDE_DIR set to: ${ASIO_INCLUDE_DIR}") # For debugging

# Fetch Crow dependency
FetchContent_Declare(
    Crow
    GIT_REPOSITORY https://github.com/CrowCpp/Crow.git
    GIT_TAG v1.1.0 # Or latest stable tag
    GIT_SHALLOW TRUE
    # Remove AMALGAMATION, keep other options
    CMAKE_ARGS -DCROW_BUILD_EXAMPLES=OFF -DCROW_BUILD_TESTS=OFF -DCROW_ENABLE_SSL=OFF
)
FetchContent_MakeAvailable(Crow)

# Fetch cpp-httplib dependency
FetchContent_Declare(
    httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
    GIT_TAG v0.15.3 # Use a recent stable tag
)
FetchContent_MakeAvailable(httplib)

# Find OpenSSL for HTTPS support in cpp-httplib
find_package(OpenSSL REQUIRED)

# --- Executable ---
add_executable(google_auth_example main.cpp)

target_link_libraries(google_auth_example PRIVATE
    minioauth2
    Crow::Crow
    httplib::httplib
    OpenSSL::SSL
    OpenSSL::Crypto
    # Asio might be linked via Crow, or link explicitly if needed:
    # Asio::asio # This target might be available if Asio creates one.
    # For header-only Asio, often just the include directory is enough,
    # which Crow should pick up via its own find_package(asio) call.
)

# Add Asio include directory to the example executable if Crow doesn't do it.
# This ensures that our main.cpp can find asio.hpp if it needs it directly,
# or if Crow's headers include it in a way that requires it to be in the path.
# Usually, Crow's target should handle this.
if(TARGET asio)
    # If Asio provides a target (e.g. Asio::asio), it's better to link against it.
    # However, standalone Asio is often header-only.
    # We need to ensure its include path is available.
    # One way is to add to Crow's interface, or directly to our executable.
    # Crow should find it via find_package if asio_SOURCE_DIR/asio_BINARY_DIR is in CMAKE_PREFIX_PATH
    # or if asio creates an export set that find_package can use.
    # FetchContent_MakeAvailable should make asio findable.
endif()

# Optional: Define where to find nlohmann/json if needed directly here
# and not linked via minioauth2 interface
# if(TARGET nlohmann_json::nlohmann_json)
#    target_link_libraries(google_auth_example PRIVATE nlohmann_json::nlohmann_json)
# endif()

# Define the macro to enable OpenSSL support in cpp-httplib
target_compile_definitions(google_auth_example
    PRIVATE
    CPPHTTPLIB_OPENSSL_SUPPORT
    ASIO_STANDALONE # Often needed by Crow
)

# Ensure Crow headers are available
target_include_directories(google_auth_example
    PRIVATE
    ${crow_SOURCE_DIR}/include
    ${httplib_SOURCE_DIR}
)

install(TARGETS google_auth_example DESTINATION bin) 