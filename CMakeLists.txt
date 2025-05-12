cmake_minimum_required(VERSION 3.16)

project(MiniOAuth2 LANGUAGES CXX VERSION 0.1.0)

# --- Options ---
# Option for C++ Standard (default to 20, allow 17)
set(MINIOAUTH2_CXX_STANDARD 20 CACHE STRING "C++ standard to use (e.g., 17, 20)")
set_property(CACHE MINIOAUTH2_CXX_STANDARD PROPERTY STRINGS 17 20)
if (NOT MINIOAUTH2_CXX_STANDARD VERSION_EQUAL 17 AND NOT MINIOAUTH2_CXX_STANDARD VERSION_EQUAL 20)
    message(FATAL_ERROR "Unsupported C++ standard: ${MINIOAUTH2_CXX_STANDARD}. Please use 17 or 20.")
endif()
set(CMAKE_CXX_STANDARD ${MINIOAUTH2_CXX_STANDARD})
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# --- Options ---
option(MINIOAUTH2_USE_NLOHMANN_JSON "Enable nlohmann/json for token parsing" ON)

# Options for building tests and examples (default OFF when used as subproject)
if(${CMAKE_PROJECT_NAME} STREQUAL ${PROJECT_NAME})
    # Top-level project build defaults
    set(MINIOAUTH2_BUILD_DEFAULT ON)
else()
    # Subproject build defaults
    set(MINIOAUTH2_BUILD_DEFAULT OFF)
endif()
option(MINIOAUTH2_BUILD_EXAMPLES "Build examples" ${MINIOAUTH2_BUILD_DEFAULT})
option(MINIOAUTH2_BUILD_TESTS "Build tests" ${MINIOAUTH2_BUILD_DEFAULT})

# --- Dependencies ---
include(FetchContent)

if(MINIOAUTH2_USE_NLOHMANN_JSON)
    FetchContent_Declare(
        nlohmann_json
        GIT_REPOSITORY https://github.com/nlohmann/json.git
        GIT_TAG v3.11.3 # Or latest stable tag
    )
    FetchContent_MakeAvailable(nlohmann_json)
endif()

# --- Add GoogleTest Dependency ---
enable_testing()

FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG    v1.14.0 # Or release-1.14.0 or main
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)
message(STATUS "GoogleTest enabled for testing.")

# --- Library Target ---
add_library(minioauth2 INTERFACE)
target_include_directories(minioauth2 INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>)
target_compile_features(minioauth2 INTERFACE cxx_std_${CMAKE_CXX_STANDARD})

if(MINIOAUTH2_USE_NLOHMANN_JSON AND TARGET nlohmann_json::nlohmann_json)
    target_link_libraries(minioauth2 INTERFACE nlohmann_json::nlohmann_json)
    target_compile_definitions(minioauth2 INTERFACE MINIOAUTH2_USE_NLOHMANN_JSON)
endif()

# --- Installation ---
# For a header-only library, just install the include directory.
include(GNUInstallDirs)
install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    COMPONENT Devel # Optional component name
)

# --- Subdirectories ---
if(MINIOAUTH2_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(MINIOAUTH2_BUILD_TESTS)
    add_subdirectory(test)
endif() 