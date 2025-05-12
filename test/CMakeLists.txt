cmake_minimum_required(VERSION 3.16)

# Define the test executable
add_executable(minioauth2_tests
    main.cpp
    test_utils.cpp
    # Add other test_*.cpp files here as they are created
)

# Link against GoogleTest
# gtest_main automatically provides a main() function
target_link_libraries(minioauth2_tests
    PRIVATE
    GTest::gtest_main
    minioauth2 # Link to our library to make headers available
)

# Include CTest support for running tests
include(GoogleTest)
gtest_discover_tests(minioauth2_tests) 