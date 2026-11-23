cmake_minimum_required(VERSION 3.25)

project(cpcp VERSION 0.1.0 LANGUAGES CXX)

include(CTest)

find_package(CLI11 CONFIG REQUIRED)
find_package(Catch2 3 CONFIG REQUIRED)
find_package(unofficial-sodium CONFIG REQUIRED)

function(cpcp_enable_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /WX /permissive-)
    else()
        target_compile_options(${target} PRIVATE
            -Wall
            -Wextra
            -Wpedantic
            -Wconversion
            -Wsign-conversion
            -Werror
        )
    endif()
endfunction()

add_library(cpcp_domain INTERFACE)
target_include_directories(cpcp_domain INTERFACE src)
target_compile_features(cpcp_domain INTERFACE cxx_std_23)

add_library(cpcp_crypto STATIC
    src/crypto/aead.cpp
    src/crypto/content_id.cpp
    src/crypto/file_identity.cpp
    src/crypto/keys.cpp
    src/crypto/snapshot_stream.cpp
)
target_link_libraries(cpcp_crypto PUBLIC
    cpcp_domain
    unofficial-sodium::sodium
)
cpcp_enable_warnings(cpcp_crypto)

add_library(cpcp_simulation STATIC
    src/storage/simulated_filesystem.cpp
)
target_link_libraries(cpcp_simulation PUBLIC cpcp_domain)
cpcp_enable_warnings(cpcp_simulation)

add_library(cpcp_cli STATIC
    src/cli/app.cpp
)
target_link_libraries(cpcp_cli PUBLIC cpcp_domain CLI11::CLI11)
target_compile_definitions(cpcp_cli PRIVATE CPCP_VERSION="${PROJECT_VERSION}")
cpcp_enable_warnings(cpcp_cli)

add_executable(cpcp src/main.cpp)
target_link_libraries(cpcp PRIVATE cpcp_cli)
cpcp_enable_warnings(cpcp)

if(BUILD_TESTING)
    add_executable(cpcp_unit_tests
        tests/unit/aead_test.cpp
        tests/unit/content_id_test.cpp
        tests/unit/file_identity_test.cpp
        tests/unit/result_test.cpp
        tests/unit/snapshot_stream_test.cpp
    )
    target_link_libraries(cpcp_unit_tests PRIVATE
        cpcp_crypto
        Catch2::Catch2WithMain
    )
    cpcp_enable_warnings(cpcp_unit_tests)

    add_executable(cpcp_simulation_tests
        tests/simulation/simulated_filesystem_test.cpp
    )
    target_link_libraries(cpcp_simulation_tests PRIVATE
        cpcp_simulation
        Catch2::Catch2WithMain
    )
    cpcp_enable_warnings(cpcp_simulation_tests)

    include(Catch)
    catch_discover_tests(cpcp_unit_tests)
    catch_discover_tests(cpcp_simulation_tests)

    add_test(
        NAME cli_contract
        COMMAND ${CMAKE_COMMAND}
            -DCPCP_EXECUTABLE=$<TARGET_FILE:cpcp>
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/cli_contract.cmake
    )
endif()
