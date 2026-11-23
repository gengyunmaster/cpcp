cmake_minimum_required(VERSION 3.25)

project(cpcp VERSION 0.1.0 LANGUAGES CXX)

include(CTest)

find_package(CLI11 CONFIG REQUIRED)
find_package(Catch2 3 CONFIG REQUIRED)
find_package(unofficial-sodium CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

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

add_library(cpcp_platform STATIC
    src/platform/binary_file.cpp
)
target_link_libraries(cpcp_platform PUBLIC cpcp_domain)
target_compile_definitions(cpcp_platform INTERFACE
    CPCP_TEST_TEMP_DIR="${CMAKE_CURRENT_BINARY_DIR}"
)
cpcp_enable_warnings(cpcp_platform)

add_library(cpcp_probe STATIC
    src/platform/durability_probe.cpp
)
target_link_libraries(cpcp_probe PUBLIC cpcp_platform)
cpcp_enable_warnings(cpcp_probe)

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

add_library(cpcp_spool STATIC
    src/storage/session_spool.cpp
)
target_link_libraries(cpcp_spool PUBLIC
    cpcp_crypto
    cpcp_platform
)
cpcp_enable_warnings(cpcp_spool)

add_library(cpcp_cli STATIC
    src/cli/app.cpp
    src/cli/probe_command.cpp
)
target_link_libraries(cpcp_cli PUBLIC
    cpcp_domain
    cpcp_probe
    CLI11::CLI11
    nlohmann_json::nlohmann_json
)
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

    add_executable(cpcp_spool_tests
        tests/integration/session_spool_test.cpp
    )
    target_link_libraries(cpcp_spool_tests PRIVATE
        cpcp_spool
        Catch2::Catch2WithMain
    )
    cpcp_enable_warnings(cpcp_spool_tests)

    add_executable(cpcp_native_file_tests
        tests/integration/native_file_test.cpp
    )
    target_link_libraries(cpcp_native_file_tests PRIVATE
        cpcp_platform
        Catch2::Catch2WithMain
    )
    cpcp_enable_warnings(cpcp_native_file_tests)

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
    catch_discover_tests(cpcp_spool_tests)
    catch_discover_tests(cpcp_native_file_tests)
    catch_discover_tests(cpcp_simulation_tests)

    add_test(
        NAME cli_contract
        COMMAND ${CMAKE_COMMAND}
            -DCPCP_EXECUTABLE=$<TARGET_FILE:cpcp>
            -DCPCP_PROBE_DIR=${CMAKE_CURRENT_BINARY_DIR}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/cli_contract.cmake
    )

    add_test(
        NAME cli_probe_write
        COMMAND $<TARGET_FILE:cpcp> repo probe ${CMAKE_CURRENT_BINARY_DIR}
            --write-test --iterations 2 --size 65536 --json
    )
endif()
