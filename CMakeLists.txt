cmake_minimum_required(VERSION 3.25)

project(cpcp VERSION 0.1.0 LANGUAGES CXX)

include(CTest)

find_package(CLI11 CONFIG REQUIRED)
find_package(Catch2 3 CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
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

add_library(cpcp_domain STATIC
    src/domain/encoding.cpp
    src/domain/strict_json.cpp
)
target_include_directories(cpcp_domain PUBLIC src)
target_compile_features(cpcp_domain PUBLIC cxx_std_23)
target_link_libraries(cpcp_domain PUBLIC nlohmann_json::nlohmann_json)

add_library(cpcp_platform STATIC
    src/platform/binary_file.cpp
    src/platform/cancellation.cpp
    src/platform/lock.cpp
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
    src/crypto/password.cpp
    src/crypto/secret.cpp
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

add_library(cpcp_repository STATIC
    src/repository/chunk_set.cpp
    src/repository/chunk_store.cpp
    src/repository/config.cpp
    src/repository/config_io.cpp
    src/repository/journal.cpp
    src/repository/snapshot.cpp
    src/repository/snapshot_index.cpp
    src/repository/snapshot_records.cpp
    src/repository/validation_cache.cpp
)
target_link_libraries(cpcp_repository PUBLIC
    cpcp_crypto
    cpcp_platform
    cpcp_spool
)
cpcp_enable_warnings(cpcp_repository)

add_library(cpcp_application STATIC
    src/application/backup_service.cpp
    src/application/check_service.cpp
    src/application/credentials.cpp
    src/application/inspection_service.cpp
    src/application/key_service.cpp
    src/application/recovery_service.cpp
    src/application/repository_service.cpp
)
target_link_libraries(cpcp_application PUBLIC
    cpcp_repository
    cpcp_probe
)
cpcp_enable_warnings(cpcp_application)

add_library(cpcp_cli STATIC
    src/cli/app.cpp
    src/cli/backup_command.cpp
    src/cli/config_command.cpp
    src/cli/errors.cpp
    src/cli/inspection_command.cpp
    src/cli/key_command.cpp
    src/cli/probe_command.cpp
    src/cli/recovery_command.cpp
)
target_link_libraries(cpcp_cli PUBLIC
    cpcp_domain
    cpcp_probe
    cpcp_application
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
        tests/unit/cancellation_test.cpp
        tests/unit/content_id_test.cpp
        tests/unit/file_identity_test.cpp
        tests/unit/result_test.cpp
        tests/unit/snapshot_stream_test.cpp
    )
    target_link_libraries(cpcp_unit_tests PRIVATE
        cpcp_application
        Catch2::Catch2WithMain
    )
    cpcp_enable_warnings(cpcp_unit_tests)

    add_executable(cpcp_storage_tests
        tests/unit/chunk_set_test.cpp
        tests/unit/chunk_store_test.cpp
        tests/unit/config_test.cpp
        tests/unit/journal_test.cpp
        tests/unit/snapshot_test.cpp
        tests/unit/snapshot_index_test.cpp
    )
    target_link_libraries(cpcp_storage_tests PRIVATE
        cpcp_application
        Catch2::Catch2WithMain
    )
    cpcp_enable_warnings(cpcp_storage_tests)

    add_executable(cpcp_recovery_tests
        tests/integration/recovery_service_test.cpp
    )
    target_link_libraries(cpcp_recovery_tests PRIVATE
        cpcp_application
        Catch2::Catch2WithMain
    )
    cpcp_enable_warnings(cpcp_recovery_tests)

    add_executable(cpcp_backup_tests
        tests/integration/backup_service_test.cpp
        tests/integration/browse_service_test.cpp
        tests/integration/check_service_test.cpp
        tests/integration/incremental_backup_test.cpp
        tests/integration/key_service_test.cpp
        tests/integration/resume_service_test.cpp
        tests/integration/validation_cache_test.cpp
    )
    target_link_libraries(cpcp_backup_tests PRIVATE
        cpcp_application
        Catch2::Catch2WithMain
    )
    cpcp_enable_warnings(cpcp_backup_tests)

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
        tests/simulation/commit_protocol_test.cpp
        tests/simulation/simulated_filesystem_test.cpp
    )
    target_link_libraries(cpcp_simulation_tests PRIVATE
        cpcp_simulation
        Catch2::Catch2WithMain
    )
    cpcp_enable_warnings(cpcp_simulation_tests)

    include(Catch)
    catch_discover_tests(cpcp_unit_tests)
    if(NOT WIN32)
        catch_discover_tests(cpcp_storage_tests)
        catch_discover_tests(cpcp_recovery_tests)
        catch_discover_tests(cpcp_backup_tests)
    endif()
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

    if(NOT WIN32)
        add_test(
            NAME restore_cli
        COMMAND ${CMAKE_COMMAND}
            -DCPCP_EXECUTABLE=$<TARGET_FILE:cpcp>
            -DCPCP_PROBE_DIR=${CMAKE_CURRENT_BINARY_DIR}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/restore_cli.cmake
    )

    add_test(
        NAME backup_cli
        COMMAND ${CMAKE_COMMAND}
            -DCPCP_EXECUTABLE=$<TARGET_FILE:cpcp>
            -DCPCP_PROBE_DIR=${CMAKE_CURRENT_BINARY_DIR}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/backup_cli.cmake
    )

    add_test(
        NAME partial_cli
        COMMAND ${CMAKE_COMMAND}
            -DCPCP_EXECUTABLE=$<TARGET_FILE:cpcp>
            -DCPCP_PROBE_DIR=${CMAKE_CURRENT_BINARY_DIR}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/partial_cli.cmake
    )

    add_test(
        NAME snapshot_browse_cli
        COMMAND ${CMAKE_COMMAND}
            -DCPCP_EXECUTABLE=$<TARGET_FILE:cpcp>
            -DCPCP_PROBE_DIR=${CMAKE_CURRENT_BINARY_DIR}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/snapshot_browse_cli.cmake
    )

    add_test(
        NAME check_cli
        COMMAND ${CMAKE_COMMAND}
            -DCPCP_EXECUTABLE=$<TARGET_FILE:cpcp>
            -DCPCP_PROBE_DIR=${CMAKE_CURRENT_BINARY_DIR}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/check_cli.cmake
    )

    add_test(
        NAME key_cli
        COMMAND ${CMAKE_COMMAND}
            -DCPCP_EXECUTABLE=$<TARGET_FILE:cpcp>
            -DCPCP_PROBE_DIR=${CMAKE_CURRENT_BINARY_DIR}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/key_cli.cmake
    )

    add_test(
        NAME repository_init
        COMMAND ${CMAKE_COMMAND}
            -DCPCP_EXECUTABLE=$<TARGET_FILE:cpcp>
            -DCPCP_PROBE_DIR=${CMAKE_CURRENT_BINARY_DIR}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/repository_init.cmake
    )
    endif()

    if(NOT WIN32)
        add_test(
            NAME cli_probe_write
            COMMAND $<TARGET_FILE:cpcp> repo probe ${CMAKE_CURRENT_BINARY_DIR}
                --write-test --iterations 2 --size 65536 --json
        )
    endif()

    if(CPCP_ENABLE_STRESS_TESTS)
        add_executable(cpcp_stress_tests
            tests/stress/large_manifest_test.cpp
        )
        target_link_libraries(cpcp_stress_tests PRIVATE
            cpcp_spool
            Catch2::Catch2WithMain
        )
        cpcp_enable_warnings(cpcp_stress_tests)
        catch_discover_tests(cpcp_stress_tests)
    endif()

    option(CPCP_ENABLE_LARGE_FILE_TESTS "Enable files larger than 4 GiB" OFF)
    if(CPCP_ENABLE_LARGE_FILE_TESTS)
        add_executable(cpcp_large_file_tests
            tests/stress/large_file_test.cpp
        )
        target_link_libraries(cpcp_large_file_tests PRIVATE
            cpcp_application
            Catch2::Catch2WithMain
        )
        cpcp_enable_warnings(cpcp_large_file_tests)
        catch_discover_tests(cpcp_large_file_tests)
    endif()

    option(CPCP_ENABLE_REFERENCE_TESTS "Enable independent Python recoverer tests" OFF)
    option(CPCP_ENABLE_STRESS_TESTS "Enable large synthetic manifest stress tests" OFF)
    set(CPCP_PYTHONPATH "" CACHE STRING "Optional PyNaCl module path for reference tests")
    if(CPCP_ENABLE_REFERENCE_TESTS AND NOT WIN32)
        find_package(Python3 REQUIRED COMPONENTS Interpreter)
        add_test(
            NAME reference_recoverer
            COMMAND ${CMAKE_COMMAND} -E env PYTHONPATH=${CPCP_PYTHONPATH}
                ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/test_reference_recoverer.py
                --cpcp $<TARGET_FILE:cpcp>
        )
    endif()
endif()
