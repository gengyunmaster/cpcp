set(root "${CPCP_PROBE_DIR}/general-cli-test")
set(password "${root}/password.txt")
set(repo "${root}/repo")
set(source "${root}/source")
file(REMOVE_RECURSE "${root}")
file(MAKE_DIRECTORY "${root}" "${source}" "${root}/nested/child")
file(WRITE "${password}" "test password\n")
file(CHMOD "${password}" PERMISSIONS OWNER_READ OWNER_WRITE)
file(WRITE "${source}/a.txt" "hello")
set(environment CPCP_PASSWORD_FILE=${password} CPCP_REPO=${repo})

execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env ${environment}
        "${CPCP_EXECUTABLE}" repo init "${repo}"
        --kdf-memory 8MiB --kdf-iterations 1 --chunk-size 1MiB
    RESULT_VARIABLE init_result
    ERROR_VARIABLE init_error
)
if(NOT init_result EQUAL 0)
    message(FATAL_ERROR "Environment-based init failed: ${init_error}")
endif()
execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env ${environment}
        "${CPCP_EXECUTABLE}" backup add "${source}"
    RESULT_VARIABLE backup_result
    ERROR_VARIABLE backup_error
)
if(NOT backup_result EQUAL 0)
    message(FATAL_ERROR "Environment-based backup failed: ${backup_error}")
endif()

execute_process(
    COMMAND "${CMAKE_COMMAND}" -E env --unset=CPCP_REPO CPCP_PASSWORD_FILE=${password}
        "${CPCP_EXECUTABLE}" --discover-repo snapshot list
    WORKING_DIRECTORY "${repo}/snapshots"
    RESULT_VARIABLE discover_result
    OUTPUT_VARIABLE discover_output
    ERROR_VARIABLE discover_error
)
if(NOT discover_result EQUAL 0 OR NOT discover_output MATCHES "1  complete")
    message(FATAL_ERROR "Repository discovery failed: ${discover_result} ${discover_error} ${discover_output}")
endif()

execute_process(
    COMMAND "${CPCP_EXECUTABLE}" --plain --no-color --quiet help
    RESULT_VARIABLE help_result
    OUTPUT_VARIABLE help_output
    ERROR_VARIABLE help_error
)
if(NOT help_result EQUAL 0 OR NOT help_output MATCHES "Encrypted content-addressed backup CLI")
    message(FATAL_ERROR "General help options failed: ${help_result} ${help_error} ${help_output}")
endif()

execute_process(
    COMMAND "${CPCP_EXECUTABLE}" repo verify --repo-read-only --repo "${repo}"
        --password-file "${password}" --json
    RESULT_VARIABLE read_result
    OUTPUT_VARIABLE read_output
    ERROR_VARIABLE read_error
)
if(NOT read_result EQUAL 0 OR NOT read_output MATCHES "\"schema\": \"cpcp.repo-verify.v1\"")
    message(FATAL_ERROR "Read-only verification failed: ${read_result} ${read_error} ${read_output}")
endif()
if(NOT read_error MATCHES "without locks" OR read_error MATCHES "\"schema\"")
    message(FATAL_ERROR "Lockless warning was missing or polluted stdout: ${read_error}")
endif()
file(REMOVE_RECURSE "${root}")
