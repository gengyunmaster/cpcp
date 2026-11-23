set(root "${CPCP_PROBE_DIR}/backup-cli-test")
set(password "${root}/password.txt")
set(repo "${root}/repo")
set(source "${root}/source")
file(REMOVE_RECURSE "${root}")
file(MAKE_DIRECTORY "${root}" "${source}/sub")
file(WRITE "${password}" "test password\n")
file(CHMOD "${password}" PERMISSIONS OWNER_READ OWNER_WRITE)
file(WRITE "${source}/empty.txt" "")
file(WRITE "${source}/a.txt" "hello")
file(WRITE "${source}/duplicate.txt" "hello")
file(WRITE "${source}/sub/b.txt" "world")

execute_process(
    COMMAND "${CPCP_EXECUTABLE}" repo init "${repo}"
        --password-file "${password}" --kdf-memory 8MiB --kdf-iterations 1
        --chunk-size 1MiB
    RESULT_VARIABLE init_result
    OUTPUT_VARIABLE init_output
    ERROR_VARIABLE init_error
)
if(NOT init_result EQUAL 0)
    message(FATAL_ERROR "Repository init failed: ${init_error}")
endif()

execute_process(
    COMMAND "${CPCP_EXECUTABLE}" backup add "${source}"
        --repo "${repo}" --password-file "${password}" --json
    RESULT_VARIABLE first_result
    OUTPUT_VARIABLE first_output
    ERROR_VARIABLE first_error
)
if(NOT first_result EQUAL 0)
    message(FATAL_ERROR "First backup failed ${first_result}: ${first_error}")
endif()
if(NOT first_output MATCHES "\"generation\": \"1\"")
    message(FATAL_ERROR "First backup did not publish generation 1: ${first_output}")
endif()
if(NOT first_output MATCHES "\"new_chunks\": \"2\"")
    message(FATAL_ERROR "First backup new chunk count is wrong: ${first_output}")
endif()
if(NOT first_output MATCHES "\"deduplicated_chunks\": \"1\"")
    message(FATAL_ERROR "First backup deduplication count is wrong: ${first_output}")
endif()

execute_process(
    COMMAND "${CPCP_EXECUTABLE}" backup add "${source}"
        --repo "${repo}" --password-file "${password}" --json
    RESULT_VARIABLE second_result
    OUTPUT_VARIABLE second_output
    ERROR_VARIABLE second_error
)
if(NOT second_result EQUAL 0)
    message(FATAL_ERROR "Second backup failed ${second_result}: ${second_error}")
endif()
if(NOT second_output MATCHES "\"generation\": \"2\"")
    message(FATAL_ERROR "Second backup did not publish generation 2: ${second_output}")
endif()
if(NOT second_output MATCHES "\"new_chunks\": \"0\"")
    message(FATAL_ERROR "Second backup created unexpected chunks: ${second_output}")
endif()
if(NOT second_output MATCHES "\"deduplicated_chunks\": \"3\"")
    message(FATAL_ERROR "Second backup deduplication count is wrong: ${second_output}")
endif()

file(REMOVE_RECURSE "${root}")
