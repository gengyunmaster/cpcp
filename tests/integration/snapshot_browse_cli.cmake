set(root "${CPCP_PROBE_DIR}/snapshot-browse-cli-test")
set(password "${root}/password.txt")
set(repo "${root}/repo")
set(source "${root}/Documents")
file(REMOVE_RECURSE "${root}")
file(MAKE_DIRECTORY "${root}" "${source}/sub")
file(WRITE "${password}" "test password\n")
file(CHMOD "${password}" PERMISSIONS OWNER_READ OWNER_WRITE)
file(WRITE "${source}/a.txt" "a")
file(WRITE "${source}/sub/b.txt" "b")
file(WRITE "${source}/sub/c.jpg" "c")

execute_process(
    COMMAND "${CPCP_EXECUTABLE}" repo init "${repo}"
        --password-file "${password}" --kdf-memory 8MiB --kdf-iterations 1
        --chunk-size 1MiB
    RESULT_VARIABLE init_result
    ERROR_VARIABLE init_error
)
if(NOT init_result EQUAL 0)
    message(FATAL_ERROR "Repository init failed: ${init_error}")
endif()
execute_process(
    COMMAND "${CPCP_EXECUTABLE}" backup add "${source}"
        --repo "${repo}" --password-file "${password}"
    RESULT_VARIABLE backup_result
    ERROR_VARIABLE backup_error
)
if(NOT backup_result EQUAL 0)
    message(FATAL_ERROR "Backup failed: ${backup_error}")
endif()

execute_process(
    COMMAND "${CPCP_EXECUTABLE}" snapshot ls 1 --root index:0
        --repo "${repo}" --password-file "${password}" --json
    RESULT_VARIABLE ls_result
    OUTPUT_VARIABLE ls_output
    ERROR_VARIABLE ls_error
)
if(NOT ls_result EQUAL 0)
    message(FATAL_ERROR "snapshot ls failed: ${ls_error}")
endif()
if(NOT ls_output MATCHES "\"schema\": \"cpcp.snapshot-entries.v1\""
    OR NOT ls_output MATCHES "\"path\": \"sub/b.txt\""
    OR NOT ls_output MATCHES "\"verification_scope\": \"full-authenticated-manifest\"")
    message(FATAL_ERROR "snapshot ls returned an invalid report: ${ls_output}")
endif()

execute_process(
    COMMAND "${CPCP_EXECUTABLE}" snapshot find 1 "*.txt" --root label:Documents
        --repo "${repo}" --password-file "${password}" --ndjson
    RESULT_VARIABLE find_result
    OUTPUT_VARIABLE find_output
    ERROR_VARIABLE find_error
)
if(NOT find_result EQUAL 0)
    message(FATAL_ERROR "snapshot find failed: ${find_error}")
endif()
string(REGEX MATCHALL "\"schema\":\"cpcp.snapshot-entry.v1\"" entry_lines "${find_output}")
list(LENGTH entry_lines entry_count)
if(NOT entry_count EQUAL 2)
    message(FATAL_ERROR "snapshot find returned ${entry_count} entries instead of 2: ${find_output}")
endif()
if(NOT find_output MATCHES "\"schema\":\"cpcp.snapshot-entries-header.v1\""
    OR NOT find_output MATCHES "\"schema\":\"cpcp.snapshot-entries-summary.v1\""
    OR NOT find_output MATCHES "\"entries\":\"2\"")
    message(FATAL_ERROR "snapshot find returned invalid NDJSON framing: ${find_output}")
endif()

execute_process(
    COMMAND "${CPCP_EXECUTABLE}" snapshot ls 99
        --repo "${repo}" --password-file "${password}" --ndjson
    RESULT_VARIABLE missing_result
    OUTPUT_VARIABLE missing_output
    ERROR_VARIABLE missing_error
)
if(NOT missing_result EQUAL 1 OR NOT missing_output STREQUAL "")
    message(FATAL_ERROR "Missing snapshot produced provisional output: ${missing_result} ${missing_output} ${missing_error}")
endif()

execute_process(
    COMMAND "${CPCP_EXECUTABLE}" snapshot ls 1 --json --ndjson
        --repo "${repo}" --password-file "${password}"
    RESULT_VARIABLE conflict_result
    ERROR_VARIABLE conflict_error
)
if(NOT conflict_result EQUAL 2)
    message(FATAL_ERROR "Conflicting output modes returned ${conflict_result}: ${conflict_error}")
endif()

file(REMOVE_RECURSE "${root}")
