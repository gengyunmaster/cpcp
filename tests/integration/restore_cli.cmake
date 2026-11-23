set(root "${CPCP_PROBE_DIR}/restore-cli-test")
set(password "${root}/password.txt")
set(repo "${root}/repo")
set(source "${root}/source")
set(restored "${root}/restored")
set(single "${root}/single")
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
    COMMAND "${CPCP_EXECUTABLE}" snapshot list --repo "${repo}"
        --password-file "${password}" --json
    RESULT_VARIABLE list_result
    OUTPUT_VARIABLE list_output
    ERROR_VARIABLE list_error
)
if(NOT list_result EQUAL 0)
    message(FATAL_ERROR "Snapshot list failed: ${list_error}")
endif()
if(NOT list_output MATCHES "\"generation\": \"1\"")
    message(FATAL_ERROR "Snapshot list missing generation: ${list_output}")
endif()

execute_process(
    COMMAND "${CPCP_EXECUTABLE}" snapshot show 1 --repo "${repo}"
        --password-file "${password}" --json
    RESULT_VARIABLE show_result
    OUTPUT_VARIABLE show_output
    ERROR_VARIABLE show_error
)
if(NOT show_result EQUAL 0)
    message(FATAL_ERROR "Snapshot show failed: ${show_error}")
endif()
if(NOT show_output MATCHES "\"label\": \"source\"")
    message(FATAL_ERROR "Snapshot show missing root label: ${show_output}")
endif()

execute_process(
    COMMAND "${CPCP_EXECUTABLE}" snapshot restore latest --to "${restored}"
        --repo "${repo}" --password-file "${password}" --json
    RESULT_VARIABLE restore_result
    OUTPUT_VARIABLE restore_output
    ERROR_VARIABLE restore_error
)
if(NOT restore_result EQUAL 0)
    message(FATAL_ERROR "Restore failed ${restore_result}: ${restore_error}")
endif()
file(READ "${restored}/source/a.txt" a_contents)
file(READ "${restored}/source/sub/b.txt" b_contents)
file(READ "${restored}/source/empty.txt" empty_contents)
if(NOT a_contents STREQUAL "hello")
    message(FATAL_ERROR "a.txt did not restore correctly")
endif()
if(NOT b_contents STREQUAL "world")
    message(FATAL_ERROR "b.txt did not restore correctly")
endif()
if(NOT empty_contents STREQUAL "")
    message(FATAL_ERROR "empty.txt did not restore correctly")
endif()

execute_process(
    COMMAND "${CPCP_EXECUTABLE}" snapshot restore 1 --root index:0
        --path sub/b.txt --to "${single}"
        --repo "${repo}" --password-file "${password}" --json
    RESULT_VARIABLE single_result
    OUTPUT_VARIABLE single_output
    ERROR_VARIABLE single_error
)
if(NOT single_result EQUAL 0)
    message(FATAL_ERROR "Selective restore failed ${single_result}: ${single_error}")
endif()
if(NOT single_output MATCHES "\"files\": \"1\"")
    message(FATAL_ERROR "Selective restore file count is wrong: ${single_output}")
endif()

execute_process(
    COMMAND "${CPCP_EXECUTABLE}" snapshot restore latest --to "${restored}"
        --repo "${repo}" --password-file "${password}"
    RESULT_VARIABLE conflict_result
    ERROR_VARIABLE conflict_error
)
if(NOT conflict_result EQUAL 1)
    message(FATAL_ERROR "Default overwrite returned ${conflict_result}, expected 1")
endif()

execute_process(
    COMMAND "${CPCP_EXECUTABLE}" snapshot restore latest --to "${restored}"
        --overwrite --yes --repo "${repo}" --password-file "${password}"
    RESULT_VARIABLE overwrite_result
    ERROR_VARIABLE overwrite_error
)
if(NOT overwrite_result EQUAL 0)
    message(FATAL_ERROR "Explicit overwrite failed: ${overwrite_error}")
endif()

execute_process(
    COMMAND "${CPCP_EXECUTABLE}" repo verify --deep --repo "${repo}"
        --password-file "${password}" --json
    RESULT_VARIABLE verify_result
    OUTPUT_VARIABLE verify_output
    ERROR_VARIABLE verify_error
)
if(NOT verify_result EQUAL 0)
    message(FATAL_ERROR "Deep verification failed: ${verify_error}")
endif()
if(NOT verify_output MATCHES "\"deep\": true")
    message(FATAL_ERROR "Deep verification scope is wrong: ${verify_output}")
endif()

execute_process(
    COMMAND "${CPCP_EXECUTABLE}" snapshot restore latest
        --path ../escape --to "${root}/escape"
        --repo "${repo}" --password-file "${password}"
    RESULT_VARIABLE traversal_result
    ERROR_VARIABLE traversal_error
)
if(NOT traversal_result EQUAL 2)
    message(FATAL_ERROR "Unsafe path returned ${traversal_result}, expected 2")
endif()

file(REMOVE_RECURSE "${root}")
