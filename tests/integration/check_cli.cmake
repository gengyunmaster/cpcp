set(root "${CPCP_PROBE_DIR}/check-cli-test")
set(password "${root}/password.txt")
set(repo "${root}/repo")
set(source "${root}/source")
file(REMOVE_RECURSE "${root}")
file(MAKE_DIRECTORY "${root}" "${source}")
file(WRITE "${password}" "test password\n")
file(CHMOD "${password}" PERMISSIONS OWNER_READ OWNER_WRITE)
file(WRITE "${source}/same.txt" "same")
file(WRITE "${source}/changed.txt" "before")
file(WRITE "${source}/missing.txt" "gone")

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
    COMMAND "${CPCP_EXECUTABLE}" backup check "${source}"
        --repo "${repo}" --password-file "${password}" --json
    RESULT_VARIABLE metadata_result
    OUTPUT_VARIABLE metadata_output
    ERROR_VARIABLE metadata_error
)
if(NOT metadata_result EQUAL 0 OR NOT metadata_output MATCHES "\"mode\": \"metadata\"")
    message(FATAL_ERROR "Metadata check failed: ${metadata_result} ${metadata_error} ${metadata_output}")
endif()
if(NOT metadata_output MATCHES "\"status\": \"metadata-match\"")
    message(FATAL_ERROR "Metadata check used the wrong status: ${metadata_output}")
endif()

execute_process(
    COMMAND "${CPCP_EXECUTABLE}" backup check "${source}"
        --repo "${repo}" --password-file "${password}" --content --verify-repo --ndjson
    RESULT_VARIABLE verified_result
    OUTPUT_VARIABLE verified_output
    ERROR_VARIABLE verified_error
)
if(NOT verified_result EQUAL 0)
    message(FATAL_ERROR "Verified check failed: ${verified_error}")
endif()
if(NOT verified_output MATCHES "\"schema\":\"cpcp.check-entry.v1\""
    OR NOT verified_output MATCHES "\"status\":\"verified\""
    OR NOT verified_output MATCHES "\"schema\":\"cpcp.check-summary.v1\""
    OR NOT verified_output MATCHES "\"mode\":\"content\+repository\""
    OR NOT verified_output MATCHES "\"differences\":\"0\"")
    message(FATAL_ERROR "Verified NDJSON report is invalid: ${verified_output}")
endif()

file(WRITE "${source}/changed.txt" "after")
file(REMOVE "${source}/missing.txt")
file(WRITE "${source}/added.txt" "added")
execute_process(
    COMMAND "${CPCP_EXECUTABLE}" backup check "${source}"
        --repo "${repo}" --password-file "${password}" --json
    RESULT_VARIABLE differences_result
    OUTPUT_VARIABLE differences_output
    ERROR_VARIABLE differences_error
)
if(NOT differences_result EQUAL 3)
    message(FATAL_ERROR "Differences returned ${differences_result}: ${differences_error}")
endif()
foreach(status IN ITEMS added missing changed)
    if(NOT differences_output MATCHES "\"status\": \"${status}\"")
        message(FATAL_ERROR "Check omitted ${status}: ${differences_output}")
    endif()
endforeach()

execute_process(
    COMMAND "${CPCP_EXECUTABLE}" backup check "${source}" --path same.txt
        --repo "${repo}" --password-file "${password}"
    RESULT_VARIABLE narrow_result
    ERROR_VARIABLE narrow_error
)
if(NOT narrow_result EQUAL 0)
    message(FATAL_ERROR "Path-scoped check failed: ${narrow_error}")
endif()

execute_process(
    COMMAND "${CPCP_EXECUTABLE}" snapshot restore 1 --to "${root}/restored"
        --repo "${repo}" --password-file "${password}"
    RESULT_VARIABLE restore_result
    ERROR_VARIABLE restore_error
)
if(NOT restore_result EQUAL 0)
    message(FATAL_ERROR "Restore failed: ${restore_error}")
endif()
execute_process(
    COMMAND "${CPCP_EXECUTABLE}" backup check "${root}/restored/source"
        --root index:0 --content --snapshot 1
        --repo "${repo}" --password-file "${password}" --json
    RESULT_VARIABLE relocated_result
    OUTPUT_VARIABLE relocated_output
    ERROR_VARIABLE relocated_error
)
if(NOT relocated_result EQUAL 0 OR NOT relocated_output MATCHES "\"status\": \"content-match\"")
    message(FATAL_ERROR "Restored-tree check failed: ${relocated_result} ${relocated_error} ${relocated_output}")
endif()

execute_process(
    COMMAND "${CPCP_EXECUTABLE}" backup check "${root}/restored/source" --verify-repo
        --repo "${repo}" --password-file "${password}"
    RESULT_VARIABLE invalid_mode_result
    ERROR_VARIABLE invalid_mode_error
)
if(NOT invalid_mode_result EQUAL 2)
    message(FATAL_ERROR "--verify-repo without --content returned ${invalid_mode_result}: ${invalid_mode_error}")
endif()
execute_process(
    COMMAND "${CPCP_EXECUTABLE}" backup check "${root}/restored/source"
        --repo "${repo}" --password-file "${password}"
    RESULT_VARIABLE unmapped_result
    ERROR_VARIABLE unmapped_error
)
if(NOT unmapped_result EQUAL 2)
    message(FATAL_ERROR "Relocated tree without --root returned ${unmapped_result}: ${unmapped_error}")
endif()

file(REMOVE_RECURSE "${root}")
