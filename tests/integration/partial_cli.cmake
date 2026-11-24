set(root "${CPCP_PROBE_DIR}/partial-cli-test")
set(password "${root}/password.txt")
set(repo "${root}/repo")
set(source "${root}/source")
file(REMOVE_RECURSE "${root}")
file(MAKE_DIRECTORY "${root}" "${source}")
file(WRITE "${password}" "test password\n")
file(CHMOD "${password}" PERMISSIONS OWNER_READ OWNER_WRITE)
file(WRITE "${source}/a.txt" "hello")
execute_process(COMMAND mkfifo "${source}/fifo" RESULT_VARIABLE fifo_result)
if(NOT fifo_result EQUAL 0)
    message(FATAL_ERROR "Could not create the unsupported FIFO fixture")
endif()

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
        --repo "${repo}" --password-file "${password}" --json
    RESULT_VARIABLE complete_result
    OUTPUT_VARIABLE complete_output
    ERROR_VARIABLE complete_error
)
if(NOT complete_result EQUAL 0 OR NOT complete_output MATCHES "\"status\": \"complete\"")
    message(FATAL_ERROR "Complete-under-policy backup failed: ${complete_result} ${complete_error} ${complete_output}")
endif()

execute_process(
    COMMAND "${CPCP_EXECUTABLE}" backup add "${source}"
        --repo "${repo}" --password-file "${password}" --unsupported=fail --json
    RESULT_VARIABLE rejected_result
    ERROR_VARIABLE rejected_error
)
if(NOT rejected_result EQUAL 3)
    message(FATAL_ERROR "Failed entries without --allow-partial returned ${rejected_result}: ${rejected_error}")
endif()

execute_process(
    COMMAND "${CPCP_EXECUTABLE}" backup add "${source}"
        --repo "${repo}" --password-file "${password}" --unsupported=fail --allow-partial --json
    RESULT_VARIABLE partial_result
    OUTPUT_VARIABLE partial_output
    ERROR_VARIABLE partial_error
)
if(NOT partial_result EQUAL 3 OR NOT partial_output MATCHES "\"status\": \"partial\"")
    message(FATAL_ERROR "Partial backup contract failed: ${partial_result} ${partial_error} ${partial_output}")
endif()
if(NOT partial_output MATCHES "\"failed_entries\": \"1\"")
    message(FATAL_ERROR "Partial backup omitted its failure count: ${partial_output}")
endif()

execute_process(
    COMMAND "${CPCP_EXECUTABLE}" snapshot restore latest --to "${root}/rejected"
        --repo "${repo}" --password-file "${password}"
    RESULT_VARIABLE restore_rejected_result
    ERROR_VARIABLE restore_rejected_error
)
if(NOT restore_rejected_result EQUAL 2)
    message(FATAL_ERROR "Unapproved partial restore returned ${restore_rejected_result}: ${restore_rejected_error}")
endif()

execute_process(
    COMMAND "${CPCP_EXECUTABLE}" snapshot restore latest-complete --to "${root}/complete"
        --repo "${repo}" --password-file "${password}" --json
    RESULT_VARIABLE latest_complete_result
    OUTPUT_VARIABLE latest_complete_output
    ERROR_VARIABLE latest_complete_error
)
if(NOT latest_complete_result EQUAL 0 OR NOT latest_complete_output MATCHES "\"snapshot\": \"1\"")
    message(FATAL_ERROR "latest-complete selected the wrong snapshot: ${latest_complete_error} ${latest_complete_output}")
endif()

execute_process(
    COMMAND "${CPCP_EXECUTABLE}" snapshot restore latest --to "${root}/partial"
        --repo "${repo}" --password-file "${password}" --allow-partial --json
    RESULT_VARIABLE restore_partial_result
    OUTPUT_VARIABLE restore_partial_output
    ERROR_VARIABLE restore_partial_error
)
if(NOT restore_partial_result EQUAL 0 OR NOT restore_partial_output MATCHES "\"snapshot\": \"2\"")
    message(FATAL_ERROR "Approved partial restore failed: ${restore_partial_error} ${restore_partial_output}")
endif()

file(REMOVE_RECURSE "${root}")
