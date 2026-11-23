set(root "${CPCP_PROBE_DIR}/repository-init-test")
set(password "${root}/password.txt")
set(header "${root}/header.json")
file(REMOVE_RECURSE "${root}")
file(MAKE_DIRECTORY "${root}")
file(WRITE "${password}" "test password\n")
file(CHMOD "${password}" PERMISSIONS OWNER_READ OWNER_WRITE)

execute_process(
    COMMAND "${CPCP_EXECUTABLE}" repo init "${root}/repo"
        --password-file "${password}"
        --kdf-memory 8MiB --kdf-iterations 1 --chunk-size 1MiB --json
    RESULT_VARIABLE init_result
    OUTPUT_VARIABLE init_output
    ERROR_VARIABLE init_error
)
if(NOT init_result EQUAL 0)
    message(FATAL_ERROR "Repository init failed ${init_result}: ${init_error}")
endif()
if(NOT init_output MATCHES "\"schema\": \"cpcp.repo-init.v1\"")
    message(FATAL_ERROR "Repository init JSON missing schema: ${init_output}")
endif()
if(NOT EXISTS "${root}/repo/cpcp.config.json")
    message(FATAL_ERROR "Primary configuration was not created")
endif()
if(NOT EXISTS "${root}/repo/cpcp.config.backup.json")
    message(FATAL_ERROR "Backup configuration was not created")
endif()

execute_process(
    COMMAND "${CPCP_EXECUTABLE}" repo export-header "${header}"
        --repo "${root}/repo" --password-file "${password}" --json
    RESULT_VARIABLE export_result
    OUTPUT_VARIABLE export_output
    ERROR_VARIABLE export_error
)
if(NOT export_result EQUAL 0)
    message(FATAL_ERROR "Header export failed ${export_result}: ${export_error}")
endif()

file(REMOVE "${root}/repo/cpcp.config.json" "${root}/repo/cpcp.config.backup.json")
execute_process(
    COMMAND "${CPCP_EXECUTABLE}" repo import-header "${header}"
        --repo "${root}/repo" --password-file "${password}" --json
    RESULT_VARIABLE import_result
    OUTPUT_VARIABLE import_output
    ERROR_VARIABLE import_error
)
if(NOT import_result EQUAL 0)
    message(FATAL_ERROR "Header import failed ${import_result}: ${import_error}")
endif()
if(NOT import_output MATCHES "\"schema\": \"cpcp.repo-import-header.v1\"")
    message(FATAL_ERROR "Header import JSON missing schema: ${import_output}")
endif()

file(WRITE "${root}/wrong-password.txt" "wrong password\n")
file(CHMOD "${root}/wrong-password.txt" PERMISSIONS OWNER_READ OWNER_WRITE)
execute_process(
    COMMAND "${CPCP_EXECUTABLE}" repo export-header "${root}/wrong.json"
        --repo "${root}/repo" --password-file "${root}/wrong-password.txt" --json
    RESULT_VARIABLE wrong_result
    OUTPUT_VARIABLE wrong_output
    ERROR_VARIABLE wrong_error
)
if(NOT wrong_result EQUAL 5)
    message(FATAL_ERROR "Wrong password returned ${wrong_result}, expected 5")
endif()

execute_process(
    COMMAND "${CPCP_EXECUTABLE}" repo init "${root}/no-password" --json
    RESULT_VARIABLE missing_result
    OUTPUT_VARIABLE missing_output
    ERROR_VARIABLE missing_error
)
if(NOT missing_result EQUAL 2)
    message(FATAL_ERROR "Missing non-interactive password returned ${missing_result}, expected 2")
endif()

file(REMOVE_RECURSE "${root}")
