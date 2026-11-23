set(root "${CPCP_PROBE_DIR}/key-cli-test")
set(repo "${root}/repo")
set(source "${root}/source")
set(first "${root}/first.txt")
set(second "${root}/second.txt")
set(third "${root}/third.txt")
set(recovery "${root}/recovery.txt")
file(REMOVE_RECURSE "${root}")
file(MAKE_DIRECTORY "${root}" "${source}")
file(WRITE "${first}" "first\n")
file(WRITE "${second}" "second\n")
file(WRITE "${third}" "third\n")
file(CHMOD "${first}" PERMISSIONS OWNER_READ OWNER_WRITE)
file(CHMOD "${second}" PERMISSIONS OWNER_READ OWNER_WRITE)
file(CHMOD "${third}" PERMISSIONS OWNER_READ OWNER_WRITE)
file(WRITE "${source}/a.txt" "hello")

execute_process(
    COMMAND "${CPCP_EXECUTABLE}" repo init "${repo}"
        --password-file "${first}" --kdf-memory 8MiB --kdf-iterations 1 --chunk-size 1MiB
    RESULT_VARIABLE init_result
    ERROR_VARIABLE init_error
)
if(NOT init_result EQUAL 0)
    message(FATAL_ERROR "init failed: ${init_error}")
endif()
execute_process(
    COMMAND "${CPCP_EXECUTABLE}" repo passwd --repo "${repo}"
        --password-file "${first}" --new-password-file "${second}"
    RESULT_VARIABLE passwd_result
    ERROR_VARIABLE passwd_error
)
if(NOT passwd_result EQUAL 0)
    message(FATAL_ERROR "passwd failed: ${passwd_error}")
endif()
execute_process(
    COMMAND "${CPCP_EXECUTABLE}" backup add "${source}"
        --repo "${repo}" --password-file "${second}"
    RESULT_VARIABLE backup_result
    ERROR_VARIABLE backup_error
)
if(NOT backup_result EQUAL 0)
    message(FATAL_ERROR "backup failed: ${backup_error}")
endif()
execute_process(
    COMMAND "${CPCP_EXECUTABLE}" repo key add-password --repo "${repo}"
        --password-file "${second}" --new-password-file "${third}" --slot-id password-2
    RESULT_VARIABLE add_password_result
    ERROR_VARIABLE add_password_error
)
if(NOT add_password_result EQUAL 0)
    message(FATAL_ERROR "add-password failed: ${add_password_error}")
endif()
execute_process(
    COMMAND "${CPCP_EXECUTABLE}" repo key add-recovery-key --repo "${repo}"
        --password-file "${second}" --show-key --json
    RESULT_VARIABLE recovery_result
    OUTPUT_VARIABLE recovery_output
    ERROR_VARIABLE recovery_error
)
if(NOT recovery_result EQUAL 0)
    message(FATAL_ERROR "add-recovery-key failed: ${recovery_error}")
endif()
if(NOT recovery_output MATCHES "\"recovery_key\": \"([0-9a-f]+)\"")
    message(FATAL_ERROR "Recovery key was not returned exactly once: ${recovery_output}")
endif()
string(LENGTH "${CMAKE_MATCH_1}" recovery_length)
if(NOT recovery_length EQUAL 64)
    message(FATAL_ERROR "Recovery key has the wrong length: ${recovery_output}")
endif()
file(WRITE "${recovery}" "${CMAKE_MATCH_1}\n")
file(CHMOD "${recovery}" PERMISSIONS OWNER_READ OWNER_WRITE)
execute_process(
    COMMAND "${CPCP_EXECUTABLE}" repo key list --repo "${repo}" --password-file "${recovery}" --json
    RESULT_VARIABLE list_result
    OUTPUT_VARIABLE list_output
    ERROR_VARIABLE list_error
)
if(NOT list_result EQUAL 0 OR NOT list_output MATCHES "\"type\": \"recovery\"")
    message(FATAL_ERROR "Recovery key could not list slots: ${list_result} ${list_error} ${list_output}")
endif()
execute_process(
    COMMAND "${CPCP_EXECUTABLE}" repo key remove password-2 --repo "${repo}"
        --password-file "${second}" --yes
    RESULT_VARIABLE remove_result
    ERROR_VARIABLE remove_error
)
if(NOT remove_result EQUAL 0)
    message(FATAL_ERROR "remove failed: ${remove_error}")
endif()
execute_process(
    COMMAND "${CPCP_EXECUTABLE}" repo key list --repo "${repo}" --password-file "${third}"
    RESULT_VARIABLE removed_result
    ERROR_VARIABLE removed_error
)
if(NOT removed_result EQUAL 5)
    message(FATAL_ERROR "Removed password still unlocked the repository: ${removed_result} ${removed_error}")
endif()
execute_process(
    COMMAND "${CPCP_EXECUTABLE}" repo rotate-epoch --repo "${repo}" --password-file "${second}" --json
    RESULT_VARIABLE rotate_result
    OUTPUT_VARIABLE rotate_output
    ERROR_VARIABLE rotate_error
)
if(NOT rotate_result EQUAL 0 OR NOT rotate_output MATCHES "\"storage_epoch\": \"[0-9a-f]+\"")
    message(FATAL_ERROR "Epoch rotation failed: ${rotate_error} ${rotate_output}")
endif()
execute_process(
    COMMAND "${CPCP_EXECUTABLE}" repo verify --deep --repo "${repo}" --password-file "${recovery}"
    RESULT_VARIABLE verify_result
    ERROR_VARIABLE verify_error
)
if(NOT verify_result EQUAL 0)
    message(FATAL_ERROR "Verification after key and epoch changes failed: ${verify_error}")
endif()
file(REMOVE_RECURSE "${root}")
