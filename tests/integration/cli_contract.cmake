if(NOT DEFINED CPCP_EXECUTABLE)
    message(FATAL_ERROR "CPCP_EXECUTABLE is required")
endif()

execute_process(
    COMMAND "${CPCP_EXECUTABLE}" --version
    RESULT_VARIABLE version_result
    OUTPUT_VARIABLE version_output
    ERROR_VARIABLE version_error
)
if(NOT version_result EQUAL 0)
    message(FATAL_ERROR "--version returned ${version_result}")
endif()
if(NOT version_output STREQUAL "cpcp 0.1.0\n")
    message(FATAL_ERROR "Unexpected version output: ${version_output}")
endif()
if(NOT version_error STREQUAL "")
    message(FATAL_ERROR "--version wrote to stderr: ${version_error}")
endif()

execute_process(
    COMMAND "${CPCP_EXECUTABLE}" --help
    RESULT_VARIABLE help_result
    OUTPUT_VARIABLE help_output
    ERROR_VARIABLE help_error
)
if(NOT help_result EQUAL 0)
    message(FATAL_ERROR "--help returned ${help_result}")
endif()
if(NOT help_output MATCHES "Encrypted content-addressed backup CLI")
    message(FATAL_ERROR "--help omitted the application description")
endif()
if(NOT help_error STREQUAL "")
    message(FATAL_ERROR "--help wrote to stderr: ${help_error}")
endif()

execute_process(
    COMMAND "${CPCP_EXECUTABLE}" unknown-command
    RESULT_VARIABLE unknown_result
    OUTPUT_VARIABLE unknown_output
    ERROR_VARIABLE unknown_error
)
if(NOT unknown_result EQUAL 2)
    message(FATAL_ERROR "Unknown command returned ${unknown_result}")
endif()
if(NOT unknown_output STREQUAL "")
    message(FATAL_ERROR "Unknown command wrote to stdout: ${unknown_output}")
endif()
if(unknown_error STREQUAL "")
    message(FATAL_ERROR "Unknown command did not write a diagnostic")
endif()

execute_process(
    COMMAND "${CPCP_EXECUTABLE}" repo probe "${CPCP_PROBE_DIR}" --json
    RESULT_VARIABLE probe_result
    OUTPUT_VARIABLE probe_output
    ERROR_VARIABLE probe_error
)
if(NOT probe_result EQUAL 0)
    message(FATAL_ERROR "Read-only probe returned ${probe_result}: ${probe_error}")
endif()
if(NOT probe_output MATCHES "\"schema\": \"cpcp.repo-probe.v1\"")
    message(FATAL_ERROR "Probe JSON has no schema: ${probe_output}")
endif()
if(NOT probe_output MATCHES "\"write_test\": false")
    message(FATAL_ERROR "Default probe enabled writes: ${probe_output}")
endif()
if(NOT probe_error STREQUAL "")
    message(FATAL_ERROR "Read-only probe wrote to stderr: ${probe_error}")
endif()
