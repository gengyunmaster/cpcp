#include "cli/app.hpp"

#include "cli/probe_command.hpp"

#include <CLI/CLI.hpp>

#include <filesystem>
#include <string>

namespace cpcp::cli {

int run(int argc, char** argv) {
    CLI::App app{"Encrypted content-addressed backup CLI", "cpcp"};
    app.set_version_flag("--version", "cpcp " CPCP_VERSION);

    int command_result = 0;
    auto* repo = app.add_subcommand("repo", "Repository operations");
    repo->require_subcommand(1);
    auto* probe = repo->add_subcommand("probe", "Probe filesystem capabilities");
    std::filesystem::path directory;
    platform::ProbeOptions options;
    bool json = false;
    probe->add_option("directory", directory, "Directory to probe")->required();
    probe->add_flag("--write-test", options.write_test, "Run the temporary-file write test");
    probe->add_option("--size", options.payload_size, "Payload size in bytes")
        ->default_val(options.payload_size);
    probe->add_option("--iterations", options.iterations, "Number of write-test iterations")
        ->default_val(options.iterations);
    probe->add_flag("--json", json, "Emit JSON output");
    probe->callback([&] {
        command_result = run_probe_command(directory, options, json);
    });

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& error) {
        const int exit_code = error.get_exit_code();
        app.exit(error);
        return exit_code == 0 ? 0 : 2;
    }

    return command_result;
}

}
