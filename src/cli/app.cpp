#include "cli/app.hpp"

#include "cli/config_command.hpp"
#include "cli/backup_command.hpp"
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

    ConfigCommandOptions config_options;
    const auto add_password_options = [&](CLI::App* command) {
        command->add_option(
            "--password-file",
            config_options.password_file,
            "Read the repository password from a protected file"
        );
        command->add_flag("--json", config_options.json, "Emit JSON output");
    };

    auto* init = repo->add_subcommand("init", "Initialize a repository");
    std::filesystem::path init_directory;
    init->add_option("directory", init_directory, "Empty repository directory")->required();
    init->add_option("--kdf-memory", config_options.kdf_memory)
        ->default_val(config_options.kdf_memory);
    init->add_option("--kdf-iterations", config_options.kdf_iterations)
        ->default_val(config_options.kdf_iterations);
    init->add_option("--chunk-size", config_options.chunk_size)
        ->default_val(config_options.chunk_size);
    add_password_options(init);
    init->callback([&] {
        command_result = run_init_command(init_directory, config_options);
    });

    auto* export_header = repo->add_subcommand("export-header", "Export an authenticated header");
    std::filesystem::path export_output;
    std::filesystem::path export_repository = ".";
    export_header->add_option("output", export_output, "Exported header path")->required();
    export_header->add_option("--repo", export_repository)
        ->default_val(export_repository);
    add_password_options(export_header);
    export_header->callback([&] {
        command_result = run_export_header_command(
            export_repository,
            export_output,
            config_options
        );
    });

    auto* import_header = repo->add_subcommand("import-header", "Import an authenticated header");
    std::filesystem::path import_path;
    std::filesystem::path import_repository = ".";
    import_header->add_option("header", import_path, "Header to import")->required();
    import_header->add_option("--repo", import_repository)
        ->default_val(import_repository);
    add_password_options(import_header);
    import_header->callback([&] {
        command_result = run_import_header_command(
            import_path,
            import_repository,
            config_options
        );
    });

    auto* backup = app.add_subcommand("backup", "Backup operations");
    backup->require_subcommand(1);
    auto* add = backup->add_subcommand("add", "Add source trees to a snapshot");
    std::vector<std::filesystem::path> backup_roots;
    std::filesystem::path backup_repository = ".";
    application::BackupOptions backup_options;
    add->add_option("paths", backup_roots, "Source root directories")->required()->expected(-1);
    add->add_option("--repo", backup_repository)->default_val(backup_repository);
    add->add_flag("--revalidate-all", backup_options.revalidate_all, "Revalidate every referenced chunk");
    add->add_flag("--full-source-read", backup_options.full_source_read, "Read every source byte");
    add->add_flag("--cross-file-systems", backup_options.cross_file_systems, "Allow mounted filesystem traversal");
    add->add_flag("--no-parent", backup_options.no_parent, "Start a new snapshot lineage");
    add_password_options(add);
    add->callback([&] {
        command_result = run_backup_add_command(
            backup_roots,
            BackupCommandOptions{backup_repository, backup_options, config_options}
        );
    });

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
