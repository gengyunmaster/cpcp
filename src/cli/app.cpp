#include "cli/app.hpp"

#include "cli/config_command.hpp"
#include "cli/backup_command.hpp"
#include "cli/inspection_command.hpp"
#include "cli/probe_command.hpp"
#include "cli/recovery_command.hpp"
#include "cli/errors.hpp"
#include "platform/cancellation.hpp"

#include <CLI/CLI.hpp>

#include <charconv>
#include <filesystem>
#include <string>

namespace cpcp::cli {

int run(int argc, char** argv) {
    const auto cancellation = platform::install_cancellation_handler();
    if (!cancellation) {
        return report_error(cancellation.error());
    }

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
    std::string unsupported_policy = "skip";
    add->add_option("paths", backup_roots, "Source root directories")->required()->expected(-1);
    add->add_option("--repo", backup_repository)->default_val(backup_repository);
    add->add_flag("--revalidate-all", backup_options.revalidate_all, "Revalidate every referenced chunk");
    add->add_flag("--full-source-read", backup_options.full_source_read, "Read every source byte");
    add->add_flag("--cross-file-systems", backup_options.cross_file_systems, "Allow mounted filesystem traversal");
    add->add_flag("--no-parent", backup_options.no_parent, "Start a new snapshot lineage");
    add->add_flag("--allow-partial", backup_options.allow_partial, "Publish a partial snapshot when required entries fail");
    add->add_option("--unsupported", unsupported_policy, "Policy for unsupported entries: skip or fail")
        ->default_val(unsupported_policy)
        ->check(CLI::IsMember({"skip", "fail"}));
    add_password_options(add);
    add->callback([&] {
        backup_options.unsupported_fail = unsupported_policy == "fail";
        command_result = run_backup_add_command(
            backup_roots,
            BackupCommandOptions{backup_repository, backup_options, config_options}
        );
    });

    auto* check = backup->add_subcommand("check", "Compare a source tree with a snapshot");
    CheckCommandOptions check_options;
    std::string check_selector = "latest";
    std::string check_root;
    check->add_option("source", check_options.check.source, "Source directory or explicitly mapped restored tree")
        ->required();
    check->add_option("--repo", check_options.repository)->default_val(check_options.repository);
    check->add_option("--snapshot", check_selector, "Snapshot generation, latest, or latest-complete")
        ->default_val(check_selector);
    check->add_option("--root", check_root, "Root selector: index:<n> or label:<name>");
    check->add_option("--path", check_options.check.path, "Limit comparison to a root-relative path");
    check->add_flag("--content", check_options.check.content, "Compare source content identities");
    check->add_flag("--verify-repo", check_options.check.verify_repo, "Validate referenced repository chunks");
    check->add_flag("--repo-read-only", check_options.check.repo_read_only, "Read the repository without locks or writes");
    add_password_options(check);
    check->add_flag("--ndjson", check_options.ndjson, "Stream newline-delimited JSON results");
    check->callback([&] {
        check_options.config = config_options;
        command_result = run_backup_check_command(check_selector, check_root, check_options);
    });

    auto* snapshot = app.add_subcommand("snapshot", "Snapshot operations");
    snapshot->require_subcommand(1);
    InspectionCommandOptions inspection_options;
    inspection_options.config = config_options;
    const auto add_inspection_options = [&](CLI::App* command) {
        command->add_option("--repo", inspection_options.repository)->default_val(inspection_options.repository);
        command->add_option("--password-file", inspection_options.config.password_file);
        command->add_flag("--json", inspection_options.config.json);
        command->add_flag("--repo-read-only", inspection_options.repo_read_only);
    };

    auto* list = snapshot->add_subcommand("list", "List snapshots");
    add_inspection_options(list);
    list->callback([&] {
        command_result = run_snapshot_list_command(inspection_options);
    });

    auto* show = snapshot->add_subcommand("show", "Show a snapshot summary");
    std::uint64_t show_generation = 0;
    show->add_option("generation", show_generation)->required();
    add_inspection_options(show);
    show->callback([&] {
        command_result = run_snapshot_show_command(inspection_options, show_generation);
    });

    auto* ls = snapshot->add_subcommand("ls", "List authenticated snapshot entries");
    std::string browse_selector;
    std::string browse_root;
    application::BrowseOptions browse_options;
    ls->add_option("snapshot", browse_selector)->required();
    ls->add_option("--root", browse_root, "Root selector: index:<n> or label:<name>");
    ls->add_option("--path", browse_options.path_prefix, "Limit results to a root-relative path prefix");
    add_inspection_options(ls);
    ls->add_flag("--ndjson", inspection_options.ndjson, "Stream newline-delimited JSON entries");
    ls->callback([&] {
        browse_options.glob.clear();
        command_result = run_snapshot_browse_command(
            inspection_options,
            browse_selector,
            browse_root,
            browse_options
        );
    });

    auto* find = snapshot->add_subcommand("find", "Find authenticated snapshot entries");
    std::string find_selector;
    std::string find_pattern;
    std::string find_root;
    application::BrowseOptions find_options;
    find->add_option("snapshot", find_selector)->required();
    find->add_option("pattern", find_pattern, "Glob with * and ? wildcards")->required();
    find->add_option("--root", find_root, "Root selector: index:<n> or label:<name>");
    add_inspection_options(find);
    find->add_flag("--ndjson", inspection_options.ndjson, "Stream newline-delimited JSON entries");
    find->callback([&] {
        find_options.glob = find_pattern;
        command_result = run_snapshot_browse_command(
            inspection_options,
            find_selector,
            find_root,
            find_options
        );
    });

    auto* restore = snapshot->add_subcommand("restore", "Restore snapshot entries");
    std::string restore_selector;
    application::RestoreOptions restore_options;
    std::string root_selector;
    restore->add_option("snapshot", restore_selector)->required();
    restore->add_option("--to", restore_options.destination)->required();
    restore->add_option("--root", root_selector);
    restore->add_option("--path", restore_options.path);
    restore->add_flag("--strip-root", restore_options.strip_root);
    restore->add_flag("--overwrite", restore_options.overwrite);
    restore->add_flag("--yes", restore_options.yes);
    restore->add_flag("--strict-metadata", restore_options.strict_metadata);
    restore->add_flag("--allow-partial", restore_options.allow_partial, "Allow restoration from a partial snapshot");
    add_inspection_options(restore);
    restore->callback([&] {
        if (!root_selector.empty()) {
            if (!root_selector.starts_with("index:")) {
                command_result = report_error(domain::Error{
                    domain::ErrorCode::usage,
                    "root selector must use index:<n> or label:<name>",
                });
                return;
            }
            std::uint32_t value = 0;
            const auto parsed = std::from_chars(
                root_selector.data() + 6,
                root_selector.data() + root_selector.size(),
                value
            );
            if (parsed.ec != std::errc{} || parsed.ptr != root_selector.data() + root_selector.size()) {
                command_result = report_error(domain::Error{
                    domain::ErrorCode::usage,
                    "invalid root index",
                });
                return;
            }
            restore_options.root = value;
        }
        command_result = run_restore_command(
            inspection_options,
            restore_selector,
            restore_options
        );
    });

    auto* verify = repo->add_subcommand("verify", "Verify repository integrity");
    bool deep_verify = false;
    verify->add_flag("--deep", deep_verify, "Validate every referenced chunk");
    add_inspection_options(verify);
    verify->callback([&] {
        command_result = run_verify_command(inspection_options, deep_verify);
    });

    auto* quarantine = repo->add_subcommand("quarantine", "Quarantine a damaged object");
    RecoveryCommandOptions recovery_options;
    recovery_options.config = config_options;
    std::string quarantine_selector;
    quarantine->add_option("object", quarantine_selector)->required();
    quarantine->add_option("--repo", recovery_options.repository)
        ->default_val(recovery_options.repository);
    quarantine->add_option("--password-file", recovery_options.config.password_file);
    quarantine->add_flag("--json", recovery_options.config.json);
    quarantine->add_flag("--dry-run", recovery_options.dry_run);
    quarantine->add_flag("--yes", recovery_options.yes);
    quarantine->callback([&] {
        command_result = run_quarantine_command(recovery_options, quarantine_selector);
    });

    auto* repair_summary = repo->add_subcommand("repair-summary", "Rebuild a snapshot summary");
    std::uint64_t repair_generation = 0;
    repair_summary->add_option("generation", repair_generation)->required();
    repair_summary->add_option("--repo", recovery_options.repository)
        ->default_val(recovery_options.repository);
    repair_summary->add_option("--password-file", recovery_options.config.password_file);
    repair_summary->add_flag("--json", recovery_options.config.json);
    repair_summary->add_flag("--yes", recovery_options.yes);
    repair_summary->callback([&] {
        command_result = run_repair_summary_command(recovery_options, repair_generation);
    });

    auto* repair_config = repo->add_subcommand("repair-config", "Repair configuration replicas");
    repair_config->add_option("--repo", recovery_options.repository)
        ->default_val(recovery_options.repository);
    repair_config->add_option("--password-file", recovery_options.config.password_file);
    repair_config->add_flag("--json", recovery_options.config.json);
    repair_config->add_flag("--yes", recovery_options.yes);
    repair_config->callback([&] {
        command_result = run_repair_config_command(recovery_options);
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
