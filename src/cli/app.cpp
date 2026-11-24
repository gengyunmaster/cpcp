#include "cli/app.hpp"

#include "cli/config_command.hpp"
#include "cli/backup_command.hpp"
#include "cli/inspection_command.hpp"
#include "cli/key_command.hpp"
#include "cli/lifecycle_command.hpp"
#include "cli/probe_command.hpp"
#include "cli/recovery_command.hpp"
#include "cli/errors.hpp"
#include "platform/cancellation.hpp"

#include <CLI/CLI.hpp>

#include <charconv>
#include <chrono>
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
    add->add_option("--base", backup_options.base_generation, "Use an explicit base snapshot generation");
    add->add_flag("--allow-partial", backup_options.allow_partial, "Publish a partial snapshot when required entries fail");
    add->add_option("--unsupported", unsupported_policy, "Policy for unsupported entries: skip or fail")
        ->default_val(unsupported_policy)
        ->check(CLI::IsMember({"skip", "fail"}));
    add->add_option("--exclude", backup_options.exclude_patterns, "Exclude a root-relative glob with * and ?")
        ->expected(-1);
    add->add_option("--jobs", backup_options.jobs, "Compression workers (1-8)")
        ->default_val(backup_options.jobs)
        ->check(CLI::Range(1, 8));
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

    SessionCommandOptions session_options;
    const auto add_session_options = [&](CLI::App* command) {
        command->add_option("--repo", session_options.repository)->default_val(session_options.repository);
        command->add_option("--password-file", session_options.config.password_file);
        command->add_flag("--json", session_options.config.json);
    };
    auto* status = backup->add_subcommand("status", "List resumable backup sessions");
    add_session_options(status);
    status->callback([&] {
        command_result = run_backup_status_command(session_options);
    });

    auto* resume = backup->add_subcommand("resume", "Resume an interrupted backup session");
    std::string resume_session;
    application::ResumeOptions resume_options;
    std::vector<std::string> remap_roots;
    resume->add_option("session", resume_session)->required();
    resume->add_flag("--restart-files", resume_options.restart_files, "Reread source files instead of reusing file completions");
    resume->add_flag("--revalidate-all", resume_options.revalidate_all, "Revalidate every referenced chunk");
    resume->add_option("--jobs", resume_options.jobs, "Compression workers (1-8)")
        ->default_val(resume_options.jobs)
        ->check(CLI::Range(1, 8));
    resume->add_option("--remap-root", remap_roots, "Map <root-uuid>=<new-path>")->expected(-1);
    add_session_options(resume);
    resume->callback([&] {
        for (const auto& mapping : remap_roots) {
            const auto separator = mapping.find('=');
            if (separator == std::string::npos || separator == 0 || separator + 1 == mapping.size()) {
                command_result = report_error(domain::Error{
                    domain::ErrorCode::usage,
                    "--remap-root requires <root-uuid>=<new-path>",
                });
                return;
            }
            const auto root = mapping.substr(0, separator);
            if (!resume_options.remap_roots.emplace(root, mapping.substr(separator + 1)).second) {
                command_result = report_error(domain::Error{domain::ErrorCode::usage, "duplicate remapped root"});
                return;
            }
        }
        command_result = run_backup_resume_command(resume_session, resume_options, session_options);
    });

    auto* discard = backup->add_subcommand("discard", "Discard resumable session state");
    std::string discard_session;
    bool discard_yes = false;
    discard->add_option("session", discard_session)->required();
    discard->add_flag("--yes", discard_yes, "Confirm discarding session state");
    add_session_options(discard);
    discard->callback([&] {
        command_result = run_backup_discard_command(discard_session, discard_yes, session_options);
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

    auto* stats = repo->add_subcommand("stats", "Report repository storage statistics");
    add_inspection_options(stats);
    stats->callback([&] {
        command_result = run_repo_stats_command(inspection_options);
    });

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

    auto* diff = snapshot->add_subcommand("diff", "Compare two authenticated snapshots");
    std::uint64_t diff_left = 0;
    std::uint64_t diff_right = 0;
    diff->add_option("left", diff_left)->required();
    diff->add_option("right", diff_right)->required();
    add_inspection_options(diff);
    diff->add_flag("--ndjson", inspection_options.ndjson, "Stream newline-delimited JSON differences");
    diff->callback([&] {
        command_result = run_snapshot_diff_command(inspection_options, diff_left, diff_right);
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
    bool refresh_validation_cache = false;
    verify->add_flag("--deep", deep_verify, "Validate every referenced chunk");
    verify->add_flag("--refresh-validation-cache", refresh_validation_cache, "Record deep validation evidence for later backups");
    add_inspection_options(verify);
    verify->callback([&] {
        command_result = run_verify_command(inspection_options, deep_verify, refresh_validation_cache);
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

    auto* forget = snapshot->add_subcommand("forget", "Retire a snapshot into trash");
    std::uint64_t forget_generation = 0;
    forget->add_option("generation", forget_generation)->required();
    forget->add_option("--repo", recovery_options.repository)->default_val(recovery_options.repository);
    forget->add_option("--password-file", recovery_options.config.password_file);
    forget->add_flag("--json", recovery_options.config.json);
    forget->add_flag("--dry-run", recovery_options.dry_run);
    forget->add_flag("--yes", recovery_options.yes);
    forget->callback([&] {
        command_result = run_snapshot_forget_command(recovery_options, forget_generation);
    });

    std::int64_t grace_seconds = 86400;
    auto* purge_quarantine = repo->add_subcommand("purge-quarantine", "Delete expired quarantined objects");
    purge_quarantine->add_option("--grace-seconds", grace_seconds)->default_val(grace_seconds);
    purge_quarantine->add_option("--repo", recovery_options.repository)->default_val(recovery_options.repository);
    purge_quarantine->add_option("--password-file", recovery_options.config.password_file);
    purge_quarantine->add_flag("--json", recovery_options.config.json);
    purge_quarantine->add_flag("--dry-run", recovery_options.dry_run);
    purge_quarantine->add_flag("--yes", recovery_options.yes);
    purge_quarantine->callback([&] {
        command_result = run_purge_quarantine_command(recovery_options, std::chrono::seconds{grace_seconds});
    });

    auto* gc = repo->add_subcommand("gc", "Move unreachable objects to trash and expire old trash");
    gc->add_option("--grace-seconds", grace_seconds)->default_val(grace_seconds);
    gc->add_option("--repo", recovery_options.repository)->default_val(recovery_options.repository);
    gc->add_option("--password-file", recovery_options.config.password_file);
    gc->add_flag("--json", recovery_options.config.json);
    gc->add_flag("--dry-run", recovery_options.dry_run);
    gc->add_flag("--yes", recovery_options.yes);
    gc->callback([&] {
        command_result = run_gc_command(recovery_options, std::chrono::seconds{grace_seconds});
    });

    KeyCommandOptions key_options;
    const auto add_key_options = [&](CLI::App* command) {
        command->add_option("--repo", key_options.repository)->default_val(key_options.repository);
        command->add_option("--password-file", key_options.password_file);
        command->add_option("--new-password-file", key_options.new_password_file);
        command->add_flag("--json", key_options.json);
    };
    auto* passwd = repo->add_subcommand("passwd", "Replace the authenticated password slot");
    add_key_options(passwd);
    passwd->callback([&] {
        command_result = run_passwd_command(key_options);
    });

    auto* key = repo->add_subcommand("key", "Manage repository key slots");
    key->require_subcommand(1);
    auto* key_list = key->add_subcommand("list", "List key slots");
    add_key_options(key_list);
    key_list->callback([&] {
        command_result = run_key_list_command(key_options);
    });
    auto* key_add_password = key->add_subcommand("add-password", "Add another password slot");
    std::optional<std::string> added_slot_id;
    key_add_password->add_option("--slot-id", added_slot_id);
    add_key_options(key_add_password);
    key_add_password->callback([&] {
        command_result = run_key_add_password_command(key_options, added_slot_id);
    });
    auto* key_add_recovery = key->add_subcommand("add-recovery-key", "Add a high-entropy recovery key");
    bool show_recovery_key = false;
    key_add_recovery->add_flag("--show-key", show_recovery_key, "Display the new recovery key once");
    add_key_options(key_add_recovery);
    key_add_recovery->callback([&] {
        command_result = run_key_add_recovery_command(key_options, show_recovery_key);
    });
    auto* key_remove = key->add_subcommand("remove", "Remove a different key slot");
    std::string removed_slot_id;
    bool remove_confirmed = false;
    key_remove->add_option("slot", removed_slot_id)->required();
    key_remove->add_flag("--yes", remove_confirmed, "Confirm key slot removal");
    add_key_options(key_remove);
    key_remove->callback([&] {
        command_result = run_key_remove_command(key_options, removed_slot_id, remove_confirmed);
    });

    auto* rotate_epoch = repo->add_subcommand("rotate-epoch", "Invalidate prior validation evidence");
    add_key_options(rotate_epoch);
    rotate_epoch->callback([&] {
        command_result = run_rotate_epoch_command(key_options);
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
