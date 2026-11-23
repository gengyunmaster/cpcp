#pragma once

#include "domain/result.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace cpcp::storage {

enum class SimulatedOperation {
    create_directory,
    write_file,
    read_file,
    sync_file,
    publish,
    sync_directory,
    remove_file,
};

class SimulatedFilesystem {
public:
    using Bytes = std::vector<std::byte>;

    domain::Result<void> create_directories(const std::filesystem::path& path);
    domain::Result<void> write_file(
        const std::filesystem::path& path,
        std::span<const std::byte> bytes
    );
    domain::Result<Bytes> read_file(const std::filesystem::path& path);
    domain::Result<void> sync_file(const std::filesystem::path& path);
    domain::Result<void> publish_no_replace(
        const std::filesystem::path& temporary,
        const std::filesystem::path& final
    );
    domain::Result<void> sync_directory(const std::filesystem::path& path);
    domain::Result<void> remove_file(const std::filesystem::path& path);

    void inject_failure(
        SimulatedOperation operation,
        domain::ErrorCode code,
        std::size_t occurrence = 1,
        std::size_t write_prefix = static_cast<std::size_t>(-1)
    );
    void enable_random_failures(
        SimulatedOperation operation,
        double probability,
        std::uint64_t seed
    );

    domain::Result<void> crash(std::span<const std::size_t> persistence_order = {});
    domain::Result<void> clean_shutdown();

    bool volatile_exists(const std::filesystem::path& path) const;
    bool durable_exists(const std::filesystem::path& path) const;
    domain::Result<Bytes> durable_read(const std::filesystem::path& path) const;
    std::size_t pending_operation_count() const;

private:
    using NodeId = std::uint64_t;

    struct Node {
        Bytes volatile_bytes;
        Bytes durable_bytes;
    };

    struct Directory {
        std::map<std::string, NodeId> volatile_entries;
        std::map<std::string, NodeId> durable_entries;
    };

    struct FileSync {
        NodeId node;
        Bytes bytes;
    };

    struct DirectorySync {
        std::string directory;
        std::map<std::string, NodeId> entries;
    };

    using PendingOperation = std::variant<FileSync, DirectorySync>;

    struct FailureRule {
        domain::ErrorCode code;
        std::size_t occurrence;
        std::size_t write_prefix;
    };

    struct ParsedPath {
        std::string normalized;
        std::string parent;
        std::string name;
    };

    domain::Result<ParsedPath> parse_path(const std::filesystem::path& path) const;
    std::optional<NodeId> find_node(
        const ParsedPath& path,
        bool durable
    ) const;
    std::optional<FailureRule> next_failure(SimulatedOperation operation);
    void reset_to_durable();
    void apply_pending(const PendingOperation& operation);

    std::map<std::string, Directory> directories_{{"/", {}}};
    std::map<NodeId, Node> nodes_;
    std::vector<PendingOperation> pending_;
    std::map<SimulatedOperation, std::vector<FailureRule>> failures_;
    std::map<SimulatedOperation, std::size_t> operation_counts_;
    std::map<SimulatedOperation, double> failure_probabilities_;
    std::mt19937_64 random_;
    NodeId next_node_ = 1;
};

}
