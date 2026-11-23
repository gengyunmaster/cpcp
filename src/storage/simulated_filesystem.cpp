#include "storage/simulated_filesystem.hpp"

#include <algorithm>
#include <numeric>
#include <set>
#include <stdexcept>
#include <utility>

namespace cpcp::storage {

using domain::Error;
using domain::ErrorCode;

namespace {

template<typename T>
domain::Result<T> failure(ErrorCode code, std::string message) {
    return std::unexpected(Error{code, std::move(message)});
}

}

domain::Result<SimulatedFilesystem::ParsedPath> SimulatedFilesystem::parse_path(
    const std::filesystem::path& path
) const {
    const std::string input = path.generic_string();
    if (input.empty() || input.front() != '/') {
        return failure<ParsedPath>(ErrorCode::usage, "simulated paths must be absolute");
    }

    for (const auto& component : path) {
        if (component == "..") {
            return failure<ParsedPath>(ErrorCode::usage, "simulated paths cannot contain '..'");
        }
    }

    const std::filesystem::path normalized_path = path.lexically_normal();
    std::string normalized = normalized_path.generic_string();
    if (normalized.size() > 1 && normalized.ends_with('/')) {
        normalized.pop_back();
    }

    if (normalized == "/") {
        return ParsedPath{normalized, "/", ""};
    }

    std::string parent = normalized_path.parent_path().generic_string();
    if (parent.empty()) {
        parent = "/";
    }

    return ParsedPath{
        normalized,
        parent,
        normalized_path.filename().generic_string(),
    };
}

std::optional<SimulatedFilesystem::FailureRule> SimulatedFilesystem::next_failure(
    SimulatedOperation operation
) {
    const std::size_t occurrence = ++operation_counts_[operation];
    const auto rules = failures_.find(operation);
    if (rules != failures_.end()) {
        for (const auto& rule : rules->second) {
            if (rule.occurrence == occurrence) {
                return rule;
            }
        }
    }

    const auto probability = failure_probabilities_.find(operation);
    if (probability != failure_probabilities_.end()
        && std::generate_canonical<double, 64>(random_) < probability->second) {
        return FailureRule{ErrorCode::retryable_io, occurrence, static_cast<std::size_t>(-1)};
    }

    return std::nullopt;
}

domain::Result<void> SimulatedFilesystem::create_directories(
    const std::filesystem::path& path
) {
    const auto parsed = parse_path(path);
    if (!parsed) {
        return std::unexpected(parsed.error());
    }
    if (const auto failure = next_failure(SimulatedOperation::create_directory)) {
        return std::unexpected(Error{failure->code, "injected directory creation failure"});
    }

    std::filesystem::path current = "/";
    for (const auto& component : std::filesystem::path(parsed->normalized).relative_path()) {
        current /= component;
        directories_.try_emplace(current.generic_string());
    }
    return {};
}

std::optional<SimulatedFilesystem::NodeId> SimulatedFilesystem::find_node(
    const ParsedPath& path,
    bool durable
) const {
    const auto directory = directories_.find(path.parent);
    if (directory == directories_.end()) {
        return std::nullopt;
    }

    const auto& entries = durable
        ? directory->second.durable_entries
        : directory->second.volatile_entries;
    const auto entry = entries.find(path.name);
    if (entry == entries.end()) {
        return std::nullopt;
    }
    return entry->second;
}

domain::Result<void> SimulatedFilesystem::write_file(
    const std::filesystem::path& path,
    std::span<const std::byte> bytes
) {
    const auto parsed = parse_path(path);
    if (!parsed) {
        return std::unexpected(parsed.error());
    }
    if (!directories_.contains(parsed->parent)) {
        return failure<void>(ErrorCode::permanent_io, "parent directory does not exist");
    }

    const auto failure = next_failure(SimulatedOperation::write_file);
    const std::size_t count = failure
        ? std::min(
            failure->write_prefix == static_cast<std::size_t>(-1)
                ? std::size_t{0}
                : failure->write_prefix,
            bytes.size()
        )
        : bytes.size();

    auto existing = find_node(*parsed, false);
    NodeId node = existing.value_or(next_node_);
    if (!existing) {
        ++next_node_;
        nodes_.try_emplace(node);
    }

    const auto written = bytes.first(count);
    nodes_[node].volatile_bytes.assign(written.begin(), written.end());
    directories_[parsed->parent].volatile_entries[parsed->name] = node;

    if (failure) {
        return std::unexpected(Error{failure->code, "injected file write failure"});
    }
    return {};
}

domain::Result<SimulatedFilesystem::Bytes> SimulatedFilesystem::read_file(
    const std::filesystem::path& path
) {
    const auto parsed = parse_path(path);
    if (!parsed) {
        return std::unexpected(parsed.error());
    }
    if (const auto failure = next_failure(SimulatedOperation::read_file)) {
        return std::unexpected(Error{failure->code, "injected file read failure"});
    }

    const auto node = find_node(*parsed, false);
    if (!node) {
        return failure<Bytes>(ErrorCode::permanent_io, "file does not exist");
    }
    return nodes_.at(*node).volatile_bytes;
}

domain::Result<SimulatedFilesystem::Bytes> SimulatedFilesystem::durable_read(
    const std::filesystem::path& path
) const {
    const auto parsed = parse_path(path);
    if (!parsed) {
        return std::unexpected(parsed.error());
    }

    const auto node = find_node(*parsed, true);
    if (!node) {
        return failure<Bytes>(ErrorCode::permanent_io, "file does not exist");
    }
    return nodes_.at(*node).durable_bytes;
}

domain::Result<void> SimulatedFilesystem::sync_file(
    const std::filesystem::path& path
) {
    const auto parsed = parse_path(path);
    if (!parsed) {
        return std::unexpected(parsed.error());
    }
    if (const auto failure = next_failure(SimulatedOperation::sync_file)) {
        return std::unexpected(Error{failure->code, "injected file sync failure"});
    }

    const auto node = find_node(*parsed, false);
    if (!node) {
        return failure<void>(ErrorCode::permanent_io, "file does not exist");
    }
    pending_.push_back(FileSync{*node, nodes_.at(*node).volatile_bytes});
    return {};
}

domain::Result<void> SimulatedFilesystem::publish_no_replace(
    const std::filesystem::path& temporary,
    const std::filesystem::path& final
) {
    const auto source = parse_path(temporary);
    if (!source) {
        return std::unexpected(source.error());
    }
    const auto destination = parse_path(final);
    if (!destination) {
        return std::unexpected(destination.error());
    }
    if (const auto injected = next_failure(SimulatedOperation::publish)) {
        return std::unexpected(Error{injected->code, "injected publication failure"});
    }

    const auto node = find_node(*source, false);
    if (!node) {
        return failure<void>(ErrorCode::permanent_io, "temporary file does not exist");
    }
    if (find_node(*destination, false)) {
        return failure<void>(ErrorCode::conflict, "destination already exists");
    }
    if (!directories_.contains(destination->parent)) {
        return failure<void>(ErrorCode::permanent_io, "destination directory does not exist");
    }

    directories_[source->parent].volatile_entries.erase(source->name);
    directories_[destination->parent].volatile_entries[destination->name] = *node;
    return {};
}

domain::Result<void> SimulatedFilesystem::sync_directory(
    const std::filesystem::path& path
) {
    const auto parsed = parse_path(path);
    if (!parsed) {
        return std::unexpected(parsed.error());
    }
    if (const auto failure = next_failure(SimulatedOperation::sync_directory)) {
        return std::unexpected(Error{failure->code, "injected directory sync failure"});
    }
    if (!directories_.contains(parsed->normalized)) {
        return failure<void>(ErrorCode::permanent_io, "directory does not exist");
    }

    pending_.push_back(DirectorySync{
        parsed->normalized,
        directories_.at(parsed->normalized).volatile_entries,
    });
    return {};
}

domain::Result<void> SimulatedFilesystem::remove_file(
    const std::filesystem::path& path
) {
    const auto parsed = parse_path(path);
    if (!parsed) {
        return std::unexpected(parsed.error());
    }
    if (const auto failure = next_failure(SimulatedOperation::remove_file)) {
        return std::unexpected(Error{failure->code, "injected remove failure"});
    }

    if (!find_node(*parsed, false)) {
        return failure<void>(ErrorCode::permanent_io, "file does not exist");
    }
    directories_[parsed->parent].volatile_entries.erase(parsed->name);
    return {};
}

void SimulatedFilesystem::inject_failure(
    SimulatedOperation operation,
    ErrorCode code,
    std::size_t occurrence,
    std::size_t write_prefix
) {
    failures_[operation].push_back(FailureRule{code, occurrence, write_prefix});
}

void SimulatedFilesystem::enable_random_failures(
    SimulatedOperation operation,
    double probability,
    std::uint64_t seed
) {
    if (probability < 0.0 || probability > 1.0) {
        throw std::invalid_argument("failure probability must be between zero and one");
    }
    random_.seed(seed);
    failure_probabilities_[operation] = probability;
}

void SimulatedFilesystem::apply_pending(const PendingOperation& operation) {
    if (const auto* file = std::get_if<FileSync>(&operation)) {
        nodes_[file->node].durable_bytes = file->bytes;
        return;
    }

    const auto& directory = std::get<DirectorySync>(operation);
    directories_[directory.directory].durable_entries = directory.entries;
}

void SimulatedFilesystem::reset_to_durable() {
    for (auto& entry : nodes_) {
        entry.second.volatile_bytes = entry.second.durable_bytes;
    }
    for (auto& entry : directories_) {
        entry.second.volatile_entries = entry.second.durable_entries;
    }
    pending_.clear();
}

domain::Result<void> SimulatedFilesystem::crash(
    std::span<const std::size_t> persistence_order
) {
    std::set<std::size_t> unique;
    for (const std::size_t index : persistence_order) {
        if (index >= pending_.size() || !unique.insert(index).second) {
            return failure<void>(ErrorCode::usage, "invalid persistence operation index");
        }
    }

    for (const std::size_t index : persistence_order) {
        apply_pending(pending_[index]);
    }
    reset_to_durable();
    return {};
}

domain::Result<void> SimulatedFilesystem::clean_shutdown() {
    std::vector<std::size_t> order(pending_.size());
    std::iota(order.begin(), order.end(), std::size_t{0});
    return crash(order);
}

bool SimulatedFilesystem::volatile_exists(const std::filesystem::path& path) const {
    const auto parsed = parse_path(path);
    return parsed && find_node(*parsed, false).has_value();
}

bool SimulatedFilesystem::durable_exists(const std::filesystem::path& path) const {
    const auto parsed = parse_path(path);
    return parsed && find_node(*parsed, true).has_value();
}

std::size_t SimulatedFilesystem::pending_operation_count() const {
    return pending_.size();
}

}
