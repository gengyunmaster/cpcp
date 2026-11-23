#include "domain/strict_json.hpp"

#include <nlohmann/json.hpp>

#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace cpcp::domain {

namespace {

class Validator : public nlohmann::json_sax<nlohmann::json> {
public:
    explicit Validator(const JsonLimits& limits) : limits_(limits) {
    }

    bool null() override { return true; }
    bool boolean(bool) override { return true; }
    bool number_integer(number_integer_t) override { return true; }
    bool number_unsigned(number_unsigned_t) override { return true; }
    bool number_float(number_float_t, const string_t&) override { return true; }

    bool string(string_t& value) override {
        return value.size() <= limits_.string;
    }

    bool binary(binary_t& value) override {
        return value.size() <= limits_.string;
    }

    bool start_object(std::size_t) override {
        if (++depth_ > limits_.depth) {
            return false;
        }
        keys_.emplace_back();
        return true;
    }

    bool end_object() override {
        if (depth_ > 0) {
            --depth_;
        }
        if (!keys_.empty()) {
            keys_.pop_back();
        }
        return true;
    }

    bool start_array(std::size_t) override {
        return ++depth_ <= limits_.depth;
    }

    bool end_array() override {
        if (depth_ > 0) {
            --depth_;
        }
        return true;
    }

    bool key(string_t& value) override {
        if (keys_.empty() || value.size() > limits_.string) {
            return false;
        }
        return keys_.back().insert(value).second;
    }

    bool parse_error(
        std::size_t position,
        const std::string& last_token,
        const nlohmann::json::exception& exception
    ) override {
        position_ = position;
        token_ = last_token;
        message_ = exception.what();
        return false;
    }

    std::size_t position_ = 0;
    std::string token_;
    std::string message_;

private:
    JsonLimits limits_;
    std::size_t depth_ = 0;
    std::vector<std::unordered_set<std::string>> keys_;
};

}

Result<nlohmann::json> parse_bounded_json(
    std::span<const std::byte> input,
    const JsonLimits& limits
) {
    if (input.size() > limits.bytes) {
        return fail<nlohmann::json>(ErrorCode::integrity, "JSON input exceeds the size limit");
    }

    Validator validator(limits);
    const std::string text{
        reinterpret_cast<const char*>(input.data()),
        input.size(),
    };
    if (!nlohmann::json::sax_parse(text, &validator)) {
        return fail<nlohmann::json>(
            ErrorCode::integrity,
            "invalid, nested, or duplicate-key JSON: " + validator.message_
        );
    }

    try {
        return nlohmann::json::parse(text);
    } catch (const nlohmann::json::exception& error) {
        return fail<nlohmann::json>(ErrorCode::integrity, error.what());
    }
}

}
