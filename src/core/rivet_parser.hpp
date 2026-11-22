#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace riftloader {

struct RivetNode {
    std::string name;
    std::string type; // "root", "obj", "array", "set", "str", "num", "float", "bool", "null"
    std::string raw_value;
    bool is_parent = false;

    // Preserves insertion order for iteration and array indexing.
    std::vector<std::unique_ptr<RivetNode>> ordered_children;
    std::unordered_map<std::string, RivetNode*> child_map;

    RivetNode* AddChild(std::unique_ptr<RivetNode> child);
    const RivetNode* Get(const std::string& dot_path) const;

    std::string AsString(const std::string& fallback = "") const;
    bool AsBool(bool fallback = false) const;
    std::optional<int64_t> AsInt() const;
    std::optional<uint64_t> AsUInt() const;
    std::optional<double> AsDouble() const;

    std::string GetString(const std::string& dot_path, const std::string& fallback = "") const;
    bool GetBool(const std::string& dot_path, bool fallback = false) const;
    std::optional<int64_t> GetInt(const std::string& dot_path) const;
    std::optional<uint64_t> GetUInt(const std::string& dot_path) const;
};

struct RivetParseResult {
    std::unique_ptr<RivetNode> root;
    std::string error;
    size_t error_line = 0;

    bool Ok() const { return root != nullptr && error.empty(); }
};

class RivetParser {
public:
    static RivetParseResult Parse(const std::string& text);
    static RivetParseResult ParseFile(const std::string& path);
};

} // namespace riftloader
