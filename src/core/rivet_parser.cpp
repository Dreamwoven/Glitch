#include "rivet_parser.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <sstream>

namespace riftloader {

namespace {

std::string Trim(const std::string& s) {
    size_t a = 0;
    while (a < s.size() && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) ++a;
    size_t b = s.size();
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) --b;
    return s.substr(a, b - a);
}

std::string RTrim(const std::string& s) {
    size_t b = s.size();
    while (b > 0 && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) --b;
    return s.substr(0, b);
}

std::string ToLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool IsAllDigits(const std::string& s) {
    if (s.empty()) return false;
    for (unsigned char c : s) {
        if (!std::isdigit(c)) return false;
    }
    return true;
}

bool TryParseInt64(const std::string& s, int64_t& out) {
    std::string t = Trim(s);
    if (t.empty()) return false;
    char* end = nullptr;
    errno = 0;
    long long v = std::strtoll(t.c_str(), &end, 0);
    if (errno != 0 || end != t.c_str() + t.size()) return false;
    out = static_cast<int64_t>(v);
    return true;
}

bool TryParseUInt64(const std::string& s, uint64_t& out) {
    std::string t = Trim(s);
    if (t.empty() || t[0] == '-') return false;
    char* end = nullptr;
    errno = 0;
    unsigned long long v = std::strtoull(t.c_str(), &end, 0);
    if (errno != 0 || end != t.c_str() + t.size()) return false;
    out = static_cast<uint64_t>(v);
    return true;
}

bool TryParseDouble(const std::string& s, double& out) {
    std::string t = Trim(s);
    if (t.empty()) return false;
    char* end = nullptr;
    errno = 0;
    double v = std::strtod(t.c_str(), &end);
    if (errno != 0 || end != t.c_str() + t.size()) return false;
    out = v;
    return true;
}

std::string UnescapeQuoted(const std::string& input) {
    std::string s = Trim(input);
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"') {
        std::string out;
        out.reserve(s.size() - 2);
        for (size_t i = 1; i + 1 < s.size(); ++i) {
            if (s[i] == '\\' && i + 2 < s.size()) {
                char next = s[++i];
                switch (next) {
                    case 'n':  out.push_back('\n'); break;
                    case 't':  out.push_back('\t'); break;
                    case 'r':  out.push_back('\r'); break;
                    case '"':  out.push_back('"'); break;
                    case '\\': out.push_back('\\'); break;
                    default:   out.push_back('\\'); out.push_back(next); break;
                }
            } else {
                out.push_back(s[i]);
            }
        }
        return out;
    }
    return s;
}

std::vector<std::string> TokenizeLine(const std::string& body) {
    std::vector<std::string> tokens;
    std::string curr;
    bool in_quote = false;
    bool escape = false;

    for (char ch : body) {
        if (escape) {
            curr.push_back(ch);
            escape = false;
            continue;
        }
        if (ch == '\\' && in_quote) {
            curr.push_back(ch);
            escape = true;
            continue;
        }
        if (ch == '"') {
            in_quote = !in_quote;
            curr.push_back(ch);
            continue;
        }
        if ((ch == ' ' || ch == '\t') && !in_quote) {
            if (!curr.empty()) {
                tokens.push_back(std::move(curr));
                curr.clear();
            }
        } else {
            curr.push_back(ch);
        }
    }
    if (!curr.empty()) {
        tokens.push_back(std::move(curr));
    }
    return tokens;
}

struct ParsedToken {
    std::string name;
    std::string type;
    std::string value;
};

bool ParseTokenContent(const std::string& clean_content, bool is_parent,
                       ParsedToken& out, std::string& err) {
    std::string body = Trim(clean_content);
    if (body.empty()) {
        err = "Empty token content";
        return false;
    }

    // 1. Parent token (ended with ';')
    if (is_parent) {
        size_t dot = body.find('.');
        if (dot == std::string::npos) {
            out = {body, "obj", ""};
            return true;
        }
        std::string name = body.substr(0, dot);
        std::string rem = Trim(body.substr(dot + 1));
        if (rem.empty() || rem == "obj") {
            out = {name, "obj", ""};
            return true;
        }
        if (rem == "arr" || rem == "array" || rem == "a") {
            out = {name, "array", ""};
            return true;
        }
        if (rem == "set" || rem == "s") {
            out = {name, "set", ""};
            return true;
        }
        if (rem.size() >= 2 && rem.front() == '"' && rem.back() == '"') {
            out = {name, "str", UnescapeQuoted(rem)};
            return true;
        }
        size_t dot2 = rem.find('.');
        if (dot2 != std::string::npos) {
            out = {name, rem.substr(0, dot2), UnescapeQuoted(rem.substr(dot2 + 1))};
            return true;
        }
        out = {name, rem, ""};
        return true;
    }

    // 2a. Bare quoted string in collection
    if (body.size() >= 2 && body.front() == '"' && body.back() == '"') {
        out = {"", "str", UnescapeQuoted(body)};
        return true;
    }

    // 2b. Colon herald for numbers (outside quotes): name:123, name.num:123, :123
    size_t colon = std::string::npos;
    bool in_q = false;
    for (size_t i = 0; i < body.size(); ++i) {
        if (body[i] == '"' && (i == 0 || body[i - 1] != '\\')) {
            in_q = !in_q;
        } else if (body[i] == ':' && !in_q) {
            colon = i;
            break;
        }
    }

    if (colon != std::string::npos) {
        std::string left = Trim(body.substr(0, colon));
        std::string right = Trim(body.substr(colon + 1));
        std::string name = left;
        std::string type_tag;
        size_t dot = left.find('.');
        if (dot != std::string::npos) {
            name = Trim(left.substr(0, dot));
            type_tag = Trim(left.substr(dot + 1));
        }

        int64_t iv = 0;
        double dv = 0.0;
        if (!type_tag.empty()) {
            out = {name, type_tag, UnescapeQuoted(right)};
        } else if (TryParseInt64(right, iv)) {
            out = {name, "num", right};
        } else if (TryParseDouble(right, dv)) {
            out = {name, "float", right};
        } else {
            out = {name, "str", UnescapeQuoted(right)};
        }
        return true;
    }

    // 2c. Boundary quote without preceding dot (e.g. name"Hi", 0.str"Hi")
    size_t qpos = body.find('"');
    if (qpos != std::string::npos && qpos > 0 && body[qpos - 1] != '.') {
        std::string left = Trim(body.substr(0, qpos));
        std::string right = Trim(body.substr(qpos));
        size_t dot = left.find('.');
        if (dot != std::string::npos) {
            out = {Trim(left.substr(0, dot)), Trim(left.substr(dot + 1)), UnescapeQuoted(right)};
        } else {
            out = {left, "str", UnescapeQuoted(right)};
        }
        return true;
    }

    // 2d. Standard dot-delimited leaf syntax: name."val", name.true, ."val", name.type.val
    size_t dot = body.find('.');
    if (dot == std::string::npos) {
        err = "Invalid leaf syntax: expected NAME.INPUT, NAME:NUMBER, or NAME.TYPE.INPUT";
        return false;
    }

    std::string name = body.substr(0, dot);
    std::string rem = Trim(body.substr(dot + 1));

    if (rem.size() >= 2 && rem.front() == '"' && rem.back() == '"') {
        out = {name, "str", UnescapeQuoted(rem)};
        return true;
    }

    std::string low = ToLower(rem);
    if (low == "true" || low == "false") {
        out = {name, "bool", low};
        return true;
    }
    if (low == "null" || low == "none") {
        out = {name, "null", ""};
        return true;
    }

    int64_t iv = 0;
    if (TryParseInt64(rem, iv)) {
        out = {name, "num", rem};
        return true;
    }
    double dv = 0.0;
    if (TryParseDouble(rem, dv)) {
        out = {name, "float", rem};
        return true;
    }

    size_t dot2 = rem.find('.');
    if (dot2 != std::string::npos) {
        out = {name, rem.substr(0, dot2), UnescapeQuoted(rem.substr(dot2 + 1))};
        return true;
    }

    out = {name, "str", rem};
    return true;
}

} // namespace

RivetNode* RivetNode::AddChild(std::unique_ptr<RivetNode> child) {
    if (!child) return nullptr;
    if (child->name.empty()) {
        // Auto-assign numeric index for unnamed elements (arrays/sets)
        child->name = std::to_string(ordered_children.size());
    }
    RivetNode* raw = child.get();
    child_map[raw->name] = raw;
    ordered_children.push_back(std::move(child));
    return raw;
}

const RivetNode* RivetNode::Get(const std::string& dot_path) const {
    if (dot_path.empty()) return this;
    const RivetNode* curr = this;
    size_t start = 0;
    while (start <= dot_path.size()) {
        size_t dot = dot_path.find('.', start);
        std::string part = (dot == std::string::npos)
            ? dot_path.substr(start)
            : dot_path.substr(start, dot - start);
        auto it = curr->child_map.find(part);
        if (it == curr->child_map.end()) return nullptr;
        curr = it->second;
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    return curr;
}

std::string RivetNode::AsString(const std::string& fallback) const {
    if (type == "null") return fallback;
    return raw_value;
}

bool RivetNode::AsBool(bool fallback) const {
    std::string low = ToLower(Trim(raw_value));
    if (low == "true" || low == "1" || low == "yes") return true;
    if (low == "false" || low == "0" || low == "no") return false;
    return fallback;
}

std::optional<int64_t> RivetNode::AsInt() const {
    int64_t v = 0;
    if (TryParseInt64(raw_value, v)) return v;
    return std::nullopt;
}

std::optional<uint64_t> RivetNode::AsUInt() const {
    uint64_t v = 0;
    if (TryParseUInt64(raw_value, v)) return v;
    return std::nullopt;
}

std::optional<double> RivetNode::AsDouble() const {
    double v = 0.0;
    if (TryParseDouble(raw_value, v)) return v;
    return std::nullopt;
}

std::string RivetNode::GetString(const std::string& dot_path, const std::string& fallback) const {
    const RivetNode* n = Get(dot_path);
    return n ? n->AsString(fallback) : fallback;
}

bool RivetNode::GetBool(const std::string& dot_path, bool fallback) const {
    const RivetNode* n = Get(dot_path);
    return n ? n->AsBool(fallback) : fallback;
}

std::optional<int64_t> RivetNode::GetInt(const std::string& dot_path) const {
    const RivetNode* n = Get(dot_path);
    return n ? n->AsInt() : std::nullopt;
}

std::optional<uint64_t> RivetNode::GetUInt(const std::string& dot_path) const {
    const RivetNode* n = Get(dot_path);
    return n ? n->AsUInt() : std::nullopt;
}

RivetParseResult RivetParser::Parse(const std::string& text) {
    RivetParseResult res;
    auto root = std::make_unique<RivetNode>();
    root->name = "__root__";
    root->type = "root";
    root->is_parent = true;

    struct StackEntry {
        int depth;
        RivetNode* node;
    };
    std::vector<StackEntry> stack;
    stack.push_back({-1, root.get()});

    RivetNode* last_node = nullptr;
    int last_depth = -1;
    int space_tab_size = 0;

    std::istringstream iss(text);
    std::string raw_line;
    size_t line_num = 0;

    while (std::getline(iss, raw_line)) {
        ++line_num;
        // Strip UTF-8 BOM on line 1 if present
        if (line_num == 1 && raw_line.size() >= 3 &&
            static_cast<unsigned char>(raw_line[0]) == 0xEF &&
            static_cast<unsigned char>(raw_line[1]) == 0xBB &&
            static_cast<unsigned char>(raw_line[2]) == 0xBF) {
            raw_line.erase(0, 3);
        }

        std::string line = RTrim(raw_line);
        std::string stripped = Trim(line);
        if (stripped.empty() || stripped.rfind("//", 0) == 0 || stripped[0] == '#') {
            continue;
        }

        size_t indent_len = 0;
        while (indent_len < line.size() && (line[indent_len] == '\t' || line[indent_len] == ' ')) {
            ++indent_len;
        }
        std::string indent_str = line.substr(0, indent_len);
        std::string line_body = line.substr(indent_len);

        // Calculate indentation depth
        int line_depth = 0;
        if (!indent_str.empty()) {
            bool has_tab = indent_str.find('\t') != std::string::npos;
            bool has_space = indent_str.find(' ') != std::string::npos;
            if (has_tab && has_space) {
                res.error = "Mixed tabs and spaces in indentation";
                res.error_line = line_num;
                return res;
            }
            if (has_tab) {
                line_depth = static_cast<int>(indent_str.size());
            } else {
                int spaces = static_cast<int>(indent_str.size());
                if (space_tab_size == 0) {
                    space_tab_size = (spaces % 4 == 0) ? 4 : 2;
                }
                if (spaces % space_tab_size != 0) {
                    res.error = "Inconsistent space indentation";
                    res.error_line = line_num;
                    return res;
                }
                line_depth = spaces / space_tab_size;
            }
        }

        auto tokens = TokenizeLine(line_body);
        if (tokens.empty()) continue;

        for (size_t tidx = 0; tidx < tokens.size(); ++tidx) {
            const std::string& tok = tokens[tidx];

            // Inline comment starting outside quotes
            if (tok.rfind("//", 0) == 0 || tok[0] == '#') {
                break;
            }

            // Ascend / jump operator (^, |, ^2, |3)
            if ((tok[0] == '^' || tok[0] == '|') &&
                (tok.size() == 1 || IsAllDigits(tok.substr(1)))) {
                int count = (tok.size() == 1) ? 1 : std::atoi(tok.substr(1).c_str());
                for (int i = 0; i < count && stack.size() > 1; ++i) {
                    stack.pop_back();
                }
                last_depth = stack.back().depth;
                last_node = stack.back().node;
                continue;
            }

            bool is_parent = !tok.empty() && tok.back() == ';';
            std::string clean = is_parent ? RTrim(tok.substr(0, tok.size() - 1)) : tok;

            int depth = 0;
            if (tidx == 0) {
                depth = line_depth;
                if (!indent_str.empty()) {
                    if (last_node != nullptr && depth > last_depth) {
                        if (!last_node->is_parent) {
                            res.error = "Node '" + last_node->name + "' is not a parent (missing ';')";
                            res.error_line = line_num;
                            return res;
                        }
                        if (depth > last_depth + 1) {
                            res.error = "Unexpected indentation jump";
                            res.error_line = line_num;
                            return res;
                        }
                    }
                    while (!stack.empty() && stack.back().depth >= depth) {
                        stack.pop_back();
                    }
                } else {
                    while (!stack.empty() && stack.back().depth >= 0) {
                        stack.pop_back();
                    }
                    depth = 0;
                }
            } else {
                depth = stack.empty() ? 0 : stack.back().depth + 1;
            }

            if (stack.empty()) {
                res.error = "Indentation error: no parent found";
                res.error_line = line_num;
                return res;
            }

            RivetNode* parent = stack.back().node;
            if (parent != root.get() && !parent->is_parent) {
                res.error = "Node '" + parent->name + "' cannot have children (missing ';')";
                res.error_line = line_num;
                return res;
            }

            ParsedToken parsed;
            std::string perr;
            if (!ParseTokenContent(clean, is_parent, parsed, perr)) {
                res.error = perr;
                res.error_line = line_num;
                return res;
            }

            auto node = std::make_unique<RivetNode>();
            node->name = std::move(parsed.name);
            node->type = std::move(parsed.type);
            node->raw_value = std::move(parsed.value);
            node->is_parent = is_parent;

            RivetNode* raw = parent->AddChild(std::move(node));
            if (is_parent) {
                stack.push_back({depth, raw});
            }
            last_node = raw;
            last_depth = depth;
        }
    }

    res.root = std::move(root);
    return res;
}

RivetParseResult RivetParser::ParseFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        RivetParseResult res;
        res.error = "Failed to open file: " + path;
        return res;
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    return Parse(ss.str());
}

} // namespace riftloader
