#pragma once
#include <string>
#include <utility>
#include <vector>

namespace minijson {

struct Value {
    enum class Type { Null, Bool, Num, Str, Arr, Obj };
    Type type = Type::Null;
    bool b = false;
    double num = 0.0;
    std::string str;
    std::vector<Value> arr;
    std::vector<std::pair<std::string, Value>> obj;

    const Value* find(const std::string& key) const {
        if (type != Type::Obj) return nullptr;
        for (const auto& kv : obj)
            if (kv.first == key) return &kv.second;
        return nullptr;
    }
    const Value* at(size_t i) const {
        return (type == Type::Arr && i < arr.size()) ? &arr[i] : nullptr;
    }
    std::string str_or(const std::string& def = std::string()) const {
        return type == Type::Str ? str : def;
    }
    double num_or(double def = 0.0) const { return type == Type::Num ? num : def; }
    size_t size() const {
        if (type == Type::Arr) return arr.size();
        if (type == Type::Obj) return obj.size();
        return 0;
    }
};

// Locates and parses the first complete top-level JSON object in `text`,
// tolerating surrounding prose and ``` fences that chat models emit even when
// instructed not to. Returns false and fills *err on failure.
bool parse_first_object(const std::string& text, Value* out, std::string* err,
                        size_t max_bytes = 1048576);

// Same, for a bare top-level array.
bool parse_first_array(const std::string& text, Value* out, std::string* err,
                       size_t max_bytes = 1048576);

std::string escape(const std::string& s);

} // namespace minijson
