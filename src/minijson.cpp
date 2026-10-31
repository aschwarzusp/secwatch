#include "minijson.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace minijson {
namespace {

void utf8_append(std::string& out, unsigned cp) {
    if (cp < 0x80) {
        out += (char)cp;
    } else if (cp < 0x800) {
        out += (char)(0xC0 | (cp >> 6));
        out += (char)(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
        out += (char)(0xE0 | (cp >> 12));
        out += (char)(0x80 | ((cp >> 6) & 0x3F));
        out += (char)(0x80 | (cp & 0x3F));
    } else {
        out += (char)(0xF0 | (cp >> 18));
        out += (char)(0x80 | ((cp >> 12) & 0x3F));
        out += (char)(0x80 | ((cp >> 6) & 0x3F));
        out += (char)(0x80 | (cp & 0x3F));
    }
}

struct Parser {
    const std::string& s;
    size_t i = 0;
    int depth = 0;
    std::string err;

    explicit Parser(const std::string& src) : s(src) {}

    void ws() {
        while (i < s.size()) {
            char c = s[i];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') ++i;
            else break;
        }
    }

    bool fail(const std::string& m) {
        if (err.empty()) err = m + " at byte " + std::to_string(i);
        return false;
    }

    bool lit(const char* word) {
        size_t n = std::strlen(word);
        if (s.compare(i, n, word) != 0) return false;
        i += n;
        return true;
    }

    bool hex4(unsigned& out) {
        if (i + 4 > s.size()) return fail("truncated \\u escape");
        unsigned v = 0;
        for (int k = 0; k < 4; ++k) {
            char c = s[i + k];
            v <<= 4;
            if (c >= '0' && c <= '9')      v |= (unsigned)(c - '0');
            else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v |= (unsigned)(c - 'A' + 10);
            else return fail("bad hex digit in \\u escape");
        }
        i += 4;
        out = v;
        return true;
    }

    bool parse_string(std::string& out) {
        if (i >= s.size() || s[i] != '"') return fail("expected string");
        ++i;
        while (i < s.size()) {
            unsigned char c = (unsigned char)s[i];
            if (c == '"') { ++i; return true; }
            if (c == '\\') {
                ++i;
                if (i >= s.size()) return fail("truncated escape");
                char e = s[i++];
                switch (e) {
                    case '"':  out += '"';  break;
                    case '\\': out += '\\'; break;
                    case '/':  out += '/';  break;
                    case 'b':  out += '\b'; break;
                    case 'f':  out += '\f'; break;
                    case 'n':  out += '\n'; break;
                    case 'r':  out += '\r'; break;
                    case 't':  out += '\t'; break;
                    case 'u': {
                        unsigned cp = 0;
                        if (!hex4(cp)) return false;
                        if (cp >= 0xD800 && cp <= 0xDBFF) {
                            if (i + 1 < s.size() && s[i] == '\\' && s[i + 1] == 'u') {
                                i += 2;
                                unsigned lo = 0;
                                if (!hex4(lo)) return false;
                                if (lo >= 0xDC00 && lo <= 0xDFFF)
                                    utf8_append(out, 0x10000 +
                                                     ((cp - 0xD800) << 10) +
                                                     (lo - 0xDC00));
                                else
                                    utf8_append(out, 0xFFFD);
                            } else {
                                utf8_append(out, 0xFFFD);
                            }
                        } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                            utf8_append(out, 0xFFFD);
                        } else {
                            utf8_append(out, cp);
                        }
                        break;
                    }
                    default: return fail("unsupported escape");
                }
            } else if (c < 0x20) {
                return fail("raw control character in string");
            } else {
                out += (char)c;
                ++i;
            }
        }
        return fail("unterminated string");
    }

    bool parse_number(Value& v) {
        if (i >= s.size()) return fail("expected number");
        char first = s[i];
        if (first != '-' && !(first >= '0' && first <= '9'))
            return fail("invalid number");
        const char* start = s.c_str() + i;
        char* end = nullptr;
        double d = std::strtod(start, &end);
        if (end == start) return fail("invalid number");
        v.type = Value::Type::Num;
        v.num = d;
        i += (size_t)(end - start);
        return true;
    }

    bool parse_array(Value& v) {
        v.type = Value::Type::Arr;
        ++i;
        if (++depth > 64) return fail("nesting too deep");
        ws();
        if (i < s.size() && s[i] == ']') { ++i; --depth; return true; }
        while (true) {
            Value child;
            if (!parse_value(child)) return false;
            v.arr.push_back(std::move(child));
            ws();
            if (i >= s.size()) return fail("unterminated array");
            if (s[i] == ',') { ++i; ws(); continue; }
            if (s[i] == ']') { ++i; --depth; return true; }
            return fail("expected ',' or ']'");
        }
    }

    bool parse_object(Value& v) {
        v.type = Value::Type::Obj;
        ++i;
        if (++depth > 64) return fail("nesting too deep");
        ws();
        if (i < s.size() && s[i] == '}') { ++i; --depth; return true; }
        while (true) {
            ws();
            std::string key;
            if (!parse_string(key)) return false;
            ws();
            if (i >= s.size() || s[i] != ':') return fail("expected ':'");
            ++i;
            Value child;
            if (!parse_value(child)) return false;
            v.obj.emplace_back(std::move(key), std::move(child));
            ws();
            if (i >= s.size()) return fail("unterminated object");
            if (s[i] == ',') { ++i; continue; }
            if (s[i] == '}') { ++i; --depth; return true; }
            return fail("expected ',' or '}'");
        }
    }

    bool parse_value(Value& v) {
        ws();
        if (i >= s.size()) return fail("unexpected end of input");
        char c = s[i];
        if (c == '{') return parse_object(v);
        if (c == '[') return parse_array(v);
        if (c == '"') { v.type = Value::Type::Str; return parse_string(v.str); }
        if (c == 't') {
            if (!lit("true")) return fail("bad literal");
            v.type = Value::Type::Bool; v.b = true; return true;
        }
        if (c == 'f') {
            if (!lit("false")) return fail("bad literal");
            v.type = Value::Type::Bool; v.b = false; return true;
        }
        if (c == 'n') {
            if (!lit("null")) return fail("bad literal");
            v.type = Value::Type::Null; return true;
        }
        return parse_number(v);
    }
};

// Byte range of the first balanced bracket pair, skipping brackets that occur
// inside string literals.
bool first_balanced_span(const std::string& t, char open, char close,
                         size_t& begin, size_t& end) {
    size_t start = t.find(open);
    if (start == std::string::npos) return false;
    int depth = 0;
    bool in_str = false;
    for (size_t i = start; i < t.size(); ++i) {
        char c = t[i];
        if (in_str) {
            if (c == '\\') { ++i; continue; }
            if (c == '"') in_str = false;
            continue;
        }
        if (c == '"') { in_str = true; continue; }
        if (c == open) ++depth;
        else if (c == close) {
            if (--depth == 0) { begin = start; end = i + 1; return true; }
        }
    }
    return false;
}

bool parse_span(const std::string& text, char open, char close, Value* out,
                std::string* err, size_t max_bytes) {
    if (!out) return false;
    if (text.size() > max_bytes) {
        if (err) *err = "input exceeds max_bytes";
        return false;
    }
    size_t b = 0, e = 0;
    if (!first_balanced_span(text, open, close, b, e)) {
        if (err) *err = std::string("no JSON ") + (open == '{' ? "object" : "array") +
                        " found in model output";
        return false;
    }
    std::string slice = text.substr(b, e - b);
    Parser p(slice);
    Value v;
    if (!p.parse_value(v)) {
        if (err) *err = p.err;
        return false;
    }
    p.ws();
    if (p.i != slice.size()) {
        if (err) *err = "trailing data after JSON value";
        return false;
    }
    *out = std::move(v);
    return true;
}

} // namespace

bool parse_first_object(const std::string& text, Value* out, std::string* err,
                        size_t max_bytes) {
    return parse_span(text, '{', '}', out, err, max_bytes);
}

bool parse_first_array(const std::string& text, Value* out, std::string* err,
                       size_t max_bytes) {
    return parse_span(text, '[', ']', out, err, max_bytes);
}

std::string escape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            case '\b': o += "\\b";  break;
            case '\f': o += "\\f";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof buf, "\\u%04x", c);
                    o += buf;
                } else {
                    o += (char)c;
                }
        }
    }
    return o;
}

} // namespace minijson
