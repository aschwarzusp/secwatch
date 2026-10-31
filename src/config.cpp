#include "config.h"
#include "util.h"

#include <cstdlib>
#include <fstream>
#include <map>

namespace {

std::string home_dir() {
#ifdef _WIN32
    std::string h = util::getenv_str("USERPROFILE");
    if (!h.empty()) return h;
    return util::getenv_str("HOMEDRIVE") + util::getenv_str("HOMEPATH");
#else
    std::string h = util::getenv_str("HOME");
    return h.empty() ? std::string(".") : h;
#endif
}

std::map<std::string, std::string> read_conf_file(const std::string& path) {
    std::map<std::string, std::string> kv;
    bool ok = false;
    std::string text = util::read_file(path, &ok);
    if (!ok) return kv;
    for (const auto& raw : util::split(text, '\n')) {
        std::string line = util::trim(raw);
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string k = util::lower(util::trim(line.substr(0, eq)));
        std::string v = util::trim(line.substr(eq + 1));
        if (v.size() >= 2 && ((v.front() == '"' && v.back() == '"') ||
                              (v.front() == '\'' && v.back() == '\'')))
            v = v.substr(1, v.size() - 2);
        if (!k.empty()) kv[k] = v;
    }
    return kv;
}

std::string pick(const std::map<std::string, std::string>& kv,
                 const char* conf_key, const char* env_key,
                 const std::string& def) {
    std::string e = util::getenv_str(env_key);
    if (!e.empty()) return e;
    auto it = kv.find(conf_key);
    if (it != kv.end() && !it->second.empty()) return it->second;
    return def;
}

bool truthy(const std::string& s, bool def) {
    if (s.empty()) return def;
    std::string v = util::lower(util::trim(s));
    if (v == "1" || v == "true" || v == "yes" || v == "on") return true;
    if (v == "0" || v == "false" || v == "no" || v == "off") return false;
    return def;
}

int to_int(const std::string& s, int def) {
    if (s.empty()) return def;
    char* end = nullptr;
    long v = std::strtol(s.c_str(), &end, 10);
    if (end == s.c_str()) return def;
    return (int)v;
}

double to_double(const std::string& s, double def) {
    if (s.empty()) return def;
    char* end = nullptr;
    double v = std::strtod(s.c_str(), &end);
    if (end == s.c_str()) return def;
    return v;
}

} // namespace

std::string secwatch_config_path() {
    std::string ov = util::getenv_str("SECWATCH_CONFIG");
    if (!ov.empty()) return ov;
#ifdef _WIN32
    std::string base = util::getenv_str("APPDATA");
    if (base.empty()) base = home_dir();
    return base + "\\secwatch\\secwatch.conf";
#else
    std::string xdg = util::getenv_str("XDG_CONFIG_HOME");
    if (xdg.empty()) xdg = home_dir() + "/.config";
    return xdg + "/secwatch/secwatch.conf";
#endif
}

std::string secwatch_cache_dir() {
#ifdef _WIN32
    std::string base = util::getenv_str("LOCALAPPDATA");
    if (base.empty()) base = home_dir();
    return base + "\\secwatch\\llm-cache";
#else
    std::string xdg = util::getenv_str("XDG_CACHE_HOME");
    if (xdg.empty()) xdg = home_dir() + "/.cache";
    return xdg + "/secwatch/llm";
#endif
}

AppConfig AppConfig::load() {
    AppConfig cfg;
    auto kv = read_conf_file(secwatch_config_path());
    LlmConfig& l = cfg.llm;

    l.enabled   = truthy(pick(kv, "llm_enabled", "SECWATCH_LLM_ENABLED", "1"), true);
    l.url       = pick(kv, "llm_url", "SECWATCH_LLM_URL", l.url);
    l.model     = pick(kv, "llm_model", "SECWATCH_LLM_MODEL", l.model);
    l.api_key   = pick(kv, "llm_api_key", "SECWATCH_LLM_API_KEY", "");
    l.max_tokens = to_int(pick(kv, "llm_max_tokens", "SECWATCH_LLM_MAX_TOKENS", ""), l.max_tokens);
    l.temperature = to_double(pick(kv, "llm_temperature", "SECWATCH_LLM_TEMPERATURE", ""), l.temperature);
    l.timeout_s = to_int(pick(kv, "llm_timeout_s", "SECWATCH_LLM_TIMEOUT", ""), l.timeout_s);
    l.max_comments = to_int(pick(kv, "llm_max_comments", "SECWATCH_LLM_MAX_COMMENTS", ""), l.max_comments);
    l.max_advisories = to_int(pick(kv, "llm_max_advisories", "SECWATCH_LLM_MAX_ADVISORIES", ""), l.max_advisories);
    l.max_excerpt_chars = to_int(pick(kv, "llm_max_excerpt", "SECWATCH_LLM_MAX_EXCERPT", ""), l.max_excerpt_chars);
    l.strict_grounding = truthy(pick(kv, "llm_strict_grounding", "SECWATCH_LLM_STRICT_GROUNDING", "1"), true);
    l.use_json_schema  = truthy(pick(kv, "llm_json_schema", "SECWATCH_LLM_JSON_SCHEMA", "0"), false);
    l.cache_enabled    = truthy(pick(kv, "llm_cache", "SECWATCH_LLM_CACHE", "1"), true);
    l.cache_dir = pick(kv, "llm_cache_dir", "SECWATCH_LLM_CACHE_DIR", secwatch_cache_dir());
    return cfg;
}
