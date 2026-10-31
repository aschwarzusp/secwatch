#pragma once
#include <string>

struct LlmConfig {
    bool enabled = true;
    std::string url = "http://127.0.0.1:8080/v1/chat/completions";
    std::string model = "gemma-4-12b";
    std::string api_key;
    int max_tokens = 768;
    double temperature = 0.2;
    int timeout_s = 180;
    int max_advisories = 6;
    int max_excerpt_chars = 700;
    int max_comments = 6;
    bool strict_grounding = true;
    bool use_json_schema = false;
    bool cache_enabled = true;
    std::string cache_dir;
};

struct AppConfig {
    LlmConfig llm;
    static AppConfig load();
};

std::string secwatch_config_path();
std::string secwatch_cache_dir();
