#pragma once
#include "config.h"
#include "types.h"
#include "minijson.h"

#include <mutex>
#include <string>
#include <vector>

struct LlmStats {
    int requests = 0;
    int cache_hits = 0;
    int failures = 0;
    int suppressed = 0;
    int fallbacks = 0;
};

class LlmClient {
public:
    explicit LlmClient(LlmConfig cfg);

    bool probe(std::string* err);

    std::vector<Comment> comment_on(const Package& pkg,
                                    const std::string& distro,
                                    const std::string& match_method,
                                    const std::vector<Advisory>& matched,
                                    std::string* err);

    LlmStats stats() const;
    const std::string& model() const { return cfg_.model; }

private:
    std::string build_system_prompt() const;
    std::string build_user_prompt(const Package& pkg, const std::string& distro,
                                  const std::string& match_method,
                                  const std::vector<Advisory>& matched);
    std::string make_chat_payload(const std::string& system, const std::string& user);
    Comment ground_comment(const minijson::Value& c, const std::string& model_name);
    bool is_cve_known(const std::string& id) const;
    bool is_version_known(const std::string& pkg, const std::string& ver) const;
    std::string cache_key(const Package& pkg, const std::string& distro,
                          const std::vector<Advisory>& matched);
    void save_cache(const std::string& key, const std::string& resp);
    std::string load_cache(const std::string& key);

    LlmConfig cfg_;
    mutable LlmStats stats_{};
    mutable std::mutex stats_mutex_;
    mutable std::mutex cache_mutex_;
};

std::vector<Comment> rule_based_comments(const Package& pkg,
                                         const std::string& match_method,
                                         const std::vector<Advisory>& matched);
