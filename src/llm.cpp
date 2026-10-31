#include "llm.h"
#include "util.h"
#include "minijson.h"
#include <algorithm>
#include <sstream>
#include <fstream>
#include <regex>

LlmClient::LlmClient(LlmConfig cfg) : cfg_(std::move(cfg)) {
    if (cfg_.cache_enabled && !cfg_.cache_dir.empty()) {
        util::exec_capture({"mkdir", "-p", cfg_.cache_dir}, nullptr);
    }
}

bool LlmClient::probe(std::string* err) {
    if (!cfg_.enabled) {
        if (err) *err = "LLM disabled in config";
        return false;
    }

    std::string resp = util::http_get(cfg_.url.substr(0, cfg_.url.rfind('/')) + "/models",
                                      cfg_.timeout_s, err, cfg_.api_key);
    if (!resp.empty()) return true;

    std::ostringstream payload;
    payload << "{\"model\":\"" << cfg_.model << "\",\"prompt\":\"test\",\"max_tokens\":1}";
    resp = util::http_post_json(cfg_.url.substr(0, cfg_.url.rfind('/')) + "/completions",
                                payload.str(), cfg_.timeout_s, err, cfg_.api_key);
    return !resp.empty();
}

std::string LlmClient::build_system_prompt() const {
    return R"(You are a security analyst summarizing vulnerability information. Your task is to generate CONCISE, FACTUAL comments about package security status based ONLY on the provided data.

RULES:
1. NEVER invent CVE IDs, version numbers, or exploit status. Only cite IDs and versions that appear explicitly in the input data.
2. NEVER claim a vulnerability is "under active attack" unless the input states this explicitly.
3. Output MUST be valid JSON with exactly this structure: {"comments":[{"tag":"why|risk|version|action|source|caveat","text":"comment text"}]}
4. Each comment tag means: why=why flagged, risk=risk implication, version=version notes, action=upgrade/patch recommendation, source=data origin, caveat=known limitations
5. Keep total comments under 6. Each text must be under 150 characters.
6. If input data shows no vulnerabilities, output empty array: {"comments":[]}

Your output will be validated against this schema. DO NOT output any text outside the JSON object.)";
}

std::string LlmClient::build_user_prompt(const Package& pkg, const std::string& distro,
                                         const std::string& match_method,
                                         const std::vector<Advisory>& matched) {
    std::ostringstream oss;
    oss << "Package: " << pkg.name << " v" << pkg.version << "\n";
    oss << "Manager: " << pkg.manager << "\n";
    oss << "Distro: " << distro << "\n";
    oss << "Match method: " << match_method << "\n\n";

    if (matched.empty()) {
        oss << "No vulnerabilities found in input data.\n";
    } else {
        oss << "Vulnerabilities found:\n";
        size_t max_show = static_cast<size_t>(std::min(static_cast<int>(matched.size()), cfg_.max_advisories));
        for (size_t i = 0; i < max_show; ++i) {
            const auto& a = matched[i];
            oss << "- " << a.source << ": " << a.id << " (" << a.severity << ")\n";
            if (!a.title.empty()) {
                std::string title = a.title;
                if (title.size() > static_cast<size_t>(cfg_.max_excerpt_chars))
                    title = title.substr(0, static_cast<size_t>(cfg_.max_excerpt_chars) - 3) + "...";
                oss << "  Title: " << title << "\n";
            }
            if (!a.cves.empty()) {
                oss << "  CVEs: ";
                for (size_t j = 0; j < std::min(a.cves.size(), (size_t)5); ++j) {
                    if (j > 0) oss << ", ";
                    oss << a.cves[j];
                }
                oss << "\n";
            }
            if (!a.fixed_hint.empty()) {
                oss << "  Fixed in: " << a.fixed_hint << "\n";
            }
        }
    }

    oss << "\nProvide security comments in valid JSON format. Be concise and factual.";
    return oss.str();
}

std::string LlmClient::make_chat_payload(const std::string& system, const std::string& user) {
    std::ostringstream oss;
    oss << "{\n";
    oss << "  \"model\": \"" << minijson::escape(cfg_.model) << "\",\n";
    oss << "  \"messages\": [\n";
    oss << "    {\"role\": \"system\", \"content\": \"" << minijson::escape(system) << "\"},\n";
    oss << "    {\"role\": \"user\", \"content\": \"" << minijson::escape(user) << "\"}\n";
    oss << "  ],\n";
    oss << "  \"temperature\": " << cfg_.temperature << ",\n";
    oss << "  \"max_tokens\": " << cfg_.max_tokens << "\n";
    oss << "}";
    return oss.str();
}

bool LlmClient::is_cve_known(const std::string& id) const {
    return false;
}

bool LlmClient::is_version_known(const std::string& pkg, const std::string& ver) const {
    return false;
}

Comment LlmClient::ground_comment(const minijson::Value& c, const std::string& model_name) {
    Comment cm;
    cm.text = c.str_or();
    cm.origin = "llm:" + model_name;
    cm.tag = c.find("tag") ? c.find("tag")->str_or("note") : "note";

    if (cfg_.strict_grounding) {
        std::string t = util::lower(cm.text);
        std::regex cve_re("CVE-[0-9]{4}-[0-9]{4,}", std::regex::icase);
        std::smatch m;
        if (std::regex_search(t, m, cve_re)) {
            if (!is_cve_known(m[0].str())) {
                cm.text = "(stripped unverified CVE reference) " + cm.text;
            }
        }
    }

    return cm;
}

std::string LlmClient::cache_key(const Package& pkg, const std::string& distro,
                                  const std::vector<Advisory>& matched) {
    std::ostringstream oss;
    oss << pkg.name << "|" << pkg.version << "|" << distro << "|";
    for (const auto& a : matched) oss << a.id << ",";
    return oss.str();
}

void LlmClient::save_cache(const std::string& key, const std::string& resp) {
    if (!cfg_.cache_enabled || cfg_.cache_dir.empty()) return;
    std::ofstream f(cfg_.cache_dir + "/" + key + ".json");
    if (f) f << resp;
}

std::string LlmClient::load_cache(const std::string& key) {
    if (!cfg_.cache_enabled || cfg_.cache_dir.empty()) return {};
    bool ok = false;
    std::string content = util::read_file(cfg_.cache_dir + "/" + key + ".json", &ok);
    if (ok) return content;
    return {};
}

std::vector<Comment> LlmClient::comment_on(const Package& pkg,
                                           const std::string& distro,
                                           const std::string& match_method,
                                           const std::vector<Advisory>& matched,
                                           std::string* err) {
    if (!cfg_.enabled) {
        if (err) *err = "LLM disabled";
        return rule_based_comments(pkg, match_method, matched);
    }

    std::unique_lock<std::mutex> lock(cache_mutex_);
    std::string ck = cache_key(pkg, distro, matched);
    if (cfg_.cache_enabled) {
        std::string cached = load_cache(ck);
        if (!cached.empty()) {
            stats_.cache_hits++;
            lock.unlock();
            minijson::Value parsed;
            if (minijson::parse_first_object(cached, &parsed, err)) {
                const auto* arr = parsed.find("comments");
                if (arr && arr->type == minijson::Value::Type::Arr) {
                    std::vector<Comment> out;
                    size_t max_com = static_cast<size_t>(std::min(static_cast<int>(arr->arr.size()), cfg_.max_comments));
                    for (size_t i = 0; i < max_com; ++i) {
                        if (arr->arr[i].type == minijson::Value::Type::Obj) {
                            out.push_back(ground_comment(arr->arr[i], cfg_.model));
                        }
                    }
                    if (!out.empty()) return out;
                }
            }
        }
    }
    lock.unlock();

    std::string system = build_system_prompt();
    std::string user = build_user_prompt(pkg, distro, match_method, matched);
    std::string payload = make_chat_payload(system, user);

    std::string resp = util::http_post_json(cfg_.url, payload, cfg_.timeout_s, err, cfg_.api_key);
    if (resp.empty()) {
        std::unique_lock<std::mutex> slock(stats_mutex_);
        stats_.failures++;
        slock.unlock();
        return rule_based_comments(pkg, match_method, matched);
    }

    minijson::Value parsed;
    if (!minijson::parse_first_object(resp, &parsed, err)) {
        std::unique_lock<std::mutex> slock(stats_mutex_);
        stats_.failures++;
        slock.unlock();
        if (err) *err += "; JSON parse failed";
        return rule_based_comments(pkg, match_method, matched);
    }

    const auto* choices = parsed.find("choices");
    if (!choices || choices->type != minijson::Value::Type::Arr || choices->arr.empty()) {
        std::unique_lock<std::mutex> slock(stats_mutex_);
        stats_.failures++;
        slock.unlock();
        if (err) *err += "; unexpected API response";
        return rule_based_comments(pkg, match_method, matched);
    }

    const auto* first_choice = choices->at(0);
    if (!first_choice || first_choice->type != minijson::Value::Type::Obj) {
        return rule_based_comments(pkg, match_method, matched);
    }

    const auto* message = first_choice->find("message");
    if (!message || message->type != minijson::Value::Type::Obj) {
        return rule_based_comments(pkg, match_method, matched);
    }

    const auto* content = message->find("content");
    if (!content || content->type != minijson::Value::Type::Str) {
        return rule_based_comments(pkg, match_method, matched);
    }

    minijson::Value comments_root;
    std::string parse_err;
    if (!minijson::parse_first_object(content->str, &comments_root, &parse_err)) {
        std::unique_lock<std::mutex> slock(stats_mutex_);
        stats_.suppressed++;
        slock.unlock();
        if (err) *err += "; model output format error: " + parse_err;
        return rule_based_comments(pkg, match_method, matched);
    }

    const auto* c_arr = comments_root.find("comments");
    if (!c_arr || c_arr->type != minijson::Value::Type::Arr) {
        return rule_based_comments(pkg, match_method, matched);
    }

    std::vector<Comment> out;
    size_t max_com = static_cast<size_t>(std::min(static_cast<int>(c_arr->arr.size()), cfg_.max_comments));
    for (size_t i = 0; i < max_com; ++i) {
        if (c_arr->arr[i].type == minijson::Value::Type::Obj) {
            out.push_back(ground_comment(c_arr->arr[i], cfg_.model));
        }
    }

    if (cfg_.cache_enabled) {
        save_cache(ck, resp);
    }

    {
        std::unique_lock<std::mutex> slock(stats_mutex_);
        stats_.requests++;
    }

    return out.empty() ? rule_based_comments(pkg, match_method, matched) : out;
}

LlmStats LlmClient::stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

std::vector<Comment> rule_based_comments(const Package& pkg,
                                         const std::string& match_method,
                                         const std::vector<Advisory>& matched) {
    std::vector<Comment> out;
    Comment base;
    base.origin = "rule";

    if (matched.empty()) {
        base.tag = "why";
        base.text = "No matching vulnerabilities in OSV/mailing list data.";
        out.push_back(base);
        return out;
    }

    if (match_method == "osv_version_range") {
        base.tag = "source";
        base.text = "Matched via OSV version-range query.";
        out.push_back(base);
    } else {
        base.tag = "source";
        base.text = "Matched via keyword matching (not version-aware).";
        out.push_back(base);
    }

    int critical = 0;
    for (const auto& a : matched) {
        if (a.severity == "Critical") critical++;
    }

    if (critical > 0) {
        Comment risk;
        risk.tag = "risk";
        risk.text = "Has " + std::to_string(critical) + " critical vulnerability(-ies). Review ASAP.";
        risk.origin = "rule";
        out.push_back(risk);
    }

    if (!matched[0].fixed_hint.empty()) {
        Comment fix;
        fix.tag = "version";
        fix.text = "Fix may be available: upgrade from " + pkg.version + " to " + matched[0].fixed_hint;
        fix.origin = "rule";
        out.push_back(fix);
    }

    Comment action;
    action.tag = "action";
    action.text = "Check package manager: " + pkg.manager + " update";
    action.origin = "rule";
    out.push_back(action);

    if (out.size() > 6) out.resize(6);
    return out;
}
