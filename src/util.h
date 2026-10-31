#pragma once
#include <string>
#include <vector>

namespace util {

std::string lower(std::string s);
std::string trim(const std::string& s);
bool starts_with(const std::string& s, const std::string& p);
bool ends_with(const std::string& s, const std::string& p);
std::vector<std::string> split(const std::string& s, char sep);

bool is_word_char(char c);
bool has_boundary_token(const std::string& hay_lower, const std::string& tok);

std::string html_unescape(const std::string& s);
std::string collapse_ws(const std::string& s);
std::string strip_tags(const std::string& s);

int compare_versions(const std::string& a, const std::string& b);

std::string exec_capture(const std::vector<std::string>& argv, int* exit_code = nullptr);
bool command_exists(const std::string& cmd);

std::string http_get(const std::string& url, long timeout_s, std::string* err,
                     const std::string& bearer = std::string());
std::string http_post_json(const std::string& url, const std::string& body,
                           long timeout_s, std::string* err,
                           const std::string& bearer = std::string());

std::string read_file(const std::string& path, bool* ok);
std::string getenv_str(const char* k);
std::string now_iso8601();

} // namespace util
