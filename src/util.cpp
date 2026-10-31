#include "util.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <sstream>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include <curl/curl.h>

namespace util {

std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace((unsigned char)s[a])) ++a;
    while (b > a && std::isspace((unsigned char)s[b - 1])) --b;
    return s.substr(a, b - a);
}

bool starts_with(const std::string& s, const std::string& p) {
    return s.size() >= p.size() && s.compare(0, p.size(), p) == 0;
}
bool ends_with(const std::string& s, const std::string& p) {
    return s.size() >= p.size() && s.compare(s.size() - p.size(), p.size(), p) == 0;
}

std::vector<std::string> split(const std::string& s, char sep) {
    std::vector<std::string> out;
    std::string cur;
    for (char c : s) {
        if (c == sep) { out.push_back(cur); cur.clear(); }
        else cur += c;
    }
    out.push_back(cur);
    return out;
}

bool is_word_char(char c) {
    unsigned char u = (unsigned char)c;
    return std::isalnum(u) || c == '_' || c == '-' || c == '+' || c == '.';
}

bool has_boundary_token(const std::string& hay, const std::string& tok) {
    if (tok.empty()) return false;
    size_t pos = 0;
    while ((pos = hay.find(tok, pos)) != std::string::npos) {
        bool lb = (pos == 0) || !is_word_char(hay[pos - 1]);
        size_t end = pos + tok.size();
        bool rb = (end >= hay.size()) || !is_word_char(hay[end]);
        if (lb && rb) return true;
        pos = end;
    }
    return false;
}

std::string html_unescape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] != '&') { out += s[i]; continue; }
        size_t semi = s.find(';', i);
        if (semi == std::string::npos || semi - i > 10) { out += s[i]; continue; }
        std::string ent = s.substr(i + 1, semi - i - 1);
        std::string rep;
        if (ent == "amp") rep = "&";
        else if (ent == "lt") rep = "<";
        else if (ent == "gt") rep = ">";
        else if (ent == "quot") rep = "\"";
        else if (ent == "apos" || ent == "#39") rep = "'";
        else if (ent == "nbsp") rep = " ";
        else if (!ent.empty() && ent[0] == '#') {
            long code = (ent.size() > 1 && (ent[1] == 'x' || ent[1] == 'X'))
                            ? strtol(ent.c_str() + 2, nullptr, 16)
                            : strtol(ent.c_str() + 1, nullptr, 10);
            if (code > 0 && code < 0x110000) {
                if (code < 0x80) rep += (char)code;
                else if (code < 0x800) {
                    rep += (char)(0xC0 | (code >> 6));
                    rep += (char)(0x80 | (code & 0x3F));
                } else if (code < 0x10000) {
                    rep += (char)(0xE0 | (code >> 12));
                    rep += (char)(0x80 | ((code >> 6) & 0x3F));
                    rep += (char)(0x80 | (code & 0x3F));
                } else {
                    rep += (char)(0xF0 | (code >> 18));
                    rep += (char)(0x80 | ((code >> 12) & 0x3F));
                    rep += (char)(0x80 | ((code >> 6) & 0x3F));
                    rep += (char)(0x80 | (code & 0x3F));
                }
            }
        }
        if (rep.empty()) out += s[i];
        else { out += rep; i = semi; }
    }
    return out;
}

std::string collapse_ws(const std::string& s) {
    std::string out;
    bool sp = false;
    for (char c : s) {
        if (std::isspace((unsigned char)c)) { sp = true; continue; }
        if (sp && !out.empty()) out += ' ';
        sp = false;
        out += c;
    }
    return out;
}

std::string strip_tags(const std::string& s) {
    std::string out;
    bool in_tag = false;
    for (char c : s) {
        if (c == '<') { in_tag = true; continue; }
        if (c == '>') { in_tag = false; out += ' '; continue; }
        if (!in_tag) out += c;
    }
    return out;
}

// Approximate version ordering. Segment-wise, numeric segments compared
// numerically, '~' sorts below everything (Debian convention). Ignores
// epochs and distro revision semantics, so treat results as indicative.
static std::vector<std::string> ver_segments(const std::string& v) {
    std::vector<std::string> segs;
    std::string cur;
    for (char ch : v) {
        unsigned char u = (unsigned char)ch;
        if (std::isalnum(u) || ch == '~') cur += (char)std::tolower(u);
        else if (!cur.empty()) { segs.push_back(cur); cur.clear(); }
    }
    if (!cur.empty()) segs.push_back(cur);
    return segs;
}

int compare_versions(const std::string& a, const std::string& b) {
    std::vector<std::string> A = ver_segments(a), B = ver_segments(b);
    size_t n = std::max(A.size(), B.size());
    for (size_t i = 0; i < n; ++i) {
        std::string x = i < A.size() ? A[i] : std::string();
        std::string y = i < B.size() ? B[i] : std::string();
        bool xn = !x.empty() &&
                  std::all_of(x.begin(), x.end(), [](char c) { return std::isdigit((unsigned char)c); });
        bool yn = !y.empty() &&
                  std::all_of(y.begin(), y.end(), [](char c) { return std::isdigit((unsigned char)c); });
        if (xn && yn) {
            long lx = strtol(x.c_str(), nullptr, 10), ly = strtol(y.c_str(), nullptr, 10);
            if (lx != ly) return lx < ly ? -1 : 1;
        } else {
            bool xt = !x.empty() && x[0] == '~', yt = !y.empty() && y[0] == '~';
            if (xt != yt) return xt ? -1 : 1;
            if (x != y) return x < y ? -1 : 1;
        }
    }
    return 0;
}

std::string exec_capture(const std::vector<std::string>& argv, int* exit_code) {
    std::string out;
    if (argv.empty()) { if (exit_code) *exit_code = -1; return out; }

#ifdef _WIN32
    std::string cmd;
    for (const auto& a : argv) {
        if (!cmd.empty()) cmd += ' ';
        cmd += '"' + a + '"';
    }
    FILE* p = _popen(cmd.c_str(), "rb");
    if (!p) { if (exit_code) *exit_code = -1; return out; }
    char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, p)) > 0) out.append(buf, n);
    if (exit_code) *exit_code = _pclose(p);
#else
    int fd[2];
    if (pipe(fd) != 0) { if (exit_code) *exit_code = -1; return out; }
    pid_t pid = fork();
    if (pid < 0) {
        close(fd[0]); close(fd[1]);
        if (exit_code) *exit_code = -1;
        return out;
    }
    if (pid == 0) {
        dup2(fd[1], STDOUT_FILENO);
        close(fd[0]); close(fd[1]);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) dup2(devnull, STDERR_FILENO);
        std::vector<char*> cargv;
        cargv.reserve(argv.size() + 1);
        for (const auto& a : argv) cargv.push_back(const_cast<char*>(a.c_str()));
        cargv.push_back(nullptr);
        execvp(cargv[0], cargv.data());
        _exit(127);
    }
    close(fd[1]);
    char buf[16384];
    ssize_t n;
    while ((n = read(fd[0], buf, sizeof buf)) > 0) out.append(buf, (size_t)n);
    close(fd[0]);
    int st = 0;
    waitpid(pid, &st, 0);
    if (exit_code) *exit_code = WIFEXITED(st) ? WEXITSTATUS(st) : -1;
#endif
    return out;
}

bool command_exists(const std::string& cmd) {
    std::string path = getenv_str("PATH");
    if (path.empty()) path = "/usr/local/bin:/usr/bin:/bin";
    for (const auto& dir : split(path, ':')) {
        if (dir.empty()) continue;
        std::string full = dir + "/" + cmd;
#ifdef _WIN32
        FILE* f = fopen(full.c_str(), "rb");
        if (f) { fclose(f); return true; }
#else
        if (access(full.c_str(), X_OK) == 0) return true;
#endif
    }
    return false;
}

static size_t write_cb(char* ptr, size_t size, size_t nmemb, void* ud) {
    static_cast<std::string*>(ud)->append(ptr, size * nmemb);
    return size * nmemb;
}

static std::string http_request(const std::string& url, const std::string& post_body,
                                const std::vector<std::string>& headers,
                                long timeout_s, std::string* err,
                                const std::string& bearer) {
    CURL* c = curl_easy_init();
    if (!c) { if (err) *err = "curl_easy_init failed"; return {}; }
    std::string body;
    struct curl_slist* hs = nullptr;
    for (const auto& h : headers) hs = curl_slist_append(hs, h.c_str());
    if (!bearer.empty()) {
        std::string auth = "Authorization: Bearer " + bearer;
        hs = curl_slist_append(hs, auth.c_str());
    }

    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(c, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, timeout_s);
    curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(c, CURLOPT_ACCEPT_ENCODING, "");
    curl_easy_setopt(c, CURLOPT_USERAGENT,
                     "secwatch/0.1 (local package triage; contact: set-your-email)");
    // Certificate verification stays on. Do not disable this.
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(c, CURLOPT_SSL_VERIFYHOST, 2L);

    if (!post_body.empty()) {
        curl_easy_setopt(c, CURLOPT_POST, 1L);
        curl_easy_setopt(c, CURLOPT_POSTFIELDS, post_body.c_str());
        curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, (long)post_body.size());
    }
    if (hs) curl_easy_setopt(c, CURLOPT_HTTPHEADER, hs);

    CURLcode rc = curl_easy_perform(c);
    long code = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
    if (rc != CURLE_OK) {
        if (err) *err = curl_easy_strerror(rc);
        body.clear();
    } else if (code >= 400) {
        if (err) *err = "HTTP " + std::to_string(code);
        body.clear();
    }
    if (hs) curl_slist_free_all(hs);
    curl_easy_cleanup(c);
    return body;
}

std::string http_get(const std::string& url, long timeout_s, std::string* err,
                     const std::string& bearer) {
    return http_request(url, {}, {}, timeout_s, err, bearer);
}

std::string http_post_json(const std::string& url, const std::string& body,
                           long timeout_s, std::string* err,
                           const std::string& bearer) {
    return http_request(url, body, {"Content-Type: application/json"},
                        timeout_s, err, bearer);
}

std::string read_file(const std::string& path, bool* ok) {
    std::ifstream f(path, std::ios::binary);
    if (!f) { if (ok) *ok = false; return {}; }
    std::ostringstream ss;
    ss << f.rdbuf();
    if (ok) *ok = true;
    return ss.str();
}

std::string getenv_str(const char* k) {
    const char* v = std::getenv(k);
    return v ? std::string(v) : std::string();
}

std::string now_iso8601() {
    std::time_t t = std::time(nullptr);
    std::tm tmv{};
#ifdef _WIN32
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%d %H:%M:%S", &tmv);
    return buf;
}

} // namespace util
