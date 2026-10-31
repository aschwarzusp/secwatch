#include "glsa.h"
#include "util.h"

#include <algorithm>
#include <regex>
#include <set>

namespace {

const char* kGlsaBase = "https://security.gentoo.org/glsa/";

bool looks_like_glsa_id(const std::string& s) {
    if (s.size() != 9) return false;
    for (int i = 0; i < 9; ++i) {
        if (i == 6) { if (s[i] != '-') return false; continue; }
        if (!std::isdigit((unsigned char)s[i])) return false;
    }
    return true;
}

std::string severity_from_words(const std::string& lower_text) {
    if (util::has_boundary_token(lower_text, "high"))   return "High";
    if (util::has_boundary_token(lower_text, "normal")) return "Medium";
    if (util::has_boundary_token(lower_text, "low"))    return "Low";
    return "Unknown";
}

} // namespace

bool GlsaScanner::available() {
    return util::command_exists("glsa-check");
}

std::vector<std::string> GlsaScanner::affected_ids(std::string* note) {
    std::vector<std::string> ids;
    if (!available()) {
        if (note) *note = "glsa-check not found; install app-portage/gentoolkit";
        return ids;
    }

    // Preferred form: ask glsa-check to list only affected advisories.
    int ec = 0;
    std::string raw = util::exec_capture({"glsa-check", "-l", "affected"}, &ec);

    bool usable = false;
    for (const auto& line : util::split(raw, '\n')) {
        std::string t = util::trim(line);
        if (t.size() >= 9 && looks_like_glsa_id(t.substr(0, 9))) { usable = true; break; }
    }

    // Fallback: full listing, keep lines that mention an affected status.
    if (!usable) {
        raw = util::exec_capture({"glsa-check", "-l"}, &ec);
        std::string filtered;
        for (const auto& line : util::split(raw, '\n')) {
            std::string t = util::trim(line);
            if (t.size() < 9 || !looks_like_glsa_id(t.substr(0, 9))) continue;
            std::string lower = util::lower(t);
            if (lower.find("affected") != std::string::npos ||
                t.find("[N]") != std::string::npos) {
                filtered += t + "\n";
            }
        }
        raw = filtered;
        if (note) *note = "glsa-check -l affected produced no parseable output; "
                          "fell back to scanning 'glsa-check -l'";
    }

    std::set<std::string> seen;
    for (const auto& line : util::split(raw, '\n')) {
        std::string t = util::trim(line);
        if (t.size() < 9) continue;
        std::string id = t.substr(0, 9);
        if (!looks_like_glsa_id(id)) continue;
        if (seen.insert(id).second) ids.push_back(id);
    }

    // Bound the number of follow-up HTTP requests.
    if (ids.size() > 40) ids.resize(40);
    return ids;
}

Advisory GlsaScanner::fetch_details(const std::string& id) {
    Advisory a;
    a.id = "GLSA-" + id;
    a.source = "GLSA";
    a.verified = true;   // glsa-check already decided this applies
    a.url = std::string(kGlsaBase) + id;

    std::string err;
    std::string html = util::http_get(a.url, 20, &err);
    if (html.empty()) {
        a.title = "GLSA " + id;
        a.severity = "Unknown";
        return a;
    }

    std::string text = util::collapse_ws(util::html_unescape(util::strip_tags(html)));

    // Title: prefer the advisory heading, else the first sentence-ish chunk.
    std::regex h1(R"(GLSA\s+\d{6}-\d{2}\s*:\s*([^.]{3,120}))");
    std::smatch m;
    if (std::regex_search(text, m, h1)) {
        a.title = util::trim(m[1].str());
    } else {
        a.title = "GLSA " + id;
    }

    // CVE identifiers give the comment generator real grounding material.
    std::set<std::string> cves;
    std::regex cve_re("CVE-[0-9]{4}-[0-9]{4,}", std::regex::icase);
    for (std::sregex_iterator it(text.begin(), text.end(), cve_re), end; it != end; ++it) {
        std::string c = it->str();
        std::transform(c.begin(), c.end(), c.begin(),
                       [](unsigned char ch) { return (char)std::toupper(ch); });
        cves.insert(c);
    }
    a.cves.assign(cves.begin(), cves.end());

    a.severity = severity_from_words(util::lower(text));

    std::string body = text;
    if (body.size() > 4000) body.resize(4000);
    a.body = body;
    return a;
}

std::vector<Advisory> GlsaScanner::collect(std::string* note) {
    std::vector<Advisory> out;
    std::vector<std::string> ids = affected_ids(note);
    for (const auto& id : ids) {
        out.push_back(fetch_details(id));
    }
    return out;
}
