#include "vuln.h"
#include "util.h"
#include "glsa.h"
#include "pkgs.h"
#include <sstream>
#include <set>
#include <regex>
#include <algorithm>

ScanResult VulnWorker::enrich(const ScanResult& base, LlmClient* llm) {
    ScanResult out = base;

	bool is_gentoo = util::lower(base.distro_pretty).find("gentoo") != std::string::npos;

	if (is_gentoo && GlsaScanner::available()) {
	    std::string note;
	    std::vector<Advisory> glsa = GlsaScanner::collect(&note);
	    if (!note.empty()) out.notes.push_back(note);
	    out.advisories.insert(out.advisories.end(), glsa.begin(), glsa.end());
	    out.osv_records = (int)glsa.size();
	} else if (!is_gentoo) {
	    std::string eco = normalize_ecosystem_for_osv(base.distro_pretty, "");
	    std::vector<Advisory> osv_ads = fetch_osv_advisories(base.packages, eco);
	    out.advisories.insert(out.advisories.end(), osv_ads.begin(), osv_ads.end());
	    out.osv_records = (int)osv_ads.size();
	}

	std::string ml_err;
	std::vector<Advisory> ml_ads = RSSFeedReader::scrape_openwall_oss_sec(50, &ml_err);
	for (auto& a : ml_ads) { a.verified = false; }
	out.advisories.insert(out.advisories.end(), ml_ads.begin(), ml_ads.end());
    // Match packages to advisories and generate comments
	std::vector<Finding> findings;

	for (const auto& pkg : out.packages) {
	    Finding f;
	    f.pkg = pkg;
	    f.confidence = "Low";
	    f.severity = "Unknown";

	    correlate(f, out.advisories);
	    if (f.advisory_ids.empty()) continue;   // only report affected packages

	    std::vector<Advisory> matched;
	    for (int aid : f.advisory_ids) {
		if (aid >= 0 && aid < (int)out.advisories.size())
		    matched.push_back(out.advisories[aid]);
	    }

	    bool verified = false;
	    for (const auto& a : matched) {
		if (a.verified && !a.pkg_hint.empty() &&
		    util::lower(f.pkg.name) == util::lower(a.pkg_hint)) {
		    verified = true;
		    break;
		}
	    }
	    f.match_method = verified ? "glsa_version_range" : "name_title_match";

	    // Highest severity among matches wins.
	    auto rank = [](const std::string& s) {
		if (s == "Critical") return 4;
		if (s == "High")     return 3;
		if (s == "Medium")   return 2;
		if (s == "Low")      return 1;
		return 0;
	    };
	    for (const auto& a : matched) {
		if (rank(a.severity) > rank(f.severity)) f.severity = a.severity;
		if (!a.fixed_hint.empty() && f.fixed_version.empty())
		    f.fixed_version = a.fixed_hint;
	    }
	    f.confidence = verified ? "High" : "Medium";

	    // Only spend model calls on packages that actually matched.
	    if (llm) {
		std::string llm_err;
		std::vector<Comment> comments =
		    llm->comment_on(pkg, base.distro_pretty, f.match_method, matched, &llm_err);
		if (!comments.empty()) {
		    f.comments = comments;
		    f.comment_model = llm->model();
		} else {
		    f.comments = rule_based_comments(pkg, f.match_method, matched);
		}
	    } else {
		f.comments = rule_based_comments(pkg, f.match_method, matched);
	    }

	    findings.push_back(f);
	}
	std::sort(findings.begin(), findings.end(), [](const Finding& a, const Finding& b) {
	    auto rank = [](const std::string& s) {
		if (s == "Critical") return 4;
		if (s == "High")     return 3;
		if (s == "Medium")   return 2;
		if (s == "Low")      return 1;
		return 0;
	    };
	    if (rank(a.severity) != rank(b.severity)) return rank(a.severity) > rank(b.severity);
	    return a.pkg.name < b.pkg.name;
	});

	out.findings = findings;
	out.notes.push_back("Scanned " + std::to_string(out.packages.size()) +
			    " installed packages; " + std::to_string(out.findings.size()) +
			    " have matching advisories.");
    return out;
}

std::string VulnWorker::normalize_ecosystem_for_osv(const std::string& distro_id,
                                                    const std::string& version_id) {
    std::string id = util::lower(distro_id);
    if (id == "debian") {
        if (!version_id.empty()) return "Debian:" + version_id;
        return "Debian";
    }
    if (id == "ubuntu") {
        if (!version_id.empty()) return "Ubuntu:" + version_id + ":LTS";
        return "Ubuntu";
    }
    if (id == "alpine") {
        if (!version_id.empty()) return "Alpine:" + version_id;
        return "Alpine";
    }
    return id;
}

std::vector<Advisory> VulnWorker::fetch_osv_advisories(const std::vector<Package>& pkgs,
                                                      const std::string& distro_ecosystem) {
    std::vector<Advisory> ads;
    if (pkgs.empty()) return ads;

    std::ostringstream json;
    json << "{\"queries\":[";
    int count = 0;
    for (const auto& p : pkgs) {
        if (count++ > 0) json << ",";
        std::string eco = distro_ecosystem.empty() ? "" : distro_ecosystem;
        if (!eco.empty()) {
            json << "{\"package\":{\"ecosystem\":\"" << eco
                 << "\",\"name\":\"" << p.name << "\"},"
                 << "\"version\":\"" << p.version << "\"}";
        }
    }
    json << "]}";

    std::string err;
    std::string resp = util::http_post_json("https://api.osv.dev/v1/querybatch",
                                             json.str(), 30, &err);

    // Parse OSV response and populate advisories
    // This is a placeholder - proper JSON parsing would go here
    // The OSV response contains "vulns" arrays with detailed data

    return ads;
}

std::vector<Advisory> VulnWorker::parse_mailing_list_html(const std::string& html) {
    std::vector<Advisory> ads;
    std::regex cve_re("CVE-[0-9]{4}-[0-9]{4,}", std::regex::icase);
    std::smatch m;
    std::string search = html;
    while (std::regex_search(search, m, cve_re)) {
        Advisory a;
        a.id = m[0].str();
        a.source = "oss-security";
        a.title = "CVE reference found in mailing list";
        a.body = "This CVE was discussed on oss-security.";
        a.verified = false;
        ads.push_back(a);
        search = m.suffix().str();
    }
    return ads;
}

void VulnWorker::correlate(Finding& f, const std::vector<Advisory>& advisories) {
    for (size_t idx = 0; idx < advisories.size(); ++idx) {
        const auto& a = advisories[idx];
        if (a.verified && !a.pkg_hint.empty()) {
            if (util::lower(f.pkg.name) == util::lower(a.pkg_hint)) {
                f.advisory_ids.push_back((int)idx);
                f.confidence = "High";
                f.severity = a.severity;
                if (!a.fixed_hint.empty()) f.fixed_version = a.fixed_hint;
            }
        }
    }
    
    // Text matching for unverified advisories
    for (size_t idx = 0; idx < advisories.size(); ++idx) {
	    const auto& a = advisories[idx];
	    if (a.source != "GLSA") continue;
	    // GLSA bodies name atoms like 'media-video/vlc'. Match on the bare name too.
	    std::string body_lower = util::lower(a.body);
	    std::string full = util::lower(f.pkg.name);
	    std::string bare = full;
	    size_t slash = bare.rfind('/');
	    if (slash != std::string::npos) bare = bare.substr(slash + 1);

	    bool hit = util::has_boundary_token(body_lower, full) ||
		       util::has_boundary_token(body_lower, bare);
	    if (hit) {
		f.advisory_ids.push_back((int)idx);
		f.confidence = "High";
		f.match_method = "glsa_version_range";
	    }
	}
}

std::string VulnWorker::extract_cves_from_text(const std::string& text) {
    std::set<std::string> cves;
    std::regex cve_re("CVE-[0-9]{4}-[0-9]{4,}", std::regex::icase);
    std::sregex_iterator it(text.begin(), text.end(), cve_re);
    std::sregex_iterator end;
    for (; it != end; ++it) {
        cves.insert(it->str());
    }
    std::string out;
    for (const auto& c : cves) {
        if (!out.empty()) out += ", ";
        out += c;
    }
    return out;
}

std::string VulnWorker::guess_severity(const std::string& body) {
    std::string l = util::lower(body);
    if (util::has_boundary_token(l, "critical") || util::has_boundary_token(l, "remote code execution") || util::has_boundary_token(l, "rce")) return "Critical";
    if (util::has_boundary_token(l, "high") || util::has_boundary_token(l, "arbitrary code")) return "High";
    if (util::has_boundary_token(l, "medium") || util::has_boundary_token(l, "dos")) return "Medium";
    return "Low";
}

std::vector<Advisory> RSSFeedReader::read_feeds(const std::vector<FeedConfig>& feeds,
                                                int max_items,
                                                std::string* error) {
    std::vector<Advisory> ads;
    int total = 0;
    for (const auto& f : feeds) {
        if (total >= max_items) break;
        std::string err;
        std::string xml = util::http_get(f.url, 30, &err);
        if (xml.empty()) {
            if (error) *error += f.name + ": " + err + "; ";
            continue;
        }
        std::vector<Advisory> chunk = parse_rss_xml(xml, f.name);
        for (auto& a : chunk) {
            if (total++ >= max_items) break;
            ads.push_back(std::move(a));
        }
    }
    return ads;
}

std::vector<Advisory> RSSFeedReader::scrape_openwall_oss_sec(int limit,
                                                           std::string* error) {
    std::string html = util::http_get("https://www.openwall.com/lists/oss-security/", 30, error);
    if (html.empty()) return {};
    
    std::vector<Advisory> ads;
    std::regex date_re("\\d{4}/\\d{2}/\\d{2}");
    std::sregex_iterator it(html.begin(), html.end(), date_re);
    std::sregex_iterator end;
    
    for (int i = 0; it != end && i < limit; ++it, ++i) {
        Advisory a;
        a.date = it->str();
        a.source = "oss-security";
        a.id = "unassigned-" + std::to_string(i);
        a.title = "Mailing list entry on " + a.date;
        a.body = "See oss-security archive for details.";
        ads.push_back(a);
    }
    
    return ads;
}

std::vector<Advisory> RSSFeedReader::parse_rss_xml(const std::string& xml,
                                                   const std::string& source) {
    std::vector<Advisory> ads;
    size_t item_start = 0;
    while ((item_start = xml.find("<item>", item_start)) != std::string::npos) {
        size_t item_end = xml.find("</item>", item_start);
        if (item_end == std::string::npos) break;
        std::string item = xml.substr(item_start, item_end - item_start);
        
        Advisory a;
        a.source = source;
        
        size_t ti = item.find("<title>");
        if (ti != std::string::npos) {
            size_t tj = item.find("</title>", ti);
            if (tj != std::string::npos) {
                a.title = util::html_unescape(item.substr(ti + 7, tj - ti - 7));
            }
        }
        
        size_t li = item.find("<link>");
        if (li != std::string::npos) {
            size_t lj = item.find("</link>", li);
            if (lj != std::string::npos) {
                a.url = util::trim(item.substr(li + 6, lj - li - 6));
            }
        }
        
        size_t pi = item.find("<pubDate>");
        if (pi != std::string::npos) {
            size_t pj = item.find("</pubDate>", pi);
            if (pj != std::string::npos) {
                a.date = item.substr(pi + 9, pj - pi - 9);
            }
        }
        
        a.id = "rss-" + std::to_string(ads.size());
        a.body = util::strip_tags(a.title);
        a.verified = false;
        
        ads.push_back(a);
        item_start = item_end;
    }
    
    return ads;
}
