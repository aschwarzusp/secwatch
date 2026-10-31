#pragma once
#include "llm.h"
#include "types.h"
#include <string>
#include <vector>
#include <mutex>
#include <atomic>

class VulnWorker {
public:
    static ScanResult enrich(const ScanResult& base, LlmClient* llm = nullptr);

private:
    static std::vector<Advisory> fetch_osv_advisories(const std::vector<Package>& pkgs,
                                                     const std::string& distro_ecosystem);
    static std::vector<Advisory> parse_mailing_list_html(const std::string& html);
    static void correlate(Finding& f, const std::vector<Advisory>& advisories);
    static std::string extract_cves_from_text(const std::string& text);
    static std::string guess_severity(const std::string& body);
    static std::string normalize_ecosystem_for_osv(const std::string& distro_id,
                                                  const std::string& version_id);
};

class RSSFeedReader {
public:
    struct FeedConfig {
        std::string name;
        std::string url;
    };

    static std::vector<Advisory> read_feeds(const std::vector<FeedConfig>& feeds,
                                            int max_items,
                                            std::string* error);
    static std::vector<Advisory> scrape_openwall_oss_sec(int limit,
                                                        std::string* error);

private:
    static std::vector<Advisory> parse_rss_xml(const std::string& xml,
                                              const std::string& source);
};
