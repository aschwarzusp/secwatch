#pragma once
#include "types.h"
#include <string>
#include <vector>

struct DistroInfo {
    std::string id;
    std::string version_id;
    std::string codename;
};

class PackageScanner {
public:
    static ScanResult scan();
    static std::vector<Package> scan_packages();
    static DistroInfo detect_distro();
    static std::vector<Package> scan_gentoo();  // ADD THIS
private:
    static std::vector<Package> scan_linux_internal();
    static std::vector<Package> scan_brew_internal();
    static std::vector<Package> scan_choco_internal();
    static std::vector<Package> scan_powershell_internal();
    static std::vector<Package> scan_flatpak_internal();
    static std::string get_arch_from_dpkg_arch(const std::string& dpkg_arch);
};

class DistroParser {
public:
    static std::string parse_id(const std::string& content);
    static std::string parse_version_id(const std::string& content);
    static std::string parse_codename(const std::string& content);
    static bool parse_debian_release_line(const std::string& line, std::string& version);
    static bool parse_ubuntu_release_line(const std::string& line, std::string& version);
    static bool parse_alpine_release_line(const std::string& line, std::string& version);
};
