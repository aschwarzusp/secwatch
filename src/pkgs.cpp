#include "pkgs.h"
#include "util.h"
#include <sstream>

std::vector<Package> PackageScanner::scan_packages() {
    std::vector<Package> pkgs;

    // TRY GENTOO FIRST if Portage is available
    if (util::command_exists("qlist")) {
        pkgs = scan_gentoo();
        if (!pkgs.empty()) {
            // Successfully scanned Gentoo, skip other Linux methods
            return pkgs;
        }
    }

    // dpkg (Debian/Ubuntu/Mint/etc.)
    if (util::command_exists("dpkg")) {
        int ec = 0;
        std::string raw = util::exec_capture({"dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\t${Status}\n"}, &ec);
        if (ec == 0) {
            for (const auto& line : util::split(raw, '\n')) {
                if (line.empty()) continue;
                auto fields = util::split(line, '\t');
                if (fields.size() < 4) continue;
                const std::string status = fields[3];
                if (!util::starts_with(status, "install ok installed")) continue;
                Package p;
                p.name = fields[0];
                p.version = fields[1];
                p.arch = fields[2];
                p.source = "dpkg";
                p.manager = "apt/dpkg";
                pkgs.push_back(p);
            }
        }
    }

    // rpm (Fedora/RHEL/CentOS/openSUSE)
    if (util::command_exists("rpm")) {
        int ec = 0;
        std::string raw = util::exec_capture({"rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"}, &ec);
        if (ec == 0) {
            for (const auto& line : util::split(raw, '\n')) {
                if (line.empty()) continue;
                auto fields = util::split(line, '\t');
                if (fields.size() < 3) continue;
                Package p;
                p.name = fields[0];
                p.version = fields[1];
                p.arch = fields[2];
                p.source = "rpm";
                p.manager = "dnf/yum/rpm";
                pkgs.push_back(p);
            }
        }
    }

    // pacman (Arch/Manjaro)
    if (util::command_exists("pacman")) {
        int ec = 0;
        std::string raw = util::exec_capture({"pacman", "-Q"}, &ec);
        if (ec == 0) {
            for (const auto& line : util::split(raw, '\n')) {
                if (line.empty()) continue;
                auto parts = util::split(line, ' ');
                if (parts.size() < 2) continue;
                Package p;
                p.name = parts[0];
                p.version = parts[1];
                p.arch = "";
                p.source = "pacman";
                p.manager = "pacman";
                pkgs.push_back(p);
            }
        }
    }

    // apk (Alpine)
    if (util::command_exists("apk")) {
        int ec = 0;
        std::string raw = util::exec_capture({"apk", "list", "--installed"}, &ec);
        if (ec == 0) {
            for (const auto& line : util::split(raw, '\n')) {
                if (line.empty()) continue;
                std::string pkg_info = line;
                size_t paren = pkg_info.rfind(" (");
                if (paren == std::string::npos) continue;
                std::string before = pkg_info.substr(0, paren);
                std::vector<std::string> tokens = util::split(before, ' ');
                if (tokens.size() < 2) continue;
                std::string ver = tokens[tokens.size() - 2];
                std::string nm = tokens[tokens.size() - 3];
                for (size_t i = 0; i < tokens.size() - 3; ++i) nm += " " + tokens[i];

                size_t dash = ver.rfind('-');
                if (dash == std::string::npos) continue;
                std::string rel = ver.substr(dash + 1);
                std::string base_ver = ver.substr(0, dash);
                std::string full_ver = base_ver + "-" + rel;

                Package p;
                p.name = nm;
                p.version = full_ver;
                p.arch = tokens.back();
                p.source = "apk";
                p.manager = "apk";
                pkgs.push_back(p);
            }
        }
    }

    return pkgs;
}

// NEW FUNCTION - add this after scan_flatpak_internal()
std::vector<Package> PackageScanner::scan_gentoo() {
    std::vector<Package> pkgs;
    if (!util::command_exists("qlist")) return pkgs;

    int ec = 0;
    std::string raw = util::exec_capture({"qlist", "-Iv"}, &ec);
    if (ec != 0) return pkgs;

    // qlist -Iv outputs: category/package-version
    for (const auto& line : util::split(raw, '\n')) {
        if (line.empty()) continue;
        size_t slash = line.rfind('/');
        if (slash == std::string::npos) continue;

        std::string category = line.substr(0, slash);
        std::string rest = line.substr(slash + 1);

        // Split name and version at last hyphen before version numbers
        // e.g., app-editors/vim-9.2.1229 -> name=app-editors/vim, version=9.2.1229
	size_t ver_start = std::string::npos;
	for (size_t i = 0; i + 1 < rest.size(); ++i) {
	    if (rest[i] == '-' && std::isdigit((unsigned char)rest[i + 1])) {
		ver_start = i;
		break;
	    }
	}
	if (ver_start == std::string::npos) continue;

	std::string name = rest.substr(0, ver_start);
	std::string version = rest.substr(ver_start + 1);
        Package p;
        p.name = category + "/" + name;  // Include category in name like Portage
        p.version = version;
        p.arch = "";  // Would need separate equery query for arch
        p.source = "portage";
        p.manager = "portage/qlist";
        pkgs.push_back(p);
    }

    return pkgs;
}

// Rest of file unchanged...

DistroInfo PackageScanner::detect_distro() {
    DistroInfo d;
    bool ok = false;
    std::string content = util::read_file("/etc/os-release", &ok);
    if (!ok) return d;
    
    d.id = DistroParser::parse_id(content);
    d.version_id = DistroParser::parse_version_id(content);
    d.codename = DistroParser::parse_codename(content);
    
    // Special handling for Debian without VERSION_CODENAME
    if (d.id == "debian" && d.codename.empty()) {
        ok = false;
        std::string r = util::read_file("/etc/debian_version", &ok);
        if (ok) {
            d.codename = util::trim(r);
        }
    }
    
    // Special handling for Alpine
    if (d.id == "alpine") {
        ok = false;
        std::string r = util::read_file("/etc/alpine-release", &ok);
        if (ok) {
            d.version_id = util::trim(r);
        }
    }
    
    return d;
}

std::string PackageScanner::get_arch_from_dpkg_arch(const std::string& dpkg_arch) {
    if (dpkg_arch == "amd64") return "x86_64";
    if (dpkg_arch == "i386") return "x86";
    if (dpkg_arch == "armhf") return "armv7l";
    if (dpkg_arch == "arm64") return "aarch64";
    return dpkg_arch;
}

std::string DistroParser::parse_id(const std::string& content) {
    for (const auto& line : util::split(content, '\n')) {
        if (util::starts_with(line, "ID=") || util::starts_with(line, "ID=\"")) {
            std::string val = line.substr(3);
            if (util::ends_with(val, "\"")) val.pop_back();
            return util::lower(util::trim(val));
        }
    }
    return {};
}

std::string DistroParser::parse_version_id(const std::string& content) {
    for (const auto& line : util::split(content, '\n')) {
        if (util::starts_with(line, "VERSION_ID=") || util::starts_with(line, "VERSION_ID=\"")) {
            std::string val = line.substr(11);
            if (util::ends_with(val, "\"")) val.pop_back();
            return util::trim(val);
        }
    }
    return {};
}

std::string DistroParser::parse_codename(const std::string& content) {
    for (const auto& line : util::split(content, '\n')) {
        if (util::starts_with(line, "VERSION_CODENAME=")) {
            std::string val = line.substr(17);
            if (util::ends_with(val, "\"")) val.pop_back();
            return util::trim(val);
        }
        if (util::starts_with(line, "UBUNTU_CODENAME=")) {
            std::string val = line.substr(18);
            if (util::ends_with(val, "\"")) val.pop_back();
            return util::trim(val);
        }
    }
    return {};
}

bool DistroParser::parse_debian_release_line(const std::string& line, std::string& version) {
    if (!util::starts_with(line, "Release:")) return false;
    std::string rest = line.substr(8);
    size_t paren = rest.find('(');
    if (paren != std::string::npos) rest = rest.substr(0, paren);
    version = util::trim(rest);
    return !version.empty();
}

bool DistroParser::parse_ubuntu_release_line(const std::string& line, std::string& version) {
    if (!util::starts_with(line, "Release:")) return false;
    std::string rest = line.substr(8);
    size_t paren = rest.find('(');
    if (paren != std::string::npos) rest = rest.substr(0, paren);
    version = util::trim(rest);
    return !version.empty();
}

bool DistroParser::parse_alpine_release_line(const std::string& line, std::string& version) {
    if (!util::starts_with(line, "Release:")) return false;
    std::string rest = line.substr(8);
    size_t paren = rest.find('(');
    if (paren != std::string::npos) rest = rest.substr(0, paren);
    version = util::trim(rest);
    return !version.empty();
}
