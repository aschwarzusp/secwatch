# SecWatch

SDL2-based vulnerability scanner that enumerates installed packages and correlates them with security advisories from OSV.dev and public mailing lists.

## Features

- **Package enumeration** across Linux distributions (dpkg, rpm, pacman, apk), macOS (brew), and Windows (Chocolatey)
- **OSV API integration** for version-aware vulnerability matching
- **Mailing list scraping** for additional context and CVE references
- **SDL2 GUI** with findings list and detail pane
- **Multi-threaded** design (network I/O decoupled from rendering)

## Requirements

### Linux
```bash
sudo apt-get install libsdl2-dev libsdl2-ttf-dev libcurl4-openssl-dev cmake g++
