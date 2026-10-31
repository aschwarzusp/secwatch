#pragma once
#include "types.h"
#include <string>
#include <vector>

class GlsaScanner {
public:
    static bool available();
    // Uses the locally installed glsa-check (app-portage/gentoolkit), which
    // performs version comparison with Portage's own logic, then enriches each
    // affected GLSA from security.gentoo.org.
    static std::vector<Advisory> collect(std::string* note);

private:
    static std::vector<std::string> affected_ids(std::string* note);
    static Advisory fetch_details(const std::string& id);
};
