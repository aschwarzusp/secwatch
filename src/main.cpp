#include "ui.h"
#include "config.h"
#include "llm.h"
#include <iostream>

int main(int argc, char* argv[]) {
    App app;
    if (!app.init()) {
        std::cerr << "Failed to initialize application" << std::endl;
        return 1;
    }

    AppConfig cfg = AppConfig::load();
    LlmClient llm_instance(cfg.llm);
    LlmClient* llm = nullptr;

    if (cfg.llm.enabled) {
        std::string err;
        if (llm_instance.probe(&err)) {
            llm = &llm_instance;
            std::cout << "Connected to LLM: " << llm->model() << std::endl;
        } else {
            std::cout << "LLM unavailable (" << err
                      << "); using rule-based comments" << std::endl;
        }
    }

    app.run(llm);   // was: app.run(); — the LLM was never reaching enrich()
    return 0;       // destructor shuts down
}
