#include "ui.h"
#include "util.h"
#include "pkgs.h"
#include "vuln.h"
#include "glsa.h"
#include "llm.h"
#include <thread>
#include <chrono>

App::App() {}

App::~App() {
    shutdown();
}

bool App::init() {
    if (SDL_Init(SDL_INIT_VIDEO) < 0) return false;
    
    win = SDL_CreateWindow("SecWatch - Vulnerability Scanner",
                           SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
                           win_w, win_h, SDL_WINDOW_RESIZABLE);
    if (!win) return false;
    
    ren = SDL_CreateRenderer(win, -1, SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC);
    if (!ren) return false;
    
    if (TTF_Init() < 0) return false;
    
    const char* fonts[] = {
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/TTF/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/liberation-fonts/LiberationSans-Regular.ttf",
        "/usr/share/fonts/liberation/LiberationSans-Regular.ttf",
        "/usr/share/fonts/liberation-fonts-ttf/LiberationMono-Regular.ttf",
        "/usr/share/fonts/terminus/ter-v16n.pcf",
        "C:\\Windows\\Fonts\\arial.ttf",
        "C:\\Windows\\Fonts\\consola.ttf",
        "/System/Library/Fonts/Helvetica.ttc",
        "/System/Library/Fonts/PingFang.ttc",
    };
    
    for (const char* fp : fonts) {
        TTF_Font* f = TTF_OpenFont(fp, 14);
        if (f) { 
            font = f; 
            break; 
        }
    }
    
    if (!font) {
        SDL_Log("WARNING: Could not load font; text will be invisible");
        SDL_Log("Hint: Install dejavu-fonts or liberation-fonts");
    }
    
    font_bold = font;
    return true;
}

void App::shutdown() {
    if (shut_) return;
    shut_ = true;
    worker_stop_.store(true, std::memory_order_release);
    if (worker_.joinable()) worker_.join();
    if (font) { TTF_CloseFont(font); font = nullptr; }
    font_bold = nullptr;
    if (ren) { SDL_DestroyRenderer(ren); ren = nullptr; }
    if (win) { SDL_DestroyWindow(win); win = nullptr; }
    TTF_Quit();
    SDL_Quit();
}

void App::run(LlmClient* llm) {
    llm_ = llm;
    worker_ = std::thread(&App::worker_main, this, llm);

    SDL_Event ev;
    while (running) {
        while (SDL_PollEvent(&ev)) {
            handle_event(ev);
            if (ev.type == SDL_QUIT) running = false;
        }
        render();
        SDL_Delay(16);

        if (scan_done.load(std::memory_order_acquire)) {
            std::lock_guard<std::mutex> lock(result_mutex);
            current_result = pending_result;
            scan_done.store(false, std::memory_order_release);
            selected_finding_idx = current_result.findings.empty() ? -1 : 0;
        }
    }

    worker_stop_.store(true, std::memory_order_release);
    if (worker_.joinable()) worker_.join();
}

void App::worker_main(LlmClient* llm) {
    update_status("Scanning installed packages...");
    ScanResult base;
    base.packages = PackageScanner::scan_packages();

    auto distro = PackageScanner::detect_distro();
    if (!distro.id.empty()) {
        base.distro_pretty = distro.version_id.empty()
                                 ? distro.id
                                 : distro.id + ":" + distro.version_id;
    }
    append_log("Found " + std::to_string(base.packages.size()) + " packages.");
    if (worker_stop_.load(std::memory_order_acquire)) return;

    update_status("Fetching advisories...");
    ScanResult enriched = VulnWorker::enrich(base, llm);
    if (worker_stop_.load(std::memory_order_acquire)) return;

    {
        std::lock_guard<std::mutex> lock(result_mutex);
        pending_result = enriched;
    }
    scan_done.store(true, std::memory_order_release);

    update_status("Scan complete.");
    for (const auto& n : enriched.notes) append_log(n);
}

void App::handle_event(const SDL_Event& ev) {
    switch (ev.type) {
        case SDL_KEYDOWN:
            switch (ev.key.keysym.sym) {
                case SDLK_ESCAPE: running = false; break;
                case SDLK_DOWN: scroll_findings_down(1.0f); break;
                case SDLK_UP: scroll_findings_up(1.0f); break;
                case SDLK_PAGEUP: scroll_findings_up(10.0f); break;
                case SDLK_PAGEDOWN: scroll_findings_down(10.0f); break;
                case SDLK_j: scroll_findings_down(1.0f); break;
                case SDLK_k: scroll_findings_up(1.0f); break;
                default: break;
            }
            break;
        case SDL_MOUSEWHEEL:
            if (ev.wheel.y > 0) scroll_findings_up(1.0f);
            else if (ev.wheel.y < 0) scroll_findings_down(1.0f);
            break;
        case SDL_WINDOWEVENT:
            if (ev.window.event == SDL_WINDOWEVENT_SIZE_CHANGED) {
                win_w = ev.window.data1;
                win_h = ev.window.data2;
                panel_div_x = win_w / 3;
            }
            break;
        case SDL_MOUSEBUTTONDOWN:
            break;
        default: break;
    }
}

void App::render() {
    SDL_SetRenderDrawColor(ren, 15, 15, 20, 255);
    SDL_RenderClear(ren);
    
    render_findings_list();
    render_detail_pane();
    render_status_bar();
    
    SDL_RenderPresent(ren);
}

void App::render_findings_list() {
    int x = 0, y = 0, w = panel_div_x, h = win_h - 40;
    
    draw_rect_filled(ren, x, y, w, h, 0xFF2A2A35);
    draw_rect_outline(ren, x, y, w, h, 0xFF444455);
    
    if (font) {
        draw_text(ren, "Findings", x + 10, y + 10, 0xFFFFFFFF);
        if (!current_result.findings.empty()) {
            std::string count = "(" + std::to_string(current_result.findings.size()) + ")";
            draw_text(ren, count, x + w - 60, y + 10, 0xFFAAAAAA);
        }
    }
    
    int item_height = 40;
    int visible = h / item_height;
    
    for (int i = list_scroll_offset; i < std::min(list_scroll_offset + visible, (int)current_result.findings.size()); ++i) {
        const auto& f = current_result.findings[i];
        int sel = (i == selected_finding_idx);
        
        Uint32 bg = sel ? 0xFF4A4A6A : 0xFF2A2A35;
        draw_rect_filled(ren, x, y + (i - list_scroll_offset) * item_height + 30,
                         w, item_height, bg);
        
        Uint32 sev_color = 0xFF666666;
        if (f.severity == "Critical") sev_color = 0xFFFF5555;
        else if (f.severity == "High") sev_color = 0xFFFFAA00;
        else if (f.severity == "Medium") sev_color = 0xFFFFFF00;
        else if (f.severity == "Low") sev_color = 0xFF55FF55;
        draw_rect_filled(ren, x + 10, y + 35 + (i - list_scroll_offset) * item_height,
                         8, 8, sev_color);
        
        if (font) {
            std::string line = f.pkg.name + " " + f.pkg.version;
            if (f.confidence == "High") line += " [GLSA]";
            draw_text(ren, line, x + 25, y + 38 + (i - list_scroll_offset) * item_height,
                      sel ? 0xFFFFFFFF : 0xFFCCCCCC);
            
            std::string info = f.pkg.manager + " | " + f.confidence + " conf";
            draw_text(ren, info, x + 300, y + 38 + (i - list_scroll_offset) * item_height,
                      0xFF888888);
        }
    }
}

void App::render_detail_pane() {
    int x = panel_div_x + 10, y = 0, w = win_w - panel_div_x - 30, h = win_h - 40;
    
    draw_rect_filled(ren, x, y, w, h, 0xFF2A2A35);
    draw_rect_outline(ren, x, y, w, h, 0xFF444455);
    
    if (font && selected_finding_idx >= 0 && selected_finding_idx < (int)current_result.findings.size()) {
        const auto& f = current_result.findings[selected_finding_idx];
        
        int cy = 20;
        
        draw_text(ren, "Package Details", x + 20, y + cy, 0xFFFFFFFF);
        cy += 30;
        
        draw_text(ren, "Name:", x + 20, y + cy, 0xFFAAAAAA);
        draw_text(ren, f.pkg.name, x + 100, y + cy, 0xFFFFFFFF);
        cy += 20;
        
        draw_text(ren, "Version:", x + 20, y + cy, 0xFFAAAAAA);
        draw_text(ren, f.pkg.version, x + 100, y + cy, 0xFFFFFFFF);
        cy += 20;
        
        draw_text(ren, "Manager:", x + 20, y + cy, 0xFFAAAAAA);
        draw_text(ren, f.pkg.manager, x + 100, y + cy, 0xFFFFFFFF);
        cy += 20;
        
        draw_text(ren, "Confidence:", x + 20, y + cy, 0xFFAAAAAA);
        std::string conf_str = f.confidence + " | Severity: " + f.severity;
        draw_text(ren, conf_str, x + 100, y + cy,
                  f.confidence == "High" ? 0xFF55FF55 : 0xFFCCCCCC);
        cy += 30;
        
        if (!f.fixed_version.empty()) {
            draw_text(ren, "Fixed version:", x + 20, y + cy, 0xFFAAAAAA);
            draw_text(ren, f.fixed_version, x + 140, y + cy, 0xFF55FF55);
            cy += 25;
        }
        
        cy += 10;
        draw_text(ren, "Related advisories:", x + 20, y + cy, 0xFFAAAAAA);
        cy += 20;
        
        for (int aid : f.advisory_ids) {
            if (aid >= 0 && aid < (int)current_result.advisories.size()) {
                const auto& a = current_result.advisories[aid];
                std::string line = a.id + " (" + a.source + ")";
                draw_text(ren, line, x + 30, y + cy, 0xFF88AAFF);
                cy += 18;
                std::string wrapped = a.title.size() > 60 ? a.title.substr(0, 60) + "..." : a.title;
                draw_text(ren, wrapped, x + 30, y + cy, 0xFFCCCCCC);
                cy += 16;
            }
        }
        
        if (!f.comments.empty() && cy < h - 100) {
            draw_text(ren, "---", x + 20, y + cy, 0xFF444444);
            cy += 15;
            draw_text(ren, "Security Comments:", x + 20, y + cy, 0xFFAAAAAA);
            cy += 20;
            
            for (const auto& cm : f.comments) {
                Uint32 tag_color = 0xFF888888;
                std::string tag_label = "[" + cm.tag + "] ";
                draw_text(ren, tag_label, x + 30, y + cy, tag_color);
                cy += 16;
                
                std::string txt = cm.text.size() > 80 ? cm.text.substr(0, 80) + "..." : cm.text;
                draw_text(ren, txt, x + 50, y + cy, 0xFFDDDDDD);
                cy += 16;
                
                if (!cm.origin.empty()) {
                    std::string origin = cm.origin.find("llm:") == 0 ? "[generated]" : "[templated]";
                    draw_text(ren, origin, x + 50, y + cy, 0xFF666666);
                    cy += 18;
                }
            }
        }
        
        if (cy < h - 50) {
            draw_text(ren, "---", x + 20, y + cy, 0xFF444444);
            cy += 15;
            draw_text(ren, "Press UP/DOWN or mouse wheel to navigate", x + 20, y + cy, 0xFF666666);
        }
    } else {
        draw_text(ren, "Select a finding to view details", x + 20, y + 100, 0xFF666666);
    }
}

void App::render_status_bar() {
    int x = 0, y = win_h - 25, w = win_w, h = 25;
    
    draw_rect_filled(ren, x, y, w, h, 0xFF1A1A22);
    draw_rect_outline(ren, x, y, w, h, 0xFF444455);
    
    std::string st = status_snapshot();
    if (st.empty()) st = "Ready";
    
    if (!current_result.notes.empty()) {
        st = current_result.notes.front();
    }
    
    if (font) {
        draw_text(ren, st, x + 10, y + 5, 0xFFAAAAAA);
    }
}

void App::scroll_findings_down(float dy) {
    list_scroll_offset += (int)(dy * 3);
    if (selected_finding_idx >= 0) {
        selected_finding_idx = std::min(selected_finding_idx + (int)dy,
                                        (int)current_result.findings.size() - 1);
    }
    if (list_scroll_offset < 0) list_scroll_offset = 0;
}

void App::scroll_findings_up(float dy) {
    list_scroll_offset -= (int)(dy * 3);
    if (selected_finding_idx >= 0) {
        selected_finding_idx = std::max(selected_finding_idx - (int)dy, 0);
    }
    if (list_scroll_offset < 0) list_scroll_offset = 0;
}

void App::select_finding(int idx) {
    if (idx >= 0 && idx < (int)current_result.findings.size())
        selected_finding_idx = idx;
}

void App::jump_to_finding(int idx) {
    select_finding(idx);
    list_scroll_offset = std::max(0, idx - 5);
}

int App::wrap_text_width(const std::string& text, int max_width, int char_width) const {
    int lines = 1;
    int cur = 0;
    for (char c : text) {
        if (c == '\n') { lines++; cur = 0; }
        else {
            cur++;
            if (cur * char_width >= max_width) { cur = 0; lines++; }
        }
    }
    return lines * char_width;
}

int App::text_height_multiline(const std::string& text, int max_width, int line_height) const {
    int chars_per_line = max_width / 8;
    int lines = 1;
    int cur = 0;
    for (char c : text) {
        if (c == '\n') { lines++; cur = 0; }
        else {
            cur++;
            if (cur >= chars_per_line) { cur = 0; lines++; }
        }
    }
    return lines * line_height;
}

void App::draw_rect_filled(SDL_Renderer* ren, int x, int y, int w, int h, Uint32 color) {
    SDL_Rect r{x, y, w, h};
    SDL_SetRenderDrawColor(ren,
                           (Uint8)((color >> 16) & 0xFF),
                           (Uint8)((color >> 8) & 0xFF),
                           (Uint8)(color & 0xFF),
                           (Uint8)((color >> 24) & 0xFF));
    SDL_RenderFillRect(ren, &r);
}

void App::draw_rect_outline(SDL_Renderer* ren, int x, int y, int w, int h, Uint32 color) {
    SDL_Rect r{x, y, w, h};
    SDL_SetRenderDrawColor(ren,
                           (Uint8)((color >> 16) & 0xFF),
                           (Uint8)((color >> 8) & 0xFF),
                           (Uint8)(color & 0xFF),
                           (Uint8)((color >> 24) & 0xFF));
    SDL_RenderDrawRect(ren, &r);
}

void App::draw_text(SDL_Renderer* ren, const std::string& text, int x, int y, Uint32 color) {
    if (!font) return;
    SDL_Color col{(Uint8)((color >> 16) & 0xFF),
                  (Uint8)((color >> 8) & 0xFF),
                  (Uint8)(color & 0xFF),
                  (Uint8)((color >> 24) & 0xFF)};
    SDL_Surface* surf = TTF_RenderUTF8_Blended(font, text.c_str(), col);
    if (!surf) return;
    SDL_Texture* tex = SDL_CreateTextureFromSurface(ren, surf);
    SDL_Rect dst{x, y, surf->w, surf->h};
    SDL_RenderCopy(ren, tex, nullptr, &dst);
    SDL_DestroyTexture(tex);
    SDL_FreeSurface(surf);
}

std::string App::truncate_text(const std::string& text, int max_chars) const {
    if ((int)text.size() <= max_chars) return text;
    return text.substr(0, max_chars - 3) + "...";
}

std::string App::status_snapshot() const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    return status_msg;
}

void App::update_status(const std::string& msg) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    status_msg = msg;
}

void App::append_log(const std::string& msg) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    log_lines.push_back(msg);
    if (log_lines.size() > 100) log_lines.erase(log_lines.begin());
}

void App::set_result(const ScanResult& result) {
    std::lock_guard<std::mutex> lock(result_mutex);
    current_result = result;
    selected_finding_idx = result.findings.empty() ? -1 : 0;
}
