#pragma once
#include "types.h"
#include "config.h"
#include "llm.h"
#include <SDL2/SDL.h>
#include <SDL2/SDL_ttf.h>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <thread>
#include <atomic>

class App {
public:
    App();
    ~App();
    
    bool init();
    void run(LlmClient* llm = nullptr);
    void shutdown();
    
    void set_result(const ScanResult& result);
    
    void update_status(const std::string& msg);
    void append_log(const std::string& msg);
    std::string status_snapshot() const;

private:
    void handle_event(const SDL_Event& ev);
    void render();
    void render_findings_list();
    void render_detail_pane();
    void render_status_bar();
    
    void scroll_findings_down(float dy);
    void scroll_findings_up(float dy);
    void select_finding(int idx);
    void jump_to_finding(int idx);
    
    int wrap_text_width(const std::string& text, int max_width, int char_width) const;
    int text_height_multiline(const std::string& text, int max_width,
                              int line_height) const;
    
    void draw_rect_filled(SDL_Renderer* ren, int x, int y, int w, int h, Uint32 color);
    void draw_rect_outline(SDL_Renderer* ren, int x, int y, int w, int h, Uint32 color);
    void draw_text(SDL_Renderer* ren, const std::string& text, int x, int y, Uint32 color);
    std::string truncate_text(const std::string& text, int max_chars) const;
    
    SDL_Window* win = nullptr;
    SDL_Renderer* ren = nullptr;
    TTF_Font* font = nullptr;
    TTF_Font* font_bold = nullptr;
    
    ScanResult current_result;
    std::vector<std::string> log_lines;
    std::string status_msg;
    
    int win_w = 1200, win_h = 800;
    int panel_div_x = 400;
    
    int list_scroll_offset = 0;
    int detail_scroll_y = 0;
    int selected_finding_idx = -1;
    
    bool running = true;
    
    std::atomic<bool> scan_done{false};
    ScanResult pending_result;
    std::mutex result_mutex;
    
    std::atomic<bool> worker_stop_{false};
    mutable std::mutex state_mutex_;
    bool shut_ = false;
    LlmClient* llm_ = nullptr;
    std::thread worker_;
    
    void worker_main(LlmClient* llm);
};
