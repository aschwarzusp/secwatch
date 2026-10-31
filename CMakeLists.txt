cmake_minimum_required(VERSION 3.16)
project(secwatch VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SDL2 REQUIRED sdl2)
pkg_check_modules(SDL2_TTF REQUIRED SDL2_ttf)

add_executable(${PROJECT_NAME}
    src/main.cpp
    src/ui.cpp
    src/pkgs.cpp
    src/vuln.cpp
    src/util.cpp
    src/llm.cpp
    src/minijson.cpp
    src/config.cpp
    src/glsa.cpp
)

target_include_directories(${PROJECT_NAME} PRIVATE
    ${SDL2_INCLUDE_DIRS}
    ${SDL2_TTF_INCLUDE_DIRS}
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    ${SDL2_LIBRARIES}
    ${SDL2_TTF_LIBRARIES}
    curl
)

if(WIN32)
    target_compile_definitions(${PROJECT_NAME} PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

install(TARGETS ${PROJECT_NAME} DESTINATION bin)
