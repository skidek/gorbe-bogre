cmake_minimum_required(VERSION 3.23)
project(scantest)

set(CMAKE_CXX_STANDARD 20)

add_executable(scantest main.cpp)

set(JSON_BuildTests OFF CACHE INTERNAL "")

include(FetchContent)

FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.11.2/json.tar.xz)
FetchContent_MakeAvailable(json)

target_link_libraries(scantest PRIVATE nlohmann_json::nlohmann_json)