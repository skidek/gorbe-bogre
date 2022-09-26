#include <iostream>
#include "main.h"
#include <windows.h>
#include <psapi.h>
#include <locale>
#include <codecvt>
#include <vector>
#include <list>
#include <nlohmann/json.hpp>

#define debug
/*
 * print to stdout the number of suitable processes, offset and pid of result (if there is any)
 */

using json = nlohmann::json;

constexpr unsigned CHUNK_SIZE = 32;

int main() {
    std::list<std::string> strs = TokenScanner::scanForTokens();
    for (const auto& str : strs) {
        std::cout << str << "\n";
    }
    return 0;
}

std::tuple<std::string, std::string> tryGetProcessName(unsigned long pid) {

    HANDLE handle =
            OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);

    if (!handle) {
        return {"", "Unable to open process."};
    }

    wchar_t buffer[MAX_PATH];
    if (GetModuleFileNameExW(handle, 0, buffer, MAX_PATH)) {
        std::wstring processPath = buffer;
        int lastSlashPosition = processPath.find_last_of(L"\\");

        if (lastSlashPosition == std::string::npos) {
            lastSlashPosition = 0;
        } else {
            lastSlashPosition++;
        }

        std::wstring name = processPath.substr(
                lastSlashPosition, processPath.length() - lastSlashPosition);

        using convert_type = std::codecvt_utf8<wchar_t>;
        std::wstring_convert<convert_type, wchar_t> converter;
        std::string convertedName = converter.to_bytes(name.c_str());

        return {convertedName, "1"};
    }

    return {"", "Failed to read process name."};
}

std::vector<unsigned long> getSuitableProcesses(std::string desiredName) {
    std::vector<unsigned long> out;

    unsigned long allProcesses[2048];
    unsigned long cbNeeded = 0;

    if (EnumProcesses(allProcesses, sizeof(allProcesses), &cbNeeded)) {
        unsigned long processCount = cbNeeded / sizeof(unsigned long);

        for (unsigned long i = 0; i < processCount; i++) {
            unsigned long pid = allProcesses[i];



            std::tuple<std::string,std::string> nametup;
            nametup = tryGetProcessName(pid);

            if (get<0>(nametup).empty()) {
                continue;
            }

            if (get<0>(nametup).find(desiredName) != std::string::npos) {
                out.push_back(pid);
            }
        }
    }

    return out;
}

std::vector<std::string> tryFindAccessToken(unsigned long pid) {
    std::vector<std::string> out;

    char* buffer = new char[CHUNK_SIZE];

    HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);

    if (!handle) {
        return out;
    }

    char* pagePointer = 0;
    MEMORY_BASIC_INFORMATION memoryInfo;

    while (VirtualQueryEx(handle, pagePointer, &memoryInfo,
                          sizeof(MEMORY_BASIC_INFORMATION))) {
        if (memoryInfo.State == MEM_COMMIT &&
            memoryInfo.Protect == PAGE_READWRITE) {
            for (unsigned long long i = 0; i < memoryInfo.RegionSize;
                 i += CHUNK_SIZE) {
                void* readPointer = (void*)(pagePointer + i);

                if (ReadProcessMemory(handle, readPointer, buffer, CHUNK_SIZE,
                                      nullptr)) {
                    std::string bufferString = buffer;

                    if (bufferString.find("{\"access") != std::string::npos) {
#ifdef debug
                        std::cout << "Found potential token at " << i << "\n";

#endif

                        delete[] buffer;
                        buffer = new char[512];

                        if (ReadProcessMemory(handle, readPointer, buffer, 512,
                                              nullptr)) {
                            bufferString = buffer;

                            size_t tokenPosition =
                                    bufferString.find(R"({"accessToken":")");
                            if (tokenPosition != std::string::npos) {
#ifdef debug
                                std::cout << "It was real.\n";
#endif

                                out.push_back(bufferString.substr(
                                        tokenPosition,
                                        bufferString.length() - tokenPosition));
                            }
                        }
                    }
                }
            }
        }

        pagePointer += memoryInfo.RegionSize;
    }

    delete[] buffer;

    return out;
}

std::list<std::string> TokenScanner::scanForTokens() {
    std::list<std::string> out;

    auto foundProcesses = getSuitableProcesses("FyreMC.exe");

#ifdef debug
    std::cout << "Scanning " << foundProcesses.size() << " processes.\n";
#endif
    for (const auto pid : foundProcesses) {
        auto foundTokens = tryFindAccessToken(pid);

        for (const auto& str : foundTokens) {
            out.push_back(str);
#ifdef debug
            out.push_back(std::to_string(pid));
#endif
        }

        //TODO: ad-hoc validation

    }

    return out;

}