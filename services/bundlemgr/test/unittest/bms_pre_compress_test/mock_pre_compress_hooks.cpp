/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mock_pre_compress_hooks.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <mutex>
#include <sys/stat.h>
#include <unistd.h>

#include "directory_ex.h"
#include "mock_zstd.h"

namespace OHOS {
namespace AppExecFwk {
namespace PreCompressHook {
namespace {
constexpr const char* PRELOAD_APP_PREFIX = "/preload/app/";
constexpr const char* MOCK_DLOPEN_ERROR = "mock dlopen failed";
constexpr const char* MOCK_DLSYM_ERROR = "mock dlsym failed";
constexpr const char* MKDTEMP_PLACEHOLDER = "XXXXXX";
// fills the placeholder, the leading part names the regular file that blocks the dir
constexpr const char* BLOCKED_FILLING = "bk/blk";
constexpr size_t BLOCKED_FILE_NAME_LEN = 2;

std::mutex g_mutex;
DlopenMode g_dlopenMode = DlopenMode::REAL;
std::string g_missingSymbol;
void *g_mockLibHandle = nullptr;
std::string g_pendingError;
std::atomic<int32_t> g_dlopenCount { 0 };
std::atomic<int32_t> g_dlcloseCount { 0 };

std::string g_preloadRoot;
std::string g_openFailKeyword;
std::string g_realPathFailKeyword;
MkdtempMode g_mkdtempMode = MkdtempMode::REAL;
std::string g_blockedPath;

bool StartsWith(const std::string &str, const std::string &prefix)
{
    return str.compare(0, prefix.size(), prefix) == 0;
}

std::string MapToPreloadRoot(const std::string &path)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_preloadRoot.empty() && StartsWith(path, PRELOAD_APP_PREFIX)) {
        return g_preloadRoot + path;
    }
    return path;
}

bool ContainsKeyword(const std::string &path, const std::string &keyword)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    return !keyword.empty() && (path.find(keyword) != std::string::npos);
}

char *BlockTemplate(char *pathTemplate)
{
    std::string path(pathTemplate);
    size_t placeholderLen = std::strlen(MKDTEMP_PLACEHOLDER);
    size_t pos = path.rfind(MKDTEMP_PLACEHOLDER);
    if ((pos == std::string::npos) || (pos + placeholderLen != path.size())) {
        errno = EINVAL;
        return nullptr;
    }
    std::string blockedPath = path.substr(0, pos) + std::string(BLOCKED_FILLING, BLOCKED_FILE_NAME_LEN);
    int fd = open(blockedPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return nullptr;
    }
    close(fd);
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_blockedPath = blockedPath;
    }
    std::copy(BLOCKED_FILLING, BLOCKED_FILLING + placeholderLen, pathTemplate + pos);
    return pathTemplate;
}
}  // namespace

void SetDlopenMode(DlopenMode mode)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    g_dlopenMode = mode;
}

void SetMissingSymbol(const std::string &symbolName)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    g_missingSymbol = symbolName;
}

int32_t GetDlopenCount()
{
    return g_dlopenCount.load();
}

int32_t GetDlcloseCount()
{
    return g_dlcloseCount.load();
}

void ResetDlHooks()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    g_dlopenMode = DlopenMode::REAL;
    g_missingSymbol.clear();
    g_mockLibHandle = nullptr;
    g_pendingError.clear();
    g_dlopenCount.store(0);
    g_dlcloseCount.store(0);
}

void *HookDlopen(const char *file, int mode)
{
    ++g_dlopenCount;
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_dlopenMode == DlopenMode::FAIL) {
        g_pendingError = MOCK_DLOPEN_ERROR;
        return nullptr;
    }
    if (g_dlopenMode == DlopenMode::MOCK_LIB) {
        // a real handle of the test process stands for libzstd, its symbols are served by MockZstd
        g_mockLibHandle = dlopen(nullptr, RTLD_NOW);
        return g_mockLibHandle;
    }
    return dlopen(file, mode);
}

void *HookDlsym(void *handle, const char *symbolName)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    if ((g_dlopenMode != DlopenMode::MOCK_LIB) || (handle == nullptr) || (handle != g_mockLibHandle)) {
        return dlsym(handle, symbolName);
    }
    void *symbol = nullptr;
    if ((symbolName != nullptr) && (g_missingSymbol != symbolName)) {
        symbol = MockZstd::GetSymbol(symbolName);
    }
    if (symbol == nullptr) {
        g_pendingError = MOCK_DLSYM_ERROR;
    }
    return symbol;
}

int HookDlclose(void *handle)
{
    ++g_dlcloseCount;
    return dlclose(handle);
}

char *HookDlerror()
{
    static std::string error;
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_pendingError.empty()) {
        error = g_pendingError;
        g_pendingError.clear();
        return error.data();
    }
    return dlerror();
}

void SetPreloadRoot(const std::string &root)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    g_preloadRoot = root;
}

std::string MapPreloadPath(const std::string &path)
{
    return MapToPreloadRoot(path);
}

void SetOpenFailKeyword(const std::string &keyword)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    g_openFailKeyword = keyword;
}

void SetRealPathFailKeyword(const std::string &keyword)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    g_realPathFailKeyword = keyword;
}

void SetMkdtempMode(MkdtempMode mode)
{
    std::lock_guard<std::mutex> lock(g_mutex);
    g_mkdtempMode = mode;
}

std::string GetBlockedPath()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_blockedPath;
}

void ResetIoHooks()
{
    std::lock_guard<std::mutex> lock(g_mutex);
    g_preloadRoot.clear();
    g_openFailKeyword.clear();
    g_realPathFailKeyword.clear();
    g_mkdtempMode = MkdtempMode::REAL;
    if (!g_blockedPath.empty()) {
        (void)unlink(g_blockedPath.c_str());
        g_blockedPath.clear();
    }
}

int HookOpen(const char *path, int flags)
{
    std::string mappedPath = MapToPreloadRoot(path);
    if (ContainsKeyword(mappedPath, g_openFailKeyword)) {
        errno = EACCES;
        return -1;
    }
    return open(mappedPath.c_str(), flags);
}

int HookOpen(const char *path, int flags, mode_t mode)
{
    std::string mappedPath = MapToPreloadRoot(path);
    if (ContainsKeyword(mappedPath, g_openFailKeyword)) {
        errno = EACCES;
        return -1;
    }
    return open(mappedPath.c_str(), flags, mode);
}

DIR *HookOpendir(const char *path)
{
    return opendir(MapToPreloadRoot(path).c_str());
}

char *HookMkdtemp(char *pathTemplate)
{
    MkdtempMode mode = MkdtempMode::REAL;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        mode = g_mkdtempMode;
    }
    if (mode == MkdtempMode::FAIL) {
        errno = ENOSPC;
        return nullptr;
    }
    if (mode == MkdtempMode::BLOCKED) {
        return BlockTemplate(pathTemplate);
    }
    return mkdtemp(pathTemplate);
}

bool HookPathToRealPath(const std::string &path, std::string &realPath)
{
    if (ContainsKeyword(path, g_realPathFailKeyword)) {
        return false;
    }
    if (!OHOS::PathToRealPath(MapToPreloadRoot(path), realPath)) {
        return false;
    }
    std::lock_guard<std::mutex> lock(g_mutex);
    if (!g_preloadRoot.empty() && StartsWith(realPath, g_preloadRoot + PRELOAD_APP_PREFIX)) {
        realPath.erase(0, g_preloadRoot.size());
    }
    return true;
}
}  // namespace PreCompressHook
}  // namespace AppExecFwk
}  // namespace OHOS
