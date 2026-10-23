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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_TEST_UNITTEST_BMS_PRE_COMPRESS_TEST_MOCK_PRE_COMPRESS_HOOKS_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_TEST_UNITTEST_BMS_PRE_COMPRESS_TEST_MOCK_PRE_COMPRESS_HOOKS_H

#include <cstdint>
#include <dirent.h>
#include <string>
#include <sys/types.h>

// The cases compile pre_compress_handler.cpp and zstd_wrapper.cpp into their own translation unit and route the
// system calls listed below to these hooks. Every hook calls the real function unless a case sets a mode, and
// every case resets the hooks when it ends.
namespace OHOS {
namespace AppExecFwk {
namespace PreCompressHook {
enum class DlopenMode {
    REAL,
    FAIL,
    // libzstd is served by MockZstd
    MOCK_LIB,
};

enum class MkdtempMode {
    REAL,
    FAIL,
    // the template is filled in with a path whose parent is a regular file, so it can not be created as a dir
    BLOCKED,
};

void SetDlopenMode(DlopenMode mode);
void SetMissingSymbol(const std::string &symbolName);
int32_t GetDlopenCount();
int32_t GetDlcloseCount();
void ResetDlHooks();

void *HookDlopen(const char *file, int mode);
void *HookDlsym(void *handle, const char *symbolName);
int HookDlclose(void *handle);
char *HookDlerror();

/**
 * @brief Serve the preload image dir /preload/app/ from root/preload/app/, root must be a real path.
 */
void SetPreloadRoot(const std::string &root);
/**
 * @brief The path a path under /preload/app/ is served from, other paths are given back as they are.
 */
std::string MapPreloadPath(const std::string &path);
void SetOpenFailKeyword(const std::string &keyword);
void SetRealPathFailKeyword(const std::string &keyword);
void SetMkdtempMode(MkdtempMode mode);
std::string GetBlockedPath();
void ResetIoHooks();

int HookOpen(const char *path, int flags);
int HookOpen(const char *path, int flags, mode_t mode);
DIR *HookOpendir(const char *path);
char *HookMkdtemp(char *pathTemplate);
bool HookPathToRealPath(const std::string &path, std::string &realPath);
}  // namespace PreCompressHook
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_TEST_UNITTEST_BMS_PRE_COMPRESS_TEST_MOCK_PRE_COMPRESS_HOOKS_H
