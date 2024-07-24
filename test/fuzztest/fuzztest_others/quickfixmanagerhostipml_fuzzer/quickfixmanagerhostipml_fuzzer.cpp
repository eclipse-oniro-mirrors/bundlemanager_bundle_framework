/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#define private public
#include "quickfixmanagerhostipml_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <iostream>

#include "quick_fix_manager_host_impl.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {

constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
constexpr size_t MESSAGE_SIZE = 21;
constexpr size_t DCAMERA_SHIFT_24 = 24;
constexpr size_t DCAMERA_SHIFT_16 = 16;
constexpr size_t DCAMERA_SHIFT_8 = 8;
uint32_t GetU32Data(const char* ptr)
{
    return (ptr[0] << DCAMERA_SHIFT_24) | (ptr[1] << DCAMERA_SHIFT_16) | (ptr[2] << DCAMERA_SHIFT_8) | (ptr[3]);
}
bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    QuickFixManagerHostImpl quickFixManagerHostImpl;
    std::vector<std::string> bundleFilePaths;
    sptr<IQuickFixStatusCallback> statusCallback = nullptr;
    std::string targetPath(data, size);
    quickFixManagerHostImpl.DeployQuickFix(bundleFilePaths, statusCallback, false, targetPath);
    std::string bundleName(data, size);
    quickFixManagerHostImpl.SwitchQuickFix(bundleName, false, statusCallback);
    quickFixManagerHostImpl.DeleteQuickFix(bundleName, statusCallback);
    std::string fileName(data, size);
    int32_t fd = static_cast<int32_t>(GetU32Data(data));
    std::string path(data, size);
    quickFixManagerHostImpl.CreateFd(fileName, fd, path);
    quickFixManagerHostImpl.GetQuickFixMgr();
    quickFixManagerHostImpl.IsFileNameValid(fileName);
    std::vector<std::string> securityFilePaths;
    quickFixManagerHostImpl.CopyHqfToSecurityDir(bundleFilePaths, securityFilePaths);
    return true;
}
} // namespace OHOS

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    /* Validate the length of size */
    if (size < OHOS::U32_AT_SIZE || size > OHOS::FOO_MAX_LEN) {
        return 0;
    }

    char* ch = (char*)malloc(size + 1);
    if (ch == nullptr) {
        std::cout << "malloc failed." << std::endl;
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size + 1, data, size) != EOK) {
        std::cout << "copy failed." << std::endl;
        free(ch);
        ch = nullptr;
        return 0;
    }

    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}