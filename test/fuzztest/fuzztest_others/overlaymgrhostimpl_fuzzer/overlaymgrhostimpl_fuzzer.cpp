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
#include "overlaymgrhostimpl_fuzzer.h"

#include "bundle_overlay_manager_host_impl.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
namespace OHOS {
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
constexpr uint32_t CODE_MAX = 8;
const int32_t USERID = 100;

bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    OverlayManagerHostImpl overlayManagerHostImpl;
    std::vector<OverlayModuleInfo> overlayModuleInfos;
    std::string bundleName(data, size);
    overlayManagerHostImpl.GetAllOverlayModuleInfo(bundleName, overlayModuleInfos, USERID);
    OverlayModuleInfo overlayModuleInfo;
    std::string moduleName(data, size);
    overlayManagerHostImpl.GetOverlayModuleInfo(bundleName, moduleName, overlayModuleInfo, USERID);
    overlayManagerHostImpl.GetOverlayModuleInfo(moduleName, overlayModuleInfo, USERID);
    std::string targetModuleName(data, size);
    overlayManagerHostImpl.GetTargetOverlayModuleInfo(targetModuleName, overlayModuleInfos, USERID);
    overlayManagerHostImpl.GetOverlayModuleInfoByBundleName(bundleName, moduleName, overlayModuleInfos, USERID);
    std::string targetBundleName(data, size);
    std::vector<OverlayBundleInfo> overlayBundleInfos;
    overlayManagerHostImpl.GetOverlayBundleInfoForTarget(targetBundleName, overlayBundleInfos, USERID);
    overlayManagerHostImpl.GetOverlayModuleInfoForTarget(targetBundleName,
        targetModuleName, overlayModuleInfos, USERID);
    overlayManagerHostImpl.SetOverlayEnabledForSelf(moduleName, true, USERID);
    overlayManagerHostImpl.SetOverlayEnabled(bundleName, moduleName, true, USERID);
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        return 0;
    }

    if (size < OHOS::U32_AT_SIZE) {
        return 0;
    }

    /* Validate the length of size */
    if (size > OHOS::FOO_MAX_LEN) {
        return 0;
    }

    char* ch = static_cast<char*>(malloc(size + 1));
    if (ch == nullptr) {
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size, data, size) != EOK) {
        free(ch);
        ch = nullptr;
        return 0;
    }
    OHOS::DoSomethingInterestingWithMyAPI(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}