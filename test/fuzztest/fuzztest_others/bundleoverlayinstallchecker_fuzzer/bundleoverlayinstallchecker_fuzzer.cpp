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
#include "bundleoverlayinstallchecker_fuzzer.h"

#include "bundle_overlay_install_checker.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
namespace OHOS {
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
constexpr uint32_t CODE_MAX = 8;
const std::string TEST_BUNDLE_NAME = "testBundleName";
const int32_t USERID = 100;

bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    BundleOverlayInstallChecker checker;
    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    int32_t overlayType = NON_OVERLAY_TYPE;
    checker.CheckOverlayInstallation(newInfos, USERID, overlayType);
    InnerBundleInfo innerBundleInfo;
    checker.CheckInternalBundle(newInfos, innerBundleInfo);
    checker.CheckExternalBundle(innerBundleInfo, USERID);
    checker.CheckTargetBundle(TEST_BUNDLE_NAME, "", "", USERID);
    InnerBundleInfo otherInnerBundleInfo;
    checker.CheckOverlayUpdate(innerBundleInfo, otherInnerBundleInfo, USERID);
    checker.CheckHapType(innerBundleInfo);
    checker.CheckBundleType(innerBundleInfo);
    checker.CheckTargetModule(TEST_BUNDLE_NAME, std::string(data, size));
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