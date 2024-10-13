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
#include "overlaydatamgr_fuzzer.h"

#include "bundle_overlay_data_manager.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
namespace OHOS {
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
constexpr uint32_t CODE_MAX = 8;
const std::string TEST_PACK_AGE = "modulePackage";
const std::string TARGET_MODULE_NAME = "targetModuleName";
const int32_t USERID = 100;

bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    OverlayDataMgr overlayDataMgr;
    std::string bundleName(data, size);
    overlayDataMgr.IsExistedNonOverlayHap(bundleName);
    InnerBundleInfo newInfo;
    InnerBundleInfo oldInfo;
    InnerBundleInfo targetInnerBundleInfo;
    overlayDataMgr.UpdateOverlayInfo(newInfo, oldInfo, targetInnerBundleInfo);
    overlayDataMgr.UpdateInternalOverlayInfo(newInfo, oldInfo);
    overlayDataMgr.UpdateExternalOverlayInfo(newInfo, oldInfo, targetInnerBundleInfo);
    overlayDataMgr.BuildOverlayConnection(newInfo, oldInfo);
    std::string moduleHapPath(data, size);
    std::string bundleDir(data, size);
    overlayDataMgr.GetBundleDir(moduleHapPath, bundleDir);
    overlayDataMgr.RemoveOverlayModuleConnection(newInfo, oldInfo);
    overlayDataMgr.RemoveOverlayBundleInfo(bundleName, targetInnerBundleInfo);
    overlayDataMgr.RemoveOverlayModuleInfo(bundleName, TEST_PACK_AGE, oldInfo, targetInnerBundleInfo);
    overlayDataMgr.BuildInternalOverlayConnection(TARGET_MODULE_NAME, oldInfo, USERID);
    overlayDataMgr.QueryOverlayInnerBundleInfo(bundleName, oldInfo);
    OverlayModuleInfo overlayModuleInfo;
    overlayDataMgr.SaveInternalOverlayModuleState(overlayModuleInfo, oldInfo);
    overlayDataMgr.SaveExternalOverlayModuleState(overlayModuleInfo, targetInnerBundleInfo, USERID, oldInfo);
    std::map<std::string, InnerModuleInfo> innerModuleInfos;
    overlayDataMgr.ResetInternalOverlayModuleState(innerModuleInfos, TARGET_MODULE_NAME, oldInfo);
    std::vector<OverlayModuleInfo> overlayModuleInfos;
    overlayDataMgr.GetAllOverlayModuleInfo(bundleName, overlayModuleInfos, USERID);
    overlayDataMgr.GetOverlayModuleInfo(bundleName, TARGET_MODULE_NAME, overlayModuleInfo, USERID);
    std::vector<OverlayBundleInfo> overlayBundleInfos;
    overlayDataMgr.GetOverlayBundleInfoForTarget(bundleName, overlayBundleInfos, USERID);
    overlayDataMgr.GetOverlayModuleInfoForTarget(bundleName, TARGET_MODULE_NAME, overlayModuleInfos, USERID);
    overlayDataMgr.SetOverlayEnabled(bundleName, TARGET_MODULE_NAME, true, USERID);
    overlayDataMgr.GetCallingBundleName();
    InnerBundleUserInfo userInfo;
    overlayDataMgr.AddOverlayModuleStates(newInfo, userInfo);
    overlayDataMgr.UpdateOverlayModule(newInfo, oldInfo);
    overlayDataMgr.GetBundleDataMgr();
    overlayDataMgr.GetModulesStateFromUserInfo(userInfo);
    overlayDataMgr.ObtainOverlayModuleState(overlayModuleInfo, USERID);
    overlayDataMgr.GetOverlayModuleInfoForTarget(oldInfo, overlayModuleInfos, USERID);
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