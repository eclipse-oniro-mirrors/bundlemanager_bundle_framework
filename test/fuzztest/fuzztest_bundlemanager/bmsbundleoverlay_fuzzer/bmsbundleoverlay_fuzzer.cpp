/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "bmsbundleoverlay_fuzzer.h"
#include <string>

#define private public
#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "bms_fuzztest_util.h"
#include "bundle_overlay_data_manager.h"
#include "bundle_overlay_install_checker.h"
#include "bundle_overlay_manager.h"
#include "bundle_overlay_manager_host_impl.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    // bundle_overlay_manager.cpp
    std::string bundleName;
    std::string moduleName;
    bool isEnabled = fdp.ConsumeBool();
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    BundleOverlayManager::GetInstance()->IsExistedNonOverlayHap(bundleName);
    bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    BundleOverlayManager::GetInstance()->IsExistedNonOverlayHap(bundleName);
    BundleOverlayManager::GetInstance()->SetOverlayEnabled(bundleName, moduleName, isEnabled, userId);
    InnerBundleInfo info;
    BundleOverlayManager::GetInstance()->GetInnerBundleInfo(bundleName, info);
    std::vector<OverlayModuleInfo> overlayModuleInfos;
    OverlayModuleInfo overlayModuleInfo;
    BundleOverlayManager::GetInstance()->GetAllOverlayModuleInfo(bundleName, overlayModuleInfos, userId);
    BundleOverlayManager::GetInstance()->GetOverlayModuleInfo(bundleName, moduleName, overlayModuleInfo, userId);
    moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    BundleOverlayManager::GetInstance()->GetOverlayModuleInfo(bundleName, moduleName, overlayModuleInfo, userId);
    BundleOverlayManager::GetInstance()->SetOverlayEnabled(bundleName, moduleName, isEnabled, userId);
    std::string targetBundleName;
    std::string targetModuleName;
    BundleOverlayManager::GetInstance()->GetOverlayModuleInfoForTarget(targetBundleName, targetModuleName, overlayModuleInfos, userId);
    targetBundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    targetModuleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    BundleOverlayManager::GetInstance()->GetOverlayModuleInfoForTarget(targetBundleName, targetModuleName, overlayModuleInfos, userId);

    // bundle_overlay_data_manager.cpp
    bundleName = "";
    OverlayDataMgr::GetInstance()->IsExistedNonOverlayHap(bundleName);
    bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    OverlayDataMgr::GetInstance()->IsExistedNonOverlayHap(bundleName);
    InnerBundleInfo oldInfo;
    OverlayDataMgr::GetInstance()->BuildInternalOverlayConnection(moduleName, oldInfo, userId);
    std::string moduleHapPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string bundleDir;
    OverlayDataMgr::GetInstance()->GetBundleDir(moduleHapPath, bundleDir);
    
    bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    InnerBundleInfo targetInnerBundleInfo;
    OverlayDataMgr::GetInstance()->RemoveOverlayBundleInfo(moduleHapPath, info);
    OverlayDataMgr::GetInstance()->QueryOverlayInnerBundleInfo(bundleName, info);
    overlayModuleInfos.clear();
    OverlayDataMgr::GetInstance()->GetAllOverlayModuleInfo(bundleName, overlayModuleInfos, userId);
    OverlayDataMgr::GetInstance()->GetOverlayModuleInfo(bundleName, moduleName, overlayModuleInfo, userId);
    std::vector<OverlayBundleInfo> overlayBundleInfos;
    OverlayDataMgr::GetInstance()->GetOverlayBundleInfoForTarget(targetBundleName, overlayBundleInfos, userId);
    OverlayDataMgr::GetInstance()->GetOverlayModuleInfoForTarget(targetBundleName, targetModuleName, overlayModuleInfos, userId);
    OverlayDataMgr::GetInstance()->SetOverlayEnabled(bundleName, moduleName, isEnabled, userId);

    // bundle_overlay_install_checker.cpp
    BundleOverlayInstallChecker checker;
    int32_t priority = fdp.ConsumeIntegral<int32_t>();
    checker.CheckTargetPriority(priority);
    targetBundleName = "";
    targetModuleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string fingerprint = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    userId = fdp.ConsumeIntegral<int32_t>();
    checker.CheckTargetBundle(targetBundleName, targetModuleName, fingerprint, userId);
    checker.CheckTargetModule(targetBundleName, targetModuleName);
    targetBundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    checker.CheckTargetBundle(targetBundleName, targetModuleName, fingerprint, userId);
    checker.CheckTargetModule(targetBundleName, targetModuleName);

    // bundle_overlay_manager_host_impl.cpp
    OverlayManagerHostImpl hostImpl;
    bundleName = "";
    overlayModuleInfos.clear();
    hostImpl.GetAllOverlayModuleInfo(bundleName, overlayModuleInfos, userId);
    bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hostImpl.GetAllOverlayModuleInfo(bundleName, overlayModuleInfos, userId);
    moduleName = "";
    hostImpl.GetOverlayModuleInfo(bundleName, moduleName, overlayModuleInfo, userId);
    hostImpl.GetOverlayModuleInfo(moduleName, overlayModuleInfo, userId);
    moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hostImpl.GetOverlayModuleInfo(bundleName, moduleName, overlayModuleInfo, userId);
    hostImpl.GetOverlayModuleInfo(moduleName, overlayModuleInfo, userId);
    targetModuleName = "";
    hostImpl.GetTargetOverlayModuleInfo(targetModuleName, overlayModuleInfos, userId);
    targetModuleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hostImpl.GetTargetOverlayModuleInfo(targetModuleName, overlayModuleInfos, userId);
    bundleName = "";
    targetBundleName = "";
    hostImpl.GetOverlayModuleInfoByBundleName(bundleName, moduleName, overlayModuleInfos, userId);
    hostImpl.GetOverlayBundleInfoForTarget(targetBundleName, overlayBundleInfos, userId);
    hostImpl.GetOverlayModuleInfoForTarget(targetBundleName, targetModuleName, overlayModuleInfos, userId);
    bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    targetBundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hostImpl.GetOverlayModuleInfoByBundleName(bundleName, moduleName, overlayModuleInfos, userId);
    hostImpl.GetOverlayBundleInfoForTarget(targetBundleName, overlayBundleInfos, userId);
    hostImpl.GetOverlayModuleInfoForTarget(targetBundleName, targetModuleName, overlayModuleInfos, userId);
    moduleName = "";
    hostImpl.SetOverlayEnabledForSelf(moduleName, isEnabled, userId);
    hostImpl.SetOverlayEnabled(bundleName, moduleName, isEnabled, userId);
    moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hostImpl.SetOverlayEnabledForSelf(moduleName, isEnabled, userId);
    hostImpl.SetOverlayEnabled(bundleName, moduleName, isEnabled, userId);
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}