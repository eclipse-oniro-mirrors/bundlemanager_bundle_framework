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

#include "bmsbundleoverlaydatamgr_fuzzer.h"
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

    // bundle_overlay_data_manager.cpp
    auto overlayDataMgr = OverlayDataMgr::GetInstance();
    if (overlayDataMgr == nullptr) {
        return false;
    }
    InnerBundleInfo newInfo;
    InnerBundleInfo oldInfo;
    InnerBundleInfo targetInnerBundleInfo;

    newInfo.overlayType_ = OVERLAY_INTERNAL_BUNDLE;
    overlayDataMgr->UpdateOverlayInfo(newInfo, oldInfo, targetInnerBundleInfo);
    newInfo.overlayType_ = OVERLAY_EXTERNAL_BUNDLE;
    overlayDataMgr->UpdateOverlayInfo(newInfo, oldInfo, targetInnerBundleInfo);
    newInfo.overlayType_ = NON_OVERLAY_TYPE;
    overlayDataMgr->UpdateOverlayInfo(newInfo, oldInfo, targetInnerBundleInfo);
    newInfo.overlayType_ = 0;
    overlayDataMgr->UpdateOverlayInfo(newInfo, oldInfo, targetInnerBundleInfo);

    std::string bundleName;
    overlayDataMgr->IsExistedNonOverlayHap(bundleName);
    bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    overlayDataMgr->dataMgr_ = std::make_shared<BundleDataMgr>();
    overlayDataMgr->IsExistedNonOverlayHap(bundleName);

    std::string moduleName = fdp.ConsumeBool() ? "entry" : "feature";
    newInfo.innerModuleInfos_[moduleName] = InnerModuleInfo();
    newInfo.innerModuleInfos_[moduleName].modulePackage = moduleName;
    newInfo.innerModuleInfos_[moduleName].isEntry = (moduleName == "entry");
    newInfo.innerModuleInfos_[moduleName].moduleName = moduleName;
    newInfo.innerModuleInfos_[moduleName].bundleType = BundleType::APP;
    newInfo.innerModuleInfos_[moduleName].targetModuleName = fdp.ConsumeBool() ? "target" : "";
    newInfo.innerModuleInfos_[moduleName].versionCode = fdp.ConsumeIntegral<int32_t>();
    newInfo.innerModuleInfos_[moduleName].modulePath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    newInfo.innerModuleInfos_[moduleName].moduleResPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    overlayDataMgr->UpdateInternalOverlayInfo(newInfo, oldInfo);
    overlayDataMgr->BuildOverlayConnection(newInfo, oldInfo);
    overlayDataMgr->RemoveOverlayModuleConnection(newInfo, oldInfo);
    overlayDataMgr->RemoveOverlayBundleInfo(bundleName, targetInnerBundleInfo);
    overlayDataMgr->UpdateExternalOverlayInfo(newInfo, oldInfo, targetInnerBundleInfo);
    targetInnerBundleInfo.baseApplicationInfo_->bundleName = "target";
    overlayDataMgr->UpdateExternalOverlayInfo(newInfo, oldInfo, targetInnerBundleInfo);

    oldInfo.overlayType_ = OVERLAY_INTERNAL_BUNDLE;
    int32_t userId = GenerateRandomUser(fdp);
    overlayDataMgr->BuildInternalOverlayConnection(moduleName, oldInfo, userId);
    overlayDataMgr->RemoveOverlayModuleInfo(bundleName, moduleName, newInfo, targetInnerBundleInfo);
    newInfo.overlayType_ = OVERLAY_INTERNAL_BUNDLE;
    overlayDataMgr->RemoveOverlayModuleInfo(bundleName, moduleName, newInfo, targetInnerBundleInfo);
    newInfo.overlayType_ = OVERLAY_EXTERNAL_BUNDLE;
    overlayDataMgr->RemoveOverlayModuleInfo(bundleName, moduleName, newInfo, targetInnerBundleInfo);
    newInfo.overlayType_ = NON_OVERLAY_TYPE;
    overlayDataMgr->RemoveOverlayModuleInfo(bundleName, moduleName, newInfo, targetInnerBundleInfo);

    InnerModuleInfo moduleInfo;
    moduleInfo.modulePackage = moduleName;
    moduleInfo.targetModuleName = moduleName;
    std::map<std::string, InnerModuleInfo> moduleInfos;
    moduleInfos[moduleName] = moduleInfo;
    overlayDataMgr->ResetInternalOverlayModuleState(moduleInfos, moduleName, oldInfo);
    overlayDataMgr->GetBundleDataMgr();
    OverlayModuleInfo overlayModuleInfo;
    overlayDataMgr->dataMgr_->multiUserIdsSet_.insert(GenerateRandomUser(fdp));
    overlayDataMgr->dataMgr_->multiUserIdsSet_.insert(userId);
    overlayDataMgr->SaveInternalOverlayModuleState(overlayModuleInfo, oldInfo);
    overlayDataMgr->SaveExternalOverlayModuleState(overlayModuleInfo, targetInnerBundleInfo, userId, oldInfo);
    std::vector<OverlayModuleInfo> overlayModuleInfos;
    overlayDataMgr->GetAllOverlayModuleInfo(bundleName, overlayModuleInfos, userId);
    overlayDataMgr->GetOverlayModuleInfo(bundleName, moduleName, overlayModuleInfo, userId);
    std::vector<OverlayBundleInfo> overlayBundleInfo;
    overlayDataMgr->GetOverlayBundleInfoForTarget(bundleName, overlayBundleInfo, userId);
    overlayDataMgr->GetOverlayModuleInfoForTarget(bundleName, moduleName, overlayModuleInfos, userId);
    overlayDataMgr->GetOverlayModuleInfoForTarget(newInfo, overlayModuleInfos, userId);
    overlayDataMgr->ObtainOverlayModuleState(overlayModuleInfo, userId);
    bool isEnabled = fdp.ConsumeBool();
    overlayDataMgr->SetOverlayEnabled(bundleName, moduleName, isEnabled, userId);
    overlayDataMgr->GetCallingBundleName();
    InnerBundleUserInfo userInfo;
    overlayDataMgr->AddOverlayModuleStates(newInfo, userInfo);
    newInfo.overlayType_ = OVERLAY_INTERNAL_BUNDLE;
    overlayDataMgr->UpdateOverlayModule(newInfo, oldInfo);
    newInfo.isNewVersion_ = false;
    oldInfo.isNewVersion_ = true;
    newInfo.overlayType_ = NON_OVERLAY_TYPE;
    overlayDataMgr->UpdateOverlayModule(newInfo, oldInfo);
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}