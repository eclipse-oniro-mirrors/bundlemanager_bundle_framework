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

#include "bmsbundleoverlayinstallerchecker_fuzzer.h"
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

    // bundle_overlay_installer_checker.cpp
    BundleOverlayInstallChecker bundleOverlayInstallChecker;

    std::unordered_map<std::string, InnerBundleInfo> newInfos;
    std::string bundleName = "bundle";
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.baseApplicationInfo_ = std::make_shared<ApplicationInfo>();
    innerBundleInfo.baseApplicationInfo_->bundleName = bundleName;
    newInfos[bundleName] = innerBundleInfo;
    innerBundleInfo.overlayType_ = NON_OVERLAY_TYPE;
    int32_t userId = GenerateRandomUser(fdp);
    int32_t overlayType = fdp.ConsumeIntegral<int32_t>();
    bundleOverlayInstallChecker.CheckOverlayInstallation(newInfos, userId, overlayType);

    newInfos[bundleName].overlayType_ = OVERLAY_INTERNAL_BUNDLE;
    bundleOverlayInstallChecker.CheckOverlayInstallation(newInfos, userId, overlayType);

    newInfos[bundleName].overlayType_ = OVERLAY_EXTERNAL_BUNDLE;
    bundleOverlayInstallChecker.CheckOverlayInstallation(newInfos, userId, overlayType);

    std::string moduleName = fdp.ConsumeBool() ? "entry" : "feature";
    innerBundleInfo.currentPackage_ = moduleName;
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.distro.moduleType = fdp.ConsumeBool() ? "shared" : "other";
    innerBundleInfo.innerModuleInfos_[moduleName] = innerModuleInfo;
    innerBundleInfo.baseBundleInfo_ = std::make_shared<BundleInfo>();
    innerBundleInfo.baseBundleInfo_->name = bundleName;
    innerBundleInfo.baseBundleInfo_->entryInstallationFree = fdp.ConsumeBool();
    bundleOverlayInstallChecker.CheckInternalBundle(newInfos, innerBundleInfo);

    InnerBundleInfo innerBundleInfo2;
    innerBundleInfo.baseBundleInfo_ = std::make_shared<BundleInfo>();
    innerBundleInfo.baseBundleInfo_->name = bundleName;
    innerBundleInfo.baseBundleInfo_->entryInstallationFree = true;
    bundleOverlayInstallChecker.CheckBundleType(innerBundleInfo2);
    innerBundleInfo2.currentPackage_ = moduleName;
    innerBundleInfo2.innerModuleInfos_[moduleName] = innerModuleInfo;
    innerBundleInfo2.innerModuleInfos_[moduleName].distro.moduleType = "shared";
    bundleOverlayInstallChecker.CheckHapType(innerBundleInfo2);
    bundleOverlayInstallChecker.CheckVersionCode(newInfos, innerBundleInfo2);
    bundleOverlayInstallChecker.CheckExternalBundle(innerBundleInfo, userId);
    std::string targetBundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string targetModuleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleOverlayInstallChecker.CheckTargetBundle("", "", "", userId);
    bundleOverlayInstallChecker.CheckTargetBundle(targetBundleName, "", "", userId);
    bundleOverlayInstallChecker.CheckTargetModule(bundleName, targetModuleName);

    innerBundleInfo.overlayType_ = OVERLAY_EXTERNAL_BUNDLE;
    innerBundleInfo2.overlayType_ = OVERLAY_INTERNAL_BUNDLE;
    bundleOverlayInstallChecker.CheckOverlayUpdate(innerBundleInfo, innerBundleInfo2, userId);
    innerBundleInfo.overlayType_ = OVERLAY_INTERNAL_BUNDLE;
    innerBundleInfo2.overlayType_ = OVERLAY_EXTERNAL_BUNDLE;
    bundleOverlayInstallChecker.CheckOverlayUpdate(innerBundleInfo, innerBundleInfo2, userId);
    innerBundleInfo.overlayType_ = OVERLAY_INTERNAL_BUNDLE;
    innerBundleInfo2.overlayType_ = OVERLAY_INTERNAL_BUNDLE;
    innerBundleInfo2.currentPackage_ = "other";
    bundleOverlayInstallChecker.CheckOverlayUpdate(innerBundleInfo, innerBundleInfo2, userId);
    innerBundleInfo2.currentPackage_ = moduleName;
    bundleOverlayInstallChecker.CheckOverlayUpdate(innerBundleInfo, innerBundleInfo2, userId);
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}