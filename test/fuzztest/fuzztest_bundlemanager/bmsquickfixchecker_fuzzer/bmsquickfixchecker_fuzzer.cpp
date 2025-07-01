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

#define private public
#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "parcel.h"

#include "bmsquickfixchecker_fuzzer.h"
#include "bms_fuzztest_util.h"
#include "quick_fix_checker.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
const std::string BUNDLE_NAME_MMS = "com.ohos.mms";
const std::string BUNDLE_NAME_DEMO = "com.ohos.demo";
const std::string MODULE_NAME = "entry";
const uint32_t QUICK_FIX_VERSION_CODE = 1;
const uint32_t BUNDLE_VERSION_CODE = 2;
const std::string QUICK_FIX_VERSION_NAME = "1.0";
const std::string BUNDLE_VERSION_NAME = "1.0";
AppQuickFix CreateAppQuickFix()
{
    AppqfInfo appInfo;
    appInfo.versionCode = QUICK_FIX_VERSION_CODE;
    appInfo.versionName = QUICK_FIX_VERSION_NAME;
    appInfo.type = QuickFixType::PATCH;
    appInfo.nativeLibraryPath = "data/";
    HqfInfo hqfInfo;
    hqfInfo.moduleName = "entry";
    hqfInfo.type = QuickFixType::PATCH;
    hqfInfo.nativeLibraryPath = "data/";
    appInfo.hqfInfos.push_back(hqfInfo);
    AppQuickFix appQuickFix;
    appQuickFix.bundleName = BUNDLE_NAME_MMS;
    appQuickFix.versionCode = BUNDLE_VERSION_CODE;
    appQuickFix.versionName = BUNDLE_VERSION_NAME;
    appQuickFix.deployingAppqfInfo = appInfo;
    return appQuickFix;
}
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    QuickFixChecker quickFixChecker;
    std::vector<std::string> bundlePaths = { fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH) };
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    quickFixChecker.CheckMultipleHqfsSignInfo(bundlePaths, hapVerifyRes);
    std::unordered_map<std::string, AppQuickFix> infos;
    AppQuickFix appQuickFix = CreateAppQuickFix();
    infos.emplace(BUNDLE_NAME_MMS, appQuickFix);
    quickFixChecker.CheckAppQuickFixInfos(infos);
    infos.emplace(BUNDLE_NAME_DEMO, appQuickFix);
    quickFixChecker.CheckAppQuickFixInfos(infos);

    ApplicationInfo applicationInfo;
    GenerateApplicationInfo(fdp, applicationInfo);
    BundleInfo bundleInfo;
    GenerateBundleInfo(fdp, bundleInfo);
    bundleInfo.applicationInfo = applicationInfo;
    AppqfInfo appqfInfo;
    appqfInfo.versionCode = QUICK_FIX_VERSION_CODE;
    appqfInfo.versionName = QUICK_FIX_VERSION_NAME;
    appqfInfo.type = QuickFixType::PATCH;
    appqfInfo.nativeLibraryPath = "data/";
    quickFixChecker.CheckPatchNativeSoWithInstalledBundle(bundleInfo, appqfInfo);
    appqfInfo.cpuAbi = "arm";
    bundleInfo.applicationInfo.cpuAbi = "arm";
    quickFixChecker.CheckPatchNativeSoWithInstalledBundle(bundleInfo, appqfInfo);

    quickFixChecker.CheckCommonWithInstalledBundle(appQuickFix, bundleInfo);
    BundleInfo installedBundleInfo;
    installedBundleInfo.name = BUNDLE_NAME_MMS;
    installedBundleInfo.versionCode = BUNDLE_VERSION_CODE;
    installedBundleInfo.applicationInfo.appQuickFix = appQuickFix;
    quickFixChecker.CheckCommonWithInstalledBundle(appQuickFix, bundleInfo);
    installedBundleInfo.applicationInfo.appQuickFix.versionCode = 1;
    quickFixChecker.CheckCommonWithInstalledBundle(appQuickFix, bundleInfo);

    Security::Verify::ProvisionInfo provisionInfo;
    quickFixChecker.CheckPatchWithInstalledBundle(appQuickFix, bundleInfo, provisionInfo);

    quickFixChecker.CheckHotReloadWithInstalledBundle(appQuickFix, bundleInfo);

    quickFixChecker.CheckModuleNameExist(bundleInfo, infos);

    provisionInfo.bundleInfo.apl = bundleInfo.applicationInfo.appPrivilegeLevel;
    quickFixChecker.CheckSignatureInfo(bundleInfo, provisionInfo);
    quickFixChecker.CheckSignatureInfo(bundleInfo, provisionInfo);

    quickFixChecker.CheckMultiNativeSo(infos);

    Security::Verify::AppDistType appDistType = Security::Verify::AppDistType::ENTERPRISE;
    quickFixChecker.GetAppDistributionType(appDistType);
    Security::Verify::ProvisionType provisionType = Security::Verify::ProvisionType::DEBUG;
    quickFixChecker.GetAppProvisionType(provisionType);
    provisionType = Security::Verify::ProvisionType::RELEASE;
    quickFixChecker.GetAppProvisionType(provisionType);
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
