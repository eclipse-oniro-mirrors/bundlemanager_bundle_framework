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

#include "bmsquickfixdeployer_fuzzer.h"
#include "bms_fuzztest_util.h"
#include "quick_fix_deployer.h"
#include "securec.h"
#include "inner_bundle_info.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;
const std::string BUNDLE_NAME_MMS = "com.ohos.mms";
const std::string MODULE_NAME = "entry";
const uint32_t QUICK_FIX_VERSION_CODE = 1;
const uint32_t BUNDLE_VERSION_CODE = 1;
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
    std::string targetPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    nlohmann::json jsonObject;
    std::vector<std::string> bundlePaths;
    QuickFixDeployer quickFixDeployer(bundlePaths, false, targetPath);
    quickFixDeployer.GetDeployQuickFixResult();
    quickFixDeployer.DeployQuickFix();

    InnerAppQuickFix oldInnerAppQuickFix;
    InnerAppQuickFix newInnerAppQuickFix;
    std::vector<std::string> bundleFilePaths;
    bundleFilePaths.push_back(targetPath);
    
    quickFixDeployer.ToDeployStartStatus(bundleFilePaths, newInnerAppQuickFix, oldInnerAppQuickFix);

    const AppQuickFix appQuickFix = CreateAppQuickFix();
    quickFixDeployer.ToDeployQuickFixResult(appQuickFix);

    BundleInfo bundleInfo;
    std::unordered_map<std::string, AppQuickFix> infos;
    quickFixDeployer.ProcessPatchDeployStart(bundleFilePaths, bundleInfo, infos);
    infos.emplace(BUNDLE_NAME_MMS, appQuickFix);
    quickFixDeployer.ProcessPatchDeployStart(bundleFilePaths, bundleInfo, infos);

    quickFixDeployer.ProcessHotReloadDeployStart(bundleInfo, appQuickFix);

    quickFixDeployer.ToDeployEndStatus(newInnerAppQuickFix, oldInnerAppQuickFix);

    QuickFixMark mark;
    mark.bundleName = appQuickFix.bundleName;
    mark.status = QuickFixStatus::DEPLOY_START;
    InnerAppQuickFix innerAppQuickFix(appQuickFix, mark);
    quickFixDeployer.ProcessNativeLibraryPath(targetPath, innerAppQuickFix);

    quickFixDeployer.isReplace_ = true;
    std::string nativeLibraryPath;
    quickFixDeployer.ProcessNativeLibraryPath(targetPath, innerAppQuickFix, nativeLibraryPath);

    quickFixDeployer.ProcessPatchDeployEnd(appQuickFix, targetPath);
    quickFixDeployer.ProcessHotReloadDeployEnd(appQuickFix, targetPath);
    quickFixDeployer.ParseAndCheckAppQuickFixInfos(bundleFilePaths, infos);
    quickFixDeployer.ResetNativeSoAttrs(infos);

    quickFixDeployer.IsLibIsolated(BUNDLE_NAME_MMS, MODULE_NAME);

    InnerBundleInfo innerBundleInfo;
    quickFixDeployer.FetchInnerBundleInfo(BUNDLE_NAME_MMS, innerBundleInfo);
    AppqfInfo appqfInfo;
    HqfInfo hqfInfo;
    std::string cpuAbi;
    quickFixDeployer.FetchPatchNativeSoAttrs(appqfInfo, hqfInfo, true, nativeLibraryPath, cpuAbi);
    quickFixDeployer.FetchPatchNativeSoAttrs(appqfInfo, hqfInfo, false, nativeLibraryPath, cpuAbi);

    quickFixDeployer.HasNativeSoInBundle(appQuickFix);
    quickFixDeployer.GetBundleInfo(BUNDLE_NAME_MMS, bundleInfo);
    quickFixDeployer.ToInnerAppQuickFix(infos, oldInnerAppQuickFix, newInnerAppQuickFix);

    AppQuickFix newAppQuickFix = CreateAppQuickFix();
    AppQuickFix oldAppQuickFix = CreateAppQuickFix();
    quickFixDeployer.CheckPatchVersionCode(newAppQuickFix, oldAppQuickFix);

    quickFixDeployer.SaveAppQuickFix(innerAppQuickFix);
    quickFixDeployer.MoveHqfFiles(innerAppQuickFix, targetPath);
    quickFixDeployer.GetDeployQuickFixResult();
    quickFixDeployer.GetQuickFixDataMgr();
    quickFixDeployer.SaveToInnerBundleInfo(newInnerAppQuickFix);

    std::vector<std::string> realPaths;
    quickFixDeployer.ProcessBundleFilePaths(bundleFilePaths, realPaths);
    quickFixDeployer.SendQuickFixSystemEvent(innerBundleInfo);
    quickFixDeployer.ExtractQuickFixSoFile(appQuickFix, "", bundleInfo);
    quickFixDeployer.ExtractSoAndApplyDiff(appQuickFix, bundleInfo, "");
    std::string tmpSoPath;
    quickFixDeployer.ExtractSoFiles(bundleInfo, "", tmpSoPath);

    quickFixDeployer.ProcessApplyDiffPatch(appQuickFix, hqfInfo, "", "", 0);

    quickFixDeployer.ExtractEncryptedSoFiles(bundleInfo, MODULE_NAME, 0, tmpSoPath);
    CodeSignatureParam codeSignatureParam;
    quickFixDeployer.PrepareCodeSignatureParam(appQuickFix, hqfInfo, bundleInfo, "", codeSignatureParam);

    quickFixDeployer.VerifyCodeSignatureForHqf(innerAppQuickFix, "");
    quickFixDeployer.CheckHqfResourceIsValid(bundleFilePaths, bundleInfo);
    quickFixDeployer.CheckReplaceMode(appQuickFix, bundleInfo);
    quickFixDeployer.ExtractQuickFixResFile(appQuickFix, bundleInfo);
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
