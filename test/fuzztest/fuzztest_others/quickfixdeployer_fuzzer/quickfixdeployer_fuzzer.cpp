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

#include "quickfixdeployer_fuzzer.h"
#define private public
#include "quick_fix_deployer.h"
#include "securec.h"
#include "inner_bundle_info.h"

using namespace OHOS::AppExecFwk;
namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;
const std::string BUNDLE_NAME = "com.example.bmsaccesstoken1";
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
    HqfInfo hqfInfo;
    hqfInfo.moduleName = "entry";
    hqfInfo.type = QuickFixType::PATCH;
    appInfo.hqfInfos.push_back(hqfInfo);
    AppQuickFix appQuickFix;
    appQuickFix.bundleName = BUNDLE_NAME;
    appQuickFix.versionCode = BUNDLE_VERSION_CODE;
    appQuickFix.versionName = BUNDLE_VERSION_NAME;
    appQuickFix.deployingAppqfInfo = appInfo;
    return appQuickFix;
}

bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    std::string targetPath(data, size);
    nlohmann::json jsonObject;
    std::vector<std::string> bundlePaths;
    QuickFixDeployer quickFixDeployer(bundlePaths, false, targetPath);
    std::unordered_map<std::string, AppQuickFix> infos;
    InnerAppQuickFix oldInnerAppQuickFix;
    InnerAppQuickFix newInnerAppQuickFix;
    std::vector<std::string> bundleFilePaths;
    bundleFilePaths.push_back(targetPath);
    quickFixDeployer.GetDeployQuickFixResult();
    quickFixDeployer.DeployQuickFix();
    quickFixDeployer.GetQuickFixDataMgr();
    quickFixDeployer.SaveToInnerBundleInfo(newInnerAppQuickFix);
    quickFixDeployer.ToDeployEndStatus(newInnerAppQuickFix, oldInnerAppQuickFix);
    quickFixDeployer.ToDeployStartStatus(bundleFilePaths, newInnerAppQuickFix, oldInnerAppQuickFix);
    quickFixDeployer.ParseAndCheckAppQuickFixInfos(bundleFilePaths, infos);
    quickFixDeployer.ToInnerAppQuickFix(infos, oldInnerAppQuickFix, newInnerAppQuickFix);
    BundleInfo bundleInfo;
    std::string bundleName(data, size);
    quickFixDeployer.GetBundleInfo(bundleName, bundleInfo);
    quickFixDeployer.ProcessPatchDeployStart(bundleFilePaths, bundleInfo, infos);
    std::unordered_map<std::string, AppQuickFix> infos1;
    const AppQuickFix appQuickFix = CreateAppQuickFix();
    quickFixDeployer.ProcessHotReloadDeployStart(bundleInfo, appQuickFix);
    quickFixDeployer.ProcessPatchDeployEnd(appQuickFix, targetPath);
    quickFixDeployer.ProcessHotReloadDeployEnd(appQuickFix, targetPath);
    AppQuickFix newAppQuickFix = CreateAppQuickFix();
    AppQuickFix oldAppQuickFix = CreateAppQuickFix();
    quickFixDeployer.CheckPatchVersionCode(newAppQuickFix, oldAppQuickFix);
    QuickFixMark mark;
    mark.bundleName = appQuickFix.bundleName;
    mark.status = QuickFixStatus::DEPLOY_START;
    InnerAppQuickFix innerAppQuickFix(appQuickFix, mark);
    quickFixDeployer.SaveAppQuickFix(innerAppQuickFix);
    quickFixDeployer.MoveHqfFiles(innerAppQuickFix, targetPath);
    std::vector<std::string> realPaths;
    quickFixDeployer.ProcessBundleFilePaths(bundleFilePaths, realPaths);
    quickFixDeployer.ToDeployQuickFixResult(appQuickFix);
    quickFixDeployer.ProcessNativeLibraryPath(targetPath, innerAppQuickFix);
    quickFixDeployer.ResetNativeSoAttrs(infos1);
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