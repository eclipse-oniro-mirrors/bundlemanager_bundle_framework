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
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
constexpr size_t MESSAGE_SIZE = 4;
constexpr size_t DCAMERA_SHIFT_24 = 24;
constexpr size_t DCAMERA_SHIFT_16 = 16;
constexpr size_t DCAMERA_SHIFT_8 = 8;

void DoSomething2(const char* data, size_t size) {}

uint32_t GetU32Data(const char* ptr)
{
    return (ptr[0] << DCAMERA_SHIFT_24) | (ptr[1] << DCAMERA_SHIFT_16) | (ptr[2] << DCAMERA_SHIFT_8) | (ptr[3]);
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
    const AppQuickFix &appQuickFix = infos1.begin()->second;
    quickFixDeployer.ProcessHotReloadDeployStart(bundleInfo, appQuickFix);
    quickFixDeployer.ProcessPatchDeployEnd(appQuickFix, targetPath);
    quickFixDeployer.ProcessHotReloadDeployEnd(appQuickFix, targetPath);
    AppQuickFix newAppQuickFix;
    AppQuickFix oldAppQuickFix;
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
    DoSomething2(data, size);
    return true;
}
}
void DoSomething2(const char* data, size_t size)
{
    std::string targetPath(data, size);
    std::vector<std::string> bundlePaths;
    std::string hqfSoPath(data, size);
    QuickFixDeployer quickFixDeployer(bundlePaths, false, hqfSoPath);
    BundleInfo bundleInfo;
    HapModuleInfo info;
    info.moduleName = "entry";
    bundleInfo.hapModuleInfos.emplace_back(info);
    std::unordered_map<std::string, AppQuickFix> infos1;
    const AppQuickFix &appQuickFix = infos1.begin()->second;
    quickFixDeployer.ExtractQuickFixSoFile(appQuickFix, hqfSoPath, bundleInfo);
    std::string bundleName(data, size);
    std::string moduleName(data, size);
    InnerBundleInfo innerBundleInfo;
    quickFixDeployer.FetchInnerBundleInfo(bundleName, innerBundleInfo);
    AppqfInfo appqfInfo;
    HqfInfo hqfInfo;
    bool isLibIsolated = false;
    std::string nativeLibraryPath(data, size);
    std::string cpuAbi(data, size);
    quickFixDeployer.FetchPatchNativeSoAttrs(appqfInfo, hqfInfo, isLibIsolated,
        nativeLibraryPath, cpuAbi);
    quickFixDeployer.HasNativeSoInBundle(appQuickFix);
    quickFixDeployer.SendQuickFixSystemEvent(innerBundleInfo);
    quickFixDeployer.ExtractSoAndApplyDiff(appQuickFix, bundleInfo, hqfSoPath);
    quickFixDeployer.ExtractSoFiles(bundleInfo, moduleName, hqfSoPath);
    std::string oldSoPath(data, size);
    quickFixDeployer.ProcessApplyDiffPatch(appQuickFix,
        appQuickFix.deployingAppqfInfo.hqfInfos[0], oldSoPath, hqfSoPath, reinterpret_cast<uintptr_t>(data));
    quickFixDeployer.ExtractEncryptedSoFiles(bundleInfo, moduleName, reinterpret_cast<uintptr_t>(data), oldSoPath);
    bundleInfo.applicationInfo.compileSdkType = "";
    CodeSignatureParam codeSignatureParam;
    quickFixDeployer.PrepareCodeSignatureParam(appQuickFix, hqfInfo, bundleInfo, hqfSoPath, codeSignatureParam);
    InnerAppQuickFix innerAppQuickFix;
    innerAppQuickFix.SetAppQuickFix(appQuickFix);
    quickFixDeployer.VerifyCodeSignatureForHqf(innerAppQuickFix, oldSoPath);
    std::vector<std::string> bundleFilePaths;
    bundleFilePaths.push_back(targetPath);
    quickFixDeployer.CheckHqfResourceIsValid(bundleFilePaths, bundleInfo);
    quickFixDeployer.ExtractQuickFixResFile(appQuickFix, bundleInfo);
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