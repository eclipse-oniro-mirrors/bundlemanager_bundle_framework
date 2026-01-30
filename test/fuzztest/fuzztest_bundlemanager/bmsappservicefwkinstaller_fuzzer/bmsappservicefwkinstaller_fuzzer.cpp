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

#include "app_service_fwk_installer.h"

#include "bmsappservicefwkinstaller_fuzzer.h"
#include "bms_fuzztest_util.h"
#include "bundle_mgr_service.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
const int32_t VERSION_LOW = 0;
const std::string MODULE_NAME_TEST = "moduleName";
const std::string TEST_CREATE_FILE_PATH = "/data/test/resource/bms/app_service_test/test_create_dir/test.hap";
const std::string VERSION_ONE_LIBRARY_ONE_PATH =
  "/data/test/resource/bms/app_service_test/test_create_dir/test.hap";
namespace AppExecFwk {
    std::string ObtainTempSoPath(const std::string &moduleName, const std::string &nativeLibPath);
}
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    AppServiceFwkInstaller appServiceFwkInstaller;
    appServiceFwkInstaller.MarkInstallFinish();

    FuzzedDataProvider fdp(data, size);
    std::vector<std::string> hspPaths = GenerateStringArray(fdp);
    hspPaths.emplace_back("/system/app/appServiceFwk/test");
    InstallParam installParam;
    GenerateInstallParam(fdp, installParam);
    appServiceFwkInstaller.BeforeInstall(hspPaths, installParam);
    appServiceFwkInstaller.Install(hspPaths, installParam);

    std::string moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appServiceFwkInstaller.MoveSoToRealPath(moduleName, "", "");
    std::string nativeLibPath;
    ObtainTempSoPath(moduleName, nativeLibPath);

    nativeLibPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    ObtainTempSoPath(moduleName, nativeLibPath);

    std::string bundleName;
    bool isKeepData = fdp.ConsumeBool();
    appServiceFwkInstaller.UnInstall(bundleName, isKeepData);
    appServiceFwkInstaller.UnInstall(bundleName, moduleName);

    bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);

    InnerBundleInfo emptyInfo;
    appServiceFwkInstaller.CheckNeedUninstallBundle(moduleName, emptyInfo);

    InnerBundleInfo innerBundleInfo;
    InnerModuleInfo innerModuleInfo2;
    innerModuleInfo2.moduleName = "entry";
    innerModuleInfo2.distro.moduleType = "shared";
    innerBundleInfo.innerModuleInfos_["entry"] = innerModuleInfo2;
    appServiceFwkInstaller.CheckNeedUninstallBundle("entry", innerBundleInfo);
    appServiceFwkInstaller.CheckNeedUninstallBundle(moduleName, innerBundleInfo);
    appServiceFwkInstaller.RemoveModuleDataDir(bundleName, moduleName, innerBundleInfo);
    appServiceFwkInstaller.ProcessInstall(hspPaths, installParam);

    std::unordered_map<std::string, InnerBundleInfo> infos;
    appServiceFwkInstaller.CheckNeedInstall(infos, emptyInfo, isKeepData);
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    hapVerifyRes.emplace_back(Security::Verify::HapVerifyResult());
    infos["test"] = InnerBundleInfo();
    appServiceFwkInstaller.UpdateDeveloperId(infos, hapVerifyRes);
    appServiceFwkInstaller.CheckAppLabelInfo(infos);
    appServiceFwkInstaller.InnerProcessInstall(infos, installParam);
    appServiceFwkInstaller.CheckNeedInstall(infos, emptyInfo, isKeepData);
    std::string realHspPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string realSoPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appServiceFwkInstaller.VerifyCodeSignatureForHsp(realHspPath, realSoPath);
    std::string dir = "data/test";
    appServiceFwkInstaller.MkdirIfNotExist(dir);
    dir = "data/test/test";
    appServiceFwkInstaller.MkdirIfNotExist(dir);

    std::string bundlePath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string moduleDir = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string versionDir = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    InnerBundleInfo newInfo;
    bool copyHapToInstallPath = fdp.ConsumeBool();
    appServiceFwkInstaller.ProcessNativeLibrary(
        bundlePath, moduleDir, moduleName, versionDir, newInfo, copyHapToInstallPath);
    moduleName = "entry";
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = moduleName;
    innerModuleInfo.compressNativeLibs = false;
    innerModuleInfo.nativeLibraryPath = "x86";
    newInfo.innerModuleInfos_[moduleName] = innerModuleInfo;
    appServiceFwkInstaller.ProcessNativeLibrary(
        bundlePath, moduleDir, moduleName, versionDir, newInfo, copyHapToInstallPath);

    newInfo.baseApplicationInfo_->bundleName = bundleName;
    appServiceFwkInstaller.newInnerBundleInfo_ = newInfo;
    appServiceFwkInstaller.MergeBundleInfos(newInfo);

    appServiceFwkInstaller.newInnerBundleInfo_.baseBundleInfo_->isPreInstallApp = true;
    appServiceFwkInstaller.RollBack();
    appServiceFwkInstaller.ProcessNewModuleInstall(newInfo, innerBundleInfo, bundlePath, installParam);
    bool isAppExist = false;
    appServiceFwkInstaller.FetchInnerBundleInfo(emptyInfo, isAppExist);

    uint32_t versionCode = fdp.ConsumeIntegral<uint32_t>();
    appServiceFwkInstaller.versionUpgrade_ = true;
    appServiceFwkInstaller.RemoveLowerVersionSoDir(versionCode);
    appServiceFwkInstaller.MarkInstallFinish();
    appServiceFwkInstaller.UnInstall(bundleName, isKeepData);
    appServiceFwkInstaller.UnInstall(bundleName, moduleName);

    appServiceFwkInstaller.ResetProperties();
    appServiceFwkInstaller.appIdentifier_ = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appServiceFwkInstaller.RemoveInfo("");
    appServiceFwkInstaller.SaveBundleInfoToStorage();
    InstallParam installParam1;
    installParam1.additionalInfo = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    installParam1.needSavePreInstallInfo = true;
    appServiceFwkInstaller.SavePreInstallBundleInfo(ERR_APPEXECFWK_INSTALL_PARAM_ERROR, infos, installParam1);
    InstallParam installParam2;
    installParam2.isPreInstallApp = true;
    installParam2.removable = false;
    ErrCode result = 0;
    appServiceFwkInstaller.SendBundleSystemEvent(hspPaths,
        BundleEventType::INSTALL, installParam2, InstallScene::BOOT, result);
    std::vector<std::string> moduleNameList = GenerateStringArray(fdp);
    appServiceFwkInstaller.UninstallLowerVersion(moduleNameList);
    InstallParam installParam3;
    installParam3.copyHapToInstallPath = false;
    appServiceFwkInstaller.UpdateAppService(innerBundleInfo, infos, installParam3);
    std::string hspPath = ", path: ";
    InnerBundleInfo oldInfo;
    appServiceFwkInstaller.ProcessBundleUpdateStatus(oldInfo, newInfo, VERSION_ONE_LIBRARY_ONE_PATH, installParam3);
    appServiceFwkInstaller.ProcessModuleUpdate(innerBundleInfo, oldInfo, hspPath, installParam3);
    appServiceFwkInstaller.RemoveLowerVersionSoDir(VERSION_LOW);
    std::string cpuAbi = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string targetSoPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    appServiceFwkInstaller.VerifyCodeSignatureForNativeFiles(bundlePath, cpuAbi, targetSoPath);
    std::vector<Security::Verify::HapVerifyResult> hapVerifyResults;
    appServiceFwkInstaller.DeliveryProfileToCodeSign(hapVerifyResults);
    appServiceFwkInstaller.UpdateDeveloperId(infos, hapVerifyResults);
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
