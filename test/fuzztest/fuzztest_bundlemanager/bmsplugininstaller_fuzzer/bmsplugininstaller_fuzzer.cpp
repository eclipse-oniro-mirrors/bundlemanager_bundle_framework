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

#include "plugin_installer.h"

#include "bmsplugininstaller_fuzzer.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    PluginInstaller installer;
    InstallPluginParam installPluginParam;

    FuzzedDataProvider fdp(data, size);
    std::string hostBundleName;
    std::vector<std::string> pluginFilePaths = GenerateStringArray(fdp);
    std::string pluginBundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);

    installPluginParam.userId = Constants::UNSPECIFIED_USERID;
    installer.InstallPlugin(hostBundleName, pluginFilePaths, installPluginParam);
    installer.UninstallPlugin(hostBundleName, pluginBundleName, installPluginParam);
    std::vector<std::string> pluginFilePaths2;
    installer.ParseFiles(pluginFilePaths2, installPluginParam);

    installPluginParam.userId = Constants::START_USERID;
    installer.InstallPlugin(hostBundleName, pluginFilePaths, installPluginParam);
    installer.UninstallPlugin(hostBundleName, pluginBundleName, installPluginParam);
    installer.ParseFiles(pluginFilePaths2, installPluginParam);

    std::string dir = "data/test";
    installer.MkdirIfNotExist(dir);

    dir = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    installer.MkdirIfNotExist(dir);

    std::vector<std::string> inBundlePaths;
    std::vector<std::string> parsedPaths;
    installer.ParseHapPaths(installPluginParam, inBundlePaths, parsedPaths);
    installer.ParseHapPaths(installPluginParam, pluginFilePaths, parsedPaths);
    std::string signatureFilePath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    installer.ObtainHspFileAndSignatureFilePath(inBundlePaths, parsedPaths, signatureFilePath);
    installer.CopyHspToSecurityDir(inBundlePaths, installPluginParam);
    std::vector<Security::Verify::HapVerifyResult> hapVerifyResults;
    installer.DeliveryProfileToCodeSign(hapVerifyResults);

    inBundlePaths.emplace_back(fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    installer.ObtainHspFileAndSignatureFilePath(inBundlePaths, parsedPaths, signatureFilePath);
    installer.ObtainHspFileAndSignatureFilePath(pluginFilePaths, parsedPaths, signatureFilePath);
    installer.CopyHspToSecurityDir(pluginFilePaths, installPluginParam);

    std::string bundlePath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string moduleDir = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string pluginBundleDir = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    InnerBundleInfo newInfo;
    installer.ProcessNativeLibrary(bundlePath, moduleDir, moduleName, pluginBundleDir, newInfo);
    moduleName = "entry";
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.moduleName = moduleName;
    innerModuleInfo.compressNativeLibs = false;
    innerModuleInfo.nativeLibraryPath = "x86";
    newInfo.innerModuleInfos_[moduleName] = innerModuleInfo;
    installer.ProcessNativeLibrary(bundlePath, moduleDir, moduleName, pluginBundleDir, newInfo);
    std::string cpuAbi = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bool isPreInstalledBundle = fdp.ConsumeBool();
    installer.VerifyCodeSignatureForNativeFiles(bundlePath, cpuAbi,
        bundlePath, signatureFilePath, isPreInstalledBundle);
    std::string appIdentifier = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bool isEnterpriseBundle = fdp.ConsumeBool();
    bool isCompileSdkOpenHarmony = fdp.ConsumeBool();
    installer.VerifyCodeSignatureForHsp(bundlePath, appIdentifier, isEnterpriseBundle, isCompileSdkOpenHarmony);

    installer.CheckPluginId(hostBundleName);
    installer.pluginIds_ = pluginFilePaths;
    installer.CheckPluginId(hostBundleName);

    std::string appServiceCapabilities;
    std::vector<std::string> pluginIds;
    installer.ParsePluginId(appServiceCapabilities, pluginIds);
    appServiceCapabilities = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    installer.ParsePluginId(appServiceCapabilities, pluginIds);
    installer.CheckSupportPluginPermission(hostBundleName);
    installer.CheckPluginAppLabelInfo();
    installer.ProcessPluginInstall(newInfo);
    installer.parsedBundles_[hostBundleName] = InnerBundleInfo();
    installer.ProcessPluginInstall(newInfo);
    installer.CheckPluginAppLabelInfo();
    installer.CreatePluginDir(hostBundleName, moduleDir);
    installer.CheckAppIdentifier();
    installer.CheckVersionCodeForUpdate();
    installer.ExtractPluginBundles(bundlePath, newInfo, moduleDir);
    installer.MergePluginBundleInfo(newInfo);
    InnerBundleInfo hostBundleInfo;
    installer.SavePluginInfoToStorage(newInfo, hostBundleInfo);
    installer.PluginRollBack(hostBundleName);
    installer.RemovePluginDir(hostBundleInfo);
    installer.SaveHspToInstallDir(bundlePath, moduleDir, moduleName, newInfo);
    installer.RemoveEmptyDirs(moduleDir);
    installer.RemoveDir(moduleDir);
    installer.ProcessPluginUninstall(hostBundleInfo);
    installer.RemoveOldInstallDir();
    installer.isPluginExist_ = true;
    installer.RemoveOldInstallDir();
    installer.UninstallRollBack(hostBundleName);
    installer.GetModuleNames();
    NotifyType type = static_cast<NotifyType>(fdp.ConsumeIntegralInRange<uint8_t>(0, ORIENTATION_MAX));
    int32_t uid = fdp.ConsumeIntegral<int32_t>();
    installer.NotifyPluginEvents(type, uid);
    InnerBundleInfo pluginInfo;
    installer.UpdateRouterInfoForPlugin(hostBundleName, pluginInfo);
    installer.DeleteRouterInfoForPlugin(hostBundleName);
    installer.SendPluginCommonEvent(hostBundleName, pluginBundleName, NotifyType::INSTALL);
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
