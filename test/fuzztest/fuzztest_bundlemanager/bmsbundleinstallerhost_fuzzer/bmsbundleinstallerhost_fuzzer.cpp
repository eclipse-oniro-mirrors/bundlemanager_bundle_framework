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

#include "bmsbundleinstallerhost_fuzzer.h"

#define private public

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "message_parcel.h"
#include "securec.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
constexpr size_t U32_AT_SIZE = 4;
constexpr size_t MESSAGE_SIZE = 10;
constexpr size_t CODE_MAX = 19;

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    auto bundleInstallerHost = std::make_unique<BundleInstallerHost>();
    FuzzedDataProvider fdp(data, size);
#ifdef ON_64BIT_SYSTEM
    for (uint32_t code = 0; code <= CODE_MAX; code++) {
        MessageParcel datas;
        std::u16string descriptor = BundleInstallerHost::GetDescriptor();
        datas.WriteInterfaceToken(descriptor);
        datas.WriteBuffer(data, size);
        datas.RewindRead(0);
        MessageParcel reply;
        MessageOption option;
        DelayedSingleton<BundleMgrService>::GetInstance()->OnStop();
        bundleInstallerHost->OnRemoteRequest(code, datas, reply, option);
    }
#endif
    int32_t userId = BMSFuzzTestUtil::GenerateRandomUser(fdp);
    int32_t appIndex = fdp.ConsumeIntegral<int32_t>();
    int32_t dplType = fdp.ConsumeIntegral<int32_t>();
    int32_t streamInstallerId = fdp.ConsumeIntegral<int32_t>();
    std::string bundleFilePath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string modulePackage = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string hostBundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string pluginFilePath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::vector<std::string> bundleFilePaths = GenerateStringArray(fdp);
    std::vector<std::string> pluginFilePaths = GenerateStringArray(fdp);
    InstallPluginParam installPluginParam;
    InstallParam installParam;
    GenerateInstallParam(fdp, installParam);

    UninstallParam uninstallParam;
    sptr<IStatusReceiver> statusReceiver;
    std::vector<std::string> originHapPaths = GenerateStringArray(fdp);
    bundleInstallerHost->Init();
    bundleInstallerHost->Install(bundleFilePath, installParam, statusReceiver);
    bundleInstallerHost->Recover(bundleName, installParam, statusReceiver);
    bundleInstallerHost->Install(bundleFilePaths, installParam, statusReceiver);
    bundleInstallerHost->Uninstall(bundleName, installParam, statusReceiver);
    bundleInstallerHost->Uninstall(bundleName, modulePackage, installParam, statusReceiver);
    bundleInstallerHost->Uninstall(uninstallParam, statusReceiver);
    bundleInstallerHost->InstallByBundleName(bundleName, installParam, statusReceiver);
    bundleInstallerHost->InstallSandboxApp(bundleName, dplType, userId, appIndex);
    bundleInstallerHost->UninstallSandboxApp(bundleName, appIndex, userId);
    bundleInstallerHost->InstallPlugin(hostBundleName, pluginFilePaths, installPluginParam);
    bundleInstallerHost->UninstallPlugin(hostBundleName, pluginFilePath, installPluginParam);
    bundleInstallerHost->CreateStreamInstaller(installParam, statusReceiver, originHapPaths);
    bundleInstallerHost->DestoryBundleStreamInstaller(streamInstallerId);
    bundleInstallerHost->StreamInstall(bundleFilePaths, installParam, statusReceiver);
    bundleInstallerHost->UpdateBundleForSelf(bundleFilePaths, installParam, statusReceiver);
    bundleInstallerHost->UninstallAndRecover(bundleName, installParam, statusReceiver);
    bundleInstallerHost->GetCurTaskNum();
    bundleInstallerHost->GetThreadsNum();
    bundleInstallerHost->InstallCloneApp(bundleName, userId, appIndex);
    bundleInstallerHost->UninstallCloneApp(bundleName, userId, appIndex, DestroyAppCloneParam());
    bundleInstallerHost->InstallExisted(bundleName, userId);
    bundleInstallerHost->CheckInstallParam(installParam);
    InstallParam installParam2;
    GenerateInstallParam(fdp, installParam2);
    bundleInstallerHost->IsPermissionVaild(installParam, installParam2);
    bundleInstallerHost->CheckBundleInstallerManager(statusReceiver);

    DestroyAppCloneParam destroyAppCloneParam;
    Parcel parcel;
    destroyAppCloneParam.Marshalling(parcel);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}