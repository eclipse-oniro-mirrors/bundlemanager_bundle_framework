/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "bundleinstallerhost_fuzzer.h"

#define private public

#include <cstddef>
#include <cstdint>
#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "message_parcel.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
namespace OHOS {
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
constexpr size_t MESSAGE_SIZE = 10;
constexpr size_t CODE_MAX = 13;

uint32_t GetU32Data(const char* ptr)
{
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | (ptr[3]);
}

bool DoSomethingInterestingWithMyAPI(const char* data, size_t size)
{
    auto bundleInstallerHost = std::make_unique<BundleInstallerHost>();
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
    int32_t userId = 0;
    int32_t appIndex = 0;
    int32_t dplType = 0;
    int32_t streamInstallerId = 0;
    std::string bundleFilePath(std::string(data, size));
    std::string bundleName(std::string(data, size));
    std::string modulePackage(std::string(data, size));
    std::vector<std::string> bundleFilePaths;
    InstallParam installParam;
    UninstallParam uninstallParam;
    sptr<IStatusReceiver> statusReceiver;
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
    bundleInstallerHost->CreateStreamInstaller(installParam, statusReceiver);
    bundleInstallerHost->DestoryBundleStreamInstaller(streamInstallerId);
    bundleInstallerHost->StreamInstall(bundleFilePaths, installParam, statusReceiver);
    bundleInstallerHost->UpdateBundleForSelf(bundleFilePaths, installParam, statusReceiver);
    bundleInstallerHost->UninstallAndRecover(bundleName, installParam, statusReceiver);
    bundleInstallerHost->GetCurTaskNum();
    bundleInstallerHost->GetThreadsNum();
    bundleInstallerHost->InstallCloneApp(bundleName, userId, appIndex);
    bundleInstallerHost->UninstallCloneApp(bundleName, userId, appIndex);
    bundleInstallerHost->InstallExisted(bundleName, userId);
    bundleInstallerHost->CheckInstallParam(installParam);
    InstallParam installParam2;
    bundleInstallerHost->IsPermissionVaild(installParam, installParam2);
    return true;
}
}

/* Fuzzer entry point */
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