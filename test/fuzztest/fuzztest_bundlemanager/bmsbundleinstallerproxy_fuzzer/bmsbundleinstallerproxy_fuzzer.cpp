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

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "bundle_installer_proxy.h"

#include "bmsbundleinstallerproxy_fuzzer.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
    bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
    {
        sptr<IRemoteObject> object;
        BundleInstallerProxy bundleinstallerProxy(object);

        FuzzedDataProvider fdp(data, size);
        std::string bundleFilePath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        InstallParam installParam;
        GenerateInstallParam(fdp, installParam);
        sptr<IStatusReceiver> statusReceiver;
        bundleinstallerProxy.Install(bundleFilePath, installParam, statusReceiver);

        std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        bundleinstallerProxy.Recover(bundleName, installParam, statusReceiver);

        std::vector<std::string> bundleFilePaths = GenerateStringArray(fdp);
        bundleinstallerProxy.Install(bundleFilePaths, installParam, statusReceiver);

        bundleinstallerProxy.Uninstall(bundleName, installParam, statusReceiver);
        std::string modulePackage = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
        bundleinstallerProxy.Uninstall(bundleFilePath, modulePackage, installParam, statusReceiver);
        int32_t dlpType = fdp.ConsumeIntegral<int32_t>();
        int32_t userId = BMSFuzzTestUtil::GenerateRandomUser(fdp);
        int32_t appIndex = fdp.ConsumeIntegral<int32_t>();
        bundleinstallerProxy.InstallSandboxApp(bundleName, dlpType, userId, appIndex);
        bundleinstallerProxy.UninstallSandboxApp(bundleName, appIndex, userId);
        std::vector<std::string> originHapPaths = GenerateStringArray(fdp);
        bundleinstallerProxy.CreateStreamInstaller(installParam, statusReceiver, originHapPaths);
        uint32_t streamInstallerId = fdp.ConsumeIntegral<uint32_t>();
        bundleinstallerProxy.DestoryBundleStreamInstaller(streamInstallerId);
        bundleinstallerProxy.StreamInstall(bundleFilePaths, installParam, statusReceiver);
        return true;
    }
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Run your code on data.
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}