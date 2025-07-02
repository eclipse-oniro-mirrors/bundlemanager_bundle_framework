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

#include "bundle_clone_installer.h"

#include "bmsbundlecloneinstaller_fuzzer.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    BundleCloneInstaller installer;
    FuzzedDataProvider fdp(data, size);

    std::string emptyBundleName = "";
    std::string randomBundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    int32_t appIndex = 1;
    int32_t randomAppIndex = fdp.ConsumeIntegral<int32_t>();
    int32_t randomUserId = fdp.ConsumeIntegral<int32_t>();

    installer.InstallCloneApp(emptyBundleName, Constants::START_USERID, appIndex);
    installer.InstallCloneApp(randomBundleName, Constants::START_USERID, appIndex);

    bool sync = fdp.ConsumeBool();

    installer.ProcessCloneBundleInstall(emptyBundleName, randomUserId, appIndex);
    installer.ProcessCloneBundleInstall(randomBundleName, Constants::START_USERID, appIndex);

    installer.ProcessCloneBundleUninstall(emptyBundleName, randomUserId, appIndex, sync);
    installer.ProcessCloneBundleUninstall(randomBundleName, Constants::START_USERID, appIndex, sync);
    installer.ProcessCloneBundleUninstall(randomBundleName, Constants::START_USERID, randomAppIndex, sync);

    int32_t uid = fdp.ConsumeIntegral<int32_t>();
    InnerBundleInfo info;
    installer.UninstallDebugAppSandbox(randomBundleName, uid, appIndex, info);
    info.baseApplicationInfo_->appProvisionType = true;
    installer.UninstallDebugAppSandbox(randomBundleName, uid, appIndex, info);

    installer.CreateCloneDataDir(info, randomUserId, uid, randomAppIndex);
    installer.CreateCloneDataDir(info, Constants::START_USERID, uid, appIndex);

    installer.RemoveCloneDataDir(emptyBundleName, randomUserId, randomAppIndex, sync);
    installer.RemoveCloneDataDir(randomBundleName, randomUserId, randomAppIndex, sync);
    installer.RemoveCloneDataDir(randomBundleName, Constants::START_USERID, appIndex, sync);

    installer.CreateEl5Dir(info, Constants::START_USERID, uid, appIndex);
    installer.CreateEl5Dir(info, randomUserId, uid, randomAppIndex);

    InnerBundleUserInfo userInfo;
    installer.RemoveEl5Dir(userInfo, uid, Constants::START_USERID, appIndex);
    installer.RemoveEl5Dir(userInfo, uid, randomUserId, randomAppIndex);

    installer.GetDataMgr();

    BundleEventType bundleEventType = BundleEventType::INSTALL;
    bool isPreInstallApp = fdp.ConsumeBool();
    bool isFreeInstallMode = fdp.ConsumeBool();
    InstallScene preBundleScene = InstallScene::NORMAL;
    installer.SendBundleSystemEvent(randomBundleName, bundleEventType, randomUserId,
        randomAppIndex, isPreInstallApp, isFreeInstallMode, preBundleScene, ERR_OK);

    EventInfo eventInfo;
    installer.GetCallingEventInfo(eventInfo);

    installer.ResetInstallProperties();

    installer.GetAssetAccessGroups(randomBundleName);

    installer.GetDeveloperId(randomBundleName);
    installer.GetDeveloperId(emptyBundleName);

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