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
#define private public
#include "bundle_distributed_manager.h"
#include "bundle_mgr_service.h"
#include "bundle_multiuser_installer.h"
#include "bmsbundlemultiuserinstaller_fuzzer.h"
#include "bms_fuzztest_util.h"

using Want = OHOS::AAFwk::Want;

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
const std::string SYS_BUNDLE_NAME = "ohos.global.systemres";
constexpr int32_t INVALID_USER_ID = -1;
constexpr int32_t USER_ID = 100;
constexpr int32_t WAIT_TIME = 5;
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    BundleMultiUserInstaller bundleMultiUserInstaller;
    auto bundleMgrService = DelayedSingleton<BundleMgrService>::GetInstance();
    if (bundleMgrService == nullptr) {
        return false;
    }
    if (!bundleMgrService->IsServiceReady()) {
        bundleMgrService->OnStart();
        bundleMgrService->GetDataMgr()->AddUserId(USER_ID);
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
    bundleMultiUserInstaller.dataMgr_ = bundleMgrService->GetDataMgr();
    std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    int32_t userId = 0;
    bundleMultiUserInstaller.InstallExistedApp(SYS_BUNDLE_NAME, userId);
    bundleMultiUserInstaller.InstallExistedApp(SYS_BUNDLE_NAME, Constants::START_USERID);
    bundleMultiUserInstaller.InstallExistedApp(bundleName, userId);
    bundleMultiUserInstaller.InstallExistedApp(bundleName, Constants::START_USERID);

    std::string emptyBundleName;
    bundleMultiUserInstaller.ProcessBundleInstall(emptyBundleName, userId);
    bundleMultiUserInstaller.ProcessBundleInstall(SYS_BUNDLE_NAME, Constants::UNSPECIFIED_USERID);
    bundleMultiUserInstaller.ProcessBundleInstall(bundleName, Constants::START_USERID);
    bundleMultiUserInstaller.ProcessBundleInstall(SYS_BUNDLE_NAME, INVALID_USER_ID);
    bundleMultiUserInstaller.ResetInstallProperties();
    bundleMultiUserInstaller.CreateDataGroupDir(bundleName, userId);

    int32_t uid = fdp.ConsumeIntegral<int32_t>();
    InnerBundleInfo info;
    bundleMultiUserInstaller.CreateDataDir(info, userId, uid);
    bundleMultiUserInstaller.CreateEl5Dir(info, userId, uid);
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.needDelete = false;
    innerModuleInfo.moduleName = "entry";
    RequestPermission requestPermission;
    requestPermission.name = ServiceConstants::PERMISSION_PROTECT_SCREEN_LOCK_DATA;
    innerModuleInfo.requestPermissions.push_back(requestPermission);
    info.innerModuleInfos_["entry"] = innerModuleInfo;
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = bundleName;
    info.SetBaseApplicationInfo(applicationInfo);
    BundleInfo bundleInfo;
    info.SetBaseBundleInfo(bundleInfo);
    bundleMultiUserInstaller.CreateEl5Dir(info, userId, uid);

    std::string testBundleName = "test";
    Security::AccessToken::AccessTokenIDEx accessTokenIdEx;
    InnerBundleInfo innerBundleInfo;
    bundleMultiUserInstaller.RecoverHapToken(bundleName, userId, accessTokenIdEx, innerBundleInfo);
    bundleMultiUserInstaller.RecoverHapToken(testBundleName, userId, accessTokenIdEx, innerBundleInfo);
    bundleMultiUserInstaller.RecoverHapToken(
        testBundleName, Constants::START_USERID, accessTokenIdEx, innerBundleInfo);
    bundleMultiUserInstaller.RemoveDataDir(bundleName, userId);
    bundleMultiUserInstaller.GetDataMgr();
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