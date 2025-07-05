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
#include <fuzzer/FuzzedDataProvider.h>
#include <set>

#include "account_helper.h"
#include "bms_fuzztest_util.h"
#include "bmshmpbundleinstaller_fuzzer.h"
#include "bundle_mgr_service.h"
#include "hmp_bundle_installer.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
const std::string SYS_BUNDLE_NAME = "ohos.global.systemres";
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    HmpBundleInstaller hmpBundleInstaller;
    hmpBundleInstaller.dataMgr_ = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    std::set<int32_t> userIds;
    hmpBundleInstaller.GetRequiredUserIds(SYS_BUNDLE_NAME, userIds);
    FuzzedDataProvider fdp(data, size);
    std::string bundleName;
    hmpBundleInstaller.GetRequiredUserIds(bundleName, userIds);
    hmpBundleInstaller.CheckAppIsUpdatedByUser(bundleName);
    hmpBundleInstaller.CheckAppIsUpdatedByUser(SYS_BUNDLE_NAME);
    bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hmpBundleInstaller.GetRequiredUserIds(bundleName, userIds);
    hmpBundleInstaller.CheckAppIsUpdatedByUser(bundleName);
    std::set<std::string> systemHspList;
    systemHspList.insert(bundleName);
    std::set<std::string> hapList;
    hapList.insert(SYS_BUNDLE_NAME);
    hapList.insert(bundleName);
    hmpBundleInstaller.RollbackHmpBundle(systemHspList, hapList);
    std::string hapFilePath = "/system/app/ohos.global.systemres";
    std::unordered_map<std::string, InnerBundleInfo> infos;
    hmpBundleInstaller.ParseHapFiles(hapFilePath, infos);
    hmpBundleInstaller.UpdateBundleInfo(bundleName, hapFilePath, hapFilePath);
    std::string modulePackage = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hmpBundleInstaller.UninstallSystemBundle(bundleName, modulePackage);
    hmpBundleInstaller.CheckUninstallSystemHsp(bundleName);
    hmpBundleInstaller.CheckUninstallSystemHsp(SYS_BUNDLE_NAME);
    hmpBundleInstaller.UpdateBundleInfo(SYS_BUNDLE_NAME, hapFilePath, hapFilePath);
    std::string filePath;
    hmpBundleInstaller.UpdateBundleInfoForHmp(filePath, hapList, systemHspList);
    hmpBundleInstaller.GetIsRemovable(SYS_BUNDLE_NAME);
    hmpBundleInstaller.GetIsRemovable(bundleName);

    hmpBundleInstaller.dataMgr_ = std::make_shared<BundleDataMgr>();
    hmpBundleInstaller.GetRequiredUserIds(SYS_BUNDLE_NAME, userIds);
    hmpBundleInstaller.GetRequiredUserIds(bundleName, userIds);
    hmpBundleInstaller.CheckAppIsUpdatedByUser(bundleName);
    hmpBundleInstaller.CheckAppIsUpdatedByUser(SYS_BUNDLE_NAME);
    hmpBundleInstaller.GetRequiredUserIds(bundleName, userIds);
    hmpBundleInstaller.CheckAppIsUpdatedByUser(bundleName);
    hmpBundleInstaller.RollbackHmpBundle(systemHspList, hapList);
    hmpBundleInstaller.ParseHapFiles(hapFilePath, infos);
    hmpBundleInstaller.UpdateBundleInfo(bundleName, hapFilePath, hapFilePath);
    hmpBundleInstaller.UpdateBundleInfo(SYS_BUNDLE_NAME, hapFilePath, hapFilePath);
    hmpBundleInstaller.UninstallSystemBundle(bundleName, modulePackage);
    hmpBundleInstaller.CheckUninstallSystemHsp(bundleName);
    hmpBundleInstaller.CheckUninstallSystemHsp(SYS_BUNDLE_NAME);
    hmpBundleInstaller.UpdatePreInfoInDb(bundleName, infos);
    hmpBundleInstaller.UpdatePreInfoInDb(SYS_BUNDLE_NAME, infos);
    hmpBundleInstaller.UpdateBundleInfoForHmp(filePath, hapList, systemHspList);
    hmpBundleInstaller.GetIsRemovable(SYS_BUNDLE_NAME);
    hmpBundleInstaller.GetIsRemovable(bundleName);

    return true;
}
} // namespace OHOS

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
