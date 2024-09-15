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

#include "el5_filekey_callback.h"
#include "installd_client.h"
#include "bundle_service_constants.h"
#include "bundle_constants.h"

#include <sys/stat.h>

namespace OHOS {
namespace AppExecFwk {
void El5FilekeyCallback::OnRegenerateAppKey(std::vector<Security::AccessToken::AppKeyInfo> &infos)
{
    if (infos.empty()) {
        APP_LOGE("OnRegenerateAppKey infos is empty");
        return;
    }
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("OnRegenerateAppKey dataMgr is nullptr");
        return;
    }
    for (auto &info : infos) {
        InnerBundleInfo bundleInfo;
        bool isAppExist = dataMgr->FetchInnerBundleInfo(info.bundleName, bundleInfo);
        if (!isAppExist) {
            APP_LOGE("OnRegenerateAppKey bundleInfo is not exist");
            continue;
        }
        CheckEl5Dir(info, bundleInfo);
        std::string keyId = "";
        auto result = InstalldClient::GetInstance()->SetEncryptionPolicy(
            info.uid, info.bundleName, info.userId, keyId);
        if (result != ERR_OK) {
            APP_LOGE("SetEncryptionPolicy failed for %{public}s", info.bundleName.c_str());
        }
        // update the keyId to the bundleInfo
        bundleInfo.SetkeyId(info.userId, keyId);
        if (!dataMgr->UpdateInnerBundleInfo(bundleInfo)) {
            APP_LOGE("save keyId failed");
            continue;
        }
        APP_LOGI("OnRegenerateAppKey success for %{public}s", info.bundleName.c_str());
    }
}

void El5FilekeyCallback::CheckEl5Dir(Security::AccessToken::AppKeyInfo &info, const InnerBundleInfo &bundleInfo)
{
    std::string parentDir = std::string(ServiceConstants::SCREEN_LOCK_FILE_DATA_PATH) +
        ServiceConstants::PATH_SEPARATOR + std::to_string(info.userId) + ServiceConstants::BASE;
    bool isDirExisted = false;
    auto result = InstalldClient::GetInstance()->IsExistDir(parentDir, isDirExisted);
    if (result != ERR_OK || !isDirExisted) {
        return;
    }
    std::string baseDir = parentDir + info.bundleName;
    result = InstalldClient::GetInstance()->IsExistDir(baseDir, isDirExisted);
    if (result == ERR_OK && isDirExisted) {
        return;
    }

    int32_t mode = S_IRWXU;
    if (InstalldClient::GetInstance()->Mkdir(baseDir, mode, info.uid, info.uid) != ERR_OK) {
        APP_LOGW("create Screen Lock Protection dir %{public}s failed", baseDir.c_str());
    }
    result = InstalldClient::GetInstance()->SetDirApl(
        baseDir, info.bundleName, bundleInfo.GetAppPrivilegeLevel(), bundleInfo.IsPreInstallApp(),
        bundleInfo.GetBaseApplicationInfo().appProvisionType == Constants::APP_PROVISION_TYPE_DEBUG);
    if (result != ERR_OK) {
        APP_LOGW("fail to SetDirApl dir %{public}s, error is %{public}d", baseDir.c_str(), result);
    }

    std::string databaseDir = std::string(ServiceConstants::SCREEN_LOCK_FILE_DATA_PATH) +
        ServiceConstants::PATH_SEPARATOR + std::to_string(info.userId) + ServiceConstants::DATABASE + info.bundleName;
    mode = S_IRWXU | S_IRWXG | S_ISGID;
    int32_t gid = ServiceConstants::DATABASE_DIR_GID;
    if (InstalldClient::GetInstance()->Mkdir(databaseDir, mode, info.uid, gid) != ERR_OK) {
        APP_LOGW("create Screen Lock Protection dir %{public}s failed", databaseDir.c_str());
    }
    result = InstalldClient::GetInstance()->SetDirApl(
        databaseDir, info.bundleName, bundleInfo.GetAppPrivilegeLevel(), bundleInfo.IsPreInstallApp(),
        bundleInfo.GetBaseApplicationInfo().appProvisionType == Constants::APP_PROVISION_TYPE_DEBUG);
    if (result != ERR_OK) {
        APP_LOGW("fail to SetDirApl dir %{public}s, error is %{public}d", databaseDir.c_str(), result);
    }
}
} // AppExecFwk
} // OHOS
