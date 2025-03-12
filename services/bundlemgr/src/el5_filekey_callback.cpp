/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include "inner_bundle_clone_common.h"
#include "installd_client.h"
#include "bundle_service_constants.h"
#include "bundle_constants.h"

#include <sys/stat.h>

namespace OHOS {
namespace AppExecFwk {
void El5FilekeyCallback::OnRegenerateAppKey(std::vector<Security::AccessToken::AppKeyInfo> &infos)
{
    APP_LOGI("el5 callback");
    if (infos.empty()) {
        APP_LOGE("OnRegenerateAppKey infos is empty");
        return;
    }
    for (auto &info : infos) {
        switch (info.type) {
            case Security::AccessToken::AppKeyType::APP:
                ProcessAppEl5Dir(info);
                break;
            case Security::AccessToken::AppKeyType::GROUPID:
                ProcessGroupEl5Dir(info);
                break;
        }
    }
}

void El5FilekeyCallback::ProcessAppEl5Dir(const Security::AccessToken::AppKeyInfo &info)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("OnRegenerateAppKey dataMgr is nullptr");
        return;
    }
    int32_t appIndex = 0;
    std::string bundleName = info.bundleName;
    if (info.bundleName.find(ServiceConstants::CLONE_PREFIX) == 0 &&
        !BundleCloneCommonHelper::ParseCloneDataDir(info.bundleName, bundleName, appIndex)) {
        APP_LOGE("parse clone name failed %{public}s", info.bundleName.c_str());
        return;
    }
    InnerBundleInfo bundleInfo;
    bool isAppExist = dataMgr->FetchInnerBundleInfo(bundleName, bundleInfo);
    if (!isAppExist || !bundleInfo.HasInnerBundleUserInfo(info.userId)) {
        APP_LOGE("%{public}s is not exist %{public}d", bundleName.c_str(), info.userId);
        return;
    }
    if (appIndex != 0) {
        bool isAppIndexExisted = false;
        ErrCode res = bundleInfo.IsCloneAppIndexExisted(info.userId, appIndex, isAppIndexExisted);
        if (res != ERR_OK || !isAppIndexExisted) {
            APP_LOGE("appIndex is not existed");
            return;
        }
    }
    CheckEl5Dir(info, bundleInfo, bundleName);
    std::string keyId = "";
    EncryptionParam encryptionParam(info.bundleName, "", info.uid, info.userId, EncryptionDirType::APP);
    auto result = InstalldClient::GetInstance()->SetEncryptionPolicy(encryptionParam, keyId);
    if (result != ERR_OK) {
        APP_LOGE("SetEncryptionPolicy failed for %{public}s", info.bundleName.c_str());
        return;
    }
    // update the keyId to the bundleInfo
    bundleInfo.SetkeyId(info.userId, keyId, appIndex);
    bundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::ENABLED);
    if (!dataMgr->UpdateInnerBundleInfo(bundleInfo)) {
        APP_LOGE("save keyId failed");
        return;
    }
    APP_LOGI("OnRegenerateAppKey success for %{public}s", info.bundleName.c_str());
}

void El5FilekeyCallback::ProcessGroupEl5Dir(const Security::AccessToken::AppKeyInfo &info)
{
    if (info.type != Security::AccessToken::AppKeyType::GROUPID || info.uid < 0 || info.groupID.empty()) {
        APP_LOGE("param error, type %{public}d uid %{public}d", static_cast<int32_t>(info.type), info.uid);
        return;
    }
    int32_t userId = info.uid / Constants::BASE_USER_RANGE;
    std::string parentDir = std::string(ServiceConstants::SCREEN_LOCK_FILE_DATA_PATH) +
        ServiceConstants::PATH_SEPARATOR + std::to_string(userId);
    bool isDirExisted = false;
    auto result = InstalldClient::GetInstance()->IsExistDir(parentDir, isDirExisted);
    if (result != ERR_OK || !isDirExisted) {
        return;
    }
    // create el5 group dir
    std::string dir = parentDir + ServiceConstants::DATA_GROUP_PATH + info.groupID;
    auto mdkirRes = InstalldClient::GetInstance()->Mkdir(dir,
        ServiceConstants::DATA_GROUP_DIR_MODE, info.uid, info.uid);
    if (mdkirRes != ERR_OK) {
        APP_LOGW("el5 group dir %{private}s userId %{public}d create failed",
            info.groupID.c_str(), userId);
    }
    // set el5 group dirs encryption policy
    EncryptionParam encryptionParam("", info.groupID, info.uid, userId, EncryptionDirType::GROUP);
    std::string keyId = "";
    auto setPolicyRes = InstalldClient::GetInstance()->SetEncryptionPolicy(encryptionParam, keyId);
    if (setPolicyRes != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLER, "SetEncryptionPolicy failed, %{public}d", setPolicyRes);
    }
}

void El5FilekeyCallback::CheckEl5Dir(const Security::AccessToken::AppKeyInfo &info, const InnerBundleInfo &bundleInfo,
    const std::string &bundleName)
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
        baseDir, bundleName, bundleInfo.GetAppPrivilegeLevel(), bundleInfo.IsPreInstallApp(),
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
        databaseDir, bundleName, bundleInfo.GetAppPrivilegeLevel(), bundleInfo.IsPreInstallApp(),
        bundleInfo.GetBaseApplicationInfo().appProvisionType == Constants::APP_PROVISION_TYPE_DEBUG);
    if (result != ERR_OK) {
        APP_LOGW("fail to SetDirApl dir %{public}s, error is %{public}d", databaseDir.c_str(), result);
    }
}
} // AppExecFwk
} // OHOS
