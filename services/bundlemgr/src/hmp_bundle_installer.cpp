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

#include <cstring>
#include <dirent.h>

#include "hmp_bundle_installer.h"

#include "app_log_wrapper.h"
#include "app_service_fwk_installer.h"
#include "bundle_constants.h"
#include "bundle_data_mgr.h"
#include "bundle_service_constants.h"
#include "bundle_mgr_service.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string APP_DIR = "/app";
const std::string APP_SERVICE_FWK_DIR = "appServiceFwk";
}  // namespace

HmpBundleInstaller::HmpBundleInstaller()
{
    APP_LOGD("hmp bundle installer instance is created");
}

HmpBundleInstaller::~HmpBundleInstaller()
{
    APP_LOGD("hmp bundle installer instance is destroyed");
}

ErrCode HmpBundleInstaller::InstallHmpBundle(const std::string &filePath, bool isNeedRollback)
{
    APP_LOGI("InstallHmpBundle called, filePath: %{public}s, isNeedRollback: %{public}d",
        filePath.c_str(), isNeedRollback);
    std::string appServiceFwkBaseDir = filePath + APP_DIR + ServiceConstants::PATH_SEPARATOR + APP_SERVICE_FWK_DIR;
    std::set<std::string> systemHspList = GetHmpBundleList(appServiceFwkBaseDir);
    std::string appBaseDir = filePath + APP_DIR;
    std::set<std::string> hapList = GetHmpBundleList(appBaseDir);
    std::set<std::string> rollbackHapList = GetRollbackHapList(hapList);

    for (const auto &appServiceFwk : systemHspList) {
        APP_LOGI("Install appServiceFwk:%{public}s", appServiceFwk.c_str());
        ErrCode ret = InstallSystemHspInHmp(appServiceFwkBaseDir + ServiceConstants::PATH_SEPARATOR + appServiceFwk);
        if (ret != ERR_OK) {
            if (isNeedRollback) {
                RollbackHmpBundle(systemHspList, rollbackHapList);
            }
            return ret;
        }
    }

    for (const auto &app : hapList) {
        APP_LOGI("Install app:%{public}s", app.c_str());
        ErrCode ret = InstallNormalAppInHmp(appBaseDir + ServiceConstants::PATH_SEPARATOR + app);
        if (ret != ERR_OK) {
            if (isNeedRollback) {
                RollbackHmpBundle(systemHspList, rollbackHapList);
            }
            return ret;
        }
    }
    return ERR_OK;
}

std::set<std::string> HmpBundleInstaller::GetHmpBundleList(const std::string &path) const
{
    std::set<std::string> hmpBundleList;
    DIR *dir = opendir(path.c_str());
    if (dir == nullptr) {
        APP_LOGE("fail to opendir:%{public}s, errno:%{public}d", path.c_str(), errno);
        return hmpBundleList;
    }
    struct dirent *ptr;
    while ((ptr = readdir(dir)) != nullptr) {
        if (strcmp(ptr->d_name, ".") == 0 || strcmp(ptr->d_name, "..") == 0 ||
            strcmp(ptr->d_name, APP_SERVICE_FWK_DIR.c_str()) == 0) {
            continue;
        }
        if (ptr->d_type == DT_DIR) {
            hmpBundleList.insert(std::string(ptr->d_name));
            continue;
        }
    }
    closedir(dir);
    return hmpBundleList;
}

ErrCode HmpBundleInstaller::InstallSystemHspInHmp(const std::string &bundleDir) const
{
    AppServiceFwkInstaller installer;
    InstallParam installParam;
    installParam.isPreInstallApp = true;
    installParam.removable = false;
    ErrCode ret = installer.Install({ bundleDir }, installParam);
    if (ret != ERR_OK) {
        APP_LOGE("install hmp system hsp %{public}s error with code: %{public}d", bundleDir.c_str(), ret);
    }
    return ret;
}

ErrCode HmpBundleInstaller::InstallNormalAppInHmp(const std::string &bundleDir)
{
    auto pos = bundleDir.rfind('/');
    auto bundleName = pos != std::string::npos ? bundleDir.substr(pos + 1) : "";
    std::set<int32_t> requiredUserIds = GetRequiredUserIds(bundleName);
    InstallParam installParam;
    installParam.isPreInstallApp = true;
    installParam.noSkipsKill = false;
    installParam.needSendEvent = true;
    installParam.needSavePreInstallInfo = true;
    installParam.copyHapToInstallPath = false;
    installParam.userId = Constants::DEFAULT_USERID;
    ErrCode ret = InstallBundle(bundleDir, installParam, Constants::AppType::SYSTEM_APP);
    ResetInstallProperties();
    if (ret == ERR_OK) {
        APP_LOGI("install hmp normal app %{public}s for user 0 success", bundleDir.c_str());
        return ret;
    }
    for (auto userId : requiredUserIds) {
        if (userId == Constants::DEFAULT_USERID) {
            continue;
        }
        installParam.userId = userId;
        ret = InstallBundle(bundleDir, installParam, Constants::AppType::SYSTEM_APP);
        ResetInstallProperties();
        APP_LOGI("install hmp bundleName: %{public}s, userId: %{public}d, result: %{public}d",
            bundleName.c_str(), userId, ret);
        if (ret != ERR_OK) {
            APP_LOGE("install hmp normal app %{public}s error with code: %{public}d", bundleDir.c_str(), ret);
            return ret;
        }
    }
    return ERR_OK;
}

std::set<int32_t> HmpBundleInstaller::GetRequiredUserIds(std::string bundleName) const
{
    std::set<int32_t> userIds;
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is nullptr");
        return userIds;
    }
    // if bundle exists, return the set of user ids that have installed the bundle
    if (dataMgr->GetInnerBundleInfoUsers(bundleName, userIds)) {
        return userIds;
    }
    // if bundle does not exist, check whether the bundle is pre-installed
    // if so, it means the bundle is uninstalled by all users, return empty set
    PreInstallBundleInfo preInfo;
    if (dataMgr->GetPreInstallBundleInfo(bundleName, preInfo)) {
        return userIds;
    }
    // if bundle does not exist and is not pre-installed, it means the bundle is new, return all user ids
    for (auto userId : dataMgr->GetAllUser()) {
        if (userId >= Constants::START_USERID) {
            userIds.insert(userId);
        }
    }
    return userIds;
}

std::set<std::string> HmpBundleInstaller::GetRollbackHapList(std::set<std::string> hapList) const
{
    std::set<std::string> rollbackHapList;
    for (const auto &bundleName : hapList) {
        if (!GetRequiredUserIds(bundleName).empty()) {
            rollbackHapList.insert(bundleName);
        } else {
            APP_LOGI("bundle %{public}s is uninstalled by user, no need to rollback", bundleName.c_str());
        }
    }
    return rollbackHapList;
}

void HmpBundleInstaller::RollbackHmpBundle(const std::set<std::string> &systemHspList,
    const std::set<std::string> &hapList)
{
    std::set<std::string> normalBundleList;
    std::set_difference(hapList.begin(), hapList.end(), systemHspList.begin(), systemHspList.end(),
        std::inserter(normalBundleList, normalBundleList.begin()));
    for (const auto &bundleName : normalBundleList) {
        ErrCode ret = RollbackHmpUserInfo(bundleName);
        if (ret != ERR_OK) {
            APP_LOGE("RollbackHmpUserInfo %{public}s error with code: %{public}d", bundleName.c_str(), ret);
        }
    }
    std::set<std::string> allBundleList;
    allBundleList.insert(systemHspList.begin(), systemHspList.end());
    allBundleList.insert(hapList.begin(), hapList.end());
    for (const auto &bundleName : allBundleList) {
        ErrCode ret = RollbackHmpCommonInfo(bundleName);
        if (ret != ERR_OK) {
            APP_LOGE("RollbackHmpCommonInfo %{public}s error with code: %{public}d", bundleName.c_str(), ret);
        }
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
