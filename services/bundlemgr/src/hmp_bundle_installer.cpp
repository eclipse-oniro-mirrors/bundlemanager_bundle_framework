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
#include "bundle_parser.h"
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

    ErrCode installRes = ERR_OK;
    for (const auto &appServiceFwk : systemHspList) {
        APP_LOGI("Install appServiceFwk:%{public}s", appServiceFwk.c_str());
        ErrCode ret = InstallSystemHspInHmp(appServiceFwkBaseDir + ServiceConstants::PATH_SEPARATOR + appServiceFwk);
        if (ret != ERR_OK) {
            if (isNeedRollback) {
                RollbackHmpBundle(systemHspList, rollbackHapList);
                return ret;
            }
            installRes = ret;
        }
    }

    for (const auto &app : hapList) {
        APP_LOGI("Install app:%{public}s", app.c_str());
        ErrCode ret = InstallNormalAppInHmp(appBaseDir + ServiceConstants::PATH_SEPARATOR + app);
        if (ret != ERR_OK) {
            if (isNeedRollback) {
                RollbackHmpBundle(systemHspList, rollbackHapList);
                return ret;
            }
            installRes = ret;
        }
    }
    UpdateBundleInfoForHmp(filePath, hapList, systemHspList);
    return installRes;
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
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    ErrCode ret = InstallBundle(bundleDir, installParam, Constants::AppType::SYSTEM_APP);
    ResetInstallProperties();
    if (ret == ERR_OK) {
        APP_LOGI("install hmp normal app %{public}s for user 0 success", bundleDir.c_str());
        return ret;
    }
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is nullptr");
        return ERR_APPEXECFWK_INSTALL_BUNDLE_MGR_SERVICE_ERROR;
    }
    if (dataMgr->IsSystemHsp(bundleName)) {
        APP_LOGE("install hmp system hsp %{public}s error with code: %{public}d", bundleDir.c_str(), ret);
        return ret;
    }
    bool installSuccess = false;
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
        installSuccess = true;
    }
    return installSuccess ? ERR_OK : ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR;
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
    // If the update fails, the information of the application in the database needs to be deleted,
    // but the user data directory and some settings set by the user,
    // such as app control rules and default applications, cannot be deleted.
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

bool HmpBundleInstaller::ParseHapFiles(
    const std::string &hapFilePath,
    std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    std::vector<std::string> hapFilePathVec { hapFilePath };
    std::vector<std::string> realPaths;
    auto ret = BundleUtil::CheckFilePath(hapFilePathVec, realPaths);
    if (ret != ERR_OK) {
        APP_LOGE("File path %{public}s invalid", hapFilePath.c_str());
        return false;
    }

    BundleParser bundleParser;
    for (auto realPath : realPaths) {
        InnerBundleInfo innerBundleInfo;
        ret = bundleParser.Parse(realPath, innerBundleInfo);
        if (ret != ERR_OK) {
            APP_LOGE("Parse bundle info failed, error: %{public}d", ret);
            continue;
        }

        infos.emplace(realPath, innerBundleInfo);
    }

    if (infos.empty()) {
        APP_LOGE("Parse hap(%{public}s) empty ", hapFilePath.c_str());
        return false;
    }

    return true;
}

void HmpBundleInstaller::ParseInfos(const std::string &bundleDir, const std::string &hspDir,
    std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    if (!bundleDir.empty()) {
        if (!ParseHapFiles(bundleDir, infos) || infos.empty()) {
            APP_LOGW("obtain bundleinfo failed : %{public}s ", bundleDir.c_str());
        }
    }
    if (!hspDir.empty()) {
        if (!ParseHapFiles(hspDir, infos) || infos.empty()) {
            APP_LOGW("obtain appService bundleinfo failed : %{public}s ", hspDir.c_str());
        }
    }
}

void HmpBundleInstaller::UpdateBundleInfo(const std::string &bundleName,
    const std::string &bundleDir, const std::string &hspDir)
{
    std::unordered_map<std::string, InnerBundleInfo> infos;
    ParseInfos(bundleDir, hspDir, infos);
    UpdateInnerBundleInfo(bundleName, infos);
    UpdatePreInfoInDb(bundleName, infos);
}

void HmpBundleInstaller::UpdateInnerBundleInfo(const std::string &bundleName,
    const std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return;
    }
    InnerBundleInfo oldBundleInfo;
    bool hasInstalled = dataMgr->FetchInnerBundleInfo(bundleName, oldBundleInfo);
    if (!hasInstalled) {
        APP_LOGW("app(%{public}s) has been uninstalled", bundleName.c_str());
        return;
    }
    auto innerModuleInfos = oldBundleInfo.GetInnerModuleInfos();
    std::set<std::string> newModulePackages;
    for (const auto &item : infos) {
        newModulePackages.insert(item.second.GetCurrentModulePackage());
    }
    for (const auto &item : innerModuleInfos) {
        if (newModulePackages.find(item.first) == newModulePackages.end()) {
            APP_LOGI("module package (%{public}s) need to be removed.", item.first.c_str());
            if (!UninstallSystemBundle(bundleName, item.first)) {
                APP_LOGW("uninstall module %{public}s for bundle %{public}s failed",
                    item.first.c_str(), bundleName.c_str());
            }
        }
    }
}

bool HmpBundleInstaller::UninstallSystemBundle(const std::string &bundleName, const std::string &modulePackage)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return false;
    }

    InstallParam installParam;
    bool uninstallResult = false;
    for (auto userId : dataMgr->GetAllUser()) {
        installParam.userId = userId;
        installParam.needSavePreInstallInfo = true;
        installParam.isPreInstallApp = true;
        installParam.noSkipsKill = false;
        installParam.needSendEvent = false;
        MarkPreBundleSyeEventBootTag(false);
        ErrCode result = UninstallBundle(bundleName, modulePackage, installParam);
        ResetInstallProperties();
        if (result != ERR_OK) {
            APP_LOGW("uninstall system bundle fail for userId %{public}d, error: %{public}d", userId, result);
            continue;
        }
        APP_LOGI("uninstall module %{public}s success", modulePackage.c_str());
        uninstallResult = true;
    }
    CheckUninstallSystemHsp(bundleName);

    return uninstallResult;
}

void HmpBundleInstaller::CheckUninstallSystemHsp(const std::string &bundleName)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return;
    }
    InnerBundleInfo info;
    if (!(dataMgr->FetchInnerBundleInfo(bundleName, info))) {
        APP_LOGD("bundleName %{public}s not existed local", bundleName.c_str());
        return;
    }
    if (info.GetApplicationBundleType() != BundleType::APP_SERVICE_FWK) {
        APP_LOGD("bundleName %{public}s is not a system hsp", bundleName.c_str());
        return;
    }
    bool isExistHsp = false;
    for (const auto &item : info.GetInnerModuleInfos()) {
        if (item.second.distro.moduleType == "shared") {
            isExistHsp = true;
            return;
        }
    }
    APP_LOGI("appService %{public}s does not have any hsp, so it need to be uninstalled.", bundleName.c_str());
    if (!isExistHsp) {
        InstallParam installParam;
        installParam.userId = Constants::DEFAULT_USERID;
        installParam.needSavePreInstallInfo = true;
        installParam.isPreInstallApp = true;
        installParam.noSkipsKill = false;
        installParam.needSendEvent = false;
        installParam.isKeepData = true;
        MarkPreBundleSyeEventBootTag(false);
        ErrCode result = UninstallBundle(bundleName, installParam);
        if (result != ERR_OK) {
            APP_LOGW("uninstall system bundle fail, error: %{public}d", result);
            return;
        }
        PreInstallBundleInfo preInstallBundleInfo;
        if ((dataMgr->GetPreInstallBundleInfo(bundleName, preInstallBundleInfo))) {
            dataMgr->DeletePreInstallBundleInfo(bundleName, preInstallBundleInfo);
        }
    }
}

void HmpBundleInstaller::UpdatePreInfoInDb(const std::string &bundleName,
    const std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return;
    }
    PreInstallBundleInfo preInstallBundleInfo;
    dataMgr->GetPreInstallBundleInfo(bundleName, preInstallBundleInfo);
    auto bundlePathList = preInstallBundleInfo.GetBundlePaths();
    for (const std::string &bundlePath : bundlePathList) {
        if (infos.find(bundlePath) == infos.end()) {
            APP_LOGI("bundlePath %{public}s need to be deleted", bundlePath.c_str());
            preInstallBundleInfo.DeleteBundlePath(bundlePath);
        }
    }
    if (preInstallBundleInfo.GetBundlePaths().empty()) {
        dataMgr->DeletePreInstallBundleInfo(bundleName, preInstallBundleInfo);
    } else {
        dataMgr->SavePreInstallBundleInfo(bundleName, preInstallBundleInfo);
    }
}

void HmpBundleInstaller::UpdateBundleInfoForHmp(const std::string &filePath, std::set<std::string> hapList,
    std::set<std::string> systemHspList)
{
    std::string appBaseDir = filePath + APP_DIR;
    std::string appServiceFwkBaseDir = filePath + APP_DIR + ServiceConstants::PATH_SEPARATOR + APP_SERVICE_FWK_DIR;
    for (const auto &bundleName : hapList) {
        std::string bundleDir = appBaseDir + ServiceConstants::PATH_SEPARATOR + bundleName;
        std::string hspDir = "";
        if (systemHspList.find(bundleName) != systemHspList.end()) {
            hspDir = appServiceFwkBaseDir + ServiceConstants::PATH_SEPARATOR + bundleName;
        }
        UpdateBundleInfo(bundleName, bundleDir, hspDir);
    }

    for (const auto &bundleName : systemHspList) {
        if (hapList.find(bundleName) == hapList.end()) {
            std::string hspDir = appServiceFwkBaseDir + ServiceConstants::PATH_SEPARATOR + bundleName;
            UpdateBundleInfo(bundleName, "", hspDir);
        }
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
