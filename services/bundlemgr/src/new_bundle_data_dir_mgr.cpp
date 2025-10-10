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

#include "new_bundle_data_dir_mgr.h"

#include "bundle_constants.h"
#include "bundle_data_mgr.h"
#include "bundle_mgr_service.h"
#include "bundle_service_constants.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* NEW_BUNDLE_DATA_DIR_MGR = "newBundleDataDirMgr";
constexpr const char* NEW_BUNDLE_DATA_DIR_MAP = "newBundleDataDirMap";
constexpr const char* USER_ID = "userIds";
}

NewBundleDataDirMgr::NewBundleDataDirMgr()
{}

NewBundleDataDirMgr::~NewBundleDataDirMgr()
{}

std::set<std::string> NewBundleDataDirMgr::GetAllNewBundleDataDirBundleName()
{
    std::lock_guard<std::mutex> lock(newBundleDataDirMutex_);
    if (!hasInit_) {
        APP_LOGI("load new data dir map start");
        if (!LoadNewBundleDataDirInfosFromDb()) {
            APP_LOGE("load new data dir map failed");
        }
    }
    std::set<std::string> allBundleNames;
    for (const auto &item : newBundleDataDirMap_) {
        allBundleNames.insert(item.first);
    }
    return allBundleNames;
}

uint32_t NewBundleDataDirMgr::GetNewBundleDataDirType(const std::string &bundleName, const int32_t userId)
{
    std::lock_guard<std::mutex> lock(newBundleDataDirMutex_);
    if (!hasInit_) {
        APP_LOGI("load new data dir map start");
        if (!LoadNewBundleDataDirInfosFromDb()) {
            APP_LOGE("load new data dir map failed");
        }
    }
    if ((newBundleDataDirMap_.find(bundleName) != newBundleDataDirMap_.end()) &&
        (userIds_.find(userId) != userIds_.end())) {
        return newBundleDataDirMap_[bundleName];
    }
    return static_cast<uint32_t>(CreateBundleDirType::CREATE_NONE_DIR);
}

std::mutex &NewBundleDataDirMgr::GetBundleMutex(const std::string &bundleName)
{
    std::lock_guard<std::mutex> lock(bundleMutex_);
    return bundleMutexMap_[bundleName];
}

bool NewBundleDataDirMgr::LoadNewBundleDataDirInfosFromDb()
{
    auto bmsPara = DelayedSingleton<BundleMgrService>::GetInstance()->GetBmsParam();
    if (bmsPara == nullptr) {
        APP_LOGE("bmsPara is nullptr");
        return false;
    }

    hasInit_ = true;
    std::string newBundleDataDirStr;
    (void)bmsPara->GetBmsParam(NEW_BUNDLE_DATA_DIR_MGR, newBundleDataDirStr);
    if (newBundleDataDirStr.empty()) {
        return true;
    }

    nlohmann::json jsonObject = nlohmann::json::parse(newBundleDataDirStr, nullptr, false);
    if (jsonObject.is_discarded() || !jsonObject.is_object()) {
        APP_LOGE("jsonObject is invalid");
        return false;
    }

    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, uint32_t>>(jsonObject, jsonObjectEnd, NEW_BUNDLE_DATA_DIR_MAP,
        newBundleDataDirMap_, false, parseResult, JsonType::NUMBER, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::set<int32_t>>(jsonObject, jsonObjectEnd, USER_ID, userIds_,
        JsonType::ARRAY, false, parseResult, ArrayType::NUMBER);

    if (parseResult != ERR_OK) {
        APP_LOGE("parse new bundle dir map error code : %{public}d", parseResult);
        newBundleDataDirMap_.clear();
        userIds_.clear();
        return false;
    }
    APP_LOGI("LoadNewBundleDataDirInfosFromDb succeed");
    return true;
}

bool NewBundleDataDirMgr::AddNewBundleDirInfo(const std::string &bundleName, const uint32_t dirType)
{
    std::lock_guard<std::mutex> lock(newBundleDataDirMutex_);
    APP_LOGI("add -n %{public}s %{public}d to newBundleDataDirMap", bundleName.c_str(), dirType);
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        return false;
    }
    if (!hasInit_) {
        APP_LOGI("load new data dir map start");
        if (!LoadNewBundleDataDirInfosFromDb()) {
            APP_LOGE("load new data dir map failed");
        }
    }
    if (newBundleDataDirMap_.find(bundleName) != newBundleDataDirMap_.end()) {
        newBundleDataDirMap_[bundleName] = newBundleDataDirMap_[bundleName] | dirType;
    } else {
        newBundleDataDirMap_[bundleName] = dirType;
    }

    if (!AddNewBundleDataDirInfosToDb()) {
        APP_LOGE("add -n %{public}s %{public}d to newBundleDataDirMap failed", bundleName.c_str(), dirType);
        return false;
    }
    return true;
}

bool NewBundleDataDirMgr::AddNewBundleDataDirInfosToDb()
{
    auto bmsPara = DelayedSingleton<BundleMgrService>::GetInstance()->GetBmsParam();
    if (bmsPara == nullptr) {
        APP_LOGE("bmsPara is nullptr");
        return false;
    }

    nlohmann::json jsonObject;
    jsonObject[NEW_BUNDLE_DATA_DIR_MAP] = newBundleDataDirMap_;
    jsonObject[USER_ID] = userIds_;
    if (!bmsPara->SaveBmsParam(NEW_BUNDLE_DATA_DIR_MGR, jsonObject.dump())) {
        APP_LOGE("Save bms param failed");
        return false;
    }
    return true;
}

bool NewBundleDataDirMgr::DeleteNewBundleDataDirInfosFromDb()
{
    auto bmsPara = DelayedSingleton<BundleMgrService>::GetInstance()->GetBmsParam();
    if (bmsPara == nullptr) {
        APP_LOGE("bmsPara is nullptr");
        return false;
    }
    if (!bmsPara->DeleteBmsParam(NEW_BUNDLE_DATA_DIR_MGR)) {
        APP_LOGE("Delete bms param failed");
        return false;
    }
    return true;
}

bool NewBundleDataDirMgr::ProcessOtaBundleDataDir(
    const std::string &bundleName, const int32_t userId)
{
    // 1. get new bundle dir type
    uint32_t dirType = GetNewBundleDataDirType(bundleName, userId);
    if (dirType == static_cast<uint32_t>(CreateBundleDirType::CREATE_NONE_DIR)) {
        return true;
    }
    APP_LOGI("-n %{public}s -u %{public}d type %{public}d create ota dir start", bundleName.c_str(), userId, dirType);
    // 2. process bundle data dir
    auto &mutex = GetBundleMutex(bundleName);
    std::lock_guard<std::mutex> lock {mutex};
    bool ret = true;
    if ((dirType & static_cast<uint32_t>(CreateBundleDirType::CREATE_ALL_DIR)) ==
        static_cast<uint32_t>(CreateBundleDirType::CREATE_ALL_DIR)) {
        // new install bundle, create all path: el2-el5 base\database\group
        if (!InnerProcessOtaNewInstallBundleDir(bundleName, userId)) {
            ret = false;
        }
    }
    if ((dirType & static_cast<uint32_t>(CreateBundleDirType::CREATE_EL5_DIR)) ==
        static_cast<uint32_t>(CreateBundleDirType::CREATE_EL5_DIR)) {
        // create el5
        if (!InnerProcessOtaBundleDataDirEl5(bundleName, userId)) {
            APP_LOGE("-n %{public}s -u %{public}d create dir el5 failed", bundleName.c_str(), userId);
            ret = false;
        }
    }

    if ((dirType & static_cast<uint32_t>(CreateBundleDirType::CREATE_GROUP_DIR)) ==
        static_cast<uint32_t>(CreateBundleDirType::CREATE_GROUP_DIR)) {
        // create group
        if (!InnerProcessOtaBundleDataDirGroup(bundleName, userId)) {
            APP_LOGE("-n %{public}s -u %{public}d create dir group failed", bundleName.c_str(), userId);
            ret = false;
        }
    }
    APP_LOGI("-n %{public}s -u %{public}d type %{public}d create ota dir end", bundleName.c_str(), userId, dirType);
    return ret;
}

bool NewBundleDataDirMgr::InnerProcessOtaNewInstallBundleDir(
    const std::string &bundleName, const int32_t userId)
{
    std::string baseBundleDataDir = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR + ServiceConstants::BUNDLE_EL[1] +
        ServiceConstants::PATH_SEPARATOR + std::to_string(userId) + ServiceConstants::DATABASE + bundleName;
    bool isExist = false;
    (void)InstalldClient::GetInstance()->IsExistDir(baseBundleDataDir, isExist);
    if (isExist) {
        APP_LOGI("bundle %{public}s user %{public}d bundle data dir exist", bundleName.c_str(), userId);
        return true;
    }
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return false;
    }
    InnerBundleInfo info;
    if (!dataMgr->FetchInnerBundleInfo(bundleName, info)) {
        APP_LOGE("-n %{public}s -u %{public}d not exist", bundleName.c_str(), userId);
        return false;
    }
    CreateDirParam createDirParam;
    createDirParam.bundleName = bundleName;
    createDirParam.userId = userId;
    createDirParam.uid = info.GetUid(userId);
    if (createDirParam.uid == Constants::INVALID_UID) {
        APP_LOGE("bundle %{public}s user %{public}d not exist", bundleName.c_str(), userId);
        return false;
    }
    createDirParam.gid = info.GetGid(userId);
    createDirParam.apl = info.GetAppPrivilegeLevel();
    createDirParam.isPreInstallApp = info.IsPreInstallApp();
    createDirParam.debug = info.GetBaseApplicationInfo().appProvisionType ==
        Constants::APP_PROVISION_TYPE_DEBUG;
    createDirParam.createDirFlag = CreateDirFlag::CREATE_DIR_UNLOCKED;
    createDirParam.extensionDirs = info.GetAllExtensionDirs();
    auto ret = InstalldClient::GetInstance()->CreateBundleDataDir(createDirParam);
    if (ret != ERR_OK) {
        APP_LOGE("bundle %{public}s user %{public}d create dir failed %{public}d", bundleName.c_str(), userId, ret);
        return false;
    }
    // create el5
    if (info.NeedCreateEl5Dir()) {
        dataMgr->CreateEl5Dir({createDirParam}, true);
        dataMgr->CreateAppEl5GroupDir(bundleName, userId);
    }
    // create group
    if (!info.GetDataGroupInfos().empty()) {
        dataMgr->CreateAppGroupDir(bundleName, userId);
    }
    return true;
}

bool NewBundleDataDirMgr::InnerProcessOtaBundleDataDirEl5(
    const std::string &bundleName, const int32_t userId)
{
    std::string baseBundleDataDir = std::string(ServiceConstants::SCREEN_LOCK_FILE_DATA_PATH) +
        ServiceConstants::PATH_SEPARATOR + std::to_string(userId) + ServiceConstants::DATABASE + bundleName;
    bool isExist = false;
    (void)InstalldClient::GetInstance()->IsExistDir(baseBundleDataDir, isExist);
    if (isExist) {
        APP_LOGI("bundle %{public}s user %{public}d bundle el5 dir exist", bundleName.c_str(), userId);
        return true;
    }
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return false;
    }
    InnerBundleInfo info;
    if (!dataMgr->FetchInnerBundleInfo(bundleName, info)) {
        APP_LOGE("-n %{public}s -u %{public}d not exist", bundleName.c_str(), userId);
        return false;
    }

    if (!info.NeedCreateEl5Dir()) {
        return true;
    }
    InnerBundleUserInfo userInfo;
    if (!info.GetInnerBundleUserInfo(userId, userInfo)) {
        APP_LOGE("bundle %{public}s user %{public}d not exist", bundleName.c_str(), userId);
        return false;
    }
    CreateDirParam createDirParam;
    createDirParam.bundleName = bundleName;
    createDirParam.userId = userId;
    createDirParam.uid = info.GetUid(userId);
    createDirParam.gid = info.GetGid(userId);
    createDirParam.apl = info.GetAppPrivilegeLevel();
    createDirParam.isPreInstallApp = info.IsPreInstallApp();
    createDirParam.debug = info.GetBaseApplicationInfo().appProvisionType == Constants::APP_PROVISION_TYPE_DEBUG;
    std::vector<CreateDirParam> createDirParams;
    createDirParams.emplace_back(createDirParam);
    for (const auto &cloneInfo : userInfo.cloneInfos) {
        CreateDirParam cloneParam = createDirParam;
        cloneParam.uid = cloneInfo.second.uid;
        cloneParam.gid = cloneInfo.second.uid;
        cloneParam.appIndex = cloneInfo.second.appIndex;
        createDirParams.emplace_back(cloneParam);
    }
    dataMgr->CreateEl5Dir(createDirParams, true);
    dataMgr->CreateAppEl5GroupDir(bundleName, userId);
    return true;
}

bool NewBundleDataDirMgr::InnerProcessOtaBundleDataDirGroup(
    const std::string &bundleName, const int32_t userId)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return false;
    }
    if (!dataMgr->CreateAppGroupDir(bundleName, userId)) {
        APP_LOGE("-n %{public}s -u %{public}d create dir group failed", bundleName.c_str(), userId);
        return false;
    }
    return true;
}

bool NewBundleDataDirMgr::AddAllUserId(const std::set<int32_t> userIds)
{
    std::lock_guard<std::mutex> lock(newBundleDataDirMutex_);
    if (!hasInit_) {
        APP_LOGI("load new data dir map start");
        if (!LoadNewBundleDataDirInfosFromDb()) {
            APP_LOGE("load new data dir map failed");
        }
    }
    bool needSave = false;
    for (const auto user : userIds) {
        if (user < Constants::START_USERID) {
            continue;
        }
        if (userIds_.find(user) == userIds_.end()) {
            userIds_.insert(user);
            needSave = true;
        }
    }
    if (needSave && !AddNewBundleDataDirInfosToDb()) {
        APP_LOGE("save userIds to new bundle dir failed");
        return false;
    }
    return true;
}

bool NewBundleDataDirMgr::DeleteUserId(const int32_t userId)
{
    std::lock_guard<std::mutex> lock(newBundleDataDirMutex_);
    if (!hasInit_) {
        APP_LOGI("load new data dir map start");
        if (!LoadNewBundleDataDirInfosFromDb()) {
            APP_LOGE("load new data dir map failed");
        }
    }
    if (userIds_.find(userId) == userIds_.end()) {
        return true;
    }
    APP_LOGI("delete -u %{public}d start", userId);
    userIds_.erase(userId);
    if (userIds_.empty()) {
        newBundleDataDirMap_.clear();
        bundleMutexMap_.clear();
        return DeleteNewBundleDataDirInfosFromDb();
    }
    return AddNewBundleDataDirInfosToDb();
}
}  // namespace AppExecFwk
}  // namespace OHOS