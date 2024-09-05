/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "bundle_state_storage.h"

#include <cerrno>
#include <fstream>
#include <sys/stat.h>
#include <unistd.h>

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_service_constants.h"
#include "bundle_util.h"
#include "installd_client.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string::size_type EXPECT_SPLIT_SIZE = 2;
constexpr const char* BUNDLE_USER_INFO_PATH =
    "/data/service/el1/public/bms/bundle_manager_service/bundle_user_info.json";

void NameAndUserIdToKey(
    const std::string &bundleName, int32_t userId, std::string &key)
{
    key.append(bundleName);
    key.append(Constants::FILE_UNDERLINE);
    key.append(std::to_string(userId));
    APP_LOGD("bundleName = %{public}s", bundleName.c_str());
}

bool KeyToNameAndUserId(
    const std::string &key, std::string &bundleName, int32_t &userId)
{
    bool ret = false;
    std::vector<std::string> splitStrs;
    OHOS::SplitStr(key, Constants::FILE_UNDERLINE, splitStrs);
    if (splitStrs.size() == EXPECT_SPLIT_SIZE) {
        bundleName = splitStrs[0];
        userId = atoi(splitStrs[1].c_str());
        ret = true;
    }

    APP_LOGD("bundleName = %{public}s", bundleName.c_str());
    return ret;
}
}

bool BundleStateStorage::HasBundleUserInfoJsonDb()
{
    APP_LOGD("HasBundleUserInfoJsonDb start");
    if (BundleUtil::IsExistFile(BUNDLE_USER_INFO_PATH)) {
        APP_LOGD("Json db exist");
        return true;
    }

    APP_LOGD("Json db not exist, and create it");
    bool isDirExist = BundleUtil::IsExistDir(ServiceConstants::BUNDLE_MANAGER_SERVICE_PATH);
    if (!isDirExist) {
        mode_t mode = S_IRWXU | S_IXGRP | S_IXOTH;
        ErrCode result = InstalldClient::GetInstance()->Mkdir(
            ServiceConstants::BUNDLE_MANAGER_SERVICE_PATH, mode, getuid(), getgid());
        if (result != ERR_OK) {
            APP_LOGE("fail create dir err %{public}d", result);
            return false;
        }
    }

    auto file = fopen(BUNDLE_USER_INFO_PATH, "at++");
    if (file == nullptr) {
        APP_LOGE("create json db failed, errno:%{public}d", errno);
        return false;
    }

    auto ret = fclose(file);
    if (ret != 0) {
        APP_LOGE("ret: %{public}d, errno:%{public}d", ret, errno);
    }

    return false;
}

bool BundleStateStorage::LoadAllBundleStateData(
    std::map<std::string, std::map<int32_t, BundleUserInfo>> &infos)
{
    APP_LOGD("load all bundle state data to map");
    std::lock_guard<std::mutex> lock(bundleStateMutex_);
    std::fstream i(BUNDLE_USER_INFO_PATH);
    nlohmann::json jParse;
    if (!GetBundleStateJson(jParse) || jParse.is_discarded()) {
        APP_LOGE("GetBundleStateJson failed or jParse is discarded");
        return false;
    }

    return LoadAllBundleStateDataFromJson(jParse, infos);
}

bool BundleStateStorage::LoadAllBundleStateDataFromJson(
    nlohmann::json &jParse, std::map<std::string, std::map<int32_t, BundleUserInfo>> &infos)
{
    if (jParse.is_discarded()) {
        APP_LOGE("Bad json due to jParse is discarded");
        return false;
    }

    for (auto &item : jParse.items()) {
        std::string bundleName;
        int32_t userId;
        if (!KeyToNameAndUserId(item.key(), bundleName, userId)) {
            continue;
        }

        BundleUserInfo bundleUserInfo;
        nlohmann::json& jsonObject = item.value();
        if (jsonObject.is_discarded()) {
            APP_LOGE("Load failed due to data is discarded");
            continue;
        }

        bundleUserInfo = jsonObject.get<BundleUserInfo>();
        if (infos.find(bundleName) == infos.end()) {
            std::map<int32_t, BundleUserInfo> tempUser;
            tempUser.try_emplace(userId, bundleUserInfo);
            infos.try_emplace(bundleName, tempUser);
            continue;
        }

        auto& bundleUserInfoMaps = infos.at(bundleName);
        if (bundleUserInfoMaps.find(userId) == bundleUserInfoMaps.end()) {
            bundleUserInfoMaps.try_emplace(userId, bundleUserInfo);
            continue;
        }

        bundleUserInfoMaps.at(userId) = bundleUserInfo;
    }

    return !infos.empty();
}

bool BundleStateStorage::SaveBundleStateStorage(
    const std::string bundleName, int32_t userId, const BundleUserInfo &bundleUserInfo)
{
    APP_LOGD("Save bundle state to json db");
    if (bundleName.empty() || userId < 0) {
        APP_LOGE("Save bundle state failed due to param invalid");
        return false;
    }

    std::lock_guard<std::mutex> lock(bundleStateMutex_);
    std::string appName;
    NameAndUserIdToKey(bundleName, userId, appName);
    nlohmann::json rootJson;
    nlohmann::json jParse;
    if (GetBundleStateJson(jParse) && !jParse.is_discarded()) {
        rootJson = jParse;
    } else {
        APP_LOGW("GetBundleStateJson failed or jParse is discarded, overwrite old data");
    }

    rootJson[appName] = bundleUserInfo;
    bool isEmpty = (rootJson.size() == 0) ? true : false;
    std::ofstream o(BUNDLE_USER_INFO_PATH, std::ios::out | std::ios::trunc);
    if (!o.is_open()) {
        APP_LOGE("open failed bundle state file, errno:%{public}d", errno);
        return false;
    }
    if (!isEmpty) {
        o << std::setw(Constants::DUMP_INDENT) << rootJson;
    }
    o.close();
    return true;
}

bool BundleStateStorage::GetBundleStateStorage(
    const std::string bundleName, int32_t userId, BundleUserInfo &bundleUserInfo)
{
    if (bundleName.empty() || userId < 0) {
        APP_LOGE("Get bundle state data failed due to param invalid");
        return false;
    }

    std::lock_guard<std::mutex> lock(bundleStateMutex_);
    std::string appName;
    NameAndUserIdToKey(bundleName, userId, appName);
    nlohmann::json jParse;
    if (!GetBundleStateJson(jParse) || jParse.is_discarded()) {
        APP_LOGE("GetBundleStateJson failed or jParse is discarded");
        return false;
    }

    if (jParse.find(appName) == jParse.end()) {
        APP_LOGE("not find appName = %{public}s", appName.c_str());
        return false;
    }

    bundleUserInfo = jParse.at(appName).get<BundleUserInfo>();
    return true;
}

bool BundleStateStorage::DeleteBundleState(
    const std::string bundleName, int32_t userId)
{
    APP_LOGD("Delete bundle state data");
    if (bundleName.empty() || userId < 0) {
        APP_LOGE("Delete bundle state data failed due to param invalid");
        return false;
    }
    std::lock_guard<std::mutex> lock(bundleStateMutex_);
    std::string appName;
    NameAndUserIdToKey(bundleName, userId, appName);
    nlohmann::json jParse;
    if (!GetBundleStateJson(jParse) || jParse.is_discarded()) {
        APP_LOGE("GetBundleStateJson failed or jParse is discarded");
        return false;
    }

    if (jParse.find(appName) == jParse.end()) {
        APP_LOGD("not find appName = %{public}s", appName.c_str());
        return true;
    }
    jParse.erase(appName);
    bool isEmpty = (jParse.size() == 0) ? true : false;
    std::ofstream o(BUNDLE_USER_INFO_PATH, std::ios::out | std::ios::trunc);
    if (!o.is_open()) {
        APP_LOGE("open failed bundle state file err:%{public}d", errno);
        return false;
    }
    if (!isEmpty) {
        o << std::setw(Constants::DUMP_INDENT) << jParse;
    }
    o.close();
    return true;
}

bool BundleStateStorage::GetBundleStateJson(nlohmann::json &jParse)
{
    std::ifstream i(BUNDLE_USER_INFO_PATH);
    if (!i.is_open()) {
        APP_LOGE("open failed bundle state file, errno:%{public}d", errno);
        return false;
    }
    i.seekg(0, std::ios::end);
    int len = static_cast<int>(i.tellg());
    if (len == 0) {
        i.close();
        APP_LOGE("bundle state file is empty");
        return true;
    }
    i.seekg(0, std::ios::beg);
    jParse = nlohmann::json::parse(i, nullptr, false);
    if (jParse.is_discarded()) {
        i.close();
        APP_LOGE("Get failed due to data is discarded");
        return false;
    }
    i.close();
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS
