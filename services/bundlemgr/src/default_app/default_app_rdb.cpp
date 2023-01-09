/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "default_app_rdb.h"

#include "app_log_wrapper.h"
#include "bundle_data_mgr.h"
#include "bundle_mgr_service.h"
#include "bundle_parser.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t INITIAL_USER_ID = -1;
const std::string DEFAULT_APP_JSON_PATH = "/system/etc/app/default_app.json";
}
DefaultAppRdb::DefaultAppRdb()
{
    APP_LOGD("create DefaultAppRdb.");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = Constants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = Constants::DEFAULT_APP_RDB_TABLE_NAME;
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager_->CreateTable();
    LoadDefaultApplicationConfig();
}

DefaultAppRdb::~DefaultAppRdb()
{
    APP_LOGD("destroy DefaultAppRdb.");
}

bool DefaultAppRdb::GetDefaultApplicationInfos(int32_t userId, std::map<std::string, Element>& infos)
{
    APP_LOGD("begin to GetDefaultApplicationInfos, userId : %{public}d.", userId);
    bool ret = GetDataFromDb(userId, infos);
    if (!ret) {
        APP_LOGE("GetDataFromDb failed.");
        return false;
    }

    APP_LOGD("GetDefaultApplicationInfos success.");
    return true;
}

bool DefaultAppRdb::GetDefaultApplicationInfo(int32_t userId, const std::string& type, Element& element)
{
    APP_LOGD("begin to GetDefaultApplicationInfo, userId : %{public}d, type : %{public}s.",
        userId, type.c_str());
    std::map<std::string, Element> infos;
    bool ret = GetDefaultApplicationInfos(userId, infos);
    if (!ret) {
        APP_LOGE("GetDefaultApplicationInfos failed.");
        return false;
    }

    if (infos.find(type) == infos.end()) {
        APP_LOGD("type is not saved in db.");
        return false;
    }

    element = infos.find(type)->second;
    APP_LOGD("GetDefaultApplicationInfo success.");
    return true;
}

bool DefaultAppRdb::SetDefaultApplicationInfos(int32_t userId, const std::map<std::string, Element>& infos)
{
    APP_LOGD("begin to SetDefaultApplicationInfos, userId : %{public}d.", userId);
    bool ret = SaveDataToDb(userId, infos);
    if (!ret) {
        APP_LOGE("SaveDataToDb failed.");
        return false;
    }

    APP_LOGD("SetDefaultApplicationInfos success.");
    return true;
}

bool DefaultAppRdb::SetDefaultApplicationInfo(int32_t userId, const std::string& type, const Element& element)
{
    APP_LOGD("begin to SetDefaultApplicationInfo, userId : %{public}d, type : %{public}s.", userId, type.c_str());
    std::map<std::string, Element> infos;
    GetDefaultApplicationInfos(userId, infos);
    if (infos.find(type) == infos.end()) {
        APP_LOGD("add default app info.");
        infos.emplace(type, element);
    } else {
        APP_LOGD("modify default app info.");
        infos[type] = element;
    }

    bool ret = SaveDataToDb(userId, infos);
    if (!ret) {
        APP_LOGE("SaveDataToDb failed.");
        return false;
    }

    APP_LOGD("SetDefaultApplicationInfo success.");
    return true;
}

bool DefaultAppRdb::DeleteDefaultApplicationInfos(int32_t userId)
{
    APP_LOGD("begin to DeleteDefaultApplicationInfos, userId : %{public}d.", userId);
    bool ret = DeleteDataFromDb(userId);
    if (!ret) {
        APP_LOGE("DeleteDataFromDb failed.");
        return false;
    }

    APP_LOGD("DeleteDefaultApplicationInfos success.");
    return true;
}

bool DefaultAppRdb::DeleteDefaultApplicationInfo(int32_t userId, const std::string& type)
{
    APP_LOGD("begin to DeleteDefaultApplicationInfo, userId : %{public}d, type : %{public}s.", userId, type.c_str());
    std::map<std::string, Element> infos;
    bool ret = GetDataFromDb(userId, infos);
    if (!ret) {
        APP_LOGE("GetDataFromDb failed.");
        return true;
    }

    if (infos.find(type) == infos.end()) {
        APP_LOGD("type doesn't exists in db.");
        return true;
    }

    infos.erase(type);
    ret = SaveDataToDb(userId, infos);
    if (!ret) {
        APP_LOGE("SaveDataToDb failed.");
        return false;
    }

    APP_LOGD("DeleteDefaultApplicationInfo success.");
    return true;
}

void DefaultAppRdb::LoadDefaultApplicationConfig()
{
    APP_LOGD("begin to LoadDefaultApplicationConfig.");
    // load default app config from json file
    nlohmann::json jsonObject;
    bool ret = BundleParser::ReadFileIntoJson(DEFAULT_APP_JSON_PATH, jsonObject);
    if (!ret) {
        APP_LOGW("read default app json file failed.");
        return;
    }

    DefaultAppData defaultAppData;
    ret = defaultAppData.ParseDefaultApplicationConfig(jsonObject);
    if (!ret) {
        APP_LOGW("default app json file format invalid.");
        return;
    }

    // get pre default app config
    std::map<std::string, Element> preInfos;
    GetDefaultApplicationInfos(INITIAL_USER_ID, preInfos);
    // save to each user
    std::shared_ptr<BundleDataMgr> dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGW("get BundleDataMgr failed.");
        return;
    }

    std::set<int32_t> allUsers = dataMgr->GetAllUser();
    for (int32_t userId : allUsers) {
        std::map<std::string, Element> infos;
        GetDefaultApplicationInfos(userId, infos);
        for (const auto& item : defaultAppData.infos) {
            const std::string& type = item.first;
            const Element& element = item.second;
            if (infos.find(type) != infos.end() && preInfos.find(type) != preInfos.end()
                && infos.find(type)->second == preInfos.find(type)->second) {
                infos[type] = element;
            } else {
                infos.try_emplace(type, element);
            }
        }

        SetDefaultApplicationInfos(userId, infos);
    }

    // save default app config to db
    SetDefaultApplicationInfos(INITIAL_USER_ID, defaultAppData.infos);
    APP_LOGD("LoadDefaultApplicationConfig done.");
}

bool DefaultAppRdb::GetDataFromDb(int32_t userId, std::map<std::string, Element>& infos)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }

    std::string key = std::to_string(userId);
    std::string value;
    bool result = rdbDataManager_->QueryData(key, value);
    if (!result) {
        APP_LOGE("QueryData failed by key %{public}d", userId);
        return false;
    }

    DefaultAppData defaultAppData;
    nlohmann::json jsonObject = nlohmann::json::parse(value, nullptr, false);
    if (jsonObject.is_discarded() || defaultAppData.FromJson(jsonObject) != ERR_OK) {
        APP_LOGE("error key : %{public}s", key.c_str());
        rdbDataManager_->DeleteData(key);
        return false;
    }

    infos = defaultAppData.infos;
    return true;
}

bool DefaultAppRdb::SaveDataToDb(int32_t userId, const std::map<std::string, Element>& infos)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }

    DefaultAppData defaultAppData;
    defaultAppData.infos = infos;
    return rdbDataManager_->InsertData(std::to_string(userId), defaultAppData.ToString());
}

bool DefaultAppRdb::DeleteDataFromDb(int32_t userId)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }

    return rdbDataManager_->DeleteData(std::to_string(userId));
}

void DefaultAppRdb::RegisterDeathListener()
{
    APP_LOGD("RegisterDeathListener.");
}

void DefaultAppRdb::UnRegisterDeathListener()
{
    APP_LOGD("UnRegisterDeathListener.");
}
}
}
