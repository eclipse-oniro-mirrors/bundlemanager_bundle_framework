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

#include "default_app_rdb.h"

#include "app_log_tag_wrapper.h"
#include "bundle_mgr_service.h"
#include "bundle_parser.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int8_t INITIAL_USER_ID = -1;
constexpr const char* DEFAULT_APP_JSON_PATH = "/etc/app/default_app.json";
constexpr const char* BACK_UP_DEFAULT_APP_JSON_PATH = "/etc/app/backup_default_app.json";
constexpr const char* DEFAULT_APP_RDB_TABLE_NAME = "default_app";
}
DefaultAppRdb::DefaultAppRdb()
{
    LOG_D(BMS_TAG_DEFAULT, "create DefaultAppRdb");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = DEFAULT_APP_RDB_TABLE_NAME;
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager_->CreateTable();
    ConvertMimeTypeToUtd();
    LoadDefaultApplicationConfig();
    LoadBackUpDefaultApplicationConfig();
}

DefaultAppRdb::~DefaultAppRdb()
{
    LOG_D(BMS_TAG_DEFAULT, "destroy DefaultAppRdb");
}

bool DefaultAppRdb::GetDefaultApplicationInfos(int32_t userId, std::map<std::string, Element>& infos)
{
    LOG_D(BMS_TAG_DEFAULT, "begin to GetDefaultApplicationInfos, userId : %{public}d", userId);
    bool ret = GetDataFromDb(userId, infos);
    if (!ret) {
        LOG_E(BMS_TAG_DEFAULT, "GetDataFromDb failed");
        return false;
    }

    LOG_D(BMS_TAG_DEFAULT, "GetDefaultApplicationInfos success");
    return true;
}

bool DefaultAppRdb::GetDefaultApplicationInfo(int32_t userId, const std::string& type, Element& element)
{
    LOG_D(BMS_TAG_DEFAULT, "begin to GetDefaultApplicationInfo, userId : %{public}d, type : %{public}s",
        userId, type.c_str());
    std::map<std::string, Element> infos;
    bool ret = GetDefaultApplicationInfos(userId, infos);
    if (!ret) {
        LOG_E(BMS_TAG_DEFAULT, "GetDefaultApplicationInfos failed");
        return false;
    }

    if (infos.find(type) == infos.end()) {
        LOG_D(BMS_TAG_DEFAULT, "type is not saved in db");
        return false;
    }

    element = infos.find(type)->second;
    LOG_D(BMS_TAG_DEFAULT, "GetDefaultApplicationInfo success");
    return true;
}

bool DefaultAppRdb::SetDefaultApplicationInfos(int32_t userId, const std::map<std::string, Element>& infos)
{
    LOG_D(BMS_TAG_DEFAULT, "begin to SetDefaultApplicationInfos, userId : %{public}d", userId);
    bool ret = SaveDataToDb(userId, infos);
    if (!ret) {
        LOG_E(BMS_TAG_DEFAULT, "SaveDataToDb failed");
        return false;
    }

    LOG_D(BMS_TAG_DEFAULT, "SetDefaultApplicationInfos success");
    return true;
}

bool DefaultAppRdb::SetDefaultApplicationInfo(int32_t userId, const std::string& type, const Element& element)
{
    LOG_D(BMS_TAG_DEFAULT, "SetDefaultApplicationInfo userId:%{public}d type:%{public}s", userId, type.c_str());
    std::map<std::string, Element> infos;
    GetDefaultApplicationInfos(userId, infos);
    if (infos.find(type) == infos.end()) {
        LOG_D(BMS_TAG_DEFAULT, "add default app info");
        infos.emplace(type, element);
    } else {
        LOG_D(BMS_TAG_DEFAULT, "modify default app info");
        infos[type] = element;
    }

    bool ret = SaveDataToDb(userId, infos);
    if (!ret) {
        LOG_E(BMS_TAG_DEFAULT, "SaveDataToDb failed");
        return false;
    }

    LOG_D(BMS_TAG_DEFAULT, "SetDefaultApplicationInfo success");
    return true;
}

bool DefaultAppRdb::DeleteDefaultApplicationInfos(int32_t userId)
{
    LOG_D(BMS_TAG_DEFAULT, "begin to DeleteDefaultApplicationInfos, userId : %{public}d", userId);
    bool ret = DeleteDataFromDb(userId);
    if (!ret) {
        LOG_E(BMS_TAG_DEFAULT, "DeleteDataFromDb failed");
        return false;
    }

    LOG_D(BMS_TAG_DEFAULT, "DeleteDefaultApplicationInfos success");
    return true;
}

bool DefaultAppRdb::DeleteDefaultApplicationInfo(int32_t userId, const std::string& type)
{
    LOG_D(BMS_TAG_DEFAULT, "begin to delete userId: %{public}d, type: %{public}s", userId, type.c_str());
    std::map<std::string, Element> infos;
    bool ret = GetDataFromDb(userId, infos);
    if (!ret) {
        LOG_E(BMS_TAG_DEFAULT, "GetDataFromDb failed");
        return true;
    }

    if (infos.find(type) == infos.end()) {
        LOG_D(BMS_TAG_DEFAULT, "type doesn't exists in db");
        return true;
    }

    infos.erase(type);
    ret = SaveDataToDb(userId, infos);
    if (!ret) {
        LOG_E(BMS_TAG_DEFAULT, "SaveDataToDb failed");
        return false;
    }

    LOG_D(BMS_TAG_DEFAULT, "DeleteDefaultApplicationInfo success");
    return true;
}

void DefaultAppRdb::ConvertMimeTypeToUtd()
{
    std::shared_ptr<BundleDataMgr> dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_W(BMS_TAG_DEFAULT, "dataMgr is null");
        return;
    }
    std::set<int32_t> allUsers = dataMgr->GetAllUser();
    allUsers.insert(INITIAL_USER_ID);
    allUsers.insert(ServiceConstants::BACKUP_DEFAULT_APP_KEY);

    for (int32_t userId : allUsers) {
        std::map<std::string, Element> infos;
        if (!GetDefaultApplicationInfos(userId, infos)) {
            continue;
        }
        std::map<std::string, Element> newInfos;
        for (auto& item : infos) {
            std::vector<std::string> normalizedTypeVector = DefaultAppMgr::Normalize(item.first);
            if (normalizedTypeVector.empty()) {
                LOG_W(BMS_TAG_DEFAULT, "normalize %{public}s failed", item.first.c_str());
                continue;
            }
            for (const std::string& normalizedType : normalizedTypeVector) {
                item.second.type = normalizedType;
                newInfos.emplace(normalizedType, item.second);
            }
        }
        (void)SetDefaultApplicationInfos(userId, newInfos);
    }
}

bool DefaultAppRdb::ParseConfig(const std::string& relativePath, DefaultAppData& defaultAppData)
{
    // load default app config from json file
    std::vector<std::string> rootDirs;
    BMSEventHandler::GetPreInstallRootDirList(rootDirs);
    if (rootDirs.empty()) {
        LOG_W(BMS_TAG_DEFAULT, "rootDirs empty");
        return false;
    }
    std::for_each(rootDirs.cbegin(), rootDirs.cend(), [&relativePath, &defaultAppData](const auto& rootDir) {
        std::string path = rootDir + relativePath;
        LOG_D(BMS_TAG_DEFAULT, "default app json path : %{public}s", path.c_str());
        nlohmann::json jsonObject;
        if (!BundleParser::ReadFileIntoJson(path, jsonObject)) {
            LOG_W(BMS_TAG_DEFAULT, "read default app json failed");
            return;
        }
        defaultAppData.ParseDefaultApplicationConfig(jsonObject);
    });
    return !defaultAppData.infos.empty();
}

void DefaultAppRdb::LoadDefaultApplicationConfig()
{
    LOG_D(BMS_TAG_DEFAULT, "begin to LoadDefaultApplicationConfig");
    DefaultAppData defaultAppData;
    if (!ParseConfig(DEFAULT_APP_JSON_PATH, defaultAppData)) {
        LOG_D(BMS_TAG_DEFAULT, "default app config empty");
        return;
    }
    // get pre default app config
    std::map<std::string, Element> preInfos;
    GetDefaultApplicationInfos(INITIAL_USER_ID, preInfos);
    // save to each user
    std::shared_ptr<BundleDataMgr> dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_W(BMS_TAG_DEFAULT, "get BundleDataMgr failed");
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
    LOG_D(BMS_TAG_DEFAULT, "LoadDefaultApplicationConfig done");
}

void DefaultAppRdb::LoadBackUpDefaultApplicationConfig()
{
    LOG_D(BMS_TAG_DEFAULT, "begin");
    DefaultAppData defaultAppData;
    if (!ParseConfig(BACK_UP_DEFAULT_APP_JSON_PATH, defaultAppData)) {
        LOG_D(BMS_TAG_DEFAULT, "backup default app config empty");
        return;
    }
    // save default app config to db
    SetDefaultApplicationInfos(ServiceConstants::BACKUP_DEFAULT_APP_KEY, defaultAppData.infos);
    LOG_D(BMS_TAG_DEFAULT, "end");
}

bool DefaultAppRdb::GetDataFromDb(int32_t userId, std::map<std::string, Element>& infos)
{
    if (rdbDataManager_ == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "rdbDataManager is null");
        return false;
    }

    std::string key = std::to_string(userId);
    std::string value;
    bool result = rdbDataManager_->QueryData(key, value);
    if (!result) {
        LOG_E(BMS_TAG_DEFAULT, "QueryData failed by key %{public}d", userId);
        return false;
    }

    DefaultAppData defaultAppData;
    nlohmann::json jsonObject = nlohmann::json::parse(value, nullptr, false);
    if (jsonObject.is_discarded() || defaultAppData.FromJson(jsonObject) != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "error key : %{public}s", key.c_str());
        rdbDataManager_->DeleteData(key);
        return false;
    }

    infos = defaultAppData.infos;
    return true;
}

bool DefaultAppRdb::SaveDataToDb(int32_t userId, const std::map<std::string, Element>& infos)
{
    if (rdbDataManager_ == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "rdbDataManager is null");
        return false;
    }

    DefaultAppData defaultAppData;
    defaultAppData.infos = infos;
    return rdbDataManager_->InsertData(std::to_string(userId), defaultAppData.ToString());
}

bool DefaultAppRdb::DeleteDataFromDb(int32_t userId)
{
    if (rdbDataManager_ == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "rdbDataManager is null");
        return false;
    }

    return rdbDataManager_->DeleteData(std::to_string(userId));
}

void DefaultAppRdb::RegisterDeathListener()
{
    LOG_D(BMS_TAG_DEFAULT, "RegisterDeathListener");
}

void DefaultAppRdb::UnRegisterDeathListener()
{
    LOG_D(BMS_TAG_DEFAULT, "UnRegisterDeathListener");
}
}
}
