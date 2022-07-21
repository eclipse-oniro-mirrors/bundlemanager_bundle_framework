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

#include "default_app_db.h"

#include <unistd.h>

#include "app_log_wrapper.h"
#include "bundle_data_mgr.h"
#include "bundle_mgr_service.h"
#include "bundle_parser.h"

using namespace OHOS::DistributedKv;

namespace OHOS {
namespace AppExecFwk {
namespace {
    constexpr int32_t TRY_TIMES = 10;
    constexpr int32_t SLEEP_INTERVAL = 100 * 1000;  // 100ms
    constexpr int32_t INITIAL_USER_ID = -1;
    const char* DEFAULT_APP_JSON_PATH = "/system/etc/app/default_app.json";
}

DefaultAppDb::DefaultAppDb()
{
    APP_LOGD("create DefaultAppDb.");
    Init();
}

DefaultAppDb::~DefaultAppDb()
{
    APP_LOGD("destroy DefaultAppDb.");
    dataManager_.CloseKvStore(appId_, kvStorePtr_);
}

void DefaultAppDb::Init()
{
    bool ret = OpenKvDb();
    if (!ret) {
        APP_LOGE("OpenKvDb failed.");
        return;
    }
    LoadDefaultApplicationConfig();
}

bool DefaultAppDb::OpenKvDb()
{
    APP_LOGD("begin to OpenKvDb.");
    Options options = {
        .createIfMissing = true,
        .encrypt = false,
        .autoSync = false,
        .kvStoreType = KvStoreType::SINGLE_VERSION
    };
    Status status = Status::ERROR;
    int32_t count = 1;
    while (count <= TRY_TIMES) {
        status = dataManager_.GetSingleKvStore(options, appId_, storeId_, kvStorePtr_);
        if (status == Status::SUCCESS && kvStorePtr_ != nullptr) {
            APP_LOGD("OpenKvDb success.");
            return true;
        }
        APP_LOGW("GetSingleKvStore failed, error : %{public}d, try times : %{public}d", status, count);
        usleep(SLEEP_INTERVAL);
        count++;
    }
    APP_LOGE("OpenKvDb failed, error : %{public}d", status);
    return false;
}

void DefaultAppDb::LoadDefaultApplicationConfig()
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

bool DefaultAppDb::GetDefaultApplicationInfos(int32_t userId, std::map<std::string, Element>& infos)
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

bool DefaultAppDb::GetDefaultApplicationInfo(int32_t userId, const std::string& type, Element& element)
{
    APP_LOGD("begin to GetDefaultApplicationInfo, userId : %{public}d, type : %{public}s.", userId, type.c_str());
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

bool DefaultAppDb::SetDefaultApplicationInfos(int32_t userId, const std::map<std::string, Element>& infos)
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

bool DefaultAppDb::SetDefaultApplicationInfo(int32_t userId, const std::string& type, const Element& element)
{
    APP_LOGD("begin to SetDefaultApplicationInfo, userId : %{public}d, type : %{public}s.", userId, type.c_str());
    std::map<std::string, Element> infos;
    bool ret = GetDefaultApplicationInfos(userId, infos);
    if (!ret) {
        APP_LOGE("GetDefaultApplicationInfos failed.");
        return false;
    }
    if (infos.find(type) == infos.end()) {
        APP_LOGD("add default app info.");
        infos.emplace(type, element);
    } else {
        APP_LOGD("modify default app info.");
        infos[type] = element;
    }
    ret = SaveDataToDb(userId, infos);
    if (!ret) {
        APP_LOGE("SaveDataToDb failed.");
        return false;
    }
    APP_LOGD("SetDefaultApplicationInfo success.");
    return true;
}

bool DefaultAppDb::DeleteDefaultApplicationInfos(int32_t userId)
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

bool DefaultAppDb::DeleteDefaultApplicationInfo(int32_t userId, const std::string& type)
{
    APP_LOGD("begin to DeleteDefaultApplicationInfo, userId : %{public}d, type : %{public}s.", userId, type.c_str());
    std::map<std::string, Element> infos;
    bool ret = GetDataFromDb(userId, infos);
    if (!ret) {
        APP_LOGE("GetDataFromDb failed.");
        return false;
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

bool DefaultAppDb::GetDataFromDb(int32_t userId, std::map<std::string, Element>& infos)
{
    if (kvStorePtr_ == nullptr && !OpenKvDb()) {
        APP_LOGE("OpenKvDb failed.");
        return false;
    }

    Key key(std::to_string(userId));
    std::vector<Entry> entries;
    Status status = kvStorePtr_->GetEntries(key, entries);
    if (status != Status::SUCCESS) {
        APP_LOGE("get raw data from db failed, error : %{public}d", status);
        dataManager_.CloseKvStore(appId_, kvStorePtr_);
        kvStorePtr_ = nullptr;
        return false;
    }
    // empty is considered correct
    APP_LOGD("get raw data from db success.");
    for (const auto& item : entries) {
        DefaultAppData defaultAppData;
        nlohmann::json jsonObject = nlohmann::json::parse(item.value.ToString(), nullptr, false);
        if (jsonObject.is_discarded() || defaultAppData.FromJson(jsonObject) != ERR_OK) {
            APP_LOGE("error key : %{public}s", item.key.ToString().c_str());
            kvStorePtr_->Delete(item.key);
            continue;
        }
        infos = defaultAppData.infos;
        break;
    }
    APP_LOGD("GetDataFromDb success.");
    return true;
}

bool DefaultAppDb::SaveDataToDb(int32_t userId, const std::map<std::string, Element>& infos)
{
    if (kvStorePtr_ == nullptr && !OpenKvDb()) {
        APP_LOGE("OpenKvDb failed.");
        return false;
    }

    DefaultAppData defaultAppData;
    defaultAppData.infos = infos;
    Key key(std::to_string(userId));
    Value value(defaultAppData.ToString());
    Status status = kvStorePtr_->Put(key, value);
    if (status != Status::SUCCESS) {
        APP_LOGE("put data to db failed, error : %{public}d", status);
        dataManager_.CloseKvStore(appId_, kvStorePtr_);
        kvStorePtr_ = nullptr;
        return false;
    }
    APP_LOGD("SaveDataToDb success.");
    return true;
}

bool DefaultAppDb::DeleteDataFromDb(int32_t userId)
{
    if (kvStorePtr_ == nullptr && !OpenKvDb()) {
        APP_LOGE("OpenKvDb failed.");
        return false;
    }

    Key key(std::to_string(userId));
    Status status = kvStorePtr_->Delete(key);
    if (status != Status::SUCCESS) {
        APP_LOGE("DeleteDataFromDb failed, error : %{public}d", status);
        dataManager_.CloseKvStore(appId_, kvStorePtr_);
        kvStorePtr_ = nullptr;
        return false;
    }
    APP_LOGD("DeleteDataFromDb success.");
    return true;
}

void DefaultAppDb::OnRemoteDied()
{
    APP_LOGD("OnRemoteDied.");
    dataManager_.CloseKvStore(appId_, kvStorePtr_);
    kvStorePtr_ = nullptr;
}

void DefaultAppDb::RegisterDeathListener()
{
    APP_LOGD("RegisterDeathListener.");
    dataManager_.RegisterKvStoreServiceDeathRecipient(shared_from_this());
}

void DefaultAppDb::UnRegisterDeathListener()
{
    APP_LOGD("UnRegisterDeathListener.");
    dataManager_.UnRegisterKvStoreServiceDeathRecipient(shared_from_this());
}
}
}
