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

#include "bms_param.h"

#include "app_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string BMS_PARAM_TABLE_NAME = "bms_param";
}
BmsParam::BmsParam()
{
    APP_LOGD("BmsParam instance is created");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = BMS_PARAM_TABLE_NAME;
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager_->CreateTable();
}

BmsParam::~BmsParam()
{
    APP_LOGD("BmsParam instance is destroyed");
}

bool BmsParam::GetBmsParam(const std::string &key, std::string &value)
{
    if (key.empty()) {
        APP_LOGE("key is empty");
        return false;
    }

    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }

    return rdbDataManager_->QueryData(key, value);
}

bool BmsParam::SaveBmsParam(const std::string &paramKeyInfo, const std::string &paramValueInfo)
{
    if (paramKeyInfo.empty() || paramValueInfo.empty()) {
        APP_LOGE("key or value is empty");
        return false;
    }

    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }

    return rdbDataManager_->InsertData(paramKeyInfo, paramValueInfo);
}

bool BmsParam::DeleteBmsParam(const std::string &key)
{
    if (key.empty()) {
        APP_LOGE("key is empty");
        return false;
    }

    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return false;
    }

    return rdbDataManager_->DeleteData(key);
}

}  // namespace AppExecFwk
}  // namespace OHOS