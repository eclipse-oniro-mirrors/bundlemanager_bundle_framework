/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "mime_type_rdb.h"

#include "app_log_wrapper.h"
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
namespace{
const std::string MIME_TYPE_RDB_TABLE_NAME = "mime_type";
const std::string BUNDLE_NAME = "BUNDLE_NAME";
const std::string MODULE_NAME = "MODULE_NAME";
const std::string ABILITY_NAME = "ABILITY_NAME";
const std::string EXT_NAME = "EXT_NAME";
const std::string MIME_TYPE = "MIME_TYPE";
const int32_t EXT_NAME_INDEX = 4;
const int32_t MIME_TYPE_INDEX = 5;
}

MimeTypeRdb::MimeTypeRdb()
{
    APP_LOGD("create MimeTypeRdb");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = Constants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = MIME_TYPE_RDB_TABLE_NAME;
    bmsRdbConfig.createTableSql = std::string(
        "CREATE TABLE IF NOT EXISTS "
        + MIME_TYPE_RDB_TABLE_NAME
        + "(BUNDLE_NAME TEXT PRIMARY KEY NOT NULL, "
        + "MODULE_NAME TEXT, ABILITY_NAME TEXT, EXT_NAME TEXT, MIME_TYPE TEXT);");
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager_->CreateTable();
}

MimeTypeRdb::~MimeTypeRdb()
{
    APP_LOGD("destroy MimeTypeRdb");
}

bool MimeTypeRdb::SetExtNameOrMimeTypeToAbility(const std::string &bundleName, const std::string &moduleName,
        const std::string &abilityName, const std::string &extName, const std::string &mimeType)
{
    if (bundleName.empty() || moduleName.empty() || abilityName.empty()) {
        APP_LOGE("bundleName, moduleName and abilityName must no be empty");
        return false;
    }
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(BUNDLE_NAME, bundleName);
    valuesBucket.PutString(MODULE_NAME, moduleName);
    valuesBucket.PutString(ABILITY_NAME, abilityName);
    valuesBucket.PutString(EXT_NAME, extName);
    valuesBucket.PutString(MIME_TYPE, mimeType);

    return rdbDataManager_->InsertData(valuesBucket);
}

bool MimeTypeRdb::DelExtNameOrMimeTypeToAbility(const std::string &bundleName, const std::string &moduleName,
        const std::string &abilityName, const std::string &extName, const std::string &mimeType)
{
    if (bundleName.empty() || moduleName.empty() || abilityName.empty()) {
        APP_LOGE("bundleName, moduleName and abilityName must no be empty");
        return false;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(MIME_TYPE_RDB_TABLE_NAME);
    AbsRdbPredicates.EqualTo(BUNDLE_NAME, bundleName);
    AbsRdbPredicates.EqualTo(MODULE_NAME, moduleName);
    AbsRdbPredicates.EqualTo(ABILITY_NAME, abilityName);
    if (!extName.empty())
    AbsRdbPredicates.EqualTo(EXT_NAME, extName);
    AbsRdbPredicates.EqualTo(MIME_TYPE, mimeType);
    return rdbDataManager_->DeleteData(absRdbPredicates);
}

bool MimeTypeRdb::GetExtAndTypeByAbility(const std::string &bundleName, const std::string &moduleName,
        const std::string &abilityName, std::vector<std::pair<std::string, std::string>> extAndTypes)
{
    AbsRdbPredicates.EqualTo(BUNDLE_NAME, bundleName);
    AbsRdbPredicates.EqualTo(MODULE_NAME, moduleName);
    AbsRdbPredicates.EqualTo(ABILITY_NAME, abilityName);
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("GetAppProvisionInfo failed.");
        return false;
    }
    ScopeGuard stateGuard([absSharedResultSet] { absSharedResultSet->Close(); });
    auto ret = absSharedResultSet->GoToFirstRow();
    CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GoToFirstRow failed, ret: %{public}d");
    do {
        std::string extName;
        ret = absSharedResultSet->GetString(EXT_NAME_INDEX, extName);
        CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetString extName failed, ret: %{public}d");
        std::string mimeType;
        ret = absSharedResultSet->GetString(MIME_TYPE_INDEX, mimeType);
            CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetString mimeType failed, ret: %{public}d");
        extAndTypes.emplace_back(extName, mimeType);
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    return true;
}

}
}