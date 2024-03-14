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

#include "app_provision_info_rdb.h"
#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_util.h"
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string APP_PROVISION_INFO_RDB_TABLE_NAME = "app_provision_info";
// app provision info table key
const std::string BUNDLE_NAME = "BUNDLE_NAME";
const std::string VERSION_CODE = "VERSION_CODE";
const std::string VERSION_NAME = "VERSION_NAME";
const std::string UUID = "UUID";
const std::string TYPE = "TYPE";
const std::string APP_DISTRIBUTION_TYPE = "APP_DISTRIBUTION_TYPE";
const std::string DEVELOPER_ID = "DEVELOPER_ID";
const std::string CERTIFICATE = "CERTIFICATE";
const std::string APL = "APL";
const std::string ISSUER = "ISSUER";
const std::string VALIDITY_NOT_BEFORE = "VALIDITY_NOT_BEFORE";
const std::string VALIDITY_NOT_AFTER = "VALIDITY_NOT_AFTER";
const std::string SPECIFIED_DISTRIBUTED_TYPE = "SPECIFIED_DISTRIBUTED_TYPE";
const std::string ADDITIONAL_INFO = "ADDITIONAL_INFO";
const std::string DEFAULT_VALUE = "";
const std::string APP_IDENTIFIER = "APP_IDENTIFIER";
const std::string APP_SERVICE_CAPABILITIES = "APP_SERVICE_CAPABILITIES";
const std::string ORGANIZATION = "ORGANIZATION";
const int32_t INDEX_BUNDLE_NAME = 0;
const int32_t INDEX_VERSION_CODE = 1;
const int32_t INDEX_VERSION_NAME = 2;
const int32_t INDEX_UUID = 3;
const int32_t INDEX_TYPE = 4;
const int32_t INDEX_APP_DISTRIBUTION_TYPE = 5;
const int32_t INDEX_DEVELOPER_ID = 6;
const int32_t INDEX_CERTIFICATE = 7;
const int32_t INDEX_APL = 8;
const int32_t INDEX_ISSUER = 9;
const int32_t INDEX_VALIDITY_NOT_BEFORE = 10;
const int32_t INDEX_VALIDITY_NOT_AFTER = 11;
const int32_t INDEX_SPECIFIED_DISTRIBUTED_TYPE = 12;
const int32_t INDEX_ADDITIONAL_INFO = 13;
const int32_t INDEX_APP_IDENTIFIER = 14;
const int32_t INDEX_APP_SERVICE_CAPABILITIES = 15;
const int32_t INDEX_ORGANIZATION = 16;
}

AppProvisionInfoManagerRdb::AppProvisionInfoManagerRdb()
{
    APP_LOGD("create AppProvisionInfoManagerRdb.");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = Constants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = APP_PROVISION_INFO_RDB_TABLE_NAME;
    bmsRdbConfig.createTableSql = std::string(
        "CREATE TABLE IF NOT EXISTS "
        + APP_PROVISION_INFO_RDB_TABLE_NAME
        + "(BUNDLE_NAME TEXT PRIMARY KEY NOT NULL, "
        + "VERSION_CODE INTEGER, VERSION_NAME TEXT, UUID TEXT, "
        + "TYPE TEXT, APP_DISTRIBUTION_TYPE TEXT, DEVELOPER_ID TEXT, CERTIFICATE TEXT, "
        + "APL TEXT, ISSUER TEXT, VALIDITY_NOT_BEFORE INTEGER, VALIDITY_NOT_AFTER INTEGER);");
    // SPECIFIED_DISTRIBUTED_TYPE and ADDITIONAL_INFO insert to old database
    bmsRdbConfig.insertColumnSql.push_back(std::string("ALTER TABLE " + APP_PROVISION_INFO_RDB_TABLE_NAME +
        " ADD SPECIFIED_DISTRIBUTED_TYPE TEXT;"));
    bmsRdbConfig.insertColumnSql.push_back(std::string("ALTER TABLE " + APP_PROVISION_INFO_RDB_TABLE_NAME +
        " ADD ADDITIONAL_INFO TEXT;"));
    bmsRdbConfig.insertColumnSql.push_back(std::string("ALTER TABLE " + APP_PROVISION_INFO_RDB_TABLE_NAME +
        " ADD APP_IDENTIFIER TEXT;"));
    bmsRdbConfig.insertColumnSql.push_back(std::string("ALTER TABLE " + APP_PROVISION_INFO_RDB_TABLE_NAME +
        " ADD APP_SERVICE_CAPABILITIES TEXT;"));
    bmsRdbConfig.insertColumnSql.push_back(std::string("ALTER TABLE " + APP_PROVISION_INFO_RDB_TABLE_NAME +
        " ADD ORGANIZATION TEXT;"));
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager_->CreateTable();
}

AppProvisionInfoManagerRdb::~AppProvisionInfoManagerRdb()
{
    APP_LOGD("destroy AppProvisionInfoManagerRdb.");
}

bool AppProvisionInfoManagerRdb::AddAppProvisionInfo(const std::string &bundleName,
    const AppProvisionInfo &appProvisionInfo)
{
    if (bundleName.empty()) {
        APP_LOGE("AddAppProvisionInfo failed, bundleName is empty");
        return false;
    }
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(BUNDLE_NAME, bundleName);
    valuesBucket.PutLong(VERSION_CODE, static_cast<int64_t>(appProvisionInfo.versionCode));
    valuesBucket.PutString(VERSION_NAME, appProvisionInfo.versionName);
    valuesBucket.PutString(UUID, appProvisionInfo.uuid);
    valuesBucket.PutString(TYPE, appProvisionInfo.type);
    valuesBucket.PutString(APP_DISTRIBUTION_TYPE, appProvisionInfo.appDistributionType);
    valuesBucket.PutString(DEVELOPER_ID, appProvisionInfo.developerId);
    valuesBucket.PutString(CERTIFICATE, appProvisionInfo.certificate);
    valuesBucket.PutString(APL, appProvisionInfo.apl);
    valuesBucket.PutString(ISSUER, appProvisionInfo.issuer);
    valuesBucket.PutLong(VALIDITY_NOT_BEFORE, appProvisionInfo.validity.notBefore);
    valuesBucket.PutLong(VALIDITY_NOT_AFTER, appProvisionInfo.validity.notAfter);
    valuesBucket.PutString(SPECIFIED_DISTRIBUTED_TYPE, DEFAULT_VALUE);
    valuesBucket.PutString(ADDITIONAL_INFO, DEFAULT_VALUE);
    valuesBucket.PutString(APP_IDENTIFIER, appProvisionInfo.appIdentifier);
    valuesBucket.PutString(APP_SERVICE_CAPABILITIES, appProvisionInfo.appServiceCapabilities);
    valuesBucket.PutString(ORGANIZATION, appProvisionInfo.organization);

    return rdbDataManager_->InsertData(valuesBucket);
}

bool AppProvisionInfoManagerRdb::DeleteAppProvisionInfo(const std::string &bundleName)
{
    if (bundleName.empty()) {
        return false;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(APP_PROVISION_INFO_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(BUNDLE_NAME, bundleName);
    return rdbDataManager_->DeleteData(absRdbPredicates);
}

bool AppProvisionInfoManagerRdb::GetAppProvisionInfo(const std::string &bundleName,
    AppProvisionInfo &appProvisionInfo)
{
    if (bundleName.empty()) {
        return false;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(APP_PROVISION_INFO_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(BUNDLE_NAME, bundleName);
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("AppProvisionInfoManagerRdb GetAppProvisionInfo failed.");
        return false;
    }
    ScopeGuard stateGuard([absSharedResultSet] { absSharedResultSet->Close(); });
    return ConvertToAppProvision(absSharedResultSet, appProvisionInfo);
}

bool AppProvisionInfoManagerRdb::GetAllAppProvisionInfoBundleName(std::unordered_set<std::string> &bundleNames)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(APP_PROVISION_INFO_RDB_TABLE_NAME);
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("GetAppProvisionInfo failed.");
        return false;
    }
    ScopeGuard stateGuard([absSharedResultSet] { absSharedResultSet->Close(); });

    auto ret = absSharedResultSet->GoToFirstRow();
    CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GoToFirstRow failed, ret: %{public}d");
    do {
        std::string name;
        ret = absSharedResultSet->GetString(INDEX_BUNDLE_NAME, name);
        CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetString bundleName failed, ret: %{public}d");
        bundleNames.insert(name);
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    return true;
}

bool AppProvisionInfoManagerRdb::ConvertToAppProvision(
    const std::shared_ptr<NativeRdb::AbsSharedResultSet> &absSharedResultSet,
    AppProvisionInfo &appProvisionInfo)
{
    if (absSharedResultSet == nullptr) {
        APP_LOGE("absSharedResultSet is nullptr");
        return false;
    }
    auto ret = absSharedResultSet->GoToFirstRow();
    CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GoToFirstRow failed, ret: %{public}d");
    int64_t versionCode;
    ret = absSharedResultSet->GetLong(INDEX_VERSION_CODE, versionCode);
    CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetString versionCode failed, ret: %{public}d");
    appProvisionInfo.versionCode = static_cast<uint32_t>(versionCode);
    ret = absSharedResultSet->GetString(INDEX_VERSION_NAME, appProvisionInfo.versionName);
    CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetString versionName failed, ret: %{public}d");
    ret = absSharedResultSet->GetString(INDEX_UUID, appProvisionInfo.uuid);
    CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetString uuid failed, ret: %{public}d");
    ret = absSharedResultSet->GetString(INDEX_TYPE, appProvisionInfo.type);
    CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetString type failed, ret: %{public}d");
    ret = absSharedResultSet->GetString(INDEX_APP_DISTRIBUTION_TYPE, appProvisionInfo.appDistributionType);
    CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetString appDistributionType failed, ret: %{public}d");
    ret = absSharedResultSet->GetString(INDEX_DEVELOPER_ID, appProvisionInfo.developerId);
    CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetString developerId failed, ret: %{public}d");
    ret = absSharedResultSet->GetString(INDEX_CERTIFICATE, appProvisionInfo.certificate);
    CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetString certificate failed, ret: %{public}d");
    ret = absSharedResultSet->GetString(INDEX_APL, appProvisionInfo.apl);
    CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetString apl failed, ret: %{public}d");
    ret = absSharedResultSet->GetString(INDEX_ISSUER, appProvisionInfo.issuer);
    CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetString issuer failed, ret: %{public}d");
    ret = absSharedResultSet->GetLong(INDEX_VALIDITY_NOT_BEFORE, appProvisionInfo.validity.notBefore);
    CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetString notBefore failed, ret: %{public}d");
    ret = absSharedResultSet->GetLong(INDEX_VALIDITY_NOT_AFTER, appProvisionInfo.validity.notAfter);
    CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetString notAfter failed, ret: %{public}d");
    ret = absSharedResultSet->GetString(INDEX_APP_IDENTIFIER, appProvisionInfo.appIdentifier);
    CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetString appIdentifier failed, ret: %{public}d");
    ret = absSharedResultSet->GetString(INDEX_APP_SERVICE_CAPABILITIES, appProvisionInfo.appServiceCapabilities);
    CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetString appServiceCapabilities failed, ret: %{public}d");
    ret = absSharedResultSet->GetString(INDEX_ORGANIZATION, appProvisionInfo.organization);
    CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetString organization failed, ret: %{public}d");
    return true;
}

bool AppProvisionInfoManagerRdb::SetSpecifiedDistributionType(
    const std::string &bundleName, const std::string &specifiedDistributionType)
{
    if (bundleName.empty()) {
        return false;
    }
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(SPECIFIED_DISTRIBUTED_TYPE, specifiedDistributionType);
    NativeRdb::AbsRdbPredicates absRdbPredicates(APP_PROVISION_INFO_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(BUNDLE_NAME, bundleName);
    if (!rdbDataManager_->UpdateData(valuesBucket, absRdbPredicates)) {
        APP_LOGE("bundleName: %{public}s SetSpecifiedDistributionType failed.", bundleName.c_str());
        return false;
    }
    return true;
}

bool AppProvisionInfoManagerRdb::GetSpecifiedDistributionType(
    const std::string &bundleName, std::string &specifiedDistributionType)
{
    if (bundleName.empty()) {
        return false;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(APP_PROVISION_INFO_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(BUNDLE_NAME, bundleName);
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGW("bundleName: %{public}s, GetSpecifiedDistributionType QueryData failed.", bundleName.c_str());
        return false;
    }
    ScopeGuard stateGuard([absSharedResultSet] { absSharedResultSet->Close(); });
    auto ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        APP_LOGW("bundleName: %{public}s, AppProvisionInfoManagerRdb GetSpecifiedDistributionType failed.",
            bundleName.c_str());
        return false;
    }
    ret = absSharedResultSet->GetString(INDEX_SPECIFIED_DISTRIBUTED_TYPE, specifiedDistributionType);
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("bundleName: %{public}s GetSpecifiedDistributionType GetString failed.", bundleName.c_str());
        return false;
    }
    return true;
}

bool AppProvisionInfoManagerRdb::SetAdditionalInfo(
    const std::string &bundleName, const std::string &additionalInfo)
{
    if (bundleName.empty()) {
        return false;
    }
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(ADDITIONAL_INFO, additionalInfo);
    NativeRdb::AbsRdbPredicates absRdbPredicates(APP_PROVISION_INFO_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(BUNDLE_NAME, bundleName);
    if (!rdbDataManager_->UpdateData(valuesBucket, absRdbPredicates)) {
        APP_LOGE("bundleName: %{public}s SetAdditionalInfo failed.", bundleName.c_str());
        return false;
    }
    return true;
}

bool AppProvisionInfoManagerRdb::GetAdditionalInfo(
    const std::string &bundleName, std::string &additionalInfo)
{
    if (bundleName.empty()) {
        return false;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(APP_PROVISION_INFO_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(BUNDLE_NAME, bundleName);
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGW("bundleName: %{public}s, GetAdditionalInfo QueryData failed.", bundleName.c_str());
        return false;
    }
    ScopeGuard stateGuard([absSharedResultSet] { absSharedResultSet->Close(); });
    auto ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        APP_LOGW("bundleName: %{public}s, AppProvisionInfoManagerRdb GetAdditionalInfo failed.", bundleName.c_str());
        return false;
    }
    ret = absSharedResultSet->GetString(INDEX_ADDITIONAL_INFO, additionalInfo);
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("bundleName: %{public}s, AppProvisionInfoManagerRdb GetAdditionalInfo failed.", bundleName.c_str());
        return false;
    }
    return true;
}
} // namespace AppExecFwk
} // namespace OHOS
