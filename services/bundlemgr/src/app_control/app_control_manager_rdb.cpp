/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "app_control_manager_rdb.h"

#include "app_control_constants.h"
#include "app_log_tag_wrapper.h"
#include "bms_extension_client.h"
#include "bundle_util.h"
#include "hitrace_meter.h"
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
    constexpr const char* APP_CONTROL_RDB_TABLE_NAME = "app_control";
    constexpr const char* RUNNING_CONTROL = "RunningControl";
    constexpr const char* DISPOSED_RULE = "DisposedRule";
    constexpr const char* UNINSTALL_DISPOSED_RULE = "UninstallDisposedRule";
    constexpr const char* APP_CONTROL_EDM_DEFAULT_MESSAGE = "The app has been disabled by EDM";
    constexpr int8_t CALLING_NAME_INDEX = 1;
    constexpr int8_t APP_ID_INDEX = 4;
    constexpr int8_t CONTROL_MESSAGE_INDEX = 5;
    constexpr int8_t DISPOSED_STATUS_INDEX = 6;
    constexpr int8_t TIME_STAMP_INDEX = 8;
    constexpr int8_t ALLOW_RUNNING_INDEX = 10;
    // app control table key
    constexpr const char* CALLING_NAME = "CALLING_NAME";
    constexpr const char* APP_CONTROL_LIST = "APP_CONTROL_LIST";
    constexpr const char* USER_ID = "USER_ID";
    constexpr const char* APP_ID = "APP_ID";
    constexpr const char* CONTROL_MESSAGE = "CONTROL_MESSAGE";
    constexpr const char* DISPOSED_STATUS = "DISPOSED_STATUS";
    constexpr const char* PRIORITY = "PRIORITY";
    constexpr const char* TIME_STAMP = "TIME_STAMP";
    constexpr const char* APP_INDEX = "APP_INDEX";
    constexpr const char* ALLOW_RUNNING = "ALLOW_RUNNING";

    enum class PRIORITY : uint16_t {
        EDM = 100,
        APP_MARKET = 200,
    };
}
AppControlManagerRdb::AppControlManagerRdb()
{
    LOG_D(BMS_TAG_DEFAULT, "create AppControlManagerRdb");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = APP_CONTROL_RDB_TABLE_NAME;
    bmsRdbConfig.createTableSql = std::string(
        "CREATE TABLE IF NOT EXISTS "
        + std::string(APP_CONTROL_RDB_TABLE_NAME)
        + "(ID INTEGER PRIMARY KEY AUTOINCREMENT, CALLING_NAME TEXT NOT NULL, "
        + "APP_CONTROL_LIST TEXT, USER_ID INTEGER, APP_ID TEXT, CONTROL_MESSAGE TEXT, "
        + "DISPOSED_STATUS TEXT, PRIORITY INTEGER, TIME_STAMP INTEGER);");
    bmsRdbConfig.insertColumnSql.push_back(std::string("ALTER TABLE " + std::string(APP_CONTROL_RDB_TABLE_NAME) +
        " ADD APP_INDEX INTEGER DEFAULT 0;"));
    bmsRdbConfig.insertColumnSql.push_back(std::string("ALTER TABLE " + std::string(APP_CONTROL_RDB_TABLE_NAME) +
        " ADD ALLOW_RUNNING INTEGER;"));
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager_->CreateTable();
}

AppControlManagerRdb::~AppControlManagerRdb()
{
    LOG_D(BMS_TAG_DEFAULT, "destroy AppControlManagerRdb");
}

ErrCode AppControlManagerRdb::AddAppInstallControlRule(const std::string &callingName,
    const std::vector<std::string> &appIds, const std::string &controlRuleType, int32_t userId)
{
    int64_t timeStamp = BundleUtil::GetCurrentTime();
    std::vector<NativeRdb::ValuesBucket> valuesBuckets;
    for (auto appId : appIds) {
        ErrCode result = DeleteOldControlRule(callingName, controlRuleType, appId, userId);
        if (result != ERR_OK) {
            LOG_E(BMS_TAG_DEFAULT, "DeleteOldControlRule failed");
            return result;
        }
        NativeRdb::ValuesBucket valuesBucket;
        valuesBucket.PutString(CALLING_NAME, callingName);
        valuesBucket.PutString(APP_CONTROL_LIST, controlRuleType);
        valuesBucket.PutInt(USER_ID, static_cast<int>(userId));
        valuesBucket.PutString(APP_ID, appId);
        valuesBucket.PutInt(TIME_STAMP, timeStamp);
        valuesBuckets.emplace_back(valuesBucket);
    }
    int64_t insertNum = 0;
    bool ret = rdbDataManager_->BatchInsert(insertNum, valuesBuckets);
    if (!ret) {
        LOG_E(BMS_TAG_DEFAULT, "BatchInsert failed");
        return ERR_APPEXECFWK_DB_BATCH_INSERT_ERROR;
    }
    if (valuesBuckets.size() != static_cast<uint64_t>(insertNum)) {
        LOG_E(BMS_TAG_DEFAULT, "BatchInsert size not expected");
        return ERR_APPEXECFWK_DB_BATCH_INSERT_ERROR;
    }
    return ERR_OK;
}

ErrCode AppControlManagerRdb::DeleteAppInstallControlRule(const std::string &callingName,
    const std::string &controlRuleType, const std::vector<std::string> &appIds, int32_t userId)
{
    for (const auto &appId : appIds) {
        NativeRdb::AbsRdbPredicates absRdbPredicates(APP_CONTROL_RDB_TABLE_NAME);
        absRdbPredicates.EqualTo(CALLING_NAME, callingName);
        absRdbPredicates.EqualTo(APP_CONTROL_LIST, controlRuleType);
        absRdbPredicates.EqualTo(USER_ID, std::to_string(userId));
        absRdbPredicates.EqualTo(APP_ID, appId);
        bool ret = rdbDataManager_->DeleteData(absRdbPredicates);
        if (!ret) {
            LOG_E(BMS_TAG_DEFAULT, "Delete failed callingName:%{public}s appId:%{private}s userId:%{public}d",
                callingName.c_str(), appId.c_str(), userId);
            return ERR_APPEXECFWK_DB_DELETE_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode AppControlManagerRdb::DeleteAppInstallControlRule(const std::string &callingName,
    const std::string &controlRuleType, int32_t userId)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(APP_CONTROL_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(CALLING_NAME, callingName);
    absRdbPredicates.EqualTo(APP_CONTROL_LIST, controlRuleType);
    absRdbPredicates.EqualTo(USER_ID, std::to_string(userId));
    bool ret = rdbDataManager_->DeleteData(absRdbPredicates);
    if (!ret) {
        LOG_E(BMS_TAG_DEFAULT, "DeleteData callingName:%{public}s controlRuleType:%{public}s failed",
            callingName.c_str(), controlRuleType.c_str());
        return ERR_APPEXECFWK_DB_DELETE_ERROR;
    }
    return ERR_OK;
}

ErrCode AppControlManagerRdb::GetAppInstallControlRule(const std::string &callingName,
    const std::string &controlRuleType, int32_t userId, std::vector<std::string> &appIds)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(APP_CONTROL_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(CALLING_NAME, callingName);
    absRdbPredicates.EqualTo(APP_CONTROL_LIST, controlRuleType);
    absRdbPredicates.EqualTo(USER_ID, std::to_string(userId));
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "GetAppInstallControlRule failed");
        return ERR_APPEXECFWK_DB_RESULT_SET_EMPTY;
    }
    ScopeGuard stateGuard([&] { absSharedResultSet->Close(); });
    int32_t count;
    int ret = absSharedResultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        LOG_E(BMS_TAG_DEFAULT, "GetRowCount failed, ret: %{public}d", ret);
        return ERR_APPEXECFWK_DB_RESULT_SET_EMPTY;
    }
    if (count == 0) {
        LOG_D(BMS_TAG_DEFAULT, "GetAppInstallControlRule size 0");
        return ERR_OK;
    }

    ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        LOG_E(BMS_TAG_DEFAULT, "GoToFirstRow failed, ret: %{public}d", ret);
        return ERR_APPEXECFWK_DB_RESULT_SET_OPT_ERROR;
    }
    do {
        std::string appId;
        ret = absSharedResultSet->GetString(APP_ID_INDEX, appId);
        if (ret != NativeRdb::E_OK) {
            LOG_E(BMS_TAG_DEFAULT, "GetString appId failed, ret: %{public}d", ret);
            return ERR_APPEXECFWK_DB_RESULT_SET_OPT_ERROR;
        }
        appIds.push_back(appId);
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    return ERR_OK;
}

ErrCode AppControlManagerRdb::GetAllUserIdsForRunningControl(std::vector<int32_t> &outUserIds)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(APP_CONTROL_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(APP_CONTROL_LIST, RUNNING_CONTROL);
    absRdbPredicates.EqualTo(CALLING_NAME, AppControlConstants::EDM_CALLING);
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (!absSharedResultSet) {
        LOG_E(BMS_TAG_DEFAULT, "QueryData with absRdbPredicates failed: result set is null");
        return ERR_APPEXECFWK_DB_RESULT_SET_EMPTY;
    }
    ScopeGuard stateGuard([&] { absSharedResultSet->Close(); });
    outUserIds.clear();
    int32_t count;
    int ret = absSharedResultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        LOG_E(BMS_TAG_DEFAULT, "GetRowCount failed, ret: %{public}d", ret);
        return ERR_APPEXECFWK_DB_RESULT_SET_OPT_ERROR;
    }
    if (count == 0) {
        LOG_D(BMS_TAG_DEFAULT, "GetAllUserIdsForRunningControl size 0");
        return ERR_OK;
    }

    std::set<int32_t> uniqueUserIds;
    ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        LOG_E(BMS_TAG_DEFAULT, "GoToFirstRow failed, ret: %{public}d", ret);
        return ERR_APPEXECFWK_DB_RESULT_SET_OPT_ERROR;
    }
    do {
        int columnIndex = -1;
        int32_t userIdValue = 0;
        if (absSharedResultSet->GetColumnIndex(USER_ID, columnIndex) != 0 || columnIndex == -1) {
            continue;
        }
        if (absSharedResultSet->GetInt(columnIndex, userIdValue) != 0) {
            continue;
        }
        if (userIdValue != -1) {
            uniqueUserIds.insert(userIdValue);
        }
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    outUserIds.assign(uniqueUserIds.begin(), uniqueUserIds.end());
    return ERR_OK;
}

ErrCode AppControlManagerRdb::AddAppRunningControlRule(const std::string &callingName,
    const std::vector<AppRunningControlRule> &controlRules, int32_t userId)
{
    int64_t timeStamp = BundleUtil::GetCurrentTime();
    std::vector<NativeRdb::ValuesBucket> valuesBuckets;
    for (auto &controlRule : controlRules) {
        ErrCode result = DeleteOldControlRule(callingName, RUNNING_CONTROL, controlRule.appId, userId);
        if (result != ERR_OK) {
            LOG_E(BMS_TAG_DEFAULT, "DeleteOldControlRule failed");
            return result;
        }
        NativeRdb::ValuesBucket valuesBucket;
        valuesBucket.PutString(CALLING_NAME, callingName);
        valuesBucket.PutString(APP_CONTROL_LIST, RUNNING_CONTROL);
        valuesBucket.PutInt(USER_ID, static_cast<int>(userId));
        valuesBucket.PutString(APP_ID, controlRule.appId);
        valuesBucket.PutString(CONTROL_MESSAGE, controlRule.controlMessage);
        valuesBucket.PutInt(ALLOW_RUNNING, controlRule.allowRunning ? 1 : 0);
        valuesBucket.PutInt(PRIORITY, static_cast<int>(PRIORITY::EDM));
        valuesBucket.PutInt(TIME_STAMP, timeStamp);
        valuesBuckets.emplace_back(valuesBucket);
    }
    int64_t insertNum = 0;
    bool ret = rdbDataManager_->BatchInsert(insertNum, valuesBuckets);
    if (!ret) {
        LOG_E(BMS_TAG_DEFAULT, "BatchInsert AddAppRunningControlRule failed");
        return ERR_APPEXECFWK_DB_BATCH_INSERT_ERROR;
    }
    if (valuesBuckets.size() != static_cast<uint64_t>(insertNum)) {
        LOG_E(BMS_TAG_DEFAULT, "BatchInsert size not expected");
        return ERR_APPEXECFWK_DB_BATCH_INSERT_ERROR;
    }
    return ERR_OK;
}

ErrCode AppControlManagerRdb::DeleteAppRunningControlRule(const std::string &callingName,
    const std::vector<AppRunningControlRule> &controlRules, int32_t userId)
{
    for (auto &rule : controlRules) {
        NativeRdb::AbsRdbPredicates absRdbPredicates(APP_CONTROL_RDB_TABLE_NAME);
        absRdbPredicates.EqualTo(CALLING_NAME, callingName);
        absRdbPredicates.EqualTo(APP_CONTROL_LIST, RUNNING_CONTROL);
        absRdbPredicates.EqualTo(USER_ID, std::to_string(userId));
        absRdbPredicates.EqualTo(APP_ID, rule.appId);
        bool ret = rdbDataManager_->DeleteData(absRdbPredicates);
        if (!ret) {
            LOG_E(BMS_TAG_DEFAULT, "Delete failed callingName:%{public}s appid:%{private}s userId:%{public}d",
                callingName.c_str(), rule.appId.c_str(), userId);
            return ERR_APPEXECFWK_DB_DELETE_ERROR;
        }
    }
    return ERR_OK;
}
ErrCode AppControlManagerRdb::DeleteAppRunningControlRule(const std::string &callingName, int32_t userId)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(APP_CONTROL_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(CALLING_NAME, callingName);
    absRdbPredicates.EqualTo(APP_CONTROL_LIST, RUNNING_CONTROL);
    absRdbPredicates.EqualTo(USER_ID, std::to_string(userId));
    bool ret = rdbDataManager_->DeleteData(absRdbPredicates);
    if (!ret) {
        LOG_E(BMS_TAG_DEFAULT, "DeleteAppRunningControlRule callingName:%{public}s userId:%{public}d failed",
            callingName.c_str(), userId);
        return ERR_APPEXECFWK_DB_DELETE_ERROR;
    }
    return ERR_OK;
}

ErrCode AppControlManagerRdb::GetAppIdsByUserId(int32_t userId, std::vector<std::string> &appIds)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    NativeRdb::AbsRdbPredicates absRdbPredicates(APP_CONTROL_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(APP_CONTROL_LIST, RUNNING_CONTROL);
    absRdbPredicates.EqualTo(CALLING_NAME, AppControlConstants::EDM_CALLING);
    absRdbPredicates.EqualTo(USER_ID, std::to_string(userId));
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "QueryData failed");
        return ERR_APPEXECFWK_DB_RESULT_SET_EMPTY;
    }
    ScopeGuard stateGuard([&] { absSharedResultSet->Close(); });
    int32_t count;
    int ret = absSharedResultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        LOG_E(BMS_TAG_DEFAULT, "GetRowCount failed, ret: %{public}d", ret);
        return ERR_APPEXECFWK_DB_RESULT_SET_OPT_ERROR;
    }
    if (count == 0) {
        LOG_D(BMS_TAG_DEFAULT, "GetAppIdsByUserId size 0");
        return ERR_OK;
    }
    ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        LOG_E(BMS_TAG_DEFAULT, "GoToFirstRow failed, ret: %{public}d", ret);
        return ERR_APPEXECFWK_DB_RESULT_SET_OPT_ERROR;
    }
    do {
        std::string appId;
        ret = absSharedResultSet->GetString(APP_ID_INDEX, appId);
        if (ret != NativeRdb::E_OK) {
            LOG_E(BMS_TAG_DEFAULT, "GetString appId failed, ret: %{public}d", ret);
            return ERR_APPEXECFWK_DB_RESULT_SET_OPT_ERROR;
        }
        appIds.push_back(appId);
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    return ERR_OK;
}

ErrCode AppControlManagerRdb::GetAppRunningControlRuleByUserId(int32_t userId, std::string &appId,
    AppRunningControlRule &controlRuleResult)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    NativeRdb::AbsRdbPredicates absRdbPredicates(APP_CONTROL_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(APP_CONTROL_LIST, RUNNING_CONTROL);
    absRdbPredicates.EqualTo(CALLING_NAME, AppControlConstants::EDM_CALLING);
    absRdbPredicates.EqualTo(USER_ID, std::to_string(userId));
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "QueryData failed");
        return ERR_APPEXECFWK_DB_RESULT_SET_EMPTY;
    }
    ScopeGuard stateGuard([&] { absSharedResultSet->Close(); });
    int32_t count;
    int ret = absSharedResultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        LOG_E(BMS_TAG_DEFAULT, "GetRowCount failed, ret: %{public}d", ret);
        return ERR_APPEXECFWK_DB_RESULT_SET_OPT_ERROR;
    }
    if (count == 0) {
        LOG_D(BMS_TAG_DEFAULT, "GetAppRunningControlRuleByUserId size 0");
        return ERR_OK;
    }
    ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        LOG_E(BMS_TAG_DEFAULT, "GoToFirstRow failed, ret: %{public}d", ret);
        return ERR_APPEXECFWK_DB_RESULT_SET_OPT_ERROR;
    }
    int allowRunningInt = 0;
    ret = absSharedResultSet->GetInt(ALLOW_RUNNING_INDEX, allowRunningInt);
    if (ret != NativeRdb::E_OK) {
        LOG_W(BMS_TAG_DEFAULT, "GetInt allowRunning failed, ret: %{public}d", ret);
        return ERR_APPEXECFWK_DB_RESULT_SET_OPT_ERROR;
    }
    controlRuleResult.allowRunning = (allowRunningInt == 1);
    ret = absSharedResultSet->GetString(APP_ID_INDEX, appId);
    if (ret != NativeRdb::E_OK) {
        LOG_W(BMS_TAG_DEFAULT, "GetString appId failed, ret: %{public}d", ret);
        return ERR_APPEXECFWK_DB_RESULT_SET_OPT_ERROR;
    }
    return ERR_OK;
}

ErrCode AppControlManagerRdb::GetAppRunningControlRule(const std::string &callingName,
    int32_t userId, std::vector<std::string> &appIds, bool &allowRunning)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    NativeRdb::AbsRdbPredicates absRdbPredicates(APP_CONTROL_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(CALLING_NAME, callingName);
    absRdbPredicates.EqualTo(APP_CONTROL_LIST, RUNNING_CONTROL);
    absRdbPredicates.EqualTo(USER_ID, std::to_string(userId));
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "QueryData failed");
        return ERR_APPEXECFWK_DB_RESULT_SET_EMPTY;
    }
    ScopeGuard stateGuard([&] { absSharedResultSet->Close(); });
    int32_t count;
    int ret = absSharedResultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        LOG_E(BMS_TAG_DEFAULT, "GetRowCount failed, ret: %{public}d", ret);
        return ERR_APPEXECFWK_DB_RESULT_SET_OPT_ERROR;
    }
    if (count == 0) {
        LOG_D(BMS_TAG_DEFAULT, "GetAppRunningControlRule size 0");
        return ERR_OK;
    }
    ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        LOG_E(BMS_TAG_DEFAULT, "GoToFirstRow failed, ret: %{public}d", ret);
        return ERR_APPEXECFWK_DB_RESULT_SET_OPT_ERROR;
    }
    int allowRunningInt = 0;
    ret = absSharedResultSet->GetInt(ALLOW_RUNNING_INDEX, allowRunningInt);
    if (ret != NativeRdb::E_OK) {
        LOG_W(BMS_TAG_DEFAULT, "GetInt allowRunning failed, ret: %{public}d", ret);
        return ERR_APPEXECFWK_DB_RESULT_SET_OPT_ERROR;
    }
    allowRunning = (allowRunningInt == 1);
    do {
        std::string appId;
        ret = absSharedResultSet->GetString(APP_ID_INDEX, appId);
        if (ret != NativeRdb::E_OK) {
            LOG_E(BMS_TAG_DEFAULT, "GetString appId failed, ret: %{public}d", ret);
            return ERR_APPEXECFWK_DB_RESULT_SET_OPT_ERROR;
        }
        appIds.push_back(appId);
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    return ERR_OK;
}

ErrCode AppControlManagerRdb::GetAppRunningControlRule(const std::vector<std::string> &appIds,
    int32_t userId, AppRunningControlRuleResult &controlRuleResult)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    NativeRdb::AbsRdbPredicates absRdbPredicates(APP_CONTROL_RDB_TABLE_NAME);
    absRdbPredicates.In(APP_ID, appIds);
    absRdbPredicates.EqualTo(APP_CONTROL_LIST, RUNNING_CONTROL);
    absRdbPredicates.EqualTo(USER_ID, std::to_string(userId));
    absRdbPredicates.OrderByAsc(PRIORITY); // ascending
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "QueryData failed");
        return ERR_APPEXECFWK_DB_RESULT_SET_EMPTY;
    }
    ScopeGuard stateGuard([&] { absSharedResultSet->Close(); });
    int32_t count;
    int ret = absSharedResultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        LOG_E(BMS_TAG_DEFAULT, "GetRowCount failed, ret: %{public}d", ret);
        return ERR_APPEXECFWK_DB_RESULT_SET_OPT_ERROR;
    }
    if (count == 0) {
        LOG_NOFUNC_W(BMS_TAG_DEFAULT, "control rule invalid size 0");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_SET_CONTROL;
    }
    ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        LOG_E(BMS_TAG_DEFAULT, "GoToFirstRow failed, ret: %{public}d", ret);
        return ERR_APPEXECFWK_DB_RESULT_SET_OPT_ERROR;
    }
    std::string callingName;
    if (absSharedResultSet->GetString(CALLING_NAME_INDEX, callingName) != NativeRdb::E_OK) {
        LOG_E(BMS_TAG_DEFAULT, "GetString callingName failed, ret: %{public}d", ret);
        return ERR_APPEXECFWK_DB_RESULT_SET_OPT_ERROR;
    }
    ret = absSharedResultSet->GetString(CONTROL_MESSAGE_INDEX, controlRuleResult.controlMessage);
    if (ret != NativeRdb::E_OK) {
        LOG_W(BMS_TAG_DEFAULT, "GetString controlMessage failed, ret: %{public}d", ret);
        return ERR_APPEXECFWK_DB_RESULT_SET_OPT_ERROR;
    }
    if (controlRuleResult.controlMessage.empty() && callingName == AppControlConstants::EDM_CALLING) {
        LOG_D(BMS_TAG_DEFAULT, "GetString controlMessage default");
        controlRuleResult.controlMessage = APP_CONTROL_EDM_DEFAULT_MESSAGE;
    }
    std::string wantString;
    if (absSharedResultSet->GetString(DISPOSED_STATUS_INDEX, wantString) != NativeRdb::E_OK) {
        LOG_E(BMS_TAG_DEFAULT, "GetString controlWant failed, ret: %{public}d", ret);
    }
    if (!wantString.empty()) {
        std::unique_ptr<Want> wantPtr(Want::FromString(wantString));
        if (wantPtr) {
            controlRuleResult.controlWant = std::make_shared<Want>(*wantPtr);
        } else {
            LOG_E(BMS_TAG_DEFAULT, "wantPtr is null");
        }
    }
    if (callingName == AppControlConstants::EDM_CALLING) {
        controlRuleResult.isEdm = true;
    }
    return ERR_OK;
}

ErrCode AppControlManagerRdb::SetDisposedStatus(const std::string &callingName,
    const std::string &appId, const Want &want, int32_t userId)
{
    LOG_D(BMS_TAG_DEFAULT, "rdb begin to SetDisposedStatus");
    ErrCode code = DeleteDisposedStatus(callingName, appId, userId);
    if (code != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "DeleteDisposedStatus failed");
        return ERR_APPEXECFWK_DB_DELETE_ERROR;
    }
    int64_t timeStamp = BundleUtil::GetCurrentTime();
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(CALLING_NAME, callingName);
    valuesBucket.PutString(APP_CONTROL_LIST, RUNNING_CONTROL);
    valuesBucket.PutString(APP_ID, appId);
    valuesBucket.PutString(DISPOSED_STATUS, want.ToString());
    valuesBucket.PutInt(PRIORITY, static_cast<int>(PRIORITY::APP_MARKET));
    valuesBucket.PutInt(TIME_STAMP, timeStamp);
    valuesBucket.PutString(USER_ID, std::to_string(userId));
    bool ret = rdbDataManager_->InsertData(valuesBucket);
    if (!ret) {
        LOG_E(BMS_TAG_DEFAULT, "SetDisposedStatus callingName:%{public}s appId:%{private}s failed",
            callingName.c_str(), appId.c_str());
        return ERR_APPEXECFWK_DB_INSERT_ERROR;
    }
    return ERR_OK;
}

ErrCode AppControlManagerRdb::DeleteDisposedStatus(const std::string &callingName,
    const std::string &appId, int32_t userId)
{
    LOG_D(BMS_TAG_DEFAULT, "rdb begin to DeleteDisposedStatus");
    NativeRdb::AbsRdbPredicates absRdbPredicates(APP_CONTROL_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(CALLING_NAME, callingName);
    absRdbPredicates.EqualTo(APP_CONTROL_LIST, RUNNING_CONTROL);
    absRdbPredicates.EqualTo(APP_ID, appId);
    absRdbPredicates.EqualTo(USER_ID, std::to_string(userId));
    bool ret = rdbDataManager_->DeleteData(absRdbPredicates);
    if (!ret) {
        LOG_E(BMS_TAG_DEFAULT, "DeleteDisposedStatus callingName:%{public}s appId:%{private}s failed",
            callingName.c_str(), appId.c_str());
        return ERR_APPEXECFWK_DB_DELETE_ERROR;
    }
    return ERR_OK;
}

ErrCode AppControlManagerRdb::GetDisposedStatus(const std::string &callingName,
    const std::string &appId, Want &want, int32_t userId)
{
    LOG_D(BMS_TAG_DEFAULT, "rdb begin to GetDisposedStatus");
    NativeRdb::AbsRdbPredicates absRdbPredicates(APP_CONTROL_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(CALLING_NAME, callingName);
    absRdbPredicates.EqualTo(APP_CONTROL_LIST, RUNNING_CONTROL);
    absRdbPredicates.EqualTo(APP_ID, appId);
    absRdbPredicates.EqualTo(USER_ID, std::to_string(userId));
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "GetAppInstallControlRule failed");
        return ERR_APPEXECFWK_DB_RESULT_SET_EMPTY;
    }
    ScopeGuard stateGuard([&] { absSharedResultSet->Close(); });
    int32_t count;
    int ret = absSharedResultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        LOG_E(BMS_TAG_DEFAULT, "GetRowCount failed, ret: %{public}d", ret);
        return ERR_APPEXECFWK_DB_RESULT_SET_OPT_ERROR;
    }
    if (count == 0) {
        LOG_D(BMS_TAG_DEFAULT, "GetAppRunningControlRule size 0");
        return ERR_OK;
    }
    ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        LOG_E(BMS_TAG_DEFAULT, "GoToFirstRow failed, ret: %{public}d", ret);
        return ERR_APPEXECFWK_DB_RESULT_SET_OPT_ERROR;
    }
    std::string wantString;
    ret = absSharedResultSet->GetString(DISPOSED_STATUS_INDEX, wantString);
    if (ret != NativeRdb::E_OK) {
        LOG_E(BMS_TAG_DEFAULT, "GetString DisposedStatus failed, ret: %{public}d", ret);
        return ERR_APPEXECFWK_DB_RESULT_SET_OPT_ERROR;
    }
    std::unique_ptr<Want> wantPtr(Want::FromString(wantString));
    if (!wantPtr) {
        LOG_E(BMS_TAG_DEFAULT, "wantPtr is null");
        return ERR_BUNDLE_MANAGER_APP_CONTROL_INTERNAL_ERROR;
    }
    want = *wantPtr;
    return ERR_OK;
}

ErrCode AppControlManagerRdb::DeleteOldControlRule(const std::string &callingName, const std::string &controlRuleType,
    const std::string &appId, int32_t userId)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(APP_CONTROL_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(CALLING_NAME, callingName);
    absRdbPredicates.EqualTo(APP_CONTROL_LIST, controlRuleType);
    absRdbPredicates.EqualTo(USER_ID, std::to_string(userId));
    absRdbPredicates.EqualTo(APP_ID, appId);
    bool ret = rdbDataManager_->DeleteData(absRdbPredicates);
    if (!ret) {
        LOG_E(BMS_TAG_DEFAULT, "DeleteOldControlRule %{public}s, %{public}s, %{public}s, %{public}d failed",
            callingName.c_str(), appId.c_str(), controlRuleType.c_str(), userId);
        return ERR_APPEXECFWK_DB_DELETE_ERROR;
    }
    return ERR_OK;
}

ErrCode AppControlManagerRdb::SetDisposedRule(const std::string &callingName,
    const std::string &appId, const DisposedRule &rule, int32_t appIndex, int32_t userId)
{
    int64_t timeStamp = BundleUtil::GetCurrentTime();
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(CALLING_NAME, callingName);
    valuesBucket.PutString(APP_CONTROL_LIST, DISPOSED_RULE);
    valuesBucket.PutString(APP_ID, appId);
    valuesBucket.PutString(DISPOSED_STATUS, rule.ToString());
    valuesBucket.PutInt(PRIORITY, rule.priority);
    valuesBucket.PutInt(TIME_STAMP, timeStamp);
    valuesBucket.PutString(USER_ID, std::to_string(userId));
    valuesBucket.PutString(APP_INDEX, std::to_string(appIndex));
    bool ret = rdbDataManager_->InsertData(valuesBucket);
    if (!ret) {
        LOG_E(BMS_TAG_DEFAULT, "SetDisposedStatus callingName:%{public}s appId:%{private}s failed.",
            callingName.c_str(), appId.c_str());
        return ERR_APPEXECFWK_DB_INSERT_ERROR;
    }
    return ERR_OK;
}

ErrCode AppControlManagerRdb::DeleteDisposedRule(const std::string &callingName,
    const std::vector<std::string> &appIdList, int32_t appIndex, int32_t userId)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(APP_CONTROL_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(CALLING_NAME, callingName);
    absRdbPredicates.EqualTo(APP_CONTROL_LIST, DISPOSED_RULE);
    absRdbPredicates.In(APP_ID, appIdList);
    absRdbPredicates.EqualTo(USER_ID, std::to_string(userId));
    absRdbPredicates.EqualTo(APP_INDEX, std::to_string(appIndex));
    bool ret = rdbDataManager_->DeleteData(absRdbPredicates);
    if (!ret) {
        return ERR_APPEXECFWK_DB_DELETE_ERROR;
    }
    return ERR_OK;
}

ErrCode AppControlManagerRdb::DeleteAllDisposedRuleByBundle(const std::vector<std::string> &appIdList,
    int32_t appIndex, int32_t userId)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(APP_CONTROL_RDB_TABLE_NAME);
    std::vector<std::string> controlList = {DISPOSED_RULE, RUNNING_CONTROL, UNINSTALL_DISPOSED_RULE};
    absRdbPredicates.In(APP_CONTROL_LIST, controlList);
    absRdbPredicates.In(APP_ID, appIdList);
    absRdbPredicates.EqualTo(USER_ID, std::to_string(userId));
    // if appIndex is main app also clear all clone app
    if (appIndex != Constants::MAIN_APP_INDEX) {
        absRdbPredicates.EqualTo(APP_INDEX, std::to_string(appIndex));
    }
    bool ret = rdbDataManager_->DeleteData(absRdbPredicates);
    if (!ret) {
        return ERR_APPEXECFWK_DB_DELETE_ERROR;
    }
    return ERR_OK;
}

ErrCode AppControlManagerRdb::OptimizeDisposedPredicates(const std::string &callingName, const std::string &appId,
    int32_t userId, int32_t appIndex, NativeRdb::AbsRdbPredicates &absRdbPredicates)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    return bmsExtensionClient->OptimizeDisposedPredicates(callingName, appId, userId, appIndex, absRdbPredicates);
}

ErrCode AppControlManagerRdb::GetDisposedRule(const std::string &callingName,
    const std::string &appId, DisposedRule &rule, int32_t appIndex, int32_t userId)
{
    LOG_D(BMS_TAG_DEFAULT, "rdb begin to GetDisposedRule");
    NativeRdb::AbsRdbPredicates absRdbPredicates(APP_CONTROL_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(CALLING_NAME, callingName);
    absRdbPredicates.EqualTo(APP_CONTROL_LIST, DISPOSED_RULE);
    absRdbPredicates.EqualTo(APP_ID, appId);
    absRdbPredicates.EqualTo(USER_ID, std::to_string(userId));
    absRdbPredicates.EqualTo(APP_INDEX, std::to_string(appIndex));
    OptimizeDisposedPredicates(callingName, appId, userId, appIndex, absRdbPredicates);
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "GetAppInstallControlRule failed");
        return ERR_APPEXECFWK_DB_RESULT_SET_EMPTY;
    }
    ScopeGuard stateGuard([&] { absSharedResultSet->Close(); });
    int32_t count;
    int ret = absSharedResultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        LOG_E(BMS_TAG_DEFAULT, "GetRowCount failed, ret: %{public}d", ret);
        return ERR_APPEXECFWK_DB_RESULT_SET_OPT_ERROR;
    }
    if (count == 0) {
        LOG_D(BMS_TAG_DEFAULT, "GetDisposedRule size 0");
        return ERR_OK;
    }
    ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        LOG_E(BMS_TAG_DEFAULT, "GoToFirstRow failed, ret: %{public}d", ret);
        return ERR_APPEXECFWK_DB_RESULT_SET_OPT_ERROR;
    }
    std::string ruleString;
    ret = absSharedResultSet->GetString(DISPOSED_STATUS_INDEX, ruleString);
    if (ret != NativeRdb::E_OK) {
        LOG_E(BMS_TAG_DEFAULT, "GetString DisposedStatus failed, ret: %{public}d", ret);
        return ERR_APPEXECFWK_DB_RESULT_SET_OPT_ERROR;
    }
    DisposedRule::FromString(ruleString, rule);
    return ERR_OK;
}

ErrCode AppControlManagerRdb::GetAbilityRunningControlRule(const std::vector<std::string> &appIdList, int32_t appIndex,
    int32_t userId, std::vector<DisposedRule>& disposedRules)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    LOG_D(BMS_TAG_DEFAULT, "rdb begin to GetAbilityRunningControlRule");
    NativeRdb::AbsRdbPredicates absRdbPredicates(APP_CONTROL_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(APP_CONTROL_LIST, DISPOSED_RULE);
    absRdbPredicates.In(APP_ID, appIdList);
    absRdbPredicates.EqualTo(USER_ID, std::to_string(userId));
    absRdbPredicates.EqualTo(APP_INDEX, std::to_string(appIndex));
    absRdbPredicates.OrderByAsc(PRIORITY); // ascending
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "GetAppInstallControlRule failed");
        return ERR_APPEXECFWK_DB_RESULT_SET_EMPTY;
    }
    ScopeGuard stateGuard([&] { absSharedResultSet->Close(); });
    int32_t count;
    int ret = absSharedResultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        LOG_E(BMS_TAG_DEFAULT, "GetRowCount failed, ret: %{public}d", ret);
        return ERR_APPEXECFWK_DB_RESULT_SET_OPT_ERROR;
    }
    if (count == 0) {
        LOG_D(BMS_TAG_DEFAULT, "GetDisposedRule size 0");
        return ERR_OK;
    }
    ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        LOG_E(BMS_TAG_DEFAULT, "GoToFirstRow failed, ret: %{public}d", ret);
        return ERR_APPEXECFWK_DB_RESULT_SET_OPT_ERROR;
    }
    do {
        ret = GetDisposedRuleFromResultSet(absSharedResultSet, disposedRules);
        if (ret != ERR_OK) {
            return ret;
        }
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    return ERR_OK;
}

ErrCode AppControlManagerRdb::GetDisposedRuleFromResultSet(
    std::shared_ptr<NativeRdb::ResultSet> absSharedResultSet, std::vector<DisposedRule> &disposedRules)
{
    if (absSharedResultSet == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "GetAppInstallControlRule failed");
        return ERR_APPEXECFWK_DB_RESULT_SET_EMPTY;
    }
    std::string ruleString;
    ErrCode ret = absSharedResultSet->GetString(DISPOSED_STATUS_INDEX, ruleString);
    if (ret != NativeRdb::E_OK) {
        LOG_E(BMS_TAG_DEFAULT, "GetString appId failed, ret: %{public}d", ret);
        return ERR_APPEXECFWK_DB_RESULT_SET_OPT_ERROR;
    }
    std::string callerName;
    ret = absSharedResultSet->GetString(CALLING_NAME_INDEX, callerName);
    if (ret != NativeRdb::E_OK) {
        callerName = "";
        LOG_I(BMS_TAG_DEFAULT, "GetString callerName failed, ret: %{public}d", ret);
    }
    int32_t setTime = 0;
    ret = absSharedResultSet->GetInt(TIME_STAMP_INDEX, setTime);
    if (ret != NativeRdb::E_OK) {
        setTime = 0;
        LOG_I(BMS_TAG_DEFAULT, "GetInt setTime failed, ret: %{public}d", ret);
    }
    DisposedRule rule;
    bool parseRet = DisposedRule::FromString(ruleString, rule);
    if (!parseRet) {
        LOG_W(BMS_TAG_DEFAULT, "parse DisposedRule failed");
    }
    rule.callerName = callerName;
    rule.setTime = setTime;
    disposedRules.push_back(rule);
    return ERR_OK;
}

ErrCode AppControlManagerRdb::SetUninstallDisposedRule(const std::string &callingName,
    const std::string &appIdentifier, const UninstallDisposedRule &rule, int32_t appIndex, int32_t userId)
{
    LOG_D(BMS_TAG_DEFAULT, "begin");
    NativeRdb::AbsRdbPredicates absRdbPredicates(APP_CONTROL_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(CALLING_NAME, callingName);
    absRdbPredicates.EqualTo(APP_CONTROL_LIST, UNINSTALL_DISPOSED_RULE);
    absRdbPredicates.EqualTo(APP_ID, appIdentifier);
    absRdbPredicates.EqualTo(USER_ID, std::to_string(userId));
    absRdbPredicates.EqualTo(APP_INDEX, std::to_string(appIndex));

    int64_t timeStamp = BundleUtil::GetCurrentTime();
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(CALLING_NAME, callingName);
    valuesBucket.PutString(APP_CONTROL_LIST, UNINSTALL_DISPOSED_RULE);
    valuesBucket.PutString(APP_ID, appIdentifier);
    valuesBucket.PutString(DISPOSED_STATUS, rule.ToString());
    valuesBucket.PutInt(PRIORITY, rule.priority);
    valuesBucket.PutInt(TIME_STAMP, timeStamp);
    valuesBucket.PutString(USER_ID, std::to_string(userId));
    valuesBucket.PutString(APP_INDEX, std::to_string(appIndex));
    bool ret = rdbDataManager_->UpdateOrInsertData(valuesBucket, absRdbPredicates);
    if (!ret) {
        LOG_E(BMS_TAG_DEFAULT, "callingName:%{public}s appIdentifier:%{private}s failed.",
            callingName.c_str(), appIdentifier.c_str());
        return ERR_APPEXECFWK_DB_UPDATE_ERROR;
    }
    return ERR_OK;
}

ErrCode AppControlManagerRdb::DeleteUninstallDisposedRule(const std::string &callingName,
    const std::string &appIdentifier, int32_t appIndex, int32_t userId)
{
    LOG_D(BMS_TAG_DEFAULT, "begin");
    NativeRdb::AbsRdbPredicates absRdbPredicates(APP_CONTROL_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(CALLING_NAME, callingName);
    absRdbPredicates.EqualTo(APP_CONTROL_LIST, UNINSTALL_DISPOSED_RULE);
    absRdbPredicates.EqualTo(APP_ID, appIdentifier);
    absRdbPredicates.EqualTo(USER_ID, std::to_string(userId));
    absRdbPredicates.EqualTo(APP_INDEX, std::to_string(appIndex));
    bool ret = rdbDataManager_->DeleteData(absRdbPredicates);
    if (!ret) {
        LOG_E(BMS_TAG_DEFAULT, "callingName:%{public}s appIdentifier:%{private}s failed",
            callingName.c_str(), appIdentifier.c_str());
        return ERR_APPEXECFWK_DB_DELETE_ERROR;
    }
    return ERR_OK;
}

ErrCode AppControlManagerRdb::GetUninstallDisposedRule(const std::string &appIdentifier,
    int32_t appIndex, int32_t userId, UninstallDisposedRule &rule)
{
    LOG_D(BMS_TAG_DEFAULT, "begin");
    NativeRdb::AbsRdbPredicates absRdbPredicates(APP_CONTROL_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(APP_CONTROL_LIST, UNINSTALL_DISPOSED_RULE);
    absRdbPredicates.EqualTo(APP_ID, appIdentifier);
    absRdbPredicates.EqualTo(USER_ID, std::to_string(userId));
    absRdbPredicates.EqualTo(APP_INDEX, std::to_string(appIndex));
    absRdbPredicates.OrderByAsc(PRIORITY);
    absRdbPredicates.OrderByAsc(TIME_STAMP);
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "null absSharedResultSet");
        return ERR_APPEXECFWK_DB_RESULT_SET_EMPTY;
    }
    ScopeGuard stateGuard([&] { absSharedResultSet->Close(); });
    int32_t count;
    int ret = absSharedResultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        LOG_E(BMS_TAG_DEFAULT, "GetRowCount failed, ret: %{public}d", ret);
        return ERR_APPEXECFWK_DB_RESULT_SET_OPT_ERROR;
    }
    if (count == 0) {
        LOG_D(BMS_TAG_DEFAULT, "count size 0");
        return ERR_OK;
    }
    ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        LOG_E(BMS_TAG_DEFAULT, "GoToFirstRow failed, ret: %{public}d", ret);
        return ERR_APPEXECFWK_DB_RESULT_SET_OPT_ERROR;
    }
    std::string ruleString;
    ret = absSharedResultSet->GetString(DISPOSED_STATUS_INDEX, ruleString);
    if (ret != NativeRdb::E_OK) {
        LOG_E(BMS_TAG_DEFAULT, "GetString failed, ret: %{public}d", ret);
        return ERR_APPEXECFWK_DB_RESULT_SET_OPT_ERROR;
    }
    UninstallDisposedRule::FromString(ruleString, rule);
    return ERR_OK;
}
}
}