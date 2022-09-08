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

#include "app_control_manager_rdb.h"

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
    const std::string APP_CONTROL_RDB_TABLE_NAME = "app_control";
    const std::string CALLING_NAME = "CALLING_NAME";
    const std::string APP_CONTROL_LIST = "APP_CONTROL_LIST";
    const std::string USER_ID = "USER_ID";
    const std::string APP_ID = "APP_ID";
    const std::string DISPOSED_STATUS = "DISPOSED_STATUS";
    const int32_t APP_ID_INDEX = 4;
    const int32_t DISPOSED_STATUS_INDEX = 7;
    // running control
    const std::string RUNNING_CONTROL = "RunningControl";
    const std::string APP_RUNNING_CONTROL_RULE_TYPE = "APP_RUNNING_CONTROL_RULE_TYPE";
    const std::string APP_RUNNING_CONTROL_RULE_PARAM_CONTROL_MESSAGE = "APP_RUNNING_CONTROL_RULE_PARAM_CONTROL_MESSAGE";
}
AppControlManagerRdb::AppControlManagerRdb()
{
    APP_LOGD("create AppControlManagerRdb.");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = Constants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = APP_CONTROL_RDB_TABLE_NAME;
    bmsRdbConfig.createTableSql = std::string(
        "CREATE TABLE IF NOT EXISTS "
        + APP_CONTROL_RDB_TABLE_NAME
        + "(ID INTEGER PRIMARY KEY AUTOINCREMENT, CALLING_NAME TEXT NOT NULL, "
        + "APP_CONTROL_LIST TEXT, USER_ID INTEGER, APP_ID TEXT, APP_RUNNING_CONTROL_RULE_PARAM_CONTROL_MESSAGE TEXT, "
        + "APP_RUNNING_CONTROL_RULE_TYPE INTEGER, DISPOSED_STATUS);");
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
}

AppControlManagerRdb::~AppControlManagerRdb()
{
    APP_LOGD("destroy AppControlManagerRdb.");
}

ErrCode AppControlManagerRdb::AddAppInstallControlRule(const std::string &callingName,
    const std::vector<std::string> &appIds, const std::string &controlRuleType, int32_t userId)
{
    ErrCode code = DeleteAppInstallControlRule(callingName, controlRuleType, userId);
    if (code != ERR_OK) {
        APP_LOGW("DeleteAppInstallControlRule failed.");
        return ERR_BUNDLEMANAGER_APP_CONTROL_INTERNAL_ERROR;
    }
    std::vector<NativeRdb::ValuesBucket> valuesBuckets;
    for (auto appId : appIds) {
        NativeRdb::ValuesBucket valuesBucket;
        valuesBucket.PutString(CALLING_NAME, callingName);
        valuesBucket.PutString(APP_CONTROL_LIST, controlRuleType);
        valuesBucket.PutInt(USER_ID, static_cast<int>(userId));
        valuesBucket.PutString(APP_ID, appId);
        valuesBuckets.emplace_back(valuesBucket);
    }
    int64_t insertNum = 0;
    bool ret = rdbDataManager_->BatchInsert(insertNum, valuesBuckets);
    if (!ret) {
        APP_LOGE("BatchInsert failed.");
        return ERR_BUNDLEMANAGER_APP_CONTROL_INTERNAL_ERROR;
    }
    if (valuesBuckets.size() != insertNum) {
        APP_LOGE("BatchInsert size not expected.");
        return ERR_BUNDLEMANAGER_APP_CONTROL_INTERNAL_ERROR;
    }
    return ERR_OK;
}

ErrCode AppControlManagerRdb::DeleteAppInstallControlRule(const std::string &callingName,
    const std::vector<std::string> &appIds, int32_t userId)
{
    for (auto appId : appIds) {
        NativeRdb::AbsRdbPredicates absRdbPredicates(APP_CONTROL_RDB_TABLE_NAME);
        absRdbPredicates.EqualTo(CALLING_NAME, callingName);
        absRdbPredicates.EqualTo(USER_ID, std::to_string(userId));
        absRdbPredicates.EqualTo(APP_ID, appId);
        bool ret = rdbDataManager_->DeleteData(absRdbPredicates);
        if (!ret) {
            APP_LOGE("DeleteAppInstallControlRule callingName:%{public}s appId:%{public}s userId:%{public}d failed.",
                callingName.c_str(), appId.c_str(), userId);
            return ERR_BUNDLEMANAGER_APP_CONTROL_INTERNAL_ERROR;
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
        APP_LOGE("DeleteData callingName:%{public}s controlRuleType:%{public}s failed.",
            callingName.c_str(), controlRuleType.c_str());
        return ERR_BUNDLEMANAGER_APP_CONTROL_INTERNAL_ERROR;
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
        APP_LOGE("GetAppInstallControlRule failed.");
        return ERR_BUNDLEMANAGER_APP_CONTROL_INTERNAL_ERROR;
    }
    int32_t count;
    int ret = absSharedResultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("GetRowCount failed, ret: %{public}d", ret);
        return ERR_BUNDLEMANAGER_APP_CONTROL_INTERNAL_ERROR;
    }
    if (count == 0) {
        APP_LOGI("GetAppInstallControlRule size 0");
        return ERR_OK;
    }
    
    ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("GoToFirstRow failed, ret: %{public}d", ret);
        return ERR_BUNDLEMANAGER_APP_CONTROL_INTERNAL_ERROR;
    }
    do {
        std::string appId;
        ret = absSharedResultSet->GetString(APP_ID_INDEX, appId);
        if (ret != NativeRdb::E_OK) {
            APP_LOGE("GetString appId failed, ret: %{public}d", ret);
            return ERR_BUNDLEMANAGER_APP_CONTROL_INTERNAL_ERROR;
        }
        appIds.push_back(appId);
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    return ERR_OK;
}

ErrCode AppControlManagerRdb::AddAppRunningControlRule(const std::string &callingName,
    const std::vector<InnerAppRunningControlRule> &controlRule, int32_t userId)
{
    ErrCode code = DeleteAppRunningControlRule(callingName, userId);
    if (code != ERR_OK) {
        APP_LOGW("DeleteAppRunningControlRule failed.");
        return ERR_BUNDLEMANAGER_APP_CONTROL_INTERNAL_ERROR;
    }

    std::vector<NativeRdb::ValuesBucket> valuesBuckets;
    for (auto &rule : controlRule) {
        NativeRdb::ValuesBucket valuesBucket;
        valuesBucket.PutString(CALLING_NAME, callingName);
        valuesBucket.PutString(APP_CONTROL_LIST, RUNNING_CONTROL);
        valuesBucket.PutInt(USER_ID, static_cast<int>(userId));
        valuesBucket.PutString(APP_ID, rule.GetControlRuleParam().appId);
        valuesBucket.PutString(APP_RUNNING_CONTROL_RULE_PARAM_CONTROL_MESSAGE,
            rule.GetControlRuleParam().controlMessage);
        valuesBucket.PutInt(APP_RUNNING_CONTROL_RULE_TYPE, static_cast<int>(rule.GetControlRuleType()));
        valuesBuckets.emplace_back(valuesBucket);
    }
    int64_t insertNum = 0;
    bool ret = rdbDataManager_->BatchInsert(insertNum, valuesBuckets);
    if (!ret) {
        APP_LOGE("BatchInsert AddAppRunningControlRule failed.");
        return ERR_BUNDLEMANAGER_APP_CONTROL_INTERNAL_ERROR;
    }
    if (valuesBuckets.size() != insertNum) {
        APP_LOGE("BatchInsert size not expected.");
        return ERR_BUNDLEMANAGER_APP_CONTROL_INTERNAL_ERROR;
    }
    return ERR_OK;
}

ErrCode AppControlManagerRdb::DeleteAppRunningControlRule(const std::string &callingName,
    const std::vector<InnerAppRunningControlRule> &controlRule, int32_t userId)
{
    for (auto &rule : controlRule) {
        NativeRdb::AbsRdbPredicates absRdbPredicates(APP_CONTROL_RDB_TABLE_NAME);
        absRdbPredicates.EqualTo(CALLING_NAME, callingName);
        absRdbPredicates.EqualTo(APP_CONTROL_LIST, RUNNING_CONTROL);
        absRdbPredicates.EqualTo(USER_ID, std::to_string(userId));
        absRdbPredicates.EqualTo(APP_ID, rule.GetControlRuleParam().appId);
        bool ret = rdbDataManager_->DeleteData(absRdbPredicates);
        if (!ret) {
            APP_LOGE("DeleteAppInstallControlRule callingName:%{public}s appid:%{public}s userId:%{public}d failed.",
                callingName.c_str(), rule.GetControlRuleParam().appId.c_str(), userId);
            return ERR_BUNDLEMANAGER_APP_CONTROL_INTERNAL_ERROR;
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
        APP_LOGE("DeleteAppRunningControlRule callingName:%{public}s userId:%{public}d failed.",
            callingName.c_str(), userId);
        return ERR_BUNDLEMANAGER_APP_CONTROL_INTERNAL_ERROR;
    }
    return ERR_OK;
}

ErrCode AppControlManagerRdb::GetAppRunningControlRule(const std::string &callingName,
    int32_t userId, std::vector<std::string> &appIds)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(APP_CONTROL_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(CALLING_NAME, callingName);
    absRdbPredicates.EqualTo(APP_CONTROL_LIST, RUNNING_CONTROL);
    absRdbPredicates.EqualTo(USER_ID, std::to_string(userId));
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("QueryData failed");
        return ERR_BUNDLEMANAGER_APP_CONTROL_INTERNAL_ERROR;
    }
    int32_t count;
    int ret = absSharedResultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("GetRowCount failed, ret: %{public}d", ret);
        return ERR_BUNDLEMANAGER_APP_CONTROL_INTERNAL_ERROR;
    }
    if (count == 0) {
        APP_LOGI("GetAppRunningControlRule size 0");
        return ERR_OK;
    }
    ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("GoToFirstRow failed, ret: %{public}d", ret);
        return ERR_BUNDLEMANAGER_APP_CONTROL_INTERNAL_ERROR;
    }
    do {
        std::string appId;
        ret = absSharedResultSet->GetString(APP_ID_INDEX, appId);
        if (ret != NativeRdb::E_OK) {
            APP_LOGE("GetString appId failed, ret: %{public}d", ret);
            return ERR_BUNDLEMANAGER_APP_CONTROL_INTERNAL_ERROR;
        }
        appIds.push_back(appId);
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    return ERR_OK;
}

ErrCode AppControlManagerRdb::SetDisposedStatus(const std::string &callingName,
    const std::string &controlRuleType, const std::string &appId, const Want &want)
{
    APP_LOGD("rdb begin to SetDisposedStatus");
    ErrCode code = DeleteDisposedStatus(callingName, controlRuleType, appId);
    if (code != ERR_OK) {
        APP_LOGW("DeleteDisposedStatus failed.");
        return ERR_BUNDLEMANAGER_APP_CONTROL_INTERNAL_ERROR;
    }
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(CALLING_NAME, callingName);
    valuesBucket.PutString(APP_CONTROL_LIST, controlRuleType);
    valuesBucket.PutString(APP_ID, appId);
    valuesBucket.PutString(DISPOSED_STATUS, want.ToString());
    bool ret = rdbDataManager_->InsertData(valuesBucket);
    if (!ret) {
        APP_LOGE("SetDisposedStatus callingName:%{public}s controlRuleType:%{public}s appId:%{public}s failed.",
            callingName.c_str(), controlRuleType.c_str(), appId.c_str());
        return ERR_BUNDLEMANAGER_APP_CONTROL_INTERNAL_ERROR;
    }
    return ERR_OK;
}

ErrCode AppControlManagerRdb::DeleteDisposedStatus(const std::string &callingName,
    const std::string &controlRuleType, const std::string &appId)
{
    APP_LOGD("rdb begin to DeleteDisposedStatus");
    NativeRdb::AbsRdbPredicates absRdbPredicates(APP_CONTROL_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(CALLING_NAME, callingName);
    absRdbPredicates.EqualTo(APP_CONTROL_LIST, controlRuleType);
    absRdbPredicates.EqualTo(APP_ID, appId);
    bool ret = rdbDataManager_->DeleteData(absRdbPredicates);
    if (!ret) {
        APP_LOGE("DeleteDisposedStatus callingName:%{public}s controlRuleType:%{public}s appId:%{public}s failed.",
            callingName.c_str(), controlRuleType.c_str(), appId.c_str());
        return ERR_BUNDLEMANAGER_APP_CONTROL_INTERNAL_ERROR;
    }
    return ERR_OK;
}

ErrCode AppControlManagerRdb::GetDisposedStatus(const std::string &callingName,
    const std::string &controlRuleType, const std::string &appId, Want &want)
{
    APP_LOGD("rdb begin to GetDisposedStatus");
    NativeRdb::AbsRdbPredicates absRdbPredicates(APP_CONTROL_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(CALLING_NAME, callingName);
    absRdbPredicates.EqualTo(APP_CONTROL_LIST, controlRuleType);
    absRdbPredicates.EqualTo(APP_ID, appId);
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("GetAppInstallControlRule failed.");
        return ERR_BUNDLEMANAGER_APP_CONTROL_INTERNAL_ERROR;
    }
    
    auto ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("GoToFirstRow failed, ret: %{public}d", ret);
        return ERR_BUNDLEMANAGER_APP_CONTROL_INTERNAL_ERROR;
    }
    std::string wantString;
    ret = absSharedResultSet->GetString(DISPOSED_STATUS_INDEX, wantString);
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("GetString DisposedStatus failed, ret: %{public}d", ret);
        return ERR_BUNDLEMANAGER_APP_CONTROL_INTERNAL_ERROR;
    }
    want = *Want::FromString(wantString);
    return ERR_OK;
}
}
}