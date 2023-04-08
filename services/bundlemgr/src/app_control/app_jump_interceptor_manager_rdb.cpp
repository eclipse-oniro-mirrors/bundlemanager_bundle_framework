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

#include "app_jump_interceptor_manager_rdb.h"

#include "common_event_manager.h"
#include "app_log_wrapper.h"
#include "scope_guard.h"
#include "bundle_util.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
    const std::string APP_JUMP_INTERCEPTOR_RDB_TABLE_NAME = "app_jump_interceptor";
    const std::string NAME_APP_JUMP_INTERCEPTOR_MANAGER_RDB = "AppJumpInterceptorManagerRdb";

    const int32_t CALLER_PKG_INDEX = 1;
    const int32_t TARGET_PKG_INDEX = 2;
    const int32_t SELECT_STATUS_INDEX = 3;
    // app jump interceptor table key
    const std::string CALLER_PKG = "CALLER_PKG";
    const std::string TARGET_PKG = "TARGET_PKG";
    const std::string SELECT_STATUS = "SELECT_STATUS";
    const std::string USER_ID = "USER_ID";
    const std::string MODIFIED_TIME = "MODIFIED_TIME";
}

AppJumpInterceptorManagerRdb::AppJumpInterceptorManagerRdb()
{
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = Constants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = APP_JUMP_INTERCEPTOR_RDB_TABLE_NAME;
    bmsRdbConfig.createTableSql = std::string(
        "CREATE TABLE IF NOT EXISTS "
        + APP_JUMP_INTERCEPTOR_RDB_TABLE_NAME
        + "(ID INTEGER PRIMARY KEY AUTOINCREMENT, CALLER_PKG TEXT NOT NULL, "
        + "TARGET_PKG TEXT NOT NULL, SELECT_STATUS INTEGER, "
        + "USER_ID INTEGER, MODIFIED_TIME INTEGER);");
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager_->CreateTable();
    InitEventRunnerAndHandler();
}

AppJumpInterceptorManagerRdb::~AppJumpInterceptorManagerRdb()
{
}

bool AppJumpInterceptorManagerRdb::InitEventRunnerAndHandler()
{
    std::lock_guard<std::mutex> lock(mutex_);
    runner_ = EventRunner::Create(NAME_APP_JUMP_INTERCEPTOR_MANAGER_RDB);
    if (runner_ == nullptr) {
        APP_LOGE("%{public}s fail, Failed to init due to create runner error", __func__);
        return false;
    }
    handler_ = std::make_shared<EventHandler>(runner_);
    if (handler_ == nullptr) {
        APP_LOGE("%{public}s fail, Failed to init due to create handler error", __func__);
        return false;
    }
    return true;
}

bool AppJumpInterceptorManagerRdb::SubscribeCommonEvent()
{
    if (eventSubscriber_ != nullptr) {
        APP_LOGI("subscribeCommonEvent already subscribed.");
        return true;
    }
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);

    eventSubscriber_ = std::make_shared<AppJumpInterceptorEventSubscriber>(subscribeInfo, shared_from_this());
    eventSubscriber_->SetEventHandler(handler_);
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(eventSubscriber_)) {
        APP_LOGE("subscribeCommonEvent subscribed failure.");
        return false;
    };
    APP_LOGI("subscribeCommonEvent subscribed success.");
    return true;
}


ErrCode AppJumpInterceptorManagerRdb::ConfirmAppJumpControlRule(const std::string &callerBundleName,
    const std::string &targetBundleName, int32_t userId)
{
    std::vector<AppJumpControlRule> controlRules;
    AppJumpControlRule rule;
    rule.callerPkg = callerBundleName;
    rule.targetPkg = targetBundleName;
    controlRules.emplace_back(rule);
    DeleteAppJumpControlRule(controlRules, userId);
    return AddAppJumpControlRule(controlRules, userId);;
}

ErrCode AppJumpInterceptorManagerRdb::AddAppJumpControlRule(const std::vector<AppJumpControlRule> &controlRules,
    int32_t userId)
{
    int64_t timeStamp = BundleUtil::GetCurrentTime();
    std::vector<NativeRdb::ValuesBucket> valuesBuckets;
    for (auto &controlRule : controlRules) {
        NativeRdb::ValuesBucket valuesBucket;
        valuesBucket.PutString(CALLER_PKG, controlRule.callerPkg);
        valuesBucket.PutString(TARGET_PKG, controlRule.targetPkg);
        valuesBucket.PutInt(SELECT_STATUS, (int) controlRule.jumpMode);
        valuesBucket.PutInt(USER_ID, userId);
        valuesBucket.PutInt(MODIFIED_TIME, timeStamp);
        valuesBuckets.emplace_back(valuesBucket);
    }
    int64_t insertNum = 0;
    bool ret = rdbDataManager_->BatchInsert(insertNum, valuesBuckets);
    if (!ret) {
        APP_LOGE("BatchInsert AddAppJumpControlRule failed.");
        return ERR_BUNDLE_MANAGER_APP_CONTROL_INTERNAL_ERROR;
    }
    if (valuesBuckets.size() != static_cast<uint64_t>(insertNum)) {
        APP_LOGE("BatchInsert size not expected.");
        return ERR_BUNDLE_MANAGER_APP_CONTROL_INTERNAL_ERROR;
    }
    return ERR_OK;
}

ErrCode AppJumpInterceptorManagerRdb::DeleteAppJumpControlRule(const std::vector<AppJumpControlRule> &controlRules,
    int32_t userId)
{
    for (auto &rule : controlRules) {
        NativeRdb::AbsRdbPredicates absRdbPredicates(APP_JUMP_INTERCEPTOR_RDB_TABLE_NAME);
        absRdbPredicates.EqualTo(CALLER_PKG, rule.callerPkg);
        absRdbPredicates.EqualTo(TARGET_PKG, rule.targetPkg);
        absRdbPredicates.EqualTo(USER_ID, std::to_string(userId));
        bool ret = rdbDataManager_->DeleteData(absRdbPredicates);
        if (!ret) {
            APP_LOGE("DeleteAppJumpControlRule caller:%{public}s, target:%{public}s, userId:%{public}d failed.",
                rule.callerPkg.c_str(), rule.targetPkg.c_str(), userId);
            return ERR_BUNDLE_MANAGER_APP_CONTROL_INTERNAL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode AppJumpInterceptorManagerRdb::DeleteRuleByCallerBundleName(const std::string &callerBundleName, int32_t userId)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(APP_JUMP_INTERCEPTOR_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(CALLER_PKG, callerBundleName);
    absRdbPredicates.EqualTo(USER_ID, std::to_string(userId));
    bool ret = rdbDataManager_->DeleteData(absRdbPredicates);
    if (!ret) {
        APP_LOGE("DeleteRuleByCallerBundleName callerBundleName:%{public}s, failed.",
            callerBundleName.c_str());
        return ERR_BUNDLE_MANAGER_APP_CONTROL_INTERNAL_ERROR;
    }
    return ERR_OK;
}

ErrCode AppJumpInterceptorManagerRdb::DeleteRuleByTargetBundleName(const std::string &targetBundleName, int32_t userId)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(APP_JUMP_INTERCEPTOR_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(TARGET_PKG, targetBundleName);
    absRdbPredicates.EqualTo(USER_ID, std::to_string(userId));
    bool ret = rdbDataManager_->DeleteData(absRdbPredicates);
    if (!ret) {
        APP_LOGE("DeleteRuleByTargetBundleName targetBundleName:%{public}s, failed.",
            targetBundleName.c_str());
        return ERR_BUNDLE_MANAGER_APP_CONTROL_INTERNAL_ERROR;
    }
    return ERR_OK;
}

ErrCode AppJumpInterceptorManagerRdb::GetAppJumpControlRule(const std::string &callerBundleName,
    const std::string &targetBundleName, int32_t userId, AppJumpControlRule &controlRule)
{
    NativeRdb::AbsRdbPredicates absRdbPredicates(APP_JUMP_INTERCEPTOR_RDB_TABLE_NAME);
    absRdbPredicates.EqualTo(CALLER_PKG, callerBundleName);
    absRdbPredicates.EqualTo(TARGET_PKG, targetBundleName);
    absRdbPredicates.EqualTo(USER_ID, std::to_string(userId));
    absRdbPredicates.OrderByAsc(MODIFIED_TIME); // ascending
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE("QueryData failed");
        return ERR_BUNDLE_MANAGER_APP_JUMP_INTERCEPTOR_INTERNAL_ERROR;
    }
    ScopeGuard stateGuard([&] { absSharedResultSet->Close(); });
    int32_t count;
    int ret = absSharedResultSet->GetRowCount(count);
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("GetRowCount failed, ret: %{public}d", ret);
        return ERR_BUNDLE_MANAGER_APP_JUMP_INTERCEPTOR_INTERNAL_ERROR;
    }
    if (count == 0) {
        APP_LOGE("GetAppRunningControlRuleResult size 0");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_SET_JUMP_INTERCPTOR;
    }
    ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        APP_LOGE("GoToFirstRow failed, ret: %{public}d", ret);
        return ERR_BUNDLE_MANAGER_APP_JUMP_INTERCEPTOR_INTERNAL_ERROR;
    }
    std::string callerPkg;
    if (absSharedResultSet->GetString(CALLER_PKG_INDEX, callerPkg) != NativeRdb::E_OK) {
        APP_LOGE("GetString callerPkg failed, ret: %{public}d", ret);
        return ERR_BUNDLE_MANAGER_APP_JUMP_INTERCEPTOR_INTERNAL_ERROR;
    }
    std::string targetPkg;
    ret = absSharedResultSet->GetString(TARGET_PKG_INDEX, targetPkg);
    if (ret != NativeRdb::E_OK) {
        APP_LOGW("GetString targetPkg failed, ret: %{public}d", ret);
        return ERR_BUNDLE_MANAGER_APP_JUMP_INTERCEPTOR_INTERNAL_ERROR;
    }
    int32_t selectStatus;
    ret = absSharedResultSet->GetInt(SELECT_STATUS_INDEX, selectStatus);
    if (ret != NativeRdb::E_OK) {
        APP_LOGW("GetInt selectStatus failed, ret: %{public}d", ret);
        return ERR_BUNDLE_MANAGER_APP_JUMP_INTERCEPTOR_INTERNAL_ERROR;
    }
    controlRule.jumpMode = (AppExecFwk::AbilityJumpMode) selectStatus;
    return ERR_OK;
}
}
}