/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "install_exception_mgr_rdb.h"

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "json_util.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace AppExecFwk {
namespace {
const char* const INSTALL_EXCEPTION_MGR_TABLE_NAME = "install_exception_mgr";
const char* const INSTALL_RENAME_EXCEPTION_STATUS = "installRenameExceptionStatus";
}

bool InstallExceptionInfo::FromString(const std::string &installExceptionInfoStr)
{
    nlohmann::json jsonObject = nlohmann::json::parse(installExceptionInfoStr, nullptr, false);
    if (jsonObject.is_discarded()) {
        APP_LOGE("failed parse installExceptionInfoStr: %{public}s", installExceptionInfoStr.c_str());
        return false;
    }
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<InstallRenameExceptionStatus>(jsonObject, jsonObjectEnd, INSTALL_RENAME_EXCEPTION_STATUS,
        status, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("read InstallExceptionInfo from json error, error code : %{public}d", parseResult);
        return false;
    }
    return true;
}

std::string InstallExceptionInfo::ToString() const
{
    nlohmann::json jsonObject = nlohmann::json {
        {INSTALL_RENAME_EXCEPTION_STATUS, status}
    };
    return jsonObject.dump();
}

InstallExceptionMgrRdb::InstallExceptionMgrRdb()
{
    APP_LOGI("exception mgr created");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    bmsRdbConfig.tableName = INSTALL_EXCEPTION_MGR_TABLE_NAME;
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager_->CreateTable();
}

InstallExceptionMgrRdb::~InstallExceptionMgrRdb()
{
}

ErrCode InstallExceptionMgrRdb::SaveBundleExceptionInfo(
    const std::string &bundleName, const InstallExceptionInfo &installExceptionInfo)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    if (!rdbDataManager_->InsertData(bundleName, installExceptionInfo.ToString())) {
        APP_LOGE("bundle %{public}s insert %{public}s failed", bundleName.c_str(),
            installExceptionInfo.ToString().c_str());
        return ERR_APPEXECFWK_UPDATE_BUNDLE_ERROR;
    }
    return ERR_OK;
}

ErrCode InstallExceptionMgrRdb::DeleteBundleExceptionInfo(const std::string &bundleName)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    if (!rdbDataManager_->DeleteData(bundleName)) {
        APP_LOGE("delete bundle %{public}s failed", bundleName.c_str());
        return ERR_APPEXECFWK_UPDATE_BUNDLE_ERROR;
    }
    return ERR_OK;
}

void InstallExceptionMgrRdb::GetAllBundleExceptionInfo(
    std::map<std::string, InstallExceptionInfo> &bundleExceptionInfos)
{
    if (rdbDataManager_ == nullptr) {
        APP_LOGE("rdbDataManager is null");
        return;
    }
    std::map<std::string, std::string> datas;
    if (!rdbDataManager_->QueryAllData(datas) || datas.empty()) {
        APP_LOGI("installExceptionInfo not exist");
        return;
    }
    for (const auto &item : datas) {
        InstallExceptionInfo installExceptionInfo;
        if (installExceptionInfo.FromString(item.second)) {
            bundleExceptionInfos.emplace(item.first, installExceptionInfo);
        }
    }
}
} // AppExecFwk
} // OHOS
