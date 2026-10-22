/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "pre_compress_bundle_resource_rdb.h"

#include "exception_util.h"
#include "json_util.h"
#include "nlohmann/json.hpp"

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_resource_constants.h"
#include "bundle_resource_param.h"
#include "bundle_service_constants.h"
#include "hitrace_meter.h"
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t INDEX_NAME = 0;
constexpr int32_t INDEX_VERSION_CODE = 1;
constexpr int32_t INDEX_LABEL = 2;
constexpr int32_t INDEX_ICON = 3;
constexpr int32_t INDEX_FOREGROUND = 4;
constexpr int32_t INDEX_BACKGROUND = 5;
constexpr const char* DEFAULT_LANGUAGE = "zh-Hans";
}

PreCompressBundleResourceRdb::PreCompressBundleResourceRdb()
{
    APP_LOGI_NOFUNC("PreCompressBundleResourceRdb create");
    BmsRdbConfig bmsRdbConfig;
    bmsRdbConfig.dbName = ServiceConstants::BUNDLE_RDB_NAME;
    bmsRdbConfig.dbPath = ServiceConstants::BUNDLE_MANAGER_SERVICE_PATH;
    bmsRdbConfig.tableName = BundleResourceConstants::PRE_COMPRESS_BUNDLE_RESOURCE_RDB;
    bmsRdbConfig.createTableSql = std::string(
        "CREATE TABLE IF NOT EXISTS "
        + std::string(BundleResourceConstants::PRE_COMPRESS_BUNDLE_RESOURCE_RDB)
        + "(NAME TEXT NOT NULL, VERSION_CODE INTEGER, LABEL TEXT, ICON TEXT, "
        + "FOREGROUND BLOB, BACKGROUND BLOB, PRIMARY KEY (NAME));");
    rdbDataManager_ = std::make_shared<RdbDataManager>(bmsRdbConfig);
    rdbDataManager_->CreateTable();
}

std::map<std::string, std::string> PreCompressBundleResourceRdb::FromString(const std::string &labels)
{
    std::map<std::string, std::string> labelMap;
    nlohmann::json jsonObject = nlohmann::json::parse(labels, nullptr, false, true);
    if (jsonObject.is_discarded()) {
        APP_LOGE_NOFUNC("failed parse labels");
        return labelMap;
    }
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetMapValueIfFindKey<std::map<std::string, std::string>>(jsonObject, jsonObjectEnd,
        BundleResourceConstants::LABEL, labelMap, false, parseResult, JsonType::STRING, ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE_NOFUNC("read labelMap jsonObject error : %{public}d", parseResult);
    }
    return labelMap;
}

std::string PreCompressBundleResourceRdb::ToString(const std::map<std::string, std::string> &labelMap)
{
    nlohmann::json json;
    json[BundleResourceConstants::LABEL] = labelMap;
    std::string result;
    if (!ExceptionUtil::GetInstance().SafeDump(json, result)) {
        APP_LOGE_NOFUNC("SafeDump failed");
        return Constants::EMPTY_STRING;
    }
    return result;
}

bool PreCompressBundleResourceRdb::AddPreCompressBundleResource(const uint32_t versionCode,
    const std::map<std::string, std::string> &labelMap, const ResourceInfo &resourceInfo)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    NativeRdb::ValuesBucket valuesBucket;
    valuesBucket.PutString(BundleResourceConstants::NAME, resourceInfo.bundleName_);
    valuesBucket.PutLong(BundleResourceConstants::VERSION_CODE, static_cast<int64_t>(versionCode));
    valuesBucket.PutString(BundleResourceConstants::LABEL, ToString(labelMap));
    valuesBucket.PutString(BundleResourceConstants::ICON, resourceInfo.icon_);
    valuesBucket.PutBlob(BundleResourceConstants::FOREGROUND, resourceInfo.foreground_);
    valuesBucket.PutBlob(BundleResourceConstants::BACKGROUND, resourceInfo.background_);
    if (!rdbDataManager_->InsertData(valuesBucket)) {
        APP_LOGE_NOFUNC("-n %{public}s add pre compress resource failed", resourceInfo.bundleName_.c_str());
        return false;
    }
    return true;
}

bool PreCompressBundleResourceRdb::DeletePreCompressBundleResource(const std::string &bundleName)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    NativeRdb::AbsRdbPredicates absRdbPredicates(BundleResourceConstants::PRE_COMPRESS_BUNDLE_RESOURCE_RDB);
    absRdbPredicates.EqualTo(BundleResourceConstants::NAME, bundleName);
    if (!rdbDataManager_->DeleteData(absRdbPredicates)) {
        APP_LOGW("delete -n %{public}s failed", bundleName.c_str());
        return false;
    }
    return true;
}

bool PreCompressBundleResourceRdb::GetPreCompressBundleResources(const std::vector<std::string> &bundleNames,
    const uint32_t flags, std::vector<BundleResourceInfo> &bundleResourceInfos)
{
    HITRACE_METER_NAME_EX(HITRACE_LEVEL_INFO, HITRACE_TAG_APP, __PRETTY_FUNCTION__, nullptr);
    if (bundleNames.empty()) {
        return true;
    }
    NativeRdb::AbsRdbPredicates absRdbPredicates(BundleResourceConstants::PRE_COMPRESS_BUNDLE_RESOURCE_RDB);
    absRdbPredicates.In(BundleResourceConstants::NAME, bundleNames);
    auto absSharedResultSet = rdbDataManager_->QueryByStep(absRdbPredicates);
    if (absSharedResultSet == nullptr) {
        APP_LOGE_NOFUNC("QueryByStep pre compress resources failed");
        return false;
    }
    ScopeGuard stateGuard([absSharedResultSet] { absSharedResultSet->Close(); });
    auto ret = absSharedResultSet->GoToFirstRow();
    if (ret == NativeRdb::E_ROW_OUT_RANGE) {
        APP_LOGD("no pre compress resource in rdb");
        return true;
    }
    CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GoToFirstRow failed, ret %{public}d");
    std::string language = BundleResourceParam::GetSystemLocale();
    do {
        BundleResourceInfo bundleResourceInfo;
        if (ConvertToBundleResourceInfo(absSharedResultSet, flags, language, bundleResourceInfo)) {
            bundleResourceInfos.emplace_back(std::move(bundleResourceInfo));
        }
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    return true;
}

std::map<std::string, uint32_t> PreCompressBundleResourceRdb::GetAllPreCompressBundleResourceVersion()
{
    std::map<std::string, uint32_t> versionCodes;
    NativeRdb::AbsRdbPredicates absRdbPredicates(BundleResourceConstants::PRE_COMPRESS_BUNDLE_RESOURCE_RDB);
    auto absSharedResultSet = rdbDataManager_->QueryData(absRdbPredicates,
        { BundleResourceConstants::NAME, BundleResourceConstants::VERSION_CODE });
    if (absSharedResultSet == nullptr) {
        APP_LOGE_NOFUNC("get all pre compress resource version failed");
        return versionCodes;
    }
    ScopeGuard stateGuard([absSharedResultSet] { absSharedResultSet->Close(); });
    auto ret = absSharedResultSet->GoToFirstRow();
    if (ret != NativeRdb::E_OK) {
        if (ret != NativeRdb::E_ROW_OUT_RANGE) {
            APP_LOGE_NOFUNC("GoToFirstRow failed, ret %{public}d", ret);
        }
        return versionCodes;
    }
    do {
        std::string bundleName;
        int64_t versionCode = 0;
        if ((absSharedResultSet->GetString(INDEX_NAME, bundleName) != NativeRdb::E_OK) ||
            (absSharedResultSet->GetLong(INDEX_VERSION_CODE, versionCode) != NativeRdb::E_OK)) {
            APP_LOGW_NOFUNC("get pre compress resource version failed");
            continue;
        }
        versionCodes[bundleName] = static_cast<uint32_t>(versionCode);
    } while (absSharedResultSet->GoToNextRow() == NativeRdb::E_OK);
    return versionCodes;
}

bool PreCompressBundleResourceRdb::ConvertToBundleResourceInfo(
    const std::shared_ptr<NativeRdb::ResultSet> absSharedResultSet,
    const uint32_t flags,
    const std::string &language,
    BundleResourceInfo &bundleResourceInfo)
{
    auto ret = absSharedResultSet->GetString(INDEX_NAME, bundleResourceInfo.bundleName);
    CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetString name failed, ret: %{public}d");
    bundleResourceInfo.appIndex = Constants::MAIN_APP_INDEX;

    bool getAll = (flags & static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL)) ==
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_ALL);
    bool getLabel = (flags & static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL)) ==
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_LABEL);
    if (getAll || getLabel) {
        std::string label;
        ret = absSharedResultSet->GetString(INDEX_LABEL, label);
        CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetString label failed, ret: %{public}d");
        bundleResourceInfo.label = GetAvailableLabel(bundleResourceInfo.bundleName, language, label);
    }
    bool getIcon = (flags & static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON)) ==
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_ICON);
    if (getAll || getIcon) {
        ret = absSharedResultSet->GetString(INDEX_ICON, bundleResourceInfo.icon);
        CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetString icon failed, ret: %{public}d");
    }
    bool getDrawable = (flags & static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR)) ==
        static_cast<uint32_t>(ResourceFlag::GET_RESOURCE_INFO_WITH_DRAWABLE_DESCRIPTOR);
    if (getDrawable) {
        ret = absSharedResultSet->GetBlob(INDEX_FOREGROUND, bundleResourceInfo.foreground);
        CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetBlob foreground, ret: %{public}d");
        ret = absSharedResultSet->GetBlob(INDEX_BACKGROUND, bundleResourceInfo.background);
        CHECK_RDB_RESULT_RETURN_IF_FAIL(ret, "GetBlob background, ret: %{public}d");
    }
    return true;
}

std::string PreCompressBundleResourceRdb::GetAvailableLabel(const std::string &bundleName,
    const std::string &language, const std::string &labels)
{
    std::map<std::string, std::string> labelMap = FromString(labels);
    auto iter = labelMap.find(language);
    if (iter != labelMap.end()) {
        return iter->second;
    }
    iter = labelMap.find(DEFAULT_LANGUAGE);
    if (iter != labelMap.end()) {
        return iter->second;
    }
    APP_LOGW("-n %{public}s -l %{public}s label not exist", bundleName.c_str(), language.c_str());
    return bundleName;
}
} // AppExecFwk
} // OHOS
