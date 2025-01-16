/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "inner_app_quick_fix.h"

#include "app_log_tag_wrapper.h"
#include "json_util.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* APP_QUICK_FIX = "appQuickFix";
constexpr const char* QUICK_FIX_MARK = "quickFixMark";
constexpr const char* QUICK_FIX_MARK_STATUS = "status";
}

InnerAppQuickFix::InnerAppQuickFix()
{
}

InnerAppQuickFix::InnerAppQuickFix(const AppQuickFix &appQuickFix, const QuickFixMark &mark)
    : appQuickFix_(appQuickFix), quickFixMark_(mark)
{
}

InnerAppQuickFix::~InnerAppQuickFix()
{
}

void InnerAppQuickFix::SetAppQuickFix(const AppQuickFix &appQuickFix)
{
    appQuickFix_ = appQuickFix;
}

AppQuickFix InnerAppQuickFix::GetAppQuickFix() const
{
    return appQuickFix_;
}

bool InnerAppQuickFix::AddHqfInfo(const AppQuickFix &newInfo)
{
    if (newInfo.deployingAppqfInfo.hqfInfos.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "InnerAppQuickFix::AddHqfInfo failed due to hqfInfos empty");
        return false;
    }
    for (const auto &item : newInfo.deployingAppqfInfo.hqfInfos) {
        if (!RemoveHqfInfo(item.moduleName)) {
            LOG_D(BMS_TAG_DEFAULT, "moduleName %{public}s does not exist", item.moduleName.c_str());
        }
        appQuickFix_.deployingAppqfInfo.hqfInfos.emplace_back(item);
    }
    return true;
}

bool InnerAppQuickFix::RemoveHqfInfo(const std::string &moduleName)
{
    auto iter = std::find_if(
        std::begin(appQuickFix_.deployingAppqfInfo.hqfInfos),
        std::end(appQuickFix_.deployingAppqfInfo.hqfInfos),
        [moduleName] (const auto &item) { return item.moduleName == moduleName;});
    if (iter == appQuickFix_.deployingAppqfInfo.hqfInfos.end()) {
        LOG_E(BMS_TAG_DEFAULT, "RemoveHqfInfo failed due to %{public}s does not exist", moduleName.c_str());
        return false;
    }
    appQuickFix_.deployingAppqfInfo.hqfInfos.erase(iter);
    return true;
}

void InnerAppQuickFix::SwitchQuickFix()
{
    AppqfInfo deployed = appQuickFix_.deployedAppqfInfo;
    appQuickFix_.deployedAppqfInfo = appQuickFix_.deployingAppqfInfo;
    appQuickFix_.deployingAppqfInfo = deployed;
}

void InnerAppQuickFix::SetQuickFixMark(const QuickFixMark &mark)
{
    quickFixMark_ = mark;
}

QuickFixMark InnerAppQuickFix::GetQuickFixMark() const
{
    return quickFixMark_;
}

std::string InnerAppQuickFix::ToString() const
{
    nlohmann::json object;
    ToJson(object);
    return object.dump();
}

void InnerAppQuickFix::ToJson(nlohmann::json &jsonObject) const
{
    jsonObject[APP_QUICK_FIX] = appQuickFix_;
    jsonObject[QUICK_FIX_MARK] = quickFixMark_;
}

int32_t InnerAppQuickFix::FromJson(const nlohmann::json &jsonObject)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<AppQuickFix>(jsonObject,
        jsonObjectEnd,
        APP_QUICK_FIX,
        appQuickFix_,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<QuickFixMark>(jsonObject,
        jsonObjectEnd,
        QUICK_FIX_MARK,
        quickFixMark_,
        JsonType::OBJECT,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "read InnerAppQuickFix from database error, error code : %{public}d", parseResult);
    }
    return parseResult;
}

void to_json(nlohmann::json &jsonObject, const QuickFixMark &quickFixMark)
{
    jsonObject = nlohmann::json {
        {Constants::BUNDLE_NAME, quickFixMark.bundleName},
        {QUICK_FIX_MARK_STATUS, quickFixMark.status}
    };
}

void from_json(const nlohmann::json &jsonObject, QuickFixMark &quickFixMark)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject,
        jsonObjectEnd,
        Constants::BUNDLE_NAME,
        quickFixMark.bundleName,
        false,
        parseResult);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        QUICK_FIX_MARK_STATUS,
        quickFixMark.status,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "QuickFixMark from_json error, error code : %{public}d", parseResult);
    }
}
} // AppExecFwk
} // OHOS