/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "pre_install_bundle_info.h"

#include "bundle_util.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* BUNDLE_NAME = "bundleName";
constexpr const char* VERSION_CODE = "versionCode";
constexpr const char* BUNDLE_PATHS = "bundlePaths";
constexpr const char* APP_TYPE = "appType";
constexpr const char* REMOVABLE = "removable";
constexpr const char* IS_UNINSTALLED = "isUninstalled";
constexpr const char* MODULE_NAME = "moduleName";
constexpr const char* LABEL_ID = "labelId";
constexpr const char* ICON_ID = "iconId";
constexpr const char* SYSTEM_APP = "systemApp";
constexpr const char* BUNDLE_TYPE = "bundleType";
}  // namespace

void PreInstallBundleInfo::ToJson(nlohmann::json &jsonObject) const
{
    jsonObject[BUNDLE_NAME] = bundleName_;
    jsonObject[VERSION_CODE] = versionCode_;
    jsonObject[BUNDLE_PATHS] = bundlePaths_;
    jsonObject[APP_TYPE] = appType_;
    jsonObject[REMOVABLE] = removable_;
    jsonObject[IS_UNINSTALLED] = isUninstalled_;
    jsonObject[MODULE_NAME] = moduleName_;
    jsonObject[LABEL_ID] = labelId_;
    jsonObject[ICON_ID] = iconId_;
    jsonObject[SYSTEM_APP] = systemApp_;
    jsonObject[BUNDLE_TYPE] = bundleType_;
}

int32_t PreInstallBundleInfo::FromJson(const nlohmann::json &jsonObject)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject, jsonObjectEnd, BUNDLE_NAME,
        bundleName_, true, parseResult);
    GetValueIfFindKey<uint32_t>(jsonObject, jsonObjectEnd, VERSION_CODE,
        versionCode_, JsonType::NUMBER, true, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject, jsonObjectEnd, BUNDLE_PATHS,
        bundlePaths_, JsonType::ARRAY, true, parseResult, ArrayType::STRING);
    GetValueIfFindKey<Constants::AppType>(jsonObject, jsonObjectEnd, APP_TYPE,
        appType_, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject, jsonObjectEnd, REMOVABLE,
        removable_, false, parseResult);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject, jsonObjectEnd, IS_UNINSTALLED,
        isUninstalled_, false, parseResult);
    BMSJsonUtil::GetStrValueIfFindKey(jsonObject, jsonObjectEnd, MODULE_NAME,
        moduleName_, false, parseResult);
    GetValueIfFindKey<uint32_t>(jsonObject, jsonObjectEnd, LABEL_ID,
        labelId_, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject, jsonObjectEnd, ICON_ID,
        iconId_, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    BMSJsonUtil::GetBoolValueIfFindKey(jsonObject, jsonObjectEnd, SYSTEM_APP,
        systemApp_, false, parseResult);
    GetValueIfFindKey<BundleType>(jsonObject, jsonObjectEnd, BUNDLE_TYPE,
        bundleType_, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    return parseResult;
}

std::string PreInstallBundleInfo::ToString() const
{
    nlohmann::json jsonObject;
    jsonObject[BUNDLE_NAME] = bundleName_;
    jsonObject[VERSION_CODE] = versionCode_;
    jsonObject[BUNDLE_PATHS] = bundlePaths_;
    jsonObject[APP_TYPE] = appType_;
    jsonObject[REMOVABLE] = removable_;
    jsonObject[IS_UNINSTALLED] = isUninstalled_;
    jsonObject[MODULE_NAME] = moduleName_;
    jsonObject[LABEL_ID] = labelId_;
    jsonObject[ICON_ID] = iconId_;
    jsonObject[SYSTEM_APP] = systemApp_;
    jsonObject[BUNDLE_TYPE] = bundleType_;
    try {
        return jsonObject.dump();
    } catch (const nlohmann::json::type_error &e) {
        APP_LOGE("json dump failed: %{public}s", e.what());
        return "";
    }
}

void PreInstallBundleInfo::CalculateHapTotalSize()
{
    hapTotalSize_ = 0;
    for (const auto &bundlePath : bundlePaths_) {
        hapTotalSize_ += BundleUtil::CalculateFileSize(bundlePath);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
