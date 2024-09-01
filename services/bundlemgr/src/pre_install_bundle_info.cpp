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
const std::string BUNDLE_NAME = "bundleName";
const std::string VERSION_CODE = "versionCode";
const std::string BUNDLE_PATHS = "bundlePaths";
const std::string APP_TYPE = "appType";
const std::string REMOVABLE = "removable";
const std::string IS_UNINSTALLED = "isUninstalled";
const std::string MODULE_NAME = "moduleName";
const std::string LABEL_ID = "labelId";
const std::string ICON_ID = "iconId";
const std::string SYSTEM_APP = "systemApp";
const std::string BUNDLE_TYPE = "bundleType";
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
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, BUNDLE_NAME,
        bundleName_, JsonType::STRING, true, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject, jsonObjectEnd, VERSION_CODE,
        versionCode_, JsonType::NUMBER, true, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<std::string>>(jsonObject, jsonObjectEnd, BUNDLE_PATHS,
        bundlePaths_, JsonType::ARRAY, true, parseResult, ArrayType::STRING);
    GetValueIfFindKey<Constants::AppType>(jsonObject, jsonObjectEnd, APP_TYPE,
        appType_, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject, jsonObjectEnd, REMOVABLE,
        removable_, JsonType::BOOLEAN, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject, jsonObjectEnd, IS_UNINSTALLED,
        isUninstalled_, JsonType::BOOLEAN, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject, jsonObjectEnd, MODULE_NAME,
        moduleName_, JsonType::STRING, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject, jsonObjectEnd, LABEL_ID,
        labelId_, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<uint32_t>(jsonObject, jsonObjectEnd, ICON_ID,
        iconId_, JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    GetValueIfFindKey<bool>(jsonObject, jsonObjectEnd, SYSTEM_APP,
        systemApp_, JsonType::BOOLEAN, false, parseResult, ArrayType::NOT_ARRAY);
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
    return jsonObject.dump();
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
