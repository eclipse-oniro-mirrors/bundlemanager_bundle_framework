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

#include "inner_patch_info.h"
#include "app_log_tag_wrapper.h"

namespace OHOS {
namespace AppExecFwk {

using json = nlohmann::json;
namespace {
constexpr const char* VERSION_CODE = "versionCode";
constexpr const char* APP_PATCH_TYPE = "appPatchType";
}  // namespace

bool InnerPatchInfo::FromJson(const std::string &jsonObject)
{
    if (jsonObject.empty() || !json::accept(jsonObject)) {
        APP_LOGE("invalid param");
        return false;
    }
    json jsonObj = json::parse(jsonObject, nullptr, false);
    if (jsonObj.is_discarded()) {
        APP_LOGE("jsonObj discarded");
        return false;
    }
    if (!jsonObj.contains(VERSION_CODE) || !jsonObj.contains(APP_PATCH_TYPE)) {
        APP_LOGE("json object missing required failed");
        return false;
    }
    if (!jsonObj[VERSION_CODE].is_number() || !jsonObj[APP_PATCH_TYPE].is_number()) {
        APP_LOGE("json object value data type failed");
        return false;
    }
    patchInfo_.versionCode = static_cast<uint32_t>(jsonObj[VERSION_CODE].get<int>());
    patchInfo_.appPatchType = static_cast<AppPatchType>(jsonObj[APP_PATCH_TYPE].get<int>());
    return true;
}

std::string InnerPatchInfo::ToString() const
{
    nlohmann::json jsonObj;
    ToJson(jsonObj);
    try {
        return jsonObj.dump();
    } catch (const nlohmann::json::type_error &e) {
        APP_LOGE("json dump failed: %{public}s", e.what());
        return "";
    }
}

void InnerPatchInfo::ToJson(nlohmann::json &jsonObject) const
{
    jsonObject[VERSION_CODE] = patchInfo_.versionCode;
    jsonObject[APP_PATCH_TYPE] = patchInfo_.appPatchType;
}
}  // namespace AppExecFwk
}  // namespace OHOS
