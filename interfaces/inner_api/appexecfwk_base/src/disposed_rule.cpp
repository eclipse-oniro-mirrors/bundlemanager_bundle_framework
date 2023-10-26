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

#include "disposed_rule.h"

#include "app_log_wrapper.h"
#include "json_util.h"
#include "nlohmann/json.hpp"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string WANT = "want";
const std::string COMPONENT_TYPE = "componentType";
const std::string DISPOSED_TYPE = "disposedType";
const std::string CONTROL_TYPE = "controlType";
const std::string ELEMENTS_LIST = "elemnetsList";
const std::string PRIORITY = "priority";
const std::string DEVICE_ID = "deviceId";
}  // namespace

bool DisposedRule::ReadFromParcel(Parcel &parcel)
{
    std::unique_ptr<AAFwk::Want> wantPtr(parcel.ReadParcelable<AAFwk::Want>());
    want = *wantPtr;
    componentType = static_cast<ComponentType>(parcel.ReadInt32());
    disposedType = static_cast<DisposedType>(parcel.ReadInt32());
    controlType = static_cast<ControlType>(parcel.ReadInt32());
    int32_t elementSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, elementSize);
    CONTAINER_SECURITY_VERIFY(parcel, elementSize, &elementsList);
    for (auto i = 0; i < elementSize; i++) {
        std::unique_ptr<ElementName> elementNamePtr(parcel.ReadParcelable<ElementName>());
        if (!elementNamePtr) {
            APP_LOGE("ReadParcelable<ElementName> failed");
            return false;
        }
        elementsList.emplace_back(*elementNamePtr);
    }
    priority = parcel.ReadInt32();
    return true;
}

bool DisposedRule::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &want);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(componentType));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(disposedType));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(controlType));
    for (auto &elementName: elementsList) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &elementName);
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, priority);

    return true;
}

DisposedRule *DisposedRule::Unmarshalling(Parcel &parcel)
{
    DisposedRule *info = new (std::nothrow) DisposedRule();
    if (info && !info->ReadFromParcel(parcel)) {
        APP_LOGW("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

void to_json(nlohmann::json &jsonObject, const ElementName &elementName)
{
    jsonObject = nlohmann::json {
        {Constants::BUNDLE_NAME, elementName.GetBundleName()},
        {Constants::MODULE_NAME, elementName.GetModuleName()},
        {Constants::ABILITY_NAME, elementName.GetAbilityName()},
        {DEVICE_ID, elementName.GetDeviceID()}
    };
}

void from_json(const nlohmann::json &jsonObject, ElementName &elementName)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    std::string bundleName;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Constants::BUNDLE_NAME,
        bundleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    elementName.SetBundleName(bundleName);
    std::string moduleName;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Constants::MODULE_NAME,
        moduleName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    elementName.SetModuleName(moduleName);
    std::string abilityName;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        Constants::ABILITY_NAME,
        abilityName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    elementName.SetAbilityName(abilityName);
    std::string deviceId;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        DEVICE_ID,
        deviceId,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    elementName.SetDeviceID(deviceId);
    if (parseResult != ERR_OK) {
        APP_LOGE("read elementName error, error code : %{public}d", parseResult);
    }
}

void to_json(nlohmann::json &jsonObject, const DisposedRule &disposedRule)
{
    std::string wantString = disposedRule.want.ToString();
    jsonObject = nlohmann::json {
        {WANT, wantString},
        {COMPONENT_TYPE, disposedRule.componentType},
        {DISPOSED_TYPE, disposedRule.disposedType},
        {CONTROL_TYPE, disposedRule.controlType},
        {ELEMENTS_LIST, disposedRule.elementsList},
        {PRIORITY, disposedRule.priority}
    };
}

void from_json(const nlohmann::json &jsonObject, DisposedRule &disposedRule)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    std::string wantString;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        WANT,
        wantString,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    disposedRule.want = *AAFwk::Want::FromString(wantString);
    GetValueIfFindKey<ComponentType>(jsonObject,
        jsonObjectEnd,
        COMPONENT_TYPE,
        disposedRule.componentType,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<DisposedType>(jsonObject,
        jsonObjectEnd,
        DISPOSED_TYPE,
        disposedRule.disposedType,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<ControlType>(jsonObject,
        jsonObjectEnd,
        CONTROL_TYPE,
        disposedRule.controlType,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::vector<ElementName>>(jsonObject,
        jsonObjectEnd,
        ELEMENTS_LIST,
        disposedRule.elementsList,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::OBJECT);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        PRIORITY,
        disposedRule.priority,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        APP_LOGE("read disposedRule error, error code : %{public}d", parseResult);
    }
}

std::string DisposedRule::ToString() const
{
    nlohmann::json jsonObject;
    to_json(jsonObject, *this);
    return jsonObject.dump();
}

bool DisposedRule::FromString(const std::string &ruleString, DisposedRule &rule)
{
    nlohmann::json jsonObject = nlohmann::json::parse(ruleString, nullptr, false);
    if (jsonObject.is_discarded()) {
        APP_LOGE("failed to parse ruleString: %{public}s.", ruleString.c_str());
        return false;
    }
    from_json(jsonObject, rule);
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS
