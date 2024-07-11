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

#include "app_log_tag_wrapper.h"
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
const std::string ELEMENT_LIST = "elementList";
const std::string PRIORITY = "priority";
const std::string DEVICE_ID = "deviceId";
const std::string IS_EDM = "isEdm";
}  // namespace

bool DisposedRule::ReadFromParcel(Parcel &parcel)
{
    want.reset(parcel.ReadParcelable<AAFwk::Want>());
    componentType = static_cast<ComponentType>(parcel.ReadInt32());
    disposedType = static_cast<DisposedType>(parcel.ReadInt32());
    controlType = static_cast<ControlType>(parcel.ReadInt32());
    int32_t elementSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, elementSize);
    CONTAINER_SECURITY_VERIFY(parcel, elementSize, &elementList);
    for (auto i = 0; i < elementSize; i++) {
        std::string elementUri = Str16ToStr8(parcel.ReadString16());
        ElementName elementName;
        if (!elementName.ParseURI(elementUri)) {
            LOG_W(TAG_DISPOSED_RULE_BASE, "parse elementName failed");
        }
        elementList.emplace_back(elementName);
    }
    priority = parcel.ReadInt32();
    isEdm = parcel.ReadBool();
    return true;
}

bool DisposedRule::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, want.get());
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(componentType));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(disposedType));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(controlType));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, elementList.size());
    for (const auto &elementName: elementList) {
        std::string elementUri = elementName.GetURI();
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(elementUri));
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, priority);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isEdm);

    return true;
}

DisposedRule *DisposedRule::Unmarshalling(Parcel &parcel)
{
    DisposedRule *info = new (std::nothrow) DisposedRule();
    if (info && !info->ReadFromParcel(parcel)) {
        LOG_W(TAG_DISPOSED_RULE_BASE, "read from parcel failed");
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
        LOG_E(TAG_DISPOSED_RULE_BASE, "read elementName error : %{public}d", parseResult);
    }
}

void to_json(nlohmann::json &jsonObject, const DisposedRule &disposedRule)
{
    std::string wantString = disposedRule.want->ToString();
    jsonObject = nlohmann::json {
        {WANT, wantString},
        {COMPONENT_TYPE, disposedRule.componentType},
        {DISPOSED_TYPE, disposedRule.disposedType},
        {CONTROL_TYPE, disposedRule.controlType},
        {ELEMENT_LIST, disposedRule.elementList},
        {PRIORITY, disposedRule.priority},
        {IS_EDM, disposedRule.isEdm},
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
    disposedRule.want.reset(AAFwk::Want::FromString(wantString));
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
        ELEMENT_LIST,
        disposedRule.elementList,
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
    GetValueIfFindKey<bool>(jsonObject,
        jsonObjectEnd,
        IS_EDM,
        disposedRule.isEdm,
        JsonType::BOOLEAN,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    if (parseResult != ERR_OK) {
        LOG_E(TAG_DISPOSED_RULE_BASE, "read disposedRule error : %{public}d", parseResult);
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
        LOG_E(TAG_DISPOSED_RULE_BASE, "failed parse ruleString: %{public}s.", ruleString.c_str());
        return false;
    }
    from_json(jsonObject, rule);
    return true;
}
}  // namespace AppExecFwk
}  // namespace OHOS
