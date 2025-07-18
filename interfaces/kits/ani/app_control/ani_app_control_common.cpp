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

#include "ani_app_control_common.h"
#include "ani_common_want.h"
#include "common_fun_ani.h"

namespace OHOS {
namespace AppExecFwk {
using Want = OHOS::AAFwk::Want;

namespace {
constexpr const char* CLASSNAME_DISPOSED_RULE_INNER = "@ohos.bundle.appControl.appControl.DisposedRuleInner";
constexpr const char* CLASSNAME_DISPOSED_UNINSTALL_RULE_INNER =
    "@ohos.bundle.appControl.appControl.UninstallDisposedRuleInner";
constexpr const char* PROPERTYNAME_WANT = "want";
constexpr const char* PROPERTYNAME_COMPONENTTYPE = "componentType";
constexpr const char* PROPERTYNAME_DISPOSEDTYPE = "disposedType";
constexpr const char* PROPERTYNAME_CONTROLTYPE = "controlType";
constexpr const char* PROPERTYNAME_ELEMENTLIST = "elementList";
constexpr const char* PROPERTYNAME_PRIORITY = "priority";
constexpr const char* PROPERTYNAME_UNINSTALLCOMPONENTTYPE = "uninstallComponentType";
constexpr const char* PROPERTYNAME_BUNDLENAME = "bundleName";
constexpr const char* PROPERTYNAME_ABILITYNAME = "abilityName";
constexpr const char* PROPERTYNAME_DEVICEID = "deviceId";
constexpr const char* PROPERTYNAME_URI = "uri";
constexpr const char* PROPERTYNAME_TYPE = "type";
constexpr const char* PROPERTYNAME_FLAGS = "flags";
constexpr const char* PROPERTYNAME_ACTION = "action";
constexpr const char* PROPERTYNAME_ENTITIES = "entities";
constexpr const char* PROPERTYNAME_MODULENAME = "moduleName";
constexpr const char* PROPERTYNAME_APPID = "appId";
constexpr const char* PROPERTYNAME_APPINDEX = "appIndex";
constexpr const char* PROPERTYNAME_DISPOSEDRULE = "disposedRule";
}

ani_object AniAppControlCommon::ConvertDisposedRule(ani_env* env, const DisposedRule& disposedRule)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CommonFunAni::CreateClassByName(env, CLASSNAME_DISPOSED_RULE_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CommonFunAni::CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    // want: Want
    if (disposedRule.want != nullptr) {
        ani_object aWant = WrapWant(env, *disposedRule.want);
        RETURN_NULL_IF_NULL(aWant);
        RETURN_NULL_IF_FALSE(CommonFunAni::CallSetter(env, cls, object, PROPERTYNAME_WANT, aWant));
    }

    // componentType: ComponentType
    RETURN_NULL_IF_FALSE(CommonFunAni::CallSetter(env, cls, object, PROPERTYNAME_COMPONENTTYPE,
        EnumUtils::EnumNativeToETS_AppControl_ComponentType(env, static_cast<int32_t>(disposedRule.componentType))));

    // disposedType: DisposedType
    RETURN_NULL_IF_FALSE(CommonFunAni::CallSetter(env, cls, object, PROPERTYNAME_DISPOSEDTYPE,
        EnumUtils::EnumNativeToETS_AppControl_DisposedType(env, static_cast<int32_t>(disposedRule.disposedType))));

    // controlType: ControlType
    RETURN_NULL_IF_FALSE(CommonFunAni::CallSetter(env, cls, object, PROPERTYNAME_CONTROLTYPE,
        EnumUtils::EnumNativeToETS_AppControl_ControlType(env, static_cast<int32_t>(disposedRule.controlType))));

    // elementList: Array<ElementName>
    ani_object aElementList = CommonFunAni::ConvertAniArray(
        env, disposedRule.elementList, CommonFunAni::ConvertElementName);
    RETURN_NULL_IF_NULL(aElementList);
    RETURN_NULL_IF_FALSE(CommonFunAni::CallSetter(env, cls, object, PROPERTYNAME_ELEMENTLIST, aElementList));

    // priority: int
    RETURN_NULL_IF_FALSE(CommonFunAni::CallSetter(env, cls, object, PROPERTYNAME_PRIORITY, disposedRule.priority));

    return object;
}

ani_object AniAppControlCommon::ConvertUninstallDisposedRule(ani_env* env,
    const UninstallDisposedRule& uninstallDisposedRule)
{
    RETURN_NULL_IF_NULL(env);

    ani_class cls = CommonFunAni::CreateClassByName(env, CLASSNAME_DISPOSED_UNINSTALL_RULE_INNER);
    RETURN_NULL_IF_NULL(cls);

    ani_object object = CommonFunAni::CreateNewObjectByClass(env, cls);
    RETURN_NULL_IF_NULL(object);

    // want: Want
    if (uninstallDisposedRule.want != nullptr) {
        ani_object aWant = WrapWant(env, *uninstallDisposedRule.want);
        RETURN_NULL_IF_NULL(aWant);
        RETURN_NULL_IF_FALSE(CommonFunAni::CallSetter(env, cls, object, PROPERTYNAME_WANT, aWant));
    }

    // uninstallComponentType: UninstallComponentType
    RETURN_NULL_IF_FALSE(CommonFunAni::CallSetter(env, cls, object, PROPERTYNAME_UNINSTALLCOMPONENTTYPE,
        EnumUtils::EnumNativeToETS_AppControl_UninstallComponentType(
            env, static_cast<int32_t>(uninstallDisposedRule.uninstallComponentType))));

    // priority: int
    RETURN_NULL_IF_FALSE(CommonFunAni::CallSetter(
        env, cls, object, PROPERTYNAME_PRIORITY, uninstallDisposedRule.priority));

    return object;
}

bool AniAppControlCommon::ParseWantWithoutVerification(ani_env* env, ani_object object, Want& want)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(object);

    ani_string string = nullptr;
    ani_double doubleValue = 0;
    ani_array array = nullptr;

    // bundleName?: string
    std::string bundleName = "";
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTYNAME_BUNDLENAME, &string)) {
        bundleName = CommonFunAni::AniStrToString(env, string);
    }

    // abilityName?: string
    std::string abilityName = "";
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTYNAME_ABILITYNAME, &string)) {
        abilityName = CommonFunAni::AniStrToString(env, string);
    }

    // deviceId?: string
    std::string deviceId = "";
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTYNAME_DEVICEID, &string)) {
        deviceId = CommonFunAni::AniStrToString(env, string);
    }

    // uri?: string
    std::string uri = "";
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTYNAME_URI, &string)) {
        uri = CommonFunAni::AniStrToString(env, string);
    }

    // type?: string
    std::string type = "";
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTYNAME_TYPE, &string)) {
        type = CommonFunAni::AniStrToString(env, string);
    }

    // flags?: number
    int32_t flags = 0;
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTYNAME_FLAGS, &doubleValue)) {
        CommonFunAni::TryCastTo(doubleValue, &flags);
    }

    // action?: string
    std::string action = "";
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTYNAME_ACTION, &string)) {
        action = CommonFunAni::AniStrToString(env, string);
    }

    // entities?: Array<string>
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTYNAME_ENTITIES, &array)) {
        std::vector<std::string> entities;
        if (CommonFunAni::ParseStrArray(env, array, entities)) {
            for (size_t idx = 0; idx < entities.size(); ++idx) {
                APP_LOGD("entity:%{public}s", entities[idx].c_str());
                want.AddEntity(entities[idx]);
            }
        }
    }

    // moduleName?: string
    std::string moduleName = "";
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTYNAME_MODULENAME, &string)) {
        moduleName = CommonFunAni::AniStrToString(env, string);
    }

    want.SetAction(action);
    want.SetUri(uri);
    want.SetType(type);
    want.SetFlags(flags);
    ElementName elementName(deviceId, bundleName, abilityName, moduleName);
    want.SetElement(elementName);

    return true;
}

bool AniAppControlCommon::ParseDisposedRule(ani_env* env, ani_object object, DisposedRule& disposedRule)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(object);

    ani_object objectValue = nullptr;
    ani_enum_item enumItem = nullptr;
    ani_array array = nullptr;
    ani_int intValue = 0;

    // want: Want
    Want want;
    RETURN_FALSE_IF_FALSE(CommonFunAni::CallGetter(env, object, PROPERTYNAME_WANT, &objectValue));
    if (!UnwrapWant(env, objectValue, want)) {
        APP_LOGE("parse want failed");
        return false;
    }
    disposedRule.want = std::make_shared<Want>(want);

    // componentType: ComponentType
    RETURN_FALSE_IF_FALSE(CommonFunAni::CallGetter(env, object, PROPERTYNAME_COMPONENTTYPE, &enumItem));
    RETURN_FALSE_IF_FALSE(EnumUtils::EnumETSToNative(env, enumItem, disposedRule.componentType));

    // disposedType: DisposedType
    RETURN_FALSE_IF_FALSE(CommonFunAni::CallGetter(env, object, PROPERTYNAME_DISPOSEDTYPE, &enumItem));
    RETURN_FALSE_IF_FALSE(EnumUtils::EnumETSToNative(env, enumItem, disposedRule.disposedType));

    // controlType: ControlType
    RETURN_FALSE_IF_FALSE(CommonFunAni::CallGetter(env, object, PROPERTYNAME_CONTROLTYPE, &enumItem));
    RETURN_FALSE_IF_FALSE(EnumUtils::EnumETSToNative(env, enumItem, disposedRule.disposedType));

    // elementList: Array<ElementName>
    RETURN_FALSE_IF_FALSE(CommonFunAni::CallGetter(env, object, PROPERTYNAME_ELEMENTLIST, &array));
    RETURN_FALSE_IF_FALSE(CommonFunAni::ParseAniArray(
        env, array, disposedRule.elementList, CommonFunAni::ParseElementName));

    // priority: int
    RETURN_FALSE_IF_FALSE(CommonFunAni::CallGetter(env, object, PROPERTYNAME_PRIORITY, &intValue));
    disposedRule.priority = intValue;

    return true;
}

bool AniAppControlCommon::ParseUninstallDisposedRule(ani_env* env,
    ani_object object, UninstallDisposedRule& uninstallDisposedRule)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(object);

    ani_object objectValue = nullptr;
    ani_enum_item enumItem = nullptr;
    ani_int intValue = 0;

    // want: Want
    Want want;
    RETURN_FALSE_IF_FALSE(CommonFunAni::CallGetter(env, object, PROPERTYNAME_WANT, &objectValue));
    if (!UnwrapWant(env, objectValue, want)) {
        APP_LOGE("parse want failed");
        return false;
    }
    uninstallDisposedRule.want = std::make_shared<Want>(want);

    // uninstallComponentType: UninstallComponentType
    RETURN_FALSE_IF_FALSE(CommonFunAni::CallGetter(env, object, PROPERTYNAME_UNINSTALLCOMPONENTTYPE, &enumItem));
    RETURN_FALSE_IF_FALSE(EnumUtils::EnumETSToNative(env, enumItem, uninstallDisposedRule.uninstallComponentType));

    // priority: int
    RETURN_FALSE_IF_FALSE(CommonFunAni::CallGetter(env, object, PROPERTYNAME_PRIORITY, &intValue));
    uninstallDisposedRule.priority = intValue;

    return true;
}

bool AniAppControlCommon::ParseDisposedRuleConfiguration(ani_env* env,
    ani_object object, DisposedRuleConfiguration& disposedRuleConfiguration)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(object);

    ani_string string = nullptr;

    // appId: string
    RETURN_FALSE_IF_FALSE(CommonFunAni::CallGetter(env, object, PROPERTYNAME_APPID, &string));
    disposedRuleConfiguration.appId = CommonFunAni::AniStrToString(env, string);
    if (disposedRuleConfiguration.appId.empty()) {
        APP_LOGE("appId empty");
        return false;
    }

    ani_int intValue = 0;

    // appIndex: int
    RETURN_FALSE_IF_FALSE(CommonFunAni::CallGetter(env, object, PROPERTYNAME_APPINDEX, &intValue));
    if (intValue < Constants::MAIN_APP_INDEX || intValue > Constants::CLONE_APP_INDEX_MAX) {
        return false;
    }
    disposedRuleConfiguration.appIndex = intValue;

    ani_object objectValue = nullptr;

    // disposedRule: DisposedRule

    RETURN_FALSE_IF_FALSE(CommonFunAni::CallGetter(env, object, PROPERTYNAME_DISPOSEDRULE, &objectValue));
    RETURN_FALSE_IF_FALSE(ParseDisposedRule(env, objectValue, disposedRuleConfiguration.disposedRule));

    return true;
}
} // namespace AppExecFwk
} // namespace OHOS