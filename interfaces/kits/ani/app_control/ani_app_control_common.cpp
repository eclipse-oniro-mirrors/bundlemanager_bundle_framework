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

#include <ani_signature_builder.h>

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
constexpr const char* CLASSNAME_WANT = "@ohos.app.ability.Want.Want";
constexpr const char* PROPERTYNAME_WANT = "want";
constexpr const char* PROPERTYNAME_COMPONENT_TYPE = "componentType";
constexpr const char* PROPERTYNAME_DISPOSED_TYPE = "disposedType";
constexpr const char* PROPERTYNAME_CONTROL_TYPE = "controlType";
constexpr const char* PROPERTYNAME_ELEMENT_LIST = "elementList";
constexpr const char* PROPERTYNAME_PRIORITY = "priority";
constexpr const char* PROPERTYNAME_UNINSTALL_COMPONENT_TYPE = "uninstallComponentType";
constexpr const char* PROPERTYNAME_BUNDLE_NAME = "bundleName";
constexpr const char* PROPERTYNAME_ABILITY_NAME = "abilityName";
constexpr const char* PROPERTYNAME_DEVICEID = "deviceId";
constexpr const char* PROPERTYNAME_URI = "uri";
constexpr const char* PROPERTYNAME_TYPE = "type";
constexpr const char* PROPERTYNAME_FLAGS = "flags";
constexpr const char* PROPERTYNAME_ACTION = "action";
constexpr const char* PROPERTYNAME_ENTITIES = "entities";
constexpr const char* PROPERTYNAME_MODULE_NAME = "moduleName";
}

ani_object AniAppControlCommon::ConvertDisposedRule(ani_env* env, const DisposedRule& disposedRule)
{
    RETURN_NULL_IF_NULL(env);

    // want: Want
    ani_object want = nullptr;
    if (disposedRule.want != nullptr) {
        want = WrapWant(env, *disposedRule.want);
        RETURN_NULL_IF_NULL(want);
    }

    // elementList: Array<ElementName>
    ani_object elementList = CommonFunAni::ConvertAniArray(
        env, disposedRule.elementList, CommonFunAni::ConvertElementName);
    RETURN_NULL_IF_NULL(elementList);

    ani_value args[] = {
        { .r = EnumUtils::EnumNativeToETS_AppControl_ComponentType(
            env, static_cast<int32_t>(disposedRule.componentType)) },
        { .r = EnumUtils::EnumNativeToETS_AppControl_DisposedType(
            env, static_cast<int32_t>(disposedRule.disposedType)) },
        { .r = EnumUtils::EnumNativeToETS_AppControl_ControlType(env, static_cast<int32_t>(disposedRule.controlType)) },
        { .r = elementList },
        { .i = disposedRule.priority },
        { .r = want },
    };
    static const std::string ctorSig =
        arkts::ani_signature::SignatureBuilder()
            .AddClass(CommonFunAniNS::CLASSNAME_APPCONTROL_COMPONENT_TYPE) // componentType: ComponentType
            .AddClass(CommonFunAniNS::CLASSNAME_APPCONTROL_DISPOSED_TYPE)  // disposedType: DisposedType
            .AddClass(CommonFunAniNS::CLASSNAME_APPCONTROL_CONTROL_TYPE)   // controlType: ControlType
            .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)                     // elementList: Array<ElementName>
            .AddInt()                                                      // priority: int
            .BuildSignatureDescriptor();
    static const std::string ctorSigWithWant =
        arkts::ani_signature::SignatureBuilder()
            .AddClass(CommonFunAniNS::CLASSNAME_APPCONTROL_COMPONENT_TYPE) // componentType: ComponentType
            .AddClass(CommonFunAniNS::CLASSNAME_APPCONTROL_DISPOSED_TYPE)  // disposedType: DisposedType
            .AddClass(CommonFunAniNS::CLASSNAME_APPCONTROL_CONTROL_TYPE)   // controlType: ControlType
            .AddClass(CommonFunAniNS::CLASSNAME_ARRAY)                     // elementList: Array<ElementName>
            .AddInt()                                                      // priority: int
            .AddClass(CLASSNAME_WANT)                                      // want: Want
            .BuildSignatureDescriptor();
    return CommonFunAni::CreateNewObjectByClassV2(
        env, CLASSNAME_DISPOSED_RULE_INNER, disposedRule.want == nullptr? ctorSig: ctorSigWithWant, args);
}

ani_object AniAppControlCommon::ConvertUninstallDisposedRule(ani_env* env,
    const UninstallDisposedRule& uninstallDisposedRule)
{
    RETURN_NULL_IF_NULL(env);

    // want: Want
    ani_object want = nullptr;
    if (uninstallDisposedRule.want != nullptr) {
        want = WrapWant(env, *uninstallDisposedRule.want);
        RETURN_NULL_IF_NULL(want);
    }

    ani_value args[] = {
        { .r = EnumUtils::EnumNativeToETS_AppControl_UninstallComponentType(
            env, static_cast<int32_t>(uninstallDisposedRule.uninstallComponentType)) },
        { .i = uninstallDisposedRule.priority },
        { .r = want },
    };
    static const std::string ctorSig =
        arkts::ani_signature::SignatureBuilder()
            .AddClass(CommonFunAniNS::CLASSNAME_APPCONTROL_UNINSTALL_COMPONENT_TYPE) // uninstallComponentType
            .AddInt()                                                                // priority: int
            .BuildSignatureDescriptor();
    static const std::string ctorSigWithWant =
        arkts::ani_signature::SignatureBuilder()
            .AddClass(CommonFunAniNS::CLASSNAME_APPCONTROL_UNINSTALL_COMPONENT_TYPE) // uninstallComponentType
            .AddInt()                                                                // priority: int
            .AddClass(CLASSNAME_WANT)                                                // want: Want
            .BuildSignatureDescriptor();
    return CommonFunAni::CreateNewObjectByClassV2(env, CLASSNAME_DISPOSED_UNINSTALL_RULE_INNER,
        uninstallDisposedRule.want == nullptr ? ctorSig : ctorSigWithWant, args);
}

bool AniAppControlCommon::ParseWantWithoutVerification(ani_env* env, ani_object object, Want& want)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(object);

    // bundleName?: string
    ani_string string = nullptr;
    std::string bundleName = "";
    if (CommonFunAni::CallGetFieldOptional(env, object, PROPERTYNAME_BUNDLE_NAME, &string)) {
        bundleName = CommonFunAni::AniStrToString(env, string);
    }

    // abilityName?: string
    std::string abilityName = "";
    if (CommonFunAni::CallGetFieldOptional(env, object, PROPERTYNAME_ABILITY_NAME, &string)) {
        abilityName = CommonFunAni::AniStrToString(env, string);
    }

    // deviceId?: string
    std::string deviceId = "";
    if (CommonFunAni::CallGetFieldOptional(env, object, PROPERTYNAME_DEVICEID, &string)) {
        deviceId = CommonFunAni::AniStrToString(env, string);
    }

    // uri?: string
    std::string uri = "";
    if (CommonFunAni::CallGetFieldOptional(env, object, PROPERTYNAME_URI, &string)) {
        uri = CommonFunAni::AniStrToString(env, string);
    }

    // type?: string
    std::string type = "";
    if (CommonFunAni::CallGetFieldOptional(env, object, PROPERTYNAME_TYPE, &string)) {
        type = CommonFunAni::AniStrToString(env, string);
    }

    // flags?: int
    ani_int intValue = 0;
    int32_t flags = 0;
    if (CommonFunAni::CallGetFieldOptional(env, object, PROPERTYNAME_FLAGS, &intValue)) {
        flags = intValue;
    }

    // action?: string
    std::string action = "";
    if (CommonFunAni::CallGetFieldOptional(env, object, PROPERTYNAME_ACTION, &string)) {
        action = CommonFunAni::AniStrToString(env, string);
    }

    // entities?: Array<string>
    ani_array array = nullptr;
    if (CommonFunAni::CallGetFieldOptional(env, object, PROPERTYNAME_ENTITIES, &array)) {
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
    if (CommonFunAni::CallGetFieldOptional(env, object, PROPERTYNAME_MODULE_NAME, &string)) {
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
    RETURN_FALSE_IF_FALSE(CommonFunAni::CallGetter(env, object, PROPERTYNAME_COMPONENT_TYPE, &enumItem));
    RETURN_FALSE_IF_FALSE(EnumUtils::EnumETSToNative(env, enumItem, disposedRule.componentType));

    // disposedType: DisposedType
    RETURN_FALSE_IF_FALSE(CommonFunAni::CallGetter(env, object, PROPERTYNAME_DISPOSED_TYPE, &enumItem));
    RETURN_FALSE_IF_FALSE(EnumUtils::EnumETSToNative(env, enumItem, disposedRule.disposedType));

    // controlType: ControlType
    RETURN_FALSE_IF_FALSE(CommonFunAni::CallGetter(env, object, PROPERTYNAME_CONTROL_TYPE, &enumItem));
    RETURN_FALSE_IF_FALSE(EnumUtils::EnumETSToNative(env, enumItem, disposedRule.controlType));

    // elementList: Array<ElementName>
    RETURN_FALSE_IF_FALSE(CommonFunAni::CallGetter(env, object, PROPERTYNAME_ELEMENT_LIST, &array));
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
    RETURN_FALSE_IF_FALSE(CommonFunAni::CallGetter(env, object, PROPERTYNAME_UNINSTALL_COMPONENT_TYPE, &enumItem));
    RETURN_FALSE_IF_FALSE(EnumUtils::EnumETSToNative(env, enumItem, uninstallDisposedRule.uninstallComponentType));

    // priority: int
    RETURN_FALSE_IF_FALSE(CommonFunAni::CallGetter(env, object, PROPERTYNAME_PRIORITY, &intValue));
    uninstallDisposedRule.priority = intValue;

    return true;
}
} // namespace AppExecFwk
} // namespace OHOS