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

#ifndef BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_COMMON_FUN_ANI_H
#define BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_COMMON_FUN_ANI_H

#include <ani.h>
#include <cstring>
#include <iostream>
#include <string>
#include <type_traits>
#include <vector>

#include "bundle_mgr_interface.h"

namespace OHOS {
namespace AppExecFwk {

namespace {
constexpr const char* BOX_BOOLEAN = "Lstd/core/Boolean;";
constexpr const char* BOX_BYTE = "Lstd/core/Byte;";
constexpr const char* BOX_CHAR = "Lstd/core/Char;";
constexpr const char* BOX_SHORT = "Lstd/core/Short;";
constexpr const char* BOX_INT = "Lstd/core/Int;";
constexpr const char* BOX_LONG = "Lstd/core/Long;";
constexpr const char* BOX_FLOAT = "Lstd/core/Float;";
constexpr const char* BOX_DOUBLE = "Lstd/core/Double;";
constexpr const char* SETTER_PREFIX = "<set>";
} // namespace
class CommonFunAni {
public:
    // Data conversion.
    static inline bool AniBooleanToBool(ani_boolean value)
    {
        return value == ANI_TRUE;
    }
    static inline ani_boolean BoolToAniBoolean(bool value)
    {
        return value ? ANI_TRUE : ANI_FALSE;
    }
    static std::string AniStrToString(ani_env* env, ani_string aniStr);
    static inline bool StringToAniStr(ani_env* env, const std::string& str, ani_string& aniStr)
    {
        ani_status status = env->String_NewUTF8(str.c_str(), str.size(), &aniStr);
        if (status != ANI_OK) {
            APP_LOGE("Array_Set_Ref %{public}s failed %{public}d", str.c_str(), status);
            return false;
        }
        return true;
    }

    // Convert from native to ets
    static ani_object ConvertMultiAppMode(ani_env* env, const MultiAppModeData& multiAppMode);
    static ani_object ConvertMetadata(ani_env* env, const Metadata& metadata);
    static ani_ref ConvertModuleMetaInfos(ani_env* env, const std::map<std::string, std::vector<Metadata>>& metadata);
    static ani_object ConvertResource(ani_env* env, const Resource& resource);
    static ani_object ConvertApplicationInfo(ani_env* env, const ApplicationInfo& appInfo);

    static ani_object ConvertAbilityInfo(ani_env* env, const AbilityInfo& abilityInfo);
    static ani_object ConvertWindowSize(ani_env* env, const AbilityInfo& abilityInfo);
    static ani_object ConvertExtensionInfo(ani_env* env, const ExtensionAbilityInfo& extensionInfo);
    static ani_object ConvertDependency(ani_env* env, const Dependency& dependency);
    static ani_object ConvertPreloadItem(ani_env* env, const PreloadItem& preloadItem);
    static ani_object ConvertHapModuleInfo(ani_env* env, const HapModuleInfo& hapModuleInfo);

    static ani_object ConvertRequestPermissionUsedScene(
        ani_env* env, const RequestPermissionUsedScene& requestPermissionUsedScene);
    static ani_object ConvertRequestPermission(ani_env* env, const RequestPermission& requestPermission);

    static ani_object ConvertSignatureInfo(ani_env* env, const SignatureInfo& signatureInfo);

    static ani_ref ConvertRouterDataInfos(ani_env* env, const std::map<std::string, std::string>& data);
    static ani_object ConvertDataItem(ani_env* env, const std::string& key, const std::string& value);
    static ani_object ConvertRouterItem(ani_env* env, const RouterItem& routerItem);

    static ani_object ConvertElementName(ani_env* env, const ElementName& elementName);

    static ani_object ConvertCustomizeData(ani_env* env, const CustomizeData& customizeData);

    static ani_object ConvertAbilitySkillUri(ani_env* env, const SkillUri& skillUri, bool isExtension);
    static ani_object ConvertAbilitySkill(ani_env* env, const Skill& skill, bool isExtension);

    static ani_object ConvertBundleInfo(ani_env* env, const BundleInfo& bundleInfo);

    static ani_object ConvertShortcutInfo(ani_env* env, const ShortcutInfo& shortcutInfo);
    static ani_ref ConvertShortcutInfos(ani_env* env, const std::vector<ShortcutInfo>& shortcutInfos);
    static ani_object ConvertShortcutIntent(ani_env* env, const ShortcutIntent& shortcutIntent);
    static ani_ref ConvertShortcutIntentParameters(
        ani_env* env, const std::map<std::string, std::string>& data, const std::string& className);

    // Parse from ets to native
    static bool ParseShortcutInfo(ani_env* env, ani_object object, ShortcutInfo& shortcutInfo);
    static bool ParseShortcutIntent(ani_env* env, ani_object object, ShortcutIntent& shortcutIntent);
    static bool ParseKeyValuePair(ani_env* env, ani_object object, std::pair<std::string, std::string>& pair);

private:
    static ani_class CreateClassByName(ani_env* env, const std::string& className);
    static ani_object CreateNewObjectByClass(ani_env* env, ani_class cls);
    static ani_ref ConvertAniArrayByClass(
        ani_env* env, const std::string& className, const std::vector<ani_object>& aArray);
    static ani_ref ConvertAniArrayString(ani_env* env, const std::vector<std::string>& cArray);

    template<typename enumType>
    static ani_array_int ConvertAniArrayEnum(
        ani_env* env, const std::vector<enumType>& cArray, int32_t (*converter)(const int32_t))
    {
        ani_size length = cArray.size();
        ani_array_int aArrayEnum = nullptr;
        ani_status status = env->Array_New_Int(length, &aArrayEnum);
        if (status != ANI_OK) {
            APP_LOGE("Array_New_Int failed %{public}d", status);
            return nullptr;
        }
        std::vector<ani_int> buffer(length);
        for (ani_size i = 0; i < length; ++i) {
            buffer[i] = converter(static_cast<int32_t>(cArray[i]));
        }
        env->Array_SetRegion_Int(aArrayEnum, 0, length, &buffer[0]);
        return aArrayEnum;
    }

    template<typename T, typename... Args>
    static bool ParseAniArray(ani_env* env, ani_array aniArray, std::vector<T>& nativeArray,
        bool (*parser)(ani_env*, ani_object, T&), Args&&... args)
    {
        ani_double length;
        ani_status status = env->Object_GetPropertyByName_Double(aniArray, "length", &length);
        if (status != ANI_OK) {
            APP_LOGE("Object_GetPropertyByName_Double failed %{public}d", status);
            return false;
        }
        for (ani_int i = 0; i < static_cast<ani_int>(length); ++i) {
            ani_ref ref;
            status = env->Object_CallMethodByName_Ref(aniArray, "$_get", "I:Lstd/core/Object;", &ref, i);
            if (status != ANI_OK) {
                APP_LOGE("Object_CallMethodByName_Ref failed %{public}d", status);
                continue;
            }
            T obj(std::forward<Args>(args)...);
            if (parser(env, reinterpret_cast<ani_object>(ref), obj)) {
                nativeArray.emplace_back(obj);
            }
            env->Reference_Delete(ref);
        }
        return true;
    }

    template<typename valueType>
    static inline void CallGetter(ani_env* env, ani_object object, const char* propertyName, valueType* value)
    {
        ani_status status = ANI_ERROR;
        if constexpr (std::is_pointer_v<valueType> && std::is_base_of_v<__ani_ref, std::remove_pointer_t<valueType>>) {
            status = env->Object_GetPropertyByName_Ref(object, propertyName, reinterpret_cast<ani_ref*>(value));
        } else if constexpr (std::is_same_v<valueType, ani_boolean>) {
            status = env->Object_GetPropertyByName_Boolean(object, propertyName, value);
        } else if constexpr (std::is_same_v<valueType, ani_char>) {
            status = env->Object_GetPropertyByName_Char(object, propertyName, value);
        } else if constexpr (std::is_same_v<valueType, ani_byte>) {
            status = env->Object_GetPropertyByName_Byte(object, propertyName, value);
        } else if constexpr (std::is_same_v<valueType, ani_short> || std::is_same_v<valueType, uint16_t>) {
            status = env->Object_GetPropertyByName_Short(object, propertyName, value);
        } else if constexpr (std::is_same_v<valueType, ani_int> || std::is_same_v<valueType, uint32_t>) {
            status = env->Object_GetPropertyByName_Int(object, propertyName, value);
        } else if constexpr (std::is_same_v<valueType, ani_long> || std::is_same_v<valueType, uint64_t>) {
            status = env->Object_GetPropertyByName_Long(object, propertyName, value);
        } else if constexpr (std::is_same_v<valueType, ani_float>) {
            status = env->Object_GetPropertyByName_Float(object, propertyName, value);
        } else if constexpr (std::is_same_v<valueType, ani_double>) {
            status = env->Object_GetPropertyByName_Double(object, propertyName, value);
        } else {
            APP_LOGE("Object_GetPropertyByName Unsupported");
            return;
        }

        if (status != ANI_OK) {
            APP_LOGE("Object_GetPropertyByName failed %{public}d", status);
        }
    }

    template<typename valueType>
    static bool CallGetterOptional(ani_env* env, ani_object object, const char* propertyName, valueType* value)
    {
        ani_ref ref = nullptr;
        ani_status status = env->Object_GetPropertyByName_Ref(object, propertyName, &ref);
        if (status != ANI_OK) {
            APP_LOGE("Object_GetPropertyByName_Ref failed %{public}d", status);
            return false;
        }

        ani_boolean isUndefined;
        env->Reference_IsUndefined(ref, &isUndefined);
        if (isUndefined) {
            return false;
        }

        if constexpr (std::is_pointer_v<valueType> && std::is_base_of_v<__ani_ref, std::remove_pointer_t<valueType>>) {
            *value = reinterpret_cast<valueType>(ref);
        } else {
            status = ANI_ERROR;
            if constexpr (std::is_same_v<valueType, ani_boolean>) {
                status = env->Object_CallMethodByName_Boolean(
                    reinterpret_cast<ani_object>(ref), "booleanValue", nullptr, value);
            } else if constexpr (std::is_same_v<valueType, ani_char>) {
                status =
                    env->Object_CallMethodByName_Char(reinterpret_cast<ani_object>(ref), "charValue", nullptr, value);
            } else if constexpr (std::is_same_v<valueType, ani_byte>) {
                status =
                    env->Object_CallMethodByName_Byte(reinterpret_cast<ani_object>(ref), "byteValue", nullptr, value);
            } else if constexpr (std::is_same_v<valueType, ani_short> || std::is_same_v<valueType, uint16_t>) {
                status =
                    env->Object_CallMethodByName_Short(reinterpret_cast<ani_object>(ref), "shortValue", nullptr, value);
            } else if constexpr (std::is_same_v<valueType, ani_int> || std::is_same_v<valueType, uint32_t>) {
                status =
                    env->Object_CallMethodByName_Int(reinterpret_cast<ani_object>(ref), "intValue", nullptr, value);
            } else if constexpr (std::is_same_v<valueType, ani_long> || std::is_same_v<valueType, uint64_t>) {
                status =
                    env->Object_CallMethodByName_Long(reinterpret_cast<ani_object>(ref), "longValue", nullptr, value);
            } else if constexpr (std::is_same_v<valueType, ani_float>) {
                status =
                    env->Object_CallMethodByName_Float(reinterpret_cast<ani_object>(ref), "floatValue", nullptr, value);
            } else if constexpr (std::is_same_v<valueType, ani_double>) {
                status = env->Object_CallMethodByName_Double(
                    reinterpret_cast<ani_object>(ref), "doubleValue", nullptr, value);
            } else {
                APP_LOGE("Object_CallMethodByName Unsupported");
                return false;
            }
            if (status != ANI_OK) {
                APP_LOGE("Object_CallMethodByName failed %{public}d", status);
            }
        }

        return true;
    }

    template<typename valueType>
    static inline void CallSetter(
        ani_env* env, ani_class cls, ani_object object, const char* propertyName, valueType value)
    {
        std::string setterName(SETTER_PREFIX);
        setterName.append(propertyName);
        ani_method setter;
        ani_status status = env->Class_FindMethod(cls, setterName.c_str(), nullptr, &setter);
        if (status != ANI_OK) {
            APP_LOGE("Class_FindMethod %{public}s failed %{public}d", propertyName, status);
        }

        status = env->Object_CallMethod_Void(object, setter, value);
        if (status != ANI_OK) {
            APP_LOGE("Object_CallMethod_Void %{public}s failed %{public}d", propertyName, status);
        }
    }

    // sets optional property to undefined
    static inline void CallSetterOptionalUndefined(
        ani_env* env, ani_class cls, ani_object object, const char* propertyName)
    {
        ani_ref undefined = nullptr;
        env->GetUndefined(&undefined);
        CallSetter(env, cls, object, propertyName, undefined);
    }

    template<typename valueType>
    static void CallSetterOptional(
        ani_env* env, ani_class cls, ani_object object, const char* propertyName, valueType value)
    {
        if constexpr (std::is_pointer_v<valueType> && std::is_base_of_v<__ani_ref, std::remove_pointer_t<valueType>>) {
            CallSetter(env, cls, object, propertyName, value);
            return;
        }

        const char* valueClassName = nullptr;
        if constexpr (std::is_same_v<valueType, ani_boolean>) {
            valueClassName = BOX_BOOLEAN;
        } else if constexpr (std::is_same_v<valueType, ani_char>) {
            valueClassName = BOX_CHAR;
        } else if constexpr (std::is_same_v<valueType, ani_byte>) {
            valueClassName = BOX_BYTE;
        } else if constexpr (std::is_same_v<valueType, ani_short> || std::is_same_v<valueType, uint16_t>) {
            valueClassName = BOX_SHORT;
        } else if constexpr (std::is_same_v<valueType, ani_int> || std::is_same_v<valueType, uint32_t>) {
            valueClassName = BOX_INT;
        } else if constexpr (std::is_same_v<valueType, ani_long> || std::is_same_v<valueType, uint64_t>) {
            valueClassName = BOX_LONG;
        } else if constexpr (std::is_same_v<valueType, ani_float>) {
            valueClassName = BOX_FLOAT;
        } else if constexpr (std::is_same_v<valueType, ani_double>) {
            valueClassName = BOX_DOUBLE;
        } else {
            APP_LOGE("Classname %{public}s Unsupported", propertyName);
            return;
        }

        ani_class valueClass = nullptr;
        ani_status status = env->FindClass(valueClassName, &valueClass);
        if (status != ANI_OK) {
            APP_LOGE("FindClass %{public}s %{public}s failed %{public}d", propertyName, valueClassName, status);
        }

        ani_method ctor = nullptr;
        status = env->Class_FindMethod(valueClass, "<ctor>", nullptr, &ctor);
        if (status != ANI_OK) {
            APP_LOGE("Class_FindMethod <ctor> %{public}s failed %{public}d", propertyName, status);
        }

        ani_object valueObj = nullptr;
        status = env->Object_New(valueClass, ctor, &valueObj, value);
        if (status != ANI_OK) {
            APP_LOGE("Object_New %{public}s failed %{public}d", propertyName, status);
        }

        CallSetter(env, cls, object, propertyName, valueObj);
    }
};
} // namespace AppExecFwk
} // namespace OHOS
#endif