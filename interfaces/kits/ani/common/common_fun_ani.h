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

#include "app_log_wrapper.h"
#include "bundle_mgr_interface.h"
#include "bundle_resource_info.h"
#include "clone_param.h"
#include "enum_util.h"
#include "install_param.h"
#include "launcher_ability_info.h"

namespace OHOS {
namespace AppExecFwk {
namespace CommonFunAniNS {
constexpr const char* TYPE_INT = "int";
constexpr const char* TYPE_NUMBER = "number";
constexpr const char* TYPE_STRING = "string";
} // namespace CommonFunAniNS

#define RETURN_NULL_IF_NULL(ptr)     \
    do {                             \
        if ((ptr) == nullptr) {      \
            APP_LOGE("ptr is null"); \
            return nullptr;          \
        }                            \
    } while (0)
#define RETURN_FALSE_IF_NULL(ptr)    \
    do {                             \
        if ((ptr) == nullptr) {      \
            APP_LOGE("ptr is null"); \
            return false;            \
        }                            \
    } while (0)
#define RETURN_NULL_IF_FALSE(condition)     \
    do {                                    \
        if (!(condition)) {                 \
            APP_LOGE("condition is false"); \
            return nullptr;                 \
        }                                   \
    } while (0)
#define RETURN_FALSE_IF_FALSE(condition)    \
    do {                                    \
        if (!(condition)) {                 \
            APP_LOGE("condition is false"); \
            return false;                   \
        }                                   \
    } while (0)
#define RETURN_ANI_STATUS_IF_NOT_OK(res, err) \
    do {                                      \
        if ((res) != ANI_OK) {                \
            APP_LOGE(err);                    \
            return res;                       \
        }                                     \
    } while (0)
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
            APP_LOGE("String_NewUTF8 failed %{public}d", status);
            return false;
        }
        return true;
    }

    // Convert from native to ets
    static ani_object ConvertMultiAppMode(ani_env* env, const MultiAppModeData& multiAppMode);
    static ani_object ConvertMetadata(ani_env* env, const Metadata& metadata);
    static ani_object ConvertModuleMetaInfosItem(
        ani_env* env, const std::pair<std::string, std::vector<Metadata>>& metadata);
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

    static ani_object ConvertKeyValuePair(
        ani_env* env, const std::pair<std::string, std::string>& item, const char* className);
    static ani_object ConvertDataItem(ani_env* env, const std::pair<std::string, std::string>& item);
    static ani_object ConvertRouterItem(ani_env* env, const RouterItem& routerItem);

    static ani_object ConvertElementName(ani_env* env, const ElementName& elementName);

    static ani_object ConvertCustomizeData(ani_env* env, const CustomizeData& customizeData);

    static ani_object ConvertAbilitySkillUriInner(ani_env* env, const SkillUri& skillUri, bool isExtension);
    static inline ani_object ConvertAbilitySkillUri(ani_env* env, const SkillUri& skillUri)
    {
        return ConvertAbilitySkillUriInner(env, skillUri, false);
    }
    static inline ani_object ConvertExtensionAbilitySkillUri(ani_env* env, const SkillUri& skillUri)
    {
        return ConvertAbilitySkillUriInner(env, skillUri, true);
    }
    static ani_object ConvertAbilitySkillInner(ani_env* env, const Skill& skill, bool isExtension);
    static inline ani_object ConvertAbilitySkill(ani_env* env, const Skill& skill)
    {
        return ConvertAbilitySkillInner(env, skill, false);
    }
    static inline ani_object ConvertExtensionAbilitySkill(ani_env* env, const Skill& skill)
    {
        return ConvertAbilitySkillInner(env, skill, true);
    }
    static ani_object ConvertBundleInfo(ani_env* env, const BundleInfo& bundleInfo, int32_t flags);

    static ani_object ConvertAppCloneIdentity(ani_env* env, const std::string& bundleName, const int32_t appIndex);

    static ani_object ConvertBundleResourceInfo(ani_env* env, const BundleResourceInfo& bundleResInfo);

    static ani_object ConvertShortcutInfo(ani_env* env, const ShortcutInfo& shortcutInfo);
    static ani_object ConvertShortcutIntent(ani_env* env, const ShortcutIntent& shortcutIntent);
    static ani_object ConvertShortcutIntentParameter(ani_env* env, const std::pair<std::string, std::string>& item);

    static ani_object ConvertLauncherAbilityInfo(ani_env* env, const LauncherAbilityInfo& launcherAbility);

    // Parse from ets to native
    static bool ParseShortcutInfo(ani_env* env, ani_object object, ShortcutInfo& shortcutInfo);
    static bool ParseShortcutIntent(ani_env* env, ani_object object, ShortcutIntent& shortcutIntent);
    static bool ParseKeyValuePair(ani_env* env, ani_object object, std::pair<std::string, std::string>& pair);
    static bool ParseKeyValuePairWithName(ani_env* env, ani_object object, std::pair<std::string, std::string>& pair,
        const char* keyName, const char* valueName);

    static ani_class CreateClassByName(ani_env* env, const std::string& className);
    static ani_object CreateNewObjectByClass(ani_env* env, ani_class cls);
    static inline ani_object ConvertAniArrayString(ani_env* env, const std::vector<std::string>& strings)
    {
        return ConvertAniArray(env, strings, [](ani_env* env, const std::string& nativeStr) {
            ani_string aniStr = nullptr;
            return StringToAniStr(env, nativeStr, aniStr) ? aniStr : nullptr;
        });
    }
    static inline bool ParseStrArray(ani_env* env, ani_object arrayObj, std::vector<std::string>& strings)
    {
        return ParseAniArray(env, arrayObj, strings, [](ani_env* env, ani_object aniStr, std::string& nativeStr) {
            nativeStr = AniStrToString(env, static_cast<ani_string>(aniStr));
            return true;
        });
    }
    template<typename enumType>
    static inline bool ParseEnumArray(ani_env* env, ani_object arrayObj, std::vector<enumType>& enums)
    {
        return ParseAniArray(env, arrayObj, enums, [](ani_env* env, ani_object aniItem, enumType& nativeItem) {
            return EnumUtils::EnumETSToNative(env, reinterpret_cast<ani_enum_item>(aniItem), nativeItem);
        });
    }
    static bool ParseInstallParam(ani_env* env, ani_object object, InstallParam& installParam);
    static bool ParseHashParams(ani_env* env, ani_object object, std::pair<std::string, std::string>& pair);
    static bool ParsePgoParams(ani_env* env, ani_object object, std::pair<std::string, std::string>& pair);
    static bool ParseUninstallParam(ani_env* env, ani_object object, UninstallParam& uninstallParam);
    static bool ParseCreateAppCloneParam(ani_env* env, ani_object object, int32_t& userId, int32_t& appIdx);
    static bool ParseDestroyAppCloneParam(ani_env* env, ani_object object, DestroyAppCloneParam& destroyAppCloneParam);
    
    static bool ParseMetadata(ani_env* env, ani_object object, Metadata& metadata);
    static bool ParseResource(ani_env* env, ani_object object, Resource& resource);
    static bool ParseMultiAppMode(ani_env* env, ani_object object, MultiAppModeData& multiAppMode);
    static bool ParseApplicationInfo(ani_env* env, ani_object object, ApplicationInfo& appInfo);
    static bool ParseWindowSize(ani_env* env, ani_object object, AbilityInfo& abilityInfo);
    static bool ParseAbilitySkillUriInner(ani_env* env, ani_object object, SkillUri& skillUri, bool isExtension);
    static inline bool ParseAbilitySkillUri(ani_env* env, ani_object object, SkillUri& skillUri)
    {
        return ParseAbilitySkillUriInner(env, object, skillUri, false);
    }
    static inline bool ParseExtensionAbilitySkillUri(ani_env* env, ani_object object, SkillUri& skillUri)
    {
        return ParseAbilitySkillUriInner(env, object, skillUri, true);
    }
    static bool ParseAbilitySkillInner(ani_env* env, ani_object object, Skill& skill, bool isExtension);
    static inline bool ParseAbilitySkill(ani_env* env, ani_object object, Skill& skill)
    {
        return ParseAbilitySkillInner(env, object, skill, false);
    }
    static inline bool ParseExtensionAbilitySkill(ani_env* env, ani_object object, Skill& skill)
    {
        return ParseAbilitySkillInner(env, object, skill, true);
    }
    static bool ParseAbilityInfo(ani_env* env, ani_object object, AbilityInfo& abilityInfo);

    template<typename toType>
    static bool TryCastDoubleTo(const double fromValue, toType* toValue)
    {
        RETURN_FALSE_IF_NULL(toValue);

        if (std::isnan(fromValue)) {
            APP_LOGE("value is NaN");
            return false;
        }
        if (std::isinf(fromValue)) {
            APP_LOGE("value is Inf");
            return false;
        }
        if (fromValue > static_cast<double>(std::numeric_limits<toType>::max())) {
            APP_LOGE("value too large");
            return false;
        }
        if (fromValue < static_cast<double>(std::numeric_limits<toType>::lowest())) {
            APP_LOGE("value too small");
            return false;
        }

        *toValue = static_cast<toType>(fromValue);
        return true;
    }

    template<typename enumType>
    static ani_object ConvertAniArrayEnum(
        ani_env* env, const std::vector<enumType>& cArray, ani_enum_item (*converter)(ani_env*, const int32_t))
    {
        RETURN_NULL_IF_NULL(env);
        RETURN_NULL_IF_NULL(converter);

        ani_class arrayCls = nullptr;
        ani_status status = env->FindClass("Lescompat/Array;", &arrayCls);
        if (status != ANI_OK) {
            APP_LOGE("FindClass failed %{public}d", status);
            return nullptr;
        }

        ani_method arrayCtor;
        status = env->Class_FindMethod(arrayCls, "<ctor>", "I:V", &arrayCtor);
        if (status != ANI_OK) {
            APP_LOGE("Class_FindMethod failed %{public}d", status);
            return nullptr;
        }

        ani_object arrayObj;
        ani_size length = cArray.size();
        status = env->Object_New(arrayCls, arrayCtor, &arrayObj, length);
        if (status != ANI_OK) {
            APP_LOGE("Object_New failed %{public}d", status);
            return nullptr;
        }
        if (length > 0) {
            for (ani_size i = 0; i < length; ++i) {
                ani_enum_item item = converter(env, static_cast<int32_t>(cArray[i]));
                if (item == nullptr) {
                    APP_LOGE("convert failed");
                    return nullptr;
                }
                status = env->Object_CallMethodByName_Void(arrayObj, "$_set", "ILstd/core/Object;:V", i, item);
                env->Reference_Delete(item);
                if (status != ANI_OK) {
                    APP_LOGE("Object_CallMethodByName_Void failed %{public}d", status);
                    return nullptr;
                }
            }
        }

        return arrayObj;
    }

    template<typename containerType, typename Converter, typename... Args>
    static ani_object ConvertAniArray(ani_env* env,
        const containerType& nativeArray, Converter converter, Args&&... args)
    {
        RETURN_NULL_IF_NULL(env);
        RETURN_NULL_IF_NULL(converter);

        ani_class arrayCls = nullptr;
        ani_status status = env->FindClass("Lescompat/Array;", &arrayCls);
        if (status != ANI_OK) {
            APP_LOGE("FindClass failed %{public}d", status);
            return nullptr;
        }

        ani_method arrayCtor;
        status = env->Class_FindMethod(arrayCls, "<ctor>", "I:V", &arrayCtor);
        if (status != ANI_OK) {
            APP_LOGE("Class_FindMethod failed %{public}d", status);
            return nullptr;
        }

        ani_size length = nativeArray.size();
        ani_object arrayObj;
        status = env->Object_New(arrayCls, arrayCtor, &arrayObj, length);
        if (status != ANI_OK) {
            APP_LOGE("Object_New failed %{public}d", status);
            return nullptr;
        }

        ani_size i = 0;
        for (const auto& iter : nativeArray) {
            ani_object item = converter(env, iter, std::forward<Args>(args)...);
            RETURN_NULL_IF_NULL(item);
            status = env->Object_CallMethodByName_Void(arrayObj, "$_set", "ILstd/core/Object;:V", i, item);
            env->Reference_Delete(item);
            if (status != ANI_OK) {
                APP_LOGE("Object_CallMethodByName_Void failed %{public}d", status);
                return nullptr;
            }
            ++i;
        }

        return arrayObj;
    }

    template<typename callbackType, typename... Args>
    static bool AniArrayForeach(ani_env* env, ani_object aniArray, callbackType callback, Args&&... args)
    {
        RETURN_FALSE_IF_NULL(env);
        RETURN_FALSE_IF_NULL(aniArray);

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
                return false;
            }
            bool result = callback(reinterpret_cast<ani_object>(ref), std::forward<Args>(args)...);
            env->Reference_Delete(ref);
            if (!result) {
                return false;
            }
        }
        return true;
    }

    template<typename nativeType, typename Parser, typename... Args>
    static bool ParseAniArray(ani_env* env,
        ani_object aniArray, std::vector<nativeType>& nativeArray, Parser parser, Args&&... args)
    {
        return AniArrayForeach(
            env, aniArray,
            [env, &nativeArray, parser](ani_object aniObj, Args&&... args) {
                nativeType nativeObj;
                bool result = parser(env, aniObj, nativeObj, std::forward<Args>(args)...);
                if (result) {
                    nativeArray.emplace_back(nativeObj);
                    return true;
                } else {
                    nativeArray.clear();
                    return false;
                }
            },
            std::forward<Args>(args)...);
    }

    template<typename valueType>
    static bool CallGetter(ani_env* env, ani_object object, const char* propertyName, valueType* value)
    {
        RETURN_FALSE_IF_NULL(env);
        RETURN_FALSE_IF_NULL(object);

        ani_status status = ANI_ERROR;
        if constexpr (std::is_pointer_v<valueType> && std::is_base_of_v<__ani_ref, std::remove_pointer_t<valueType>>) {
            status = env->Object_GetPropertyByName_Ref(object, propertyName, reinterpret_cast<ani_ref*>(value));
        } else if constexpr (std::is_same_v<valueType, ani_boolean>) {
            status = env->Object_GetPropertyByName_Boolean(object, propertyName, value);
        } else if constexpr (std::is_same_v<valueType, ani_char>) {
            status = env->Object_GetPropertyByName_Char(object, propertyName, value);
        } else if constexpr (std::is_same_v<valueType, ani_byte> || std::is_same_v<valueType, ani_short> ||
                             std::is_same_v<valueType, ani_int> || std::is_same_v<valueType, uint32_t> ||
                             std::is_same_v<valueType, ani_long> || std::is_same_v<valueType, uint64_t> ||
                             std::is_same_v<valueType, ani_float> || std::is_same_v<valueType, ani_double>) {
            // uint64_t -> BigInt later
            double d = 0;
            status = env->Object_GetPropertyByName_Double(object, propertyName, &d);
            if (status != ANI_OK) {
                APP_LOGE("Object_GetPropertyByName %{public}s failed %{public}d", propertyName, status);
                return false;
            }
            if (!TryCastDoubleTo(d, value)) {
                APP_LOGE("TryCastDoubleTo %{public}s failed", propertyName);
                return false;
            }
            return true;
        } else {
            APP_LOGE("Object_GetPropertyByName %{public}s Unsupported", propertyName);
            return false;
        }

        if (status != ANI_OK) {
            APP_LOGE("Object_GetPropertyByName %{public}s failed %{public}d", propertyName, status);
            return false;
        }

        return true;
    }

    template<typename valueType>
    static bool CallGetterOptional(ani_env* env, ani_object object, const char* propertyName, valueType* value)
    {
        RETURN_FALSE_IF_NULL(env);
        RETURN_FALSE_IF_NULL(object);

        ani_ref ref = nullptr;
        ani_status status = env->Object_GetPropertyByName_Ref(object, propertyName, &ref);
        if (status != ANI_OK) {
            APP_LOGE("Object_GetPropertyByName_Ref %{public}s failed %{public}d", propertyName, status);
            return false;
        }

        ani_boolean isUndefined;
        status = env->Reference_IsUndefined(ref, &isUndefined);
        if (status != ANI_OK) {
            APP_LOGE("Reference_IsUndefined %{public}s failed %{public}d", propertyName, status);
            return false;
        }
        if (isUndefined) {
            return false;
        }

        if constexpr (std::is_pointer_v<valueType> && std::is_base_of_v<__ani_ref, std::remove_pointer_t<valueType>>) {
            *value = reinterpret_cast<valueType>(ref);
        } else {
            status = ANI_ERROR;
            if constexpr (std::is_same_v<valueType, ani_boolean>) {
                status = env->Object_CallMethodByName_Boolean(
                    reinterpret_cast<ani_object>(ref), "unboxed", ":Z", value);
            } else if constexpr (std::is_same_v<valueType, ani_char>) {
                status = env->Object_CallMethodByName_Char(reinterpret_cast<ani_object>(ref), "unboxed", ":C", value);
            } else if constexpr (std::is_same_v<valueType, ani_byte> || std::is_same_v<valueType, ani_short> ||
                                 std::is_same_v<valueType, ani_int> || std::is_same_v<valueType, uint32_t> ||
                                 std::is_same_v<valueType, ani_long> ||
                                 std::is_same_v<valueType, ani_float> || std::is_same_v<valueType, ani_double>) {
                double d = 0;
                status =
                    env->Object_CallMethodByName_Double(reinterpret_cast<ani_object>(ref), "doubleValue", nullptr, &d);
                if (status != ANI_OK) {
                    APP_LOGE("Object_GetPropertyByName %{public}s failed %{public}d", propertyName, status);
                    return false;
                }
                *value = static_cast<valueType>(d);
                if (!TryCastDoubleTo(d, value)) {
                    APP_LOGE("TryCastDoubleTo %{public}s failed", propertyName);
                    return false;
                }
                return true;
            } else {
                APP_LOGE("Object_CallMethodByName %{public}s Unsupported", propertyName);
                return false;
            }
            if (status != ANI_OK) {
                APP_LOGE("Object_CallMethodByName %{public}s failed %{public}d", propertyName, status);
                return false;
            }
        }

        return true;
    }

    template<typename valueType>
    static bool CallSetter(ani_env* env, ani_class cls, ani_object object, const char* propertyName, valueType value)
    {
        RETURN_FALSE_IF_NULL(env);
        RETURN_FALSE_IF_NULL(cls);
        RETURN_FALSE_IF_NULL(object);

        std::string setterName("<set>");
        setterName.append(propertyName);
        ani_method setter;
        ani_status status = env->Class_FindMethod(cls, setterName.c_str(), nullptr, &setter);
        if (status != ANI_OK) {
            APP_LOGE("Class_FindMethod %{public}s failed %{public}d", propertyName, status);
            return false;
        }

        if constexpr (std::is_same_v<valueType, ani_byte> || std::is_same_v<valueType, ani_short> ||
                      std::is_same_v<valueType, ani_int> || std::is_same_v<valueType, uint32_t> ||
                      std::is_same_v<valueType, ani_long> ||
                      std::is_same_v<valueType, ani_float> || std::is_same_v<valueType, ani_double>) {
            status = env->Object_CallMethod_Void(object, setter, static_cast<double>(value));
        } else {
            status = env->Object_CallMethod_Void(object, setter, value);
        }

        if (status != ANI_OK) {
            APP_LOGE("Object_CallMethod_Void %{public}s failed %{public}d", propertyName, status);
            return false;
        }

        return true;
    }

    // sets property to null
    static bool CallSetterNull(ani_env* env, ani_class cls, ani_object object, const char* propertyName)
    {
        RETURN_FALSE_IF_NULL(env);
        RETURN_FALSE_IF_NULL(cls);
        RETURN_FALSE_IF_NULL(object);

        ani_ref nullRef = nullptr;
        ani_status status = env->GetNull(&nullRef);
        if (status != ANI_OK) {
            APP_LOGE("GetNull %{public}s failed %{public}d", propertyName, status);
            return false;
        }

        return CallSetter(env, cls, object, propertyName, nullRef);
    }

    // sets optional property to undefined
    static bool CallSetterOptionalUndefined(ani_env* env, ani_class cls, ani_object object, const char* propertyName)
    {
        RETURN_FALSE_IF_NULL(env);
        RETURN_FALSE_IF_NULL(cls);
        RETURN_FALSE_IF_NULL(object);

        ani_ref undefined = nullptr;
        ani_status status = env->GetUndefined(&undefined);
        if (status != ANI_OK) {
            APP_LOGE("GetUndefined %{public}s failed %{public}d", propertyName, status);
            return false;
        }

        return CallSetter(env, cls, object, propertyName, undefined);
    }

    template<typename valueType>
    static bool CallSetterOptional(
        ani_env* env, ani_class cls, ani_object object, const char* propertyName, valueType value)
    {
        RETURN_FALSE_IF_NULL(env);
        RETURN_FALSE_IF_NULL(cls);
        RETURN_FALSE_IF_NULL(object);

        if constexpr (std::is_pointer_v<valueType> && std::is_base_of_v<__ani_ref, std::remove_pointer_t<valueType>>) {
            return CallSetter(env, cls, object, propertyName, value);
        }

        const char* valueClassName = nullptr;
        const char* ctorSig = nullptr;
        if constexpr (std::is_same_v<valueType, ani_boolean>) {
            valueClassName = "Lstd/core/Boolean;";
            ctorSig = "Z:V";
        } else if constexpr (std::is_same_v<valueType, ani_char>) {
            valueClassName = "Lstd/core/Char;";
            ctorSig = "C:V";
        } else if constexpr (std::is_same_v<valueType, ani_byte> || std::is_same_v<valueType, ani_short> ||
                             std::is_same_v<valueType, ani_int> || std::is_same_v<valueType, uint32_t> ||
                             std::is_same_v<valueType, ani_long> ||
                             std::is_same_v<valueType, ani_float> || std::is_same_v<valueType, ani_double>) {
            valueClassName = "Lstd/core/Double;";
            ctorSig = "D:V";
        } else {
            APP_LOGE("Classname %{public}s Unsupported", propertyName);
            return false;
        }

        ani_class valueClass = nullptr;
        ani_status status = env->FindClass(valueClassName, &valueClass);
        if (status != ANI_OK) {
            APP_LOGE("FindClass %{public}s %{public}s failed %{public}d", propertyName, valueClassName, status);
            return false;
        }

        ani_method ctor = nullptr;
        status = env->Class_FindMethod(valueClass, "<ctor>", ctorSig, &ctor);
        if (status != ANI_OK) {
            APP_LOGE("Class_FindMethod <ctor> %{public}s failed %{public}d", propertyName, status);
            return false;
        }

        ani_object valueObj = nullptr;
        if constexpr (std::is_same_v<valueType, ani_byte> || std::is_same_v<valueType, ani_short> ||
                      std::is_same_v<valueType, ani_int> || std::is_same_v<valueType, uint32_t> ||
                      std::is_same_v<valueType, ani_long> ||
                      std::is_same_v<valueType, ani_float> || std::is_same_v<valueType, ani_double>) {
            status = env->Object_New(valueClass, ctor, &valueObj, static_cast<double>(value));
        } else {
            APP_LOGE("Classname %{public}s Unsupported", propertyName);
            return false;
        }

        if (status != ANI_OK) {
            APP_LOGE("Object_New %{public}s failed %{public}d", propertyName, status);
            return false;
        }

        return CallSetter(env, cls, object, propertyName, valueObj);
    }
};
} // namespace AppExecFwk
} // namespace OHOS
#endif