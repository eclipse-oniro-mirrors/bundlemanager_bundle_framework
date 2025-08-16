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

#ifndef BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_ENUM_UTIL_H
#define BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_ENUM_UTIL_H

#include <array>
#include <string>

#include "app_log_wrapper.h"
#include "bundle_mgr_interface.h"

namespace OHOS {
namespace AppExecFwk {
namespace CommonFunAniNS {
constexpr int32_t UNSPECIFIED = 255;

constexpr const char* CLASSNAME_BUNDLEMANAGER_BUNDLE_FLAG = "@ohos.bundle.bundleManager.bundleManager.BundleFlag";
constexpr const char* CLASSNAME_BUNDLEMANAGER_BUNDLE_TYPE = "@ohos.bundle.bundleManager.bundleManager.BundleType";
constexpr const char* CLASSNAME_BUNDLEMANAGER_MULTI_APP_MODE_TYPE =
    "@ohos.bundle.bundleManager.bundleManager.MultiAppModeType";
constexpr const char* CLASSNAME_BUNDLEMANAGER_DISPLAY_ORIENTATION =
    "@ohos.bundle.bundleManager.bundleManager.DisplayOrientation";
constexpr const char* CLASSNAME_BUNDLEMANAGER_LAUNCH_TYPE = "@ohos.bundle.bundleManager.bundleManager.LaunchType";
constexpr const char* CLASSNAME_BUNDLEMANAGER_SUPPORT_WINDOW_MODE =
    "@ohos.bundle.bundleManager.bundleManager.SupportWindowMode";
constexpr const char* CLASSNAME_BUNDLEMANAGER_EXTENSION_ABILITY_TYPE =
    "@ohos.bundle.bundleManager.bundleManager.ExtensionAbilityType";
constexpr const char* CLASSNAME_BUNDLEMANAGER_MODULE_TYPE = "@ohos.bundle.bundleManager.bundleManager.ModuleType";
constexpr const char* CLASSNAME_BUNDLEMANAGER_PERMISSION_GRANT_STATE =
    "@ohos.bundle.bundleManager.bundleManager.PermissionGrantState";
constexpr const char* CLASSNAME_BUNDLEMANAGER_APPLICATION_FLAG =
    "@ohos.bundle.bundleManager.bundleManager.ApplicationFlag";
constexpr const char* CLASSNAME_BUNDLEMANAGER_COMPATIBLE_POLICY =
    "@ohos.bundle.bundleManager.bundleManager.CompatiblePolicy";
constexpr const char* CLASSNAME_BUNDLE_DISPLAY_ORIENTATION = "@ohos.bundle.bundle.DisplayOrientation";
constexpr const char* CLASSNAME_BUNDLE_ABILITY_TYPE = "@ohos.bundle.bundle.AbilityType";
constexpr const char* CLASSNAME_BUNDLE_ABILITY_SUB_TYPE = "@ohos.bundle.bundle.AbilitySubType";
constexpr const char* CLASSNAME_BUNDLE_LAUNCH_MODE = "@ohos.bundle.bundle.LaunchMode";
constexpr const char* CLASSNAME_ZLIB_COMPRESS_LEVEL = "@ohos.zlib.zlib.CompressLevel";
constexpr const char* CLASSNAME_ZLIB_MEM_LEVEL = "@ohos.zlib.zlib.MemLevel";
constexpr const char* CLASSNAME_ZLIB_COMPRESS_STRATEGY = "@ohos.zlib.zlib.CompressStrategy";
constexpr const char* CLASSNAME_ZLIB_RETURN_STATUS = "@ohos.zlib.zlib.ReturnStatus";
constexpr const char* CLASSNAME_APPCONTROL_COMPONENT_TYPE = "@ohos.bundle.appControl.appControl.ComponentType";
constexpr const char* CLASSNAME_APPCONTROL_DISPOSED_TYPE = "@ohos.bundle.appControl.appControl.DisposedType";
constexpr const char* CLASSNAME_APPCONTROL_CONTROL_TYPE = "@ohos.bundle.appControl.appControl.ControlType";
constexpr const char* CLASSNAME_APPCONTROL_UNINSTALL_COMPONENT_TYPE =
    "@ohos.bundle.appControl.appControl.UninstallComponentType";
} // namespace CommonFunAniNS
class EnumUtils {
private:
    static ani_enum_item EnumNativeToETSByIndex(ani_env* env, const char* enumClassName, const size_t index)
    {
        if (env == nullptr) {
            APP_LOGE("null env");
            return nullptr;
        }

        ani_enum aniEnum = nullptr;
        ani_status status = env->FindEnum(enumClassName, &aniEnum);
        if (status != ANI_OK) {
            APP_LOGE("FindEnum failed %{public}d", status);
            return nullptr;
        }

        ani_enum_item enumItem = nullptr;
        status = env->Enum_GetEnumItemByIndex(aniEnum, index, &enumItem);
        if (status != ANI_OK) {
            APP_LOGE("Enum_GetEnumItemByIndex failed %{public}d", status);
            return nullptr;
        }
        return enumItem;
    }

    // enum offset = enum value - enum index
    static inline ani_enum_item EnumNativeToETSByOffset(
        ani_env* env, const char* enumClassName, const int32_t enumValue, const int32_t offset)
    {
        if (enumValue < offset) {
            APP_LOGE("invalid index");
            return nullptr;
        }
        return EnumNativeToETSByIndex(env, enumClassName, enumValue - offset);
    }

    template<std::size_t tableSize>
    static inline ani_enum_item EnumNativeToETSByTable(
        ani_env* env, const char* enumClassName, const int32_t enumValue, const std::array<int32_t, tableSize>& table)
    {
        for (std::size_t index = 0; index < table.size(); ++index) {
            if (enumValue == table[index]) {
                return EnumNativeToETSByIndex(env, enumClassName, index);
            }
        }

        APP_LOGE("Not found %{public}d", enumValue);
        return nullptr;
    }

    /* bundleManager.BundleFlag
    enum BundleFlag {
        GET_BUNDLE_INFO_DEFAULT = 0x00000000,
        GET_BUNDLE_INFO_WITH_APPLICATION = 0x00000001,
        GET_BUNDLE_INFO_WITH_HAP_MODULE = 0x00000002,
        GET_BUNDLE_INFO_WITH_ABILITY = 0x00000004,
        GET_BUNDLE_INFO_WITH_EXTENSION_ABILITY = 0x00000008,
        GET_BUNDLE_INFO_WITH_REQUESTED_PERMISSION = 0x00000010,
        GET_BUNDLE_INFO_WITH_METADATA = 0x00000020,
        GET_BUNDLE_INFO_WITH_DISABLE = 0x00000040,
        GET_BUNDLE_INFO_WITH_SIGNATURE_INFO = 0x00000080,
        GET_BUNDLE_INFO_WITH_MENU = 0x00000100,
        GET_BUNDLE_INFO_WITH_ROUTER_MAP = 0x00000200,
        GET_BUNDLE_INFO_WITH_SKILL = 0x00000800,
        GET_BUNDLE_INFO_ONLY_WITH_LAUNCHER_ABILITY = 0x00001000,
        GET_BUNDLE_INFO_OF_ANY_USER = 0x00002000,
        GET_BUNDLE_INFO_EXCLUDE_CLONE = 0x00004000,
    } */
    static constexpr std::array<int, 15> Array_BundleManager_BundleFlag = {
        0x00000000,
        0x00000001,
        0x00000002,
        0x00000004,
        0x00000008,
        0x00000010,
        0x00000020,
        0x00000040,
        0x00000080,
        0x00000100,
        0x00000200,
        0x00000800,
        0x00001000,
        0x00002000,
        0x00004000,
    };
    /* bundleManager.ExtensionAbilityType
    enum ExtensionAbilityType {
        FORM = 0,
        WORK_SCHEDULER = 1,
        INPUT_METHOD = 2,
        SERVICE = 3,
        ACCESSIBILITY = 4,
        DATA_SHARE = 5,
        FILE_SHARE = 6,
        STATIC_SUBSCRIBER = 7,
        WALLPAPER = 8,
        BACKUP = 9,
        WINDOW = 10,
        ENTERPRISE_ADMIN = 11,
        THUMBNAIL = 13,
        PREVIEW = 14,
        PRINT = 15,
        SHARE = 16,
        PUSH = 17,
        DRIVER = 18,
        ACTION = 19,
        ADS_SERVICE = 20,
        EMBEDDED_UI = 21,
        INSIGHT_INTENT_UI = 22,
        FENCE = 24,
        CALLER_INFO_QUERY = 25,
        ASSET_ACCELERATION = 26,
        FORM_EDIT = 27,
        DISTRIBUTED = 28,
        APP_SERVICE = 29,
        LIVE_FORM = 30,
        UNSPECIFIED = 255
    } */
    static constexpr std::array<int, 30> Array_BundleManager_ExtensionAbilityType = {
        0,
        1,
        2,
        3,
        4,
        5,
        6,
        7,
        8,
        9,
        10,
        11,
        13,
        14,
        15,
        16,
        17,
        18,
        19,
        20,
        21,
        22,
        24,
        25,
        26,
        27,
        28,
        29,
        30,
        255,
    };
    /* bundleManager.ApplicationFlag
    enum ApplicationFlag {
        GET_APPLICATION_INFO_DEFAULT = 0x00000000,
        GET_APPLICATION_INFO_WITH_PERMISSION = 0x00000001,
        GET_APPLICATION_INFO_WITH_METADATA = 0x00000002,
        GET_APPLICATION_INFO_WITH_DISABLE = 0x00000004
    } */
    static constexpr std::array<int, 4> Array_BundleManager_ApplicationFlag = {
        0x00000000,
        0x00000001,
        0x00000002,
        0x00000004,
    };
    /* zlib.CompressLevel
    enum CompressLevel {
        COMPRESS_LEVEL_NO_COMPRESSION = 0,
        COMPRESS_LEVEL_BEST_SPEED = 1,
        COMPRESS_LEVEL_BEST_COMPRESSION = 9,
        COMPRESS_LEVEL_DEFAULT_COMPRESSION = -1
    }*/
    static constexpr std::array<int, 4> Array_Zlib_CompressLevel = {
        0,
        1,
        9,
        -1,
    };
    /* zlib.MemLevel
    enum MemLevel {
        MEM_LEVEL_MIN = 1,
        MEM_LEVEL_MAX = 9,
        MEM_LEVEL_DEFAULT = 8
    } */
    static constexpr std::array<int, 3> Array_Zlib_MemLevel = {
        1,
        9,
        8,
    };

public:
    template<typename enumType>
    static bool EnumETSToNative(ani_env* env, ani_enum_item enumItem, enumType& enumValue)
    {
        if (env == nullptr) {
            APP_LOGE("null env");
            return false;
        }

        if (enumItem == nullptr) {
            APP_LOGE("null enumItem");
            return false;
        }

        ani_int value {};
        ani_status status = env->EnumItem_GetValue_Int(enumItem, &value);
        if (status != ANI_OK) {
            APP_LOGE("EnumItem_GetValue_Int failed %{public}d", status);
            return false;
        }

        enumValue = static_cast<enumType>(value);
        return true;
    }

    // bundleManager.BundleFlag
    static inline ani_enum_item EnumNativeToETS_BundleManager_BundleFlag(ani_env* env, const int32_t value)
    {
        return EnumNativeToETSByTable(
            env, CommonFunAniNS::CLASSNAME_BUNDLEMANAGER_BUNDLE_FLAG, value, Array_BundleManager_BundleFlag);
    }

    /* bundleManager.BundleType
    enum BundleType {
        APP = 0,
        ATOMIC_SERVICE = 1
    } */
    static inline ani_enum_item EnumNativeToETS_BundleManager_BundleType(ani_env* env, const int32_t value)
    {
        return EnumNativeToETSByOffset(env, CommonFunAniNS::CLASSNAME_BUNDLEMANAGER_BUNDLE_TYPE, value, 0);
    }

    /* bundleManager.MultiAppModeType
    enum MultiAppModeType {
        UNSPECIFIED = 0,
        MULTI_INSTANCE = 1,
        APP_CLONE = 2,
    } */
    static inline ani_enum_item EnumNativeToETS_BundleManager_MultiAppModeType(ani_env* env, const int32_t value)
    {
        return EnumNativeToETSByOffset(env, CommonFunAniNS::CLASSNAME_BUNDLEMANAGER_MULTI_APP_MODE_TYPE, value, 0);
    }

    /* bundleManager.DisplayOrientation
    enum DisplayOrientation {
        UNSPECIFIED,
        LANDSCAPE,
        PORTRAIT,
        FOLLOW_RECENT,
        LANDSCAPE_INVERTED,
        PORTRAIT_INVERTED,
        AUTO_ROTATION,
        AUTO_ROTATION_LANDSCAPE,
        AUTO_ROTATION_PORTRAIT,
        AUTO_ROTATION_RESTRICTED,
        AUTO_ROTATION_LANDSCAPE_RESTRICTED,
        AUTO_ROTATION_PORTRAIT_RESTRICTED,
        LOCKED,
        AUTO_ROTATION_UNSPECIFIED,
        FOLLOW_DESKTOP
    } */
    static inline ani_enum_item EnumNativeToETS_BundleManager_DisplayOrientation(ani_env* env, const int32_t value)
    {
        return EnumNativeToETSByOffset(env, CommonFunAniNS::CLASSNAME_BUNDLEMANAGER_DISPLAY_ORIENTATION, value, 0);
    }

    /* bundleManager.LaunchType
    enum LaunchType {
        SINGLETON = 0,
        MULTITON = 1,
        SPECIFIED = 2
    } */
    static inline ani_enum_item EnumNativeToETS_BundleManager_LaunchType(ani_env* env, const int32_t value)
    {
        return EnumNativeToETSByOffset(env, CommonFunAniNS::CLASSNAME_BUNDLEMANAGER_LAUNCH_TYPE, value, 0);
    }

    /* bundleManager.SupportWindowMode
    SupportWindowMode {
        FULL_SCREEN = 0,
        SPLIT = 1,
        FLOATING = 2
    } */
    static inline ani_enum_item EnumNativeToETS_BundleManager_SupportWindowMode(ani_env* env, const int32_t value)
    {
        return EnumNativeToETSByOffset(env, CommonFunAniNS::CLASSNAME_BUNDLEMANAGER_SUPPORT_WINDOW_MODE, value, 0);
    }

    // bundleManager.ExtensionAbilityType
    static inline ani_enum_item EnumNativeToETS_BundleManager_ExtensionAbilityType(ani_env* env, const int32_t value)
    {
        bool isValid = std::find(std::begin(Array_BundleManager_ExtensionAbilityType),
                                 std::end(Array_BundleManager_ExtensionAbilityType),
                                 value) != std::end(Array_BundleManager_ExtensionAbilityType);
        return EnumNativeToETSByTable(env, CommonFunAniNS::CLASSNAME_BUNDLEMANAGER_EXTENSION_ABILITY_TYPE,
            isValid ? value : CommonFunAniNS::UNSPECIFIED, Array_BundleManager_ExtensionAbilityType);
    }

    /* bundleManager.ModuleType
    enum ModuleType {
        ENTRY = 1,
        FEATURE = 2,
        SHARED = 3
    } */
    static inline ani_enum_item EnumNativeToETS_BundleManager_ModuleType(ani_env* env, const int32_t value)
    {
        return EnumNativeToETSByOffset(env, CommonFunAniNS::CLASSNAME_BUNDLEMANAGER_MODULE_TYPE, value, 1);
    }

    /* bundleManager.PermissionGrantState
    enum PermissionGrantState {
        PERMISSION_DENIED = -1,
        PERMISSION_GRANTED = 0
    } */
    static inline ani_enum_item EnumNativeToETS_BundleManager_PermissionGrantState(ani_env* env, const int32_t value)
    {
        return EnumNativeToETSByOffset(env, CommonFunAniNS::CLASSNAME_BUNDLEMANAGER_PERMISSION_GRANT_STATE, value, -1);
    }

    // bundleManager.ApplicationFlag
    static inline ani_enum_item EnumNativeToETS_BundleManager_ApplicationFlag(ani_env* env, const int32_t value)
    {
        return EnumNativeToETSByTable(
            env, CommonFunAniNS::CLASSNAME_BUNDLEMANAGER_APPLICATION_FLAG, value, Array_BundleManager_ApplicationFlag);
    }

    /* bundleManager.CompatiblePolicy
    enum CompatiblePolicy {
        BACKWARD_COMPATIBILITY = 1
    } */
    static inline ani_enum_item EnumNativeToETS_BundleManager_CompatiblePolicy(ani_env* env, const int32_t value)
    {
        return EnumNativeToETSByOffset(env, CommonFunAniNS::CLASSNAME_BUNDLEMANAGER_COMPATIBLE_POLICY, value, 1);
    }

    /* bundle.DisplayOrientation
    enum DisplayOrientation {
        UNSPECIFIED,
        LANDSCAPE,
        PORTRAIT,
        FOLLOW_RECENT
    } */
    static inline ani_enum_item EnumNativeToETS_Bundle_DisplayOrientation(ani_env* env, const int32_t value)
    {
        return EnumNativeToETSByOffset(env, CommonFunAniNS::CLASSNAME_BUNDLE_DISPLAY_ORIENTATION, value, 0);
    }

    /* bundle.AbilityType
    enum AbilityType {
        UNKNOWN,
        PAGE,
        SERVICE,
        DATA
    } */
    static inline ani_enum_item EnumNativeToETS_Bundle_AbilityType(ani_env* env, const int32_t value)
    {
        return EnumNativeToETSByOffset(env, CommonFunAniNS::CLASSNAME_BUNDLE_ABILITY_TYPE, value, 0);
    }

    /* bundle.AbilitySubType
    enum AbilitySubType {
        UNSPECIFIED = 0,
        CA = 1
    } */
    static inline ani_enum_item EnumNativeToETS_Bundle_AbilitySubType(ani_env* env, const int32_t value)
    {
        return EnumNativeToETSByOffset(env, CommonFunAniNS::CLASSNAME_BUNDLE_ABILITY_SUB_TYPE, value, 0);
    }

    /* bundle.LaunchMode
    enum LaunchMode {
        SINGLETON = 0,
        STANDARD = 1
    } */
    static inline ani_enum_item EnumNativeToETS_Bundle_LaunchMode(ani_env* env, const int32_t value)
    {
        return EnumNativeToETSByOffset(env, CommonFunAniNS::CLASSNAME_BUNDLE_LAUNCH_MODE, value, 0);
    }

    // zlib.CompressLevel
    static inline ani_enum_item EnumNativeToETS_Zlib_CompressLevel(ani_env* env, const int32_t value)
    {
        return EnumNativeToETSByTable(
            env, CommonFunAniNS::CLASSNAME_ZLIB_COMPRESS_LEVEL, value, Array_Zlib_CompressLevel);
    }

    // zlib.MemLevel
    static inline ani_enum_item EnumNativeToETS_Zlib_MemLevel(ani_env* env, const int32_t value)
    {
        return EnumNativeToETSByTable(env, CommonFunAniNS::CLASSNAME_ZLIB_MEM_LEVEL, value, Array_Zlib_MemLevel);
    }

    /* zlib.CompressStrategy
    enum CompressStrategy {
        COMPRESS_STRATEGY_DEFAULT_STRATEGY = 0,
        COMPRESS_STRATEGY_FILTERED = 1,
        COMPRESS_STRATEGY_HUFFMAN_ONLY = 2,
        COMPRESS_STRATEGY_RLE = 3,
        COMPRESS_STRATEGY_FIXED = 4
    } */
    static inline ani_enum_item EnumNativeToETS_Zlib_CompressStrategy(ani_env* env, const int32_t value)
    {
        return EnumNativeToETSByOffset(env, CommonFunAniNS::CLASSNAME_ZLIB_COMPRESS_STRATEGY, value, 0);
    }

    // zlib.ReturnStatus
    // enum ReturnStatus {
    //     OK = 0,
    //     STREAM_END = 1,
    //     NEED_DICT = 2,
    // }
    static inline ani_enum_item EnumNativeToETS_Zlib_ReturnStatus(ani_env* env, const int32_t value)
    {
        return EnumNativeToETSByOffset(env, CommonFunAniNS::CLASSNAME_ZLIB_RETURN_STATUS, value, 0);
    }

    // appControl.ComponentType
    // enum ComponentType {
    //     UI_ABILITY = 1,
    //     UI_EXTENSION = 2
    // }
    static inline ani_enum_item EnumNativeToETS_AppControl_ComponentType(ani_env* env, const int32_t value)
    {
        return EnumNativeToETSByOffset(env, CommonFunAniNS::CLASSNAME_APPCONTROL_COMPONENT_TYPE, value, 1);
    }

    /* appControl.DisposedType
    enum DisposedType {
        BLOCK_APPLICATION = 1,
        BLOCK_ABILITY = 2,
        NON_BLOCK = 3
    } */
    static inline ani_enum_item EnumNativeToETS_AppControl_DisposedType(ani_env* env, const int32_t value)
    {
        return EnumNativeToETSByOffset(env, CommonFunAniNS::CLASSNAME_APPCONTROL_DISPOSED_TYPE, value, 1);
    }

    /* appControl.ControlType
    enum ControlType {
        ALLOWED_LIST = 1,
        DISALLOWED_LIST = 2
    } */
    static inline ani_enum_item EnumNativeToETS_AppControl_ControlType(ani_env* env, const int32_t value)
    {
        return EnumNativeToETSByOffset(env, CommonFunAniNS::CLASSNAME_APPCONTROL_CONTROL_TYPE, value, 1);
    }

    /* appControl.UninstallComponentType
    enum UninstallComponentType {
        EXTENSION = 1,
    } */
    static inline ani_enum_item EnumNativeToETS_AppControl_UninstallComponentType(ani_env* env, const int32_t value)
    {
        return EnumNativeToETSByOffset(env, CommonFunAniNS::CLASSNAME_APPCONTROL_UNINSTALL_COMPONENT_TYPE, value, 1);
    }
};
} // namespace AppExecFwk
} // namespace OHOS
#endif
