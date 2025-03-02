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
#include <iostream>
#include <string>

#include "bundle_mgr_interface.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
#define DEFINE_INLINE_CONVERT_FUNC(prefix, namespace, enumname, argname, offset) \
    static inline int prefix##_##namespace##_##enumname(const int argname)       \
    {                                                                            \
        return argname + (offset);                                               \
    }
#define DEFINE_NATIVE_VALUE_TO_INDEX(namespace, enumname, offset) \
    DEFINE_INLINE_CONVERT_FUNC(NativeValueToIndex, namespace, enumname, value, offset)
#define DEFINE_INDEX_TO_NATIVE_VALUE(namespace, enumname, offset) \
    DEFINE_INLINE_CONVERT_FUNC(IndexToNativeValue, namespace, enumname, index, offset)
#define DEFINE_NATIVE_VALUE_TO_INDEX_LOOKUP(namespace, enumname)                                 \
    static inline int32_t NativeValueToIndex##_##namespace##_##enumname(const int32_t value)     \
    {                                                                                            \
        for (std::size_t i = 0; i < Array##_##namespace##_##enumname.size(); ++i) {              \
            if (value == Array##_##namespace##_##enumname[i]) {                                  \
                return i;                                                                        \
            }                                                                                    \
        }                                                                                        \
        std::cerr << "NativeValueToIndex" #namespace #enumname " failed " << value << std::endl; \
        return 0;                                                                                \
    }
#define DEFINE_INDEX_TO_NATIVE_VALUE_LOOKUP(namespace, enumname)                                     \
    static inline int32_t IndexToNativeValue##_##namespace##_##enumname(const int32_t index)         \
    {                                                                                                \
        auto i = static_cast<std::size_t>(index);                                                    \
        if (i < 0 || i >= Array##_##namespace##_##enumname.size()) {                                 \
            std::cerr << "IndexToNativeValue" #namespace #enumname " failed " << index << std::endl; \
            return 0;                                                                                \
        }                                                                                            \
        return Array##_##namespace##_##enumname[i];                                                  \
    }
} // namespace
class EnumUtils {
public:
    // bundleManager.BundleFlag
    DEFINE_NATIVE_VALUE_TO_INDEX_LOOKUP(BundleManager, BundleFlag)
    DEFINE_INDEX_TO_NATIVE_VALUE_LOOKUP(BundleManager, BundleFlag)

    // bundleManager.BundleType
    // enum BundleType {
    //     APP = 0,
    //     ATOMIC_SERVICE = 1
    // }
    DEFINE_NATIVE_VALUE_TO_INDEX(BundleManager, BundleType, 0)
    DEFINE_INDEX_TO_NATIVE_VALUE(BundleManager, BundleType, 0)

    // bundleManager.MultiAppModeType
    // enum MultiAppModeType {
    //     UNSPECIFIED = 0,
    //     MULTI_INSTANCE = 1,
    //     APP_CLONE = 2,
    // }
    DEFINE_NATIVE_VALUE_TO_INDEX(BundleManager, MultiAppModeType, 0)
    DEFINE_INDEX_TO_NATIVE_VALUE(BundleManager, MultiAppModeType, 0)

    // bundleManager.AbilityType
    // enum AbilityType {
    //     PAGE = 1,
    //     SERVICE = 2,
    //     DATA = 3
    // }
    DEFINE_NATIVE_VALUE_TO_INDEX(BundleManager, AbilityType, -1)
    DEFINE_INDEX_TO_NATIVE_VALUE(BundleManager, AbilityType, 1)

    // bundleManager.DisplayOrientation
    // enum DisplayOrientation {
    //     UNSPECIFIED,
    //     LANDSCAPE,
    //     PORTRAIT,
    //     FOLLOW_RECENT,
    //     LANDSCAPE_INVERTED,
    //     PORTRAIT_INVERTED,
    //     AUTO_ROTATION,
    //     AUTO_ROTATION_LANDSCAPE,
    //     AUTO_ROTATION_PORTRAIT,
    //     AUTO_ROTATION_RESTRICTED,
    //     AUTO_ROTATION_LANDSCAPE_RESTRICTED,
    //     AUTO_ROTATION_PORTRAIT_RESTRICTED,
    //     LOCKED,
    //     AUTO_ROTATION_UNSPECIFIED,
    //     FOLLOW_DESKTOP
    // }
    DEFINE_NATIVE_VALUE_TO_INDEX(BundleManager, DisplayOrientation, 0)
    DEFINE_INDEX_TO_NATIVE_VALUE(BundleManager, DisplayOrientation, 0)

    // bundleManager.LaunchType
    // enum LaunchType {
    //     SINGLETON = 0,
    //     MULTITON = 1,
    //     SPECIFIED = 2
    // }
    DEFINE_NATIVE_VALUE_TO_INDEX(BundleManager, LaunchType, 0)
    DEFINE_INDEX_TO_NATIVE_VALUE(BundleManager, LaunchType, 0)

    // bundleManager.SupportWindowMode
    // SupportWindowMode {
    //     FULL_SCREEN = 0,
    //     SPLIT = 1,
    //     FLOATING = 2
    // }
    DEFINE_NATIVE_VALUE_TO_INDEX(BundleManager, SupportWindowMode, 0)
    DEFINE_INDEX_TO_NATIVE_VALUE(BundleManager, SupportWindowMode, 0)

    // bundleManager.ExtensionAbilityType
    DEFINE_NATIVE_VALUE_TO_INDEX_LOOKUP(BundleManager, ExtensionAbilityType)
    DEFINE_INDEX_TO_NATIVE_VALUE_LOOKUP(BundleManager, ExtensionAbilityType)

    // bundleManager.ModuleType
    // enum ModuleType {
    //     ENTRY = 1,
    //     FEATURE = 2,
    //     SHARED = 3
    // }
    DEFINE_NATIVE_VALUE_TO_INDEX(BundleManager, ModuleType, -1)
    DEFINE_INDEX_TO_NATIVE_VALUE(BundleManager, ModuleType, 1)

    // bundleManager.PermissionGrantState
    // enum PermissionGrantState {
    //     PERMISSION_DENIED = -1,
    //     PERMISSION_GRANTED = 0
    // }
    DEFINE_NATIVE_VALUE_TO_INDEX(BundleManager, PermissionGrantState, 1)
    DEFINE_INDEX_TO_NATIVE_VALUE(BundleManager, PermissionGrantState, -1)

    // bundle.DisplayOrientation
    // enum DisplayOrientation {
    //     UNSPECIFIED,
    //     LANDSCAPE,
    //     PORTRAIT,
    //     FOLLOW_RECENT
    // }
    DEFINE_NATIVE_VALUE_TO_INDEX(Bundle, DisplayOrientation, 0)
    DEFINE_INDEX_TO_NATIVE_VALUE(Bundle, DisplayOrientation, 0)

    // bundle.AbilityType
    // enum AbilityType {
    //     UNKNOWN,
    //     PAGE,
    //     SERVICE,
    //     DATA
    // }
    DEFINE_NATIVE_VALUE_TO_INDEX(Bundle, AbilityType, 0)
    DEFINE_INDEX_TO_NATIVE_VALUE(Bundle, AbilityType, 0)

    // bundle.AbilitySubType
    // enum AbilitySubType {
    //     UNSPECIFIED = 0,
    //     CA = 1
    // }
    DEFINE_NATIVE_VALUE_TO_INDEX(Bundle, AbilitySubType, 0)
    DEFINE_INDEX_TO_NATIVE_VALUE(Bundle, AbilitySubType, 0)

    // bundle.LaunchMode
    // enum LaunchMode {
    //     SINGLETON = 0,
    //     STANDARD = 1
    // }
    DEFINE_NATIVE_VALUE_TO_INDEX(Bundle, LaunchMode, 0)
    DEFINE_INDEX_TO_NATIVE_VALUE(Bundle, LaunchMode, 0)

private:
    // bundleManager.BundleFlag
    // enum BundleFlag {
    //     GET_BUNDLE_INFO_DEFAULT = 0x00000000,
    //     GET_BUNDLE_INFO_WITH_APPLICATION = 0x00000001,
    //     GET_BUNDLE_INFO_WITH_HAP_MODULE = 0x00000002,
    //     GET_BUNDLE_INFO_WITH_ABILITY = 0x00000004,
    //     GET_BUNDLE_INFO_WITH_EXTENSION_ABILITY = 0x00000008,
    //     GET_BUNDLE_INFO_WITH_REQUESTED_PERMISSION = 0x00000010,
    //     GET_BUNDLE_INFO_WITH_METADATA = 0x00000020,
    //     GET_BUNDLE_INFO_WITH_DISABLE = 0x00000040,
    //     GET_BUNDLE_INFO_WITH_SIGNATURE_INFO = 0x00000080,
    //     GET_BUNDLE_INFO_WITH_MENU = 0x00000100,
    //     GET_BUNDLE_INFO_WITH_ROUTER_MAP = 0x00000200,
    //     GET_BUNDLE_INFO_WITH_SKILL = 0x00000800,
    //     GET_BUNDLE_INFO_ONLY_WITH_LAUNCHER_ABILITY = 0x00001000,
    //     GET_BUNDLE_INFO_OF_ANY_USER = 0x00002000,
    //     GET_BUNDLE_INFO_EXCLUDE_CLONE = 0x00004000,
    // }
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
    // bundleManager.ExtensionAbilityType
    // enum ExtensionAbilityType {
    //     FORM = 0,
    //     WORK_SCHEDULER = 1,
    //     INPUT_METHOD = 2,
    //     SERVICE = 3,
    //     ACCESSIBILITY = 4,
    //     DATA_SHARE = 5,
    //     FILE_SHARE = 6,
    //     STATIC_SUBSCRIBER = 7,
    //     WALLPAPER = 8,
    //     BACKUP = 9,
    //     WINDOW = 10,
    //     ENTERPRISE_ADMIN = 11,
    //     THUMBNAIL = 13,
    //     PREVIEW = 14,
    //     PRINT = 15,
    //     SHARE = 16,
    //     PUSH = 17,
    //     DRIVER = 18,
    //     ACTION = 19,
    //     ADS_SERVICE = 20,
    //     EMBEDDED_UI = 21,
    //     INSIGHT_INTENT_UI = 22,
    //     UNSPECIFIED = 255
    // }
    static constexpr std::array<int, 23> Array_BundleManager_ExtensionAbilityType = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
        10, 11, 13, 14, 15, 16, 17, 18, 19, 20,
        21, 22, 255,
    };
};
} // namespace AppExecFwk
} // namespace OHOS
#endif
