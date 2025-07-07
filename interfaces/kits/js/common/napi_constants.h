/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#ifndef NAPI_CONSTANTS_H
#define NAPI_CONSTANTS_H

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr size_t ARGS_SIZE_ZERO = 0;
constexpr size_t ARGS_SIZE_ONE = 1;
constexpr size_t ARGS_SIZE_TWO = 2;
constexpr size_t ARGS_SIZE_THREE = 3;
constexpr size_t ARGS_SIZE_FOUR = 4;
constexpr size_t ARGS_SIZE_FIVE = 5;

constexpr size_t ARGS_POS_ZERO = 0;
constexpr size_t ARGS_POS_ONE = 1;
constexpr size_t ARGS_POS_TWO = 2;
constexpr size_t ARGS_POS_THREE = 3;
constexpr size_t ARGS_POS_FOUR = 4;

constexpr size_t NAPI_RETURN_ONE = 1;
constexpr size_t CALLBACK_PARAM_SIZE = 2;

constexpr const char* TYPE_NUMBER = "number";
constexpr const char* TYPE_STRING = "string";
constexpr const char* TYPE_OBJECT = "object";
constexpr const char* TYPE_BOOLEAN = "boolean";
constexpr const char* TYPE_FUNCTION = "function";
constexpr const char* TYPE_ARRAY = "array";

constexpr const char* UID = "uid";
constexpr const char* USER_ID = "userId";
constexpr const char* BUNDLE_NAME = "bundleName";
constexpr const char* MODULE_NAME = "moduleName";
constexpr const char* ABILITY_NAME = "abilityName";
constexpr const char* APP_INDEX = "appIndex";
constexpr const char* PARAM_TYPE_CHECK_ERROR = "param type check error";

constexpr const char* BUNDLE_FLAGS = "bundleFlags";
constexpr const char* APP_FLAGS = "appFlags";
constexpr const char* ERR_MSG_BUNDLE_SERVICE_EXCEPTION = "Bundle manager service is excepted.";
constexpr const char* IS_APPLICATION_ENABLED_SYNC = "IsApplicationEnabledSync";
constexpr const char* GET_BUNDLE_INFO_FOR_SELF_SYNC = "GetBundleInfoForSelfSync";
constexpr const char* GET_BUNDLE_INFO_SYNC = "GetBundleInfoSync";
constexpr const char* GET_APPLICATION_INFO_SYNC = "GetApplicationInfoSync";
constexpr const char* BUNDLE_PERMISSIONS =
    "ohos.permission.GET_BUNDLE_INFO or ohos.permission.GET_BUNDLE_INFO_PRIVILEGED";
constexpr const char* GET_BUNDLE_INFO = "GetBundleInfo";
constexpr const char* GET_APPLICATION_INFO = "GetApplicationInfo";

constexpr const char* GET_SHORTCUT_INFO = "GetShortcutInfo";
constexpr const char* GET_SHORTCUT_INFO_SYNC = "GetShortcutInfoSync";
constexpr const char* GET_SHORTCUT_INFO_BY_APPINDEX = "GetShortcutInfoByAppIndex";
constexpr const char* ERROR_EMPTY_WANT = "want in ShortcutInfo cannot be empty";
constexpr const char* PARSE_START_OPTIONS = "parse StartOptions failed";
constexpr const char* START_SHORTCUT = "StartShortcut";

constexpr const char* PERMISSION_GET_BUNDLE_RESOURCES = "ohos.permission.GET_BUNDLE_RESOURCES";
constexpr const char* GET_BUNDLE_RESOURCE_INFO = "GetBundleResourceInfo";
constexpr const char* RESOURCE_FLAGS = "resourceFlags";

constexpr const char* ADD_DESKTOP_SHORTCUT_INFO = "AddDesktopShortcutInfo";
constexpr const char* DELETE_DESKTOP_SHORTCUT_INFO = "DeleteDesktopShortcutInfo";
constexpr const char* GET_ALL_DESKTOP_SHORTCUT_INFO = "GetAllDesktopShortcutInfo";
}
}
}
#endif