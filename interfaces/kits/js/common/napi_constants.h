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
constexpr const char* FLAGS = "flags";
constexpr const char* BUNDLE_FLAGS = "bundleFlags";
constexpr const char* ABILITY_FLAGS = "abilityFlags";
constexpr const char* APPLICATION_FLAGS = "applicationFlags";
constexpr const char* ABILITY_INFO = "abilityInfo";
constexpr const char* LINK_FEATURE = "linkFeature";
constexpr const char* EXTENSION_TYPE_NAME = "extensionTypeName";
constexpr const char* EXTENSION_ABILITY_TYPE = "extensionAbilityType";
constexpr const char* ERR_MSG_BUNDLE_SERVICE_EXCEPTION = "Bundle manager service is excepted.";
constexpr const char*  PARAM_EXTENSION_ABILITY_TYPE_EMPTY_ERROR =
    "BusinessError 401: Parameter error.Parameter extensionAbilityType is empty.";
constexpr const char* BUNDLE_PERMISSIONS =
    "ohos.permission.GET_BUNDLE_INFO or ohos.permission.GET_BUNDLE_INFO_PRIVILEGED";
constexpr const char* INVALID_WANT_ERROR =
    "implicit query condition, at least one query param(action, entities, uri, type, or linkFeature) non-empty.";
constexpr const char* PARAM_TYPE_CHECK_ERROR = "param type check error";
constexpr const char* APP_CLONE_IDENTITY_PERMISSIONS = "ohos.permission.GET_BUNDLE_INFO_PRIVILEGED";
constexpr const char* IS_APPLICATION_ENABLED_SYNC = "IsApplicationEnabledSync";
constexpr const char* GET_BUNDLE_INFO_FOR_SELF_SYNC = "GetBundleInfoForSelfSync";
constexpr const char* GET_BUNDLE_INFO_SYNC = "GetBundleInfoSync";
constexpr const char* GET_APPLICATION_INFO_SYNC = "GetApplicationInfoSync";
constexpr const char* GET_BUNDLE_INFO = "GetBundleInfo";
constexpr const char* GET_BUNDLE_INFOS = "GetBundleInfos";
constexpr const char* GET_APPLICATION_INFOS = "GetApplicationInfos";
constexpr const char* IS_APPLICATION_ENABLED = "IsApplicationEnabled";
constexpr const char* QUERY_ABILITY_INFOS_SYNC = "QueryAbilityInfosSync";
constexpr const char* GET_APPLICATION_INFO = "GetApplicationInfo";
constexpr const char* GET_APP_CLONE_IDENTITY = "getAppCloneIdentity";
constexpr const char* GET_ABILITY_LABEL = "GetAbilityLabel";
constexpr const char* QUERY_EXTENSION_INFOS_SYNC = "QueryExtensionInfosSync";
constexpr const char* GET_LAUNCH_WANT_FOR_BUNDLE_SYNC = "GetLaunchWantForBundleSync";
constexpr const char* IS_ABILITY_ENABLED_SYNC = "IsAbilityEnabledSync";
constexpr const char* SET_ABILITY_ENABLED_SYNC = "SetAbilityEnabledSync";
constexpr const char* SET_APPLICATION_ENABLED_SYNC = "SetApplicationEnabledSync";
constexpr const char* GET_APP_CLONE_BUNDLE_INFO = "GetAppCloneBundleInfo";
constexpr const char* GET_DYNAMIC_ICON = "GetDynamicIcon";
constexpr const char* RESOURCE_NAME_OF_GET_SPECIFIED_DISTRIBUTION_TYPE = "GetSpecifiedDistributionType";
constexpr const char* BATCH_QUERY_ABILITY_INFOS = "BatchQueryAbilityInfos";
constexpr const char* GET_BUNDLE_NAME_BY_UID = "GetBundleNameByUid";
}
}
}
#endif