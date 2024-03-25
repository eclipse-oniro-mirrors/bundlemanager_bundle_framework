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

#ifndef FOUNDATION_BUNDLEMANAGER_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_BUNDLE_RESOURCE_CONSTANTS_H
#define FOUNDATION_BUNDLEMANAGER_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_BUNDLE_RESOURCE_CONSTANTS_H

#include <shared_mutex>
#include <string>

namespace OHOS {
namespace AppExecFwk {
namespace BundleResourceConstants {
// resource rdb path
constexpr const char* BUNDLE_RESOURCE_RDB_PATH = "/data/service/el1/public/bms/bundle_resources";
// resource rdb storage path
constexpr const char* BUNDLE_RESOURCE_RDB_STORAGE_PATH = "/data/storage/bundle_resources";
// resource database name
constexpr const char* BUNDLE_RESOURCE_RDB_NAME = "/bundleResource.db";
// resource table name
constexpr const char* BUNDLE_RESOURCE_RDB_TABLE_NAME = "bundleResource";
constexpr const char* SEPARATOR = "/";
// bundle resource rdb table key
constexpr const char* NAME = "NAME";
constexpr const char* UPDATE_TIME = "UPDATE_TIME";
constexpr const char* LABEL = "LABEL";
constexpr const char* ICON = "ICON";
constexpr const char* SYSTEM_STATE = "SYSTEM_STATE";
constexpr const char* FOREGROUND = "FOREGROUND";
constexpr const char* BACKGROUND = "BACKGROUND";

constexpr int32_t INDEX_NAME = 0;
constexpr int32_t INDEX_UPDATE_TIME = 1;
constexpr int32_t INDEX_LABEL = 2;
constexpr int32_t INDEX_ICON = 3;
constexpr int32_t INDEX_SYSTEM_STATE = 4;
constexpr int32_t INDEX_FOREGROUND = 5;
constexpr int32_t INDEX_BACKGROUND = 6;
}
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_INTERFACES_INNERKITS_APPEXECFWK_BASE_INCLUDE_BUNDLE_RESOURCE_CONSTANTS_H
