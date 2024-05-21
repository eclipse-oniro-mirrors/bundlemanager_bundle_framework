/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_SERVICE_CONSTANTS_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_SERVICE_CONSTANTS_H

#include <map>
#include <string>
#include <vector>

namespace OHOS {
namespace AppExecFwk {
namespace ServiceConstants {
constexpr const char* ASSETS_DIR = "assets";
constexpr const char* RESOURCES_INDEX = "resources.index";
constexpr int32_t INVALID_GID = -1;
const int32_t BUNDLE_RDB_VERSION = 1;
const std::string PATH_SEPARATOR = "/";
const std::string LIBS = "libs/";
const std::string AN = "an/";
const std::string RES_FILE_PATH = "resources/resfile/";
const std::string HNPS_FILE_PATH = "hnp_tmp_extract_dir/";
const std::string HNPS = "hnp/";
constexpr const char* DIR_EL1 = "el1";
constexpr const char* DIR_EL2 = "el2";
constexpr const char* DIR_EL3 = "el3";
constexpr const char* DIR_EL4 = "el4";
const std::vector<std::string> BUNDLE_EL = {DIR_EL1, DIR_EL2, DIR_EL3, DIR_EL4};
constexpr const char* ARM_EABI = "armeabi";
constexpr const char* ARM_EABI_V7A = "armeabi-v7a";
constexpr const char* ARM64_V8A = "arm64-v8a";
constexpr const char* ARM64 = "arm64";
constexpr const char* X86 = "x86";
constexpr const char* X86_64 = "x86_64";
const std::map<std::string, std::string> ABI_MAP = {
    {ARM_EABI, "arm"},
    {ARM_EABI_V7A, "arm"},
    {ARM64_V8A, "arm64"},
    {X86, "x86"},
    {X86_64, "x86_64"},
};
constexpr const char* INSTALL_FILE_SUFFIX = ".hap";
constexpr const char* HSP_FILE_SUFFIX = ".hsp";
constexpr const char* QUICK_FIX_FILE_SUFFIX = ".hqf";
const char FILE_SEPARATOR_CHAR = '/';
constexpr const char* CURRENT_DEVICE_ID = "PHONE-001";
constexpr const char* HAP_COPY_PATH = "/data/service/el1/public/bms/bundle_manager_service";
constexpr const char* TMP_SUFFIX = "_tmp";
constexpr const char* BUNDLE_APP_DATA_BASE_DIR = "/data/app/";
constexpr const char* BASE = "/base/";
constexpr const char* DATABASE = "/database/";
constexpr const char* LOG = "/log/";
constexpr const char* HAPS = "/haps/";
constexpr const char* BUNDLE_MANAGER_SERVICE_PATH = "/data/service/el1/public/bms/bundle_manager_service";
constexpr const char* SANDBOX_DATA_PATH = "/data/storage/el2/base";
constexpr const char* REAL_DATA_PATH = "/data/app/el2";
constexpr const char* DATA_GROUP_PATH = "/group/";
constexpr const char* STREAM_INSTALL_PATH = "stream_install";
constexpr const char* SECURITY_STREAM_INSTALL_PATH = "security_stream_install";
constexpr const char* QUICK_FIX_PATH = "quick_fix";
constexpr const char* SECURITY_QUICK_FIX_PATH = "security_quick_fix";
constexpr const char* BUNDLE_ASAN_LOG_DIR = "/data/local/app-logs";
}  // namespace ServiceConstants
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_SERVICE_CONSTANTS_H