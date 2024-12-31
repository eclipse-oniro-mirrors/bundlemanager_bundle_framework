/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_BUNDLE_MANAGER_SERVICE_IPC_INTERFACE_CODE_H
#define OHOS_BUNDLE_MANAGER_SERVICE_IPC_INTERFACE_CODE_H

#include <stdint.h>

/* SAID: 401 */
namespace OHOS {
namespace AppExecFwk {
enum class BundleManagerCallbackInterfaceCode : uint32_t {
        QUERY_RPC_ID_CALLBACK = 0,
};

enum class InstalldInterfaceCode : uint32_t {
    CREATE_BUNDLE_DIR = 1,
    EXTRACT_MODULE_FILES = 2,
    RENAME_MODULE_DIR = 3,
    CREATE_BUNDLE_DATA_DIR = 4,
    CLEAN_BUNDLE_DATA_DIR = 5,
    REMOVE_BUNDLE_DATA_DIR = 6,
    REMOVE_MODULE_DATA_DIR = 7,
    REMOVE_DIR = 8,
    GET_BUNDLE_STATS = 9,
    SET_DIR_APL = 10,
    GET_BUNDLE_CACHE_PATH = 11,
    SCAN_DIR = 12,
    MOVE_FILE = 13,
    COPY_FILE = 14,
    MKDIR = 15,
    GET_FILE_STAT = 16,
    EXTRACT_DIFF_FILES = 17,
    APPLY_DIFF_PATCH = 18,
    IS_EXIST_DIR = 19,
    IS_DIR_EMPTY = 20,
    OBTAIN_QUICK_FIX_DIR = 21,
    COPY_FILES = 22,
    EXTRACT_FILES = 23,
    GET_NATIVE_LIBRARY_FILE_NAMES = 24,
    EXECUTE_AOT = 25,
    IS_EXIST_FILE = 26,
    IS_EXIST_AP_FILE = 27,
    VERIFY_CODE_SIGNATURE = 28,
    MOVE_FILES = 29,
    EXTRACT_DRIVER_SO_FILE = 30,
    CHECK_ENCRYPTION = 31,
    EXTRACT_CODED_SO_FILE = 32,
    VERIFY_CODE_SIGNATURE_FOR_HAP = 33,
    DELIVERY_SIGN_PROFILE = 34,
    REMOVE_SIGN_PROFILE = 35,
    CLEAN_BUNDLE_DATA_DIR_BY_NAME = 36,
    CREATE_BUNDLE_DATA_DIR_WITH_VECTOR = 37,
    GET_ALL_BUNDLE_STATS = 38,
    STOP_AOT = 39,
    SET_ENCRYPTION_DIR = 40,
    DELETE_ENCRYPTION_KEY_ID = 41,
    EXTRACT_HNP_FILES = 42,
    INSTALL_NATIVE = 43,
    UNINSTALL_NATIVE = 44,
    GET_DISK_USAGE = 45,
    PEND_SIGN_AOT = 46,
    REMOVE_EXTENSION_DIR = 47,
    IS_EXIST_EXTENSION_DIR = 48,
    CREATE_EXTENSION_DATA_DIR = 49,
    GET_EXTENSION_SANDBOX_TYPE_LIST = 50,
    ADD_USER_DIR_DELETE_DFX = 51,
    MOVE_HAP_TO_CODE_DIR = 52,
    DELETE_UNINSTALL_TMP_DIRS = 53,
};

} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_BUNDLE_MANAGER_SERVICE_IPC_INTERFACE_CODE_H