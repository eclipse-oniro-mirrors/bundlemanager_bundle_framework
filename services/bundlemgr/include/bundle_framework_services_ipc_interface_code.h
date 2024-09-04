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
    EXTRACT_MODULE_FILES,
    RENAME_MODULE_DIR,
    CREATE_BUNDLE_DATA_DIR,
    CLEAN_BUNDLE_DATA_DIR,
    REMOVE_BUNDLE_DATA_DIR,
    REMOVE_MODULE_DATA_DIR,
    REMOVE_DIR,
    GET_BUNDLE_STATS,
    SET_DIR_APL,
    GET_BUNDLE_CACHE_PATH,
    SCAN_DIR,
    MOVE_FILE,
    COPY_FILE,
    MKDIR,
    GET_FILE_STAT,
    EXTRACT_DIFF_FILES,
    APPLY_DIFF_PATCH,
    IS_EXIST_DIR,
    IS_DIR_EMPTY,
    OBTAIN_QUICK_FIX_DIR,
    COPY_FILES,
    EXTRACT_FILES,
    GET_NATIVE_LIBRARY_FILE_NAMES,
    EXECUTE_AOT,
    IS_EXIST_FILE,
    IS_EXIST_AP_FILE,
    VERIFY_CODE_SIGNATURE,
    MOVE_FILES,
    EXTRACT_DRIVER_SO_FILE,
    CHECK_ENCRYPTION,
    EXTRACT_CODED_SO_FILE,
    VERIFY_CODE_SIGNATURE_FOR_HAP,
    DELIVERY_SIGN_PROFILE,
    REMOVE_SIGN_PROFILE,
    CLEAN_BUNDLE_DATA_DIR_BY_NAME,
    CREATE_BUNDLE_DATA_DIR_WITH_VECTOR,
    GET_ALL_BUNDLE_STATS,
    STOP_AOT,
    SET_ENCRYPTION_DIR,
    DELETE_ENCRYPTION_KEY_ID,
    EXTRACT_HNP_FILES,
    INSTALL_NATIVE,
    UNINSTALL_NATIVE,
    GET_DISK_USAGE,
    PEND_SIGN_AOT,
    REMOVE_EXTENSION_DIR,
    IS_EXIST_EXTENSION_DIR,
    CREATE_EXTENSION_DATA_DIR,
    GET_EXTENSION_SANDBOX_TYPE_LIST,
    ADD_USER_DIR_DELETE_DFX,
    MOVE_HAP_TO_CODE_DIR,
};

} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_BUNDLE_MANAGER_SERVICE_IPC_INTERFACE_CODE_H