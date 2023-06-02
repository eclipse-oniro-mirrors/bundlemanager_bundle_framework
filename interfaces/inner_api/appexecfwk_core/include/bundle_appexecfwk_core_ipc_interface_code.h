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

#ifndef OHOS_BUNDLE_APPEXECFWK_CORE_IPC_INTERFACE_CODE_H
#define OHOS_BUNDLE_APPEXECFWK_CORE_IPC_INTERFACE_CODE_H

/* SAID: 401 */
namespace OHOS {
namespace AppExecFwk {
enum class AppControlManagerInterfaceCode : uint32_t {
    ADD_APP_INSTALL_CONTROL_RULE = 0,
    DELETE_APP_INSTALL_CONTROL_RULE,
    CLEAN_APP_INSTALL_CONTROL_RULE,
    GET_APP_INSTALL_CONTROL_RULE,
    ADD_APP_RUNNING_CONTROL_RULE,
    DELETE_APP_RUNNING_CONTROL_RULE,
    CLEAN_APP_RUNNING_CONTROL_RULE,
    GET_APP_RUNNING_CONTROL_RULE,
    GET_APP_RUNNING_CONTROL_RULE_RESULT,
    SET_DISPOSED_STATUS,
    DELETE_DISPOSED_STATUS,
    GET_DISPOSED_STATUS,
    CONFIRM_APP_JUMP_CONTROL_RULE,
    ADD_APP_JUMP_CONTROL_RULE,
    DELETE_APP_JUMP_CONTROL_RULE,
    DELETE_APP_JUMP_CONTROL_RULE_BY_CALLER,
    DELETE_APP_JUMP_CONTROL_RULE_BY_TARGET,
    GET_APP_JUMP_CONTROL_RULE,
};

enum class BundleEventCallbackInterfaceCode : uint32_t {
    ON_RECEIVE_EVENT,
};

enum class BundleInstallerInterfaceCode : uint32_t {
    INSTALL = 0,
    INSTALL_MULTIPLE_HAPS,
    UNINSTALL,
    UNINSTALL_MODULE,
    UNINSTALL_BY_UNINSTALL_PARAM,
    RECOVER,
    INSTALL_SANDBOX_APP,
    UNINSTALL_SANDBOX_APP,
    CREATE_STREAM_INSTALLER,
    DESTORY_STREAM_INSTALLER,
};

enum class BundleStatusCallbackInterfaceCode : uint32_t {
    ON_BUNDLE_STATE_CHANGED,
};

enum class BundleStreamInstallerInterfaceCode : uint32_t {
    CREATE_STREAM = 0,
    STREAM_INSTALL = 1,
    CREATE_SHARED_BUNDLE_STREAM = 2,
};

enum class CleanCacheCallbackInterfaceCode : uint32_t {
    ON_CLEAN_CACHE_CALLBACK,
};

enum class StatusReceiverInterfaceCode : uint32_t {
    ON_STATUS_NOTIFY,
    ON_FINISHED,
};

enum class DefaultAppInterfaceCode : uint32_t {
    IS_DEFAULT_APPLICATION = 0,
    GET_DEFAULT_APPLICATION = 1,
    SET_DEFAULT_APPLICATION = 2,
    RESET_DEFAULT_APPLICATION = 3,
};

enum class OverlayManagerInterfaceCode : uint32_t {
    GET_ALL_OVERLAY_MODULE_INFO = 0,
    GET_OVERLAY_MODULE_INFO_BY_NAME = 1,
    GET_OVERLAY_MODULE_INFO = 2,
    GET_TARGET_OVERLAY_MODULE_INFOS = 3,
    GET_OVERLAY_MODULE_INFO_BY_BUNDLE_NAME = 4,
    GET_OVERLAY_BUNDLE_INFO_FOR_TARGET = 5,
    GET_OVERLAY_MODULE_INFO_FOR_TARGET = 6,
    SET_OVERLAY_ENABLED = 7,
    SET_OVERLAY_ENABLED_FOR_SELF = 8,
};

enum class QuickFixManagerInterfaceCode : uint32_t {
    DEPLOY_QUICK_FIX = 0,
    SWITCH_QUICK_FIX = 1,
    DELETE_QUICK_FIX = 2,
    CREATE_FD = 3
};

enum class QuickFixStatusCallbackInterfaceCode : uint32_t {
    ON_PATCH_DEPLOYED = 1,
    ON_PATCH_SWITCHED = 2,
    ON_PATCH_DELETED = 3
};

} // namespace AppExecFwk
} // namespace OHOS
#endif // OHOS_BUNDLE_APPEXECFWK_CORE_IPC_INTERFACE_CODE_H