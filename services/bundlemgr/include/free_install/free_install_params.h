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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_FREE_INSTALL_FREE_INSTALL_PARAMS_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_FREE_INSTALL_FREE_INSTALL_PARAMS_H

#include <string>

#include "iremote_object.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
    const std::u16string ATOMIC_SERVICE_STATUS_CALLBACK_TOKEN = u"ohos.IAtomicServiceStatusCallback";
    const std::u16string SERVICE_CENTER_TOKEN = u"abilitydispatcherhm.openapi.hapinstall.IHapInstall";
    const std::u16string SEEVICE_CENTER_CALLBACK_TOKEN = u"abilitydispatcherhm.openapi.hapinstall.IHapInstallCallback";
    constexpr uint32_t FREE_INSTALL_DONE = 0;
};

enum UpgradeFlag {
    NOT_UPGRADE = 0,
    SINGLE_UPGRADE = 1,
    RELATION_UPGRADE = 2,
};

enum FreeInstallErrorCode {
    CONNECT_ERROR = 0x820101,
    SERVICE_CENTER_CRASH = 0x820102,
    SERVICE_CENTER_TIMEOUT = 0x820103,
    UNDEFINED_ERROR = 0x820104,
};

enum ServiceCenterFunction {
    CONNECT_DISPATCHER_INFO = 1,
    CONNECT_SILENT_INSTALL = 2,
    CONNECT_UPGRADE_CHECK = 3,
    CONNECT_UPGRADE_INSTALL = 4,
    CONNECT_QUERY_RPCID = 5,
    CONNECT_PRELOAD_INSTALL = 6,
};

enum ServiceCenterResultCode {
    FREE_INSTALL_OK = 0,
    FREE_INSTALL_DOWNLOADING = 1,
};

enum ServiceCenterConnectState {
    CONNECTED = 0,
    CONNECTING = 1,
    DISCONNECTED = 2,
};

struct FreeInstallParams : public virtual RefBase {
    sptr<IRemoteObject> callback;
    OHOS::AAFwk::Want want;
    int32_t userId;
    ServiceCenterFunction serviceCenterFunction;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_FREE_INSTALL_FREE_INSTALL_PARAMS_H
