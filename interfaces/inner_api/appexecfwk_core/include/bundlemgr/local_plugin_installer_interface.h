/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_LOCAL_PLUGIN_INSTALLER_INTERFACE_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_LOCAL_PLUGIN_INSTALLER_INTERFACE_H

#include <cstdint>
#include <string>
#include <vector>

#include "appexecfwk_errors.h"
#include "iremote_broker.h"
#include "local_plugin_stream_installer_interface.h"
#include "status_receiver_interface.h"

namespace OHOS {
namespace AppExecFwk {
class ILocalPluginInstaller : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.appexecfwk.LocalPluginInstaller");

    virtual ErrCode Install(const std::vector<std::string> &pluginFilePaths,
        const sptr<IStatusReceiver> &statusReceiver) = 0;

    virtual ErrCode Uninstall(const std::string &pluginBundleName,
        const sptr<IStatusReceiver> &statusReceiver) = 0;

    virtual ErrCode Uninstall(const std::string &bundleName, const std::string &pluginBundleName,
        int32_t userId) = 0;

    virtual sptr<ILocalPluginStreamInstaller> CreateLocalPluginStreamInstaller(
        const sptr<IStatusReceiver> &statusReceiver) = 0;

    virtual bool DestroyLocalPluginStreamInstaller(uint32_t installerId) = 0;
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif  // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_LOCAL_PLUGIN_INSTALLER_INTERFACE_H