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

#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLEMGR_LOCAL_PLUGIN_INSTALLER_PROXY_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLEMGR_LOCAL_PLUGIN_INSTALLER_PROXY_H

#include <string>
#include <vector>

#include "iremote_proxy.h"

#include "bundle_framework_core_ipc_interface_code.h"
#include "local_plugin_installer_interface.h"

namespace OHOS {
namespace AppExecFwk {
class LocalPluginInstallerProxy : public IRemoteProxy<ILocalPluginInstaller> {
public:
    explicit LocalPluginInstallerProxy(const sptr<IRemoteObject> &object);
    ~LocalPluginInstallerProxy() override;

    ErrCode Install(const std::vector<std::string> &pluginFilePaths,
        const sptr<IStatusReceiver> &statusReceiver) override;

    ErrCode Uninstall(const std::string &pluginBundleName,
        const sptr<IStatusReceiver> &statusReceiver) override;

    ErrCode Uninstall(const std::string &bundleName, const std::string &pluginBundleName,
        int32_t userId) override;

    sptr<ILocalPluginStreamInstaller> CreateLocalPluginStreamInstaller(
        const sptr<IStatusReceiver> &statusReceiver) override;

    bool DestroyLocalPluginStreamInstaller(uint32_t installerId) override;

private:
    ErrCode SendRequest(LocalPluginInstallerInterfaceCode code, MessageParcel &data, MessageParcel &reply);

    ErrCode WriteFileToLocalPluginStream(const sptr<ILocalPluginStreamInstaller> &pluginStreamInstaller,
        const std::string &path);

    static inline BrokerDelegator<LocalPluginInstallerProxy> delegator_;
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif  // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLEMGR_LOCAL_PLUGIN_INSTALLER_PROXY_H