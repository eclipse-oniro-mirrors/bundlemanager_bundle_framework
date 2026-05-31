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

#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_LOCAL_PLUGIN_STREAM_INSTALLER_PROXY_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_LOCAL_PLUGIN_STREAM_INSTALLER_PROXY_H

#include <string>

#include "iremote_proxy.h"

#include "bundle_framework_core_ipc_interface_code.h"
#include "local_plugin_stream_installer_interface.h"

namespace OHOS {
namespace AppExecFwk {
class LocalPluginStreamInstallerProxy : public IRemoteProxy<ILocalPluginStreamInstaller> {
public:
    explicit LocalPluginStreamInstallerProxy(const sptr<IRemoteObject> &object);
    ~LocalPluginStreamInstallerProxy() override;

    int32_t CreatePluginFileStream(const std::string &fileName) override;
    bool CommitLocalPluginInstall() override;
    uint32_t GetLocalPluginInstallerId() const override;
    void SetLocalPluginInstallerId(uint32_t installerId) override;

private:
    bool SendRequest(LocalPluginStreamInstallerInterfaceCode code, MessageParcel &data, MessageParcel &reply);

    uint32_t installerId_ = Constants::DEFAULT_INSTALLERID;
    static inline BrokerDelegator<LocalPluginStreamInstallerProxy> delegator_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_LOCAL_PLUGIN_STREAM_INSTALLER_PROXY_H