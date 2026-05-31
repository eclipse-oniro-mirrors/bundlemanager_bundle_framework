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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_LOCAL_PLUGIN_INSTALLER_HOST_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_LOCAL_PLUGIN_INSTALLER_HOST_H

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "iremote_stub.h"
#include "nocopyable.h"

#include "bundle_installer_manager.h"
#include "local_plugin_installer_interface.h"

namespace OHOS {
namespace AppExecFwk {
class LocalPluginInstallerHost : public IRemoteStub<ILocalPluginInstaller> {
public:
    LocalPluginInstallerHost();
    ~LocalPluginInstallerHost() override;

    void Init();
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

    ErrCode Install(const std::vector<std::string> &pluginFilePaths,
        const sptr<IStatusReceiver> &statusReceiver) override;
    ErrCode Uninstall(const std::string &pluginBundleName,
        const sptr<IStatusReceiver> &statusReceiver) override;
    ErrCode Uninstall(const std::string &bundleName, const std::string &pluginBundleName,
        int32_t userId) override;
    sptr<ILocalPluginStreamInstaller> CreateLocalPluginStreamInstaller(
        const sptr<IStatusReceiver> &statusReceiver) override;
    bool DestroyLocalPluginStreamInstaller(uint32_t installerId) override;

    ErrCode InstallByLocalPluginStream(const std::string &hostBundleName,
        const std::vector<std::string> &pluginFilePaths,
        const InstallPluginParam &installPluginParam, const sptr<IStatusReceiver> &statusReceiver);

private:
    ErrCode HandleUninstallMessage(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleInternalUninstallMessage(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleCreateLocalPluginStreamInstallerMessage(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleDestroyLocalPluginStreamInstallerMessage(MessageParcel &data, MessageParcel &reply);

    bool CheckInstallerManager(const sptr<IStatusReceiver> &statusReceiver) const;
    ErrCode CheckOperationCondition() const;
    ErrCode GetBundleNameAndUserId(int32_t uid, std::string &hostBundleName,
        InstallPluginParam &installPluginParam) const;

    std::shared_ptr<BundleInstallerManager> manager_;
    std::atomic<uint32_t> localPluginStreamInstallerIds_ = 0;
    std::vector<sptr<ILocalPluginStreamInstaller>> localPluginStreamInstallers_;
    std::mutex localPluginStreamInstallMutex_;

    DISALLOW_COPY_AND_MOVE(LocalPluginInstallerHost);
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif
