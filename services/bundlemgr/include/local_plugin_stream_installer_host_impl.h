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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_LOCAL_PLUGIN_STREAM_INSTALLER_HOST_IMPL_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_LOCAL_PLUGIN_STREAM_INSTALLER_HOST_IMPL_H

#include <mutex>
#include <vector>

#include "local_plugin_stream_installer_host.h"
#include "plugin/install_plugin_param.h"
#include "status_receiver_interface.h"

namespace OHOS {
namespace AppExecFwk {
class LocalPluginStreamInstallerHostImpl : public LocalPluginStreamInstallerHost {
public:
    LocalPluginStreamInstallerHostImpl(uint32_t installerId, int32_t installedUid);
    ~LocalPluginStreamInstallerHostImpl() override;

    bool Init(const InstallPluginParam &installPluginParam, const sptr<IStatusReceiver> &statusReceiver,
        const std::string &hostBundleName);
    void UnInit() override;

    int32_t CreatePluginFileStream(const std::string &fileName) override;
    bool CommitLocalPluginInstall() override;
    uint32_t GetLocalPluginInstallerId() const override;
    void SetLocalPluginInstallerId(uint32_t installerId) override;

private:
    uint32_t installerId_ = Constants::DEFAULT_INSTALLERID;
    int32_t installedUid_ = 0;
    std::string tempDir_;
    std::string hostBundleName_;
    sptr<IStatusReceiver> receiver_ = nullptr;
    mutable std::mutex mutex_;
    std::vector<int32_t> streamFdVec_;
    InstallPluginParam installPluginParam_;
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_LOCAL_PLUGIN_STREAM_INSTALLER_HOST_IMPL_H