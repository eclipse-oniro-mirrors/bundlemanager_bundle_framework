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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_LOCAL_PLUGIN_STREAM_INSTALLER_HOST_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_LOCAL_PLUGIN_STREAM_INSTALLER_HOST_H

#include <functional>
#include <map>

#include "iremote_stub.h"
#include "nocopyable.h"

#include "local_plugin_stream_installer_interface.h"

namespace OHOS {
namespace AppExecFwk {
class LocalPluginStreamInstallerHost : public IRemoteStub<ILocalPluginStreamInstaller> {
public:
    LocalPluginStreamInstallerHost();
    ~LocalPluginStreamInstallerHost() override = default;

    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    DISALLOW_COPY_AND_MOVE(LocalPluginStreamInstallerHost);

    void Init();
    ErrCode HandleCreatePluginFileStream(MessageParcel &data, MessageParcel &reply);
    ErrCode HandleCommitLocalPluginInstall(MessageParcel &data, MessageParcel &reply);

    std::map<uint32_t, std::function<ErrCode(MessageParcel &data, MessageParcel &reply)>> funcMap_;
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_LOCAL_PLUGIN_STREAM_INSTALLER_HOST_H