/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLE_STREAM_INSTALLER_PROXY_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLE_STREAM_INSTALLER_PROXY_H

#include "bundle_framework_core_ipc_interface_code.h"
#include "bundle_stream_installer_interface.h"
#include "ipc_types.h"
#include "iremote_proxy.h"
#include "parcel.h"

namespace OHOS {
namespace AppExecFwk {
class BundleStreamInstallerProxy : public IRemoteProxy<IBundleStreamInstaller> {
public:
    explicit BundleStreamInstallerProxy(const sptr<IRemoteObject> &impl);
    virtual ~BundleStreamInstallerProxy() override;

    virtual int32_t CreateStream(const std::string &fileName) override;
    virtual int32_t CreateSignatureFileStream(const std::string &moduleName, const std::string &fileName) override;
    virtual int32_t CreateSharedBundleStream(const std::string &hspName, uint32_t sharedBundleIdx) override;
    virtual int32_t CreatePgoFileStream(const std::string &moduleName, const std::string &fileName) override;
    virtual int32_t CreateExtProfileFileStream(const std::string &fileName) override;
    virtual bool Install() override;
    virtual uint32_t GetInstallerId() const override;
    virtual void SetInstallerId(uint32_t installerId) override;
    virtual void UnInit() override {};

private:
    uint32_t installerId_ = -1;
    static inline BrokerDelegator<BundleStreamInstallerProxy> delegator_;
    bool SendStreamInstallRequest(BundleStreamInstallerInterfaceCode code, MessageParcel& data, MessageParcel& reply);
};
} // AppExecFwk
} // OHOS

#endif // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLE_STREAM_INSTALLER_PROXY_H