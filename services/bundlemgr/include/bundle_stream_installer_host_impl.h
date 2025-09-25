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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_STREAM_INSTALLER_HOST_IMPL_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_STREAM_INSTALLER_HOST_IMPL_H

#include <mutex>
#include <vector>

#include "bundle_stream_installer_host.h"
#include "install_param.h"
#include "status_receiver_interface.h"

namespace OHOS {
namespace AppExecFwk {
class BundleStreamInstallerHostImpl : public BundleStreamInstallerHost {
public:
    BundleStreamInstallerHostImpl(uint32_t installerId, int32_t installedUid);
    virtual ~BundleStreamInstallerHostImpl() override;

    bool Init(const InstallParam &installParam, const sptr<IStatusReceiver> &statusReceiver,
        const std::vector<std::string> &originHapPaths);
    virtual void UnInit() override;

    virtual int32_t CreateStream(const std::string &fileName) override;
    virtual int32_t CreateSignatureFileStream(const std::string &moduleName, const std::string &fileName) override;
    virtual int32_t CreateSharedBundleStream(const std::string &bundleName, uint32_t sharedBundleIdx) override;
    virtual int32_t CreatePgoFileStream(const std::string &moduleName, const std::string &fileName) override;
    virtual int32_t CreateExtProfileFileStream(const std::string &fileName) override;
    virtual bool Install() override;

    virtual uint32_t GetInstallerId() const override;
    virtual void SetInstallerId(uint32_t installerId) override;
    bool InstallApp(const std::vector<std::string> &pathVec);

private:
    bool isInstallSharedBundlesOnly_ = true;
    uint32_t installerId_ = -1;
    int32_t installedUid_;
    std::string tempDir_;
    std::string tempSignatureFileDir_;
    std::string tempPgoFileDir_;
    sptr<IStatusReceiver> receiver_ = nullptr;
    std::mutex fdVecMutex_;
    std::vector<int32_t> streamFdVec_;
    std::vector<std::string> originHapPaths_;
    InstallParam installParam_;
    std::string tempExtProfileDir_;
};
} // AppExecFwk
} // OHOS


#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_STREAM_INSTALLER_HOST_IMPL_H