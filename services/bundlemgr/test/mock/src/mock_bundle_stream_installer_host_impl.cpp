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

#include "bundle_stream_installer_host_impl.h"

#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "bundle_util.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AppExecFwk {
BundleStreamInstallerHostImpl::BundleStreamInstallerHostImpl(uint32_t installerId, int32_t installedUid)
{
    APP_LOGD("create bundle stream installer host impl instance");
    installerId_ = installerId;
    installedUid_ = installedUid;
}

BundleStreamInstallerHostImpl::~BundleStreamInstallerHostImpl()
{
    APP_LOGD("destroy bundle stream installer host impl instance");
    UnInit();
}

bool BundleStreamInstallerHostImpl::Init(const InstallParam &installParam, const sptr<IStatusReceiver> &statusReceiver,
    const std::vector<std::string> &originHapPaths)
{
    return true;
}

void BundleStreamInstallerHostImpl::UnInit()
{
    APP_LOGD("destroy stream installer with installerId %{public}d and temp dir %{public}s", installerId_,
        tempDir_.c_str());
    installerId_ = 0;
}

int BundleStreamInstallerHostImpl::CreateStream(const std::string &hapName)
{
    isInstallSharedBundlesOnly_ = false;
    return -1;
}

int BundleStreamInstallerHostImpl::CreateSignatureFileStream(const std::string &moduleName, const std::string &fileName)
{
    return -1;
}

int BundleStreamInstallerHostImpl::CreateSharedBundleStream(const std::string &hspName, uint32_t index)
{
    return -1;
}

int BundleStreamInstallerHostImpl::CreatePgoFileStream(const std::string &moduleName, const std::string &fileName)
{
    return -1;
}

bool BundleStreamInstallerHostImpl::Install()
{
    return true;
}

uint32_t BundleStreamInstallerHostImpl::GetInstallerId() const
{
    return installerId_;
}

void BundleStreamInstallerHostImpl::SetInstallerId(uint32_t installerId)
{
    installerId_ = installerId;
}
} // AppExecFwk
} // OHOS