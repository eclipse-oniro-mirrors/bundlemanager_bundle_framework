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

#include "local_plugin_stream_installer_host_impl.h"

#include "bundle_file_util.h"
#include "bundle_hitrace_chain.h"
#include "bundle_mgr_service.h"
#include "bundle_permission_mgr.h"
#include "bundle_service_constants.h"
#include "bundle_util.h"
#include "ipc_skeleton.h"
#include "status_receiver_host.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* ILLEGAL_PATH_FIELD = "../";
constexpr const char* PATH_SEPARATOR = "/";

class LocalPluginCleanupReceiver final : public StatusReceiverHost {
public:
    LocalPluginCleanupReceiver(const sptr<IStatusReceiver> &receiver, uint32_t installerId)
        : receiver_(receiver), installerId_(installerId)
    {}

    void OnStatusNotify(const int32_t progress) override
    {
        if (receiver_ != nullptr) {
            receiver_->OnStatusNotify(progress);
        }
    }

    void OnFinished(const int32_t resultCode, const std::string &resultMsg) override
    {
        Cleanup();
        if (receiver_ != nullptr) {
            receiver_->OnFinished(resultCode, resultMsg);
        }
    }

    void OnFinished(const int32_t resultCode, const std::string &resultMsg, const int32_t innerCode) override
    {
        Cleanup();
        if (receiver_ != nullptr) {
            receiver_->OnFinished(resultCode, resultMsg, innerCode);
        }
    }

private:
    void Cleanup()
    {
        uint32_t installerId = 0;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            installerId = installerId_;
            installerId_ = 0;
        }
        if (installerId == 0) {
            return;
        }
        auto localPluginInstaller = DelayedSingleton<BundleMgrService>::GetInstance()->GetLocalPluginInstaller();
        if (localPluginInstaller == nullptr) {
            APP_LOGE("local plugin installer is nullptr");
            return;
        }
        localPluginInstaller->DestroyLocalPluginStreamInstaller(installerId);
    }

    sptr<IStatusReceiver> receiver_;
    uint32_t installerId_ = 0;
    std::mutex mutex_;
};
}

LocalPluginStreamInstallerHostImpl::LocalPluginStreamInstallerHostImpl(uint32_t installerId, int32_t installedUid)
    : installerId_(installerId), installedUid_(installedUid)
{}

LocalPluginStreamInstallerHostImpl::~LocalPluginStreamInstallerHostImpl()
{
    UnInit();
}

bool LocalPluginStreamInstallerHostImpl::Init(const InstallPluginParam &installPluginParam,
    const sptr<IStatusReceiver> &statusReceiver, const std::string &hostBundleName)
{
    std::lock_guard<std::mutex> lock(mutex_);
    installPluginParam_ = installPluginParam;
    receiver_ = statusReceiver;
    hostBundleName_ = hostBundleName;
    tempDir_ = BundleUtil::CreateInstallTempDir(installerId_, DirType::STREAM_INSTALL_DIR);
    return !tempDir_.empty();
}

void LocalPluginStreamInstallerHostImpl::UnInit()
{
    std::vector<int32_t> fdVec;
    std::string tempDir;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        fdVec = streamFdVec_;
        tempDir = tempDir_;
        streamFdVec_.clear();
    }
    BundleUtil::CloseFileDescriptor(fdVec);
    BundleUtil::DeleteDir(tempDir);
}

int32_t LocalPluginStreamInstallerHostImpl::CreatePluginFileStream(const std::string &fileName)
{
    if (fileName.empty()) {
        APP_LOGE("CreateStream param fileName is empty");
        return Constants::DEFAULT_STREAM_FD;
    }
    
    if (IPCSkeleton::GetCallingUid() != installedUid_) {
        APP_LOGE("calling uid is inconsistent");
        return Constants::DEFAULT_STREAM_FD;
    }

    if (!BundleFileUtil::CheckFileType(fileName, ServiceConstants::HSP_FILE_SUFFIX) ||
        fileName.find(ILLEGAL_PATH_FIELD) != std::string::npos) {
        APP_LOGE("CreateStream failed due to invalid fileName");
        return Constants::DEFAULT_STREAM_FD;
    }

    std::string tempDir;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        tempDir = tempDir_;
    }
    if (tempDir.empty()) {
        APP_LOGE("temp dir is empty");
        return Constants::DEFAULT_STREAM_FD;
    }

    std::string filePath = tempDir;
    if (filePath.back() != PATH_SEPARATOR[0]) {
        filePath.append(PATH_SEPARATOR);
    }
    filePath.append(fileName);

    int32_t fd = BundleUtil::CreateFileDescriptor(filePath, 0);
    if (fd < 0) {
        APP_LOGE("create file descriptor failed");
        return Constants::DEFAULT_STREAM_FD;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    streamFdVec_.emplace_back(fd);
    return fd;
}

bool LocalPluginStreamInstallerHostImpl::CommitLocalPluginInstall()
{
    BUNDLE_MANAGER_HITRACE_CHAIN_NAME("LocalPluginInstall", HITRACE_FLAG_INCLUDE_ASYNC);
    sptr<IStatusReceiver> receiver;
    uint32_t installerId;
    std::string tempDir;
    std::string hostBundleName;
    InstallPluginParam installPluginParam;
    bool hasPluginFileStream;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        receiver = receiver_;
        installerId = installerId_;
        tempDir = tempDir_;
        hostBundleName = hostBundleName_;
        installPluginParam = installPluginParam_;
        hasPluginFileStream = !streamFdVec_.empty();
    }
    if (receiver == nullptr) {
        APP_LOGE("receiver is null");
        return false;
    }

    sptr<IStatusReceiver> cleanupReceiver = new (std::nothrow) LocalPluginCleanupReceiver(receiver, installerId);
    if (cleanupReceiver == nullptr) {
        APP_LOGE("create cleanup receiver failed");
        receiver->OnFinished(ERR_APPEXECFWK_NULL_PTR, "");
        return false;
    }

    auto installer = DelayedSingleton<BundleMgrService>::GetInstance()->GetLocalPluginInstaller();
    if (installer == nullptr) {
        APP_LOGE("get local plugin installer failed");
        cleanupReceiver->OnFinished(ERR_APPEXECFWK_NULL_PTR, "");
        return false;
    }

    std::vector<std::string> pluginPaths;
    if (hasPluginFileStream) {
        pluginPaths.emplace_back(tempDir);
    }
    ErrCode res = installer->InstallByLocalPluginStream(hostBundleName, pluginPaths, installPluginParam,
        cleanupReceiver);
    if (res != ERR_OK) {
        APP_LOGE("install local plugin failed, err:%{public}d", res);
        cleanupReceiver->OnFinished(res, "");
        return false;
    }
    return true;
}

uint32_t LocalPluginStreamInstallerHostImpl::GetLocalPluginInstallerId() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return installerId_;
}

void LocalPluginStreamInstallerHostImpl::SetLocalPluginInstallerId(uint32_t installerId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    installerId_ = installerId;
}
}  // namespace AppExecFwk
}  // namespace OHOS