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
#include "ipc_skeleton.h"
namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* ILLEGAL_PATH_FIELD = "../";
}

BundleStreamInstallerHostImpl::BundleStreamInstallerHostImpl(uint32_t installerId, int32_t installedUid)
{
    APP_LOGD("create bundle stream installer host impl instance");
    installerId_ = installerId;
    installedUid_ = installedUid;
}

BundleStreamInstallerHostImpl::~BundleStreamInstallerHostImpl()
{
    APP_LOGD("destory bundle stream installer host impl instance");
    UnInit();
}

bool BundleStreamInstallerHostImpl::Init(const InstallParam &installParam,
    const sptr<IStatusReceiver> &statusReceiver, const std::vector<std::string> &originHapPaths)
{
    installParam_ = installParam;
    receiver_ = statusReceiver;
    originHapPaths_ = originHapPaths;
    std::string tempDir = BundleUtil::CreateInstallTempDir(installerId_, DirType::STREAM_INSTALL_DIR);
    if (tempDir.empty()) {
        APP_LOGE("tempDir is empty");
        return false;
    }
    tempDir_ = tempDir;

    installParam_.sharedBundleDirPaths.clear();
    uint32_t size = static_cast<uint32_t>(installParam.sharedBundleDirPaths.size());
    for (uint32_t i = 0; i < size; ++i) {
        tempDir = BundleUtil::CreateSharedBundleTempDir(installerId_, i);
        if (tempDir.empty()) {
            APP_LOGE("create temp dir for hsp failed");
            return false;
        }
        installParam_.sharedBundleDirPaths.emplace_back(tempDir);
    }

    installParam_.pgoParams.clear();

    tempSignatureFileDir_ = BundleUtil::CreateInstallTempDir(installerId_, DirType::SIG_FILE_DIR);
    if (tempSignatureFileDir_.empty()) {
        APP_LOGE("tempSignatureFileDir_ is empty");
        return false;
    }

    tempPgoFileDir_ = BundleUtil::CreateInstallTempDir(installerId_, DirType::PGO_FILE_DIR);
    if (tempPgoFileDir_.empty()) {
        APP_LOGE("tempPgoFileDir_ is empty");
        return false;
    }

    auto iter = installParam.parameters.find(ServiceConstants::ENTERPRISE_MANIFEST);
    if ((iter != installParam.parameters.end()) && !(iter->second.empty())) {
        installParam_.parameters[ServiceConstants::ENTERPRISE_MANIFEST] = "";
        tempExtProfileDir_ = BundleUtil::CreateInstallTempDir(installerId_, DirType::EXT_PROFILE_DIR);
        if (tempExtProfileDir_.empty()) {
            APP_LOGW("tempExtProfileDir_ is empty");
        }
    }
    
    return true;
}

void BundleStreamInstallerHostImpl::UnInit()
{
    APP_LOGD("destory stream installer with installerId %{public}d and temp dir %{public}s", installerId_,
        tempDir_.c_str());
    std::lock_guard<std::mutex> lock(fdVecMutex_);
    BundleUtil::CloseFileDescriptor(streamFdVec_);
    BundleUtil::DeleteDir(tempDir_);
    for (const auto &path : installParam_.sharedBundleDirPaths) {
        BundleUtil::DeleteDir(path);
    }
    BundleUtil::DeleteDir(tempSignatureFileDir_);
    BundleUtil::DeleteDir(tempPgoFileDir_);
    BundleUtil::DeleteDir(tempExtProfileDir_);
}

int32_t BundleStreamInstallerHostImpl::CreateStream(const std::string &fileName)
{
    if (fileName.empty()) {
        APP_LOGE("CreateStream param fileName is empty");
        return Constants::DEFAULT_STREAM_FD;
    }

    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_INSTALL_ENTERPRISE_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(
            ServiceConstants::PERMISSION_INSTALL_ENTERPRISE_NORMAL_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(
            ServiceConstants::PERMISSION_INSTALL_ENTERPRISE_MDM_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(
            ServiceConstants::PERMISSION_INSTALL_INTERNALTESTING_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_INSTALL_SELF_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_INSTALL_SANDBOX_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_INSTALL_QUICK_FIX_BUNDLE)) {
        APP_LOGE("CreateStream permission denied");
        return Constants::DEFAULT_STREAM_FD;
    }

    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid != installedUid_) {
        APP_LOGE("calling uid is inconsistent");
        return Constants::DEFAULT_STREAM_FD;
    }

    if (!BundleUtil::CheckFileType(fileName, ServiceConstants::INSTALL_FILE_SUFFIX) &&
        !BundleUtil::CheckFileType(fileName, ServiceConstants::HSP_FILE_SUFFIX)) {
        APP_LOGE("file is not hap or hsp");
        return Constants::DEFAULT_STREAM_FD;
    }
    // to prevent the hap copied to relevant path
    if (fileName.find(ILLEGAL_PATH_FIELD) != std::string::npos) {
        APP_LOGE("CreateStream failed due to invalid fileName");
        return Constants::DEFAULT_STREAM_FD;
    }
    std::string filePath = tempDir_ + fileName;
    int32_t fd = BundleUtil::CreateFileDescriptor(filePath, 0);
    if (fd < 0) {
        APP_LOGE("stream installer create file descriptor failed");
    }
    if (fd > 0) {
        std::lock_guard<std::mutex> lock(fdVecMutex_);
        streamFdVec_.emplace_back(fd);
        isInstallSharedBundlesOnly_ = false;
    }
    return fd;
}

int32_t BundleStreamInstallerHostImpl::CreateSignatureFileStream(const std::string &moduleName,
    const std::string &fileName)
{
    if (moduleName.empty() || fileName.empty()) {
        APP_LOGE("CreateSignatureFileStream params are invalid");
        return Constants::DEFAULT_STREAM_FD;
    }

    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_INSTALL_ENTERPRISE_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(
            ServiceConstants::PERMISSION_INSTALL_ENTERPRISE_NORMAL_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(
            ServiceConstants::PERMISSION_INSTALL_ENTERPRISE_MDM_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(
            ServiceConstants::PERMISSION_INSTALL_INTERNALTESTING_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_INSTALL_SELF_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_INSTALL_SANDBOX_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_INSTALL_QUICK_FIX_BUNDLE)) {
        APP_LOGE("CreateSignatureFileStream permission denied");
        return Constants::DEFAULT_STREAM_FD;
    }

    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid != installedUid_) {
        APP_LOGE("calling uid is inconsistent");
        return Constants::DEFAULT_STREAM_FD;
    }

    if (!BundleUtil::CheckFileType(fileName, ServiceConstants::CODE_SIGNATURE_FILE_SUFFIX)) {
        APP_LOGE("file is not sig");
        return Constants::DEFAULT_STREAM_FD;
    }

    auto iterator = installParam_.verifyCodeParams.find(moduleName);
    if (iterator == installParam_.verifyCodeParams.end()) {
        APP_LOGE("module name cannot be found");
        return Constants::DEFAULT_STREAM_FD;
    }

    // to prevent the sig copied to relevant path
    if (fileName.find(ILLEGAL_PATH_FIELD) != std::string::npos) {
        APP_LOGE("CreateStream failed due to invalid fileName");
        return Constants::DEFAULT_STREAM_FD;
    }
    std::string filePath = tempSignatureFileDir_ + fileName;
    int32_t fd = BundleUtil::CreateFileDescriptor(filePath, 0);
    if (fd < 0) {
        APP_LOGE("stream installer create file descriptor failed");
    }

    if (fd > 0) {
        std::lock_guard<std::mutex> lock(fdVecMutex_);
        streamFdVec_.emplace_back(fd);
        installParam_.verifyCodeParams.at(moduleName) = filePath;
    }
    return fd;
}

int32_t BundleStreamInstallerHostImpl::CreateSharedBundleStream(const std::string &hspName, uint32_t index)
{
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_INSTALL_ENTERPRISE_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(
            ServiceConstants::PERMISSION_INSTALL_ENTERPRISE_NORMAL_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(
            ServiceConstants::PERMISSION_INSTALL_ENTERPRISE_MDM_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(
            ServiceConstants::PERMISSION_INSTALL_INTERNALTESTING_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_INSTALL_SELF_BUNDLE)) {
        APP_LOGE("CreateSharedBundleStream permission denied");
        return Constants::DEFAULT_STREAM_FD;
    }

    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid != installedUid_) {
        APP_LOGE("calling uid is inconsistent");
        return Constants::DEFAULT_STREAM_FD;
    }

    if (!BundleUtil::CheckFileType(hspName, ServiceConstants::INSTALL_FILE_SUFFIX) &&
        !BundleUtil::CheckFileType(hspName, ServiceConstants::HSP_FILE_SUFFIX) &&
        !BundleUtil::CheckFileType(hspName, ServiceConstants::CODE_SIGNATURE_FILE_SUFFIX)) {
        APP_LOGE("file is not hap or hsp");
        return Constants::DEFAULT_STREAM_FD;
    }

    // to prevent the hsp copied to relevant path
    if (hspName.find(ILLEGAL_PATH_FIELD) != std::string::npos) {
        APP_LOGE("CreateSharedBundleStream failed due to invalid hapName");
        return Constants::DEFAULT_STREAM_FD;
    }

    if (index >= installParam_.sharedBundleDirPaths.size()) {
        APP_LOGE("invalid shared bundle index");
        return Constants::DEFAULT_STREAM_FD;
    }

    std::string bundlePath = installParam_.sharedBundleDirPaths[index] + hspName;
    int32_t fd = BundleUtil::CreateFileDescriptor(bundlePath, 0);
    if (fd < 0) {
        APP_LOGE("stream installer create file descriptor failed");
    }
    if (fd > 0) {
        std::lock_guard<std::mutex> lock(fdVecMutex_);
        streamFdVec_.emplace_back(fd);
    }
    return fd;
}

int32_t BundleStreamInstallerHostImpl::CreatePgoFileStream(const std::string &moduleName,
    const std::string &fileName)
{
    if (moduleName.empty() || fileName.empty()) {
        APP_LOGE("CreatePgoFileStream params are invalid");
        return Constants::DEFAULT_STREAM_FD;
    }

    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_INSTALL_ENTERPRISE_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(
            ServiceConstants::PERMISSION_INSTALL_ENTERPRISE_NORMAL_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(
            ServiceConstants::PERMISSION_INSTALL_ENTERPRISE_MDM_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(
            ServiceConstants::PERMISSION_INSTALL_INTERNALTESTING_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_INSTALL_SELF_BUNDLE)) {
        APP_LOGE("CreatePgoFileStream permission denied");
        return Constants::DEFAULT_STREAM_FD;
    }

    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid != installedUid_) {
        APP_LOGE("calling uid is inconsistent");
        return Constants::DEFAULT_STREAM_FD;
    }

    if (!BundleUtil::CheckFileType(fileName, ServiceConstants::PGO_FILE_SUFFIX)) {
        APP_LOGE("file is not pgo");
        return Constants::DEFAULT_STREAM_FD;
    }

    // to prevent the pgo copied to relevant path
    if (fileName.find(ILLEGAL_PATH_FIELD) != std::string::npos) {
        APP_LOGE("CreateStream failed due to invalid fileName");
        return Constants::DEFAULT_STREAM_FD;
    }
    std::string filePath = tempPgoFileDir_ + fileName;
    int32_t fd = BundleUtil::CreateFileDescriptor(filePath, 0);
    if (fd < 0) {
        APP_LOGE("stream installer create file descriptor failed");
    }

    if (fd > 0) {
        std::lock_guard<std::mutex> lock(fdVecMutex_);
        streamFdVec_.emplace_back(fd);
        installParam_.pgoParams[moduleName] = filePath;
    }
    return fd;
}

int32_t BundleStreamInstallerHostImpl::CreateExtProfileFileStream(const std::string &fileName)
{
    if (fileName.empty()) {
        APP_LOGE("CreateExtProfileFileStream param is invalid");
        return Constants::DEFAULT_STREAM_FD;
    }

    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_INSTALL_ENTERPRISE_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(
            ServiceConstants::PERMISSION_INSTALL_ENTERPRISE_NORMAL_BUNDLE) &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(
            ServiceConstants::PERMISSION_INSTALL_ENTERPRISE_MDM_BUNDLE)) {
        APP_LOGE("CreateExtProfileFileStream permission denied");
        return Constants::DEFAULT_STREAM_FD;
    }

    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid != installedUid_) {
        APP_LOGE("calling uid is inconsistent");
        return Constants::DEFAULT_STREAM_FD;
    }

    if (!BundleUtil::CheckFileType(fileName, ServiceConstants::JSON_SUFFIX)) {
        APP_LOGE("file is not json");
        return Constants::DEFAULT_STREAM_FD;
    }

    // to prevent the sig copied to relevant path
    if (fileName.find(ILLEGAL_PATH_FIELD) != std::string::npos) {
        APP_LOGE("CreateStream failed due to invalid fileName");
        return Constants::DEFAULT_STREAM_FD;
    }
    std::string filePath = tempExtProfileDir_ + fileName;
    int32_t fd = BundleUtil::CreateFileDescriptor(filePath, 0);
    if (fd < 0) {
        APP_LOGE("stream installer create file descriptor failed");
    } else {
        std::lock_guard<std::mutex> lock(fdVecMutex_);
        streamFdVec_.emplace_back(fd);
        installParam_.parameters[ServiceConstants::ENTERPRISE_MANIFEST] = filePath;
    }
    return fd;
}

bool BundleStreamInstallerHostImpl::Install()
{
    if (receiver_ == nullptr) {
        APP_LOGE("receiver_ is nullptr");
        return false;
    }
    receiver_->SetStreamInstallId(installerId_);
    auto installer = DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleInstaller();
    if (installer == nullptr) {
        APP_LOGE("get bundle installer failed");
        receiver_->OnFinished(ERR_APPEXECFWK_INSTALL_INTERNAL_ERROR, "");
        return false;
    }
    std::vector<std::string> pathVec;
    if (installParam_.IsRenameInstall()) {
        pathVec = originHapPaths_;
    } else if (!isInstallSharedBundlesOnly_) {
        pathVec.emplace_back(tempDir_);
    }
    installParam_.withCopyHaps = true;

    bool res;
    if (installParam_.isSelfUpdate) {
        res = installer->UpdateBundleForSelf(pathVec, installParam_, receiver_);
    } else {
        res = installer->Install(pathVec, installParam_, receiver_);
    }
    if (!res) {
        APP_LOGE("install bundle failed");
        return false;
    }
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