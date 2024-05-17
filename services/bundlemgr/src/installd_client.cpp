/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "installd_client.h"

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "if_system_ability_manager.h"
#include "installd/installd_load_callback.h"
#include "installd_death_recipient.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "system_ability_helper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const int LOAD_SA_TIMEOUT_MS = 4 * 1000;
} // namespace

ErrCode InstalldClient::CreateBundleDir(const std::string &bundleDir)
{
    if (bundleDir.empty()) {
        APP_LOGE("bundle dir is empty");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    return CallService(&IInstalld::CreateBundleDir, bundleDir);
}

ErrCode InstalldClient::ExtractModuleFiles(const std::string &srcModulePath, const std::string &targetPath,
    const std::string &targetSoPath, const std::string &cpuAbi)
{
    if (srcModulePath.empty() || targetPath.empty()) {
        APP_LOGE("src module path or target path is empty");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    return CallService(&IInstalld::ExtractModuleFiles, srcModulePath, targetPath, targetSoPath, cpuAbi);
}

ErrCode InstalldClient::ExtractFiles(const ExtractParam &extractParam)
{
    if (extractParam.srcPath.empty() || extractParam.targetPath.empty()) {
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    return CallService(&IInstalld::ExtractFiles, extractParam);
}

ErrCode InstalldClient::ExecuteAOT(const AOTArgs &aotArgs)
{
    return CallService(&IInstalld::ExecuteAOT, aotArgs);
}

ErrCode InstalldClient::StopAOT()
{
    return CallService(&IInstalld::StopAOT);
}

ErrCode InstalldClient::RenameModuleDir(const std::string &oldPath, const std::string &newPath)
{
    if (oldPath.empty() || newPath.empty()) {
        APP_LOGE("rename path is empty");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    return CallService(&IInstalld::RenameModuleDir, oldPath, newPath);
}

ErrCode InstalldClient::CreateBundleDataDir(const CreateDirParam &createDirParam)
{
    if (createDirParam.bundleName.empty() || createDirParam.userId < 0
        || createDirParam.uid < 0 || createDirParam.gid < 0) {
        APP_LOGE("params are invalid");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    return CallService(&IInstalld::CreateBundleDataDir, createDirParam);
}

ErrCode InstalldClient::CreateBundleDataDirWithVector(const std::vector<CreateDirParam> &createDirParams)
{
    return CallService(&IInstalld::CreateBundleDataDirWithVector, createDirParams);
}

ErrCode InstalldClient::RemoveBundleDataDir(
    const std::string &bundleName, const int userid)
{
    if (bundleName.empty() || userid < 0) {
        APP_LOGE("params are invalid");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    return CallService(&IInstalld::RemoveBundleDataDir, bundleName, userid);
}

ErrCode InstalldClient::RemoveModuleDataDir(const std::string &ModuleName, const int userid)
{
    if (ModuleName.empty() || userid < 0) {
        APP_LOGE("params are invalid");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    return CallService(&IInstalld::RemoveModuleDataDir, ModuleName, userid);
}

ErrCode InstalldClient::RemoveDir(const std::string &dir)
{
    if (dir.empty()) {
        APP_LOGE("dir removed is empty");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    return CallService(&IInstalld::RemoveDir, dir);
}

ErrCode InstalldClient::CleanBundleDataDir(const std::string &bundleDir)
{
    if (bundleDir.empty()) {
        APP_LOGE("bundle dir is empty");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    return CallService(&IInstalld::CleanBundleDataDir, bundleDir);
}

ErrCode InstalldClient::CleanBundleDataDirByName(const std::string &bundleName, const int userid)
{
    if (bundleName.empty() || userid < 0) {
        APP_LOGE("params are invalid");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    return CallService(&IInstalld::CleanBundleDataDirByName, bundleName, userid);
}

ErrCode InstalldClient::GetBundleStats(
    const std::string &bundleName, const int32_t userId, std::vector<int64_t> &bundleStats, const int32_t uid)
{
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    return CallService(&IInstalld::GetBundleStats, bundleName, userId, bundleStats, uid);
}

ErrCode InstalldClient::GetAllBundleStats(const std::vector<std::string> &bundleNames, const int32_t userId,
    std::vector<int64_t> &bundleStats, const std::vector<int32_t> &uids)
{
    if (bundleNames.empty()) {
        APP_LOGE("bundleName is empty");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    if (bundleNames.size() != uids.size()) {
        APP_LOGE("bundleNames size is not equal to uids size");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    return CallService(&IInstalld::GetAllBundleStats, bundleNames, userId, bundleStats, uids);
}

ErrCode InstalldClient::SetDirApl(const std::string &dir, const std::string &bundleName, const std::string &apl,
    bool isPreInstallApp, bool debug)
{
    if (dir.empty() || bundleName.empty() || apl.empty()) {
        APP_LOGE("params are invalid");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    return CallService(&IInstalld::SetDirApl, dir, bundleName, apl, isPreInstallApp, debug);
}

ErrCode InstalldClient::GetBundleCachePath(const std::string &dir, std::vector<std::string> &cachePath)
{
    if (dir.empty()) {
        APP_LOGE("params are invalid");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    return CallService(&IInstalld::GetBundleCachePath, dir, cachePath);
}

void InstalldClient::ResetInstalldProxy()
{
    if ((installdProxy_ != nullptr) && (installdProxy_->AsObject() != nullptr)) {
        installdProxy_->AsObject()->RemoveDeathRecipient(recipient_);
    }
    SystemAbilityHelper::UnloadSystemAbility(INSTALLD_SERVICE_ID);
    installdProxy_ = nullptr;
}

bool InstalldClient::LoadInstalldService()
{
    {
        std::unique_lock<std::mutex> lock(loadSaMutex_);
        loadSaFinished_ = false;
    }
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityMgr == nullptr) {
        APP_LOGE("Failed to get SystemAbilityManager.");
        return false;
    }
    sptr<InstalldLoadCallback> loadCallback = new (std::nothrow) InstalldLoadCallback();
    if (loadCallback == nullptr) {
        APP_LOGE("Create load callback failed.");
        return false;
    }
    auto ret = systemAbilityMgr->LoadSystemAbility(INSTALLD_SERVICE_ID, loadCallback);
    if (ret != 0) {
        APP_LOGE("Load system ability %{public}d failed with %{public}d.", INSTALLD_SERVICE_ID, ret);
        return false;
    }

    {
        std::unique_lock<std::mutex> lock(loadSaMutex_);
        auto waitStatus = loadSaCondition_.wait_for(lock, std::chrono::milliseconds(LOAD_SA_TIMEOUT_MS),
            [this]() {
                return loadSaFinished_;
            });
        if (!waitStatus) {
            APP_LOGE("Wait for load sa timeout.");
            return false;
        }
    }
    return true;
}

bool InstalldClient::GetInstalldProxy()
{
    std::lock_guard<std::mutex> lock(getProxyMutex_);
    if (installdProxy_ != nullptr) {
        APP_LOGD("installd ready");
        return true;
    }

    APP_LOGI("try to get installd proxy");
    if (!LoadInstalldService()) {
        APP_LOGE("load installd service failed");
        return false;
    }
    if ((installdProxy_ == nullptr) || (installdProxy_->AsObject() == nullptr)) {
        APP_LOGE("the installd proxy or remote object is null");
        return false;
    }

    recipient_ = new (std::nothrow) InstalldDeathRecipient();
    if (recipient_ == nullptr) {
        APP_LOGE("the death recipient is nullptr");
        return false;
    }
    installdProxy_->AsObject()->AddDeathRecipient(recipient_);
    return true;
}

ErrCode InstalldClient::ScanDir(
    const std::string &dir, ScanMode scanMode, ResultMode resultMode, std::vector<std::string> &paths)
{
    if (dir.empty()) {
        APP_LOGE("params are invalid");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    return CallService(&IInstalld::ScanDir, dir, scanMode, resultMode, paths);
}

ErrCode InstalldClient::MoveFile(const std::string &oldPath, const std::string &newPath)
{
    if (oldPath.empty() || newPath.empty()) {
        APP_LOGE("params are invalid");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    return CallService(&IInstalld::MoveFile, oldPath, newPath);
}

ErrCode InstalldClient::CopyFile(const std::string &oldPath, const std::string &newPath,
    const std::string &signatureFilePath)
{
    if (oldPath.empty() || newPath.empty()) {
        APP_LOGE("params are invalid");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    return CallService(&IInstalld::CopyFile, oldPath, newPath, signatureFilePath);
}

ErrCode InstalldClient::Mkdir(
    const std::string &dir, const int32_t mode, const int32_t uid, const int32_t gid)
{
    if (dir.empty()) {
        APP_LOGE("params are invalid");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    return CallService(&IInstalld::Mkdir, dir, mode, uid, gid);
}

ErrCode InstalldClient::GetFileStat(const std::string &file, FileStat &fileStat)
{
    if (file.empty()) {
        APP_LOGE("params are invalid");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    return CallService(&IInstalld::GetFileStat, file, fileStat);
}

ErrCode InstalldClient::ExtractDiffFiles(const std::string &filePath, const std::string &targetPath,
    const std::string &cpuAbi)
{
    if (filePath.empty() || targetPath.empty() || cpuAbi.empty()) {
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    return CallService(&IInstalld::ExtractDiffFiles, filePath, targetPath, cpuAbi);
}

ErrCode InstalldClient::ApplyDiffPatch(const std::string &oldSoPath, const std::string &diffFilePath,
    const std::string &newSoPath, int32_t uid)
{
    if (oldSoPath.empty() || diffFilePath.empty() || newSoPath.empty()) {
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    return CallService(&IInstalld::ApplyDiffPatch, oldSoPath, diffFilePath, newSoPath, uid);
}

ErrCode InstalldClient::IsExistDir(const std::string &dir, bool &isExist)
{
    return CallService(&IInstalld::IsExistDir, dir, isExist);
}

ErrCode InstalldClient::IsExistFile(const std::string &path, bool &isExist)
{
    return CallService(&IInstalld::IsExistFile, path, isExist);
}

ErrCode InstalldClient::IsExistApFile(const std::string &path, bool &isExist)
{
    return CallService(&IInstalld::IsExistApFile, path, isExist);
}

ErrCode InstalldClient::IsDirEmpty(const std::string &dir, bool &isDirEmpty)
{
    return CallService(&IInstalld::IsDirEmpty, dir, isDirEmpty);
}

ErrCode InstalldClient::ObtainQuickFixFileDir(const std::string &dir, std::vector<std::string> &dirVec)
{
    return CallService(&IInstalld::ObtainQuickFixFileDir, dir, dirVec);
}

ErrCode InstalldClient::CopyFiles(const std::string &sourceDir, const std::string &destinationDir)
{
    return CallService(&IInstalld::CopyFiles, sourceDir, destinationDir);
}

ErrCode InstalldClient::GetNativeLibraryFileNames(const std::string &filePath, const std::string &cpuAbi,
    std::vector<std::string> &fileNames)
{
    return CallService(&IInstalld::GetNativeLibraryFileNames, filePath, cpuAbi, fileNames);
}

ErrCode InstalldClient::VerifyCodeSignature(const CodeSignatureParam &codeSignatureParam)
{
    if (codeSignatureParam.modulePath.empty()) {
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    return CallService(&IInstalld::VerifyCodeSignature, codeSignatureParam);
}

ErrCode InstalldClient::CheckEncryption(const CheckEncryptionParam &checkEncryptionParam, bool &isEncryption)
{
    if (checkEncryptionParam.modulePath.empty()) {
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    return CallService(&IInstalld::CheckEncryption, checkEncryptionParam, isEncryption);
}

ErrCode InstalldClient::MoveFiles(const std::string &srcDir, const std::string &desDir)
{
    if (srcDir.empty() || desDir.empty()) {
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    return CallService(&IInstalld::MoveFiles, srcDir, desDir);
}


ErrCode InstalldClient::ExtractDriverSoFiles(const std::string &srcPath,
    const std::unordered_multimap<std::string, std::string> &dirMap)
{
    if (srcPath.empty() || dirMap.empty()) {
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    return CallService(&IInstalld::ExtractDriverSoFiles, srcPath, dirMap);
}

ErrCode InstalldClient::VerifyCodeSignatureForHap(const CodeSignatureParam &codeSignatureParam)
{
    if (codeSignatureParam.modulePath.empty()) {
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    return CallService(&IInstalld::VerifyCodeSignatureForHap, codeSignatureParam);
}

ErrCode InstalldClient::DeliverySignProfile(const std::string &bundleName, int32_t profileBlockLength,
    const unsigned char *profileBlock)
{
    if (bundleName.empty() || profileBlock == nullptr) {
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    return CallService(&IInstalld::DeliverySignProfile, bundleName, profileBlockLength, profileBlock);
}

ErrCode InstalldClient::RemoveSignProfile(const std::string &bundleName)
{
    if (bundleName.empty()) {
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    return CallService(&IInstalld::RemoveSignProfile, bundleName);
}

void InstalldClient::OnLoadSystemAbilitySuccess(const sptr<IRemoteObject> &remoteObject)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        installdProxy_ = iface_cast<IInstalld>(remoteObject);
    }

    {
        std::lock_guard<std::mutex> lock(loadSaMutex_);
        loadSaFinished_ = true;
        loadSaCondition_.notify_one();
    }
}

void InstalldClient::OnLoadSystemAbilityFail()
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        installdProxy_ = nullptr;
    }

    {
        std::lock_guard<std::mutex> lock(loadSaMutex_);
        loadSaFinished_ = true;
        loadSaCondition_.notify_one();
    }
}

bool InstalldClient::StartInstalldService()
{
    return GetInstalldProxy();
}

ErrCode InstalldClient::ExtractEncryptedSoFiles(const std::string &hapPath, const std::string &realSoFilesPath,
    const std::string &cpuAbi, const std::string &tmpSoPath, int32_t uid)
{
    if (hapPath.empty() || tmpSoPath.empty() || cpuAbi.empty()) {
        APP_LOGE("params are invalid");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    return CallService(&IInstalld::ExtractEncryptedSoFiles, hapPath, realSoFilesPath, cpuAbi, tmpSoPath, uid);
}
}  // namespace AppExecFwk
}  // namespace OHOS
