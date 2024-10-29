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

#include "installd/installd_host_impl.h"

#include "app_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
InstalldHostImpl::InstalldHostImpl()
{
    APP_LOGI("installd service instance is created");
}

InstalldHostImpl::~InstalldHostImpl()
{
    APP_LOGI("installd service instance is destroyed");
}

ErrCode InstalldHostImpl::CreateBundleDir(const std::string &bundleDir)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::ExtractModuleFiles(const std::string &srcModulePath, const std::string &targetPath,
    const std::string &targetSoPath, const std::string &cpuAbi)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::ExtractHnpFiles(const std::string &hnpPackageInfo, const ExtractParam &extractParam)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::ProcessBundleInstallNative(const std::string &userId, const std::string &hnpRootPath,
    const std::string &hapPath, const std::string &cpuAbi, const std::string &packageName)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::ProcessBundleUnInstallNative(const std::string &userId, const std::string &packageName)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::RenameModuleDir(const std::string &oldPath, const std::string &newPath)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::CreateBundleDataDir(const CreateDirParam &createDirParam)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::CreateBundleDataDirWithVector(const std::vector<CreateDirParam> &createDirParams)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::RemoveBundleDataDir(const std::string &bundleName, const int userId, bool isAtomicService)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::RemoveModuleDataDir(const std::string &ModuleDir, const int userid)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::RemoveDir(const std::string &dir)
{
    return ERR_OK;
}

int64_t InstalldHostImpl::GetDiskUsage(const std::string &dir, bool isRealPath)
{
    return 0;
}

ErrCode InstalldHostImpl::CleanBundleDataDir(const std::string &dataDir)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::CleanBundleDataDirByName(const std::string &bundleName, const int userid,
    const int appIndex)
{
    return ERR_OK;
}

std::string InstalldHostImpl::GetBundleDataDir(const std::string &el, const int userid) const
{
    return "";
}

ErrCode InstalldHostImpl::GetBundleStats(
    const std::string &bundleName, const int32_t userId, std::vector<int64_t> &bundleStats,
    const int32_t uid, const int32_t appIndex, const uint32_t statFlag,
    const std::vector<std::string> &moduleNameList)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::GetAllBundleStats(const int32_t userId,
    std::vector<int64_t> &bundleStats, const std::vector<int32_t> &uids)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::SetDirApl(const std::string &dir, const std::string &bundleName, const std::string &apl,
    bool isPreInstallApp, bool debug)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::GetBundleCachePath(const std::string &dir, std::vector<std::string> &cachePath)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::ScanDir(
    const std::string &dir, ScanMode scanMode, ResultMode resultMode, std::vector<std::string> &paths)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::MoveFile(const std::string &oldPath, const std::string &newPath)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::CopyFile(const std::string &oldPath, const std::string &newPath,
    const std::string &signatureFilePath)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::Mkdir(
    const std::string &dir, const int32_t mode, const int32_t uid, const int32_t gid)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::GetFileStat(const std::string &file, FileStat &fileStat)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::ExtractDiffFiles(const std::string &filePath, const std::string &targetPath,
    const std::string &cpuAbi)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::ApplyDiffPatch(const std::string &oldSoPath, const std::string &diffFilePath,
    const std::string &newSoPath, int32_t uid)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::IsExistDir(const std::string &dir, bool &isExist)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::IsExistFile(const std::string &path, bool &isExist)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::IsExistApFile(const std::string &path, bool &isExist)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::IsDirEmpty(const std::string &dir, bool &isDirEmpty)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::ObtainQuickFixFileDir(const std::string &dir, std::vector<std::string> &dirVec)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::CopyFiles(const std::string &sourceDir, const std::string &destinationDir)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::ExtractFiles(const ExtractParam &extractParam)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::ExecuteAOT(const AOTArgs &aotArgs, std::vector<uint8_t> &pendSignData)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::PendSignAOT(const std::string &anFileName, const std::vector<uint8_t> &signData)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::StopAOT()
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::GetNativeLibraryFileNames(const std::string &filePath, const std::string &cpuAbi,
    std::vector<std::string> &fileNames)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::VerifyCodeSignature(const CodeSignatureParam &codeSignatureParam)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::CheckEncryption(const CheckEncryptionParam &checkEncryptionParam, bool &isEncryption)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::MoveFiles(const std::string &srcDir, const std::string &desDir)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::ExtractDriverSoFiles(const std::string &srcPath,
    const std::unordered_multimap<std::string, std::string> &dirMap)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::ExtractEncryptedSoFiles(const std::string &hapPath, const std::string &realSoFilesPath,
    const std::string &cpuAbi, const std::string &tmpSoPath, int32_t uid)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::VerifyCodeSignatureForHap(const CodeSignatureParam &codeSignatureParam)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::DeliverySignProfile(const std::string &bundleName, int32_t profileBlockLength,
    const unsigned char *profileBlock)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::RemoveSignProfile(const std::string &bundleName)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::SetEncryptionPolicy(int32_t uid, const std::string &bundleName,
    const int32_t userId, std::string &keyId)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::DeleteEncryptionKeyId(const std::string &bundleName, const int32_t userId)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::RemoveExtensionDir(int32_t userId, const std::vector<std::string> &extensionBundleDirs)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::IsExistExtensionDir(int32_t userId, const std::string &extensionBundleDir, bool &isExist)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::CreateExtensionDataDir(const CreateDirParam &createDirParam)
{
    return ERR_OK;
}

ErrCode InstalldHostImpl::GetExtensionSandboxTypeList(std::vector<std::string> &typeList)
{
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
