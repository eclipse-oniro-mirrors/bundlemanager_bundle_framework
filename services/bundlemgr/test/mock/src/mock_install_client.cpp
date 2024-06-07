/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

namespace OHOS {
namespace AppExecFwk {
ErrCode InstalldClient::CreateBundleDir(const std::string &bundleDir)
{
    return 0;
}

ErrCode InstalldClient::ExtractModuleFiles(const std::string &srcModulePath, const std::string &targetPath,
    const std::string &targetSoPath, const std::string &cpuAbi)
{
    return 0;
}

ErrCode InstalldClient::ExtractFiles(const ExtractParam &extractParam)
{
    return 0;
}

ErrCode InstalldClient::ExtractHnpFiles(const std::string &hnpPackageInfo, const ExtractParam &extractParam)
{
    return 0;
}

ErrCode InstalldClient::ProcessBundleInstallNative(const std::string &userId, const std::string &hnpRootPath,
    const std::string &hapPath, const std::string &cpuAbi, const std::string &packageName)
{
    return 0;
}

ErrCode InstalldClient::ProcessBundleUnInstallNative(const std::string &userId, const std::string &packageName)
{
    return 0;
}

ErrCode InstalldClient::ExecuteAOT(const AOTArgs &aotArgs, std::vector<uint8_t> &pendSignData)
{
    return 0;
}

ErrCode InstalldClient::PendSignAOT(const std::string &anFileName, const std::vector<uint8_t> &signData)
{
    return 0;
}

ErrCode InstalldClient::StopAOT()
{
    return 0;
}

ErrCode InstalldClient::RenameModuleDir(const std::string &oldPath, const std::string &newPath)
{
    return 0;
}

ErrCode InstalldClient::CreateBundleDataDir(const CreateDirParam &createDirParam)
{
    return 0;
}

ErrCode InstalldClient::CreateBundleDataDirWithVector(const std::vector<CreateDirParam> &createDirParams)
{
    return ERR_OK;
}

ErrCode InstalldClient::RemoveBundleDataDir(const std::string &bundleName, const int userid)
{
    if (bundleName.empty()) {
        return -1;
    }
    return 0;
}

ErrCode InstalldClient::RemoveModuleDataDir(const std::string &ModuleName, const int userid)
{
    return 0;
}

ErrCode InstalldClient::RemoveDir(const std::string &dir)
{
    if (dir.empty()) {
        return -1;
    }
    return 0;
}

int64_t InstalldClient::GetDiskUsage(const std::string &dir, bool isRealPath)
{
    return 0;
}

ErrCode InstalldClient::CleanBundleDataDir(const std::string &bundleDir)
{
    return 0;
}

ErrCode InstalldClient::CleanBundleDataDirByName(const std::string &bundleName, const int userid)
{
    if (bundleName.empty()) {
        return -1;
    }
    return 0;
}

ErrCode InstalldClient::GetBundleStats(const std::string &bundleName, const int32_t userId,
    std::vector<int64_t> &bundleStats, const int32_t uid, const int32_t appIndex)
{
    return 0;
}

ErrCode InstalldClient::GetAllBundleStats(const std::vector<std::string> &bundleNames, const int32_t userId,
    std::vector<int64_t> &bundleStats, const std::vector<int32_t> &uids)
{
    return 0;
}

ErrCode InstalldClient::SetDirApl(const std::string &dir, const std::string &bundleName, const std::string &apl,
    bool isPreInstallApp, bool debug)
{
    return 0;
}

ErrCode InstalldClient::GetBundleCachePath(const std::string &dir, std::vector<std::string> &cachePath)
{
    return 0;
}

void InstalldClient::ResetInstalldProxy()
{
    return;
}

bool InstalldClient::GetInstalldProxy()
{
    return true;
}

ErrCode InstalldClient::ScanDir(
    const std::string &dir, ScanMode scanMode, ResultMode resultMode, std::vector<std::string> &paths)
{
    return 0;
}

ErrCode InstalldClient::MoveFile(const std::string &oldPath, const std::string &newPath)
{
    return 0;
}

ErrCode InstalldClient::CopyFile(const std::string &oldPath, const std::string &newPath,
    const std::string &signatureFilePath)
{
    return 0;
}

ErrCode InstalldClient::Mkdir(const std::string &dir, const int32_t mode, const int32_t uid, const int32_t gid)
{
    return 0;
}

ErrCode InstalldClient::GetFileStat(const std::string &file, FileStat &fileStat)
{
    return 0;
}

ErrCode InstalldClient::ExtractDiffFiles(
    const std::string &filePath, const std::string &targetPath, const std::string &cpuAbi)
{
    return 0;
}

ErrCode InstalldClient::ApplyDiffPatch(
    const std::string &oldSoPath, const std::string &diffFilePath, const std::string &newSoPath, int32_t uid)
{
    return 0;
}

ErrCode InstalldClient::IsExistDir(const std::string &dir, bool &isExist)
{
    return 0;
}

ErrCode InstalldClient::IsExistFile(const std::string &path, bool &isExist)
{
    return 0;
}

ErrCode InstalldClient::IsExistApFile(const std::string &path, bool &isExist)
{
    return 0;
}

ErrCode InstalldClient::IsDirEmpty(const std::string &dir, bool &isDirEmpty)
{
    return 0;
}

ErrCode InstalldClient::ObtainQuickFixFileDir(const std::string &dir, std::vector<std::string> &dirVec)
{
    return 0;
}

ErrCode InstalldClient::CopyFiles(const std::string &sourceDir, const std::string &destinationDir)
{
    return 0;
}

ErrCode InstalldClient::GetNativeLibraryFileNames(const std::string &filePath, const std::string &cpuAbi,
    std::vector<std::string> &fileNames)
{
    return 0;
}

ErrCode InstalldClient::VerifyCodeSignature(const CodeSignatureParam &codeSignatureParam)
{
    return ERR_OK;
}

ErrCode InstalldClient::CheckEncryption(const CheckEncryptionParam &checkEncryptionParam, bool &isEncryption)
{
    return ERR_OK;
}

ErrCode InstalldClient::MoveFiles(const std::string &srcDir, const std::string &desDir)
{
    return ERR_OK;
}

bool InstalldClient::StartInstalldService()
{
    return GetInstalldProxy();
}

ErrCode InstalldClient::ExtractDriverSoFiles(const std::string &srcPath,
    const std::unordered_multimap<std::string, std::string> &dirMap)
{
    return ERR_OK;
}

ErrCode InstalldClient::ExtractEncryptedSoFiles(const std::string &hapPath, const std::string &realSoFilesPath,
    const std::string &cpuAbi, const std::string &tmpSoPath, int32_t uid)
{
    return ERR_OK;
}

ErrCode InstalldClient::VerifyCodeSignatureForHap(const CodeSignatureParam &codeSignatureParam)
{
    return ERR_OK;
}

ErrCode InstalldClient::DeliverySignProfile(const std::string &bundleName, int32_t profileBlockLength,
    const unsigned char *profileBlock)
{
    return ERR_OK;
}

ErrCode InstalldClient::RemoveSignProfile(const std::string &bundleName)
{
    return ERR_OK;
}

ErrCode InstalldClient::SetEncryptionPolicy(int32_t uid, const std::string &bundleName,
    const int32_t userId, std::string &keyId)
{
    return ERR_OK;
}

ErrCode InstalldClient::DeleteEncryptionKeyId(const std::string &keyId)
{
    return ERR_OK;
}

ErrCode InstalldClient::RemoveExtensionDir(int32_t userId, const std::vector<std::string> &extensionBundleDirs)
{
    return ERR_OK;
}

ErrCode InstalldClient::IsExistExtensionDir(int32_t userId, const std::string &extensionBundleDir, bool &isExist)
{
    return ERR_OK;
}

ErrCode InstalldClient::CreateExtensionDataDir(const CreateDirParam &createDirParam)
{
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
