/*
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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
int32_t retIndex = 0;
std::vector<int32_t> retList = {};
bool g_isDir = false;
ErrCode g_errCode = ERR_OK;
bool g_vectorEmpty = true;
ErrCode g_testErrCode = ERR_OK;
uint64_t g_inodeCount = 0;

void SetTestReturnValue(const std::vector<int32_t> &list)
{
    retList = list;
    retIndex = 0;
}

void SetInodeCountValue(uint64_t count, uint32_t value)
{
    g_inodeCount = count;
    g_testErrCode = value;
}

void SetIsDirForTest(bool value)
{
    g_isDir = value;
}

void SetErrCodeForTest(ErrCode value)
{
    g_errCode = value;
}

void SetVectorEmptyForTest(bool value)
{
    g_vectorEmpty = value;
}

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

ErrCode InstalldClient::ExtractHnpFiles(const std::map<std::string, std::string> &hnpPackageMap,
    const ExtractParam &extractParam)
{
    return 0;
}

ErrCode InstalldClient::ProcessBundleInstallNative(const InstallHnpParam &installHnpParam)
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

ErrCode InstalldClient::DeleteUninstallTmpDirs(const std::vector<std::string> &dirs)
{
    return ERR_OK;
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

ErrCode InstalldClient::RemoveBundleDataDir(
    const std::string &bundleName, const int32_t userId, bool isAtomicService, const bool async)
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

ErrCode InstalldClient::RemoveDir(const std::string &dir, bool async)
{
    if (dir.empty()) {
        return -1;
    }
    return 0;
}

ErrCode InstalldClient::GetDiskUsage(const std::string &dir, int64_t &statSize, bool isRealPath)
{
    return 0;
}

ErrCode InstalldClient::GetDiskUsageFromPath(const std::vector<std::string> &path, int64_t &statSize,
    int64_t timeoutMs)
{
    return 0;
}

ErrCode InstalldClient::GetBundleInodeCount(int32_t uid, uint64_t &inodeCount)
{
    if (g_testErrCode != ERR_OK) {
        inodeCount = 0;
        return g_testErrCode;
    }
    inodeCount = g_inodeCount;
    return ERR_OK;
}

ErrCode InstalldClient::CleanBundleDataDir(const std::string &bundleDir)
{
    return 0;
}

ErrCode InstalldClient::CleanBundleDirs(const std::vector<std::string> &dirs, bool keepParent)
{
    return 0;
}

ErrCode InstalldClient::CleanBundleDataDirByName(const std::string &bundleName, const int userid, const int appIndex,
    const bool isAtomicService)
{
    if (bundleName.empty()) {
        return -1;
    }
    return 0;
}

ErrCode InstalldClient::GetBundleStats(const std::string &bundleName, const int32_t userId,
    std::vector<int64_t> &bundleStats, const std::unordered_set<int32_t> &uids,
    const int32_t appIndex, const uint32_t statFlag, const std::vector<std::string> &moduleNameList)
{
    return 0;
}

ErrCode InstalldClient::BatchGetBundleStats(const std::vector<std::string> &bundleNames,
    const std::unordered_map<std::string, std::unordered_set<int32_t>> &uidMap,
    std::vector<BundleStorageStats> &bundleStats)
{
    return 0;
}

ErrCode InstalldClient::GetAllBundleStats(const int32_t userId,
    std::vector<int64_t> &bundleStats, const std::vector<int32_t> &uids)
{
    return 0;
}

ErrCode InstalldClient::LoadInstalls()
{
    return 0;
}

ErrCode InstalldClient::SetDirApl(const std::string &dir, const std::string &bundleName, const std::string &apl,
    bool isPreInstallApp, bool debug, int32_t uid)
{
    if (retIndex >= 0 && retIndex < static_cast<int32_t>(retList.size())) {
        return retList[retIndex++];
    }
    return 0;
}

ErrCode InstalldClient::SetDirsApl(const CreateDirParam &createDirParam, bool isExtensionDir)
{
    if (createDirParam.bundleName.empty() || createDirParam.userId < 0
        || createDirParam.uid < 0 || createDirParam.extensionDirs.empty()) {
        APP_LOGE("params are invalid");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }

    return 0;
}
ErrCode InstalldClient::SetArkStartupCacheApl(const std::string &dir)
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

sptr<IInstalld> InstalldClient::GetInstalldProxy()
{
    return nullptr;
}

ErrCode InstalldClient::ScanDir(
    const std::string &dir, ScanMode scanMode, ResultMode resultMode, std::vector<std::string> &paths)
{
    if (!g_vectorEmpty) {
        paths.emplace_back("");
    }
    return 0;
}

ErrCode InstalldClient::MoveFile(const std::string &oldPath, const std::string &newPath)
{
    return 0;
}

ErrCode InstalldClient::RenameFile(const std::string &oldPath, const std::string &newPath)
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
    if (retIndex >= 0 && retIndex < static_cast<int32_t>(retList.size())) {
        return retList[retIndex++];
    }
    return 0;
}

ErrCode InstalldClient::GetFileStat(const std::string &file, FileStat &fileStat)
{
    fileStat.isDir = g_isDir;
    return g_errCode;
}

ErrCode InstalldClient::ChangeFileStat(const std::string &file, FileStat &fileStat)
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
    if (retIndex >= 0 && retIndex < static_cast<int32_t>(retList.size())) {
        ErrCode ret = retList[retIndex++];
        if (retIndex >= 0 && retIndex < static_cast<int32_t>(retList.size())) {
            isExist = retList[retIndex++];
        }
        return ret;
    }
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
    return GetInstalldProxy() != nullptr;
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

ErrCode InstalldClient::AddCertAndEnableKey(const std::string &certPath, const std::string &certContent)
{
    return ERR_OK;
}

ErrCode InstalldClient::SetEncryptionPolicy(const EncryptionParam &encryptionParam, std::string &keyId)
{
    if (retIndex >= 0 && retIndex < static_cast<int32_t>(retList.size())) {
        return retList[retIndex++];
    }
    return ERR_OK;
}

ErrCode InstalldClient::DeleteEncryptionKeyId(const EncryptionParam &encryptionParam)
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

ErrCode InstalldClient::MigrateData(const std::vector<std::string> &sourcePaths, const std::string &destinationPath)
{
    if (sourcePaths.empty()) {
        return ERR_BUNDLE_MANAGER_MIGRATE_DATA_SOURCE_PATH_INVALID;
    }
    if (destinationPath.empty()) {
        return ERR_BUNDLE_MANAGER_MIGRATE_DATA_DESTINATION_PATH_INVALID;
    }
    return ERR_OK;
}

ErrCode InstalldClient::GetExtensionSandboxTypeList(std::vector<std::string> &typeList)
{
    return ERR_OK;
}

ErrCode InstalldClient::AddUserDirDeleteDfx(int32_t userId)
{
    return ERR_OK;
}

ErrCode InstalldClient::MoveHapToCodeDir(const std::string &originPath, const std::string &targetPath)
{
    return ERR_OK;
}

ErrCode InstalldClient::CreateDataGroupDirs(const std::vector<CreateDirParam> &params)
{
    return ERR_OK;
}

ErrCode InstalldClient::DeleteDataGroupDirs(const std::vector<std::string> &uuidList, int32_t userId)
{
    return ERR_OK;
}

ErrCode InstalldClient::ClearDir(const std::string &dir)
{
    return ERR_OK;
}

ErrCode InstalldClient::HashSoFile(const std::string& soPath, uint32_t catchSoNum, uint64_t catchSoMaxSize,
    std::vector<std::string> &soName, std::vector<std::string> &soHash)
{
    return ERR_OK;
}

ErrCode InstalldClient::HashFiles(const std::vector<std::string> &files, std::vector<std::string> &filesHash)
{
    return ERR_OK;
}

ErrCode InstalldClient::RestoreconPath(const std::string &path)
{
    return ERR_OK;
}

ErrCode InstalldClient::ResetBmsDBSecurity()
{
    return ERR_OK;
}

ErrCode InstalldClient::CopyDir(const std::string &sourceDir, const std::string &destinationDir)
{
    return ERR_OK;
}

ErrCode InstalldClient::DeleteCertAndRemoveKey(const std::vector<std::string> &certPaths)
{
    return ERR_OK;
}

ErrCode InstalldClient::SetFileConForce(const std::vector<std::string> &paths, const CreateDirParam &createDirParam)
{
    return 0;
}

ErrCode InstalldClient::StopSetFileCon(const CreateDirParam &createDirParam, int32_t reason)
{
    return 0;
}
}  // namespace AppExecFwk
}  // namespace OHOS
