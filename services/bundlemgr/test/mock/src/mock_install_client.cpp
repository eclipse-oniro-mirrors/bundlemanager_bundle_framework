/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

ErrCode InstalldClient::RenameModuleDir(const std::string &oldPath, const std::string &newPath)
{
    return 0;
}

ErrCode InstalldClient::CreateBundleDataDir(const CreateDirParam &createDirParam)
{
    return 0;
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

ErrCode InstalldClient::CleanBundleDataDir(const std::string &bundleDir)
{
    return 0;
}

ErrCode InstalldClient::GetBundleStats(
    const std::string &bundleName, const int32_t userId, std::vector<int64_t> &bundleStats)
{
    return 0;
}

ErrCode InstalldClient::SetDirApl(const std::string &dir, const std::string &bundleName, const std::string &apl,
    bool isPreInstallApp)
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

ErrCode InstalldClient::CopyFile(const std::string &oldPath, const std::string &newPath)
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
    const std::string &oldSoPath, const std::string &diffFilePath, const std::string &newSoPath)
{
    return 0;
}

ErrCode InstalldClient::IsExistDir(const std::string &dir, bool &isExist)
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

}  // namespace AppExecFwk
}  // namespace OHOS
