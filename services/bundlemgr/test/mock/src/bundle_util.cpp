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

#include "bundle_util.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
}

std::mutex BundleUtil::g_mutex;

#ifdef BUNDLE_FRAMEWORK_BUNDLE_UTIL_RETURN_TRUE
ErrCode BundleUtil::CheckFilePath(const std::string &bundlePath, std::string &realPath)
{
    return ERR_OK;
}

ErrCode BundleUtil::CheckFilePath(const std::vector<std::string> &bundlePaths, std::vector<std::string> &realPaths)
{
    return ERR_OK;
}

bool BundleUtil::CheckFileType(const std::string &fileName, const std::string &extensionName)
{
    return true;
}

bool BundleUtil::CheckFileName(const std::string &fileName)
{
    return true;
}

bool BundleUtil::CheckFileSize(const std::string &bundlePath, const int64_t fileSize)
{
    return true;
}

bool BundleUtil::CheckSystemSize(const std::string &bundlePath, const std::string &diskPath)
{
    return true;
}

bool BundleUtil::CheckSystemFreeSize(const std::string &path, int64_t size)
{
    return true;
}

bool BundleUtil::CheckSystemSizeAndHisysEvent(const std::string &path, const std::string &fileName)
{
    return true;
}

bool BundleUtil::GetHapFilesFromBundlePath(const std::string& currentBundlePath, std::vector<std::string>& hapFileList)
{
    return true;
}

int64_t BundleUtil::GetCurrentTime()
{
    int64_t time = 0;
    return time;
}

int64_t BundleUtil::GetCurrentTimeMs()
{
    int64_t time = 1000 * 60 * 30 + 10;
    return time;
}

int64_t BundleUtil::GetCurrentTimeNs()
{
    int64_t time = 0;
    return time;
}

void BundleUtil::DeviceAndNameToKey(
    const std::string &deviceId, const std::string &bundleName, std::string &key)
{
}

bool BundleUtil::KeyToDeviceAndName(
    const std::string &key, std::string &deviceId, std::string &bundleName)
{
    return true;
}

int32_t BundleUtil::GetUserIdByCallingUid()
{
    return 0;
}

int32_t BundleUtil::GetUserIdByUid(int32_t uid)
{
    return 0;
}

void BundleUtil::MakeFsConfig(const std::string &bundleName, int32_t bundleId, const std::string &configPath)
{
}

void BundleUtil::RemoveFsConfig(const std::string &bundleName, const std::string &configPath)
{
}

std::string BundleUtil::CreateTempDir(const std::string &tempDir)
{
    return "";
}

std::string BundleUtil::CreateInstallTempDir(uint32_t installerId, const DirType &type)
{
    return "";
}

std::string BundleUtil::CreateSharedBundleTempDir(uint32_t installerId, uint32_t index)
{
    return "";
}

int32_t BundleUtil::CreateFileDescriptor(const std::string &bundlePath, long long offset)
{
    return 0;
}

int32_t BundleUtil::CreateFileDescriptorForReadOnly(const std::string &bundlePath, long long offset)
{
    return 0;
}

void BundleUtil::CloseFileDescriptor(std::vector<int32_t> &fdVec)
{
}

bool BundleUtil::IsExistFile(const std::string &path)
{
    return true;
}

bool BundleUtil::IsExistFileNoLog(const std::string &path)
{
    return true;
}

bool BundleUtil::IsExistDir(const std::string &path)
{
    return true;
}

bool BundleUtil::IsExistDirNoLog(const std::string &path)
{
    return true;
}

bool BundleUtil::IsPathInformationConsistent(const std::string &path, int32_t uid, int32_t gid)
{
    return true;
}

int64_t BundleUtil::CalculateFileSize(const std::string &bundlePath)
{
    int64_t res = 0;
    return res;
}

bool BundleUtil::RenameFile(const std::string &oldPath, const std::string &newPath)
{
    return true;
}

bool BundleUtil::DeleteDir(const std::string &path)
{
    return true;
}

bool BundleUtil::IsUtd(const std::string &param)
{
    return true;
}

bool BundleUtil::IsSpecificUtd(const std::string &param)
{
    return true;
}

std::vector<std::string> BundleUtil::GetUtdVectorByMimeType(const std::string &mimeType)
{
    std::vector<std::string> utdVector;
    return utdVector;
}

std::string BundleUtil::GetBoolStrVal(bool val)
{
    return val ? "true" : "false";
}

bool BundleUtil::CopyFile(
    const std::string &sourceFile, const std::string &destinationFile)
{
    return true;
}

bool BundleUtil::CopyFileFast(const std::string &sourcePath, const std::string &destPath)
{
    return true;
}

Resource BundleUtil::GetResource(const std::string &bundleName, const std::string &moduleName, uint32_t resId)
{
    Resource resource;
    resource.bundleName = bundleName;
    resource.moduleName = moduleName;
    resource.id = resId;
    return resource;
}

bool BundleUtil::CreateDir(const std::string &dir)
{
    return true;
}

bool BundleUtil::RevertToRealPath(const std::string &sandBoxPath, const std::string &bundleName, std::string &realPath)
{
    return true;
}

bool BundleUtil::IsSandBoxPath(const std::string &path)
{
    return true;
}

bool BundleUtil::StartWith(const std::string &source, const std::string &prefix)
{
    return true;
}

bool BundleUtil::EndWith(const std::string &source, const std::string &suffix)
{
    return true;
}

int64_t BundleUtil::GetFileSize(const std::string &filePath)
{
    int64_t res = 0;
    return res;
}

std::string BundleUtil::CopyFileToSecurityDir(const std::string &filePath, const DirType &dirType,
    std::vector<std::string> &toDeletePaths, bool rename)
{
    return "";
}

std::string BundleUtil::GetAppInstallPrefix(const std::string &filePath, bool rename)
{
    return "";
}

void BundleUtil::RestoreAppInstallHaps()
{
}

void BundleUtil::RestoreHaps(const std::string &sourcePath, const std::string &bundleName, const std::string &userId)
{
}

void BundleUtil::DeleteTempDirs(const std::vector<std::string> &tempDirs)
{
}

std::string BundleUtil::GetHexHash(const std::string &s)
{
    return "";
}

void BundleUtil::RecursiveHash(std::string& s)
{
}

std::string BundleUtil::GenerateUuid()
{
    return "";
}

std::string BundleUtil::GenerateUuidByKey(const std::string &key)
{
    return "";
}

std::vector<uint8_t> BundleUtil::GenerateRandomNumbers(uint8_t size, uint8_t lRange, uint8_t rRange)
{
    std::vector<uint8_t> rangeV;
    return rangeV;
}

std::string BundleUtil::ExtractGroupIdByDevelopId(const std::string &developerId)
{
    return "";
}

std::string BundleUtil::ToString(const std::vector<std::string> &vector)
{
    return "";
}

std::string BundleUtil::GetNoDisablingConfigPath()
{
    return "";
}

uint32_t BundleUtil::ExtractNumberFromString(nlohmann::json &jsonObject, const std::string &key)
{
    return 0;
}

bool BundleUtil::StrToUint32(const std::string &str, uint32_t &value)
{
    return true;
}

std::string BundleUtil::ExtractStringFromJson(nlohmann::json &jsonObject, const std::string &key)
{
    return "";
}

std::unordered_map<std::string, std::string> BundleUtil::ParseMapFromJson(const std::string &jsonStr)
{
    std::unordered_map<std::string, std::string> result;
    return result;
}
#endif
#ifdef BUNDLE_FRAMEWORK_BUNDLE_UTIL_RETURN_FALSE
ErrCode BundleUtil::CheckFilePath(const std::string &bundlePath, std::string &realPath)
{
    return -1;
}

ErrCode BundleUtil::CheckFilePath(const std::vector<std::string> &bundlePaths, std::vector<std::string> &realPaths)
{
    return -1;
}

bool BundleUtil::CheckFileType(const std::string &fileName, const std::string &extensionName)
{
    return false;
}

bool BundleUtil::CheckFileName(const std::string &fileName)
{
    return false;
}

bool BundleUtil::CheckFileSize(const std::string &bundlePath, const int64_t fileSize)
{
    return false;
}

bool BundleUtil::CheckSystemSize(const std::string &bundlePath, const std::string &diskPath)
{
    return false;
}

bool BundleUtil::CheckSystemFreeSize(const std::string &path, int64_t size)
{
    return false;
}

bool BundleUtil::CheckSystemSizeAndHisysEvent(const std::string &path, const std::string &fileName)
{
    return false;
}

bool BundleUtil::GetHapFilesFromBundlePath(const std::string& currentBundlePath, std::vector<std::string>& hapFileList)
{
    return false;
}

int64_t BundleUtil::GetCurrentTime()
{
    int64_t time = 0;
    return time;
}

int64_t BundleUtil::GetCurrentTimeMs()
{
    int64_t time = 1000 * 60 * 30 + 10;
    return time;
}

int64_t BundleUtil::GetCurrentTimeNs()
{
    int64_t time = 0;
    return time;
}

void BundleUtil::DeviceAndNameToKey(
    const std::string &deviceId, const std::string &bundleName, std::string &key)
{
}

bool BundleUtil::KeyToDeviceAndName(
    const std::string &key, std::string &deviceId, std::string &bundleName)
{
    return false;
}

int32_t BundleUtil::GetUserIdByCallingUid()
{
    return 0;
}

int32_t BundleUtil::GetUserIdByUid(int32_t uid)
{
    return 0;
}

void BundleUtil::MakeFsConfig(const std::string &bundleName, int32_t bundleId, const std::string &configPath)
{
}

void BundleUtil::RemoveFsConfig(const std::string &bundleName, const std::string &configPath)
{
}

std::string BundleUtil::CreateTempDir(const std::string &tempDir)
{
    return "";
}

std::string BundleUtil::CreateInstallTempDir(uint32_t installerId, const DirType &type)
{
    return "";
}

std::string BundleUtil::CreateSharedBundleTempDir(uint32_t installerId, uint32_t index)
{
    return "";
}

int32_t BundleUtil::CreateFileDescriptor(const std::string &bundlePath, long long offset)
{
    return 0;
}

int32_t BundleUtil::CreateFileDescriptorForReadOnly(const std::string &bundlePath, long long offset)
{
    return 0;
}

void BundleUtil::CloseFileDescriptor(std::vector<int32_t> &fdVec)
{
}

bool BundleUtil::IsExistFile(const std::string &path)
{
    return false;
}

bool BundleUtil::IsExistFileNoLog(const std::string &path)
{
    return false;
}

bool BundleUtil::IsExistDir(const std::string &path)
{
    return false;
}

bool BundleUtil::IsExistDirNoLog(const std::string &path)
{
    return false;
}

bool BundleUtil::IsPathInformationConsistent(const std::string &path, int32_t uid, int32_t gid)
{
    return false;
}

int64_t BundleUtil::CalculateFileSize(const std::string &bundlePath)
{
    int64_t res = 0;
    return res;
}

bool BundleUtil::RenameFile(const std::string &oldPath, const std::string &newPath)
{
    return false;
}

bool BundleUtil::DeleteDir(const std::string &path)
{
    return false;
}

bool BundleUtil::IsUtd(const std::string &param)
{
    return false;
}

bool BundleUtil::IsSpecificUtd(const std::string &param)
{
    return false;
}

std::vector<std::string> BundleUtil::GetUtdVectorByMimeType(const std::string &mimeType)
{
    std::vector<std::string> utdVector;
    return utdVector;
}

std::string BundleUtil::GetBoolStrVal(bool val)
{
    return val ? "true" : "false";
}

bool BundleUtil::CopyFile(
    const std::string &sourceFile, const std::string &destinationFile)
{
    return false;
}

bool BundleUtil::CopyFileFast(const std::string &sourcePath, const std::string &destPath)
{
    return false;
}

Resource BundleUtil::GetResource(const std::string &bundleName, const std::string &moduleName, uint32_t resId)
{
    Resource resource;
    resource.bundleName = bundleName;
    resource.moduleName = moduleName;
    resource.id = resId;
    return resource;
}

bool BundleUtil::CreateDir(const std::string &dir)
{
    return false;
}

bool BundleUtil::RevertToRealPath(const std::string &sandBoxPath, const std::string &bundleName, std::string &realPath)
{
    return false;
}

bool BundleUtil::IsSandBoxPath(const std::string &path)
{
    return false;
}

bool BundleUtil::StartWith(const std::string &source, const std::string &prefix)
{
    return false;
}

bool BundleUtil::EndWith(const std::string &source, const std::string &suffix)
{
    return false;
}

int64_t BundleUtil::GetFileSize(const std::string &filePath)
{
    int64_t res = 0;
    return res;
}

std::string BundleUtil::CopyFileToSecurityDir(const std::string &filePath, const DirType &dirType,
    std::vector<std::string> &toDeletePaths, bool rename)
{
    return "";
}

std::string BundleUtil::GetAppInstallPrefix(const std::string &filePath, bool rename)
{
    return "";
}

void BundleUtil::RestoreAppInstallHaps()
{
}

void BundleUtil::RestoreHaps(const std::string &sourcePath, const std::string &bundleName, const std::string &userId)
{
}

void BundleUtil::DeleteTempDirs(const std::vector<std::string> &tempDirs)
{
}

std::string BundleUtil::GetHexHash(const std::string &s)
{
    return "";
}

void BundleUtil::RecursiveHash(std::string& s)
{
}

std::string BundleUtil::GenerateUuid()
{
    return "";
}

std::string BundleUtil::GenerateUuidByKey(const std::string &key)
{
    return "";
}

std::vector<uint8_t> BundleUtil::GenerateRandomNumbers(uint8_t size, uint8_t lRange, uint8_t rRange)
{
    std::vector<uint8_t> rangeV;
    return rangeV;
}

std::string BundleUtil::ExtractGroupIdByDevelopId(const std::string &developerId)
{
    return "";
}

std::string BundleUtil::ToString(const std::vector<std::string> &vector)
{
    return "";
}

std::string BundleUtil::GetNoDisablingConfigPath()
{
    return "";
}

uint32_t BundleUtil::ExtractNumberFromString(nlohmann::json &jsonObject, const std::string &key)
{
    return 0;
}

bool BundleUtil::StrToUint32(const std::string &str, uint32_t &value)
{
    return true;
}

std::string BundleUtil::ExtractStringFromJson(nlohmann::json &jsonObject, const std::string &key)
{
    return "";
}

std::unordered_map<std::string, std::string> BundleUtil::ParseMapFromJson(const std::string &jsonStr)
{
    std::unordered_map<std::string, std::string> result;
    return result;
}
#endif
}  // namespace AppExecFwk
}  // namespace OHOS
