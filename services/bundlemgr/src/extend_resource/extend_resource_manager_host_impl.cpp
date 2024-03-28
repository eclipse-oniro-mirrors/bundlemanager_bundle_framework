/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "extend_resource_manager_host_impl.h"

#include <fcntl.h>
#include <unistd.h>

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_data_mgr.h"
#include "bundle_install_checker.h"
#include "bundle_mgr_service.h"
#include "bundle_parser.h"
#include "bundle_permission_mgr.h"
#include "bundle_resource_helper.h"
#include "bundle_util.h"
#include "installd_client.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string SEPARATOR = "/";

bool IsFileNameValid(const std::string &fileName)
{
    if (fileName.find("..") != std::string::npos
        || fileName.find("/") != std::string::npos
        || fileName.find("\\") != std::string::npos
        || fileName.find("%") != std::string::npos) {
        return false;
    }
    return true;
}

bool IsValidPath(const std::string &path)
{
    if (path.find("..") != std::string::npos) {
        return false;
    }
    return true;
}

std::string GetFileName(const std::string &sourcePath)
{
    size_t pos = sourcePath.find_last_of(SEPARATOR);
    if (pos == std::string::npos) {
        APP_LOGE("invalid sourcePath %{public}s.", sourcePath.c_str());
        return sourcePath;
    }
    return sourcePath.substr(pos + 1);
}

std::string BuildResourcePath(const std::string &bundleName)
{
    std::string filePath;
    filePath.append(Constants::BUNDLE_CODE_DIR).append(Constants::PATH_SEPARATOR)
        .append(bundleName).append(Constants::PATH_SEPARATOR)
        .append(Constants::EXT_RESOURCE_FILE_PATH).append(Constants::PATH_SEPARATOR);
    return filePath;
}

void ConvertToExtendResourceInfo(
    const std::string &bundleName,
    const InnerBundleInfo &innerBundleInfo,
    ExtendResourceInfo &extendResourceInfo)
{
    extendResourceInfo.moduleName = innerBundleInfo.GetCurModuleName();
    extendResourceInfo.iconId = innerBundleInfo.GetIconId();
    std::string path = BuildResourcePath(bundleName);
    path.append(extendResourceInfo.moduleName).append(Constants::EXT_RESOURCE_FILE_SUFFIX);
    extendResourceInfo.filePath = path;
}
}
ExtendResourceManagerHostImpl::ExtendResourceManagerHostImpl()
{
    APP_LOGI("create ExtendResourceManagerHostImpl.");
}

ExtendResourceManagerHostImpl::~ExtendResourceManagerHostImpl()
{
    APP_LOGI("destroy ExtendResourceManagerHostImpl.");
}

ErrCode ExtendResourceManagerHostImpl::AddExtResource(
    const std::string &bundleName, const std::vector<std::string> &filePaths)
{
    ErrCode ret = BeforeAddExtResource(bundleName, filePaths);
    CHECK_RESULT(ret, "BeforeAddExtResource failed %{public}d");
    ret = ProcessAddExtResource(bundleName, filePaths);
    CHECK_RESULT(ret, "InnerEnableDynamicIcon failed %{public}d");
    return ERR_OK;
}

ErrCode ExtendResourceManagerHostImpl::BeforeAddExtResource(
    const std::string &bundleName, const std::vector<std::string> &filePaths)
{
    if (bundleName.empty()) {
        APP_LOGE("fail to AddExtResource due to bundleName is empty.");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    if (filePaths.empty()) {
        APP_LOGE("fail to AddExtResource due to filePaths is empty.");
        return ERR_EXT_RESOURCE_MANAGER_INVALID_PATH_FAILED;
    }

    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("Non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }

    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(
        Constants::PERMISSION_INSTALL_BUNDLE)) {
        APP_LOGE("verify permission failed");
        return ERR_APPEXECFWK_PERMISSION_DENIED;
    }

    for (const auto &filePath: filePaths) {
        if (!CheckFileParam(filePath)) {
            APP_LOGE("CheckFile failed.");
            return ERR_EXT_RESOURCE_MANAGER_INVALID_PATH_FAILED;
        }
    }

    return ERR_OK;
}

bool ExtendResourceManagerHostImpl::CheckFileParam(const std::string &filePath)
{
    if (!IsValidPath(filePath)) {
        APP_LOGE("CheckFile filePath(%{public}s) failed due to invalid path", filePath.c_str());
        return false;
    }
    if (!BundleUtil::CheckFileType(filePath, Constants::EXT_RESOURCE_FILE_SUFFIX)) {
        APP_LOGE("CheckFile filePath(%{public}s) failed due to suffix error.", filePath.c_str());
        return false;
    }
    if (!BundleUtil::StartWith(filePath, Constants::HAP_COPY_PATH)) {
        APP_LOGE("CheckFile filePath(%{public}s) failed due to prefix error.", filePath.c_str());
        return false;
    }
    return true;
}

ErrCode ExtendResourceManagerHostImpl::ProcessAddExtResource(
    const std::string &bundleName, const std::vector<std::string> &filePaths)
{
    InnerBundleInfo info;
    if (!GetInnerBundleInfo(bundleName, info)) {
        APP_LOGE("GetInnerBundleInfo failed %{public}s.", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    std::vector<std::string> newFilePaths;
    ErrCode ret = CopyToTempDir(bundleName, filePaths, newFilePaths);
    CHECK_RESULT(ret, "CopyToTempDir failed %{public}d");

    std::vector<ExtendResourceInfo> extendResourceInfos;
    if (ParseExtendResourceFile(bundleName, newFilePaths, extendResourceInfos) != ERR_OK) {
        APP_LOGE("parse %{public}s extendResource failed", bundleName.c_str());
        RollBack(newFilePaths);
        return ERR_EXT_RESOURCE_MANAGER_PARSE_FILE_FAILED;
    }

    InnerSaveExtendResourceInfo(bundleName, newFilePaths, extendResourceInfos);
    return ERR_OK;
}

void ExtendResourceManagerHostImpl::InnerSaveExtendResourceInfo(
    const std::string &bundleName,
    const std::vector<std::string> &filePaths,
    const std::vector<ExtendResourceInfo> &extendResourceInfos)
{
    ErrCode ret = ERR_OK;
    std::vector<ExtendResourceInfo> newExtendResourceInfos;
    for (uint32_t i = 0; i < filePaths.size(); ++i) {
        ret = InstalldClient::GetInstance()->MoveFile(
            filePaths[i], extendResourceInfos[i].filePath);
        if (ret != ERR_OK) {
            APP_LOGW("MoveFile %{public}s file failed %{public}d",
                extendResourceInfos[i].moduleName.c_str(), ret);
            continue;
        }

        newExtendResourceInfos.emplace_back(extendResourceInfos[i]);
    }
    UpateExtResourcesDb(bundleName, newExtendResourceInfos);
}

ErrCode ExtendResourceManagerHostImpl::ParseExtendResourceFile(
    const std::string &bundleName,
    const std::vector<std::string> &filePaths,
    std::vector<ExtendResourceInfo> &extendResourceInfos)
{
    BundleInstallChecker bundleChecker;
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    ErrCode ret = bundleChecker.CheckMultipleHapsSignInfo(filePaths, hapVerifyRes);
    CHECK_RESULT(ret, "Check sign failed %{public}d");

    for (uint32_t i = 0; i < filePaths.size(); ++i) {
        BundleParser bundleParser;
        InnerBundleInfo innerBundleInfo;
        ErrCode result = bundleParser.Parse(filePaths[i], innerBundleInfo);
        if (result != ERR_OK) {
            APP_LOGE("parse bundle info %{public}s failed, error: %{public}d",
                filePaths[i].c_str(), result);
            return result;
        }

        ExtendResourceInfo extendResourceInfo;
        ConvertToExtendResourceInfo(bundleName, innerBundleInfo, extendResourceInfo);
        extendResourceInfos.emplace_back(extendResourceInfo);
    }

    return ERR_OK;
}

ErrCode ExtendResourceManagerHostImpl::MkdirIfNotExist(const std::string &dir)
{
    bool isDirExist = false;
    ErrCode result = InstalldClient::GetInstance()->IsExistDir(dir, isDirExist);
    if (result != ERR_OK) {
        APP_LOGE("Check if dir exist failed %{public}d", result);
        return result;
    }
    if (!isDirExist) {
        result = InstalldClient::GetInstance()->CreateBundleDir(dir);
        if (result != ERR_OK) {
            APP_LOGE("Create dir failed %{public}d", result);
            return result;
        }
    }
    return result;
}

ErrCode ExtendResourceManagerHostImpl::CopyToTempDir(const std::string &bundleName,
    const std::vector<std::string> &oldFilePaths, std::vector<std::string> &newFilePaths)
{
    for (const auto &oldFile : oldFilePaths) {
        std::string tempFile = BuildResourcePath(bundleName);
        ErrCode ret = MkdirIfNotExist(tempFile);
        if (ret != ERR_OK) {
            APP_LOGE("mkdir fileDir %{public}s failed %{public}d", tempFile.c_str(), ret);
            RollBack(newFilePaths);
            return ret;
        }
        tempFile.append(GetFileName(oldFile));
        ret = InstalldClient::GetInstance()->MoveFile(oldFile, tempFile);
        if (ret != ERR_OK) {
            APP_LOGE("MoveFile file %{public}s failed %{public}d", tempFile.c_str(), ret);
            RollBack(newFilePaths);
            return ret;
        }
        newFilePaths.emplace_back(tempFile);
    }
    return ERR_OK;
}

bool ExtendResourceManagerHostImpl::GetInnerBundleInfo(
    const std::string &bundleName, InnerBundleInfo &info)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return false;
    }
    return dataMgr->FetchInnerBundleInfo(bundleName, info);
}

bool ExtendResourceManagerHostImpl::UpateExtResourcesDb(const std::string &bundleName,
    const std::vector<ExtendResourceInfo> &extendResourceInfos)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return false;
    }
    return dataMgr->UpateExtResources(bundleName, extendResourceInfos);
}

bool ExtendResourceManagerHostImpl::RemoveExtResourcesDb(const std::string &bundleName,
    const std::vector<std::string> &moduleNames)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return false;
    }
    return dataMgr->RemoveExtResources(bundleName, moduleNames);
}

void ExtendResourceManagerHostImpl::RollBack(const std::vector<std::string> &filePaths)
{
    for (const auto &filePath : filePaths) {
        ErrCode result = InstalldClient::GetInstance()->RemoveDir(filePath);
        if (result != ERR_OK) {
            APP_LOGE("Remove failed %{public}s.", filePath.c_str());
        }
    }
}

ErrCode ExtendResourceManagerHostImpl::RemoveExtResource(
    const std::string &bundleName, const std::vector<std::string> &moduleNames)
{
    if (bundleName.empty()) {
        APP_LOGE("fail to RemoveExtResource due to bundleName is empty.");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    if (moduleNames.empty()) {
        APP_LOGE("fail to RemoveExtResource due to moduleName is empty.");
        return ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST;
    }

    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("Non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }

    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({
        Constants::PERMISSION_INSTALL_BUNDLE, Constants::PERMISSION_UNINSTALL_BUNDLE})) {
        APP_LOGE("verify permission failed");
        return ERR_APPEXECFWK_PERMISSION_DENIED;
    }

    std::vector<ExtendResourceInfo> extendResourceInfos;
    ErrCode ret = CheckModuleExist(bundleName, moduleNames, extendResourceInfos);
    CHECK_RESULT(ret, "Check mpdule exist failed %{public}d");
    InnerRemoveExtendResources(bundleName, moduleNames, extendResourceInfos);
    return ERR_OK;
}

void ExtendResourceManagerHostImpl::InnerRemoveExtendResources(
    const std::string &bundleName, const std::vector<std::string> &moduleNames,
    std::vector<ExtendResourceInfo> &extResourceInfos)
{
    for (const auto &extResourceInfo : extResourceInfos) {
        ErrCode result = InstalldClient::GetInstance()->RemoveDir(extResourceInfo.filePath);
        if (result != ERR_OK) {
            APP_LOGE("Remove failed %{public}s.", extResourceInfo.filePath.c_str());
        }
    }
    RemoveExtResourcesDb(bundleName, moduleNames);
}

ErrCode ExtendResourceManagerHostImpl::CheckModuleExist(
    const std::string &bundleName, const std::vector<std::string> &moduleNames,
    std::vector<ExtendResourceInfo> &collectorExtResourceInfos)
{
    InnerBundleInfo info;
    if (!GetInnerBundleInfo(bundleName, info)) {
        APP_LOGE("GetInnerBundleInfo failed %{public}s.", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    std::map<std::string, ExtendResourceInfo> extendResourceInfos = info.GetExtendResourceInfos();
    for (const auto &moduleName : moduleNames) {
        auto iter = extendResourceInfos.find(moduleName);
        if (iter == extendResourceInfos.end()) {
            APP_LOGE("Module not exist %{public}s.", moduleName.c_str());
            return ERR_EXT_RESOURCE_MANAGER_REMOVE_EXT_RESOURCE_FAILED;
        }

        collectorExtResourceInfos.emplace_back(iter->second);
    }
    return ERR_OK;
}

ErrCode ExtendResourceManagerHostImpl::GetExtResource(
    const std::string &bundleName, std::vector<std::string> &moduleNames)
{
    if (bundleName.empty()) {
        APP_LOGE("fail to GetExtResource due to param is empty.");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("Non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }

    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({
        Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED, Constants::PERMISSION_GET_BUNDLE_INFO})) {
        APP_LOGE("verify permission failed");
        return ERR_APPEXECFWK_PERMISSION_DENIED;
    }

    InnerBundleInfo info;
    if (!GetInnerBundleInfo(bundleName, info)) {
        APP_LOGE("GetInnerBundleInfo failed %{public}s.", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    std::map<std::string, ExtendResourceInfo> extendResourceInfos = info.GetExtendResourceInfos();
    if (extendResourceInfos.empty()) {
        APP_LOGE("%{public}s no extend Resources", bundleName.c_str());
        return ERR_EXT_RESOURCE_MANAGER_GET_EXT_RESOURCE_FAILED;
    }

    for (const auto &extendResourceInfo : extendResourceInfos) {
        moduleNames.emplace_back(extendResourceInfo.first);
    }

    return ERR_OK;
}

ErrCode ExtendResourceManagerHostImpl::EnableDynamicIcon(
    const std::string &bundleName, const std::string &moduleName)
{
    APP_LOGI("EnableDynamicIcon %{public}s, %{public}s",
        bundleName.c_str(), moduleName.c_str());
    if (bundleName.empty()) {
        APP_LOGE("fail to EnableDynamicIcon due to bundleName is empty.");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    if (moduleName.empty()) {
        APP_LOGE("fail to EnableDynamicIcon due to moduleName is empty.");
        return ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST;
    }

    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("Non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }

    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(
        Constants::PERMISSION_ACCESS_DYNAMIC_ICON)) {
        APP_LOGE("verify permission failed");
        return ERR_APPEXECFWK_PERMISSION_DENIED;
    }

    ExtendResourceInfo extendResourceInfo;
    ErrCode ret = GetExtendResourceInfo(bundleName, moduleName, extendResourceInfo);
    CHECK_RESULT(ret, "GetExtendResourceInfo failed %{public}d");
    if (!ParseBundleResource(bundleName, extendResourceInfo)) {
        APP_LOGE("%{public}s no extend Resources", bundleName.c_str());
        return ERR_EXT_RESOURCE_MANAGER_ENABLE_DYNAMIC_ICON_FAILED;
    }

    SaveCurDynamicIcon(bundleName, moduleName);
    SendBroadcast(bundleName, true);
    return ERR_OK;
}

void ExtendResourceManagerHostImpl::SaveCurDynamicIcon(
    const std::string &bundleName, const std::string &moduleName)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return;
    }

    dataMgr->UpateCurDynamicIconModule(bundleName, moduleName);
}

void ExtendResourceManagerHostImpl::SendBroadcast(
    const std::string &bundleName, bool isEnableDynamicIcon)
{
    std::shared_ptr<BundleCommonEventMgr> commonEventMgr = std::make_shared<BundleCommonEventMgr>();
    commonEventMgr->NotifyDynamicIconEvent(bundleName, isEnableDynamicIcon);
}

bool ExtendResourceManagerHostImpl::ParseBundleResource(
    const std::string &bundleName, const ExtendResourceInfo &extendResourceInfo)
{
    APP_LOGI("ParseBundleResource %{public}s", bundleName.c_str());
    std::string icon;
    if (!BundleResourceHelper::ParseIconResourceByPath(
        extendResourceInfo.filePath, extendResourceInfo.iconId, icon)) {
        APP_LOGW("ParseIconResourceByPath failed, bundleName:%{public}s", bundleName.c_str());
        return false;
    }

    if (icon.empty()) {
        APP_LOGE("icon is empty, bundleName:%{public}s", bundleName.c_str());
        return false;
    }

    if (!BundleResourceHelper::UpdateBundleIcon(bundleName, icon)) {
        APP_LOGE("UpdateBundleIcon failed, bundleName:%{public}s", bundleName.c_str());
        return false;
    }

    return true;
}

ErrCode ExtendResourceManagerHostImpl::GetExtendResourceInfo(const std::string &bundleName,
    const std::string &moduleName, ExtendResourceInfo &extendResourceInfo)
{
    InnerBundleInfo info;
    if (!GetInnerBundleInfo(bundleName, info)) {
        APP_LOGE("GetInnerBundleInfo failed %{public}s.", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    std::map<std::string, ExtendResourceInfo> extendResourceInfos = info.GetExtendResourceInfos();
    if (extendResourceInfos.empty()) {
        APP_LOGE("%{public}s no extend Resources", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST;
    }
    auto iter = extendResourceInfos.find(moduleName);
    if (iter == extendResourceInfos.end()) {
        APP_LOGE("%{public}s no %{public}s extend Resources", bundleName.c_str(), moduleName.c_str());
        return ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST;
    }
    extendResourceInfo = iter->second;
    return ERR_OK;
}

ErrCode ExtendResourceManagerHostImpl::DisableDynamicIcon(const std::string &bundleName)
{
    APP_LOGI("DisableDynamicIcon %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        APP_LOGE("fail to DisableDynamicIcon due to param is empty.");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("Non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }

    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(
        Constants::PERMISSION_ACCESS_DYNAMIC_ICON)) {
        APP_LOGE("verify permission failed");
        return ERR_APPEXECFWK_PERMISSION_DENIED;
    }

    InnerBundleInfo info;
    if (!GetInnerBundleInfo(bundleName, info)) {
        APP_LOGE("GetInnerBundleInfo failed %{public}s.", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    std::string curDynamicModule = info.GetCurDynamicIconModule();
    if (curDynamicModule.empty()) {
        APP_LOGE("%{public}s no enabled dynamic icon", bundleName.c_str());
        return ERR_EXT_RESOURCE_MANAGER_DISABLE_DYNAMIC_ICON_FAILED;
    }

    SaveCurDynamicIcon(bundleName, "");
    ResetBunldleResourceIcon(bundleName);
    SendBroadcast(bundleName, false);
    return ERR_OK;
}

bool ExtendResourceManagerHostImpl::ResetBunldleResourceIcon(const std::string &bundleName)
{
    return BundleResourceHelper::ResetBunldleResourceIcon(bundleName);
}

ErrCode ExtendResourceManagerHostImpl::GetDynamicIcon(
    const std::string &bundleName, std::string &moudleName)
{
    if (bundleName.empty()) {
        APP_LOGE("fail to GetDynamicIcon due to param is empty.");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("Non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }

    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({
        Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED, Constants::PERMISSION_GET_BUNDLE_INFO})) {
        APP_LOGE("verify permission failed");
        return ERR_APPEXECFWK_PERMISSION_DENIED;
    }

    InnerBundleInfo info;
    if (!GetInnerBundleInfo(bundleName, info)) {
        APP_LOGE("GetInnerBundleInfo failed %{public}s.", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    std::string curDynamicModule = info.GetCurDynamicIconModule();
    if (curDynamicModule.empty()) {
        APP_LOGE("%{public}s no enabled dynamic icon", bundleName.c_str());
        return ERR_EXT_RESOURCE_MANAGER_GET_DYNAMIC_ICON_FAILED;
    }

    moudleName = curDynamicModule;
    return ERR_OK;
}

ErrCode ExtendResourceManagerHostImpl::CreateFd(
    const std::string &fileName, int32_t &fd, std::string &path)
{
    if (fileName.empty()) {
        APP_LOGE("fail to CreateFd due to param is empty.");
        return ERR_EXT_RESOURCE_MANAGER_CREATE_FD_FAILED;
    }
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("Non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(
        Constants::PERMISSION_INSTALL_BUNDLE)) {
        APP_LOGE("verify permission failed");
        return ERR_APPEXECFWK_PERMISSION_DENIED;
    }
    if (!BundleUtil::CheckFileType(fileName, Constants::EXT_RESOURCE_FILE_SUFFIX)) {
        APP_LOGE("not hsp file.");
        return ERR_EXT_RESOURCE_MANAGER_CREATE_FD_FAILED;
    }
    if (!IsFileNameValid(fileName)) {
        APP_LOGE("invalid fileName");
        return ERR_EXT_RESOURCE_MANAGER_CREATE_FD_FAILED;
    }
    std::string tmpDir = BundleUtil::CreateInstallTempDir(
        ++id_, DirType::EXT_RESOURCE_FILE_DIR);
    if (tmpDir.empty()) {
        APP_LOGE("create tmp dir failed.");
        return ERR_EXT_RESOURCE_MANAGER_CREATE_FD_FAILED;
    }
    path = tmpDir + fileName;
    if ((fd = BundleUtil::CreateFileDescriptor(path, 0)) < 0) {
        APP_LOGE("create file descriptor failed.");
        BundleUtil::DeleteDir(tmpDir);
        return ERR_EXT_RESOURCE_MANAGER_CREATE_FD_FAILED;
    }
    return ERR_OK;
}
} // AppExecFwk
} // namespace OHOS
