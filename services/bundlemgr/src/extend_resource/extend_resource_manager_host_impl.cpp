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

#include "account_helper.h"
#include "bundle_mgr_service.h"
#include "bundle_parser.h"
#include "bundle_permission_mgr.h"
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
#include "bundle_resource/bundle_resource_manager.h"
#include "bundle_resource/bundle_resource_parser.h"
#include "bundle_resource/resource_info.h"
#endif
#include "installd_client.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const char* SEPARATOR = "/";
constexpr const char* EXT_RESOURCE_FILE_SUFFIX = ".hsp";

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
        APP_LOGE("invalid sourcePath %{public}s", sourcePath.c_str());
        return sourcePath;
    }
    return sourcePath.substr(pos + 1);
}

std::string BuildResourcePath(const std::string &bundleName)
{
    std::string filePath;
    filePath.append(Constants::BUNDLE_CODE_DIR).append(ServiceConstants::PATH_SEPARATOR)
        .append(bundleName).append(ServiceConstants::PATH_SEPARATOR)
        .append(ServiceConstants::EXT_RESOURCE_FILE_PATH).append(ServiceConstants::PATH_SEPARATOR);
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
    path.append(extendResourceInfo.moduleName).append(EXT_RESOURCE_FILE_SUFFIX);
    extendResourceInfo.filePath = path;
}
}
ExtendResourceManagerHostImpl::ExtendResourceManagerHostImpl()
{
    APP_LOGI("create ExtendResourceManagerHostImpl");
}

ExtendResourceManagerHostImpl::~ExtendResourceManagerHostImpl()
{
    APP_LOGI("destroy ExtendResourceManagerHostImpl");
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
        APP_LOGE("fail to AddExtResource due to bundleName is empty");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    if (filePaths.empty()) {
        APP_LOGE("fail to AddExtResource due to filePaths is empty");
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
            APP_LOGE("CheckFile failed");
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
    if (!BundleUtil::CheckFileType(filePath, EXT_RESOURCE_FILE_SUFFIX)) {
        APP_LOGE("CheckFile filePath(%{public}s) failed due to suffix error", filePath.c_str());
        return false;
    }
    if (!BundleUtil::StartWith(filePath, ServiceConstants::HAP_COPY_PATH)) {
        APP_LOGE("CheckFile filePath(%{public}s) failed due to prefix error", filePath.c_str());
        return false;
    }
    return true;
}

ErrCode ExtendResourceManagerHostImpl::ProcessAddExtResource(
    const std::string &bundleName, const std::vector<std::string> &filePaths)
{
    InnerBundleInfo info;
    if (!GetInnerBundleInfo(bundleName, info)) {
        APP_LOGE("GetInnerBundleInfo failed %{public}s", bundleName.c_str());
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
            APP_LOGE("parse bundle info %{public}s failed, err %{public}d",
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
            APP_LOGE("Remove failed %{public}s", filePath.c_str());
        }
    }
}

ErrCode ExtendResourceManagerHostImpl::RemoveExtResource(
    const std::string &bundleName, const std::vector<std::string> &moduleNames)
{
    if (bundleName.empty()) {
        APP_LOGE("fail to RemoveExtResource due to bundleName is empty");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    if (moduleNames.empty()) {
        APP_LOGE("fail to RemoveExtResource due to moduleName is empty");
        return ERR_EXT_RESOURCE_MANAGER_REMOVE_EXT_RESOURCE_FAILED;
    }

    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("Non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }

    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({
        Constants::PERMISSION_INSTALL_BUNDLE, ServiceConstants::PERMISSION_UNINSTALL_BUNDLE})) {
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
            APP_LOGE("Remove failed %{public}s", extResourceInfo.filePath.c_str());
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
        APP_LOGE("GetInnerBundleInfo failed %{public}s", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    std::map<std::string, ExtendResourceInfo> extendResourceInfos = info.GetExtendResourceInfos();
    for (const auto &moduleName : moduleNames) {
        auto iter = extendResourceInfos.find(moduleName);
        if (iter == extendResourceInfos.end()) {
            APP_LOGE("Module not exist %{public}s", moduleName.c_str());
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
        APP_LOGE("fail to GetExtResource due to param is empty");
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
        APP_LOGE("GetInnerBundleInfo failed %{public}s", bundleName.c_str());
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
    const std::string &bundleName, const std::string &moduleName, const int32_t userId, const int32_t appIndex)
{
    APP_LOGI("EnableDynamicIcon %{public}s, %{public}s, %{public}d, %{public}d",
        bundleName.c_str(), moduleName.c_str(), userId, appIndex);
    if (bundleName.empty()) {
        APP_LOGE("fail to EnableDynamicIcon due to bundleName is empty");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    if (moduleName.empty()) {
        APP_LOGE("fail to EnableDynamicIcon due to moduleName is empty");
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
    ErrCode ret = GetExtendResourceInfo(bundleName, moduleName, extendResourceInfo, userId, appIndex);
    CHECK_RESULT(ret, "GetExtendResourceInfo failed %{public}d");
    if (!ParseBundleResource(bundleName, extendResourceInfo, userId, appIndex)) {
        APP_LOGE("%{public}s no extend Resources", bundleName.c_str());
        return ERR_EXT_RESOURCE_MANAGER_ENABLE_DYNAMIC_ICON_FAILED;
    }

    SaveCurDynamicIcon(bundleName, moduleName, userId, appIndex);
    SendBroadcast(bundleName, true, userId, appIndex);
    return ERR_OK;
}

void ExtendResourceManagerHostImpl::SaveCurDynamicIcon(
    const std::string &bundleName, const std::string &moduleName, const int32_t userId, const int32_t appIndex)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return;
    }

    dataMgr->UpateCurDynamicIconModule(bundleName, moduleName, userId, appIndex);
}

void ExtendResourceManagerHostImpl::SendBroadcast(
    const std::string &bundleName, bool isEnableDynamicIcon,
    const int32_t userId, const int32_t appIndex)
{
    std::shared_ptr<BundleCommonEventMgr> commonEventMgr = std::make_shared<BundleCommonEventMgr>();
    commonEventMgr->NotifyDynamicIconEvent(bundleName, isEnableDynamicIcon, userId, appIndex);
}

bool ExtendResourceManagerHostImpl::ParseBundleResource(
    const std::string &bundleName, const ExtendResourceInfo &extendResourceInfo,
    const int32_t userId, const int32_t appIndex)
{
    APP_LOGI("ParseBundleResource %{public}s", bundleName.c_str());
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    BundleResourceParser bundleResourceParser;
    ResourceInfo info;
    info.bundleName_ = bundleName;
    info.iconId_ = extendResourceInfo.iconId;
    if (!bundleResourceParser.ParseIconResourceByPath(extendResourceInfo.filePath,
        extendResourceInfo.iconId, info)) {
        APP_LOGW("ParseIconResourceByPath failed, bundleName:%{public}s", bundleName.c_str());
        return false;
    }
    if (info.icon_.empty()) {
        APP_LOGE("icon empty %{public}s", bundleName.c_str());
        return false;
    }
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    if (manager == nullptr) {
        APP_LOGE("failed, manager is nullptr");
        return false;
    }
    if (!manager->UpdateBundleIcon(bundleName, info)) {
        APP_LOGE("UpdateBundleIcon failed, bundleName:%{public}s", bundleName.c_str());
        return false;
    }
    return true;
#else
    APP_LOGI("bundle resource not support");
    return false;
#endif
}

ErrCode ExtendResourceManagerHostImpl::GetExtendResourceInfo(const std::string &bundleName,
    const std::string &moduleName, ExtendResourceInfo &extendResourceInfo,
    const int32_t userId, const int32_t appIndex)
{
    InnerBundleInfo info;
    if (!GetInnerBundleInfo(bundleName, info)) {
        APP_LOGE("GetInnerBundleInfo failed %{public}s", bundleName.c_str());
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
    ErrCode ret = CheckParamInvalid(info, userId, appIndex);
    CHECK_RESULT(ret, "check user or appIndex failed %{public}d");
    extendResourceInfo = iter->second;
    return ERR_OK;
}

ErrCode ExtendResourceManagerHostImpl::DisableDynamicIcon(const std::string &bundleName,
    const int32_t userId, const int32_t appIndex)
{
    APP_LOGI("DisableDynamicIcon %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        APP_LOGE("fail to DisableDynamicIcon due to param is empty");
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
        APP_LOGE("GetInnerBundleInfo failed %{public}s", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    ErrCode ret = CheckParamInvalid(info, userId, appIndex);
    CHECK_RESULT(ret, "check user or appIndex failed %{public}d");

    std::string curDynamicModule = info.GetCurDynamicIconModule(userId, appIndex);
    if (curDynamicModule.empty()) {
        APP_LOGE("%{public}s no enabled dynamic icon", bundleName.c_str());
        return ERR_EXT_RESOURCE_MANAGER_DISABLE_DYNAMIC_ICON_FAILED;
    }

    SaveCurDynamicIcon(bundleName, "", userId, appIndex);
    ResetBundleResourceIcon(bundleName, userId, appIndex);
    SendBroadcast(bundleName, false, userId, appIndex);
    return ERR_OK;
}

bool ExtendResourceManagerHostImpl::ResetBundleResourceIcon(const std::string &bundleName,
    const int32_t userId, const int32_t appIndex)
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    APP_LOGI("ResetBundleResourceIcon %{public}s", bundleName.c_str());
    auto manager = DelayedSingleton<BundleResourceManager>::GetInstance();
    if (manager == nullptr) {
        APP_LOGE("failed, manager is nullptr");
        return false;
    }

    // Delete dynamic icon resource
    if (!manager->DeleteResourceInfo(bundleName)) {
        APP_LOGE("DeleteResourceInfo failed, bundleName:%{public}s", bundleName.c_str());
        return false;
    }

    // Reset default icon
    int32_t currentUserId = AccountHelper::GetCurrentActiveUserId();
    if ((currentUserId <= 0)) {
        currentUserId = Constants::START_USERID;
    }
    if (!manager->AddResourceInfoByBundleName(bundleName, currentUserId)) {
        APP_LOGE("No default icon, bundleName:%{public}s", bundleName.c_str());
    }
    return true;
#else
    return false;
#endif
}

ErrCode ExtendResourceManagerHostImpl::GetDynamicIcon(
    const std::string &bundleName, const int32_t userId, const int32_t appIndex, std::string &moudleName)
{
    if (bundleName.empty()) {
        APP_LOGE("fail to GetDynamicIcon due to param is empty");
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
        APP_LOGE("GetInnerBundleInfo failed %{public}s", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    ErrCode ret = CheckParamInvalid(info, userId, appIndex);
    CHECK_RESULT(ret, "check user or appIndex failed %{public}d");

    std::string curDynamicModule = info.GetCurDynamicIconModule(userId, appIndex);
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
        APP_LOGE("fail to CreateFd due to param is empty");
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
    if (!BundleUtil::CheckFileType(fileName, EXT_RESOURCE_FILE_SUFFIX)) {
        APP_LOGE("not hsp file");
        return ERR_EXT_RESOURCE_MANAGER_CREATE_FD_FAILED;
    }
    if (!IsFileNameValid(fileName)) {
        APP_LOGE("invalid fileName");
        return ERR_EXT_RESOURCE_MANAGER_CREATE_FD_FAILED;
    }
    std::string tmpDir = BundleUtil::CreateInstallTempDir(
        ++id_, DirType::EXT_RESOURCE_FILE_DIR);
    if (tmpDir.empty()) {
        APP_LOGE("create tmp dir failed");
        return ERR_EXT_RESOURCE_MANAGER_CREATE_FD_FAILED;
    }
    path = tmpDir + fileName;
    if ((fd = BundleUtil::CreateFileDescriptor(path, 0)) < 0) {
        APP_LOGE("create file descriptor failed");
        BundleUtil::DeleteDir(tmpDir);
        return ERR_EXT_RESOURCE_MANAGER_CREATE_FD_FAILED;
    }
    return ERR_OK;
}

ErrCode ExtendResourceManagerHostImpl::CheckParamInvalid(const InnerBundleInfo &bundleInfo,
    const int32_t userId, const int32_t appIndex)
{
    if ((userId == Constants::ALL_USERID) && (appIndex == Constants::ALL_USERID)) {
        return ERR_OK;
    }
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    if (!dataMgr->HasUserId(userId)) {
        APP_LOGE("userId %{public}d not exist", userId);
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }
    InnerBundleUserInfo userInfo;
    if (!bundleInfo.GetInnerBundleUserInfo(userId, userInfo)) {
        APP_LOGE("bundle %{public}s not exist in userId %{public}d", bundleInfo.GetBundleName().c_str(), userId);
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    if (appIndex == 0) {
        return ERR_OK;
    }
    std::string cloneInfoKey = InnerBundleUserInfo::AppIndexToKey(appIndex);
    if (userInfo.cloneInfos.find(cloneInfoKey) == userInfo.cloneInfos.end()) {
        APP_LOGE("bundle %{public}s not exist in userId %{public}d appIndex %{public}d",
            bundleInfo.GetBundleName().c_str(), userId, appIndex);
        return ERR_APPEXECFWK_APP_INDEX_OUT_OF_RANGE;
    }
    return ERR_OK;
}
} // AppExecFwk
} // namespace OHOS
