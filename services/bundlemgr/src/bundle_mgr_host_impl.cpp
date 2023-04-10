/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "bundle_mgr_host_impl.h"

#include <dirent.h>
#include <future>
#include <set>
#include <string>

#include "app_log_wrapper.h"
#include "app_privilege_capability.h"
#include "bundle_mgr_service.h"
#include "bundle_parser.h"
#include "bundle_permission_mgr.h"
#include "bundle_sandbox_app_helper.h"
#include "bundle_util.h"
#include "bundle_verify_mgr.h"
#include "directory_ex.h"
#ifdef DISTRIBUTED_BUNDLE_FRAMEWORK
#include "distributed_bms_proxy.h"
#endif
#include "element_name.h"
#include "if_system_ability_manager.h"
#include "installd_client.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "json_serializer.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AppExecFwk {
bool BundleMgrHostImpl::GetApplicationInfo(
    const std::string &appName, const ApplicationFlag flag, const int userId, ApplicationInfo &appInfo)
{
    return GetApplicationInfo(appName, static_cast<int32_t>(flag), userId, appInfo);
}

bool BundleMgrHostImpl::GetApplicationInfo(
    const std::string &appName, int32_t flags, int32_t userId, ApplicationInfo &appInfo)
{
    APP_LOGD("start GetApplicationInfo, bundleName : %{public}s, flags : %{public}d, userId : %{public}d",
        appName.c_str(), flags, userId);
    if (!VerifySystemApi(Constants::API_VERSION_NINE)) {
        APP_LOGD("non-system app calling system api");
        return true;
    }
    if (!VerifyQueryPermission(appName)) {
        APP_LOGE("verify permission failed");
        return false;
    }
    APP_LOGD("verify permission success, begin to GetApplicationInfo");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->GetApplicationInfo(appName, flags, userId, appInfo);
}

ErrCode BundleMgrHostImpl::GetApplicationInfoV9(
    const std::string &appName, int32_t flags, int32_t userId, ApplicationInfo &appInfo)
{
    APP_LOGD("start GetApplicationInfoV9, bundleName : %{public}s, flags : %{public}d, userId : %{public}d",
        appName.c_str(), flags, userId);
    if (!VerifySystemApi()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!VerifyQueryPermission(appName)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    APP_LOGD("verify permission success, bgein to GetApplicationInfoV9");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->GetApplicationInfoV9(appName, flags, userId, appInfo);
}

bool BundleMgrHostImpl::GetApplicationInfos(
    const ApplicationFlag flag, const int userId, std::vector<ApplicationInfo> &appInfos)
{
    return GetApplicationInfos(static_cast<int32_t>(flag), userId, appInfos);
}

bool BundleMgrHostImpl::GetApplicationInfos(
    int32_t flags, int32_t userId, std::vector<ApplicationInfo> &appInfos)
{
    APP_LOGD("start GetApplicationInfos, flags : %{public}d, userId : %{public}d", flags, userId);
    if (!VerifySystemApi(Constants::API_VERSION_NINE)) {
        APP_LOGD("non-system app calling system api");
        return true;
    }
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify permission failed");
        return false;
    }
    APP_LOGD("verify permission success, begin to GetApplicationInfos");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->GetApplicationInfos(flags, userId, appInfos);
}

ErrCode BundleMgrHostImpl::GetApplicationInfosV9(
    int32_t flags, int32_t userId, std::vector<ApplicationInfo> &appInfos)
{
    APP_LOGD("start GetApplicationInfosV9, flags : %{public}d, userId : %{public}d", flags, userId);
    if (!VerifySystemApi()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    APP_LOGD("verify permission success, begin to GetApplicationInfosV9");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->GetApplicationInfosV9(flags, userId, appInfos);
}

bool BundleMgrHostImpl::GetBundleInfo(
    const std::string &bundleName, const BundleFlag flag, BundleInfo &bundleInfo, int32_t userId)
{
    return GetBundleInfo(bundleName, static_cast<int32_t>(flag), bundleInfo, userId);
}

bool BundleMgrHostImpl::GetBundleInfo(
    const std::string &bundleName, int32_t flags, BundleInfo &bundleInfo, int32_t userId)
{
    APP_LOGD("start GetBundleInfo, bundleName : %{public}s, flags : %{public}d, userId : %{public}d",
        bundleName.c_str(), flags, userId);
    if (!VerifySystemApi(Constants::API_VERSION_NINE)) {
        APP_LOGD("non-system app calling system api");
        return true;
    }
    if (!VerifyQueryPermission(bundleName)) {
        APP_LOGE("verify permission failed");
        return false;
    }
    APP_LOGD("verify permission success, begin to GetBundleInfo");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->GetBundleInfo(bundleName, flags, bundleInfo, userId);
}

ErrCode BundleMgrHostImpl::GetBundleInfoV9(
    const std::string &bundleName, int32_t flags, BundleInfo &bundleInfo, int32_t userId)
{
    APP_LOGD("start GetBundleInfoV9, bundleName : %{public}s, flags : %{public}d, userId : %{public}d",
        bundleName.c_str(), flags, userId);
    if (!VerifySystemApi()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!VerifyQueryPermission(bundleName)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    APP_LOGD("verify permission success, begin to GetBundleInfoV9");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->GetBundleInfoV9(bundleName, flags, bundleInfo, userId);
}

ErrCode BundleMgrHostImpl::GetBundleInfoForSelf(int32_t flags, BundleInfo &bundleInfo)
{
    auto uid = IPCSkeleton::GetCallingUid();
    int32_t userId = uid / Constants::BASE_USER_RANGE;
    std::string bundleName;
    bool ret = GetBundleNameForUid(uid, bundleName);
    if (!ret) {
        APP_LOGE("GetBundleNameForUid failed");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->GetBundleInfoV9(bundleName, flags, bundleInfo, userId);
}

ErrCode BundleMgrHostImpl::GetBundlePackInfo(
    const std::string &bundleName, const BundlePackFlag flag, BundlePackInfo &bundlePackInfo, int32_t userId)
{
    return GetBundlePackInfo(bundleName, static_cast<int32_t>(flag), bundlePackInfo, userId);
}

ErrCode BundleMgrHostImpl::GetBundlePackInfo(
    const std::string &bundleName, int32_t flags, BundlePackInfo &bundlePackInfo, int32_t userId)
{
    // check permission
    if (!VerifySystemApi()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("SetModuleUpgradeFlag failed due to lack of permission");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    return dataMgr->GetBundlePackInfo(bundleName, flags, bundlePackInfo, userId);
}

bool BundleMgrHostImpl::GetBundleUserInfo(
    const std::string &bundleName, int32_t userId, InnerBundleUserInfo &innerBundleUserInfo)
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->GetInnerBundleUserInfoByUserId(bundleName, userId, innerBundleUserInfo);
}

bool BundleMgrHostImpl::GetBundleUserInfos(
    const std::string &bundleName, std::vector<InnerBundleUserInfo> &innerBundleUserInfos)
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->GetInnerBundleUserInfos(bundleName, innerBundleUserInfos);
}

bool BundleMgrHostImpl::GetBundleInfos(const BundleFlag flag, std::vector<BundleInfo> &bundleInfos, int32_t userId)
{
    return GetBundleInfos(static_cast<int32_t>(flag), bundleInfos, userId);
}

bool BundleMgrHostImpl::GetBundleInfos(int32_t flags, std::vector<BundleInfo> &bundleInfos, int32_t userId)
{
    APP_LOGD("start GetBundleInfos, flags : %{public}d, userId : %{public}d", flags, userId);
    if (!VerifySystemApi(Constants::API_VERSION_NINE)) {
        APP_LOGD("non-system app calling system api");
        return true;
    }
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify permission failed");
        return false;
    }
    APP_LOGD("verify permission success, begin to GetBundleInfos");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->GetBundleInfos(flags, bundleInfos, userId);
}

ErrCode BundleMgrHostImpl::GetBundleInfosV9(int32_t flags, std::vector<BundleInfo> &bundleInfos, int32_t userId)
{
    APP_LOGD("start GetBundleInfosV9, flags : %{public}d, userId : %{public}d", flags, userId);
    if (!VerifySystemApi()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    APP_LOGD("verify permission success, begin to GetBundleInfosV9");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->GetBundleInfosV9(flags, bundleInfos, userId);
}

bool BundleMgrHostImpl::GetBundleNameForUid(const int uid, std::string &bundleName)
{
    APP_LOGD("start GetBundleNameForUid, uid : %{public}d", uid);
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->GetBundleNameForUid(uid, bundleName);
}

bool BundleMgrHostImpl::GetBundlesForUid(const int uid, std::vector<std::string> &bundleNames)
{
    APP_LOGD("start GetBundlesForUid, uid : %{public}d", uid);
    if (!BundlePermissionMgr::IsNativeTokenType()) {
        APP_LOGE("verify token type failed");
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->GetBundlesForUid(uid, bundleNames);
}

ErrCode BundleMgrHostImpl::GetNameForUid(const int uid, std::string &name)
{
    APP_LOGD("start GetNameForUid, uid : %{public}d", uid);
    if (!VerifySystemApi(Constants::API_VERSION_NINE)) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO) &&
        !BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify query permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->GetNameForUid(uid, name);
}

bool BundleMgrHostImpl::GetBundleGids(const std::string &bundleName, std::vector<int> &gids)
{
    APP_LOGD("start GetBundleGids, bundleName : %{public}s", bundleName.c_str());
    if (!BundlePermissionMgr::IsNativeTokenType()) {
        APP_LOGE("verify token type failed");
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->GetBundleGids(bundleName, gids);
}

bool BundleMgrHostImpl::GetBundleGidsByUid(const std::string &bundleName, const int &uid, std::vector<int> &gids)
{
    APP_LOGD("start GetBundleGidsByUid, bundleName : %{public}s, uid : %{public}d", bundleName.c_str(), uid);
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->GetBundleGidsByUid(bundleName, uid, gids);
}

bool BundleMgrHostImpl::CheckIsSystemAppByUid(const int uid)
{
    APP_LOGD("start CheckIsSystemAppByUid, uid : %{public}d", uid);
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->CheckIsSystemAppByUid(uid);
}

bool BundleMgrHostImpl::GetBundleInfosByMetaData(const std::string &metaData, std::vector<BundleInfo> &bundleInfos)
{
    APP_LOGD("start GetBundleInfosByMetaData, metaData : %{public}s", metaData.c_str());
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify permission failed");
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->GetBundleInfosByMetaData(metaData, bundleInfos);
}

bool BundleMgrHostImpl::QueryAbilityInfo(const Want &want, AbilityInfo &abilityInfo)
{
    return QueryAbilityInfo(want, GET_ABILITY_INFO_WITH_APPLICATION, Constants::UNSPECIFIED_USERID, abilityInfo);
}

#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
bool BundleMgrHostImpl::QueryAbilityInfo(const Want &want, int32_t flags, int32_t userId,
    AbilityInfo &abilityInfo, const sptr<IRemoteObject> &callBack)
{
    if (!BundlePermissionMgr::VerifyCallingUid()) {
        APP_LOGE("QueryAbilityInfo verify failed.");
        return false;
    }
    auto connectAbilityMgr = GetConnectAbilityMgrFromService();
    if (connectAbilityMgr == nullptr) {
        APP_LOGE("connectAbilityMgr is nullptr");
        return false;
    }
    return connectAbilityMgr->QueryAbilityInfo(want, flags, userId, abilityInfo, callBack);
}

bool BundleMgrHostImpl::SilentInstall(const Want &want, int32_t userId, const sptr<IRemoteObject> &callBack)
{
    APP_LOGD("SilentInstall in");
    auto connectMgr = GetConnectAbilityMgrFromService();
    if (connectMgr == nullptr) {
        APP_LOGE("connectMgr is nullptr");
        return false;
    }
    return connectMgr->SilentInstall(want, userId, callBack);
}

void BundleMgrHostImpl::UpgradeAtomicService(const Want &want, int32_t userId)
{
    if (!BundlePermissionMgr::VerifyCallingUid()) {
        APP_LOGE("UpgradeAtomicService verify failed.");
        return;
    }
    auto connectAbilityMgr = GetConnectAbilityMgrFromService();
    if (connectAbilityMgr == nullptr) {
        APP_LOGE("connectAbilityMgr is nullptr");
        return;
    }
    connectAbilityMgr->UpgradeAtomicService(want, userId);
}

bool BundleMgrHostImpl::CheckAbilityEnableInstall(
    const Want &want, int32_t missionId, int32_t userId, const sptr<IRemoteObject> &callback)
{
    if (!BundlePermissionMgr::IsNativeTokenType()) {
        APP_LOGE("verify token type failed");
        return false;
    }
    auto elementName = want.GetElement();
    if (elementName.GetDeviceID().empty() || elementName.GetBundleName().empty() ||
        elementName.GetAbilityName().empty()) {
        APP_LOGE("check ability install parameter is invalid");
        return false;
    }
    auto bundleDistributedManager = DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleDistributedManager();
    if (bundleDistributedManager == nullptr) {
        APP_LOGE("bundleDistributedManager failed");
        return false;
    }
    return bundleDistributedManager->CheckAbilityEnableInstall(want, missionId, userId, callback);
}

bool BundleMgrHostImpl::ProcessPreload(const Want &want)
{
    if (!BundlePermissionMgr::VerifyPreload(want)) {
        APP_LOGE("ProcessPreload verify failed.");
        return false;
    }
    APP_LOGD("begin to process preload.");
    auto connectAbilityMgr = GetConnectAbilityMgrFromService();
    if (connectAbilityMgr == nullptr) {
        APP_LOGE("connectAbilityMgr is nullptr");
        return false;
    }
    return connectAbilityMgr->ProcessPreload(want);
}
#endif

bool BundleMgrHostImpl::QueryAbilityInfo(const Want &want, int32_t flags, int32_t userId, AbilityInfo &abilityInfo)
{
    APP_LOGD("start QueryAbilityInfo, flags : %{public}d, userId : %{public}d", flags, userId);
    if (!VerifySystemApi(Constants::API_VERSION_NINE)) {
        APP_LOGD("non-system app calling system api");
        return true;
    }
    if (!VerifyQueryPermission(want.GetElement().GetBundleName())) {
        APP_LOGE("verify permission failed");
        return false;
    }
    APP_LOGD("verify permission success, begin to QueryAbilityInfo");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->QueryAbilityInfo(want, flags, userId, abilityInfo);
}

bool BundleMgrHostImpl::QueryAbilityInfos(const Want &want, std::vector<AbilityInfo> &abilityInfos)
{
    return QueryAbilityInfos(
        want, GET_ABILITY_INFO_WITH_APPLICATION, Constants::UNSPECIFIED_USERID, abilityInfos);
}

bool BundleMgrHostImpl::QueryAbilityInfos(
    const Want &want, int32_t flags, int32_t userId, std::vector<AbilityInfo> &abilityInfos)
{
    APP_LOGD("start QueryAbilityInfos, flags : %{public}d, userId : %{public}d", flags, userId);
    if (!VerifySystemApi(Constants::API_VERSION_NINE)) {
        APP_LOGD("non-system app calling system api");
        return true;
    }
    if (!VerifyQueryPermission(want.GetElement().GetBundleName())) {
        APP_LOGE("verify permission failed");
        return false;
    }
    APP_LOGD("verify permission success, begin to QueryAbilityInfos");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->QueryAbilityInfos(want, flags, userId, abilityInfos);
}

ErrCode BundleMgrHostImpl::QueryAbilityInfosV9(
    const Want &want, int32_t flags, int32_t userId, std::vector<AbilityInfo> &abilityInfos)
{
    APP_LOGD("start QueryAbilityInfosV9, flags : %{public}d, userId : %{public}d", flags, userId);
    if (!VerifySystemApi()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!VerifyQueryPermission(want.GetElement().GetBundleName())) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    APP_LOGD("verify permission success, begin to QueryAbilityInfosV9");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->QueryAbilityInfosV9(want, flags, userId, abilityInfos);
}

bool BundleMgrHostImpl::QueryAllAbilityInfos(const Want &want, int32_t userId, std::vector<AbilityInfo> &abilityInfos)
{
    APP_LOGD("start QueryAllAbilityInfos, userId : %{public}d", userId);
    if (!VerifySystemApi(Constants::API_VERSION_NINE)) {
        APP_LOGD("non-system app calling system api");
        return true;
    }
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify permission failed");
        return false;
    }
    APP_LOGD("verify permission success, begin to QueryAllAbilityInfos");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->QueryLauncherAbilityInfos(want, userId, abilityInfos);
}

bool BundleMgrHostImpl::QueryAbilityInfoByUri(const std::string &abilityUri, AbilityInfo &abilityInfo)
{
    APP_LOGD("start QueryAbilityInfoByUri, uri : %{private}s", abilityUri.c_str());
    if (!VerifySystemApi(Constants::API_VERSION_NINE)) {
        APP_LOGE("non-system app calling system api");
        return true;
    }
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO) &&
        !BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify query permission failed");
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->QueryAbilityInfoByUri(abilityUri, Constants::UNSPECIFIED_USERID, abilityInfo);
}

bool BundleMgrHostImpl::QueryAbilityInfosByUri(const std::string &abilityUri, std::vector<AbilityInfo> &abilityInfos)
{
    APP_LOGD("start QueryAbilityInfosByUri, uri : %{private}s", abilityUri.c_str());
    if (!VerifySystemApi(Constants::API_VERSION_NINE)) {
        APP_LOGD("non-system app calling system api");
        return true;
    }
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify permission failed");
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->QueryAbilityInfosByUri(abilityUri, abilityInfos);
}

bool BundleMgrHostImpl::QueryAbilityInfoByUri(
    const std::string &abilityUri, int32_t userId, AbilityInfo &abilityInfo)
{
    APP_LOGD("start QueryAbilityInfoByUri, uri : %{private}s, userId : %{public}d", abilityUri.c_str(), userId);
    if (!VerifySystemApi(Constants::API_VERSION_NINE)) {
        APP_LOGE("non-system app calling system api");
        return true;
    }
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO) &&
        !BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify query permission failed");
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->QueryAbilityInfoByUri(abilityUri, userId, abilityInfo);
}

bool BundleMgrHostImpl::QueryKeepAliveBundleInfos(std::vector<BundleInfo> &bundleInfos)
{
    auto dataMgr = GetDataMgrFromService();
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify permission failed");
        return false;
    }
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->QueryKeepAliveBundleInfos(bundleInfos);
}

std::string BundleMgrHostImpl::GetAbilityLabel(const std::string &bundleName, const std::string &abilityName)
{
    APP_LOGD("start GetAbilityLabel, bundleName : %{public}s, abilityName : %{public}s",
        bundleName.c_str(), abilityName.c_str());
    if (!VerifySystemApi(Constants::API_VERSION_NINE)) {
        APP_LOGD("non-system app calling system api");
        return Constants::EMPTY_STRING;
    }
    if (!VerifyQueryPermission(bundleName)) {
        APP_LOGE("verify permission failed");
        return Constants::EMPTY_STRING;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return Constants::EMPTY_STRING;
    }
    std::string label;
    ErrCode ret = dataMgr->GetAbilityLabel(bundleName, Constants::EMPTY_STRING, abilityName, label);
    if (ret != ERR_OK) {
        return Constants::EMPTY_STRING;
    }
    return label;
}

ErrCode BundleMgrHostImpl::GetAbilityLabel(const std::string &bundleName, const std::string &moduleName,
    const std::string &abilityName, std::string &label)
{
    if (!VerifySystemApi(Constants::API_VERSION_NINE)) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!VerifyQueryPermission(bundleName)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_APPEXECFWK_SERVICE_NOT_READY;
    }
    return dataMgr->GetAbilityLabel(bundleName, moduleName, abilityName, label);
}

bool BundleMgrHostImpl::GetBundleArchiveInfo(
    const std::string &hapFilePath, const BundleFlag flag, BundleInfo &bundleInfo)
{
    return GetBundleArchiveInfo(hapFilePath, static_cast<int32_t>(flag), bundleInfo);
}

bool BundleMgrHostImpl::GetBundleArchiveInfo(
    const std::string &hapFilePath, int32_t flags, BundleInfo &bundleInfo)
{
    APP_LOGD("start GetBundleArchiveInfo, hapFilePath : %{public}s, flags : %{public}d", hapFilePath.c_str(), flags);
    if (!VerifySystemApi(Constants::API_VERSION_NINE)) {
        APP_LOGD("non-system app calling system api");
        return true;
    }
    if (hapFilePath.find(Constants::SANDBOX_DATA_PATH) == std::string::npos) {
        std::string realPath;
        auto ret = BundleUtil::CheckFilePath(hapFilePath, realPath);
        if (ret != ERR_OK) {
            APP_LOGE("GetBundleArchiveInfo file path %{private}s invalid", hapFilePath.c_str());
            return false;
        }

        InnerBundleInfo info;
        BundleParser bundleParser;
        ret = bundleParser.Parse(realPath, info);
        if (ret != ERR_OK) {
            APP_LOGE("parse bundle info failed, error: %{public}d", ret);
            return false;
        }
        APP_LOGD("verify permission success, begin to GetBundleArchiveInfo");
        info.GetBundleInfo(flags, bundleInfo, Constants::NOT_EXIST_USERID);
        return true;
    } else {
        return GetBundleArchiveInfoBySandBoxPath(hapFilePath, flags, bundleInfo) == ERR_OK;
    }
}

ErrCode BundleMgrHostImpl::GetBundleArchiveInfoV9(
    const std::string &hapFilePath, int32_t flags, BundleInfo &bundleInfo)
{
    APP_LOGD("start GetBundleArchiveInfoV9, hapFilePath : %{public}s, flags : %{public}d", hapFilePath.c_str(), flags);
    if (!VerifySystemApi()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    if (hapFilePath.find(Constants::SANDBOX_DATA_PATH) == 0) {
        APP_LOGD("sandbox path");
        return GetBundleArchiveInfoBySandBoxPath(hapFilePath, flags, bundleInfo, true);
    }
    std::string realPath;
    ErrCode ret = BundleUtil::CheckFilePath(hapFilePath, realPath);
    if (ret != ERR_OK) {
        APP_LOGE("GetBundleArchiveInfoV9 file path %{private}s invalid", hapFilePath.c_str());
        return ERR_BUNDLE_MANAGER_INVALID_HAP_PATH;
    }
    InnerBundleInfo info;
    BundleParser bundleParser;
    ret = bundleParser.Parse(realPath, info);
    if (ret != ERR_OK) {
        APP_LOGE("parse bundle info failed, error: %{public}d", ret);
        return ERR_BUNDLE_MANAGER_INVALID_HAP_PATH;
    }
    info.GetBundleInfoV9(flags, bundleInfo, Constants::NOT_EXIST_USERID);
    return ERR_OK;
}

ErrCode BundleMgrHostImpl::GetBundleArchiveInfoBySandBoxPath(const std::string &hapFilePath,
    int32_t flags, BundleInfo &bundleInfo, bool fromV9)
{
    std::string bundleName;
    int32_t apiVersion = fromV9 ? Constants::INVALID_API_VERSION : Constants::API_VERSION_NINE;
    if (!VerifySystemApi(apiVersion)) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!ObtainCallingBundleName(bundleName)) {
        APP_LOGE("get calling bundleName failed");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    std::string hapRealPath;
    if (!BundleUtil::RevertToRealPath(hapFilePath, bundleName, hapRealPath)) {
        APP_LOGE("GetBundleArchiveInfo RevertToRealPath failed");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    std::string tempHapPath = Constants::BUNDLE_MANAGER_SERVICE_PATH +
        Constants::PATH_SEPARATOR + std::to_string(BundleUtil::GetCurrentTime());
    if (!BundleUtil::CreateDir(tempHapPath)) {
        APP_LOGE("GetBundleArchiveInfo make temp dir failed");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    std::string hapName = hapFilePath.substr(hapFilePath.find_last_of("//") + 1);
    std::string tempHapFile = tempHapPath + Constants::PATH_SEPARATOR + hapName;
    if (InstalldClient::GetInstance()->CopyFile(hapRealPath, tempHapFile) != ERR_OK) {
        APP_LOGE("GetBundleArchiveInfo copy hap file failed");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    std::string realPath;
    auto ret = BundleUtil::CheckFilePath(tempHapFile, realPath);
    if (ret != ERR_OK) {
        APP_LOGE("CheckFilePath failed");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    InnerBundleInfo info;
    BundleParser bundleParser;
    ret = bundleParser.Parse(realPath, info);
    if (ret != ERR_OK) {
        APP_LOGE("parse bundle info failed, error: %{public}d", ret);
        BundleUtil::DeleteDir(tempHapPath);
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    BundleUtil::DeleteDir(tempHapPath);
    APP_LOGD("verify permission success, begin to GetBundleArchiveInfo");
    if (fromV9) {
        info.GetBundleInfoV9(flags, bundleInfo, Constants::NOT_EXIST_USERID);
    } else {
        info.GetBundleInfo(flags, bundleInfo, Constants::NOT_EXIST_USERID);
    }
    return ERR_OK;
}

bool BundleMgrHostImpl::GetHapModuleInfo(const AbilityInfo &abilityInfo, HapModuleInfo &hapModuleInfo)
{
    APP_LOGD("start GetHapModuleInfo");
    return GetHapModuleInfo(abilityInfo, Constants::UNSPECIFIED_USERID, hapModuleInfo);
}

bool BundleMgrHostImpl::GetHapModuleInfo(const AbilityInfo &abilityInfo, int32_t userId, HapModuleInfo &hapModuleInfo)
{
    APP_LOGD("start GetHapModuleInfo with userId: %{public}d", userId);
    if (!VerifyQueryPermission(abilityInfo.bundleName)) {
        APP_LOGE("verify permission failed");
        return false;
    }
    if (abilityInfo.bundleName.empty() || abilityInfo.package.empty()) {
        APP_LOGE("fail to GetHapModuleInfo due to params empty");
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->GetHapModuleInfo(abilityInfo, hapModuleInfo, userId);
}

ErrCode BundleMgrHostImpl::GetLaunchWantForBundle(const std::string &bundleName, Want &want, int32_t userId)
{
    APP_LOGD("start GetLaunchWantForBundle, bundleName : %{public}s", bundleName.c_str());
    if (!VerifySystemApi(Constants::API_VERSION_NINE)) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }

    APP_LOGD("verify permission success, begin to GetLaunchWantForBundle");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }

    return dataMgr->GetLaunchWantForBundle(bundleName, want, userId);
}

int BundleMgrHostImpl::CheckPublicKeys(const std::string &firstBundleName, const std::string &secondBundleName)
{
    APP_LOGD("start CheckPublicKeys, firstBundleName : %{public}s, secondBundleName : %{public}s",
        firstBundleName.c_str(), secondBundleName.c_str());
    if (!BundlePermissionMgr::IsNativeTokenType()) {
        APP_LOGE("verify token type failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->CheckPublicKeys(firstBundleName, secondBundleName);
}

ErrCode BundleMgrHostImpl::GetPermissionDef(const std::string &permissionName, PermissionDef &permissionDef)
{
    if (!VerifySystemApi()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify GET_BUNDLE_INFO_PRIVILEGED failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    if (permissionName.empty()) {
        APP_LOGW("fail to GetPermissionDef due to params empty");
        return ERR_BUNDLE_MANAGER_QUERY_PERMISSION_DEFINE_FAILED;
    }
    return BundlePermissionMgr::GetPermissionDef(permissionName, permissionDef);
}

bool BundleMgrHostImpl::HasSystemCapability(const std::string &capName)
{
    return true;
}

bool BundleMgrHostImpl::GetSystemAvailableCapabilities(std::vector<std::string> &systemCaps)
{
    return true;
}

bool BundleMgrHostImpl::IsSafeMode()
{
    return true;
}

ErrCode BundleMgrHostImpl::CleanBundleCacheFiles(
    const std::string &bundleName, const sptr<ICleanCacheCallback> &cleanCacheCallback,
    int32_t userId)
{
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = BundleUtil::GetUserIdByCallingUid();
    }

    APP_LOGD("start CleanBundleCacheFiles, bundleName : %{public}s, userId : %{public}d", bundleName.c_str(), userId);
    if (!VerifySystemApi()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (userId < 0) {
        APP_LOGE("userId is invalid");
        EventReport::SendCleanCacheSysEvent(bundleName, userId, true, true);
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }

    if (bundleName.empty() || !cleanCacheCallback) {
        APP_LOGE("the cleanCacheCallback is nullptr or bundleName empty");
        EventReport::SendCleanCacheSysEvent(bundleName, userId, true, true);
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }

    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_REMOVECACHEFILE)) {
        APP_LOGE("ohos.permission.REMOVE_CACHE_FILES permission denied");
        EventReport::SendCleanCacheSysEvent(bundleName, userId, true, true);
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }

    ApplicationInfo applicationInfo;
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        EventReport::SendCleanCacheSysEvent(bundleName, userId, true, true);
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }

    auto ret = dataMgr->GetApplicationInfoV9(bundleName,
        static_cast<int32_t>(GetApplicationFlag::GET_APPLICATION_INFO_WITH_DISABLE), userId, applicationInfo);
    if (ret != ERR_OK) {
        APP_LOGE("can not get application info of %{public}s", bundleName.c_str());
        EventReport::SendCleanCacheSysEvent(bundleName, userId, true, true);
        return ret;
    }

    if (applicationInfo.isSystemApp && !applicationInfo.userDataClearable) {
        APP_LOGE("can not clean cacheFiles of %{public}s due to userDataClearable is false", bundleName.c_str());
        EventReport::SendCleanCacheSysEvent(bundleName, userId, true, true);
        return ERR_BUNDLE_MANAGER_CAN_NOT_CLEAR_USER_DATA;
    }

    CleanBundleCacheTask(bundleName, cleanCacheCallback, dataMgr, userId);
    return ERR_OK;
}

void BundleMgrHostImpl::CleanBundleCacheTask(const std::string &bundleName,
    const sptr<ICleanCacheCallback> &cleanCacheCallback,
    const std::shared_ptr<BundleDataMgr> &dataMgr,
    int32_t userId)
{
    std::vector<std::string> rootDir;
    for (const auto &el : Constants::BUNDLE_EL) {
        std::string dataDir = Constants::BUNDLE_APP_DATA_BASE_DIR + el +
            Constants::PATH_SEPARATOR + std::to_string(userId) + Constants::BASE + bundleName;
        rootDir.emplace_back(dataDir);
    }

    auto cleanCache = [bundleName, userId, rootDir, dataMgr, cleanCacheCallback, this]() {
        std::vector<std::string> caches;
        for (const auto &st : rootDir) {
            std::vector<std::string> cache;
            if (InstalldClient::GetInstance()->GetBundleCachePath(st, cache) != ERR_OK) {
                APP_LOGW("GetBundleCachePath failed, path: %{public}s", st.c_str());
            }
            std::copy(cache.begin(), cache.end(), std::back_inserter(caches));
        }

        bool succeed = true;
        if (!caches.empty()) {
            for (const auto& cache : caches) {
                ErrCode ret = InstalldClient::GetInstance()->CleanBundleDataDir(cache);
                if (ret != ERR_OK) {
                    APP_LOGE("CleanBundleDataDir failed, path: %{private}s", cache.c_str());
                    succeed = false;
                }
            }
        }
        EventReport::SendCleanCacheSysEvent(bundleName, userId, true, !succeed);
        APP_LOGD("CleanBundleCacheFiles with succeed %{public}d", succeed);
        cleanCacheCallback->OnCleanCacheFinished(succeed);
        InnerBundleUserInfo innerBundleUserInfo;
        if (!this->GetBundleUserInfo(bundleName, userId, innerBundleUserInfo)) {
            APP_LOGW("Get calling userInfo in bundle(%{public}s) failed", bundleName.c_str());
            return;
        }
        NotifyBundleEvents installRes = {
            .bundleName = bundleName,
            .resultCode = ERR_OK,
            .type = NotifyType::BUNDLE_CACHE_CLEARED,
            .uid = innerBundleUserInfo.uid,
            .accessTokenId = innerBundleUserInfo.accessTokenId
        };
        NotifyBundleStatus(installRes);
    };
    handler_->PostTask(cleanCache);
}

bool BundleMgrHostImpl::CleanBundleDataFiles(const std::string &bundleName, const int userId)
{
    APP_LOGD("start CleanBundleDataFiles, bundleName : %{public}s, userId : %{public}d", bundleName.c_str(), userId);
    if (!VerifySystemApi()) {
        APP_LOGE("ohos.permission.REMOVE_CACHE_FILES system api denied");
        EventReport::SendCleanCacheSysEvent(bundleName, userId, false, true);
        return false;
    }
    if (bundleName.empty() || userId < 0) {
        APP_LOGE("the  bundleName empty or invalid userid");
        EventReport::SendCleanCacheSysEvent(bundleName, userId, false, true);
        return false;
    }
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_REMOVECACHEFILE)) {
        APP_LOGE("ohos.permission.REMOVE_CACHE_FILES permission denied");
        EventReport::SendCleanCacheSysEvent(bundleName, userId, false, true);
        return false;
    }
    ApplicationInfo applicationInfo;
    if (GetApplicationInfoV9(bundleName, static_cast<int32_t>(GetApplicationFlag::GET_APPLICATION_INFO_WITH_DISABLE),
        userId, applicationInfo) != ERR_OK) {
        APP_LOGE("can not get application info of %{public}s", bundleName.c_str());
        EventReport::SendCleanCacheSysEvent(bundleName, userId, false, true);
        return false;
    }

    if (applicationInfo.isSystemApp && !applicationInfo.userDataClearable) {
        APP_LOGE("can not clean dataFiles of %{public}s due to userDataClearable is false", bundleName.c_str());
        EventReport::SendCleanCacheSysEvent(bundleName, userId, false, true);
        return false;
    }

    InnerBundleUserInfo innerBundleUserInfo;
    if (!GetBundleUserInfo(bundleName, userId, innerBundleUserInfo)) {
        APP_LOGE("%{public}s, userId:%{public}d, GetBundleUserInfo failed", bundleName.c_str(), userId);
        EventReport::SendCleanCacheSysEvent(bundleName, userId, false, true);
        return false;
    }

    if (BundlePermissionMgr::ClearUserGrantedPermissionState(applicationInfo.accessTokenId)) {
        APP_LOGE("%{public}s, ClearUserGrantedPermissionState failed", bundleName.c_str());
        EventReport::SendCleanCacheSysEvent(bundleName, userId, false, true);
        return false;
    }

    if (InstalldClient::GetInstance()->RemoveBundleDataDir(bundleName, userId) != ERR_OK) {
        APP_LOGE("%{public}s, RemoveBundleDataDir failed", bundleName.c_str());
        EventReport::SendCleanCacheSysEvent(bundleName, userId, false, true);
        return false;
    }

    if (InstalldClient::GetInstance()->CreateBundleDataDir(bundleName, userId, innerBundleUserInfo.uid,
        innerBundleUserInfo.uid, GetAppPrivilegeLevel(bundleName, userId))) {
        APP_LOGE("%{public}s, CreateBundleDataDir failed", bundleName.c_str());
        EventReport::SendCleanCacheSysEvent(bundleName, userId, false, true);
        return false;
    }

    EventReport::SendCleanCacheSysEvent(bundleName, userId, false, false);
    return true;
}

bool BundleMgrHostImpl::RegisterBundleStatusCallback(const sptr<IBundleStatusCallback> &bundleStatusCallback)
{
    APP_LOGD("start RegisterBundleStatusCallback");
    if ((!bundleStatusCallback) || (bundleStatusCallback->GetBundleName().empty())) {
        APP_LOGE("the bundleStatusCallback is nullptr or bundleName empty");
        return false;
    }
    // check permission
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::LISTEN_BUNDLE_CHANGE)) {
        APP_LOGE("register bundle status callback failed due to lack of permission");
        return false;
    }

    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->RegisterBundleStatusCallback(bundleStatusCallback);
}

bool BundleMgrHostImpl::RegisterBundleEventCallback(const sptr<IBundleEventCallback> &bundleEventCallback)
{
    APP_LOGD("begin to RegisterBundleEventCallback");
    if (bundleEventCallback == nullptr) {
        APP_LOGE("bundleEventCallback is null");
        return false;
    }
    if (IPCSkeleton::GetCallingUid() != Constants::FOUNDATION_UID) {
        APP_LOGE("verify calling uid failed");
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->RegisterBundleEventCallback(bundleEventCallback);
}

bool BundleMgrHostImpl::UnregisterBundleEventCallback(const sptr<IBundleEventCallback> &bundleEventCallback)
{
    APP_LOGD("begin to UnregisterBundleEventCallback");
    if (bundleEventCallback == nullptr) {
        APP_LOGE("bundleEventCallback is null");
        return false;
    }
    if (IPCSkeleton::GetCallingUid() != Constants::FOUNDATION_UID) {
        APP_LOGE("verify calling uid failed");
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->UnregisterBundleEventCallback(bundleEventCallback);
}

bool BundleMgrHostImpl::ClearBundleStatusCallback(const sptr<IBundleStatusCallback> &bundleStatusCallback)
{
    APP_LOGD("start ClearBundleStatusCallback");
    if (!bundleStatusCallback) {
        APP_LOGE("the bundleStatusCallback is nullptr");
        return false;
    }

    // check permission
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::LISTEN_BUNDLE_CHANGE)) {
        APP_LOGE("register bundle status callback failed due to lack of permission");
        return false;
    }

    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->ClearBundleStatusCallback(bundleStatusCallback);
}

bool BundleMgrHostImpl::UnregisterBundleStatusCallback()
{
    APP_LOGD("start UnregisterBundleStatusCallback");
    // check permission
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::LISTEN_BUNDLE_CHANGE)) {
        APP_LOGE("register bundle status callback failed due to lack of permission");
        return false;
    }

    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->UnregisterBundleStatusCallback();
}

bool BundleMgrHostImpl::DumpInfos(
    const DumpFlag flag, const std::string &bundleName, int32_t userId, std::string &result)
{
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify permission failed");
        return false;
    }
    bool ret = false;
    switch (flag) {
        case DumpFlag::DUMP_BUNDLE_LIST: {
            ret = DumpAllBundleInfoNames(userId, result);
            break;
        }
        case DumpFlag::DUMP_BUNDLE_INFO: {
            ret = DumpBundleInfo(bundleName, userId, result);
            break;
        }
        case DumpFlag::DUMP_SHORTCUT_INFO: {
            ret = DumpShortcutInfo(bundleName, userId, result);
            break;
        }
        default:
            APP_LOGE("dump flag error");
            return false;
    }
    return ret;
}

bool BundleMgrHostImpl::DumpAllBundleInfoNames(int32_t userId, std::string &result)
{
    APP_LOGD("DumpAllBundleInfoNames begin");
    if (userId != Constants::ALL_USERID) {
        return DumpAllBundleInfoNamesByUserId(userId, result);
    }

    auto userIds = GetExistsCommonUserIs();
    for (auto userId : userIds) {
        DumpAllBundleInfoNamesByUserId(userId, result);
    }

    APP_LOGD("DumpAllBundleInfoNames success");
    return true;
}

bool BundleMgrHostImpl::DumpAllBundleInfoNamesByUserId(int32_t userId, std::string &result)
{
    APP_LOGI("DumpAllBundleInfoNamesByUserId begin");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }

    std::vector<std::string> bundleNames;
    if (!dataMgr->GetBundleList(bundleNames, userId)) {
        APP_LOGE("get bundle list failed by userId(%{public}d)", userId);
        return false;
    }

    result.append("ID: ");
    result.append(std::to_string(userId));
    result.append(":\n");
    for (const auto &name : bundleNames) {
        result.append("\t");
        result.append(name);
        result.append("\n");
    }
    APP_LOGI("DumpAllBundleInfoNamesByUserId successfully");
    return true;
}

bool BundleMgrHostImpl::DumpBundleInfo(
    const std::string &bundleName, int32_t userId, std::string &result)
{
    APP_LOGD("DumpBundleInfo begin");
    std::vector<InnerBundleUserInfo> innerBundleUserInfos;
    if (userId == Constants::ALL_USERID) {
        if (!GetBundleUserInfos(bundleName, innerBundleUserInfos)) {
            APP_LOGE("get all userInfos in bundle(%{public}s) failed", bundleName.c_str());
            return false;
        }
        userId = innerBundleUserInfos.begin()->bundleUserInfo.userId;
    } else {
        InnerBundleUserInfo innerBundleUserInfo;
        if (!GetBundleUserInfo(bundleName, userId, innerBundleUserInfo)) {
            APP_LOGI("get userInfo in bundle(%{public}s) failed", bundleName.c_str());
        }
        innerBundleUserInfos.emplace_back(innerBundleUserInfo);
    }

    BundleInfo bundleInfo;
    if (!GetBundleInfo(bundleName,
        BundleFlag::GET_BUNDLE_WITH_ABILITIES |
        BundleFlag::GET_BUNDLE_WITH_REQUESTED_PERMISSION |
        BundleFlag::GET_BUNDLE_WITH_EXTENSION_INFO |
        BundleFlag::GET_BUNDLE_WITH_HASH_VALUE, bundleInfo, userId)) {
        APP_LOGE("get bundleInfo(%{public}s) failed", bundleName.c_str());
        return false;
    }

    result.append(bundleName);
    result.append(":\n");
    nlohmann::json jsonObject = bundleInfo;
    jsonObject.erase("abilityInfos");
    jsonObject.erase("extensionAbilityInfo");
    for (auto &hapModule : jsonObject["hapModuleInfos"]) {
        for (auto &ability : hapModule["abilityInfos"]) {
            ability.erase("applicationInfo");
        }
        for (auto &extension : hapModule["extensionInfos"]) {
            extension.erase("applicationInfo");
        }
    }
    jsonObject["userInfo"] = innerBundleUserInfos;
    result.append(jsonObject.dump(Constants::DUMP_INDENT));
    result.append("\n");
    APP_LOGI("DumpBundleInfo success with bundleName %{public}s", bundleName.c_str());
    return true;
}

bool BundleMgrHostImpl::DumpShortcutInfo(
    const std::string &bundleName, int32_t userId, std::string &result)
{
    APP_LOGD("DumpShortcutInfo begin");
    std::vector<ShortcutInfo> shortcutInfos;
    if (userId == Constants::ALL_USERID) {
        std::vector<InnerBundleUserInfo> innerBundleUserInfos;
        if (!GetBundleUserInfos(bundleName, innerBundleUserInfos)) {
            APP_LOGE("get all userInfos in bundle(%{public}s) failed", bundleName.c_str());
            return false;
        }
        userId = innerBundleUserInfos.begin()->bundleUserInfo.userId;
    }

    if (!GetShortcutInfos(bundleName, userId, shortcutInfos)) {
        APP_LOGE("get all shortcut info by bundle(%{public}s) failed", bundleName.c_str());
        return false;
    }

    result.append("shortcuts");
    result.append(":\n");
    for (const auto &info : shortcutInfos) {
        result.append("\"shortcut\"");
        result.append(":\n");
        nlohmann::json jsonObject = info;
        result.append(jsonObject.dump(Constants::DUMP_INDENT));
        result.append("\n");
    }
    APP_LOGD("DumpShortcutInfo success with bundleName %{public}s", bundleName.c_str());
    return true;
}

ErrCode BundleMgrHostImpl::IsModuleRemovable(const std::string &bundleName, const std::string &moduleName,
    bool &isRemovable)
{
    // check permission
    if (!VerifySystemApi()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("IsModuleRemovable failed due to lack of permission");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    return dataMgr->IsModuleRemovable(bundleName, moduleName, isRemovable);
}

bool BundleMgrHostImpl::SetModuleRemovable(const std::string &bundleName, const std::string &moduleName, bool isEnable)
{
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("SetModuleRemovable failed due to lack of permission");
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->SetModuleRemovable(bundleName, moduleName, isEnable);
}

bool BundleMgrHostImpl::GetModuleUpgradeFlag(const std::string &bundleName, const std::string &moduleName)
{
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_INSTALL_BUNDLE)) {
        APP_LOGE("GetModuleUpgradeFlag failed due to lack of permission");
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->GetModuleUpgradeFlag(bundleName, moduleName);
}

ErrCode BundleMgrHostImpl::SetModuleUpgradeFlag(const std::string &bundleName,
    const std::string &moduleName, int32_t upgradeFlag)
{
    // check permission
    if (!VerifySystemApi(Constants::API_VERSION_NINE)) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_INSTALL_BUNDLE)) {
        APP_LOGE("SetModuleUpgradeFlag failed due to lack of permission");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    return dataMgr->SetModuleUpgradeFlag(bundleName, moduleName, upgradeFlag);
}

ErrCode BundleMgrHostImpl::IsApplicationEnabled(const std::string &bundleName, bool &isEnable)
{
    APP_LOGD("start IsApplicationEnabled, bundleName : %{public}s", bundleName.c_str());
    if (!VerifySystemApi(Constants::API_VERSION_NINE)) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_APPEXECFWK_SERVICE_NOT_READY;
    }
    return dataMgr->IsApplicationEnabled(bundleName, isEnable);
}

ErrCode BundleMgrHostImpl::SetApplicationEnabled(const std::string &bundleName, bool isEnable, int32_t userId)
{
    APP_LOGD("SetApplicationEnabled begin");
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = BundleUtil::GetUserIdByCallingUid();
    }
    if (!VerifySystemApi()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_CHANGE_ABILITY_ENABLED_STATE)) {
        APP_LOGE("verify permission failed");
        EventReport::SendComponentStateSysEvent(bundleName, "", userId, isEnable, true);
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    APP_LOGD("verify permission success, begin to SetApplicationEnabled");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        EventReport::SendComponentStateSysEvent(bundleName, "", userId, isEnable, true);
        return ERR_APPEXECFWK_SERVICE_NOT_READY;
    }

    auto ret = dataMgr->SetApplicationEnabled(bundleName, isEnable, userId);
    if (ret != ERR_OK) {
        APP_LOGE("Set application(%{public}s) enabled value faile.", bundleName.c_str());
        EventReport::SendComponentStateSysEvent(bundleName, "", userId, isEnable, true);
        return ret;
    }

    EventReport::SendComponentStateSysEvent(bundleName, "", userId, isEnable, false);
    InnerBundleUserInfo innerBundleUserInfo;
    if (!GetBundleUserInfo(bundleName, userId, innerBundleUserInfo)) {
        APP_LOGE("Get calling userInfo in bundle(%{public}s) failed", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    NotifyBundleEvents installRes = {
        .bundleName = bundleName,
        .resultCode = ERR_OK,
        .type = NotifyType::APPLICATION_ENABLE,
        .uid = innerBundleUserInfo.uid,
        .accessTokenId = innerBundleUserInfo.accessTokenId
    };
    NotifyBundleStatus(installRes);
    APP_LOGD("SetApplicationEnabled finish");
    return ERR_OK;
}

ErrCode BundleMgrHostImpl::IsAbilityEnabled(const AbilityInfo &abilityInfo, bool &isEnable)
{
    APP_LOGD("start IsAbilityEnabled");
    if (!VerifySystemApi(Constants::API_VERSION_NINE)) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_APPEXECFWK_SERVICE_NOT_READY;
    }
    return dataMgr->IsAbilityEnabled(abilityInfo, isEnable);
}

ErrCode BundleMgrHostImpl::SetAbilityEnabled(const AbilityInfo &abilityInfo, bool isEnabled, int32_t userId)
{
    APP_LOGD("start SetAbilityEnabled");
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = BundleUtil::GetUserIdByCallingUid();
    }
    if (!VerifySystemApi()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_CHANGE_ABILITY_ENABLED_STATE)) {
        APP_LOGE("verify permission failed");
        EventReport::SendComponentStateSysEvent(
            abilityInfo.bundleName, abilityInfo.name, userId, isEnabled, true);
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }

    APP_LOGD("verify permission success, begin to SetAbilityEnabled");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        EventReport::SendComponentStateSysEvent(
            abilityInfo.bundleName, abilityInfo.name, userId, isEnabled, true);
        return ERR_APPEXECFWK_SERVICE_NOT_READY;
    }
    auto ret = dataMgr->SetAbilityEnabled(abilityInfo, isEnabled, userId);
    if (ret != ERR_OK) {
        APP_LOGE("Set ability(%{public}s) enabled value failed.", abilityInfo.bundleName.c_str());
        EventReport::SendComponentStateSysEvent(
            abilityInfo.bundleName, abilityInfo.name, userId, isEnabled, true);
        return ret;
    }

    EventReport::SendComponentStateSysEvent(
        abilityInfo.bundleName, abilityInfo.name, userId, isEnabled, false);
    InnerBundleUserInfo innerBundleUserInfo;
    if (!GetBundleUserInfo(abilityInfo.bundleName, userId, innerBundleUserInfo)) {
        APP_LOGE("Get calling userInfo in bundle(%{public}s) failed", abilityInfo.bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    NotifyBundleEvents installRes = {
        .bundleName = abilityInfo.bundleName,
        .abilityName = abilityInfo.name,
        .resultCode = ERR_OK,
        .type = NotifyType::APPLICATION_ENABLE,
        .uid = innerBundleUserInfo.uid,
        .accessTokenId = innerBundleUserInfo.accessTokenId,
    };
    NotifyBundleStatus(installRes);
    return ERR_OK;
}

sptr<IBundleInstaller> BundleMgrHostImpl::GetBundleInstaller()
{
    APP_LOGD("start GetBundleInstaller");
    if (!VerifySystemApi()) {
        APP_LOGE("non-system app calling system api");
        return nullptr;
    }
    return DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleInstaller();
}

sptr<IBundleUserMgr> BundleMgrHostImpl::GetBundleUserMgr()
{
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid != Constants::ACCOUNT_UID) {
        APP_LOGE("invalid calling uid %{public}d to GetbundleUserMgr", callingUid);
        return nullptr;
    }
    return DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleUserMgr();
}

bool BundleMgrHostImpl::GetAllFormsInfo(std::vector<FormInfo> &formInfos)
{
    APP_LOGD("start GetAllFormsInfo");
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify permission failed");
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->GetAllFormsInfo(formInfos);
}

bool BundleMgrHostImpl::GetFormsInfoByApp(const std::string &bundleName, std::vector<FormInfo> &formInfos)
{
    APP_LOGD("start GetFormsInfoByApp, bundleName : %{public}s", bundleName.c_str());
    if (!VerifyQueryPermission(bundleName)) {
        APP_LOGE("verify permission failed");
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->GetFormsInfoByApp(bundleName, formInfos);
}

bool BundleMgrHostImpl::GetFormsInfoByModule(
    const std::string &bundleName, const std::string &moduleName, std::vector<FormInfo> &formInfos)
{
    APP_LOGD("start GetFormsInfoByModule, bundleName : %{public}s, moduleName : %{public}s",
        bundleName.c_str(), moduleName.c_str());
    if (!VerifyQueryPermission(bundleName)) {
        APP_LOGE("verify permission failed");
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->GetFormsInfoByModule(bundleName, moduleName, formInfos);
}

bool BundleMgrHostImpl::GetShortcutInfos(
    const std::string &bundleName, std::vector<ShortcutInfo> &shortcutInfos)
{
    return GetShortcutInfos(bundleName, Constants::UNSPECIFIED_USERID, shortcutInfos);
}

bool BundleMgrHostImpl::GetShortcutInfos(
    const std::string &bundleName, int32_t userId, std::vector<ShortcutInfo> &shortcutInfos)
{
    APP_LOGD("start GetShortcutInfos, bundleName : %{public}s, userId : %{public}d", bundleName.c_str(), userId);
    if (!VerifySystemApi(Constants::API_VERSION_NINE)) {
        APP_LOGD("non-system app calling system api");
        return true;
    }
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify permission failed");
        return false;
    }
    APP_LOGD("verify permission success, begin to GetShortcutInfos");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->GetShortcutInfos(bundleName, userId, shortcutInfos);
}

ErrCode BundleMgrHostImpl::GetShortcutInfoV9(const std::string &bundleName, std::vector<ShortcutInfo> &shortcutInfos)
{
    if (!VerifySystemApi()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!VerifyPrivilegedPermission(bundleName)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->GetShortcutInfoV9(bundleName, Constants::UNSPECIFIED_USERID, shortcutInfos);
}

bool BundleMgrHostImpl::GetAllCommonEventInfo(const std::string &eventKey,
    std::vector<CommonEventInfo> &commonEventInfos)
{
    APP_LOGD("start GetAllCommonEventInfo, eventKey : %{public}s", eventKey.c_str());
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify permission failed");
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->GetAllCommonEventInfo(eventKey, commonEventInfos);
}

bool BundleMgrHostImpl::GetDistributedBundleInfo(const std::string &networkId, const std::string &bundleName,
    DistributedBundleInfo &distributedBundleInfo)
{
    APP_LOGD("start GetDistributedBundleInfo, bundleName : %{public}s", bundleName.c_str());
#ifdef DISTRIBUTED_BUNDLE_FRAMEWORK
    if (!VerifyQueryPermission(bundleName)) {
        APP_LOGE("verify permission failed");
        return false;
    }
    auto distributedBundleMgr = GetDistributedBundleMgrService();
    if (distributedBundleMgr == nullptr) {
        APP_LOGE("DistributedBundleMgrService is nullptr");
        return false;
    }
    return distributedBundleMgr->GetDistributedBundleInfo(networkId, bundleName, distributedBundleInfo);
#else
    APP_LOGW("DISTRIBUTED_BUNDLE_FRAMEWORK is false");
    return false;
#endif
}

bool BundleMgrHostImpl::QueryExtensionAbilityInfos(const Want &want, const int32_t &flag, const int32_t &userId,
    std::vector<ExtensionAbilityInfo> &extensionInfos)
{
    APP_LOGD("QueryExtensionAbilityInfos without type begin");
    if (!VerifySystemApi(Constants::API_VERSION_NINE)) {
        APP_LOGD("non-system app calling system api");
        return true;
    }
    if (!VerifyQueryPermission(want.GetElement().GetBundleName())) {
        APP_LOGE("verify permission failed");
        return false;
    }
    APP_LOGD("want uri is %{private}s", want.GetUriString().c_str());
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    bool ret = dataMgr->QueryExtensionAbilityInfos(want, flag, userId, extensionInfos);
    if (!ret) {
        APP_LOGE("QueryExtensionAbilityInfos is failed");
        return false;
    }
    if (extensionInfos.empty()) {
        APP_LOGE("no valid extension info can be inquired");
        return false;
    }
    return true;
}

ErrCode BundleMgrHostImpl::QueryExtensionAbilityInfosV9(const Want &want, int32_t flags, int32_t userId,
    std::vector<ExtensionAbilityInfo> &extensionInfos)
{
    APP_LOGD("QueryExtensionAbilityInfosV9 without type begin");
    if (!VerifySystemApi()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!VerifyQueryPermission(want.GetElement().GetBundleName())) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    APP_LOGD("want uri is %{private}s", want.GetUriString().c_str());
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    ErrCode ret = dataMgr->QueryExtensionAbilityInfosV9(want, flags, userId, extensionInfos);
    if (ret != ERR_OK) {
        APP_LOGE("QueryExtensionAbilityInfosV9 is failed");
        return ret;
    }
    if (extensionInfos.empty()) {
        APP_LOGE("no valid extension info can be inquired");
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }
    return ERR_OK;
}

bool BundleMgrHostImpl::QueryExtensionAbilityInfos(const Want &want, const ExtensionAbilityType &extensionType,
    const int32_t &flag, const int32_t &userId, std::vector<ExtensionAbilityInfo> &extensionInfos)
{
    APP_LOGD("QueryExtensionAbilityInfos begin");
    if (!VerifySystemApi(Constants::API_VERSION_NINE)) {
        APP_LOGD("non-system app calling system api");
        return true;
    }
    if (!VerifyQueryPermission(want.GetElement().GetBundleName())) {
        APP_LOGE("verify permission failed");
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    std::vector<ExtensionAbilityInfo> infos;
    bool ret = dataMgr->QueryExtensionAbilityInfos(want, flag, userId, infos);
    if (!ret) {
        APP_LOGE("QueryExtensionAbilityInfos is failed");
        return false;
    }
    for_each(infos.begin(), infos.end(), [&extensionType, &extensionInfos](const auto &info)->decltype(auto) {
        APP_LOGD("QueryExtensionAbilityInfos extensionType is %{public}d, info.type is %{public}d",
            static_cast<int32_t>(extensionType), static_cast<int32_t>(info.type));
        if (extensionType == info.type) {
            extensionInfos.emplace_back(info);
        }
    });
    if (extensionInfos.empty()) {
        APP_LOGE("no valid extension info can be inquired");
        return false;
    }
    return true;
}

ErrCode BundleMgrHostImpl::QueryExtensionAbilityInfosV9(const Want &want, const ExtensionAbilityType &extensionType,
    int32_t flags, int32_t userId, std::vector<ExtensionAbilityInfo> &extensionInfos)
{
    APP_LOGD("QueryExtensionAbilityInfosV9 begin");
    if (!VerifySystemApi()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!VerifyQueryPermission(want.GetElement().GetBundleName())) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    std::vector<ExtensionAbilityInfo> infos;
    ErrCode ret = dataMgr->QueryExtensionAbilityInfosV9(want, flags, userId, infos);
    if (ret != ERR_OK) {
        APP_LOGE("QueryExtensionAbilityInfosV9 is failed");
        return ret;
    }
    for_each(infos.begin(), infos.end(), [&extensionType, &extensionInfos](const auto &info)->decltype(auto) {
        APP_LOGD("QueryExtensionAbilityInfosV9 extensionType is %{public}d, info.type is %{public}d",
            static_cast<int32_t>(extensionType), static_cast<int32_t>(info.type));
        if (extensionType == info.type) {
            extensionInfos.emplace_back(info);
        }
    });
    if (extensionInfos.empty()) {
        APP_LOGE("no valid extension info can be inquired");
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }
    return ERR_OK;
}

bool BundleMgrHostImpl::QueryExtensionAbilityInfos(const ExtensionAbilityType &extensionType, const int32_t &userId,
    std::vector<ExtensionAbilityInfo> &extensionInfos)
{
    APP_LOGD("QueryExtensionAbilityInfos with type begin");
    if (!VerifySystemApi(Constants::API_VERSION_NINE)) {
        APP_LOGD("non-system app calling system api");
        return true;
    }
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify permission failed");
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    bool ret = dataMgr->QueryExtensionAbilityInfos(extensionType, userId, extensionInfos);
    if (!ret) {
        APP_LOGE("QueryExtensionAbilityInfos is failed");
        return false;
    }

    if (extensionInfos.empty()) {
        APP_LOGE("no valid extension info can be inquired");
        return false;
    }
    return true;
}

const std::shared_ptr<BundleDataMgr> BundleMgrHostImpl::GetDataMgrFromService()
{
    return DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
}

#ifdef DISTRIBUTED_BUNDLE_FRAMEWORK
const OHOS::sptr<IDistributedBms> BundleMgrHostImpl::GetDistributedBundleMgrService()
{
    auto saMgr = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr == nullptr) {
        APP_LOGE("saMgr is nullptr");
        return nullptr;
    }
    OHOS::sptr<OHOS::IRemoteObject> remoteObject =
        saMgr->CheckSystemAbility(OHOS::DISTRIBUTED_BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    return OHOS::iface_cast<IDistributedBms>(remoteObject);
}
#endif

#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
const std::shared_ptr<BundleConnectAbilityMgr> BundleMgrHostImpl::GetConnectAbilityMgrFromService()
{
    return DelayedSingleton<BundleMgrService>::GetInstance()->GetConnectAbility();
}
#endif

std::set<int32_t> BundleMgrHostImpl::GetExistsCommonUserIs()
{
    std::set<int32_t> userIds;
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return userIds;
    }

    for (auto userId : dataMgr->GetAllUser()) {
        if (userId >= Constants::START_USERID) {
            userIds.insert(userId);
        }
    }
    return userIds;
}

bool BundleMgrHostImpl::VerifyQueryPermission(const std::string &queryBundleName)
{
    std::string callingBundleName;
    bool ret = GetBundleNameForUid(IPCSkeleton::GetCallingUid(), callingBundleName);
    APP_LOGD("callingBundleName : %{public}s", callingBundleName.c_str());
    if (ret && (queryBundleName == callingBundleName)) {
        APP_LOGD("query own info, verify success");
        return true;
    }
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO) &&
        !BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify query permission failed");
        return false;
    }
    APP_LOGD("verify query permission successfully");
    return true;
}

bool BundleMgrHostImpl::VerifyPrivilegedPermission(const std::string &queryBundleName)
{
    std::string callingBundleName;
    bool ret = GetBundleNameForUid(IPCSkeleton::GetCallingUid(), callingBundleName);
    APP_LOGD("callingBundleName : %{public}s", callingBundleName.c_str());
    if (ret && (queryBundleName == callingBundleName)) {
        APP_LOGD("query own info, verify success");
        return true;
    }
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify query permission failed");
        return false;
    }
    APP_LOGD("verify query permission successfully");
    return true;
}

std::string BundleMgrHostImpl::GetAppPrivilegeLevel(const std::string &bundleName, int32_t userId)
{
    APP_LOGD("start GetAppPrivilegeLevel");
    if (!VerifyQueryPermission(bundleName)) {
        APP_LOGE("verify permission failed");
        return Constants::EMPTY_STRING;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return Constants::EMPTY_STRING;
    }
    return dataMgr->GetAppPrivilegeLevel(bundleName, userId);
}

bool BundleMgrHostImpl::VerifyCallingPermission(const std::string &permission)
{
    APP_LOGD("VerifyCallingPermission begin");
    return BundlePermissionMgr::VerifyCallingPermission(permission);
}

std::vector<std::string> BundleMgrHostImpl::GetAccessibleAppCodePaths(int32_t userId)
{
    APP_LOGD("GetAccessibleAppCodePaths begin");
    if (!BundlePermissionMgr::IsNativeTokenType()) {
        APP_LOGE("verify token type failed");
        std::vector<std::string> vec;
        return vec;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        std::vector<std::string> vec;
        return vec;
    }

    return dataMgr->GetAccessibleAppCodePaths(userId);
}

bool BundleMgrHostImpl::QueryExtensionAbilityInfoByUri(const std::string &uri, int32_t userId,
    ExtensionAbilityInfo &extensionAbilityInfo)
{
    APP_LOGD("uri : %{private}s, userId : %{public}d", uri.c_str(), userId);
    if (!VerifySystemApi(Constants::API_VERSION_NINE)) {
        APP_LOGE("non-system app calling system api");
        return true;
    }
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO) &&
        !BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify query permission failed");
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->QueryExtensionAbilityInfoByUri(uri, userId, extensionAbilityInfo);
}

std::string BundleMgrHostImpl::GetAppIdByBundleName(const std::string &bundleName, const int userId)
{
    APP_LOGD("bundleName : %{public}s, userId : %{public}d", bundleName.c_str(), userId);
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO) &&
        !BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify query permission failed");
        return Constants::EMPTY_STRING;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return Constants::EMPTY_STRING;
    }
    BundleInfo bundleInfo;
    bool ret = dataMgr->GetBundleInfo(bundleName, GET_BUNDLE_DEFAULT, bundleInfo, userId);
    if (!ret) {
        APP_LOGE("get bundleInfo failed");
        return Constants::EMPTY_STRING;
    }
    APP_LOGD("appId is %{private}s", bundleInfo.appId.c_str());
    return bundleInfo.appId;
}

std::string BundleMgrHostImpl::GetAppType(const std::string &bundleName)
{
    APP_LOGD("bundleName : %{public}s", bundleName.c_str());
    if (!VerifyQueryPermission(bundleName)) {
        APP_LOGE("verify permission failed");
        return Constants::EMPTY_STRING;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return Constants::EMPTY_STRING;
    }
    BundleInfo bundleInfo;
    bool ret = dataMgr->GetBundleInfo(bundleName, GET_BUNDLE_DEFAULT, bundleInfo, Constants::UNSPECIFIED_USERID);
    if (!ret) {
        APP_LOGE("get bundleInfo failed");
        return Constants::EMPTY_STRING;
    }
    bool isSystemApp = bundleInfo.applicationInfo.isSystemApp;
    std::string appType = isSystemApp ? Constants::SYSTEM_APP : Constants::THIRD_PARTY_APP;
    APP_LOGD("appType is %{public}s", appType.c_str());
    return appType;
}

int BundleMgrHostImpl::GetUidByBundleName(const std::string &bundleName, const int userId)
{
    APP_LOGD("bundleName : %{public}s, userId : %{public}d", bundleName.c_str(), userId);
    if (!BundlePermissionMgr::IsNativeTokenType()) {
        APP_LOGE("verify token type failed");
        return Constants::INVALID_UID;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return Constants::INVALID_UID;
    }
    std::vector<BundleInfo> bundleInfos;
    int32_t uid = Constants::INVALID_UID;
    bool ret = dataMgr->GetBundleInfos(GET_BUNDLE_DEFAULT, bundleInfos, userId);
    if (ret) {
        for (auto bundleInfo : bundleInfos) {
            if (bundleInfo.name == bundleName) {
                uid = bundleInfo.uid;
                break;
            }
        }
        APP_LOGD("get bundle uid success");
    } else {
        APP_LOGE("can not get bundleInfo's uid");
    }
    APP_LOGD("uid is %{public}d", uid);
    return uid;
}

int BundleMgrHostImpl::GetUidByDebugBundleName(const std::string &bundleName, const int userId)
{
    APP_LOGD("bundleName : %{public}s, userId : %{public}d", bundleName.c_str(), userId);
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return Constants::INVALID_UID;
    }
    ApplicationInfo appInfo;
    int32_t uid = Constants::INVALID_UID;
    bool ret = dataMgr->GetApplicationInfo(bundleName, GET_BUNDLE_DEFAULT, userId, appInfo);
    if (ret && appInfo.debug) {
        uid = appInfo.uid;
        APP_LOGD("get debug bundle uid success, uid is %{public}d", uid);
    } else {
        APP_LOGE("can not get bundleInfo's uid");
    }
    return uid;
}

bool BundleMgrHostImpl::GetAbilityInfo(
    const std::string &bundleName, const std::string &abilityName, AbilityInfo &abilityInfo)
{
    APP_LOGD("start GetAbilityInfo, bundleName : %{public}s, abilityName : %{public}s",
        bundleName.c_str(), abilityName.c_str());
    ElementName elementName("", bundleName, abilityName);
    Want want;
    want.SetElement(elementName);
    return QueryAbilityInfo(want, abilityInfo);
}

bool BundleMgrHostImpl::GetAbilityInfo(
    const std::string &bundleName, const std::string &moduleName,
    const std::string &abilityName, AbilityInfo &abilityInfo)
{
    APP_LOGD("start GetAbilityInfo, bundleName : %{public}s, moduleName : %{public}s, abilityName : %{public}s",
        bundleName.c_str(), moduleName.c_str(), abilityName.c_str());
    if (!VerifySystemApi(Constants::API_VERSION_NINE)) {
        APP_LOGD("non-system app calling system api");
        return true;
    }
    ElementName elementName("", bundleName, abilityName, moduleName);
    Want want;
    want.SetElement(elementName);
    return QueryAbilityInfo(want, abilityInfo);
}

bool BundleMgrHostImpl::ImplicitQueryInfoByPriority(const Want &want, int32_t flags, int32_t userId,
    AbilityInfo &abilityInfo, ExtensionAbilityInfo &extensionInfo)
{
    APP_LOGD("start ImplicitQueryInfoByPriority, flags : %{public}d, userId : %{public}d", flags, userId);
    if (!VerifySystemApi(Constants::API_VERSION_NINE)) {
        APP_LOGD("non-system app calling system api");
        return true;
    }
    if (!VerifyQueryPermission(want.GetElement().GetBundleName())) {
        APP_LOGE("verify permission failed");
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->ImplicitQueryInfoByPriority(want, flags, userId, abilityInfo, extensionInfo);
}

bool BundleMgrHostImpl::ImplicitQueryInfos(const Want &want, int32_t flags, int32_t userId,
    std::vector<AbilityInfo> &abilityInfos, std::vector<ExtensionAbilityInfo> &extensionInfos)
{
    APP_LOGD("begin to ImplicitQueryInfos, flags : %{public}d, userId : %{public}d", flags, userId);
    if (!VerifySystemApi(Constants::API_VERSION_NINE)) {
        APP_LOGD("non-system app calling system api");
        return true;
    }
    if (!VerifyQueryPermission(want.GetElement().GetBundleName())) {
        APP_LOGE("verify permission failed");
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->ImplicitQueryInfos(want, flags, userId, abilityInfos, extensionInfos);
}

int BundleMgrHostImpl::Dump(int fd, const std::vector<std::u16string> &args)
{
    std::string result;
    std::vector<std::string> argsStr;
    for (auto item : args) {
        argsStr.emplace_back(Str16ToStr8(item));
    }

    if (!DelayedSingleton<BundleMgrService>::GetInstance()->Hidump(argsStr, result)) {
        APP_LOGE("Hidump error");
        return ERR_APPEXECFWK_HIDUMP_ERROR;
    }

    int ret = dprintf(fd, "%s\n", result.c_str());
    if (ret < 0) {
        APP_LOGE("dprintf error");
        return ERR_APPEXECFWK_HIDUMP_ERROR;
    }

    return ERR_OK;
}

bool BundleMgrHostImpl::GetAllDependentModuleNames(const std::string &bundleName, const std::string &moduleName,
    std::vector<std::string> &dependentModuleNames)
{
    APP_LOGD("GetAllDependentModuleNames: bundleName: %{public}s, moduleName: %{public}s",
        bundleName.c_str(), moduleName.c_str());
    if (!VerifyQueryPermission(bundleName)) {
        APP_LOGE("verify permission failed");
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->GetAllDependentModuleNames(bundleName, moduleName, dependentModuleNames);
}

ErrCode BundleMgrHostImpl::GetSandboxBundleInfo(
    const std::string &bundleName, int32_t appIndex, int32_t userId, BundleInfo &info)
{
    APP_LOGD("start GetSandboxBundleInfo, bundleName : %{public}s, appindex : %{public}d, userId : %{public}d",
        bundleName.c_str(), appIndex, userId);
    // check bundle name
    if (bundleName.empty()) {
        APP_LOGE("GetSandboxBundleInfo failed due to empty bundleName");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR;
    }
    // check appIndex
    if (appIndex <= Constants::INITIAL_APP_INDEX || appIndex > Constants::MAX_APP_INDEX) {
        APP_LOGE("the appIndex %{public}d is invalid", appIndex);
        return ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR;
    }
    if (!VerifyQueryPermission(bundleName)) {
        APP_LOGE("verify permission failed");
        return ERR_APPEXECFWK_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_INTERNAL_ERROR;
    }
    auto sandboxAppHelper = dataMgr->GetSandboxAppHelper();
    if (sandboxAppHelper == nullptr) {
        APP_LOGE("sandboxAppHelper is nullptr");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_INTERNAL_ERROR;
    }
    int32_t requestUserId = dataMgr->GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return ERR_APPEXECFWK_SANDBOX_QUERY_INVALID_USER_ID;
    }
    return sandboxAppHelper->GetSandboxAppBundleInfo(bundleName, appIndex, requestUserId, info);
}

bool BundleMgrHostImpl::SetDisposedStatus(const std::string &bundleName, int32_t status)
{
    APP_LOGD("SetDisposedStatus: bundleName: %{public}s, status: %{public}d", bundleName.c_str(), status);
    // check permission
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_MANAGE_DISPOSED_APP_STATUS)) {
        APP_LOGE("SetDisposedStatus bundleName: %{public}s failed due to lack of permission", bundleName.c_str());
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->SetDisposedStatus(bundleName, status);
}

int32_t BundleMgrHostImpl::GetDisposedStatus(const std::string &bundleName)
{
    APP_LOGD("GetDisposedStatus: bundleName: %{public}s", bundleName.c_str());
    // check permission
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_MANAGE_DISPOSED_APP_STATUS)) {
        APP_LOGE("GetDisposedStatus bundleName: %{public}s failed due to lack of permission", bundleName.c_str());
        return Constants::DEFAULT_DISPOSED_STATUS;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return Constants::DEFAULT_DISPOSED_STATUS;
    }
    return dataMgr->GetDisposedStatus(bundleName);
}

bool BundleMgrHostImpl::ObtainCallingBundleName(std::string &bundleName)
{
    bool ret = GetBundleNameForUid(IPCSkeleton::GetCallingUid(), bundleName);
    if (!ret) {
        APP_LOGE("query calling bundle name failed");
        return false;
    }
    APP_LOGD("calling bundleName is : %{public}s", bundleName.c_str());
    return ret;
}

bool BundleMgrHostImpl::GetBundleStats(const std::string &bundleName, int32_t userId,
    std::vector<int64_t> &bundleStats)
{
    if (!VerifyQueryPermission(bundleName)) {
        APP_LOGE("verify permission failed");
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->GetBundleStats(bundleName, userId, bundleStats);
}

std::string BundleMgrHostImpl::GetStringById(const std::string &bundleName, const std::string &moduleName,
    uint32_t resId, int32_t userId, const std::string &localeInfo)
{
    if (!BundlePermissionMgr::IsNativeTokenType()) {
        APP_LOGE("verify token type failed");
        return Constants::EMPTY_STRING;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return Constants::EMPTY_STRING;
    }
    return dataMgr->GetStringById(bundleName, moduleName, resId, userId, localeInfo);
}

std::string BundleMgrHostImpl::GetIconById(
    const std::string &bundleName, const std::string &moduleName, uint32_t resId, uint32_t density, int32_t userId)
{
    if (!BundlePermissionMgr::IsNativeTokenType()) {
        APP_LOGE("verify token type failed");
        return Constants::EMPTY_STRING;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return Constants::EMPTY_STRING;
    }
    return dataMgr->GetIconById(bundleName, moduleName, resId, density, userId);
}

int32_t BundleMgrHostImpl::GetUdidByNetworkId(const std::string &networkId, std::string &udid)
{
#ifdef DEVICE_MANAGER_ENABLE
    if (!BundlePermissionMgr::VerifyCallingPermission(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify permission failed");
        return -1;
    }
    auto deviceManager = DelayedSingleton<BundleMgrService>::GetInstance()->GetDeviceManager();
    if (deviceManager == nullptr) {
        APP_LOGE("deviceManager is nullptr");
        return -1;
    }
    return deviceManager->GetUdidByNetworkId(networkId, udid);
#else
    APP_LOGW("deviceManager is unable");
    return -1;
#endif
}

#ifdef BUNDLE_FRAMEWORK_DEFAULT_APP
sptr<IDefaultApp> BundleMgrHostImpl::GetDefaultAppProxy()
{
    return DelayedSingleton<BundleMgrService>::GetInstance()->GetDefaultAppProxy();
}
#endif

#ifdef BUNDLE_FRAMEWORK_APP_CONTROL
sptr<IAppControlMgr> BundleMgrHostImpl::GetAppControlProxy()
{
    return DelayedSingleton<BundleMgrService>::GetInstance()->GetAppControlProxy();
}
#endif

sptr<IQuickFixManager> BundleMgrHostImpl::GetQuickFixManagerProxy()
{
#ifdef BUNDLE_FRAMEWORK_QUICK_FIX
    return DelayedSingleton<BundleMgrService>::GetInstance()->GetQuickFixManagerProxy();
#else
    return nullptr;
#endif
}

ErrCode BundleMgrHostImpl::GetSandboxAbilityInfo(const Want &want, int32_t appIndex, int32_t flags, int32_t userId,
    AbilityInfo &info)
{
    APP_LOGD("start GetSandboxAbilityInfo appIndex : %{public}d, userId : %{public}d", appIndex, userId);
    if (!VerifyQueryPermission(want.GetElement().GetBundleName())) {
        APP_LOGE("verify permission failed");
        return ERR_APPEXECFWK_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_APPEXECFWK_SANDBOX_QUERY_INTERNAL_ERROR;
    }

    if (!dataMgr->QueryAbilityInfo(want, flags, userId, info, appIndex)) {
        APP_LOGE("query ability info failed");
        return ERR_APPEXECFWK_SANDBOX_QUERY_INTERNAL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHostImpl::GetSandboxExtAbilityInfos(const Want &want, int32_t appIndex, int32_t flags,
    int32_t userId, std::vector<ExtensionAbilityInfo> &infos)
{
    APP_LOGD("start GetSandboxExtAbilityInfos appIndex : %{public}d, userId : %{public}d", appIndex, userId);
    if (!VerifyQueryPermission(want.GetElement().GetBundleName())) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_APPEXECFWK_SANDBOX_QUERY_INTERNAL_ERROR;
    }

    if (!dataMgr->QueryExtensionAbilityInfos(want, flags, userId, infos, appIndex)) {
        APP_LOGE("query extension ability info failed");
        return ERR_APPEXECFWK_SANDBOX_QUERY_INTERNAL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHostImpl::GetSandboxHapModuleInfo(const AbilityInfo &abilityInfo, int32_t appIndex, int32_t userId,
    HapModuleInfo &info)
{
    APP_LOGD("start GetSandboxHapModuleInfo appIndex : %{public}d, userId : %{public}d", appIndex, userId);
    if (!VerifyQueryPermission(abilityInfo.bundleName)) {
        APP_LOGE("verify permission failed");
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_APPEXECFWK_SANDBOX_QUERY_INTERNAL_ERROR;
    }
    auto sandboxAppHelper = dataMgr->GetSandboxAppHelper();
    if (sandboxAppHelper == nullptr) {
        APP_LOGE("sandboxAppHelper is nullptr");
        return ERR_APPEXECFWK_SANDBOX_QUERY_INTERNAL_ERROR;
    }
    int32_t requestUserId = dataMgr->GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return ERR_APPEXECFWK_SANDBOX_QUERY_INVALID_USER_ID;
    }
    return sandboxAppHelper->GetSandboxHapModuleInfo(abilityInfo, appIndex, requestUserId, info);
}

ErrCode BundleMgrHostImpl::GetMediaData(const std::string &bundleName, const std::string &moduleName,
    const std::string &abilityName, std::unique_ptr<uint8_t[]> &mediaDataPtr, size_t &len, int32_t userId)
{
    if (!VerifySystemApi(Constants::API_VERSION_NINE)) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!VerifyQueryPermission(bundleName)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->GetMediaData(bundleName, moduleName, abilityName, mediaDataPtr, len, userId);
}

void BundleMgrHostImpl::NotifyBundleStatus(const NotifyBundleEvents &installRes)
{
    std::shared_ptr<BundleCommonEventMgr> commonEventMgr = std::make_shared<BundleCommonEventMgr>();
    commonEventMgr->NotifyBundleStatus(installRes, nullptr);
}

ErrCode BundleMgrHostImpl::SetDebugMode(bool isDebug)
{
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (callingUid != Constants::ROOT_UID && callingUid != Constants::BMS_UID) {
        APP_LOGE("invalid calling uid %{public}d to set debug mode", callingUid);
        return ERR_BUNDLEMANAGER_SET_DEBUG_MODE_UID_CHECK_FAILED;
    }
    if (isDebug) {
        BundleVerifyMgr::EnableDebug();
    } else {
        BundleVerifyMgr::DisableDebug();
    }
    return ERR_OK;
}

bool BundleMgrHostImpl::VerifySystemApi(int32_t beginApiVersion)
{
    APP_LOGD("begin to verify system app");
    return BundlePermissionMgr::VerifySystemApp(beginApiVersion);
}

ErrCode BundleMgrHostImpl::GetProvisionMetadata(const std::string &bundleName, int32_t userId,
    std::vector<Metadata> &provisionMetadatas)
{
    if (!VerifyQueryPermission(bundleName)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->GetProvisionMetadata(bundleName, userId, provisionMetadatas);
}
}  // namespace AppExecFwk
}  // namespace OHOS
