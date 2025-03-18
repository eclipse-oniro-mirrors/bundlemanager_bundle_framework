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

#include "bundle_mgr_host_impl.h"

#include "account_helper.h"
#include "app_log_tag_wrapper.h"
#include "app_mgr_interface.h"
#include "aot/aot_handler.h"
#include "bms_extension_client.h"
#include "bms_extension_data_mgr.h"
#include "bundle_parser.h"
#include "bundle_permission_mgr.h"
#ifdef DISTRIBUTED_BUNDLE_FRAMEWORK
#include "distributed_bms_proxy.h"
#endif
#include "hitrace_meter.h"
#include "installd_client.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_helper.h"
#include "inner_bundle_clone_common.h"
#ifdef DEVICE_USAGE_STATISTICS_ENABLED
#include "bundle_active_client.h"
#include "bundle_active_period_stats.h"
#endif
#include "directory_ex.h"
#ifdef BMS_USER_AUTH_FRAMEWORK_ENABLED
#include "migrate_data_user_auth_callback.h"
#endif
#include "system_ability_definition.h"
#include "scope_guard.h"
#ifdef BMS_USER_AUTH_FRAMEWORK_ENABLED
#include "user_auth_client_impl.h"
#endif
#include "xcollie_helper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* SYSTEM_APP = "system";
constexpr const char* THIRD_PARTY_APP = "third-party";
constexpr const char* APP_LINKING = "applinking";
constexpr const char* EMPTY_ABILITY_NAME = "";
const std::string FUNCTION_GET_NAME_FOR_UID = "BundleMgrHostImpl::GetNameForUid";
const std::string FUNCTION_GET_OVERLAY_MANAGER_PROXY = "BundleMgrHostImpl::GetOverlayManagerProxy";
const std::string FUNCTION_GET_BUNDLE_RESOURCE_PROXY = "BundleMgrHostImpl::GetBundleResourceProxy";
const std::string FUNCTION_VERIFY_SYSTEM_API = "BundleMgrHostImpl::VerifySystemApi";
const std::string FUNCTION_VERIFY_CALLING_PERMISSION = "BundleMgrHostImpl::VerifyCallingPermission";
const std::string FUNCTION_GET_CLONE_BUNDLE_INFO = "BundleMgrHostImpl::GetCloneBundleInfo";
const std::string FUNCTION_GET_SHARED_BUNDLE_INFO_BY_SELF = "BundleMgrHostImpl::GetSharedBundleInfoBySelf";
const std::string FUNCTION_GET_HAP_MODULE_INFO = "BundleMgrHostImpl::GetHapModuleInfo";
const std::string FUNCTION_BATCH_BUNDLE_INFO = "BundleMgrHostImpl::BatchGetBundleInfo";
const std::string FUNCTION_GET_BUNDLE_INFO = "BundleMgrHostImpl::GetBundleInfo";
const std::string FUNCTION_GET_BUNDLE_INFO_V9 = "BundleMgrHostImpl::GetBundleInfoV9";
const std::string FUNCTION_GET_BUNDLE_INFO_FOR_SELF = "BundleMgrHostImpl::GetBundleInfoForSelf";
const std::string CLONE_APP_DIR_PREFIX = "+clone-";
const std::u16string ATOMIC_SERVICE_STATUS_CALLBACK_TOKEN = u"ohos.IAtomicServiceStatusCallback";
const std::string PLUS = "+";
const std::string AUTH_TITLE = "      ";
const uint64_t BAD_CONTEXT_ID = 0;
const uint64_t VECTOR_SIZE_MAX = 200;
}

bool BundleMgrHostImpl::GetApplicationInfo(
    const std::string &appName, const ApplicationFlag flag, const int userId, ApplicationInfo &appInfo)
{
    return GetApplicationInfo(appName, static_cast<int32_t>(flag), userId, appInfo);
}

bool BundleMgrHostImpl::GetApplicationInfo(
    const std::string &appName, int32_t flags, int32_t userId, ApplicationInfo &appInfo)
{
    LOG_D(BMS_TAG_QUERY, "GetApplicationInfo bundleName:%{public}s flags:%{public}d userId:%{public}d",
        appName.c_str(), flags, userId);
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(ServiceConstants::API_VERSION_NINE)) {
        LOG_D(BMS_TAG_QUERY, "non-system app calling system api");
        return true;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO}) &&
        !BundlePermissionMgr::IsBundleSelfCalling(appName)) {
        LOG_E(BMS_TAG_QUERY, "verify permission failed");
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_QUERY, "DataMgr is nullptr");
        return false;
    }
    return dataMgr->GetApplicationInfo(appName, flags, userId, appInfo);
}

ErrCode BundleMgrHostImpl::GetApplicationInfoV9(
    const std::string &appName, int32_t flags, int32_t userId, ApplicationInfo &appInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    LOG_D(BMS_TAG_QUERY, "GetApplicationInfoV9 bundleName:%{public}s flags:%{public}d userId:%{public}d",
        appName.c_str(), flags, userId);
    if (!BundlePermissionMgr::IsSystemApp()) {
        LOG_E(BMS_TAG_QUERY, "non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO}) &&
        !BundlePermissionMgr::IsBundleSelfCalling(appName)) {
        LOG_E(BMS_TAG_QUERY, "verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_QUERY, "DataMgr is nullptr");
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
    LOG_D(BMS_TAG_QUERY, "GetApplicationInfos flags:%{public}d userId:%{public}d", flags, userId);
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(ServiceConstants::API_VERSION_NINE)) {
        LOG_D(BMS_TAG_QUERY, "non-system app calling system api");
        return true;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        LOG_E(BMS_TAG_QUERY, "verify permission failed");
        return false;
    }
    if (!BundlePermissionMgr::IsNativeTokenType() &&
        (BundlePermissionMgr::GetHapApiVersion() >= ServiceConstants::API_VERSION_NINE)) {
        LOG_D(BMS_TAG_QUERY,
            "GetApplicationInfos return empty, not support target level greater than or equal to api9");
        return true;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_QUERY, "DataMgr is nullptr");
        return false;
    }
    return dataMgr->GetApplicationInfos(flags, userId, appInfos);
}

ErrCode BundleMgrHostImpl::GetApplicationInfosV9(
    int32_t flags, int32_t userId, std::vector<ApplicationInfo> &appInfos)
{
    LOG_D(BMS_TAG_QUERY, "GetApplicationInfosV9 flags:%{public}d userId:%{public}d", flags, userId);
    if (!BundlePermissionMgr::IsSystemApp()) {
        LOG_E(BMS_TAG_QUERY, "non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_INSTALLED_BUNDLE_LIST)) {
        LOG_E(BMS_TAG_QUERY, "verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_QUERY, "DataMgr is nullptr");
        BundlePermissionMgr::AddPermissionUsedRecord(Constants::PERMISSION_GET_INSTALLED_BUNDLE_LIST, 0, 1);
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    auto ret = dataMgr->GetApplicationInfosV9(flags, userId, appInfos);
    if (ret == ERR_OK) {
        BundlePermissionMgr::AddPermissionUsedRecord(Constants::PERMISSION_GET_INSTALLED_BUNDLE_LIST, 1, 0);
    } else {
        BundlePermissionMgr::AddPermissionUsedRecord(Constants::PERMISSION_GET_INSTALLED_BUNDLE_LIST, 0, 1);
    }
    return ret;
}

bool BundleMgrHostImpl::GetBundleInfo(
    const std::string &bundleName, const BundleFlag flag, BundleInfo &bundleInfo, int32_t userId)
{
    return GetBundleInfo(bundleName, static_cast<int32_t>(flag), bundleInfo, userId);
}

bool BundleMgrHostImpl::GetBundleInfo(
    const std::string &bundleName, int32_t flags, BundleInfo &bundleInfo, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    LOG_D(BMS_TAG_QUERY,
        "start GetBundleInfo, bundleName : %{public}s, flags : %{public}d, userId : %{public}d",
        bundleName.c_str(), flags, userId);
    int32_t timerId = XCollieHelper::SetRecoveryTimer(FUNCTION_GET_BUNDLE_INFO);
    ScopeGuard cancelTimerIdGuard([timerId] { XCollieHelper::CancelTimer(timerId); });
    // API9 need to be system app
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(ServiceConstants::API_VERSION_NINE)) {
        LOG_D(BMS_TAG_QUERY, "non-system app calling system api");
        return true;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO}) &&
        !BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
        LOG_E(BMS_TAG_QUERY, "verify permission failed");
        return false;
    }
    LOG_D(BMS_TAG_QUERY, "verify permission success, begin to GetBundleInfo");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_QUERY, "DataMgr is nullptr");
        return false;
    }
    bool res = dataMgr->GetBundleInfo(bundleName, flags, bundleInfo, userId);
    if (!res) {
        if (isBrokerServiceExisted_) {
            auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
            return bmsExtensionClient->GetBundleInfo(bundleName, flags, bundleInfo, userId) == ERR_OK;
        }
    }
    return res;
}

ErrCode BundleMgrHostImpl::GetBaseSharedBundleInfos(const std::string &bundleName,
    std::vector<BaseSharedBundleInfo> &baseSharedBundleInfos, GetDependentBundleInfoFlag flag)
{
    APP_LOGD("start GetBaseSharedBundleInfos, bundleName : %{public}s", bundleName.c_str());
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED) &&
        !BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->GetBaseSharedBundleInfos(bundleName, baseSharedBundleInfos, flag);
}

ErrCode BundleMgrHostImpl::GetBundleInfoV9(
    const std::string &bundleName, int32_t flags, BundleInfo &bundleInfo, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    int32_t timerId = XCollieHelper::SetRecoveryTimer(FUNCTION_GET_BUNDLE_INFO_V9);
    ScopeGuard cancelTimerIdGuard([timerId] { XCollieHelper::CancelTimer(timerId); });
    LOG_D(BMS_TAG_QUERY, "GetBundleInfoV9, bundleName:%{public}s, flags:%{public}d, userId:%{public}d",
        bundleName.c_str(), flags, userId);
    bool permissionVerify = [bundleName]() {
        if (BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
            return true;
        }
        if (BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO) &&
            BundlePermissionMgr::IsSystemApp()) {
            return true;
        }
        if (BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
            return true;
        }
        return false;
    }();
    if (!permissionVerify) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    LOG_D(BMS_TAG_QUERY, "verify permission success, begin to GetBundleInfoV9");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_QUERY, "DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    auto res = dataMgr->GetBundleInfoV9(bundleName, flags, bundleInfo, userId);
    if (res != ERR_OK) {
        if (isBrokerServiceExisted_) {
            auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
            if (bmsExtensionClient->GetBundleInfo(bundleName, flags, bundleInfo, userId, true) == ERR_OK) {
                return ERR_OK;
            }
        }
    }
    return res;
}

ErrCode BundleMgrHostImpl::BatchGetBundleInfo(const std::vector<std::string> &bundleNames, int32_t flags,
    std::vector<BundleInfo> &bundleInfos, int32_t userId)
{
    APP_LOGI("start BatchGetBundleInfo, bundleName : %{public}s, flags : %{public}d, userId : %{public}d",
        BundleUtil::ToString(bundleNames).c_str(), flags, userId);
    int32_t timerId = XCollieHelper::SetRecoveryTimer(FUNCTION_BATCH_BUNDLE_INFO);
    ScopeGuard cancelTimerIdGuard([timerId] { XCollieHelper::CancelTimer(timerId); });
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED})) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    APP_LOGD("verify permission success, begin to BatchGetBundleInfo");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    dataMgr->BatchGetBundleInfo(bundleNames, flags, bundleInfos, userId);
    if (bundleInfos.size() == bundleNames.size()) {
        return ERR_OK;
    }
    if (isBrokerServiceExisted_) {
        auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
        bmsExtensionClient->BatchGetBundleInfo(bundleNames, flags, bundleInfos, userId, true);
    }
    return bundleInfos.empty() ? ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST : ERR_OK;
}

ErrCode BundleMgrHostImpl::GetBundleInfoForSelf(int32_t flags, BundleInfo &bundleInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    int32_t timerId = XCollieHelper::SetRecoveryTimer(FUNCTION_GET_BUNDLE_INFO_FOR_SELF);
    ScopeGuard cancelTimerIdGuard([timerId] { XCollieHelper::CancelTimer(timerId); });
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_QUERY, "DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->GetBundleInfoForSelf(flags, bundleInfo);
}

ErrCode BundleMgrHostImpl::GetDependentBundleInfo(const std::string &sharedBundleName,
    BundleInfo &sharedBundleInfo, GetDependentBundleInfoFlag flag)
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }

    int32_t bundleInfoFlags = static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) |
        static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION);
    switch (flag) {
        case GetDependentBundleInfoFlag::GET_APP_CROSS_HSP_BUNDLE_INFO: {
            if (!VerifyDependency(sharedBundleName)) {
                APP_LOGE("failed");
                return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
            }
            return dataMgr->GetSharedBundleInfo(sharedBundleName, bundleInfoFlags, sharedBundleInfo);
        }
        case GetDependentBundleInfoFlag::GET_APP_SERVICE_HSP_BUNDLE_INFO: {
            // no need to check permission for app service hsp
            return dataMgr->GetAppServiceHspBundleInfo(sharedBundleName, sharedBundleInfo);
        }
        case GetDependentBundleInfoFlag::GET_ALL_DEPENDENT_BUNDLE_INFO: {
            if (dataMgr->GetAppServiceHspBundleInfo(sharedBundleName, sharedBundleInfo) == ERR_OK) {
                return ERR_OK;
            }
            if (!VerifyDependency(sharedBundleName)) {
                APP_LOGE("failed");
                return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
            }
            return dataMgr->GetSharedBundleInfo(sharedBundleName, bundleInfoFlags, sharedBundleInfo);
        }
        default:
            return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
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
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("GetBundlePackInfo failed due to lack of permission");
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
    LOG_I(BMS_TAG_QUERY, "-f: %{public}d, -u: %{public}d uid:%{public}d", flags,
        userId, IPCSkeleton::GetCallingUid());
    // API9 need to be system app
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(ServiceConstants::API_VERSION_NINE)) {
        LOG_D(BMS_TAG_QUERY, "non-system app calling system api");
        return true;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        LOG_E(BMS_TAG_QUERY, "verify permission failed");
        return false;
    }
    LOG_D(BMS_TAG_QUERY, "verify permission success, begin to GetBundleInfos");
    if (!BundlePermissionMgr::IsNativeTokenType() &&
        (BundlePermissionMgr::GetHapApiVersion() >= ServiceConstants::API_VERSION_NINE)) {
        LOG_D(BMS_TAG_QUERY,
            "GetBundleInfos return empty, not support target level greater than or equal to api9");
        return true;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_QUERY, "DataMgr is nullptr");
        return false;
    }
    dataMgr->GetBundleInfos(flags, bundleInfos, userId);
    if (isBrokerServiceExisted_) {
        auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
        bmsExtensionClient->GetBundleInfos(flags, bundleInfos, userId);
    }
    APP_LOGI_NOFUNC("GetBundleInfos size:%{public}zu", bundleInfos.size());
    return !bundleInfos.empty();
}

ErrCode BundleMgrHostImpl::GetBundleInfosV9(int32_t flags, std::vector<BundleInfo> &bundleInfos, int32_t userId)
{
    LOG_I(BMS_TAG_QUERY, "-f: %{public}d, -u: %{public}d uid:%{public}d", flags,
        userId, IPCSkeleton::GetCallingUid());
    if (!BundlePermissionMgr::IsSystemApp()) {
        LOG_E(BMS_TAG_QUERY, "non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_INSTALLED_BUNDLE_LIST)) {
        LOG_E(BMS_TAG_QUERY, "verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    LOG_D(BMS_TAG_QUERY, "verify permission success, begin to GetBundleInfosV9");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_QUERY, "DataMgr is nullptr");
        BundlePermissionMgr::AddPermissionUsedRecord(Constants::PERMISSION_GET_INSTALLED_BUNDLE_LIST, 0, 1);
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    auto res = dataMgr->GetBundleInfosV9(flags, bundleInfos, userId);
    // menu profile is currently not supported in BrokerService
    bool getMenu = ((static_cast<uint32_t>(flags) &
        static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_MENU))
        == static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_MENU));
    if (isBrokerServiceExisted_ && !getMenu) {
        auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
        if (bmsExtensionClient->GetBundleInfos(flags, bundleInfos, userId, true) == ERR_OK) {
            LOG_D(BMS_TAG_QUERY, "query bundle infos from bms extension successfully");
            BundlePermissionMgr::AddPermissionUsedRecord(Constants::PERMISSION_GET_INSTALLED_BUNDLE_LIST, 1, 0);
            APP_LOGI_NOFUNC("GetBundleInfosV9 size:%{public}zu", bundleInfos.size());
            return ERR_OK;
        }
    }
    if (res == ERR_OK) {
        BundlePermissionMgr::AddPermissionUsedRecord(Constants::PERMISSION_GET_INSTALLED_BUNDLE_LIST, 1, 0);
    } else {
        BundlePermissionMgr::AddPermissionUsedRecord(Constants::PERMISSION_GET_INSTALLED_BUNDLE_LIST, 0, 1);
    }
    APP_LOGI_NOFUNC("GetBundleInfosV9 size:%{public}zu", bundleInfos.size());
    return res;
}

bool BundleMgrHostImpl::GetBundleNameForUid(const int uid, std::string &bundleName)
{
    APP_LOGD("start GetBundleNameForUid, uid : %{public}d", uid);
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(ServiceConstants::API_VERSION_NINE)) {
        APP_LOGE("non-system app calling system api");
        return false;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO})) {
        APP_LOGE("verify query permission failed");
        return false;
    }
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
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return false;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO})) {
        APP_LOGE("verify permission failed");
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
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("start GetNameForUid, uid : %{public}d", uid);
    int32_t timerId = XCollieHelper::SetRecoveryTimer(FUNCTION_GET_NAME_FOR_UID);
    ScopeGuard cancelTimerIdGuard([timerId] { XCollieHelper::CancelTimer(timerId); });
    bool permissionVerify = []() {
        if (BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
            return true;
        }
        if (BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO) &&
            (BundlePermissionMgr::IsSystemApp() ||
            BundlePermissionMgr::VerifyCallingBundleSdkVersion(ServiceConstants::API_VERSION_NINE))) {
            return true;
        }
        return false;
    }();
    if (!permissionVerify) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    auto ret = dataMgr->GetNameForUid(uid, name);
    if (ret != ERR_OK && isBrokerServiceExisted_) {
        auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
        ret = bmsExtensionClient->GetBundleNameByUid(uid, name);
        if (ret != ERR_OK) {
            return ERR_BUNDLE_MANAGER_INVALID_UID;
        }
    }
    return ret;
}

ErrCode BundleMgrHostImpl::GetNameAndIndexForUid(const int uid, std::string &bundleName, int32_t &appIndex)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("start GetNameAndIndexForUid, uid : %{public}d", uid);
    bool permissionVerify = []() {
        if (BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
            return true;
        }
        if (BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO) &&
            BundlePermissionMgr::IsSystemApp()) {
            return true;
        }
        return false;
    }();
    if (!permissionVerify) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->GetBundleNameAndIndexForUid(uid, bundleName, appIndex);
}

ErrCode BundleMgrHostImpl::GetSimpleAppInfoForUid(
    const std::vector<std::int32_t> &uids, std::vector<SimpleAppInfo> &simpleAppInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("start GetSimpleAppInfoForUid");
    bool permissionVerify = []() {
        if (BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
            return true;
        }
        if (BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO) &&
            BundlePermissionMgr::IsSystemApp()) {
            return true;
        }
        return false;
    }();
    if (!permissionVerify) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }

    SimpleAppInfo info;
    for (size_t i = 0; i < uids.size(); i++) {
        auto ret = dataMgr->GetBundleNameAndIndexForUid(uids[i], info.bundleName, info.appIndex);
        if (ret != ERR_OK) {
            APP_LOGW("get name and index for uid failed, uid : %{public}d ret : %{public}d", uids[i], ret);
            info.bundleName = "";
            info.appIndex = -1;
        }
        info.uid = uids[i];
        info.ret = ret;
        simpleAppInfo.emplace_back(info);
    }
    return ERR_OK;
}

bool BundleMgrHostImpl::GetBundleGids(const std::string &bundleName, std::vector<int> &gids)
{
    APP_LOGD("start GetBundleGids, bundleName : %{public}s", bundleName.c_str());
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED) &&
        !BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
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
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED) &&
        !BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
        APP_LOGE("verify token type failed");
        return false;
    }
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
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return false;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify permission failed");
        return false;
    }
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
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
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

bool BundleMgrHostImpl::QueryAbilityInfo(const Want &want, int32_t flags, int32_t userId,
    AbilityInfo &abilityInfo, const sptr<IRemoteObject> &callBack)
{
    if (!BundlePermissionMgr::IsSystemApp()) {
        LOG_E(BMS_TAG_QUERY, "check is system app failed");
        return false;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO})) {
        LOG_E(BMS_TAG_QUERY, "verify permission failed");
        return false;
    }
#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
    auto connectAbilityMgr = GetConnectAbilityMgrFromService();
    if (connectAbilityMgr == nullptr) {
        LOG_E(BMS_TAG_QUERY, "connectAbilityMgr is nullptr");
        return false;
    }
    return connectAbilityMgr->QueryAbilityInfo(want, flags, userId, abilityInfo, callBack);
#else
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_QUERY, "DataMgr is nullptr");
        return false;
    }
    if (dataMgr->IsObtainAbilityInfo(want, userId, abilityInfo)) {
        CallAbilityManager(ERR_OK, want, userId, callBack);
        return true;
    }
    CallAbilityManager(ERR_APPEXECFWK_FREE_INSTALL_NOT_SUPPORT, want, userId, callBack);
    return false;
#endif
}

#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
bool BundleMgrHostImpl::SilentInstall(const Want &want, int32_t userId, const sptr<IRemoteObject> &callBack)
{
    APP_LOGD("SilentInstall in");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is null");
        return false;
    }
    std::string callingBundleName;
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    ErrCode ret = dataMgr->GetNameForUid(callingUid, callingBundleName);
    if (ret != ERR_OK) {
        APP_LOGE("get bundleName failed %{public}d %{public}d", ret, callingUid);
        return false;
    }
    ElementName element = want.GetElement();
    std::string packageName = element.GetBundleName();
    if (packageName != callingBundleName) {
        APP_LOGE("callingBundleName vaild fail %{public}s %{public}s",
            packageName.c_str(), callingBundleName.c_str());
        return false;
    }
    auto connectMgr = GetConnectAbilityMgrFromService();
    if (connectMgr == nullptr) {
        APP_LOGE("connectMgr is nullptr");
        return false;
    }
    return connectMgr->SilentInstall(want, userId, callBack);
}

void BundleMgrHostImpl::UpgradeAtomicService(const Want &want, int32_t userId)
{
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("check is system app failed");
        return;
    }

    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify permission failed");
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
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("check is system app failed");
        return false;
    }

    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify permission failed");
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
        APP_LOGE("ProcessPreload verify failed");
        return false;
    }
    APP_LOGD("begin to process preload");
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
    LOG_D(BMS_TAG_QUERY, "start QueryAbilityInfo, flags : %{public}d, userId : %{public}d", flags, userId);
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(ServiceConstants::API_VERSION_NINE)) {
        LOG_D(BMS_TAG_QUERY, "non-system app calling system api");
        return true;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO}) &&
        !BundlePermissionMgr::IsBundleSelfCalling(want.GetElement().GetBundleName())) {
        LOG_E(BMS_TAG_QUERY, "verify permission failed");
        return false;
    }
    APP_LOGD("verify permission success, begin to QueryAbilityInfo");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_QUERY, "DataMgr is nullptr");
        return false;
    }
    bool res = dataMgr->QueryAbilityInfo(want, flags, userId, abilityInfo);
    if (!res) {
        if (!IsAppLinking(flags) && isBrokerServiceExisted_) {
            auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
            return (bmsExtensionClient->QueryAbilityInfo(want, flags, userId, abilityInfo) == ERR_OK);
        }
    }
    return res;
}

bool BundleMgrHostImpl::QueryAbilityInfos(const Want &want, std::vector<AbilityInfo> &abilityInfos)
{
    return QueryAbilityInfos(
        want, GET_ABILITY_INFO_WITH_APPLICATION, Constants::UNSPECIFIED_USERID, abilityInfos);
}

bool BundleMgrHostImpl::QueryAbilityInfos(
    const Want &want, int32_t flags, int32_t userId, std::vector<AbilityInfo> &abilityInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    LOG_D(BMS_TAG_QUERY, "start QueryAbilityInfos, flags : %{public}d, userId : %{public}d", flags, userId);
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(ServiceConstants::API_VERSION_NINE)) {
        LOG_D(BMS_TAG_QUERY, "non-system app calling system api");
        return true;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO}) &&
        !BundlePermissionMgr::IsBundleSelfCalling(want.GetElement().GetBundleName())) {
        LOG_E(BMS_TAG_QUERY, "verify permission failed");
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_QUERY, "DataMgr is nullptr");
        return false;
    }
    dataMgr->QueryAbilityInfos(want, flags, userId, abilityInfos);
    if (!IsAppLinking(flags) && isBrokerServiceExisted_) {
        auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
        bmsExtensionClient->QueryAbilityInfos(want, flags, userId, abilityInfos);
    }
    return !abilityInfos.empty();
}

ErrCode BundleMgrHostImpl::QueryAbilityInfosV9(
    const Want &want, int32_t flags, int32_t userId, std::vector<AbilityInfo> &abilityInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    LOG_D(BMS_TAG_QUERY, "start QueryAbilityInfosV9, flags : %{public}d, userId : %{public}d", flags, userId);
    if (!BundlePermissionMgr::IsSystemApp()) {
        LOG_E(BMS_TAG_QUERY, "non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO}) &&
        !BundlePermissionMgr::IsBundleSelfCalling(want.GetElement().GetBundleName())) {
        LOG_E(BMS_TAG_QUERY, "verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_QUERY, "DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    auto res = dataMgr->QueryAbilityInfosV9(want, flags, userId, abilityInfos);
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    if (!IsAppLinking(flags) && isBrokerServiceExisted_ &&
        bmsExtensionClient->QueryAbilityInfos(want, flags, userId, abilityInfos, true) == ERR_OK) {
        LOG_D(BMS_TAG_QUERY, "query ability infos from bms extension successfully");
        return ERR_OK;
    }
    return res;
}

ErrCode BundleMgrHostImpl::BatchQueryAbilityInfos(
    const std::vector<Want> &wants, int32_t flags, int32_t userId, std::vector<AbilityInfo> &abilityInfos)
{
    APP_LOGD("start BatchQueryAbilityInfos, flags : %{public}d, userId : %{public}d", flags, userId);
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    bool callingPermission = BundlePermissionMgr::VerifyCallingPermissionsForAll(
        { Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED, Constants::PERMISSION_GET_BUNDLE_INFO });
    for (size_t i = 0; i < wants.size(); i++) {
        if (!callingPermission && !BundlePermissionMgr::IsBundleSelfCalling(wants[i].GetElement().GetBundleName())) {
            APP_LOGE("verify is bundle self calling failed");
            return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
        }
    }
    APP_LOGD("verify permission success, begin to BatchQueryAbilityInfos");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    auto res = dataMgr->BatchQueryAbilityInfos(wants, flags, userId, abilityInfos);
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    if (!IsAppLinking(flags) && isBrokerServiceExisted_ &&
        bmsExtensionClient->BatchQueryAbilityInfos(wants, flags, userId, abilityInfos, true) == ERR_OK) {
        APP_LOGD("query ability infos from bms extension successfully");
        return ERR_OK;
    }
    return res;
}

ErrCode BundleMgrHostImpl::QueryLauncherAbilityInfos(
    const Want &want, int32_t userId, std::vector<AbilityInfo> &abilityInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    LOG_D(BMS_TAG_QUERY, "start QueryLauncherAbilityInfos, userId : %{public}d", userId);
    if (!BundlePermissionMgr::IsSystemApp()) {
        LOG_E(BMS_TAG_QUERY, "non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        LOG_E(BMS_TAG_QUERY, "verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    APP_LOGD("verify permission success, begin to QueryLauncherAbilityInfos");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_QUERY, "DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }

    auto ret = dataMgr->QueryLauncherAbilityInfos(want, userId, abilityInfos);
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    if (bmsExtensionClient->QueryLauncherAbility(want, userId, abilityInfos) == ERR_OK) {
        LOG_D(BMS_TAG_QUERY, "query launcher ability infos from bms extension successfully");
        return ERR_OK;
    }
    return ret;
}

ErrCode BundleMgrHostImpl::GetLauncherAbilityInfoSync(
    const std::string &bundleName, int32_t userId, std::vector<AbilityInfo> &abilityInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    LOG_D(BMS_TAG_QUERY, "start GetLauncherAbilityInfoSync, userId : %{public}d", userId);

    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        LOG_E(BMS_TAG_QUERY, "verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    APP_LOGD("verify permission success, begin to GetLauncherAbilityInfoSync");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_QUERY, "DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    if (bundleName.empty()) {
        LOG_E(BMS_TAG_QUERY, "no bundleName %{public}s found", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    Want want;
    want.SetAction(Want::ACTION_HOME);
    want.AddEntity(Want::ENTITY_HOME);
    ElementName elementName;
    elementName.SetBundleName(bundleName);
    want.SetElement(elementName);

    auto ret = dataMgr->GetLauncherAbilityInfoSync(want, userId, abilityInfos);
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    if (bmsExtensionClient->QueryLauncherAbility(want, userId, abilityInfos) == ERR_OK) {
        LOG_D(BMS_TAG_QUERY, "query launcher ability infos from bms extension successfully");
        return ERR_OK;
    }
    return ret;
}

bool BundleMgrHostImpl::QueryAllAbilityInfos(const Want &want, int32_t userId, std::vector<AbilityInfo> &abilityInfos)
{
    LOG_D(BMS_TAG_QUERY, "start QueryAllAbilityInfos, userId : %{public}d", userId);
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(ServiceConstants::API_VERSION_NINE)) {
        LOG_D(BMS_TAG_QUERY, "non-system app calling system api");
        return true;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        LOG_E(BMS_TAG_QUERY, "verify permission failed");
        return false;
    }
    APP_LOGD("verify permission success, begin to QueryAllAbilityInfos");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_QUERY, "DataMgr is nullptr");
        return false;
    }
    bool res = dataMgr->QueryLauncherAbilityInfos(want, userId, abilityInfos) == ERR_OK;
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    if (bmsExtensionClient->QueryLauncherAbility(want, userId, abilityInfos) == ERR_OK) {
        LOG_D(BMS_TAG_QUERY, "query launcher ability infos from bms extension successfully");
        return true;
    }
    return res;
}

bool BundleMgrHostImpl::QueryAbilityInfoByUri(const std::string &abilityUri, AbilityInfo &abilityInfo)
{
    LOG_D(BMS_TAG_QUERY, "start QueryAbilityInfoByUri, uri : %{private}s", abilityUri.c_str());
    // API9 need to be system app, otherwise return empty data
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(ServiceConstants::API_VERSION_NINE)) {
        LOG_D(BMS_TAG_QUERY, "non-system app calling system api");
        return true;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO})) {
        LOG_E(BMS_TAG_QUERY, "verify query permission failed");
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_QUERY, "DataMgr is nullptr");
        return false;
    }
    return dataMgr->QueryAbilityInfoByUri(abilityUri, Constants::UNSPECIFIED_USERID, abilityInfo);
}

bool BundleMgrHostImpl::QueryAbilityInfosByUri(const std::string &abilityUri, std::vector<AbilityInfo> &abilityInfos)
{
    LOG_D(BMS_TAG_QUERY, "start QueryAbilityInfosByUri, uri : %{private}s", abilityUri.c_str());
    // API9 need to be system app, otherwise return empty data
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(ServiceConstants::API_VERSION_NINE)) {
        return true;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        LOG_E(BMS_TAG_QUERY, "verify permission failed");
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_QUERY, "DataMgr is nullptr");
        return false;
    }
    return dataMgr->QueryAbilityInfosByUri(abilityUri, abilityInfos);
}

bool BundleMgrHostImpl::QueryAbilityInfoByUri(
    const std::string &abilityUri, int32_t userId, AbilityInfo &abilityInfo)
{
    LOG_D(BMS_TAG_QUERY, "start QueryAbilityInfoByUri, uri : %{private}s, userId : %{public}d",
        abilityUri.c_str(), userId);
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(ServiceConstants::API_VERSION_NINE)) {
        LOG_D(BMS_TAG_QUERY, "non-system app calling system api");
        return true;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO,
        Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED})) {
        LOG_E(BMS_TAG_QUERY, "verify query permission failed");
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_QUERY, "DataMgr is nullptr");
        return false;
    }
    return dataMgr->QueryAbilityInfoByUri(abilityUri, userId, abilityInfo);
}

bool BundleMgrHostImpl::QueryKeepAliveBundleInfos(std::vector<BundleInfo> &bundleInfos)
{
    auto dataMgr = GetDataMgrFromService();
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
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
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("start GetAbilityLabel, bundleName : %{public}s, abilityName : %{public}s",
        bundleName.c_str(), abilityName.c_str());
    // API9 need to be system app otherwise return empty data
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(ServiceConstants::API_VERSION_NINE)) {
        APP_LOGD("non-system app calling system api");
        return Constants::EMPTY_STRING;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO}) &&
        !BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
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
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO}) &&
        !BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
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
    APP_LOGD("start GetBundleArchiveInfo, hapFilePath : %{private}s, flags : %{public}d",
        hapFilePath.c_str(), flags);
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(ServiceConstants::API_VERSION_NINE)) {
        APP_LOGD("non-system app calling system api");
        return true;
    }
    if (hapFilePath.find(ServiceConstants::RELATIVE_PATH) != std::string::npos) {
        APP_LOGE("invalid hapFilePath");
        return false;
    }
    if (hapFilePath.find(ServiceConstants::SANDBOX_DATA_PATH) == std::string::npos &&
        hapFilePath.find(ServiceConstants::APP_INSTALL_SANDBOX_PATH) == std::string::npos) {
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
        SetProvisionInfoToInnerBundleInfo(realPath, info);
        info.GetBundleInfo(flags, bundleInfo, ServiceConstants::NOT_EXIST_USERID);
        return true;
    } else {
        return GetBundleArchiveInfoBySandBoxPath(hapFilePath, flags, bundleInfo) == ERR_OK;
    }
}

ErrCode BundleMgrHostImpl::GetBundleArchiveInfoV9(
    const std::string &hapFilePath, int32_t flags, BundleInfo &bundleInfo)
{
    APP_LOGD("start GetBundleArchiveInfoV9, hapFilePath : %{private}s, flags : %{public}d",
        hapFilePath.c_str(), flags);
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    if (hapFilePath.find(ServiceConstants::RELATIVE_PATH) != std::string::npos) {
        APP_LOGD("invalid hapFilePath");
        return ERR_BUNDLE_MANAGER_INVALID_HAP_PATH;
    }
    if (hapFilePath.find(ServiceConstants::SANDBOX_DATA_PATH) == 0 ||
        hapFilePath.find(ServiceConstants::APP_INSTALL_SANDBOX_PATH) == 0) {
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
    if ((static_cast<uint32_t>(flags) & static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO))
        == static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO)) {
        SetProvisionInfoToInnerBundleInfo(realPath, info);
    }
    info.GetBundleInfoV9(flags, bundleInfo, ServiceConstants::NOT_EXIST_USERID);
    return ERR_OK;
}

ErrCode BundleMgrHostImpl::GetBundleArchiveInfoBySandBoxPath(const std::string &hapFilePath,
    int32_t flags, BundleInfo &bundleInfo, bool fromV9)
{
    std::string bundleName;
    int32_t apiVersion = fromV9 ? Constants::INVALID_API_VERSION : ServiceConstants::API_VERSION_NINE;
    if (!BundlePermissionMgr::IsSystemApp() && !BundlePermissionMgr::VerifyCallingBundleSdkVersion(apiVersion)) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!ObtainCallingBundleName(bundleName)) {
        APP_LOGE("get calling bundleName failed");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    if (hapFilePath.find(ServiceConstants::APP_INSTALL_SANDBOX_PATH) == 0 &&
        !BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_ACCESS_APP_INSTALL_DIR)) {
        APP_LOGE("verify ACCESS_APP_INSTALL_DIR failed");
        return ERR_BUNDLE_MANAGER_INVALID_HAP_PATH;
    }
    std::string hapRealPath;
    if (!BundleUtil::RevertToRealPath(hapFilePath, bundleName, hapRealPath)) {
        APP_LOGE("GetBundleArchiveInfo RevertToRealPath failed");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    std::string tempHapPath = std::string(ServiceConstants::BUNDLE_MANAGER_SERVICE_PATH) +
        ServiceConstants::PATH_SEPARATOR + std::to_string(BundleUtil::GetCurrentTimeNs());
    if (!BundleUtil::CreateDir(tempHapPath)) {
        APP_LOGE("GetBundleArchiveInfo make temp dir failed");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    std::string hapName = hapFilePath.substr(hapFilePath.find_last_of("//") + 1);
    std::string tempHapFile = tempHapPath + ServiceConstants::PATH_SEPARATOR + hapName;
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
    SetProvisionInfoToInnerBundleInfo(realPath, info);
    BundleUtil::DeleteDir(tempHapPath);
    if (fromV9) {
        info.GetBundleInfoV9(flags, bundleInfo, ServiceConstants::NOT_EXIST_USERID);
    } else {
        info.GetBundleInfo(flags, bundleInfo, ServiceConstants::NOT_EXIST_USERID);
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
    APP_LOGD("start GetHapModuleInfo with bundleName %{public}s and userId: %{public}d",
        abilityInfo.bundleName.c_str(), userId);
    int32_t timerId = XCollieHelper::SetRecoveryTimer(FUNCTION_GET_HAP_MODULE_INFO);
    ScopeGuard cancelTimerIdGuard([timerId] { XCollieHelper::CancelTimer(timerId); });
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED) &&
        !BundlePermissionMgr::IsBundleSelfCalling(abilityInfo.bundleName)) {
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
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("start GetLaunchWantForBundle, bundleName : %{public}s", bundleName.c_str());
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(ServiceConstants::API_VERSION_NINE)) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
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

ErrCode BundleMgrHostImpl::GetPermissionDef(const std::string &permissionName, PermissionDef &permissionDef)
{
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify GET_BUNDLE_INFO_PRIVILEGED failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    if (permissionName.empty()) {
        APP_LOGW("fail to GetPermissionDef due to params empty");
        return ERR_BUNDLE_MANAGER_QUERY_PERMISSION_DEFINE_FAILED;
    }
    return BundlePermissionMgr::GetPermissionDef(permissionName, permissionDef);
}

ErrCode BundleMgrHostImpl::CleanBundleCacheFilesAutomatic(uint64_t cacheSize)
{
    if (cacheSize == 0) {
        APP_LOGE("parameter error, cache size must be greater than 0");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }

    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_REMOVECACHEFILE)) {
        APP_LOGE("ohos.permission.REMOVE_CACHE_FILES permission denied");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }

    // Get current active userId
    int32_t currentUserId = AccountHelper::GetCurrentActiveUserId();
    APP_LOGI("current active userId is %{public}d", currentUserId);
    if (currentUserId == Constants::INVALID_USERID) {
        APP_LOGE("currentUserId %{public}d is invalid", currentUserId);
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }

    // Get apps use time under the current active user
    int64_t startTime = 0;
    int64_t endTime = BundleUtil::GetCurrentTimeMs();
    const int32_t PERIOD_ANNUALLY = 4; // 4 is the number of the period ANN
    uint32_t notRunningSum = 0; // The total amount of application that is not running
#ifdef DEVICE_USAGE_STATISTICS_ENABLED
    std::vector<DeviceUsageStats::BundleActivePackageStats> useStats;
    DeviceUsageStats::BundleActiveClient::GetInstance().QueryBundleStatsInfoByInterval(
        useStats, PERIOD_ANNUALLY, startTime, endTime, currentUserId);

    if (useStats.empty()) {
        APP_LOGE("useStats under the current active user is empty");
        return ERR_BUNDLE_MANAGER_DEVICE_USAGE_STATS_EMPTY;
    }

    // Sort apps use time from small to large under the current active user
    std::sort(useStats.begin(), useStats.end(),
        [](DeviceUsageStats::BundleActivePackageStats a,
        DeviceUsageStats::BundleActivePackageStats b) {
            return a.totalInFrontTime_ < b.totalInFrontTime_;
        });

    // Get all running apps
    sptr<IAppMgr> appMgrProxy =
        iface_cast<IAppMgr>(SystemAbilityHelper::GetSystemAbility(APP_MGR_SERVICE_ID));
    if (appMgrProxy == nullptr) {
        APP_LOGE("fail to find the app mgr service to check app is running");
        return ERR_BUNDLE_MANAGER_GET_SYSTEM_ABILITY_FAILED;
    }

    std::vector<RunningProcessInfo> runningList;
    int result = appMgrProxy->GetAllRunningProcesses(runningList);
    if (result != ERR_OK) {
        APP_LOGE("GetAllRunningProcesses failed");
        return ERR_BUNDLE_MANAGER_GET_ALL_RUNNING_PROCESSES_FAILED;
    }

    std::unordered_set<std::string> runningSet;
    for (const auto &info : runningList) {
        runningSet.insert(info.bundleNames.begin(), info.bundleNames.end());
    }

    uint64_t cleanCacheSum = 0; // The total amount of application cache currently cleaned
    for (auto useStat : useStats) {
        if (runningSet.find(useStat.bundleName_) == runningSet.end()) {
            notRunningSum++;
            uint64_t cleanCacheSize = 0; // The cache size of a single application cleaned up
            ErrCode ret = CleanBundleCacheFilesGetCleanSize(useStat.bundleName_, currentUserId, cleanCacheSize);
            if (ret != ERR_OK) {
                APP_LOGE("CleanBundleCacheFilesGetCleanSize failed,"
                    "bundleName: %{public}s, currentUserId: %{public}d, ret: %{public}d",
                    useStat.bundleName_.c_str(), currentUserId, ret);
                continue;
            }
            APP_LOGI("bundleName : %{public}s, cleanCacheSize: %{public}" PRIu64 "",
                useStat.bundleName_.c_str(), cleanCacheSize);
            if (cleanCacheSum <= std::numeric_limits<uint64_t>::max() - cleanCacheSize) {
                cleanCacheSum += cleanCacheSize;
            } else {
                APP_LOGE("add overflow cleanCacheSum: %{public}" PRIu64 ", cleanCacheSize: %{public}" PRIu64 "",
                    cleanCacheSum, cleanCacheSize);
            }
            if (cleanCacheSum >= cacheSize) {
                return ERR_OK;
            }
        }
    }
#endif
    if (notRunningSum == 0) {
        APP_LOGE("All apps are running under the current active user");
        return ERR_BUNDLE_MANAGER_ALL_BUNDLES_ARE_RUNNING;
    }

    return ERR_OK;
}

ErrCode BundleMgrHostImpl::CleanBundleCacheFilesGetCleanSize(const std::string &bundleName,
    int32_t userId, uint64_t &cleanCacheSize)
{
    APP_LOGI("start CleanBundleCacheFilesGetCleanSize, bundleName : %{public}s, userId : %{public}d",
        bundleName.c_str(), userId);

    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }

    if (userId < 0) {
        APP_LOGE("userId is invalid");
        EventReport::SendCleanCacheSysEvent(bundleName, userId, true, true);
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }

    if (bundleName.empty()) {
        APP_LOGE("the bundleName empty");
        EventReport::SendCleanCacheSysEvent(bundleName, userId, true, true);
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }

    ApplicationInfo applicationInfo;
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        EventReport::SendCleanCacheSysEvent(bundleName, userId, true, true);
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }

    auto ret = dataMgr->GetApplicationInfoWithResponseId(bundleName,
        static_cast<int32_t>(GetApplicationFlag::GET_APPLICATION_INFO_WITH_DISABLE), userId, applicationInfo);
    if (ret != ERR_OK) {
        APP_LOGE("can not get application info of %{public}s", bundleName.c_str());
        EventReport::SendCleanCacheSysEvent(bundleName, userId, true, true);
        return ret;
    }

    if (!applicationInfo.userDataClearable) {
        APP_LOGE("can not clean cacheFiles of %{public}s due to userDataClearable is false", bundleName.c_str());
        EventReport::SendCleanCacheSysEvent(bundleName, userId, true, true);
        return ERR_BUNDLE_MANAGER_CAN_NOT_CLEAR_USER_DATA;
    }

    CleanBundleCacheTaskGetCleanSize(bundleName, userId, cleanCacheSize);
    return ERR_OK;
}

void BundleMgrHostImpl::CleanBundleCacheTaskGetCleanSize(const std::string &bundleName,
    int32_t userId, uint64_t &cleanCacheSize)
{
    InnerBundleInfo info;
    auto dataMgr = GetDataMgrFromService();
    if (!dataMgr->FetchInnerBundleInfo(bundleName, info)) {
        APP_LOGE("can not get bundleinfo of %{public}s", bundleName.c_str());
        EventReport::SendCleanCacheSysEvent(bundleName, userId, true, true);
        return;
    }
    std::vector<std::tuple<std::string, std::vector<std::string>, std::vector<int32_t>>> validBundles;
    dataMgr->GetBundleCacheInfo([](std::string &bundleName, std::vector<int32_t> &allidx) {
            return allidx;
        }, info, validBundles, userId, false);
    uint64_t cleanSize;
    BundleCacheMgr().GetBundleCacheSize(validBundles, userId, cleanSize);
    auto ret = BundleCacheMgr().CleanBundleCache(validBundles, userId);
    if (ret != ERR_OK) {
        APP_LOGE("can not get CleanBundleCache of %{public}s", bundleName.c_str());
        EventReport::SendCleanCacheSysEvent(bundleName, userId, true, true);
        return;
    }
    cleanCacheSize = cleanSize;
    bool succeed = true;

    EventReport::SendCleanCacheSysEvent(bundleName, userId, true, !succeed);
    APP_LOGI("CleanBundleCacheFiles with succeed %{public}d", succeed);
    InnerBundleUserInfo innerBundleUserInfo;
    if (!this->GetBundleUserInfo(bundleName, userId, innerBundleUserInfo)) {
        APP_LOGE("Get calling userInfo in bundle(%{public}s) failed", bundleName.c_str());
        return;
    }
    NotifyBundleEvents installRes = {
        .type = NotifyType::BUNDLE_CACHE_CLEARED,
        .resultCode = ERR_OK,
        .accessTokenId = innerBundleUserInfo.accessTokenId,
        .uid = innerBundleUserInfo.uid,
        .bundleName = bundleName
    };
    NotifyBundleStatus(installRes);
}

bool BundleMgrHostImpl::CheckAppIndex(const std::string &bundleName, int32_t userId, int32_t appIndex)
{
    if (appIndex == 0) {
        return true;
    }
    if (appIndex < 0) {
        APP_LOGE("appIndex is invalid");
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    std::vector<int32_t> appIndexes = dataMgr->GetCloneAppIndexes(bundleName, userId);
    bool isAppIndexValid = std::find(appIndexes.cbegin(), appIndexes.cend(), appIndex) == appIndexes.cend();
    if (isAppIndexValid) {
        APP_LOGE("appIndex is not in the installed appIndexes range");
        return false;
    }
    return true;
}

ErrCode BundleMgrHostImpl::CleanBundleCacheFiles(
    const std::string &bundleName, const sptr<ICleanCacheCallback> cleanCacheCallback,
    int32_t userId, int32_t appIndex)
{
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = BundleUtil::GetUserIdByCallingUid();
    }
    APP_LOGI("start -n %{public}s -u %{public}d -i %{public}d", bundleName.c_str(), userId, appIndex);
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_REMOVECACHEFILE) &&
        !BundlePermissionMgr::IsBundleSelfCalling(bundleName, appIndex)) {
        APP_LOGE("ohos.permission.REMOVE_CACHE_FILES permission denied");
        EventReport::SendCleanCacheSysEventWithIndex(bundleName, userId, appIndex, true, true);
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    if (userId < 0) {
        APP_LOGE("userId is invalid");
        EventReport::SendCleanCacheSysEventWithIndex(bundleName, userId, appIndex, true, true);
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }
    if (bundleName.empty() || !cleanCacheCallback) {
        APP_LOGE("the cleanCacheCallback is nullptr or bundleName empty");
        EventReport::SendCleanCacheSysEventWithIndex(bundleName, userId, appIndex, true, true);
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }

    if (isBrokerServiceExisted_ && !IsBundleExist(bundleName)) {
        return ClearCache(bundleName, cleanCacheCallback, userId);
    }

    ApplicationInfo applicationInfo;
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        EventReport::SendCleanCacheSysEventWithIndex(bundleName, userId, appIndex, true, true);
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }

    auto ret = dataMgr->GetApplicationInfoWithResponseId(bundleName,
        static_cast<int32_t>(GetApplicationFlag::GET_APPLICATION_INFO_WITH_DISABLE), userId, applicationInfo);
    if (ret != ERR_OK) {
        APP_LOGE("can not get application info of %{public}s", bundleName.c_str());
        EventReport::SendCleanCacheSysEventWithIndex(bundleName, userId, appIndex, true, true);
        return ret;
    }

    if (!CheckAppIndex(bundleName, userId, appIndex)) {
        EventReport::SendCleanCacheSysEventWithIndex(bundleName, userId, appIndex, true, true);
        return ERR_APPEXECFWK_APP_INDEX_OUT_OF_RANGE;
    }

    if (!applicationInfo.userDataClearable) {
        APP_LOGE("can not clean cacheFiles of %{public}s due to userDataClearable is false", bundleName.c_str());
        EventReport::SendCleanCacheSysEventWithIndex(bundleName, userId, appIndex, true, true);
        return ERR_BUNDLE_MANAGER_CAN_NOT_CLEAR_USER_DATA;
    }

    CleanBundleCacheTask(bundleName, cleanCacheCallback, dataMgr, userId, appIndex);
    return ERR_OK;
}

void BundleMgrHostImpl::CleanBundleCacheTask(const std::string &bundleName,
    const sptr<ICleanCacheCallback> cleanCacheCallback,
    const std::shared_ptr<BundleDataMgr> &dataMgr,
    int32_t userId, int32_t appIndex)
{
    std::vector<std::string> rootDir;
    std::vector<std::string> moduleNameList;
    dataMgr->GetBundleModuleNames(bundleName, moduleNameList);
    rootDir = BundleCacheMgr().GetBundleCachePath(bundleName, userId, appIndex, moduleNameList);

    auto cleanCache = [bundleName, userId, rootDir, dataMgr, cleanCacheCallback, appIndex, this]() {
        std::vector<std::string> caches = rootDir;
        std::string shaderCachePath;
        shaderCachePath.append(ServiceConstants::SHADER_CACHE_PATH).append(bundleName);
        caches.push_back(shaderCachePath);
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
        NotifyBundleEvents installRes;
        if (appIndex > 0) {
            std::map<std::string, InnerBundleCloneInfo> cloneInfos = innerBundleUserInfo.cloneInfos;
            auto cloneInfoIter = cloneInfos.find(std::to_string(appIndex));
            if (cloneInfoIter == cloneInfos.end()) {
                APP_LOGW("Get calling userCloneInfo in bundle(%{public}s) failed, appIndex:%{public}d",
                    bundleName.c_str(), appIndex);
                return;
            }
            int32_t uid = cloneInfoIter->second.uid;
            installRes = {
                .type = NotifyType::BUNDLE_CACHE_CLEARED,
                .resultCode = ERR_OK,
                .accessTokenId = innerBundleUserInfo.accessTokenId,
                .uid = uid,
                .appIndex = appIndex,
                .bundleName = bundleName
            };
            NotifyBundleStatus(installRes);
            return;
        }
        installRes = {
            .type = NotifyType::BUNDLE_CACHE_CLEARED,
            .resultCode = ERR_OK,
            .accessTokenId = innerBundleUserInfo.accessTokenId,
            .uid = innerBundleUserInfo.uid,
            .bundleName = bundleName
        };
        NotifyBundleStatus(installRes);
    };
    ffrt::submit(cleanCache);
}

bool BundleMgrHostImpl::CleanBundleDataFiles(const std::string &bundleName, const int userId, const int appIndex)
{
    APP_LOGI("start CleanBundleDataFiles, bundleName : %{public}s, userId:%{public}d, appIndex:%{public}d",
        bundleName.c_str(), userId, appIndex);
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("ohos.permission.REMOVE_CACHE_FILES system api denied");
        EventReport::SendCleanCacheSysEventWithIndex(bundleName, userId, appIndex, false, true);
        return false;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_REMOVECACHEFILE)) {
        APP_LOGE("ohos.permission.REMOVE_CACHE_FILES permission denied");
        EventReport::SendCleanCacheSysEventWithIndex(bundleName, userId, appIndex, false, true);
        return false;
    }
    if (bundleName.empty() || userId < 0) {
        APP_LOGE("the  bundleName empty or invalid userid");
        EventReport::SendCleanCacheSysEventWithIndex(bundleName, userId, appIndex, false, true);
        return false;
    }
    if (!CheckAppIndex(bundleName, userId, appIndex)) {
        EventReport::SendCleanCacheSysEventWithIndex(bundleName, userId, appIndex, false, true);
        return false;
    }
    if (isBrokerServiceExisted_ && !IsBundleExist(bundleName)) {
        auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
        ErrCode ret = bmsExtensionClient->ClearData(bundleName, userId);
        APP_LOGI("ret : %{public}d", ret);
        EventReport::SendCleanCacheSysEventWithIndex(bundleName, userId, appIndex, false, ret != ERR_OK);
        return ret == ERR_OK;
    }
    ApplicationInfo applicationInfo;
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr || dataMgr->GetApplicationInfoV9(bundleName,
        static_cast<int32_t>(GetApplicationFlag::GET_APPLICATION_INFO_WITH_DISABLE),
        userId, applicationInfo, appIndex) != ERR_OK) {
        APP_LOGE("can not get application info of %{public}s", bundleName.c_str());
        EventReport::SendCleanCacheSysEventWithIndex(bundleName, userId, appIndex, false, true);
        return false;
    }

    if (!applicationInfo.userDataClearable) {
        APP_LOGE("can not clean dataFiles of %{public}s due to userDataClearable is false", bundleName.c_str());
        EventReport::SendCleanCacheSysEventWithIndex(bundleName, userId, appIndex, false, true);
        return false;
    }
    InnerBundleUserInfo innerBundleUserInfo;
    if (!GetBundleUserInfo(bundleName, userId, innerBundleUserInfo)) {
        APP_LOGE("%{public}s, userId:%{public}d, GetBundleUserInfo failed", bundleName.c_str(), userId);
        EventReport::SendCleanCacheSysEventWithIndex(bundleName, userId, appIndex, false, true);
        return false;
    }
    if (BundlePermissionMgr::ClearUserGrantedPermissionState(applicationInfo.accessTokenId)) {
        APP_LOGE("%{public}s, ClearUserGrantedPermissionState failed", bundleName.c_str());
        EventReport::SendCleanCacheSysEventWithIndex(bundleName, userId, appIndex, false, true);
        return false;
    }
    if (InstalldClient::GetInstance()->CleanBundleDataDirByName(bundleName, userId, appIndex) != ERR_OK) {
        APP_LOGE("%{public}s, CleanBundleDataDirByName failed", bundleName.c_str());
        EventReport::SendCleanCacheSysEventWithIndex(bundleName, userId, appIndex, false, true);
        return false;
    }
    EventReport::SendCleanCacheSysEventWithIndex(bundleName, userId, appIndex, false, false);
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
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::LISTEN_BUNDLE_CHANGE)) {
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
    auto uid = IPCSkeleton::GetCallingUid();
    if (uid != Constants::FOUNDATION_UID) {
        APP_LOGE("verify calling uid failed, uid : %{public}d", uid);
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
    auto uid = IPCSkeleton::GetCallingUid();
    if (uid != Constants::FOUNDATION_UID) {
        APP_LOGE("verify calling uid failed, uid : %{public}d", uid);
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
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::LISTEN_BUNDLE_CHANGE)) {
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
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::LISTEN_BUNDLE_CHANGE)) {
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

ErrCode BundleMgrHostImpl::CompileProcessAOT(const std::string &bundleName, const std::string &compileMode,
    bool isAllBundle, std::vector<std::string> &compileResults)
{
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    return AOTHandler::GetInstance().HandleCompile(bundleName, compileMode, isAllBundle, compileResults);
}

ErrCode BundleMgrHostImpl::CompileReset(const std::string &bundleName, bool isAllBundle)
{
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    AOTHandler::GetInstance().HandleResetAOT(bundleName, isAllBundle);
    return ERR_OK;
}

ErrCode BundleMgrHostImpl::CopyAp(const std::string &bundleName, bool isAllBundle, std::vector<std::string> &results)
{
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    return AOTHandler::GetInstance().HandleCopyAp(bundleName, isAllBundle, results);
}

bool BundleMgrHostImpl::DumpInfos(
    const DumpFlag flag, const std::string &bundleName, int32_t userId, std::string &result)
{
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify permission failed");
        return false;
    }
    bool ret = false;
    switch (flag) {
        case DumpFlag::DUMP_BUNDLE_LIST: {
            ret = DumpAllBundleInfoNames(userId, result);
            break;
        }
        case DumpFlag::DUMP_DEBUG_BUNDLE_LIST: {
            ret = DumpDebugBundleInfoNames(userId, result);
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

bool BundleMgrHostImpl::DumpDebugBundleInfoNames(int32_t userId, std::string &result)
{
    APP_LOGD("DumpDebugBundleInfoNames begin");
    if (userId != Constants::ALL_USERID) {
        return DumpDebugBundleInfoNamesByUserId(userId, result);
    }

    auto userIds = GetExistsCommonUserIs();
    for (auto userId : userIds) {
        DumpDebugBundleInfoNamesByUserId(userId, result);
    }

    APP_LOGD("DumpDebugBundleInfoNames success");
    return true;
}

bool BundleMgrHostImpl::DumpDebugBundleInfoNamesByUserId(int32_t userId, std::string &result)
{
    APP_LOGD("DumpDebugBundleInfoNamesByUserId begin");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }

    std::vector<std::string> bundleNames;
    if (!dataMgr->GetDebugBundleList(bundleNames, userId)) {
        APP_LOGE("get debug bundle list failed by userId(%{public}d)", userId);
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
    APP_LOGD("DumpDebugBundleInfoNamesByUserId successfully");
    return true;
}

bool BundleMgrHostImpl::DumpBundleInfo(
    const std::string &bundleName, int32_t userId, std::string &result)
{
    APP_LOGD("DumpBundleInfo begin");
    std::vector<InnerBundleUserInfo> innerBundleUserInfos;
    InnerBundleUserInfo innerBundleUserInfo;
    if (!GetBundleUserInfo(bundleName, userId, innerBundleUserInfo) &&
        !GetBundleUserInfo(bundleName, Constants::DEFAULT_USERID, innerBundleUserInfo)) {
        APP_LOGE("get all userInfos in bundle(%{public}s) failed", bundleName.c_str());
        return false;
    }
    innerBundleUserInfos.emplace_back(innerBundleUserInfo);

    BundleInfo bundleInfo;
    if (!GetBundleInfo(bundleName,
        BundleFlag::GET_BUNDLE_WITH_ABILITIES |
        BundleFlag::GET_BUNDLE_WITH_REQUESTED_PERMISSION |
        BundleFlag::GET_BUNDLE_WITH_EXTENSION_INFO |
        BundleFlag::GET_BUNDLE_WITH_HASH_VALUE |
        BundleFlag::GET_BUNDLE_WITH_MENU |
        BundleFlag::GET_BUNDLE_WITH_ROUTER_MAP, bundleInfo, userId)) {
        APP_LOGE("get bundleInfo(%{public}s) failed", bundleName.c_str());
        return false;
    }

    result.append(bundleName);
    result.append(":\n");
    nlohmann::json jsonObject = bundleInfo;
    jsonObject.erase("abilityInfos");
    jsonObject.erase("signatureInfo");
    jsonObject.erase("extensionAbilityInfo");
    jsonObject["applicationInfo"] = bundleInfo.applicationInfo;
    jsonObject["userInfo"] = innerBundleUserInfos;
    jsonObject["appIdentifier"] = bundleInfo.signatureInfo.appIdentifier;
    try {
        result.append(jsonObject.dump(Constants::DUMP_INDENT));
    } catch (const nlohmann::json::type_error &e) {
        APP_LOGE("dump[%{public}s] failed: %{public}s", bundleName.c_str(), e.what());
        return false;
    }
    result.append("\n");
    APP_LOGD("DumpBundleInfo success with bundleName %{public}s", bundleName.c_str());
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
        try {
            result.append(jsonObject.dump(Constants::DUMP_INDENT));
        } catch (const nlohmann::json::type_error &e) {
            APP_LOGE("dump shortcut failed: %{public}s", e.what());
            return false;
        }
        result.append("\n");
    }
    APP_LOGD("DumpShortcutInfo success with bundleName %{public}s", bundleName.c_str());
    return true;
}

ErrCode BundleMgrHostImpl::IsModuleRemovable(const std::string &bundleName, const std::string &moduleName,
    bool &isRemovable)
{
    // check permission
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
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
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
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
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_BUNDLE)) {
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
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_INSTALL_BUNDLE)) {
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
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("start IsApplicationEnabled, bundleName : %{public}s", bundleName.c_str());
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(ServiceConstants::API_VERSION_NINE)) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_APPEXECFWK_SERVICE_NOT_READY;
    }
    return dataMgr->IsApplicationEnabled(bundleName, 0, isEnable);
}

ErrCode BundleMgrHostImpl::IsCloneApplicationEnabled(const std::string &bundleName, int32_t appIndex, bool &isEnable)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("start IsCloneApplicationEnabled, bundleName: %{public}s appIndex: %{public}d",
        bundleName.c_str(), appIndex);
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_APPEXECFWK_SERVICE_NOT_READY;
    }
    return dataMgr->IsApplicationEnabled(bundleName, appIndex, isEnable);
}

ErrCode BundleMgrHostImpl::SetApplicationEnabled(const std::string &bundleName, bool isEnable, int32_t userId)
{
    std::string caller = GetCallerName();
    APP_LOGW_NOFUNC("SetApplicationEnabled %{public}s %{public}d %{public}d caller:%{public}s",
        bundleName.c_str(), isEnable, userId, caller.c_str());
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = BundleUtil::GetUserIdByCallingUid();
    }
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_CHANGE_ABILITY_ENABLED_STATE)) {
        APP_LOGE("verify permission failed");
        EventReport::SendComponentStateSysEventForException(bundleName, "", userId, isEnable, 0, caller);
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    if (!CheckCanSetEnable(bundleName)) {
        APP_LOGE("bundle in white-list");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        EventReport::SendComponentStateSysEventForException(bundleName, "", userId, isEnable, 0, caller);
        return ERR_APPEXECFWK_SERVICE_NOT_READY;
    }

    auto ret = dataMgr->SetApplicationEnabled(bundleName, 0, isEnable, caller, userId);
    if (ret != ERR_OK) {
        APP_LOGE("Set application(%{public}s) enabled value faile", bundleName.c_str());
        EventReport::SendComponentStateSysEventForException(bundleName, "", userId, isEnable, 0, caller);
        return ret;
    }

    EventReport::SendComponentStateSysEvent(bundleName, "", userId, isEnable, 0, caller);
    InnerBundleUserInfo innerBundleUserInfo;
    if (!GetBundleUserInfo(bundleName, userId, innerBundleUserInfo)) {
        APP_LOGE("Get calling userInfo in bundle(%{public}s) failed", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    NotifyBundleEvents installRes = {
        .type = NotifyType::APPLICATION_ENABLE,
        .resultCode = ERR_OK,
        .accessTokenId = innerBundleUserInfo.accessTokenId,
        .uid = innerBundleUserInfo.uid,
        .bundleName = bundleName
    };
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    std::shared_ptr<BundleCommonEventMgr> commonEventMgr = std::make_shared<BundleCommonEventMgr>();
    commonEventMgr->NotifyBundleStatus(installRes, dataMgr);
    IPCSkeleton::SetCallingIdentity(identity);
    return ERR_OK;
}

ErrCode BundleMgrHostImpl::SetCloneApplicationEnabled(
    const std::string &bundleName, int32_t appIndex, bool isEnable, int32_t userId)
{
    std::string caller = GetCallerName();
    APP_LOGW_NOFUNC("SetCloneApplicationEnabled param %{public}s %{public}d %{public}d %{public}d caller:%{public}s",
        bundleName.c_str(), appIndex, isEnable, userId, caller.c_str());
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_CHANGE_ABILITY_ENABLED_STATE)) {
        APP_LOGE("verify permission failed");
        EventReport::SendComponentStateSysEventForException(bundleName, "", userId, isEnable, appIndex, caller);
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = BundleUtil::GetUserIdByCallingUid();
    }
    APP_LOGD("verify permission success, begin to SetCloneApplicationEnabled");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        EventReport::SendComponentStateSysEventForException(bundleName, "", userId, isEnable, appIndex, caller);
        return ERR_APPEXECFWK_SERVICE_NOT_READY;
    }
    auto ret = dataMgr->SetApplicationEnabled(bundleName, appIndex, isEnable, caller, userId);
    if (ret != ERR_OK) {
        APP_LOGE("Set application(%{public}s) enabled value fail", bundleName.c_str());
        EventReport::SendComponentStateSysEventForException(bundleName, "", userId, isEnable, appIndex, caller);
        return ret;
    }

    EventReport::SendComponentStateSysEvent(bundleName, "", userId, isEnable, appIndex, caller);
    InnerBundleUserInfo innerBundleUserInfo;
    if (!GetBundleUserInfo(bundleName, userId, innerBundleUserInfo)) {
        APP_LOGE("Get calling userInfo in bundle(%{public}s) failed", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    NotifyBundleEvents installRes = {
        .type = NotifyType::APPLICATION_ENABLE,
        .resultCode = ERR_OK,
        .accessTokenId = innerBundleUserInfo.accessTokenId,
        .uid = innerBundleUserInfo.uid,
        .appIndex = appIndex,
        .bundleName = bundleName
    };
    NotifyBundleStatus(installRes);
    APP_LOGD("SetCloneApplicationEnabled finish");
    return ERR_OK;
}

ErrCode BundleMgrHostImpl::IsAbilityEnabled(const AbilityInfo &abilityInfo, bool &isEnable)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("start IsAbilityEnabled");
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(ServiceConstants::API_VERSION_NINE)) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_APPEXECFWK_SERVICE_NOT_READY;
    }
    return dataMgr->IsAbilityEnabled(abilityInfo, 0, isEnable);
}

ErrCode BundleMgrHostImpl::IsCloneAbilityEnabled(const AbilityInfo &abilityInfo, int32_t appIndex, bool &isEnable)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("start IsCloneAbilityEnabled");
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_APPEXECFWK_SERVICE_NOT_READY;
    }
    return dataMgr->IsAbilityEnabled(abilityInfo, appIndex, isEnable);
}

ErrCode BundleMgrHostImpl::SetAbilityEnabled(const AbilityInfo &abilityInfo, bool isEnabled, int32_t userId)
{
    std::string caller = GetCallerName();
    APP_LOGW_NOFUNC("SetAbilityEnabled %{public}s %{public}d %{public}d caller:%{public}s",
        abilityInfo.name.c_str(), isEnabled, userId, caller.c_str());
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = BundleUtil::GetUserIdByCallingUid();
    }
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_CHANGE_ABILITY_ENABLED_STATE)) {
        APP_LOGE("verify permission failed");
        EventReport::SendComponentStateSysEventForException(abilityInfo.bundleName, abilityInfo.name,
            userId, isEnabled, 0, caller);
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    if (!CheckCanSetEnable(abilityInfo.bundleName)) {
        APP_LOGE("bundle in white-list");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        EventReport::SendComponentStateSysEventForException(abilityInfo.bundleName, abilityInfo.name,
            userId, isEnabled, 0, caller);
        return ERR_APPEXECFWK_SERVICE_NOT_READY;
    }
    auto ret = dataMgr->SetAbilityEnabled(abilityInfo, 0, isEnabled, userId);
    if (ret != ERR_OK) {
        APP_LOGE("Set ability(%{public}s) enabled value failed", abilityInfo.bundleName.c_str());
        EventReport::SendComponentStateSysEventForException(abilityInfo.bundleName, abilityInfo.name,
            userId, isEnabled, 0, caller);
        return ret;
    }
    EventReport::SendComponentStateSysEvent(abilityInfo.bundleName, abilityInfo.name, userId, isEnabled, 0, caller);
    InnerBundleUserInfo innerBundleUserInfo;
    if (!GetBundleUserInfo(abilityInfo.bundleName, userId, innerBundleUserInfo)) {
        APP_LOGE("Get calling userInfo in bundle(%{public}s) failed", abilityInfo.bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    NotifyBundleEvents installRes = {
        .type = NotifyType::APPLICATION_ENABLE,
        .resultCode = ERR_OK,
        .accessTokenId = innerBundleUserInfo.accessTokenId,
        .uid = innerBundleUserInfo.uid,
        .bundleName = abilityInfo.bundleName,
        .abilityName = abilityInfo.name
    };
    NotifyBundleStatus(installRes);
    return ERR_OK;
}

ErrCode BundleMgrHostImpl::SetCloneAbilityEnabled(const AbilityInfo &abilityInfo,
    int32_t appIndex, bool isEnabled, int32_t userId)
{
    std::string caller = GetCallerName();
    APP_LOGW_NOFUNC("SetCloneAbilityEnabled %{public}s %{public}d %{public}d %{public}d caller:%{public}s",
        abilityInfo.name.c_str(), appIndex, isEnabled, userId, caller.c_str());
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_CHANGE_ABILITY_ENABLED_STATE)) {
        APP_LOGE("verify permission failed");
        EventReport::SendComponentStateSysEventForException(abilityInfo.bundleName, abilityInfo.name,
            userId, isEnabled, appIndex, caller);
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = BundleUtil::GetUserIdByCallingUid();
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        EventReport::SendComponentStateSysEventForException(abilityInfo.bundleName, abilityInfo.name,
            userId, isEnabled, appIndex, caller);
        return ERR_APPEXECFWK_SERVICE_NOT_READY;
    }
    auto ret = dataMgr->SetAbilityEnabled(abilityInfo, appIndex, isEnabled, userId);
    if (ret != ERR_OK) {
        APP_LOGE("Set ability(%{public}s) enabled value failed", abilityInfo.bundleName.c_str());
        EventReport::SendComponentStateSysEventForException(abilityInfo.bundleName, abilityInfo.name,
            userId, isEnabled, appIndex, caller);
        return ret;
    }
    EventReport::SendComponentStateSysEvent(
        abilityInfo.bundleName, abilityInfo.name, userId, isEnabled, appIndex, caller);
    InnerBundleUserInfo innerBundleUserInfo;
    if (!GetBundleUserInfo(abilityInfo.bundleName, userId, innerBundleUserInfo)) {
        APP_LOGE("Get calling userInfo in bundle(%{public}s) failed", abilityInfo.bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    NotifyBundleEvents installRes = {
        .type = NotifyType::APPLICATION_ENABLE,
        .resultCode = ERR_OK,
        .accessTokenId = innerBundleUserInfo.accessTokenId,
        .uid = innerBundleUserInfo.uid,
        .appIndex = appIndex,
        .bundleName = abilityInfo.bundleName,
        .abilityName = abilityInfo.name
    };
    NotifyBundleStatus(installRes);
    return ERR_OK;
}

sptr<IBundleInstaller> BundleMgrHostImpl::GetBundleInstaller()
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
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
    if (callingUid != ServiceConstants::ACCOUNT_UID) {
        APP_LOGE("invalid calling uid %{public}d to GetbundleUserMgr", callingUid);
        return nullptr;
    }
    return DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleUserMgr();
}

sptr<IVerifyManager> BundleMgrHostImpl::GetVerifyManager()
{
    return DelayedSingleton<BundleMgrService>::GetInstance()->GetVerifyManager();
}

sptr<IExtendResourceManager> BundleMgrHostImpl::GetExtendResourceManager()
{
    return DelayedSingleton<BundleMgrService>::GetInstance()->GetExtendResourceManager();
}

bool BundleMgrHostImpl::GetAllFormsInfo(std::vector<FormInfo> &formInfos)
{
    APP_LOGD("start GetAllFormsInfo");
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
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
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED) &&
        !BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
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
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED) &&
        !BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
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
    int32_t currentUserId = AccountHelper::GetCurrentActiveUserId();
    APP_LOGD("current active userId is %{public}d", currentUserId);
    if (currentUserId == Constants::INVALID_USERID) {
        APP_LOGW("current userId is invalid");
        return false;
    }

    return GetShortcutInfos(bundleName, currentUserId, shortcutInfos);
}

bool BundleMgrHostImpl::GetShortcutInfos(
    const std::string &bundleName, int32_t userId, std::vector<ShortcutInfo> &shortcutInfos)
{
    APP_LOGD("start GetShortcutInfos, bundleName : %{public}s, userId : %{public}d", bundleName.c_str(), userId);
    // API9 need to be system app otherwise return empty data
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(ServiceConstants::API_VERSION_NINE)) {
        APP_LOGD("non-system app calling system api");
        return true;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
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

ErrCode BundleMgrHostImpl::GetShortcutInfoV9(const std::string &bundleName,
    std::vector<ShortcutInfo> &shortcutInfos, int32_t userId)
{
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO}) &&
        !BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->GetShortcutInfoV9(bundleName, userId, shortcutInfos);
}

bool BundleMgrHostImpl::GetAllCommonEventInfo(const std::string &eventKey,
    std::vector<CommonEventInfo> &commonEventInfos)
{
    APP_LOGD("start GetAllCommonEventInfo, eventKey : %{public}s", eventKey.c_str());
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
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
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("Non-system app calling system api");
        return false;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO}) &&
        !BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
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
    LOG_D(BMS_TAG_QUERY, "QueryExtensionAbilityInfos without type begin");
    // API9 need to be system app, otherwise return empty data
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(ServiceConstants::API_VERSION_NINE)) {
        LOG_D(BMS_TAG_QUERY, "non-system app calling system api");
        return true;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO}) &&
        !BundlePermissionMgr::IsBundleSelfCalling(want.GetElement().GetBundleName())) {
        LOG_E(BMS_TAG_QUERY, "verify permission failed");
        return false;
    }
    LOG_D(BMS_TAG_QUERY, "want uri is %{private}s", want.GetUriString().c_str());
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_QUERY, "DataMgr is nullptr");
        return false;
    }
    (void)dataMgr->QueryExtensionAbilityInfos(want, flag, userId, extensionInfos);
    dataMgr->QueryAllCloneExtensionInfos(want, flag, userId, extensionInfos);
    if (extensionInfos.empty()) {
        LOG_E(BMS_TAG_QUERY, "no valid extension info can be inquired");
        return false;
    }
    return true;
}

ErrCode BundleMgrHostImpl::QueryExtensionAbilityInfosV9(const Want &want, int32_t flags, int32_t userId,
    std::vector<ExtensionAbilityInfo> &extensionInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    LOG_D(BMS_TAG_QUERY, "QueryExtensionAbilityInfosV9 without type begin");
    if (!BundlePermissionMgr::IsSystemApp()) {
        LOG_E(BMS_TAG_QUERY, "non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO}) &&
        !BundlePermissionMgr::IsBundleSelfCalling(want.GetElement().GetBundleName())) {
        LOG_E(BMS_TAG_QUERY, "verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    LOG_D(BMS_TAG_QUERY, "want uri is %{private}s", want.GetUriString().c_str());
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_QUERY, "DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    ErrCode ret = dataMgr->QueryExtensionAbilityInfosV9(want, flags, userId, extensionInfos);
    dataMgr->QueryAllCloneExtensionInfosV9(want, flags, userId, extensionInfos);

    if (extensionInfos.empty()) {
        if (ret != ERR_OK) {
            LOG_E(BMS_TAG_QUERY, "query extension ability fail, %{public}d", ret);
            return ret;
        }
        LOG_E(BMS_TAG_QUERY, "no valid extension info can be inquired");
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }
    return ERR_OK;
}

bool BundleMgrHostImpl::QueryExtensionAbilityInfos(const Want &want, const ExtensionAbilityType &extensionType,
    const int32_t &flag, const int32_t &userId, std::vector<ExtensionAbilityInfo> &extensionInfos)
{
    LOG_D(BMS_TAG_QUERY, "QueryExtensionAbilityInfos begin");
    // API9 need to be system app, otherwise return empty data
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(ServiceConstants::API_VERSION_NINE)) {
        LOG_D(BMS_TAG_QUERY, "non-system app calling system api");
        return true;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO}) &&
        !BundlePermissionMgr::IsBundleSelfCalling(want.GetElement().GetBundleName())) {
        LOG_E(BMS_TAG_QUERY, "verify permission failed");
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_QUERY, "DataMgr is nullptr");
        return false;
    }
    std::vector<ExtensionAbilityInfo> infos;
    (void)dataMgr->QueryExtensionAbilityInfos(want, flag, userId, infos);
    dataMgr->QueryAllCloneExtensionInfos(want, flag, userId, infos);

    for_each(infos.begin(), infos.end(), [&extensionType, &extensionInfos](const auto &info)->decltype(auto) {
        LOG_D(BMS_TAG_QUERY, "QueryExtensionAbilityInfos extensionType:%{public}d info.type:%{public}d",
            static_cast<int32_t>(extensionType), static_cast<int32_t>(info.type));
        if (extensionType == info.type) {
            extensionInfos.emplace_back(info);
        }
    });
    if (extensionInfos.empty()) {
        LOG_E(BMS_TAG_QUERY, "no valid extension info can be inquired");
        return false;
    }
    return true;
}

ErrCode BundleMgrHostImpl::QueryExtensionAbilityInfosV9(const Want &want, const ExtensionAbilityType &extensionType,
    int32_t flags, int32_t userId, std::vector<ExtensionAbilityInfo> &extensionInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    LOG_D(BMS_TAG_QUERY, "QueryExtensionAbilityInfosV9 begin");
    if (!BundlePermissionMgr::IsSystemApp()) {
        LOG_E(BMS_TAG_QUERY, "non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO}) &&
        !BundlePermissionMgr::IsBundleSelfCalling(want.GetElement().GetBundleName())) {
        LOG_E(BMS_TAG_QUERY, "verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_QUERY, "DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    std::vector<ExtensionAbilityInfo> infos;
    ErrCode ret = dataMgr->QueryExtensionAbilityInfosV9(want, flags, userId, infos);
    dataMgr->QueryAllCloneExtensionInfosV9(want, flags, userId, infos);
    for_each(infos.begin(), infos.end(), [&extensionType, &extensionInfos](const auto &info)->decltype(auto) {
        LOG_D(BMS_TAG_QUERY, "QueryExtensionAbilityInfosV9 extensionType:%{public}d info.type:%{public}d",
            static_cast<int32_t>(extensionType), static_cast<int32_t>(info.type));
        if (extensionType == info.type) {
            extensionInfos.emplace_back(info);
        }
    });
    if (extensionInfos.empty()) {
        if (ret != ERR_OK) {
            LOG_E(BMS_TAG_QUERY, "query extension ability fail, %{public}d", ret);
            return ret;
        }
        LOG_E(BMS_TAG_QUERY, "no valid extension info can be inquired");
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }
    return ERR_OK;
}

bool BundleMgrHostImpl::QueryExtensionAbilityInfos(const ExtensionAbilityType &extensionType, const int32_t &userId,
    std::vector<ExtensionAbilityInfo> &extensionInfos)
{
    LOG_D(BMS_TAG_QUERY, "QueryExtensionAbilityInfos with type begin");
    // API9 need to be system app, otherwise return empty data
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(ServiceConstants::API_VERSION_NINE)) {
        LOG_D(BMS_TAG_QUERY, "non-system app calling system api");
        return true;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO})) {
        LOG_E(BMS_TAG_QUERY, "verify permission failed");
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_QUERY, "DataMgr is nullptr");
        return false;
    }
    bool ret = dataMgr->QueryExtensionAbilityInfos(extensionType, userId, extensionInfos);
    if (!ret) {
        LOG_E(BMS_TAG_QUERY, "QueryExtensionAbilityInfos is failed, errno: %{public}d", ret);
        return false;
    }

    if (extensionInfos.empty()) {
        LOG_E(BMS_TAG_QUERY, "no valid extension info can be inquired");
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
    int32_t currentUserId = AccountHelper::GetCurrentActiveUserId();
    return DelayedSingleton<BundleMgrService>::GetInstance()->GetConnectAbility(currentUserId);
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

std::string BundleMgrHostImpl::GetAppPrivilegeLevel(const std::string &bundleName, int32_t userId)
{
    APP_LOGD("start GetAppPrivilegeLevel");
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED) &&
        !BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
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
    int32_t timerId = XCollieHelper::SetRecoveryTimer(FUNCTION_VERIFY_CALLING_PERMISSION);
    ScopeGuard cancelTimerIdGuard([timerId] { XCollieHelper::CancelTimer(timerId); });
    return BundlePermissionMgr::VerifyCallingPermissionForAll(permission);
}

bool BundleMgrHostImpl::QueryExtensionAbilityInfoByUri(const std::string &uri, int32_t userId,
    ExtensionAbilityInfo &extensionAbilityInfo)
{
    LOG_I(BMS_TAG_QUERY, "uri:%{private}s -u %{public}d", uri.c_str(), userId);
    // API9 need to be system app, otherwise return empty data
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(ServiceConstants::API_VERSION_NINE)) {
        LOG_D(BMS_TAG_QUERY, "non-system app calling system api");
        return true;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO})) {
        LOG_E(BMS_TAG_QUERY, "verify query permission failed");
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_QUERY, "DataMgr is nullptr");
        return false;
    }
    return dataMgr->QueryExtensionAbilityInfoByUri(uri, userId, extensionAbilityInfo);
}

std::string BundleMgrHostImpl::GetAppIdByBundleName(const std::string &bundleName, const int userId)
{
    APP_LOGD("bundleName : %{public}s, userId : %{public}d", bundleName.c_str(), userId);
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED) &&
        !BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
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
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED) &&
        !BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
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
    std::string appType = isSystemApp ? SYSTEM_APP : THIRD_PARTY_APP;
    APP_LOGD("appType is %{public}s", appType.c_str());
    return appType;
}

int32_t BundleMgrHostImpl::GetUidByBundleName(const std::string &bundleName, const int32_t userId)
{
    return GetUidByBundleName(bundleName, userId, 0);
}

int32_t BundleMgrHostImpl::GetUidByBundleName(const std::string &bundleName, const int32_t userId, int32_t appIndex)
{
    APP_LOGD("bundleName : %{public}s, userId : %{public}d", bundleName.c_str(), userId);
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED) &&
        !BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
        APP_LOGE("verify token type failed");
        return Constants::INVALID_UID;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return Constants::INVALID_UID;
    }
    return dataMgr->GetUidByBundleName(bundleName, userId, appIndex);
}

int BundleMgrHostImpl::GetUidByDebugBundleName(const std::string &bundleName, const int userId)
{
    APP_LOGD("bundleName : %{public}s, userId : %{public}d", bundleName.c_str(), userId);
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO}) &&
        !BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
        APP_LOGE("verify token type failed");
        return Constants::INVALID_UID;
    }
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
    LOG_D(BMS_TAG_QUERY, "start GetAbilityInfo, bundleName:%{public}s abilityName:%{public}s",
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
    LOG_D(BMS_TAG_QUERY,
        "start GetAbilityInfo bundleName:%{public}s moduleName:%{public}s abilityName:%{public}s",
        bundleName.c_str(), moduleName.c_str(), abilityName.c_str());
    if (!VerifySystemApi(ServiceConstants::API_VERSION_NINE)) {
        LOG_D(BMS_TAG_QUERY, "non-system app calling system api");
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
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(ServiceConstants::API_VERSION_NINE)) {
        APP_LOGD("non-system app calling system api");
        return true;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO}) &&
        !BundlePermissionMgr::IsBundleSelfCalling(want.GetElement().GetBundleName())) {
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

bool BundleMgrHostImpl::ImplicitQueryInfos(const Want &want, int32_t flags, int32_t userId,  bool withDefault,
    std::vector<AbilityInfo> &abilityInfos, std::vector<ExtensionAbilityInfo> &extensionInfos, bool &findDefaultApp)
{
    APP_LOGD("begin to ImplicitQueryInfos, flags : %{public}d, userId : %{public}d", flags, userId);
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(ServiceConstants::API_VERSION_NINE)) {
        APP_LOGD("non-system app calling system api");
        return true;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO}) &&
        !BundlePermissionMgr::IsBundleSelfCalling(want.GetElement().GetBundleName())) {
        APP_LOGE("verify permission failed");
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    findDefaultApp = false;
    auto ret = dataMgr->ImplicitQueryInfos(
        want, flags, userId, withDefault, abilityInfos, extensionInfos, findDefaultApp);
    if (ret && findDefaultApp) {
        APP_LOGD("default app has been found and unnecessary to find from bms extension");
        return ret;
    }
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    if (!IsAppLinking(flags) && isBrokerServiceExisted_ &&
        bmsExtensionClient->ImplicitQueryAbilityInfos(want, flags, userId, abilityInfos, false) == ERR_OK) {
        APP_LOGD("implicitly query from bms extension successfully");
        FilterAbilityInfos(abilityInfos);
        APP_LOGI_NOFUNC("ImplicitQueryInfos ret a.size:%{public}zu e.size:%{public}zu",
            abilityInfos.size(), extensionInfos.size());
        return true;
    }
    APP_LOGI_NOFUNC("ImplicitQueryInfos ret a.size:%{public}zu e.size:%{public}zu",
        abilityInfos.size(), extensionInfos.size());
    return ret;
}

void BundleMgrHostImpl::FilterAbilityInfos(std::vector<AbilityInfo> &abilityInfos)
{
    AbilityInfo appLinkingAbility;
    bool hasAppLinking = false;
    for (const auto& ability : abilityInfos) {
        if (ability.kind == APP_LINKING) {
            appLinkingAbility = ability;
            hasAppLinking = true;
            break;
        }
    }
    if (hasAppLinking) {
        abilityInfos.clear();
        abilityInfos.push_back(appLinkingAbility);
    }
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
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO}) &&
        !BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
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
    APP_LOGD("start GetSandboxBundleInfo, bundleName : %{public}s, appIndex : %{public}d, userId : %{public}d",
        bundleName.c_str(), appIndex, userId);
    // check bundle name
    if (bundleName.empty()) {
        APP_LOGE("GetSandboxBundleInfo failed due to empty bundleName");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR;
    }
    // check appIndex
    if (appIndex <= Constants::INITIAL_SANDBOX_APP_INDEX || appIndex > Constants::MAX_SANDBOX_APP_INDEX) {
        APP_LOGE("the appIndex %{public}d is invalid", appIndex);
        return ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO}) &&
        !BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
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

bool BundleMgrHostImpl::ObtainCallingBundleName(std::string &bundleName)
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    bool ret = dataMgr->GetBundleNameForUid(IPCSkeleton::GetCallingUid(), bundleName);
    if (!ret) {
        APP_LOGE("query calling bundle name failed");
        return ret;
    }
    APP_LOGD("calling bundleName is : %{public}s", bundleName.c_str());
    return ret;
}

bool BundleMgrHostImpl::GetBundleStats(const std::string &bundleName, int32_t userId,
    std::vector<int64_t> &bundleStats, int32_t appIndex, uint32_t statFlag)
{
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO}) &&
        !BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
        APP_LOGE("verify permission failed");
        return false;
    }
    if (bundleName.empty()) {
        APP_LOGE("bundleName empty");
        return false;
    }
    if (!CheckAppIndex(bundleName, userId, appIndex)) {
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    if (isBrokerServiceExisted_ && !IsBundleExist(bundleName)) {
        auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
        ErrCode ret = bmsExtensionClient->GetBundleStats(bundleName, userId, bundleStats);
        APP_LOGI("ret : %{public}d", ret);
        return ret == ERR_OK;
    }
    return dataMgr->GetBundleStats(bundleName, userId, bundleStats, appIndex, statFlag);
}

bool BundleMgrHostImpl::GetAllBundleStats(int32_t userId, std::vector<int64_t> &bundleStats)
{
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO})) {
        APP_LOGE("verify permission failed");
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->GetAllBundleStats(userId, bundleStats);
}

ErrCode BundleMgrHostImpl::GetAllBundleCacheStat(const sptr<IProcessCacheCallback> processCacheCallback)
{
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("ohos.permission.PERMISSION_GET_BUNDLE_INFO_PRIVILEGED permission denied");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }

    if (processCacheCallback == nullptr) {
        APP_LOGE("the processCacheCallback is nullptr");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    return BundleCacheMgr().GetAllBundleCacheStat(processCacheCallback);
}

ErrCode BundleMgrHostImpl::CleanAllBundleCache(const sptr<IProcessCacheCallback> processCacheCallback)
{
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_REMOVECACHEFILE)) {
        APP_LOGE("ohos.permission.PERMISSION_REMOVECACHEFILE permission denied");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }

    if (processCacheCallback == nullptr) {
        APP_LOGE("the processCacheCallback is nullptr");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    return BundleCacheMgr().CleanAllBundleCache(processCacheCallback);
}

std::string BundleMgrHostImpl::GetStringById(const std::string &bundleName, const std::string &moduleName,
    uint32_t resId, int32_t userId, const std::string &localeInfo)
{
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO}) &&
        !BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
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
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO}) &&
        !BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
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

sptr<IBundleMgrExt> BundleMgrHostImpl::GetBundleMgrExtProxy()
{
    return DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleMgrExtProxy();
}

sptr<IQuickFixManager> BundleMgrHostImpl::GetQuickFixManagerProxy()
{
#ifdef BUNDLE_FRAMEWORK_QUICK_FIX
    return DelayedSingleton<BundleMgrService>::GetInstance()->GetQuickFixManagerProxy();
#else
    return nullptr;
#endif
}

sptr<IOverlayManager> BundleMgrHostImpl::GetOverlayManagerProxy()
{
#ifdef BUNDLE_FRAMEWORK_OVERLAY_INSTALLATION
    int32_t timerId = XCollieHelper::SetRecoveryTimer(FUNCTION_GET_OVERLAY_MANAGER_PROXY);
    ScopeGuard cancelTimerIdGuard([timerId] { XCollieHelper::CancelTimer(timerId); });
    return DelayedSingleton<BundleMgrService>::GetInstance()->GetOverlayManagerProxy();
#else
    return nullptr;
#endif
}

ErrCode BundleMgrHostImpl::GetSandboxAbilityInfo(const Want &want, int32_t appIndex, int32_t flags, int32_t userId,
    AbilityInfo &info)
{
    APP_LOGD("start GetSandboxAbilityInfo appIndex : %{public}d, userId : %{public}d", appIndex, userId);
    // check appIndex
    if (appIndex <= Constants::INITIAL_SANDBOX_APP_INDEX || appIndex > Constants::MAX_SANDBOX_APP_INDEX) {
        APP_LOGE("the appIndex %{public}d is invalid", appIndex);
        return ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO}) &&
        !BundlePermissionMgr::IsBundleSelfCalling(want.GetElement().GetBundleName())) {
        APP_LOGE("verify permission failed");
        return ERR_APPEXECFWK_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_APPEXECFWK_SANDBOX_QUERY_INTERNAL_ERROR;
    }

    if (!(dataMgr->QueryAbilityInfo(want, flags, userId, info, appIndex)
        || dataMgr->QueryAbilityInfo(want, flags, Constants::DEFAULT_USERID, info, appIndex))) {
        APP_LOGE("query ability info failed");
        return ERR_APPEXECFWK_SANDBOX_QUERY_INTERNAL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHostImpl::GetSandboxExtAbilityInfos(const Want &want, int32_t appIndex, int32_t flags,
    int32_t userId, std::vector<ExtensionAbilityInfo> &infos)
{
    APP_LOGD("start GetSandboxExtAbilityInfos appIndex : %{public}d, userId : %{public}d", appIndex, userId);
    // check appIndex
    if (appIndex <= Constants::INITIAL_SANDBOX_APP_INDEX || appIndex > Constants::MAX_SANDBOX_APP_INDEX) {
        APP_LOGE("the appIndex %{public}d is invalid", appIndex);
        return ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO}) &&
        !BundlePermissionMgr::IsBundleSelfCalling(want.GetElement().GetBundleName())) {
        APP_LOGE("verify permission failed");
        return ERR_APPEXECFWK_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_APPEXECFWK_SANDBOX_QUERY_INTERNAL_ERROR;
    }

    if (!(dataMgr->QueryExtensionAbilityInfos(want, flags, userId, infos, appIndex)
        || dataMgr->QueryExtensionAbilityInfos(want, flags, Constants::DEFAULT_USERID, infos, appIndex))) {
        APP_LOGE("query extension ability info failed");
        return ERR_APPEXECFWK_SANDBOX_QUERY_INTERNAL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHostImpl::GetSandboxHapModuleInfo(const AbilityInfo &abilityInfo, int32_t appIndex, int32_t userId,
    HapModuleInfo &info)
{
    APP_LOGD("start GetSandboxHapModuleInfo appIndex : %{public}d, userId : %{public}d", appIndex, userId);
    // check appIndex
    if (appIndex <= Constants::INITIAL_SANDBOX_APP_INDEX || appIndex > Constants::MAX_SANDBOX_APP_INDEX) {
        APP_LOGE("the appIndex %{public}d is invalid", appIndex);
        return ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO}) &&
        !BundlePermissionMgr::IsBundleSelfCalling(abilityInfo.bundleName)) {
        APP_LOGE("verify permission failed");
        return ERR_APPEXECFWK_PERMISSION_DENIED;
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
    // API9 need to be system app, otherwise return empty data
    if (!BundlePermissionMgr::IsSystemApp() &&
        !BundlePermissionMgr::VerifyCallingBundleSdkVersion(ServiceConstants::API_VERSION_NINE)) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO}) &&
        !BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
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
    if (callingUid != Constants::ROOT_UID && callingUid != ServiceConstants::BMS_UID) {
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
    int32_t timerId = XCollieHelper::SetRecoveryTimer(FUNCTION_VERIFY_SYSTEM_API);
    ScopeGuard cancelTimerIdGuard([timerId] { XCollieHelper::CancelTimer(timerId); });
    return BundlePermissionMgr::VerifySystemApp(beginApiVersion);
}

ErrCode BundleMgrHostImpl::GetAppProvisionInfo(const std::string &bundleName, int32_t userId,
    AppProvisionInfo &appProvisionInfo)
{
    APP_LOGD("begin to GetAppProvisionInfo bundleName: %{public}s, userId: %{public}d", bundleName.c_str(),
        userId);
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED) &&
        !BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->GetAppProvisionInfo(bundleName, userId, appProvisionInfo);
}

ErrCode BundleMgrHostImpl::GetProvisionMetadata(const std::string &bundleName, int32_t userId,
    std::vector<Metadata> &provisionMetadatas)
{
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO}) &&
        !BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
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

ErrCode BundleMgrHostImpl::GetAllSharedBundleInfo(std::vector<SharedBundleInfo> &sharedBundles)
{
    APP_LOGD("begin to GetAllSharedBundleInfo");
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }

    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->GetAllSharedBundleInfo(sharedBundles);
}

ErrCode BundleMgrHostImpl::GetSharedBundleInfo(const std::string &bundleName, const std::string &moduleName,
    std::vector<SharedBundleInfo> &sharedBundles)
{
    APP_LOGD("GetSharedBundleInfo: bundleName: %{public}s, moduleName: %{public}s",
        bundleName.c_str(), moduleName.c_str());
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED) &&
        !BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }

    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->GetSharedBundleInfo(bundleName, moduleName, sharedBundles);
}

ErrCode BundleMgrHostImpl::GetSharedBundleInfoBySelf(const std::string &bundleName,
    SharedBundleInfo &sharedBundleInfo)
{
    APP_LOGD("begin to GetSharedBundleInfoBySelf bundleName: %{public}s", bundleName.c_str());
    int32_t timerId = XCollieHelper::SetRecoveryTimer(FUNCTION_GET_SHARED_BUNDLE_INFO_BY_SELF);
    ScopeGuard cancelTimerIdGuard([timerId] { XCollieHelper::CancelTimer(timerId); });
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO}) &&
        !BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }

    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->GetSharedBundleInfoBySelf(bundleName, sharedBundleInfo);
}

ErrCode BundleMgrHostImpl::GetSharedDependencies(const std::string &bundleName, const std::string &moduleName,
    std::vector<Dependency> &dependencies)
{
    APP_LOGD("GetSharedDependencies: bundleName: %{public}s, moduleName: %{public}s",
        bundleName.c_str(), moduleName.c_str());
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED) &&
        !BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->GetSharedDependencies(bundleName, moduleName, dependencies);
}

bool BundleMgrHostImpl::VerifyDependency(const std::string &sharedBundleName)
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }

    std::string callingBundleName;
    bool ret = dataMgr->GetBundleNameForUid(IPCSkeleton::GetCallingUid(), callingBundleName);
    if (!ret) {
        APP_LOGE("GetBundleNameForUid failed");
        return false;
    }

    InnerBundleInfo callingBundleInfo;
    if (!dataMgr->FetchInnerBundleInfo(callingBundleName, callingBundleInfo)) {
        APP_LOGE("get %{public}s failed", callingBundleName.c_str());
        return false;
    }

    // check whether callingBundleName is dependent on sharedBundleName
    const auto& dependencies = callingBundleInfo.GetDependencies();
    auto iter = std::find_if(dependencies.begin(), dependencies.end(), [&sharedBundleName](const auto &dependency) {
        return dependency.bundleName == sharedBundleName;
    });
    if (iter == dependencies.end()) {
        APP_LOGE("%{public}s is not dependent on %{public}s", callingBundleName.c_str(), sharedBundleName.c_str());
        return false;
    }
    APP_LOGD("verify dependency successfully");
    return true;
}

bool BundleMgrHostImpl::IsPreInstallApp(const std::string &bundleName)
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    return dataMgr->IsPreInstallApp(bundleName);
}

ErrCode BundleMgrHostImpl::GetProxyDataInfos(const std::string &bundleName, const std::string &moduleName,
    std::vector<ProxyData> &proxyDatas, int32_t userId)
{
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify token type failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->GetProxyDataInfos(bundleName, moduleName, userId, proxyDatas);
}

ErrCode BundleMgrHostImpl::GetAllProxyDataInfos(std::vector<ProxyData> &proxyDatas, int32_t userId)
{
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify token type failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->GetAllProxyDataInfos(userId, proxyDatas);
}

ErrCode BundleMgrHostImpl::GetSpecifiedDistributionType(const std::string &bundleName,
    std::string &specifiedDistributionType)
{
    APP_LOGD("GetSpecifiedDistributionType bundleName: %{public}s", bundleName.c_str());
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED) &&
        !BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }

    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->GetSpecifiedDistributionType(bundleName, specifiedDistributionType);
}

ErrCode BundleMgrHostImpl::GetAdditionalInfo(const std::string &bundleName,
    std::string &additionalInfo)
{
    APP_LOGD("GetAdditionalInfo bundleName: %{public}s", bundleName.c_str());
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }

    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->GetAdditionalInfo(bundleName, additionalInfo);
}

ErrCode BundleMgrHostImpl::SetExtNameOrMIMEToApp(const std::string &bundleName, const std::string &moduleName,
    const std::string &abilityName, const std::string &extName, const std::string &mimeType)
{
    APP_LOGD("SetExtNameOrMIMEToApp bundleName: %{public}s, moduleName: %{public}s, \
        abilityName: %{public}s, extName: %{public}s, mimeType: %{public}s",
        bundleName.c_str(), moduleName.c_str(), abilityName.c_str(), extName.c_str(), mimeType.c_str());
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->SetExtNameOrMIMEToApp(bundleName, moduleName, abilityName, extName, mimeType);
}

ErrCode BundleMgrHostImpl::DelExtNameOrMIMEToApp(const std::string &bundleName, const std::string &moduleName,
    const std::string &abilityName, const std::string &extName, const std::string &mimeType)
{
    APP_LOGD("DelExtNameOrMIMEToApp bundleName: %{public}s, moduleName: %{public}s, \
        abilityName: %{public}s, extName: %{public}s, mimeType: %{public}s",
        bundleName.c_str(), moduleName.c_str(), abilityName.c_str(), extName.c_str(), mimeType.c_str());
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->DelExtNameOrMIMEToApp(bundleName, moduleName, abilityName, extName, mimeType);
}

bool BundleMgrHostImpl::QueryDataGroupInfos(const std::string &bundleName, int32_t userId,
    std::vector<DataGroupInfo> &infos)
{
    APP_LOGD("QueryDataGroupInfos bundleName: %{public}s, userId: %{public}d", bundleName.c_str(), userId);
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify permission failed");
        return false;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is nullptr");
        return false;
    }
    return dataMgr->QueryDataGroupInfos(bundleName, userId, infos);
}

bool BundleMgrHostImpl::GetGroupDir(const std::string &dataGroupId, std::string &dir)
{
    APP_LOGD("GetGroupDir dataGroupId: %{public}s", dataGroupId.c_str());
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is nullptr");
        return false;
    }
    return dataMgr->GetGroupDir(dataGroupId, dir);
}

void BundleMgrHostImpl::SetBrokerServiceStatus(bool isServiceExisted)
{
    APP_LOGD("broker service status is %{public}d", isServiceExisted);
    isBrokerServiceExisted_ = isServiceExisted;
}

bool BundleMgrHostImpl::QueryAppGalleryBundleName(std::string &bundleName)
{
    APP_LOGD("QueryAppGalleryBundleName in bundle host impl start");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return false;
    }
    std::string abilityName;
    bool ret = dataMgr->QueryAppGalleryAbilityName(bundleName, abilityName);
    if (!ret) {
        APP_LOGE("get bundleName failed");
        return false;
    }
    APP_LOGD("bundleName is %{public}s", bundleName.c_str());
    return  true;
}

ErrCode BundleMgrHostImpl::QueryExtensionAbilityInfosWithTypeName(const Want &want, const std::string &typeName,
    int32_t flags, int32_t userId, std::vector<ExtensionAbilityInfo> &extensionInfos)
{
    if (!BundlePermissionMgr::IsSystemApp()) {
        LOG_E(BMS_TAG_QUERY, "Non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO}) &&
        !BundlePermissionMgr::IsBundleSelfCalling(want.GetElement().GetBundleName())) {
        LOG_E(BMS_TAG_QUERY, "Verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_QUERY, "DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    std::vector<ExtensionAbilityInfo> infos;
    ErrCode ret = dataMgr->QueryExtensionAbilityInfosV9(want, flags, userId, infos);
    dataMgr->QueryAllCloneExtensionInfosV9(want, flags, userId, infos);
    if (infos.empty()) {
        if (ret != ERR_OK) {
            LOG_E(BMS_TAG_QUERY,
                "QueryExtensionAbilityInfosV9 is failed, -type %{public}s, -f %{public}d -u %{public}d ret: %{public}d",
                typeName.c_str(), flags, userId, ret);
            return ret;
        }
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }
    if (typeName.empty()) {
        extensionInfos = infos;
    } else {
        for_each(infos.begin(), infos.end(), [&typeName, &extensionInfos](const auto &info)->decltype(auto) {
            APP_LOGD("Input typeName is %{public}s, info.type is %{public}s",
                typeName.c_str(), info.extensionTypeName.c_str());
            if (typeName == info.extensionTypeName) {
                extensionInfos.emplace_back(info);
            }
        });
    }
    if (extensionInfos.empty()) {
        LOG_E(BMS_TAG_QUERY, "No valid extension info can be inquired");
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }
    return ERR_OK;
}

ErrCode BundleMgrHostImpl::QueryExtensionAbilityInfosOnlyWithTypeName(const std::string &typeName,
    uint32_t flags, int32_t userId, std::vector<ExtensionAbilityInfo> &extensionInfos)
{
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("Non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO})) {
        APP_LOGE("Verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    if (typeName.empty()) {
        APP_LOGE("Input typeName is empty");
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }
    std::vector<ExtensionAbilityInfo> infos;
    ErrCode ret = dataMgr->QueryExtensionAbilityInfosByExtensionTypeName(typeName, flags, userId, infos);
    if (ret != ERR_OK) {
        APP_LOGE("QueryExtensionAbilityInfosByExtensionTypeName is failed");
        return ret;
    }
    if ((flags &
        static_cast<uint32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_BY_TYPE_NAME)) ==
        static_cast<uint32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_BY_TYPE_NAME)) {
        extensionInfos = infos;
        return ret;
    }
    for_each(infos.begin(), infos.end(), [&typeName, &extensionInfos](const auto &info)->decltype(auto) {
        APP_LOGD("Input typeName is %{public}s, info.type is %{public}s",
            typeName.c_str(), info.extensionTypeName.c_str());
        if (typeName == info.extensionTypeName) {
            extensionInfos.emplace_back(info);
        }
    });
    if (extensionInfos.empty()) {
        APP_LOGE("No valid extension info can be inquired");
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }
    return ERR_OK;
}

ErrCode BundleMgrHostImpl::ResetAOTCompileStatus(const std::string &bundleName, const std::string &moduleName,
    int32_t triggerMode)
{
    APP_LOGD("ResetAOTCompileStatus begin");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is null");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    std::string callingBundleName;
    ErrCode ret = dataMgr->GetNameForUid(IPCSkeleton::GetCallingUid(), callingBundleName);
    if (ret != ERR_OK || bundleName != callingBundleName) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    return dataMgr->ResetAOTCompileStatus(bundleName, moduleName, triggerMode);
}

ErrCode BundleMgrHostImpl::GetJsonProfile(ProfileType profileType, const std::string &bundleName,
    const std::string &moduleName, std::string &profile, int32_t userId)
{
    APP_LOGD("GetJsonProfile profileType: %{public}d, bundleName: %{public}s, moduleName: %{public}s"
        "userId: %{public}d", profileType, bundleName.c_str(), moduleName.c_str(), userId);
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED,
        Constants::PERMISSION_GET_BUNDLE_INFO}) &&
        !BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    if (!BundlePermissionMgr::IsSystemApp() &&
        profileType != ProfileType::NETWORK_PROFILE &&
        profileType != ProfileType::PKG_CONTEXT_PROFILE) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->GetJsonProfile(profileType, bundleName, moduleName, profile, userId);
}

ErrCode BundleMgrHostImpl::SetAdditionalInfo(const std::string &bundleName, const std::string &additionalInfo)
{
    APP_LOGD("Called. BundleName: %{public}s", bundleName.c_str());
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("Non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }

    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("Verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }

    std::string appGalleryBundleName;
    QueryAppGalleryBundleName(appGalleryBundleName);

    std::string callingBundleName;
    ObtainCallingBundleName(callingBundleName);

    if (appGalleryBundleName.empty() || callingBundleName.empty() || appGalleryBundleName != callingBundleName) {
        APP_LOGE("Failed, appGalleryBundleName: %{public}s. callingBundleName: %{public}s",
            appGalleryBundleName.c_str(), callingBundleName.c_str());
        return ERR_BUNDLE_MANAGER_NOT_APP_GALLERY_CALL;
    }

    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->SetAdditionalInfo(bundleName, additionalInfo);
}

ErrCode BundleMgrHostImpl::CreateBundleDataDir(int32_t userId)
{
    if (!BundlePermissionMgr::IsCallingUidValid(Constants::ROOT_UID)) {
        APP_LOGE("IsCallingUidValid failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }

    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->CreateBundleDataDir(userId);
}

ErrCode BundleMgrHostImpl::CreateBundleDataDirWithEl(int32_t userId, DataDirEl dirEl)
{
    if (!BundlePermissionMgr::IsCallingUidValid(Constants::ROOT_UID)) {
        APP_LOGE("IsCallingUidValid failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }

    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->CreateBundleDataDirWithEl(userId, dirEl);
}

ErrCode BundleMgrHostImpl::UpdateAppEncryptedStatus(const std::string &bundleName, bool isExisted, int32_t appIndex)
{
    if (!BundlePermissionMgr::IsCallingUidValid(Constants::CODE_PROTECT_UID)) {
        APP_LOGE("IsCallingUidValid failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }

    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->UpdateAppEncryptedStatus(bundleName, isExisted, appIndex);
}

ErrCode BundleMgrHostImpl::MigrateData(const std::vector<std::string> &sourcePaths, const std::string &destinationPath)
{
    APP_LOGI("MigrateData start");
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("Non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }

    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_MIGRATE_DATA)) {
        APP_LOGE("Verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }

    std::vector<std::string> inspectionPassedSourcePaths = sourcePaths;
    std::string inspectionPassedDestPath = destinationPath;
    auto result = MigrateDataParameterCheck(inspectionPassedSourcePaths, inspectionPassedDestPath);
    if (result != ERR_OK) {
        APP_LOGE("migrate data parameter check err:%{public}d", result);
        return result;
    }

    result = MigrateDataUserAuthentication();
    if (result != ERR_OK) {
        APP_LOGE("migrate data user authentication err:%{public}d", result);
        return result;
    }

    auto installdClient = InstalldClient::GetInstance();
    if (installdClient == nullptr) {
        APP_LOGE("get install client err");
        return ERR_BUNDLE_MANAGER_MIGRATE_DATA_OTHER_REASON_FAILED;
    }

    result = installdClient->MigrateData(inspectionPassedSourcePaths, inspectionPassedDestPath);
    if (result != ERR_OK) {
        APP_LOGE("migrate data filesd, errcode:%{public}d", result);
    }
    APP_LOGI("MigrateData end");
    return result;
}

ErrCode BundleMgrHostImpl::MigrateDataParameterCheck(
    std::vector<std::string> &sourcePaths, std::string &destinationPath)
{
    if (sourcePaths.size() > VECTOR_SIZE_MAX) {
        APP_LOGE("source paths size out of range");
        return ERR_BUNDLE_MANAGER_MIGRATE_DATA_SOURCE_PATH_INVALID;
    }
    auto checkPath = [](const auto &path) { return path.find(ServiceConstants::RELATIVE_PATH) != std::string::npos; };
    if (sourcePaths.empty() || std::any_of(sourcePaths.begin(), sourcePaths.end(), checkPath)) {
        APP_LOGE("source paths check err");
        return ERR_BUNDLE_MANAGER_MIGRATE_DATA_SOURCE_PATH_INVALID;
    }
    if (destinationPath.empty() || checkPath(destinationPath)) {
        APP_LOGE("destinationPath err: %{private}s", destinationPath.c_str());
        return ERR_BUNDLE_MANAGER_MIGRATE_DATA_DESTINATION_PATH_INVALID;
    }
    return CheckSandboxPath(sourcePaths, destinationPath);
}

ErrCode BundleMgrHostImpl::CheckSandboxPath(std::vector<std::string> &sourcePaths, std::string &destinationPath)
{
    bool sourcePathCheck = std::any_of(
        sourcePaths.begin(), sourcePaths.end(), [](const auto &path) { return BundleUtil::IsSandBoxPath(path); });
    if (!sourcePathCheck && !BundleUtil::IsSandBoxPath(destinationPath)) {
        APP_LOGD("the current paths does not involve sandbox path");
        return ERR_OK;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_MIGRATE_DATA_OTHER_REASON_FAILED;
    }
    auto uid = IPCSkeleton::GetCallingUid();
    std::string bundleName;
    if (!dataMgr->GetBundleNameForUid(uid, bundleName)) {
        APP_LOGE("GetBundleNameForUid failed uid:%{public}d", uid);
        return ERR_BUNDLE_MANAGER_MIGRATE_DATA_OTHER_REASON_FAILED;
    }
    std::string realPath{ "" };
    for (size_t index = 0; index < sourcePaths.size(); ++index) {
        if (!BundleUtil::IsSandBoxPath(sourcePaths[index])) {
            continue;
        }
        if (BundleUtil::RevertToRealPath(sourcePaths[index], bundleName, realPath)) {
            APP_LOGD("convert source sandbox path[%{public}s] to read path[%{public}s]", sourcePaths[index].c_str(),
                realPath.c_str());
            sourcePaths[index] = realPath;
        }
    }
    if (BundleUtil::IsSandBoxPath(destinationPath)) {
        if (BundleUtil::RevertToRealPath(destinationPath, bundleName, realPath)) {
            APP_LOGD("convert destination sandbox path[%{public}s] to read path[%{public}s]", destinationPath.c_str(),
                realPath.c_str());
            destinationPath = realPath;
        } else {
            APP_LOGE("destination path[%{public}s] revert to real path invalid", destinationPath.c_str());
            return ERR_BUNDLE_MANAGER_MIGRATE_DATA_DESTINATION_PATH_INVALID;
        }
    }
    return ERR_OK;
}


ErrCode BundleMgrHostImpl::MigrateDataUserAuthentication()
{
#ifdef BMS_USER_AUTH_FRAMEWORK_ENABLED
    int32_t userId = AccountHelper::GetCurrentActiveUserId();
    if (userId == Constants::INVALID_USERID) {
        APP_LOGE("userId %{public}d is invalid", userId);
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }
    std::vector<UserIam::UserAuth::AuthType> authTypes{ UserIam::UserAuth::AuthType::PIN,
        UserIam::UserAuth::AuthType::FACE, UserIam::UserAuth::AuthType::FINGERPRINT };
    u_int8_t keyLength{ 32 };
    u_int8_t keyMinValue{ 0 };
    u_int8_t keyMaxValue{ 9 };

    UserIam::UserAuth::WidgetAuthParam authParam;
    authParam.userId = userId;
    authParam.challenge = BundleUtil::GenerateRandomNumbers(keyLength, keyMinValue, keyMaxValue);
    authParam.authTypes = authTypes;
    authParam.authTrustLevel = UserIam::UserAuth::AuthTrustLevel::ATL3;

    UserIam::UserAuth::WidgetParam widgetInfo;
    widgetInfo.title = AUTH_TITLE;
    widgetInfo.windowMode = UserIam::UserAuth::WindowModeType::UNKNOWN_WINDOW_MODE;

    std::shared_ptr<MigrateDataUserAuthCallback> userAuthaCallback = std::make_shared<MigrateDataUserAuthCallback>();
    if (userAuthaCallback == nullptr) {
        APP_LOGE("make shared err!");
        return ERR_BUNDLE_MANAGER_MIGRATE_DATA_USER_AUTHENTICATION_FAILED;
    }
    auto contextId =
        UserIam::UserAuth::UserAuthClientImpl::GetInstance().BeginWidgetAuth(authParam, widgetInfo, userAuthaCallback);
    if (contextId == BAD_CONTEXT_ID) {
        APP_LOGE("begin user auth err!");
        return ERR_BUNDLE_MANAGER_MIGRATE_DATA_USER_AUTHENTICATION_FAILED;
    }
    auto result = userAuthaCallback->GetUserAuthResult();
    if (result != ERR_OK) {
        APP_LOGE("user auth err:%{public}d", result);
        if (result == ERR_BUNDLE_MANAGER_MIGRATE_DATA_USER_AUTHENTICATION_TIME_OUT) {
            UserIam::UserAuth::UserAuthClientImpl::GetInstance().CancelAuthentication(contextId);
            return result;
        }
        return ERR_BUNDLE_MANAGER_MIGRATE_DATA_USER_AUTHENTICATION_FAILED;
    }
    return ERR_OK;
#else
    APP_LOGE("user auth framework is not enabled");
    return ERR_BUNDLE_MANAGER_MIGRATE_DATA_USER_AUTHENTICATION_FAILED;
#endif
}

sptr<IBundleResource> BundleMgrHostImpl::GetBundleResourceProxy()
{
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
    int32_t timerId = XCollieHelper::SetRecoveryTimer(FUNCTION_GET_BUNDLE_RESOURCE_PROXY);
    ScopeGuard cancelTimerIdGuard([timerId] { XCollieHelper::CancelTimer(timerId); });
    return DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleResourceProxy();
#else
    return nullptr;
#endif
}

bool BundleMgrHostImpl::GetPreferableBundleInfoFromHapPaths(const std::vector<std::string> &hapPaths,
    BundleInfo &bundleInfo)
{
    if (hapPaths.empty()) {
        return false;
    }
    for (auto hapPath: hapPaths) {
        BundleInfo resultBundleInfo;
        if (!GetBundleArchiveInfo(hapPath, GET_BUNDLE_DEFAULT, resultBundleInfo)) {
            return false;
        }
        bundleInfo = resultBundleInfo;
        if (!bundleInfo.hapModuleInfos.empty()) {
            bundleInfo.hapModuleInfos[0].hapPath = hapPath;
            if (bundleInfo.hapModuleInfos[0].moduleType == ModuleType::ENTRY) {
                return true;
            }
        }
    }
    return true;
}

ErrCode BundleMgrHostImpl::GetRecoverableApplicationInfo(
    std::vector<RecoverableApplicationInfo> &recoverableApplicaitons)
{
    APP_LOGD("begin to GetRecoverableApplicationInfo");
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    int32_t userId = AccountHelper::GetCurrentActiveUserId();
    if (userId == Constants::INVALID_USERID) {
        APP_LOGE("userId %{public}d is invalid", userId);
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }
    BmsExtensionDataMgr bmsExtensionDataMgr;
    std::vector<PreInstallBundleInfo> recoverableBundleInfos = dataMgr->GetRecoverablePreInstallBundleInfos();
    for (auto recoverableBundleInfo: recoverableBundleInfos) {
        std::string bundleName = recoverableBundleInfo.GetBundleName();
        if (bmsExtensionDataMgr.IsAppInBlocklist(bundleName, userId)) {
            APP_LOGI("recover app %{public}s is in blocklist", bundleName.c_str());
            continue;
        }
        RecoverableApplicationInfo recoverableApplication;
        recoverableApplication.bundleName = bundleName;
        recoverableApplication.labelId = recoverableBundleInfo.GetLabelId();
        recoverableApplication.iconId = recoverableBundleInfo.GetIconId();
        recoverableApplication.systemApp = recoverableBundleInfo.GetSystemApp();
        recoverableApplication.codePaths = recoverableBundleInfo.GetBundlePaths();
        recoverableApplication.moduleName = recoverableBundleInfo.GetModuleName();
        recoverableApplication.bundleType = recoverableBundleInfo.GetBundleType();
        recoverableApplicaitons.emplace_back(recoverableApplication);
    }
    return ERR_OK;
}

ErrCode BundleMgrHostImpl::GetUninstalledBundleInfo(const std::string bundleName, BundleInfo &bundleInfo)
{
    APP_LOGD("begin to GetUninstalledBundleInfo");
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    int32_t userId = AccountHelper::GetCurrentActiveUserId();
    if (userId == Constants::INVALID_USERID) {
        APP_LOGE("userId %{public}d is invalid", userId);
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }
    if (dataMgr->HasUserInstallInBundle(bundleName, Constants::DEFAULT_USERID) ||
        dataMgr->HasUserInstallInBundle(bundleName, userId)) {
        APP_LOGE("bundle has installed");
        return ERR_APPEXECFWK_FAILED_GET_BUNDLE_INFO;
    }
    PreInstallBundleInfo preInstallBundleInfo;
    if (!dataMgr->GetPreInstallBundleInfo(bundleName, preInstallBundleInfo)) {
        APP_LOGE("get preinstallBundleInfo failed");
        return ERR_APPEXECFWK_FAILED_GET_BUNDLE_INFO;
    }
    if (!GetPreferableBundleInfoFromHapPaths(
        preInstallBundleInfo.GetBundlePaths(), bundleInfo)) {
        APP_LOGE("prefect bundle is not found");
        return ERR_APPEXECFWK_FAILED_GET_BUNDLE_INFO;
    }
    return ERR_OK;
}

bool BundleMgrHostImpl::IsBundleExist(const std::string &bundleName)
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is nullptr");
        return false;
    }
    return dataMgr->IsBundleExist(bundleName);
}

ErrCode BundleMgrHostImpl::ClearCache(const std::string &bundleName,
    const sptr<ICleanCacheCallback> cleanCacheCallback, int32_t userId)
{
    auto bmsExtensionClient = std::make_shared<BmsExtensionClient>();
    ErrCode ret = bmsExtensionClient->ClearCache(bundleName, cleanCacheCallback->AsObject(), userId);
    APP_LOGI("ret : %{public}d", ret);
    if (ret != ERR_OK) {
        ret = ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    EventReport::SendCleanCacheSysEvent(bundleName, userId, true, ret != ERR_OK);
    return ret;
}

ErrCode BundleMgrHostImpl::CanOpenLink(
    const std::string &link, bool &canOpen)
{
    APP_LOGD("start CanOpenLink, link : %{public}s", link.c_str());
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->CanOpenLink(link, canOpen);
}

ErrCode BundleMgrHostImpl::GetOdid(std::string &odid)
{
    APP_LOGD("start GetOdid");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->GetOdid(odid);
}

ErrCode BundleMgrHostImpl::GetAllPreinstalledApplicationInfos(
    std::vector<PreinstalledApplicationInfo> &preinstalledApplicationInfos)
{
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("Non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("Verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    std::vector<PreInstallBundleInfo> preInstallBundleInfos = dataMgr->GetAllPreInstallBundleInfos();
    for (auto &preInstallBundleInfo: preInstallBundleInfos) {
        PreinstalledApplicationInfo preinstalledApplicationInfo;
        preinstalledApplicationInfo.bundleName = preInstallBundleInfo.GetBundleName();
        preinstalledApplicationInfo.moduleName = preInstallBundleInfo.GetModuleName();
        preinstalledApplicationInfo.labelId = preInstallBundleInfo.GetLabelId();
        preinstalledApplicationInfo.iconId = preInstallBundleInfo.GetIconId();
        preinstalledApplicationInfos.emplace_back(preinstalledApplicationInfo);
    }
    return ERR_OK;
}

ErrCode BundleMgrHostImpl::GetAllBundleInfoByDeveloperId(const std::string &developerId,
    std::vector<BundleInfo> &bundleInfos, int32_t userId)
{
    APP_LOGI("start GetAllBundleInfoByDeveloperId for developerId: %{public}s with user: %{public}d",
        developerId.c_str(), userId);
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    APP_LOGI("verify permission success, begin to GetAllBundleInfoByDeveloperId");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->GetAllBundleInfoByDeveloperId(developerId, bundleInfos, userId);
}

ErrCode BundleMgrHostImpl::GetDeveloperIds(const std::string &appDistributionType,
    std::vector<std::string> &developerIdList, int32_t userId)
{
    APP_LOGI("start GetDeveloperIds for appDistributionType: %{public}s with user: %{public}d",
        appDistributionType.c_str(), userId);
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    APP_LOGI("verify permission success, begin to GetDeveloperIds");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->GetDeveloperIds(appDistributionType, developerIdList, userId);
}

ErrCode BundleMgrHostImpl::SwitchUninstallState(const std::string &bundleName, const bool &state,
    bool isNeedSendNotify)
{
    APP_LOGD("start SwitchUninstallState, bundleName : %{public}s, state : %{public}d", bundleName.c_str(), state);
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(
        ServiceConstants::PERMISSION_CHANGE_BUNDLE_UNINSTALL_STATE)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    APP_LOGD("verify permission success, begin to SwitchUninstallState");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    bool stateChange = false;
    auto resCode = dataMgr->SwitchUninstallState(bundleName, state, isNeedSendNotify, stateChange);
    if (resCode != ERR_OK) {
        APP_LOGE("set status fail");
        return resCode;
    }
    if (!isNeedSendNotify || !stateChange) {
        APP_LOGI("no need notify %{public}s %{public}d %{public}d",
            bundleName.c_str(), isNeedSendNotify, stateChange);
        return resCode;
    }
    InnerBundleInfo innerBundleInfo;
    bool isSuccess = dataMgr->FetchInnerBundleInfo(bundleName, innerBundleInfo);
    if (!isSuccess) {
        APP_LOGE("get innerBundleInfo fail");
        return resCode;
    }
    AbilityInfo mainAbilityInfo;
    int32_t currentActiveUserId = AccountHelper::GetCurrentActiveUserId();
    innerBundleInfo.GetMainAbilityInfo(mainAbilityInfo);
    NotifyBundleEvents installRes = {
        .isModuleUpdate = false,
        .type = NotifyType::UNINSTALL_STATE,
        .resultCode = ERR_OK,
        .accessTokenId = innerBundleInfo.GetAccessTokenId(currentActiveUserId),
        .uid = innerBundleInfo.GetUid(currentActiveUserId),
        .bundleType = static_cast<int32_t>(innerBundleInfo.GetApplicationBundleType()),
        .bundleName = innerBundleInfo.GetBundleName(),
        .modulePackage = innerBundleInfo.GetModuleNameVec()[0],
        .abilityName = mainAbilityInfo.name,
        .appDistributionType = innerBundleInfo.GetAppDistributionType(),
    };
    std::shared_ptr<BundleCommonEventMgr> commonEventMgr = std::make_shared<BundleCommonEventMgr>();
    commonEventMgr->NotifyBundleStatus(installRes, dataMgr);
    return resCode;
}

void BundleMgrHostImpl::SetProvisionInfoToInnerBundleInfo(const std::string &hapPath, InnerBundleInfo &info)
{
    Security::Verify::HapVerifyResult hapVerifyResult;
    ErrCode verifyRes = BundleVerifyMgr::HapVerify(hapPath, hapVerifyResult);
    if (verifyRes != ERR_OK) {
        return;
    }
    Security::Verify::ProvisionInfo provisionInfo = hapVerifyResult.GetProvisionInfo();
    bool isSystemApp = provisionInfo.bundleInfo.appFeature == ServiceConstants::HOS_SYSTEM_APP;
    info.SetAppType(isSystemApp ? Constants::AppType::SYSTEM_APP : Constants::AppType::THIRD_PARTY_APP);
    info.SetProvisionId(provisionInfo.appId);
    info.SetCertificateFingerprint(provisionInfo.fingerprint);
    info.SetAppIdentifier(provisionInfo.bundleInfo.appIdentifier);
    if (provisionInfo.type == Security::Verify::ProvisionType::DEBUG) {
        info.SetCertificate(provisionInfo.bundleInfo.developmentCertificate);
    } else {
        info.SetCertificate(provisionInfo.bundleInfo.distributionCertificate);
    }
    info.SetAppPrivilegeLevel(provisionInfo.bundleInfo.apl);
    bool isDebug = provisionInfo.type == Security::Verify::ProvisionType::DEBUG;
    info.SetAppProvisionType(isDebug ? Constants::APP_PROVISION_TYPE_DEBUG : Constants::APP_PROVISION_TYPE_RELEASE);
    std::string distributionType;
    auto typeIter = APP_DISTRIBUTION_TYPE_MAPS.find(provisionInfo.distributionType);
    if (typeIter == APP_DISTRIBUTION_TYPE_MAPS.end()) {
        distributionType = Constants::APP_DISTRIBUTION_TYPE_NONE;
    } else {
        distributionType = typeIter->second;
    }
    info.SetAppDistributionType(distributionType);
}

ErrCode BundleMgrHostImpl::QueryAbilityInfoByContinueType(const std::string &bundleName,
    const std::string &continueType, AbilityInfo &abilityInfo, int32_t userId)
{
    APP_LOGD("QueryAbilityInfoByContinueType, bundleName : %{public}s, continueType : %{public}s, userId: %{public}d",
        bundleName.c_str(), continueType.c_str(), userId);
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        EventReport::SendQueryAbilityInfoByContinueTypeSysEvent(bundleName, EMPTY_ABILITY_NAME,
            ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED, userId, continueType);
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED}) &&
        !BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
        APP_LOGE("verify permission failed");
        EventReport::SendQueryAbilityInfoByContinueTypeSysEvent(bundleName, EMPTY_ABILITY_NAME,
            ERR_BUNDLE_MANAGER_PERMISSION_DENIED, userId, continueType);
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    APP_LOGD("verify permission success, begin to QueryAbilityInfoByContinueType");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        EventReport::SendQueryAbilityInfoByContinueTypeSysEvent(bundleName, EMPTY_ABILITY_NAME,
            ERR_BUNDLE_MANAGER_INTERNAL_ERROR, userId, continueType);
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    ErrCode res = dataMgr->QueryAbilityInfoByContinueType(bundleName, continueType, abilityInfo, userId);
    std::string abilityName;
    if (res == ERR_OK) {
        abilityName = abilityInfo.name;
    }
    EventReport::SendQueryAbilityInfoByContinueTypeSysEvent(bundleName, abilityName, res, userId, continueType);
    return res;
}

ErrCode BundleMgrHostImpl::QueryCloneAbilityInfo(const ElementName &element,
    int32_t flags, int32_t appIndex, AbilityInfo &abilityInfo, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = element.GetBundleName();
    std::string abilityName = element.GetAbilityName();
    LOG_D(BMS_TAG_QUERY,
        "flags : %{public}d, userId : %{public}d, bundleName: %{public}s, abilityName: %{public}s",
        flags, userId, bundleName.c_str(), abilityName.c_str());

    if (bundleName.empty() || abilityName.empty()) {
        LOG_E(BMS_TAG_QUERY, "invalid params");
        return ERR_APPEXECFWK_CLONE_QUERY_PARAM_ERROR;
    }
    if (!BundlePermissionMgr::IsSystemApp()) {
        LOG_E(BMS_TAG_QUERY, "non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED})
        && !BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
        LOG_E(BMS_TAG_QUERY, "verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_QUERY, "DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    auto res = dataMgr->QueryCloneAbilityInfo(element, flags, userId, appIndex, abilityInfo);
    if (res != ERR_OK) {
        LOG_E(BMS_TAG_QUERY, "QueryCloneAbilityInfo fail, err: %{public}d", res);
        return res;
    }
    return ERR_OK;
}

ErrCode BundleMgrHostImpl::GetCloneBundleInfo(const std::string &bundleName, int32_t flags,
    int32_t appIndex, BundleInfo &bundleInfo, int32_t userId)
{
    int32_t timerId = XCollieHelper::SetRecoveryTimer(FUNCTION_GET_CLONE_BUNDLE_INFO);
    ScopeGuard cancelTimerIdGuard([timerId] { XCollieHelper::CancelTimer(timerId); });
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)
        && !BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    APP_LOGD("verify permission success, begin to GetCloneBundleInfo");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    auto res = dataMgr->GetCloneBundleInfo(bundleName, flags, appIndex, bundleInfo, userId);
    if (res != ERR_OK) {
        APP_LOGE_NOFUNC("GetCloneBundleInfo fail -n %{public}s -u %{public}d -i %{public}d -f %{public}d"
            " err:%{public}d", bundleName.c_str(), userId, appIndex, flags, res);
        return res;
    }
    return ERR_OK;
}

ErrCode BundleMgrHostImpl::GetCloneAppIndexes(const std::string &bundleName, std::vector<int32_t> &appIndexes,
    int32_t userId)
{
    APP_LOGD("start GetCloneAppIndexes bundleName = %{public}s, userId = %{public}d", bundleName.c_str(), userId);
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)
        && !BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
        APP_LOGE("verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    APP_LOGD("verify permission success, begin to GetCloneAppIndexes");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    appIndexes = dataMgr->GetCloneAppIndexes(bundleName, userId);
    return ERR_OK;
}

ErrCode BundleMgrHostImpl::GetLaunchWant(Want &want)
{
    APP_LOGD("start GetLaunchWant");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_QUERY, "DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    auto uid = IPCSkeleton::GetCallingUid();
    std::string bundleName;
    auto ret = dataMgr->GetBundleNameForUid(uid, bundleName);
    if (!ret) {
        LOG_NOFUNC_E(BMS_TAG_QUERY, "GetBundleNameForUid failed uid:%{public}d", uid);
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    int32_t userId = AccountHelper::GetOsAccountLocalIdFromUid(uid);
    return dataMgr->GetLaunchWantForBundle(bundleName, want, userId);
}

ErrCode BundleMgrHostImpl::QueryCloneExtensionAbilityInfoWithAppIndex(const ElementName &element, int32_t flags,
    int32_t appIndex, ExtensionAbilityInfo &extensionAbilityInfo, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    LOG_D(BMS_TAG_QUERY, "QueryCloneExtensionAbilityInfoWithAppIndex without type begin");
    if (!BundlePermissionMgr::VerifyCallingPermissionsForAll({Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED})) {
        LOG_E(BMS_TAG_QUERY, "verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_QUERY, "DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    std::string bundleName = element.GetBundleName();
    std::string extensionName = element.GetAbilityName();
    if (bundleName.empty() || extensionName.empty()) {
        LOG_E(BMS_TAG_QUERY,
            "QueryCloneExtensionAbilityInfoWithAppIndex is failed, bundleName:%{public}s, extensionName:%{public}s",
            bundleName.c_str(), extensionName.c_str());
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }

    Want want;
    want.SetElement(element);
    ErrCode ret = dataMgr->ExplicitQueryExtensionInfoV9(want, flags, userId, extensionAbilityInfo, appIndex);
    if (ret != ERR_OK) {
        LOG_D(BMS_TAG_QUERY, "explicit queryExtensionInfo error");
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }
    return ERR_OK;
}

ErrCode BundleMgrHostImpl::GetSignatureInfoByBundleName(const std::string &bundleName, SignatureInfo &signatureInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    int32_t uid = OHOS::IPCSkeleton::GetCallingUid();
    if (uid != Constants::FOUNDATION_UID) {
        LOG_E(BMS_TAG_DEFAULT, "uid: %{public}d not foundation", uid);
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->GetSignatureInfoByBundleName(bundleName, signatureInfo);
}

ErrCode BundleMgrHostImpl::GetSignatureInfoByUid(const int32_t uid, SignatureInfo &signatureInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_SIGNATURE_INFO)) {
        LOG_E(BMS_TAG_QUERY, "verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->GetSignatureInfoByUid(uid, signatureInfo);
}

bool BundleMgrHostImpl::CheckCanSetEnable(const std::string &bundleName)
{
    std::vector<std::string> noDisablingList;
    std::string configPath = BundleUtil::GetNoDisablingConfigPath();
    ErrCode ret = BundleParser::ParseNoDisablingList(configPath, noDisablingList);
    if (ret != ERR_OK) {
        LOG_W(BMS_TAG_DEFAULT, "GetNoDisablingList failed");
        return true;
    }
    auto it = std::find(noDisablingList.begin(), noDisablingList.end(), bundleName);
    if (it == noDisablingList.end()) {
        return true;
    }
    return false;
}

ErrCode BundleMgrHostImpl::AddDesktopShortcutInfo(const ShortcutInfo &shortcutInfo, int32_t userId)
{
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("Non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_MANAGER_SHORTCUT)) {
        APP_LOGE("Verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->AddDesktopShortcutInfo(shortcutInfo, userId);
}

ErrCode BundleMgrHostImpl::DeleteDesktopShortcutInfo(const ShortcutInfo &shortcutInfo, int32_t userId)
{
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("Non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_MANAGER_SHORTCUT)) {
        APP_LOGE("Verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->DeleteDesktopShortcutInfo(shortcutInfo, userId);
}

ErrCode BundleMgrHostImpl::GetAllDesktopShortcutInfo(int32_t userId, std::vector<ShortcutInfo> &shortcutInfos)
{
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("Non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_MANAGER_SHORTCUT)) {
        APP_LOGE("Verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->GetAllDesktopShortcutInfo(userId, shortcutInfos);
}

bool BundleMgrHostImpl::IsAppLinking(int32_t flags) const
{
    if ((static_cast<uint32_t>(flags) &
        static_cast<uint32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_APP_LINKING)) ==
        static_cast<uint32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_APP_LINKING)) {
        APP_LOGI("contains app linking flag, no need to query from bms extension");
        return true;
    }
    return false;
}

ErrCode BundleMgrHostImpl::GetOdidByBundleName(const std::string &bundleName, std::string &odid)
{
    APP_LOGD("start GetOdidByBundleName");
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("Verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->GetOdidByBundleName(bundleName, odid);
}

bool BundleMgrHostImpl::GetBundleInfosForContinuation(int32_t flags, std::vector<BundleInfo> &bundleInfos,
    int32_t userId)
{
    GetBundleInfos(flags, bundleInfos, userId);
    auto dataMgr = GetDataMgrFromService();
    dataMgr->GetBundleInfosForContinuation(bundleInfos);
    return !bundleInfos.empty();
}

ErrCode BundleMgrHostImpl::GetContinueBundleNames(
    const std::string &continueBundleName, std::vector<std::string> &bundleNames, int32_t userId)
{
    if (continueBundleName.empty()) {
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }

    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("Verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }

    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->GetContinueBundleNames(continueBundleName, bundleNames, userId);
}

ErrCode BundleMgrHostImpl::IsBundleInstalled(const std::string &bundleName, int32_t userId,
    int32_t appIndex, bool &isInstalled)
{
    APP_LOGD("IsBundleInstalled -n %{public}s -u %{public}d -i %{public}d", bundleName.c_str(), userId, appIndex);
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("Non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("Verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }

    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->IsBundleInstalled(bundleName, userId, appIndex, isInstalled);
}

ErrCode BundleMgrHostImpl::GetCompatibleDeviceTypeNative(std::string &deviceType)
{
    APP_LOGD("start GetCompatibleDeviceTypeNative");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    std::string bundleName;
    dataMgr->GetBundleNameForUid(IPCSkeleton::GetCallingUid(), bundleName);
    BmsExtensionDataMgr bmsExtensionDataMgr;
    deviceType = bmsExtensionDataMgr.GetCompatibleDeviceType(bundleName);
    APP_LOGI("deviceType : %{public}s", deviceType.c_str());
    return ERR_OK;
}

ErrCode BundleMgrHostImpl::GetCompatibleDeviceType(const std::string &bundleName, std::string &deviceType)
{
    APP_LOGD("start GetCompatibleDeviceType");
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("Verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }

    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    BmsExtensionDataMgr bmsExtensionDataMgr;
    deviceType = bmsExtensionDataMgr.GetCompatibleDeviceType(bundleName);
    APP_LOGI("deviceType : %{public}s", deviceType.c_str());
    return ERR_OK;
}

ErrCode BundleMgrHostImpl::GetBundleNameByAppId(const std::string &appId, std::string &bundleName)
{
    APP_LOGD("start GetBundleNameByAppId");
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("Verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    auto ret = dataMgr->GetBundleNameByAppId(appId, bundleName);
    if (ret != ERR_OK) {
        APP_LOGW("get bundleName by appId %{private}s failed %{public}d", appId.c_str(), ret);
        return ret;
    }
    APP_LOGI("appId: %{private}s bundleName : %{public}s", appId.c_str(), bundleName.c_str());
    return ERR_OK;
}

std::string BundleMgrHostImpl::GetCallerName()
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return Constants::EMPTY_STRING;
    }
    std::string callerName;
    int32_t uid = IPCSkeleton::GetCallingUid();
    auto ret = dataMgr->GetNameForUid(uid, callerName);
    if (ret != ERR_OK) {
        callerName = std::to_string(uid);
    }
    return callerName;
}

ErrCode GetDirForApp(const std::string &bundleName, const int32_t appIndex, std::string &dataDir)
{
    APP_LOGD("start GetDirForApp");
    if (appIndex < 0) {
        return ERR_BUNDLE_MANAGER_GET_DIR_INVALID_APP_INDEX;
    } else if (appIndex == 0) {
        dataDir = bundleName;
    } else {
        dataDir = CLONE_APP_DIR_PREFIX + std::to_string(appIndex) + PLUS + bundleName;
    }
    return ERR_OK;
}

ErrCode BundleMgrHostImpl::GetDirByBundleNameAndAppIndex(const std::string &bundleName, const int32_t appIndex,
    std::string &dataDir)
{
    APP_LOGD("start GetDirByBundleNameAndAppIndex");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }

    BundleType type;
    dataMgr->GetBundleType(bundleName, type);
    if (type != BundleType::ATOMIC_SERVICE) {
        return GetDirForApp(bundleName, appIndex, dataDir);
    }

    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)
        && !BundlePermissionMgr::IsBundleSelfCalling(bundleName)) {
        APP_LOGE("Verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    return dataMgr->GetDirByBundleNameAndAppIndex(bundleName, appIndex, dataDir);
}

ErrCode BundleMgrHostImpl::GetAllBundleDirs(int32_t userId, std::vector<BundleDir> &bundleDirs)
{
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        APP_LOGE("Verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataMgr->GetAllBundleDirs(userId, bundleDirs);
}

ErrCode BundleMgrHostImpl::SetAppDistributionTypes(std::set<AppDistributionTypeEnum> &appDistributionTypeEnums)
{
    if (!BundlePermissionMgr::IsSystemApp()) {
        APP_LOGE("non-system app calling system api");
        return ERR_BUNDLE_MANAGER_SYSTEM_API_DENIED;
    }
    if (!BundlePermissionMgr::VerifyCallingPermissionForAll(ServiceConstants::PERMISSION_MANAGE_EDM_POLICY)) {
        APP_LOGE("Verify permission failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    std::string value = "";
    for (auto it = appDistributionTypeEnums.begin(); it != appDistributionTypeEnums.end(); ++it) {
        if (it == appDistributionTypeEnums.begin()) {
            value += std::to_string(static_cast<int>(*it));
        } else {
            value += Constants::SUPPORT_APP_TYPES_SEPARATOR + std::to_string(static_cast<int>(*it));
        }
    }
    auto bmsPara = DelayedSingleton<BundleMgrService>::GetInstance()->GetBmsParam();
    if (bmsPara == nullptr) {
        APP_LOGE("bmsPara is nullptr");
        return ERR_APPEXECFWK_NULL_PTR;
    }
    if (!bmsPara->SaveBmsParam(Constants::APP_DISTRIBUTION_TYPE_WHITE_LIST, value)) {
        APP_LOGE("SaveBmsParam failed");
        return ERR_BMS_PARAM_SET_PARAM_ERROR;
    }
    APP_LOGI("save bms param success %{public}s", value.c_str());
    return ERR_OK;
}

void BundleMgrHostImpl::CallAbilityManager(
    int32_t resultCode, const Want &want, int32_t userId, const sptr<IRemoteObject> &callBack)
{
    if (callBack == nullptr) {
        APP_LOGI("callBack is nullptr");
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    if (!data.WriteInterfaceToken(ATOMIC_SERVICE_STATUS_CALLBACK_TOKEN)) {
        APP_LOGE("Write interface token failed");
        return;
    }
    if (!data.WriteInt32(resultCode)) {
        APP_LOGE("Write result code failed");
        return;
    }
    if (!data.WriteParcelable(&want)) {
        APP_LOGE("Write want failed");
        return;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("Write userId failed");
        return;
    }

    if (callBack->SendRequest(ERR_OK, data, reply, option) != ERR_OK) {
        APP_LOGE("SendRequest failed");
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
