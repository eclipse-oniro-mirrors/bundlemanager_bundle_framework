/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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
#include "bundle_mgr.h"

#include <string>
#include <unordered_map>

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_constants.h"
#include "bundle_errors.h"
#include "bundle_mgr_client.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "business_error.h"
#include "cleancache_callback.h"
#include "common_func.h"
#include "if_system_ability_manager.h"
#include "installer_callback.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "napi_arg.h"
#include "napi_constants.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#ifdef BUNDLE_FRAMEWORK_GRAPHICS
#include "bundle_graphics_client.h"
#include "pixel_map_napi.h"
#endif
#include "securec.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AppExecFwk {
using namespace OHOS;
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AbilityRuntime;

namespace {
constexpr size_t NAPI_ERR_NO_ERROR = 0;
constexpr size_t ARGS_ASYNC_COUNT = 1;
constexpr size_t ARGS_MAX_COUNT = 10;
constexpr size_t CALLBACK_SIZE = 1;
constexpr int32_t PARAM0 = 0;
constexpr int32_t PARAM1 = 1;
constexpr int32_t PARAM2 = 2;
constexpr int32_t PARAM3 = 3;
constexpr int32_t NAPI_RETURN_FAILED = -1;
constexpr int32_t NAPI_RETURN_ZERO = 0;
constexpr int32_t NAPI_RETURN_TWO = 2;
constexpr int32_t NAPI_RETURN_THREE = 3;
constexpr int32_t CODE_SUCCESS = 0;
constexpr int32_t CODE_FAILED = -1;
constexpr int32_t OPERATION_FAILED = 1;
constexpr int32_t INVALID_PARAM = 2;
constexpr int32_t PARAM_TYPE_ERROR = 1;
constexpr int32_t UNDEFINED_ERROR = -1;
#ifndef BUNDLE_FRAMEWORK_GRAPHICS
constexpr int32_t UNSUPPORTED_FEATURE_ERRCODE = 801;
const char* UNSUPPORTED_FEATURE_MESSAGE = "unsupported BundleManagerService feature";
#endif
enum class InstallErrorCode : uint8_t {
    SUCCESS = 0,
    STATUS_INSTALL_FAILURE = 1,
    STATUS_INSTALL_FAILURE_ABORTED = 2,
    STATUS_INSTALL_FAILURE_INVALID = 3,
    STATUS_INSTALL_FAILURE_CONFLICT = 4,
    STATUS_INSTALL_FAILURE_STORAGE = 5,
    STATUS_INSTALL_FAILURE_INCOMPATIBLE = 6,
    STATUS_UNINSTALL_FAILURE = 7,
    STATUS_UNINSTALL_FAILURE_BLOCKED = 8,
    STATUS_UNINSTALL_FAILURE_ABORTED = 9,
    STATUS_UNINSTALL_FAILURE_CONFLICT = 10,
    STATUS_INSTALL_FAILURE_DOWNLOAD_TIMEOUT = 0x0B,
    STATUS_INSTALL_FAILURE_DOWNLOAD_FAILED = 0x0C,
    STATUS_RECOVER_FAILURE_INVALID = 0x0D,
    STATUS_ABILITY_NOT_FOUND = 0x40,
    STATUS_BMS_SERVICE_ERROR = 0x41,
    STATUS_FAILED_NO_SPACE_LEFT = 0X42,
    STATUS_GRANT_REQUEST_PERMISSIONS_FAILED = 0X43,
    STATUS_INSTALL_PERMISSION_DENIED = 0X44,
    STATUS_UNINSTALL_PERMISSION_DENIED = 0X45,
    STATUS_USER_NOT_EXIST = 0X50,
    STATUS_USER_FAILURE_INVALID = 0X51,
    STATUS_USER_CREATE_FAILED = 0X52,
    STATUS_USER_REMOVE_FAILED = 0X53,
};

const char* IS_SET_APPLICATION_ENABLED = "IsSetApplicationEnabled";
const char* IS_ABILITY_ENABLED = "IsAbilityEnabled";
const char* GET_LAUNCH_WANT_FOR_BUNDLE = "GetLaunchWantForBundle";
const char* GET_BUNDLE_ARCHIVE_INFO = "GetBundleArchiveInfo";
const char* GET_ABILITY_ICON = "GetAbilityIcon";
constexpr const char* NAPI_GET_APPLICATION_INFO = "GetApplicationInfo";
const char* GET_BUNDLE_INFO = "getBundleInfo";
const char* GET_ALL_BUNDLE_INFO = "GetAllBundleInfo";
const char* GET_PERMISSION_DEF = "GetPermissionDef";
const char* QUERY_ABILITY_BY_WANT = "queryAbilityByWant";
const char* TYPE_MISMATCH = "type misMatch";

const std::vector<int32_t> PACKINFO_FLAGS = {
    BundlePackFlag::GET_PACK_INFO_ALL,
    BundlePackFlag::GET_PACKAGES,
    BundlePackFlag::GET_BUNDLE_SUMMARY,
    BundlePackFlag::GET_MODULE_SUMMARY,
};

thread_local std::mutex g_permissionsCallbackMutex;
thread_local std::mutex g_anyPermissionsCallbackMutex;

struct PermissionsKey {
    napi_ref callback = 0;
    std::vector<int32_t> uids;
    bool operator<(const PermissionsKey &other) const
    {
        return this->callback < other.callback;
    }
};

static OHOS::sptr<OHOS::AppExecFwk::IBundleMgr> bundleMgr_ = nullptr;
static std::unordered_map<Query, napi_ref, QueryHash> cache;
static std::unordered_map<Query, napi_ref, QueryHash> abilityInfoCache;
static std::mutex abilityInfoCacheMutex_;
static std::mutex bundleMgrMutex_;
static sptr<BundleMgrDeathRecipient> bundleMgrDeathRecipient(new (std::nothrow) BundleMgrDeathRecipient());
}  // namespace

void BundleMgrDeathRecipient::OnRemoteDied([[maybe_unused]] const wptr<IRemoteObject>& remote)
{
    APP_LOGD("BundleManagerService dead");
    std::lock_guard<std::mutex> lock(bundleMgrMutex_);
    bundleMgr_ = nullptr;
};

AsyncWorkData::AsyncWorkData(napi_env napiEnv) : env(napiEnv) {}

AsyncWorkData::~AsyncWorkData()
{
    if (callback) {
        APP_LOGD("AsyncWorkData::~AsyncWorkData delete callback");
        napi_delete_reference(env, callback);
        callback = nullptr;
    }
    if (asyncWork) {
        APP_LOGD("AsyncWorkData::~AsyncWorkData delete asyncWork");
        napi_delete_async_work(env, asyncWork);
        asyncWork = nullptr;
    }
}
napi_ref thread_local g_classBundleInstaller;

static OHOS::sptr<OHOS::AppExecFwk::IBundleMgr> GetBundleMgr()
{
    if (bundleMgr_ == nullptr) {
        std::lock_guard<std::mutex> lock(bundleMgrMutex_);
        if (bundleMgr_ == nullptr) {
            auto systemAbilityManager = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
            if (systemAbilityManager == nullptr) {
                APP_LOGE("GetBundleMgr GetSystemAbilityManager is null");
                return nullptr;
            }
            auto bundleMgrSa = systemAbilityManager->GetSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
            if (bundleMgrSa == nullptr) {
                APP_LOGE("GetBundleMgr GetSystemAbility is null");
                return nullptr;
            }
            auto bundleMgr = OHOS::iface_cast<IBundleMgr>(bundleMgrSa);
            if (bundleMgr == nullptr) {
                APP_LOGE("GetBundleMgr iface_cast get null");
            }
            bundleMgr_ = bundleMgr;
            bundleMgr_->AsObject()->AddDeathRecipient(bundleMgrDeathRecipient);
        }
    }
    return bundleMgr_;
}

static void HandleAbilityInfoCache(
    napi_env env, const Query &query, const AsyncAbilityInfoCallbackInfo *info, napi_value jsObject)
{
    if (info == nullptr) {
        return;
    }
    ElementName element = info->want.GetElement();
    if (element.GetBundleName().empty() || element.GetAbilityName().empty()) {
        return;
    }
    uint32_t explicitQueryResultLen = 1;
    if (info->abilityInfos.size() != explicitQueryResultLen ||
        info->abilityInfos[0].uid != IPCSkeleton::GetCallingUid()) {
        return;
    }
    napi_ref cacheAbilityInfo = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_create_reference(env, jsObject, NAPI_RETURN_ONE, &cacheAbilityInfo));
    abilityInfoCache.clear();
    abilityInfoCache[query] = cacheAbilityInfo;
}

static bool CheckIsSystemApp()
{
    auto iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return false;
    }

    int32_t uid = IPCSkeleton::GetCallingUid();
    return iBundleMgr->CheckIsSystemAppByUid(uid);
}

static void ConvertCustomizeData(napi_env env, napi_value objCustomizeData, const CustomizeData &customizeData)
{
    napi_value nName;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, customizeData.name.c_str(), NAPI_AUTO_LENGTH, &nName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objCustomizeData, "name", nName));
    napi_value nValue;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, customizeData.value.c_str(), NAPI_AUTO_LENGTH, &nValue));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objCustomizeData, "value", nValue));
    napi_value nExtra;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, customizeData.extra.c_str(), NAPI_AUTO_LENGTH, &nExtra));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objCustomizeData, "extra", nExtra));
}

static void ConvertInnerMetadata(napi_env env, napi_value value, const Metadata &metadata)
{
    napi_value nName;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, metadata.name.c_str(), NAPI_AUTO_LENGTH, &nName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "name", nName));
    napi_value nValue;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, metadata.value.c_str(), NAPI_AUTO_LENGTH, &nValue));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "value", nValue));
    napi_value nResource;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, metadata.resource.c_str(), NAPI_AUTO_LENGTH, &nResource));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "resource", nResource));
}

static void ConvertResource(napi_env env, napi_value objResource, const Resource &resource)
{
    napi_value nBundleName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, resource.bundleName.c_str(), NAPI_AUTO_LENGTH, &nBundleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objResource, "bundleName", nBundleName));

    napi_value nModuleName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, resource.moduleName.c_str(), NAPI_AUTO_LENGTH, &nModuleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objResource, "moduleName", nModuleName));

    napi_value nId;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, resource.id, &nId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objResource, "id", nId));
}

static void ConvertApplicationInfo(napi_env env, napi_value objAppInfo, const ApplicationInfo &appInfo)
{
    napi_value nName;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, appInfo.name.c_str(), NAPI_AUTO_LENGTH, &nName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "name", nName));

    napi_value nCodePath;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, appInfo.codePath.c_str(), NAPI_AUTO_LENGTH, &nCodePath));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "codePath", nCodePath));

    napi_value nAccessTokenId;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, appInfo.accessTokenId, &nAccessTokenId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "accessTokenId", nAccessTokenId));

    napi_value nDescription;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, appInfo.description.c_str(), NAPI_AUTO_LENGTH, &nDescription));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "description", nDescription));

    napi_value nDescriptionId;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, appInfo.descriptionId, &nDescriptionId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "descriptionId", nDescriptionId));

    napi_value nIconPath;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, appInfo.iconPath.c_str(), NAPI_AUTO_LENGTH, &nIconPath));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "icon", nIconPath));

    napi_value nIconId;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, appInfo.iconId, &nIconId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "iconId", nIconId));

    napi_value nLabel;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, appInfo.label.c_str(), NAPI_AUTO_LENGTH, &nLabel));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "label", nLabel));

    napi_value nLabelId;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, appInfo.labelId, &nLabelId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "labelId", nLabelId));

    napi_value nIsSystemApp;
    NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, appInfo.isSystemApp, &nIsSystemApp));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "systemApp", nIsSystemApp));

    napi_value nSupportedModes;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, appInfo.supportedModes, &nSupportedModes));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "supportedModes", nSupportedModes));

    napi_value nProcess;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, appInfo.process.c_str(), NAPI_AUTO_LENGTH, &nProcess));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "process", nProcess));

    napi_value nIconIndex;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, appInfo.iconId, &nIconIndex));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "iconIndex", nIconIndex));

    napi_value nLabelIndex;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, appInfo.labelId, &nLabelIndex));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "labelIndex", nLabelIndex));

    napi_value nEntryDir;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, appInfo.entryDir.c_str(), NAPI_AUTO_LENGTH, &nEntryDir));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "entryDir", nEntryDir));

    napi_value nPermissions;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nPermissions));
    for (size_t idx = 0; idx < appInfo.permissions.size(); idx++) {
        napi_value nPermission;
        NAPI_CALL_RETURN_VOID(
            env, napi_create_string_utf8(env, appInfo.permissions[idx].c_str(), NAPI_AUTO_LENGTH, &nPermission));
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nPermissions, idx, nPermission));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "permissions", nPermissions));

    napi_value nModuleSourceDirs;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nModuleSourceDirs));
    for (size_t idx = 0; idx < appInfo.moduleSourceDirs.size(); idx++) {
        napi_value nModuleSourceDir;
        NAPI_CALL_RETURN_VOID(env,
            napi_create_string_utf8(env, appInfo.moduleSourceDirs[idx].c_str(), NAPI_AUTO_LENGTH, &nModuleSourceDir));
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nModuleSourceDirs, idx, nModuleSourceDir));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "moduleSourceDirs", nModuleSourceDirs));

    napi_value nModuleInfos;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nModuleInfos));
    for (size_t idx = 0; idx < appInfo.moduleInfos.size(); idx++) {
        napi_value objModuleInfos;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &objModuleInfos));

        napi_value nModuleName;
        NAPI_CALL_RETURN_VOID(env,
            napi_create_string_utf8(env, appInfo.moduleInfos[idx].moduleName.c_str(), NAPI_AUTO_LENGTH, &nModuleName));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objModuleInfos, "moduleName", nModuleName));

        napi_value nModuleSourceDir;
        NAPI_CALL_RETURN_VOID(env,
            napi_create_string_utf8(
                env, appInfo.moduleInfos[idx].moduleSourceDir.c_str(), NAPI_AUTO_LENGTH, &nModuleSourceDir));
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objModuleInfos, "moduleSourceDir", nModuleSourceDir));

        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nModuleInfos, idx, objModuleInfos));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "moduleInfos", nModuleInfos));

    napi_value nMetaData;
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nMetaData));
    for (const auto &item : appInfo.metaData) {
        napi_value nCustomizeDataArray;
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nCustomizeDataArray));
        for (size_t j = 0; j < item.second.size(); j++) {
            napi_value nCustomizeData;
            NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nCustomizeData));
            ConvertCustomizeData(env, nCustomizeData, item.second[j]);
            NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nCustomizeDataArray, j, nCustomizeData));
        }
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, nMetaData, item.first.c_str(), nCustomizeDataArray));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "metaData", nMetaData));

    napi_value nMetadata;
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nMetadata));
    for (const auto &item : appInfo.metadata) {
        napi_value nInnerMetadata;
        size_t len = item.second.size();
        NAPI_CALL_RETURN_VOID(env, napi_create_array_with_length(env, len, &nInnerMetadata));
        for (size_t index = 0; index < len; ++index) {
            napi_value nMeta;
            NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nMeta));
            ConvertInnerMetadata(env, nMeta, item.second[index]);
            NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nInnerMetadata, index, nMeta));
        }
        NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, nMetadata, item.first.c_str(), nInnerMetadata));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "metadata", nMetadata));

    napi_value nEnabled;
    NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, appInfo.enabled, &nEnabled));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "enabled", nEnabled));

    napi_value nUid;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, appInfo.uid, &nUid));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "uid", nUid));

    napi_value nEntityType;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, appInfo.entityType.c_str(), NAPI_AUTO_LENGTH,
        &nEntityType));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "entityType", nEntityType));

    napi_value nRemovable;
    NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, appInfo.removable, &nRemovable));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "removable", nRemovable));

    napi_value nFingerprint;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, appInfo.fingerprint.c_str(), NAPI_AUTO_LENGTH,
        &nFingerprint));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "fingerprint", nFingerprint));

    napi_value nIconResource;
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nIconResource));
    ConvertResource(env, nIconResource, appInfo.iconResource);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "iconResource", nIconResource));

    napi_value nLabelResource;
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nLabelResource));
    ConvertResource(env, nLabelResource, appInfo.labelResource);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "labelResource", nLabelResource));

    napi_value nDescriptionResource;
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nDescriptionResource));
    ConvertResource(env, nDescriptionResource, appInfo.descriptionResource);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "descriptionResource", nDescriptionResource));

    napi_value nAppDistributionType;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, appInfo.appDistributionType.c_str(), NAPI_AUTO_LENGTH,
        &nAppDistributionType));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "appDistributionType", nAppDistributionType));

    napi_value nAppProvisionType;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, appInfo.appProvisionType.c_str(), NAPI_AUTO_LENGTH,
        &nAppProvisionType));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAppInfo, "appProvisionType", nAppProvisionType));
}

static void ConvertMetaData(napi_env env, napi_value objMetaData, const MetaData &metaData)
{
    for (size_t idx = 0; idx < metaData.customizeData.size(); idx++) {
        napi_value nCustomizeData;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nCustomizeData));
        ConvertCustomizeData(env, nCustomizeData, metaData.customizeData[idx]);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, objMetaData, idx, nCustomizeData));
    }
}

static void ConvertAbilityInfo(napi_env env, napi_value objAbilityInfo, const AbilityInfo &abilityInfo)
{
    napi_value nName;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, abilityInfo.name.c_str(), NAPI_AUTO_LENGTH, &nName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "name", nName));

    napi_value nLabel;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, abilityInfo.label.c_str(), NAPI_AUTO_LENGTH, &nLabel));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "label", nLabel));

    napi_value nDescription;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, abilityInfo.description.c_str(), NAPI_AUTO_LENGTH, &nDescription));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "description", nDescription));

    napi_value nIconPath;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, abilityInfo.iconPath.c_str(), NAPI_AUTO_LENGTH, &nIconPath));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "icon", nIconPath));

    napi_value nVisible;
    NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, abilityInfo.visible, &nVisible));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "isVisible", nVisible));

    napi_value nPermissions;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nPermissions));
    for (size_t idx = 0; idx < abilityInfo.permissions.size(); idx++) {
        napi_value nPermission;
        NAPI_CALL_RETURN_VOID(
            env, napi_create_string_utf8(env, abilityInfo.permissions[idx].c_str(), NAPI_AUTO_LENGTH, &nPermission));
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nPermissions, idx, nPermission));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "permissions", nPermissions));

    napi_value nDeviceCapabilities;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nDeviceCapabilities));
    for (size_t idx = 0; idx < abilityInfo.deviceCapabilities.size(); idx++) {
        napi_value nDeviceCapability;
        NAPI_CALL_RETURN_VOID(env,
            napi_create_string_utf8(
                env, abilityInfo.deviceCapabilities[idx].c_str(), NAPI_AUTO_LENGTH, &nDeviceCapability));
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nDeviceCapabilities, idx, nDeviceCapability));
    }
    NAPI_CALL_RETURN_VOID(
        env, napi_set_named_property(env, objAbilityInfo, "deviceCapabilities", nDeviceCapabilities));

    napi_value nDeviceTypes;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nDeviceTypes));
    for (size_t idx = 0; idx < abilityInfo.deviceTypes.size(); idx++) {
        napi_value nDeviceType;
        NAPI_CALL_RETURN_VOID(
            env, napi_create_string_utf8(env, abilityInfo.deviceTypes[idx].c_str(), NAPI_AUTO_LENGTH, &nDeviceType));
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nDeviceTypes, idx, nDeviceType));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "deviceTypes", nDeviceTypes));

    napi_value nProcess;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, abilityInfo.process.c_str(), NAPI_AUTO_LENGTH, &nProcess));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "process", nProcess));

    napi_value nUri;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, abilityInfo.uri.c_str(), NAPI_AUTO_LENGTH, &nUri));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "uri", nUri));

    napi_value nBundleName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, abilityInfo.bundleName.c_str(), NAPI_AUTO_LENGTH, &nBundleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "bundleName", nBundleName));

    napi_value nModuleName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, abilityInfo.moduleName.c_str(), NAPI_AUTO_LENGTH, &nModuleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "moduleName", nModuleName));

    napi_value nAppInfo;
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nAppInfo));
    ConvertApplicationInfo(env, nAppInfo, abilityInfo.applicationInfo);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "applicationInfo", nAppInfo));

    napi_value nType;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(abilityInfo.type), &nType));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "type", nType));

    napi_value nOrientation;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(abilityInfo.orientation), &nOrientation));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "orientation", nOrientation));

    napi_value nLaunchMode;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(abilityInfo.launchMode), &nLaunchMode));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "launchMode", nLaunchMode));

    napi_value nBackgroundModes;
    if (!abilityInfo.isModuleJson) {
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, abilityInfo.backgroundModes, &nBackgroundModes));
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, 0, &nBackgroundModes));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "backgroundModes", nBackgroundModes));

    napi_value nDescriptionId;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, abilityInfo.descriptionId, &nDescriptionId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "descriptionId", nDescriptionId));

    napi_value nFormEnabled;
    NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, abilityInfo.formEnabled, &nFormEnabled));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "formEnabled", nFormEnabled));

    napi_value nIconId;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, abilityInfo.iconId, &nIconId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "iconId", nIconId));

    napi_value nLabelId;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, abilityInfo.labelId, &nLabelId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "labelId", nLabelId));

    napi_value nSubType;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(abilityInfo.subType), &nSubType));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "subType", nSubType));

    napi_value nReadPermission;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, abilityInfo.readPermission.c_str(), NAPI_AUTO_LENGTH, &nReadPermission));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "readPermission", nReadPermission));

    napi_value nWritePermission;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, abilityInfo.writePermission.c_str(), NAPI_AUTO_LENGTH, &nWritePermission));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "writePermission", nWritePermission));

    napi_value nTargetAbility;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_string_utf8(env, abilityInfo.targetAbility.c_str(), NAPI_AUTO_LENGTH, &nTargetAbility));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "targetAbility", nTargetAbility));

    napi_value nMetaData;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nMetaData));
    ConvertMetaData(env, nMetaData, abilityInfo.metaData);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "metaData", nMetaData));

    napi_value nMetadata;
    size_t size = abilityInfo.metadata.size();
    NAPI_CALL_RETURN_VOID(env, napi_create_array_with_length(env, size, &nMetadata));
    for (size_t index = 0; index < size; ++index) {
        napi_value innerMeta;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &innerMeta));
        ConvertInnerMetadata(env, innerMeta, abilityInfo.metadata[index]);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nMetadata, index, innerMeta));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "metadata", nMetadata));

    napi_value nEnabled;
    NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, abilityInfo.enabled, &nEnabled));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "enabled", nEnabled));

    napi_value nMaxWindowRatio;
    NAPI_CALL_RETURN_VOID(env, napi_create_double(env, abilityInfo.maxWindowRatio, &nMaxWindowRatio));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "maxWindowRatio", nMaxWindowRatio));

    napi_value mMinWindowRatio;
    NAPI_CALL_RETURN_VOID(env, napi_create_double(env, abilityInfo.minWindowRatio, &mMinWindowRatio));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "minWindowRatio", mMinWindowRatio));

    napi_value nMaxWindowWidth;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, abilityInfo.maxWindowWidth, &nMaxWindowWidth));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "maxWindowWidth", nMaxWindowWidth));

    napi_value nMinWindowWidth;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, abilityInfo.minWindowWidth, &nMinWindowWidth));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "minWindowWidth", nMinWindowWidth));

    napi_value nMaxWindowHeight;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, abilityInfo.maxWindowHeight, &nMaxWindowHeight));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "maxWindowHeight", nMaxWindowHeight));

    napi_value nMinWindowHeight;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, abilityInfo.minWindowHeight, &nMinWindowHeight));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objAbilityInfo, "minWindowHeight", nMinWindowHeight));
}

static void ProcessAbilityInfos(
    napi_env env, napi_value result, const std::vector<OHOS::AppExecFwk::AbilityInfo> &abilityInfos)
{
    if (abilityInfos.size() > 0) {
        APP_LOGI("-----abilityInfos is not null-----");
        size_t index = 0;
        for (const auto &item : abilityInfos) {
            APP_LOGI("name: %{public}s ", item.name.c_str());
            napi_value objAbilityInfo = nullptr;
            napi_create_object(env, &objAbilityInfo);
            ConvertAbilityInfo(env, objAbilityInfo, item);
            napi_set_element(env, result, index, objAbilityInfo);
            index++;
        }
    } else {
        APP_LOGI("-----abilityInfos is null-----");
    }
}

static void ConvertHapModuleInfo(napi_env env, napi_value objHapModuleInfo, const HapModuleInfo &hapModuleInfo)
{
    napi_value nName;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, hapModuleInfo.name.c_str(), NAPI_AUTO_LENGTH, &nName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objHapModuleInfo, "name", nName));

    napi_value nModuleName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, hapModuleInfo.moduleName.c_str(), NAPI_AUTO_LENGTH, &nModuleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objHapModuleInfo, "moduleName", nModuleName));

    napi_value nDescription;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, hapModuleInfo.description.c_str(), NAPI_AUTO_LENGTH, &nDescription));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objHapModuleInfo, "description", nDescription));

    napi_value ndescriptionId;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, hapModuleInfo.descriptionId, &ndescriptionId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objHapModuleInfo, "descriptionId", ndescriptionId));

    napi_value nIcon;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, hapModuleInfo.iconPath.c_str(), NAPI_AUTO_LENGTH, &nIcon));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objHapModuleInfo, "icon", nIcon));

    napi_value nLabel;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, hapModuleInfo.label.c_str(), NAPI_AUTO_LENGTH, &nLabel));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objHapModuleInfo, "label", nLabel));

    napi_value nHashValue;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, hapModuleInfo.hashValue.c_str(), NAPI_AUTO_LENGTH, &nHashValue));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objHapModuleInfo, "hashValue", nHashValue));

    napi_value nLabelId;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, hapModuleInfo.labelId, &nLabelId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objHapModuleInfo, "labelId", nLabelId));

    napi_value nIconId;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, hapModuleInfo.iconId, &nIconId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objHapModuleInfo, "iconId", nIconId));

    napi_value nBackgroundImg;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, hapModuleInfo.backgroundImg.c_str(), NAPI_AUTO_LENGTH, &nBackgroundImg));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objHapModuleInfo, "backgroundImg", nBackgroundImg));

    napi_value nSupportedModes;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, hapModuleInfo.supportedModes, &nSupportedModes));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objHapModuleInfo, "supportedModes", nSupportedModes));

    napi_value nReqCapabilities;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nReqCapabilities));
    for (size_t idx = 0; idx < hapModuleInfo.reqCapabilities.size(); idx++) {
        napi_value nReqCapabilitie;
        NAPI_CALL_RETURN_VOID(env,
            napi_create_string_utf8(
                env, hapModuleInfo.reqCapabilities[idx].c_str(), NAPI_AUTO_LENGTH, &nReqCapabilitie));
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nReqCapabilities, idx, nReqCapabilitie));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objHapModuleInfo, "reqCapabilities", nReqCapabilities));

    napi_value nDeviceTypes;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nDeviceTypes));
    for (size_t idx = 0; idx < hapModuleInfo.deviceTypes.size(); idx++) {
        napi_value nDeviceType;
        NAPI_CALL_RETURN_VOID(
            env, napi_create_string_utf8(env, hapModuleInfo.deviceTypes[idx].c_str(), NAPI_AUTO_LENGTH, &nDeviceType));
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nDeviceTypes, idx, nDeviceType));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objHapModuleInfo, "deviceTypes", nDeviceTypes));

    napi_value nAbilityInfos;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nAbilityInfos));
    for (size_t idx = 0; idx < hapModuleInfo.abilityInfos.size(); idx++) {
        napi_value objAbilityInfo;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &objAbilityInfo));
        ConvertAbilityInfo(env, objAbilityInfo, hapModuleInfo.abilityInfos[idx]);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nAbilityInfos, idx, objAbilityInfo));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objHapModuleInfo, "abilityInfo", nAbilityInfos));

    napi_value nMainAbilityName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, hapModuleInfo.mainAbility.c_str(), NAPI_AUTO_LENGTH, &nMainAbilityName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objHapModuleInfo, "mainAbilityName", nMainAbilityName));

    napi_value nInstallationFree;
    NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, hapModuleInfo.installationFree, &nInstallationFree));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objHapModuleInfo, "installationFree", nInstallationFree));

    napi_value nMainElementName;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, hapModuleInfo.mainElementName.c_str(), NAPI_AUTO_LENGTH,
        &nMainElementName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objHapModuleInfo, "mainElementName", nMainElementName));

    napi_value nMetadata;
    size_t size = hapModuleInfo.metadata.size();
    NAPI_CALL_RETURN_VOID(env, napi_create_array_with_length(env, size, &nMetadata));
    for (size_t index = 0; index < size; ++index) {
        napi_value innerMeta;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &innerMeta));
        ConvertInnerMetadata(env, innerMeta, hapModuleInfo.metadata[index]);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nMetadata, index, innerMeta));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objHapModuleInfo, "metadata", nMetadata));
}

static void ConvertRequestPermissionUsedScene(napi_env env, napi_value result,
    const RequestPermissionUsedScene &requestPermissionUsedScene)
{
    napi_value nAbilities;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nAbilities));
    for (size_t idx = 0; idx < requestPermissionUsedScene.abilities.size(); idx++) {
        napi_value objAbility;
        NAPI_CALL_RETURN_VOID(env,
            napi_create_string_utf8(env, requestPermissionUsedScene.abilities[idx].c_str(),
                                    NAPI_AUTO_LENGTH, &objAbility));
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nAbilities, idx, objAbility));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, "abilities", nAbilities));

    napi_value nWhen;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_string_utf8(env, requestPermissionUsedScene.when.c_str(), NAPI_AUTO_LENGTH, &nWhen));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, "when", nWhen));
}

static void ConvertRequestPermission(napi_env env, napi_value result, const RequestPermission &requestPermission)
{
    napi_value nPermissionName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, requestPermission.name.c_str(), NAPI_AUTO_LENGTH, &nPermissionName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, "name", nPermissionName));

    napi_value nReason;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, requestPermission.reason.c_str(), NAPI_AUTO_LENGTH, &nReason));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, "reason", nReason));

    napi_value nReasonId;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, requestPermission.reasonId, &nReasonId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, "reasonId", nReasonId));

    napi_value nUsedScene;
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nUsedScene));
    ConvertRequestPermissionUsedScene(env, nUsedScene, requestPermission.usedScene);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, "usedScene", nUsedScene));
}

static void ConvertBundleInfo(napi_env env, napi_value objBundleInfo, const BundleInfo &bundleInfo)
{
    napi_value nName;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, bundleInfo.name.c_str(), NAPI_AUTO_LENGTH, &nName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleInfo, "name", nName));

    napi_value nVendor;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, bundleInfo.vendor.c_str(), NAPI_AUTO_LENGTH, &nVendor));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleInfo, "vendor", nVendor));

    napi_value nVersionCode;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, bundleInfo.versionCode, &nVersionCode));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleInfo, "versionCode", nVersionCode));

    napi_value nVersionName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, bundleInfo.versionName.c_str(), NAPI_AUTO_LENGTH, &nVersionName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleInfo, "versionName", nVersionName));

    napi_value nCpuAbi;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, bundleInfo.cpuAbi.c_str(), NAPI_AUTO_LENGTH, &nCpuAbi));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleInfo, "cpuAbi", nCpuAbi));

    napi_value nAppId;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, bundleInfo.appId.c_str(), NAPI_AUTO_LENGTH, &nAppId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleInfo, "appId", nAppId));

    napi_value nEntryModuleName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, bundleInfo.entryModuleName.c_str(), NAPI_AUTO_LENGTH, &nEntryModuleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleInfo, "entryModuleName", nEntryModuleName));

    napi_value nCompatibleVersion;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, bundleInfo.compatibleVersion, &nCompatibleVersion));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleInfo, "compatibleVersion", nCompatibleVersion));

    napi_value nTargetVersion;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, bundleInfo.targetVersion, &nTargetVersion));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleInfo, "targetVersion", nTargetVersion));

    napi_value nUid;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, bundleInfo.uid, &nUid));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleInfo, "uid", nUid));

    napi_value nInstallTime;
    NAPI_CALL_RETURN_VOID(env, napi_create_int64(env, bundleInfo.installTime, &nInstallTime));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleInfo, "installTime", nInstallTime));

    napi_value nUpdateTime;
    NAPI_CALL_RETURN_VOID(env, napi_create_int64(env, bundleInfo.updateTime, &nUpdateTime));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleInfo, "updateTime", nUpdateTime));

    napi_value nAppInfo;
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nAppInfo));
    ConvertApplicationInfo(env, nAppInfo, bundleInfo.applicationInfo);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleInfo, "appInfo", nAppInfo));

    napi_value nAbilityInfos;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nAbilityInfos));
    for (size_t idx = 0; idx < bundleInfo.abilityInfos.size(); idx++) {
        napi_value objAbilityInfo;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &objAbilityInfo));
        ConvertAbilityInfo(env, objAbilityInfo, bundleInfo.abilityInfos[idx]);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nAbilityInfos, idx, objAbilityInfo));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleInfo, "abilityInfos", nAbilityInfos));

    napi_value nHapModuleInfos;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nHapModuleInfos));
    for (size_t idx = 0; idx < bundleInfo.hapModuleInfos.size(); idx++) {
        napi_value objHapModuleInfo;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &objHapModuleInfo));
        ConvertHapModuleInfo(env, objHapModuleInfo, bundleInfo.hapModuleInfos[idx]);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nHapModuleInfos, idx, objHapModuleInfo));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleInfo, "hapModuleInfos", nHapModuleInfos));

    napi_value nReqPermissions;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nReqPermissions));
    for (size_t idx = 0; idx < bundleInfo.reqPermissions.size(); idx++) {
        napi_value nReqPermission;
        NAPI_CALL_RETURN_VOID(env,
            napi_create_string_utf8(env, bundleInfo.reqPermissions[idx].c_str(), NAPI_AUTO_LENGTH, &nReqPermission));
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nReqPermissions, idx, nReqPermission));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleInfo, "reqPermissions", nReqPermissions));

    napi_value nReqPermissionStates;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nReqPermissionStates));
    for (size_t idx = 0; idx < bundleInfo.reqPermissionStates.size(); idx++) {
        napi_value nReqPermissionState;
        NAPI_CALL_RETURN_VOID(env,
            napi_create_int32(env, bundleInfo.reqPermissionStates[idx], &nReqPermissionState));
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nReqPermissionStates, idx, nReqPermissionState));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleInfo, "reqPermissionStates",
        nReqPermissionStates));

    napi_value nIsCompressNativeLibs;
    NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, bundleInfo.applicationInfo.isCompressNativeLibs,
        &nIsCompressNativeLibs));
    NAPI_CALL_RETURN_VOID(
        env, napi_set_named_property(env, objBundleInfo, "isCompressNativeLibs", nIsCompressNativeLibs));

    napi_value nIsSilentInstallation;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, std::string().c_str(), NAPI_AUTO_LENGTH, &nIsSilentInstallation));
    NAPI_CALL_RETURN_VOID(
        env, napi_set_named_property(env, objBundleInfo, "isSilentInstallation", nIsSilentInstallation));

    napi_value nType;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, std::string().c_str(), NAPI_AUTO_LENGTH, &nType));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objBundleInfo, "type", nType));

    napi_value nReqPermissionDetails;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nReqPermissionDetails));
    for (size_t idx = 0; idx < bundleInfo.reqPermissionDetails.size(); idx++) {
        napi_value objReqPermission;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &objReqPermission));
        ConvertRequestPermission(env, objReqPermission, bundleInfo.reqPermissionDetails[idx]);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nReqPermissionDetails, idx, objReqPermission));
    }
    NAPI_CALL_RETURN_VOID(
        env, napi_set_named_property(env, objBundleInfo, "reqPermissionDetails", nReqPermissionDetails));

    napi_value nMinCompatibleVersionCode;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, bundleInfo.minCompatibleVersionCode, &nMinCompatibleVersionCode));
    NAPI_CALL_RETURN_VOID(
        env, napi_set_named_property(env, objBundleInfo, "minCompatibleVersionCode", nMinCompatibleVersionCode));

    napi_value nEntryInstallationFree;
    NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, bundleInfo.entryInstallationFree, &nEntryInstallationFree));
    NAPI_CALL_RETURN_VOID(
        env, napi_set_named_property(env, objBundleInfo, "entryInstallationFree", nEntryInstallationFree));
}

static void ConvertFormCustomizeData(napi_env env, napi_value objformInfo, const FormCustomizeData &customizeData)
{
    napi_value nName;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, customizeData.name.c_str(), NAPI_AUTO_LENGTH, &nName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objformInfo, "name", nName));
    napi_value nValue;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, customizeData.value.c_str(), NAPI_AUTO_LENGTH, &nValue));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objformInfo, "value", nValue));
}

static void ConvertFormWindow(napi_env env, napi_value objWindowInfo, const FormWindow &formWindow)
{
    napi_value nDesignWidth;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, formWindow.designWidth, &nDesignWidth));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objWindowInfo, "designWidth", nDesignWidth));
    napi_value nAutoDesignWidth;
    NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, formWindow.autoDesignWidth, &nAutoDesignWidth));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objWindowInfo, "autoDesignWidth", nAutoDesignWidth));
}

static void ConvertFormInfo(napi_env env, napi_value objformInfo, const FormInfo &formInfo)
{
    napi_value nName;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, formInfo.name.c_str(), NAPI_AUTO_LENGTH, &nName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objformInfo, "name", nName));
    APP_LOGI("ConvertFormInfo name=%{public}s", formInfo.name.c_str());

    napi_value nDescription;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, formInfo.description.c_str(), NAPI_AUTO_LENGTH, &nDescription));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objformInfo, "description", nDescription));

    napi_value nDescriptionId;
    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, formInfo.descriptionId, &nDescriptionId));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objformInfo, "descriptionId", nDescriptionId));

    napi_value nBundleName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, formInfo.bundleName.c_str(), NAPI_AUTO_LENGTH, &nBundleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objformInfo, "bundleName", nBundleName));

    napi_value nModuleName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, formInfo.moduleName.c_str(), NAPI_AUTO_LENGTH, &nModuleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objformInfo, "moduleName", nModuleName));

    napi_value nAbilityName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, formInfo.abilityName.c_str(), NAPI_AUTO_LENGTH, &nAbilityName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objformInfo, "abilityName", nAbilityName));

    napi_value nRelatedBundleName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, formInfo.relatedBundleName.c_str(), NAPI_AUTO_LENGTH, &nRelatedBundleName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objformInfo, "relatedBundleName", nRelatedBundleName));

    napi_value nDefaultFlag;
    NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, formInfo.defaultFlag, &nDefaultFlag));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objformInfo, "defaultFlag", nDefaultFlag));

    napi_value nFormVisibleNotify;
    NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, formInfo.formVisibleNotify, &nFormVisibleNotify));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objformInfo, "formVisibleNotify", nFormVisibleNotify));

    napi_value nFormConfigAbility;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, formInfo.formConfigAbility.c_str(), NAPI_AUTO_LENGTH, &nFormConfigAbility));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objformInfo, "formConfigAbility", nFormConfigAbility));

    napi_value nType;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(formInfo.type), &nType));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objformInfo, "type", nType));

    napi_value nColorMode;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(formInfo.colorMode), &nColorMode));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objformInfo, "colorMode", nColorMode));

    napi_value nSupportDimensions;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nSupportDimensions));
    for (size_t idx = 0; idx < formInfo.supportDimensions.size(); idx++) {
        napi_value nSupportDimension;
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, formInfo.supportDimensions[idx], &nSupportDimension));
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nSupportDimensions, idx, nSupportDimension));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objformInfo, "supportDimensions", nSupportDimensions));

    napi_value nDefaultDimension;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, formInfo.defaultDimension, &nDefaultDimension));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objformInfo, "defaultDimension", nDefaultDimension));

    napi_value nJsComponentName;
    NAPI_CALL_RETURN_VOID(
        env, napi_create_string_utf8(env, formInfo.jsComponentName.c_str(), NAPI_AUTO_LENGTH, &nJsComponentName));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objformInfo, "jsComponentName", nJsComponentName));

    napi_value nUpdateDuration;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, formInfo.updateDuration, &nUpdateDuration));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objformInfo, "updateDuration", nUpdateDuration));

    napi_value nCustomizeDatas;
    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &nCustomizeDatas));
    for (size_t idx = 0; idx < formInfo.customizeDatas.size(); idx++) {
        napi_value nCustomizeData;
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nCustomizeData));
        ConvertFormCustomizeData(env, nCustomizeData, formInfo.customizeDatas[idx]);
        NAPI_CALL_RETURN_VOID(env, napi_set_element(env, nCustomizeDatas, idx, nCustomizeData));
    }
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objformInfo, "customizeDatas", nCustomizeDatas));

    napi_value nSrc;
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, formInfo.src.c_str(), NAPI_AUTO_LENGTH, &nSrc));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objformInfo, "src", nSrc));
    APP_LOGI("ConvertFormInfo src=%{public}s", formInfo.src.c_str());

    napi_value nWindow;
    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &nWindow));
    ConvertFormWindow(env, nWindow, formInfo.window);
    APP_LOGI("ConvertFormInfo window.designWidth=%{public}d", formInfo.window.designWidth);
    APP_LOGI("ConvertFormInfo window.autoDesignWidth=%{public}d", formInfo.window.autoDesignWidth);
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, objformInfo, "window", nWindow));
}

static std::string GetStringFromNAPI(napi_env env, napi_value value)
{
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, value, &valueType);
    if (valueType != napi_string) {
        return "";
    }
    std::string result;
    size_t size = 0;

    if (napi_get_value_string_utf8(env, value, nullptr, NAPI_RETURN_ZERO, &size) != napi_ok) {
        return "";
    }
    result.reserve(size + NAPI_RETURN_ONE);
    result.resize(size);
    if (napi_get_value_string_utf8(env, value, result.data(), (size + NAPI_RETURN_ONE), &size) != napi_ok) {
        return "";
    }
    return result;
}

static napi_value ParseInt(napi_env env, int &param, napi_value args)
{
    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args, &valuetype));
    APP_LOGD("valuetype=%{public}d", valuetype);
    NAPI_ASSERT(env, valuetype == napi_number, "Wrong argument type. int32 expected");
    int32_t value = 0;
    napi_get_value_int32(env, args, &value);
    APP_LOGD("param=%{public}d", value);
    param = value;
    // create result code
    napi_value result = nullptr;
    napi_status status = napi_create_int32(env, NAPI_RETURN_ONE, &result);
    NAPI_ASSERT(env, status == napi_ok, "napi_create_int32 error");
    return result;
}

static napi_value GetCallbackErrorValue(napi_env env, int errCode)
{
    napi_value result = nullptr;
    napi_value eCode = nullptr;
    NAPI_CALL(env, napi_create_int32(env, errCode, &eCode));
    NAPI_CALL(env, napi_create_object(env, &result));
    NAPI_CALL(env, napi_set_named_property(env, result, "code", eCode));
    return result;
}

static bool InnerGetApplicationInfos(napi_env env, int32_t flags, const int userId,
    std::vector<OHOS::AppExecFwk::ApplicationInfo> &appInfos)
{
    auto iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return false;
    }
    return iBundleMgr->GetApplicationInfos(flags, userId, appInfos);
}

static void ProcessApplicationInfos(
    napi_env env, napi_value result, const std::vector<OHOS::AppExecFwk::ApplicationInfo> &appInfos)
{
    if (appInfos.size() > 0) {
        APP_LOGI("-----appInfos is not null-----");
        size_t index = 0;
        for (const auto &item : appInfos) {
            APP_LOGI("name: %{public}s, bundleName: %{public}s ", item.name.c_str(), item.bundleName.c_str());
            for (const auto &moduleInfo : item.moduleInfos) {
                APP_LOGI("moduleName: %{public}s, moduleSourceDir: %{public}s ",
                    moduleInfo.moduleName.c_str(), moduleInfo.moduleSourceDir.c_str());
            }
            napi_value objAppInfo;
            NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &objAppInfo));
            ConvertApplicationInfo(env, objAppInfo, item);
            NAPI_CALL_RETURN_VOID(env, napi_set_element(env, result, index, objAppInfo));
            index++;
        }
    } else {
        APP_LOGI("-----appInfos is null-----");
    }
}
/**
 * Promise and async callback
 */
napi_value GetApplicationInfos(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI_GetApplicationInfos called");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    APP_LOGI("argc = [%{public}zu]", argc);
    AsyncApplicationInfosCallbackInfo *asyncCallbackInfo = new (std::nothrow) AsyncApplicationInfosCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncApplicationInfosCallbackInfo> callbackPtr {asyncCallbackInfo};
    for (size_t i = 0; i < argc; ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if ((i == 0) && (valueType == napi_number)) {
            ParseInt(env, asyncCallbackInfo->flags, argv[i]);
            if (argc == ARGS_SIZE_ONE) {
                asyncCallbackInfo->userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
            }
        } else if ((i == ARGS_SIZE_ONE) && (valueType == napi_number)) {
            ParseInt(env, asyncCallbackInfo->userId, argv[i]);
        } else if ((i == ARGS_SIZE_ONE) && (valueType == napi_function)) {
            asyncCallbackInfo->userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
            NAPI_CALL(env, napi_create_reference(env, argv[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
        } else if ((i == ARGS_SIZE_TWO) && (valueType == napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, argv[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            break;
        } else {
            asyncCallbackInfo->err = PARAM_TYPE_ERROR;
            asyncCallbackInfo->message = TYPE_MISMATCH;
        }
    }

    if (argc == 0) {
        asyncCallbackInfo->err = PARAM_TYPE_ERROR;
        asyncCallbackInfo->message = TYPE_MISMATCH;
    }

    napi_value promise = nullptr;
    if (asyncCallbackInfo->callback == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncCallbackInfo->deferred, &promise));
    } else {
        NAPI_CALL(env, napi_get_undefined(env,  &promise));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "GetApplicationInfo", NAPI_AUTO_LENGTH, &resource));

    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resource,
        [](napi_env env, void* data) {
            AsyncApplicationInfosCallbackInfo* asyncCallbackInfo =
                reinterpret_cast<AsyncApplicationInfosCallbackInfo*>(data);
            if (!asyncCallbackInfo->err) {
                asyncCallbackInfo->ret = InnerGetApplicationInfos(asyncCallbackInfo->env,
                                                                  asyncCallbackInfo->flags,
                                                                  asyncCallbackInfo->userId,
                                                                  asyncCallbackInfo->appInfos);
            }
        },
        [](napi_env env, napi_status status, void* data) {
            AsyncApplicationInfosCallbackInfo* asyncCallbackInfo =
                reinterpret_cast<AsyncApplicationInfosCallbackInfo*>(data);
            std::unique_ptr<AsyncApplicationInfosCallbackInfo> callbackPtr {asyncCallbackInfo};
            napi_value result[2] = { 0 };
            if (asyncCallbackInfo->err) {
                NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, static_cast<uint32_t>(asyncCallbackInfo->err),
                    &result[0]));
                NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, asyncCallbackInfo->message.c_str(),
                    NAPI_AUTO_LENGTH, &result[1]));
            } else {
                if (asyncCallbackInfo->ret) {
                    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, 0, &result[0]));
                    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[1]));
                    ProcessApplicationInfos(env, result[1], asyncCallbackInfo->appInfos);
                } else {
                    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, 1, &result[0]));
                    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
                }
            }
            if (asyncCallbackInfo->deferred) {
              if (asyncCallbackInfo->ret) {
                  NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncCallbackInfo->deferred, result[1]));
              } else {
                  NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncCallbackInfo->deferred, result[0]));
              }
            } else {
                napi_value callback = nullptr;
                napi_value placeHolder = nullptr;
                NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->callback, &callback));
                NAPI_CALL_RETURN_VOID(env, napi_call_function(env, nullptr, callback,
                    sizeof(result) / sizeof(result[0]), result, &placeHolder));
            }
        },
        reinterpret_cast<void*>(asyncCallbackInfo), &asyncCallbackInfo->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
    callbackPtr.release();
    return promise;
}

static napi_value ParseStringArray(napi_env env, std::vector<std::string> &stringArray, napi_value args)
{
    APP_LOGD("begin to parse string array");
    bool isArray = false;
    NAPI_CALL(env, napi_is_array(env, args, &isArray));
    if (!isArray) {
        APP_LOGE("args not array");
        return nullptr;
    }
    uint32_t arrayLength = 0;
    NAPI_CALL(env, napi_get_array_length(env, args, &arrayLength));
    APP_LOGD("length=%{public}ud", arrayLength);
    for (uint32_t j = 0; j < arrayLength; j++) {
        napi_value value = nullptr;
        NAPI_CALL(env, napi_get_element(env, args, j, &value));
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, value, &valueType));
        if (valueType != napi_string) {
            APP_LOGE("array inside not string type");
            stringArray.clear();
            return nullptr;
        }
        stringArray.push_back(GetStringFromNAPI(env, value));
    }
    // create result code
    napi_value result;
    napi_status status = napi_create_int32(env, NAPI_RETURN_ONE, &result);
    NAPI_ASSERT(env, status == napi_ok, "napi_create_int32 error");
    return result;
}

// QueryAbilityInfos(want)
static bool InnerQueryAbilityInfos(napi_env env, const Want &want,
    int32_t flags, int32_t userId, std::vector<AbilityInfo> &abilityInfos)
{
    auto iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return false;
    }
    return iBundleMgr->QueryAbilityInfos(want, flags, userId, abilityInfos);
}

static bool ParseBundleOptions(napi_env env, BundleOptions &bundleOptions, napi_value args)
{
    APP_LOGD("begin to parse bundleOptions");
    napi_valuetype valueType;
    NAPI_CALL_BASE(env, napi_typeof(env, args, &valueType), false);
    if (valueType != napi_object) {
        APP_LOGE("args not object type");
        return false;
    }

    napi_value prop = nullptr;
    napi_get_named_property(env, args, "userId", &prop);
    napi_typeof(env, prop, &valueType);
    if (valueType == napi_number) {
        napi_get_value_int32(env, prop, &bundleOptions.userId);
    }
    return true;
}

static bool ParseWant(napi_env env, Want &want, napi_value args)
{
    APP_LOGD("begin to parse want");
    napi_valuetype valueType;
    NAPI_CALL_BASE(env, napi_typeof(env, args, &valueType), false);
    if (valueType != napi_object) {
        APP_LOGE("args not object type");
        return false;
    }
    int32_t wantFlags = 0;
    std::vector<std::string> wantEntities;
    std::string elementUri;
    std::string elementDeviceId;
    std::string elementBundleName;
    std::string elementModuleName;
    std::string elementAbilityName;

    napi_value prop = nullptr;
    napi_get_named_property(env, args, "bundleName", &prop);
    std::string wantBundleName = GetStringFromNAPI(env, prop);

    prop = nullptr;
    napi_get_named_property(env, args, "moduleName", &prop);
    std::string wantModuleName = GetStringFromNAPI(env, prop);

    prop = nullptr;
    napi_get_named_property(env, args, "abilityName", &prop);
    std::string wantAbilityName = GetStringFromNAPI(env, prop);

    prop = nullptr;
    napi_get_named_property(env, args, "deviceId", &prop);
    std::string wantDeviceId = GetStringFromNAPI(env, prop);

    prop = nullptr;
    napi_get_named_property(env, args, "type", &prop);
    std::string wantType = GetStringFromNAPI(env, prop);

    prop = nullptr;
    napi_get_named_property(env, args, "flags", &prop);
    napi_typeof(env, prop, &valueType);
    if (valueType == napi_number) {
        napi_get_value_int32(env, prop, &wantFlags);
    }

    prop = nullptr;
    napi_get_named_property(env, args, "action", &prop);
    std::string wantAction = GetStringFromNAPI(env, prop);

    prop = nullptr;
    napi_get_named_property(env, args, "uri", &prop);
    std::string wantUri = GetStringFromNAPI(env, prop);

    prop = nullptr;
    napi_get_named_property(env, args, "entities", &prop);
    ParseStringArray(env, wantEntities, prop);
    for (size_t idx = 0; idx < wantEntities.size(); idx++) {
        APP_LOGD("entity:%{public}s", wantEntities[idx].c_str());
        want.AddEntity(wantEntities[idx]);
    }

    napi_value elementProp = nullptr;
    napi_get_named_property(env, args, "elementName", &elementProp);
    napi_typeof(env, elementProp, &valueType);
    if (valueType == napi_object) {
        APP_LOGD("begin to parse want elementName");
        prop = nullptr;
        napi_get_named_property(env, elementProp, "deviceId", &prop);
        elementDeviceId = GetStringFromNAPI(env, prop);

        prop = nullptr;
        napi_get_named_property(env, elementProp, "uri", &prop);
        elementUri = GetStringFromNAPI(env, prop);

        prop = nullptr;
        napi_status status = napi_get_named_property(env, elementProp, "bundleName", &prop);
        napi_typeof(env, prop, &valueType);
        if ((status != napi_ok) || (valueType != napi_string)) {
            APP_LOGE("elementName bundleName incorrect");
            return false;
        }
        elementBundleName = GetStringFromNAPI(env, prop);

        prop = nullptr;
        status = napi_get_named_property(env, elementProp, "abilityName", &prop);
        napi_typeof(env, prop, &valueType);
        if ((status != napi_ok) || (valueType != napi_string)) {
            APP_LOGE("elementName abilityName incorrect");
            return false;
        }
        elementAbilityName = GetStringFromNAPI(env, prop);

        prop = nullptr;
        bool hasKey = false;
        napi_has_named_property(env, elementProp, "moduleName", &hasKey);
        if (hasKey) {
            status = napi_get_named_property(env, elementProp, "moduleName", &prop);
            napi_typeof(env, prop, &valueType);
            if ((status != napi_ok) || (valueType != napi_string)) {
                APP_LOGE("elementName moduleName incorrect");
                return false;
            }
            elementModuleName = GetStringFromNAPI(env, prop);
        }
    }
    if (elementBundleName.empty()) {
        elementBundleName = wantBundleName;
    }
    if (elementModuleName.empty()) {
        elementModuleName = wantModuleName;
    }
    if (elementAbilityName.empty()) {
        elementAbilityName = wantAbilityName;
    }
    if (elementDeviceId.empty()) {
        elementDeviceId = wantDeviceId;
    }
    if (elementUri.empty()) {
        elementUri = wantUri;
    }
    APP_LOGD("bundleName:%{public}s, moduleName: %{public}s, abilityName:%{public}s",
             elementBundleName.c_str(), elementModuleName.c_str(), elementAbilityName.c_str());
    APP_LOGD("action:%{public}s, uri:%{private}s, type:%{public}s, flags:%{public}d",
        wantAction.c_str(), elementUri.c_str(), wantType.c_str(), wantFlags);
    want.SetAction(wantAction);
    want.SetUri(elementUri);
    want.SetType(wantType);
    want.SetFlags(wantFlags);
    ElementName elementName(elementDeviceId, elementBundleName, elementAbilityName, elementModuleName);
    want.SetElement(elementName);
    return true;
}

/**
 * Promise and async callback
 */
napi_value QueryAbilityInfos(napi_env env, napi_callback_info info)
{
    APP_LOGI("QueryAbilityInfos called");
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    APP_LOGI("argc = [%{public}zu]", argc);
    Want want;
    AsyncAbilityInfoCallbackInfo *asyncCallbackInfo = new (std::nothrow) AsyncAbilityInfoCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncAbilityInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    asyncCallbackInfo->want = want;
    asyncCallbackInfo->userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;

    for (size_t i = 0; i < argc; ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if ((i == 0) && (valueType == napi_object)) {
            bool ret = ParseWant(env, asyncCallbackInfo->want, argv[i]);
            if (!ret) {
                asyncCallbackInfo->err = PARAM_TYPE_ERROR;
            }
        } else if ((i == ARGS_SIZE_ONE) && (valueType == napi_number)) {
            ParseInt(env, asyncCallbackInfo->flags, argv[i]);
        } else if (i == ARGS_SIZE_TWO) {
            if (valueType == napi_number) {
                ParseInt(env, asyncCallbackInfo->userId, argv[i]);
            } else if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, argv[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
                break;
            } else {
                asyncCallbackInfo->err = PARAM_TYPE_ERROR;
            }
        } else if ((i == ARGS_SIZE_THREE) && (valueType == napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, argv[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
        } else {
            asyncCallbackInfo->err = PARAM_TYPE_ERROR;
        }
    }
    napi_value promise = nullptr;
    if (asyncCallbackInfo->callback == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncCallbackInfo->deferred, &promise));
    } else {
        NAPI_CALL(env, napi_get_undefined(env,  &promise));
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "QueryAbilityInfos", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resource,
        [](napi_env env, void *data) {
            AsyncAbilityInfoCallbackInfo *asyncCallbackInfo =
                reinterpret_cast<AsyncAbilityInfoCallbackInfo *>(data);
            if (!asyncCallbackInfo->err) {
                {
                    std::lock_guard<std::mutex> lock(abilityInfoCacheMutex_);
                    auto item = abilityInfoCache.find(Query(asyncCallbackInfo->want.ToString(),
                        QUERY_ABILITY_BY_WANT, asyncCallbackInfo->flags, asyncCallbackInfo->userId, env));
                    if (item != abilityInfoCache.end()) {
                        APP_LOGD("has cache,no need to query from host");
                        asyncCallbackInfo->ret = true;
                        return;
                    }
                }
                asyncCallbackInfo->ret = InnerQueryAbilityInfos(env, asyncCallbackInfo->want, asyncCallbackInfo->flags,
                    asyncCallbackInfo->userId, asyncCallbackInfo->abilityInfos);
            }
        },
        [](napi_env env, napi_status status, void *data) {
            AsyncAbilityInfoCallbackInfo *asyncCallbackInfo =
                reinterpret_cast<AsyncAbilityInfoCallbackInfo *>(data);
            std::unique_ptr<AsyncAbilityInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
            napi_value result[2] = { 0 };
            if (asyncCallbackInfo->err) {
                NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, static_cast<uint32_t>(asyncCallbackInfo->err),
                    &result[0]));
                NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, "type mismatch",
                    NAPI_AUTO_LENGTH, &result[1]));
            } else {
                if (asyncCallbackInfo->ret) {
                    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, 0, &result[0]));
                    NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[1]));
                    // get from cache first
                    std::lock_guard<std::mutex> lock(abilityInfoCacheMutex_);
                    Query query(asyncCallbackInfo->want.ToString(), QUERY_ABILITY_BY_WANT,
                        asyncCallbackInfo->flags, asyncCallbackInfo->userId, env);
                    auto item = abilityInfoCache.find(query);
                    if (item != abilityInfoCache.end()) {
                        APP_LOGD("get abilityInfo from cache");
                        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, item->second, &result[1]));
                    } else {
                        ProcessAbilityInfos(env, result[1], asyncCallbackInfo->abilityInfos);
                        HandleAbilityInfoCache(env, query, asyncCallbackInfo, result[1]);
                    }
                } else {
                    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, 1, &result[0]));
                    NAPI_CALL_RETURN_VOID(env,
                        napi_create_string_utf8(env, "QueryAbilityInfos failed", NAPI_AUTO_LENGTH, &result[1]));
                }
            }
            if (asyncCallbackInfo->deferred) {
                if (asyncCallbackInfo->ret) {
                    NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncCallbackInfo->deferred, result[1]));
                } else {
                    NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncCallbackInfo->deferred, result[0]));
                }
            } else {
                napi_value callback = nullptr;
                napi_value placeHolder = nullptr;
                NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->callback, &callback));
                NAPI_CALL_RETURN_VOID(env, napi_call_function(env, nullptr, callback,
                    sizeof(result) / sizeof(result[0]), result, &placeHolder));
            }
        },
        reinterpret_cast<void*>(asyncCallbackInfo), &asyncCallbackInfo->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
    callbackPtr.release();
    return promise;
}

static napi_value ParseString(napi_env env, std::string &param, napi_value args)
{
    napi_valuetype valuetype;
    NAPI_CALL(env, napi_typeof(env, args, &valuetype));
    NAPI_ASSERT(env, valuetype == napi_string, "Wrong argument type. String expected");
    param = GetStringFromNAPI(env, args);
    APP_LOGD("param=%{public}s", param.c_str());
    // create result code
    napi_value result;
    napi_status status = napi_create_int32(env, NAPI_RETURN_ONE, &result);
    NAPI_ASSERT(env, status == napi_ok, "napi_create_int32 error");
    return result;
}

static bool InnerGetBundleInfos(
    napi_env env, int32_t flags, int32_t userId, std::vector<OHOS::AppExecFwk::BundleInfo> &bundleInfos)
{
    auto iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return false;
    }
    return iBundleMgr->GetBundleInfos(flags, bundleInfos, userId);
}

static void ProcessBundleInfos(
    napi_env env, napi_value result, const std::vector<OHOS::AppExecFwk::BundleInfo> &bundleInfos)
{
    if (bundleInfos.size() > 0) {
        APP_LOGI("-----bundleInfos is not null-----");
        size_t index = 0;
        for (const auto &item : bundleInfos) {
            APP_LOGD("name is %{public}s and bundleName is %{public}s ",
                item.name.c_str(), item.applicationInfo.bundleName.c_str());
            for (const auto &moduleInfo : item.applicationInfo.moduleInfos) {
                APP_LOGD("moduleName: %{public}s, moduleSourceDir: %{public}s ",
                    moduleInfo.moduleName.c_str(), moduleInfo.moduleSourceDir.c_str());
            }
            napi_value objBundleInfo = nullptr;
            napi_create_object(env, &objBundleInfo);
            ConvertBundleInfo(env, objBundleInfo, item);
            napi_set_element(env, result, index, objBundleInfo);
            index++;
        }
    } else {
        APP_LOGI("-----bundleInfos is null-----");
    }
}

void GetBundleInfosExec(napi_env env, void *data)
{
    APP_LOGD("NAPI begin");
    AsyncBundleInfosCallbackInfo* asyncCallbackInfo = reinterpret_cast<AsyncBundleInfosCallbackInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    if (asyncCallbackInfo->err == NO_ERROR) {
        asyncCallbackInfo->ret = InnerGetBundleInfos(
            env, asyncCallbackInfo->flags, asyncCallbackInfo->userId, asyncCallbackInfo->bundleInfos);
    }
    APP_LOGD("NAPI end");
}

void GetBundleInfosComplete(napi_env env, napi_status status, void *data)
{
    APP_LOGD("NAPI begin");
    AsyncBundleInfosCallbackInfo* asyncCallbackInfo = reinterpret_cast<AsyncBundleInfosCallbackInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    std::unique_ptr<AsyncBundleInfosCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO] = { 0 };
    if (asyncCallbackInfo->err != NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, static_cast<uint32_t>(asyncCallbackInfo->err),
            &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, asyncCallbackInfo->message.c_str(),
            NAPI_AUTO_LENGTH, &result[ARGS_POS_ONE]));
    } else {
        if (asyncCallbackInfo->ret) {
            NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, 0, &result[ARGS_POS_ZERO]));
            NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[ARGS_POS_ONE]));
            ProcessBundleInfos(env, result[ARGS_POS_ONE], asyncCallbackInfo->bundleInfos);
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, 1, &result[ARGS_POS_ZERO]));
            NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[ARGS_POS_ONE]));
        }
    }
    if (asyncCallbackInfo->deferred) {
        if (asyncCallbackInfo->ret) {
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncCallbackInfo->deferred, result[ARGS_POS_ONE]));
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncCallbackInfo->deferred, result[ARGS_POS_ZERO]));
        }
    } else {
        napi_value callback = nullptr;
        napi_value placeHolder = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->callback, &callback));
        NAPI_CALL_RETURN_VOID(env, napi_call_function(env, nullptr, callback,
            sizeof(result) / sizeof(result[ARGS_POS_ZERO]), result, &placeHolder));
    }
    APP_LOGD("NAPI end");
}

napi_value GetBundleInfos(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI called");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {0};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    APP_LOGD("argc = [%{public}zu]", argc);
    AsyncBundleInfosCallbackInfo *asyncCallbackInfo = new (std::nothrow) AsyncBundleInfosCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is nullptr");
        return nullptr;
    }
    std::unique_ptr<AsyncBundleInfosCallbackInfo> callbackPtr {asyncCallbackInfo};
    for (size_t i = 0; i < argc; ++i) {
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[i], &valueType));
        if ((i == PARAM0) && (valueType == napi_number)) {
            ParseInt(env, asyncCallbackInfo->flags, argv[i]);
        } else if ((i == PARAM1) && (valueType == napi_number)) {
            ParseInt(env, asyncCallbackInfo->userId, argv[i]);
        } else if ((i == PARAM1) && (valueType == napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, argv[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            break;
        } else if ((i == PARAM2) && (valueType == napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, argv[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            break;
        } else {
            asyncCallbackInfo->err = PARAM_TYPE_ERROR;
            asyncCallbackInfo->message = TYPE_MISMATCH;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<AsyncBundleInfosCallbackInfo>(
        env, asyncCallbackInfo, GET_ALL_BUNDLE_INFO, GetBundleInfosExec, GetBundleInfosComplete);
    callbackPtr.release();
    APP_LOGD("NAPI done");
    return promise;
}

static bool InnerGetPermissionDef(const std::string &permissionName, PermissionDef &permissionDef)
{
    auto iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return false;
    };
    ErrCode ret = iBundleMgr->GetPermissionDef(permissionName, permissionDef);
    if (ret != NO_ERROR) {
        APP_LOGE("permissionName is not find");
        return false;
    }
    return true;
}

void GetPermissionDefExec(napi_env env, void *data)
{
    APP_LOGD("NAPI begin");
    AsyncPermissionDefCallbackInfo *asyncCallbackInfo = reinterpret_cast<AsyncPermissionDefCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    if (asyncCallbackInfo->err == NO_ERROR) {
        asyncCallbackInfo->ret =
            InnerGetPermissionDef(asyncCallbackInfo->permissionName, asyncCallbackInfo->permissionDef);
    }
    APP_LOGD("NAPI end");
}

void GetPermissionDefComplete(napi_env env, napi_status status, void *data)
{
    APP_LOGD("NAPI begin");
    AsyncPermissionDefCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<AsyncPermissionDefCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    std::unique_ptr<AsyncPermissionDefCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO] = {0};
    if (asyncCallbackInfo->err) {
        NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, static_cast<uint32_t>(asyncCallbackInfo->err),
            &result[PARAM0]));
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, asyncCallbackInfo->message.c_str(),
            NAPI_AUTO_LENGTH, &result[PARAM1]));
    } else {
        if (asyncCallbackInfo->ret) {
            NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, CODE_SUCCESS, &result[PARAM0]));
            NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result[PARAM1]));
            CommonFunc::ConvertPermissionDef(env, result[PARAM1], asyncCallbackInfo->permissionDef);
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, OPERATION_FAILED, &result[PARAM0]));
            NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[PARAM1]));
        }
    }
    if (asyncCallbackInfo->deferred) {
        if (asyncCallbackInfo->ret) {
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncCallbackInfo->deferred, result[PARAM1]));
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncCallbackInfo->deferred, result[PARAM0]));
        }
    } else {
        napi_value callback = nullptr;
        napi_value placeHolder = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->callback, &callback));
        NAPI_CALL_RETURN_VOID(env, napi_call_function(env, nullptr, callback,
            sizeof(result) / sizeof(result[PARAM0]), result, &placeHolder));
    }
    APP_LOGD("NAPI end");
}

napi_value GetPermissionDef(napi_env env, napi_callback_info info)
{
    APP_LOGD("Napi called");
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    APP_LOGD("argc = [%{public}zu]", argc);
    AsyncPermissionDefCallbackInfo *asyncCallbackInfo = new (std::nothrow) AsyncPermissionDefCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncPermissionDefCallbackInfo> callbackPtr {asyncCallbackInfo};
    for (size_t i = 0; i < argc; ++i) {
        napi_valuetype valuetype = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[i], &valuetype));
        if ((i == PARAM0) && (valuetype == napi_string)) {
            ParseString(env, asyncCallbackInfo->permissionName, argv[i]);
        } else if ((i == PARAM1) && (valuetype == napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, argv[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
        } else {
            asyncCallbackInfo->err = PARAM_TYPE_ERROR;
            asyncCallbackInfo->message = TYPE_MISMATCH;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<AsyncPermissionDefCallbackInfo>(
        env, asyncCallbackInfo, GET_PERMISSION_DEF, GetPermissionDefExec, GetPermissionDefComplete);
    callbackPtr.release();
    APP_LOGD("Napi done");
    return promise;
}

static bool VerifyCallingPermission(std::string permissionName)
{
    auto iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return false;
    }
    return iBundleMgr->VerifyCallingPermission(permissionName);
}

static bool VerifySystemApi()
{
    auto iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return false;
    }
    return iBundleMgr->VerifySystemApi();
}

static bool ParseHashParam(napi_env env, std::string &key, std::string &value, napi_value args)
{
    napi_valuetype valueType;
    NAPI_CALL_BASE(env, napi_typeof(env, args, &valueType), false);
    if (valueType != napi_object) {
        APP_LOGE("args type incorrect");
        return false;
    }
    napi_value property = nullptr;
    bool hasKey = false;
    napi_has_named_property(env, args, "moduleName", &hasKey);
    if (!hasKey) {
        APP_LOGE("parse HashParam failed due to moduleName is not exist");
        return false;
    }
    napi_status status = napi_get_named_property(env, args, "moduleName", &property);
    if (status != napi_ok) {
        APP_LOGE("napi get named moduleName property error");
        return false;
    }
    ParseString(env, key, property);
    if (key.empty()) {
        APP_LOGE("param string moduleName is empty");
        return false;
    }
    APP_LOGD("ParseHashParam moduleName=%{public}s", key.c_str());

    property = nullptr;
    hasKey = false;
    napi_has_named_property(env, args, "hashValue", &hasKey);
    if (!hasKey) {
        APP_LOGE("parse HashParam failed due to hashValue is not exist");
        return false;
    }
    status = napi_get_named_property(env, args, "hashValue", &property);
    if (status != napi_ok) {
        APP_LOGE("napi get named hashValue property error");
        return false;
    }
    ParseString(env, value, property);
    if (value.empty()) {
        APP_LOGE("param string hashValue is empty");
        return false;
    }
    APP_LOGD("ParseHashParam hashValue=%{public}s", value.c_str());
    return true;
}

static bool ParseHashParams(napi_env env, napi_value args, std::map<std::string, std::string> &hashParams)
{
    bool hasKey = false;
    napi_has_named_property(env, args, "hashParams", &hasKey);
    if (hasKey) {
        napi_value property = nullptr;
        napi_status status = napi_get_named_property(env, args, "hashParams", &property);
        if (status != napi_ok) {
            APP_LOGE("napi get named hashParams property error");
            return false;
        }
        bool isArray = false;
        uint32_t arrayLength = 0;
        napi_value valueAry = 0;
        napi_valuetype valueAryType = napi_undefined;
        NAPI_CALL_BASE(env, napi_is_array(env, property, &isArray), false);
        if (!isArray) {
            APP_LOGE("hashParams is not array");
            return false;
        }

        NAPI_CALL_BASE(env, napi_get_array_length(env, property, &arrayLength), false);
        APP_LOGD("ParseHashParams property is array, length=%{public}ud", arrayLength);
        for (uint32_t j = 0; j < arrayLength; j++) {
            NAPI_CALL_BASE(env, napi_get_element(env, property, j, &valueAry), false);
            NAPI_CALL_BASE(env, napi_typeof(env, valueAry, &valueAryType), false);
            std::string key;
            std::string value;
            if (!ParseHashParam(env, key, value, valueAry)) {
                APP_LOGD("parse hash param failed");
                return false;
            }
            if (hashParams.find(key) != hashParams.end()) {
                APP_LOGD("moduleName(%{public}s) is duplicate", key.c_str());
                return false;
            }
            hashParams.emplace(key, value);
        }
    }
    return true;
}

static bool ParseUserId(napi_env env, napi_value args, int32_t &userId)
{
    bool hasKey = false;
    napi_has_named_property(env, args, "userId", &hasKey);
    if (hasKey) {
        napi_value property = nullptr;
        napi_status status = napi_get_named_property(env, args, "userId", &property);
        if (status != napi_ok) {
            APP_LOGE("napi get named userId property error");
            return false;
        }
        napi_valuetype valueType;
        napi_typeof(env, property, &valueType);
        if (valueType != napi_number) {
            APP_LOGE("param(userId) type incorrect");
            return false;
        }

        userId = Constants::UNSPECIFIED_USERID;
        NAPI_CALL_BASE(env, napi_get_value_int32(env, property, &userId), false);
    }
    return true;
}

static bool ParseInstallFlag(napi_env env, napi_value args, InstallFlag &installFlag)
{
    bool hasKey = false;
    napi_has_named_property(env, args, "installFlag", &hasKey);
    if (hasKey) {
        napi_value property = nullptr;
        napi_status status = napi_get_named_property(env, args, "installFlag", &property);
        if (status != napi_ok) {
            APP_LOGE("napi get named installFlag property error");
            return false;
        }
        napi_valuetype valueType;
        napi_typeof(env, property, &valueType);
        if (valueType != napi_number) {
            APP_LOGE("param(installFlag) type incorrect");
            return false;
        }

        int32_t flag = 0;
        NAPI_CALL_BASE(env, napi_get_value_int32(env, property, &flag), false);
        installFlag = static_cast<OHOS::AppExecFwk::InstallFlag>(flag);
    }
    return true;
}

static bool ParseIsKeepData(napi_env env, napi_value args, bool &isKeepData)
{
    bool hasKey = false;
    napi_has_named_property(env, args, "isKeepData", &hasKey);
    if (hasKey) {
        napi_value property = nullptr;
        napi_status status = napi_get_named_property(env, args, "isKeepData", &property);
        if (status != napi_ok) {
            APP_LOGE("napi get named isKeepData property error");
            return false;
        }
        napi_valuetype valueType;
        napi_typeof(env, property, &valueType);
        if (valueType != napi_boolean) {
            APP_LOGE("param(isKeepData) type incorrect");
            return false;
        }

        NAPI_CALL_BASE(env, napi_get_value_bool(env, property, &isKeepData), false);
    }
    return true;
}

static bool ParseCrowdtestDeadline(napi_env env, napi_value args, int64_t &crowdtestDeadline)
{
    bool hasKey = false;
    napi_has_named_property(env, args, "crowdtestDeadline", &hasKey);
    if (hasKey) {
        napi_value property = nullptr;
        napi_status status = napi_get_named_property(env, args, "crowdtestDeadline", &property);
        if (status != napi_ok) {
            APP_LOGE("napi get named crowdtestDeadline property error");
            return false;
        }
        napi_valuetype valueType;
        napi_typeof(env, property, &valueType);
        if (valueType != napi_number) {
            APP_LOGE("param(crowdtestDeadline) type incorrect");
            return false;
        }
        NAPI_CALL_BASE(env, napi_get_value_int64(env, property, &crowdtestDeadline), false);
    }
    return true;
}

static bool ParseInstallParam(napi_env env, InstallParam &installParam, napi_value args)
{
    napi_valuetype valueType;
    NAPI_CALL_BASE(env, napi_typeof(env, args, &valueType), false);
    if (valueType != napi_object) {
        APP_LOGE("args type incorrect");
        return false;
    }

    if (!ParseUserId(env, args, installParam.userId) || !ParseInstallFlag(env, args, installParam.installFlag) ||
        !ParseIsKeepData(env, args, installParam.isKeepData) || !ParseHashParams(env, args, installParam.hashParams) ||
        !ParseCrowdtestDeadline(env, args, installParam.crowdtestDeadline)) {
        APP_LOGE("ParseInstallParam failed");
        return false;
    }
    return true;
}

static bool InnerGetAllFormsInfo(napi_env env, std::vector<OHOS::AppExecFwk::FormInfo> &formInfos)
{
    auto iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return false;
    }
    return iBundleMgr->GetAllFormsInfo(formInfos);
}

static void ProcessFormsInfo(napi_env env, napi_value result, const std::vector<OHOS::AppExecFwk::FormInfo> &formInfos)
{
    if (formInfos.size() > 0) {
        APP_LOGI("-----formInfos is not null-----");
        size_t index = 0;
        for (const auto &item : formInfos) {
            APP_LOGI("name: %{public}s, bundleName: %{public}s ", item.name.c_str(), item.bundleName.c_str());
            napi_value objFormInfo;
            NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &objFormInfo));
            ConvertFormInfo(env, objFormInfo, item);
            NAPI_CALL_RETURN_VOID(env, napi_set_element(env, result, index, objFormInfo));
            index++;
        }
    } else {
        APP_LOGI("-----formInfos is null-----");
    }
}
/**
 * Promise and async callback
 */
napi_value GetAllFormsInfo(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {nullptr};
    napi_value thisArg;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    APP_LOGI("ARGCSIZE is =%{public}zu", argc);

    AsyncFormInfosCallbackInfo *asyncCallbackInfo = new (std::nothrow) AsyncFormInfosCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncFormInfosCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (argc > (ARGS_SIZE_ONE - CALLBACK_SIZE)) {
        APP_LOGI("GetAllFormsInfo asyncCallback");
        napi_value resourceName;
        NAPI_CALL(env, napi_create_string_latin1(env, "GetAllFormsInfo", NAPI_AUTO_LENGTH, &resourceName));
        napi_valuetype valuetype = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
        NAPI_ASSERT(env, valuetype == napi_function, "Wrong argument type. Function expected");
        NAPI_CALL(env, napi_create_reference(env, argv[PARAM0], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));

        NAPI_CALL(env, napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                AsyncFormInfosCallbackInfo *asyncCallbackInfo =
                    reinterpret_cast<AsyncFormInfosCallbackInfo *>(data);
                asyncCallbackInfo->ret = InnerGetAllFormsInfo(env, asyncCallbackInfo->formInfos);
            },
            [](napi_env env, napi_status status, void *data) {
                AsyncFormInfosCallbackInfo *asyncCallbackInfo =
                    reinterpret_cast<AsyncFormInfosCallbackInfo *>(data);
                std::unique_ptr<AsyncFormInfosCallbackInfo> callbackPtr {asyncCallbackInfo};
                napi_value result[ARGS_SIZE_TWO] = {0};
                napi_value callback = 0;
                napi_value undefined = 0;
                napi_value callResult = 0;
                NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
                NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[PARAM1]));
                ProcessFormsInfo(env, result[PARAM1], asyncCallbackInfo->formInfos);
                result[PARAM0] = GetCallbackErrorValue(env, asyncCallbackInfo->ret ? CODE_SUCCESS : CODE_FAILED);
                NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->callback, &callback));
                NAPI_CALL_RETURN_VOID(env, napi_call_function(env, undefined, callback, ARGS_SIZE_TWO,
                    &result[PARAM0], &callResult));
            },
            reinterpret_cast<void*>(asyncCallbackInfo),
            &asyncCallbackInfo->asyncWork));
        NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
        callbackPtr.release();
        napi_value result;
        napi_create_int32(env, NAPI_RETURN_ONE, &result);
        return result;
    } else {
        APP_LOGI("GetFormInfos promise");
        napi_deferred deferred;
        napi_value promise;
        NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->deferred = deferred;

        napi_value resourceName;
        NAPI_CALL(env, napi_create_string_latin1(env, "GetFormInfos", NAPI_AUTO_LENGTH, &resourceName));
        NAPI_CALL(env, napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                AsyncFormInfosCallbackInfo *asyncCallbackInfo =
                    reinterpret_cast<AsyncFormInfosCallbackInfo *>(data);
                InnerGetAllFormsInfo(env, asyncCallbackInfo->formInfos);
            },
            [](napi_env env, napi_status status, void *data) {
                APP_LOGI("=================load=================");
                AsyncFormInfosCallbackInfo *asyncCallbackInfo =
                    reinterpret_cast<AsyncFormInfosCallbackInfo *>(data);
                std::unique_ptr<AsyncFormInfosCallbackInfo> callbackPtr {asyncCallbackInfo};
                napi_value result;
                NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result));
                ProcessFormsInfo(env, result, asyncCallbackInfo->formInfos);
                NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred,
                    result));
            },
            reinterpret_cast<void*>(asyncCallbackInfo),
            &asyncCallbackInfo->asyncWork));
        NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
        callbackPtr.release();
        return promise;
    }
}

static bool InnerGetFormInfosByModule(napi_env env, const std::string &bundleName, const std::string &moduleName,
    std::vector<OHOS::AppExecFwk::FormInfo> &formInfos)
{
    auto iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return false;
    }
    return iBundleMgr->GetFormsInfoByModule(bundleName, moduleName, formInfos);
}
/**
 * Promise and async callback
 */
napi_value GetFormsInfoByModule(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    APP_LOGI("ARGCSIZE is =%{public}zu", argc);
    std::string bundleName;
    std::string moduleName;
    ParseString(env, bundleName, argv[PARAM0]);
    ParseString(env, moduleName, argv[PARAM1]);

    AsyncFormInfosByModuleCallbackInfo *asyncCallbackInfo = new (std::nothrow) AsyncFormInfosByModuleCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncFormInfosByModuleCallbackInfo> callbackPtr {asyncCallbackInfo};
    asyncCallbackInfo->bundleName = bundleName;
    asyncCallbackInfo->moduleName = moduleName;

    if (argc > (ARGS_SIZE_THREE - CALLBACK_SIZE)) {
        APP_LOGI("GetFormsInfoByModule asyncCallback");
        napi_value resourceName;
        NAPI_CALL(env, napi_create_string_latin1(env, "GetFormsInfoByModule", NAPI_AUTO_LENGTH, &resourceName));
        napi_valuetype valuetype = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[ARGS_SIZE_TWO], &valuetype));
        NAPI_ASSERT(env, valuetype == napi_function, "Wrong argument type. Function expected");
        NAPI_CALL(env, napi_create_reference(env, argv[ARGS_SIZE_TWO], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));

        NAPI_CALL(env, napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                AsyncFormInfosByModuleCallbackInfo *asyncCallbackInfo =
                    reinterpret_cast<AsyncFormInfosByModuleCallbackInfo *>(data);
                asyncCallbackInfo->ret = InnerGetFormInfosByModule(
                    env, asyncCallbackInfo->bundleName, asyncCallbackInfo->moduleName, asyncCallbackInfo->formInfos);
            },
            [](napi_env env, napi_status status, void *data) {
                AsyncFormInfosByModuleCallbackInfo *asyncCallbackInfo =
                    reinterpret_cast<AsyncFormInfosByModuleCallbackInfo *>(data);
                std::unique_ptr<AsyncFormInfosByModuleCallbackInfo> callbackPtr {asyncCallbackInfo};
                napi_value result[ARGS_SIZE_TWO] = {0};
                napi_value callback = 0;
                napi_value undefined = 0;
                napi_value callResult = 0;
                NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
                NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[PARAM1]));
                ProcessFormsInfo(env, result[PARAM1], asyncCallbackInfo->formInfos);
                result[PARAM0] = GetCallbackErrorValue(env, asyncCallbackInfo->ret ? CODE_SUCCESS : CODE_FAILED);
                NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->callback, &callback));
                NAPI_CALL_RETURN_VOID(env, napi_call_function(env, undefined, callback, ARGS_SIZE_TWO,
                    &result[PARAM0], &callResult));
            },
            reinterpret_cast<void*>(asyncCallbackInfo),
            &asyncCallbackInfo->asyncWork));
        NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
        callbackPtr.release();
        napi_value result;
        napi_create_int32(env, NAPI_RETURN_ONE, &result);
        return result;
    } else {
        APP_LOGI("GetFormsInfoByModule promise");
        napi_deferred deferred;
        napi_value promise;
        NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->deferred = deferred;

        napi_value resourceName;
        NAPI_CALL(env, napi_create_string_latin1(env, "GetFormsInfoByModule", NAPI_AUTO_LENGTH, &resourceName));
        NAPI_CALL(env, napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                AsyncFormInfosByModuleCallbackInfo *asyncCallbackInfo =
                    reinterpret_cast<AsyncFormInfosByModuleCallbackInfo *>(data);
                InnerGetFormInfosByModule(
                    env, asyncCallbackInfo->bundleName, asyncCallbackInfo->moduleName, asyncCallbackInfo->formInfos);
            },
            [](napi_env env, napi_status status, void *data) {
                APP_LOGI("=================load=================");
                AsyncFormInfosByModuleCallbackInfo *asyncCallbackInfo =
                    reinterpret_cast<AsyncFormInfosByModuleCallbackInfo *>(data);
                std::unique_ptr<AsyncFormInfosByModuleCallbackInfo> callbackPtr {asyncCallbackInfo};
                napi_value result;
                NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result));
                ProcessFormsInfo(env, result, asyncCallbackInfo->formInfos);
                NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred,
                    result));
            },
            reinterpret_cast<void*>(asyncCallbackInfo),
            &asyncCallbackInfo->asyncWork));
        NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
        callbackPtr.release();
        return promise;
    }
}

static bool InnerGetFormInfosByApp(
    napi_env env, const std::string &bundleName, std::vector<OHOS::AppExecFwk::FormInfo> &formInfos)
{
    auto iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return false;
    }
    return iBundleMgr->GetFormsInfoByApp(bundleName, formInfos);
}
/**
 * Promise and async callback
 */
napi_value GetFormsInfoByApp(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = {nullptr};
    napi_value thisArg;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    APP_LOGI("ARGCSIZE is =%{public}zu", argc);
    std::string bundleName;
    ParseString(env, bundleName, argv[PARAM0]);

    AsyncFormInfosByAppCallbackInfo *asyncCallbackInfo = new (std::nothrow) AsyncFormInfosByAppCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncFormInfosByAppCallbackInfo> callbackPtr {asyncCallbackInfo};
    asyncCallbackInfo->bundleName = bundleName;
    if (argc > (ARGS_SIZE_TWO - CALLBACK_SIZE)) {
        APP_LOGI("GetFormsInfoByApp asyncCallback");
        napi_value resourceName;
        NAPI_CALL(env, napi_create_string_latin1(env, "GetFormsInfoByApp", NAPI_AUTO_LENGTH, &resourceName));
        napi_valuetype valuetype = napi_undefined;
        napi_typeof(env, argv[ARGS_SIZE_ONE], &valuetype);
        NAPI_ASSERT(env, valuetype == napi_function, "Wrong argument type. Function expected");
        NAPI_CALL(env, napi_create_reference(env, argv[ARGS_SIZE_ONE], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));

        NAPI_CALL(env, napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                AsyncFormInfosByAppCallbackInfo *asyncCallbackInfo =
                    reinterpret_cast<AsyncFormInfosByAppCallbackInfo *>(data);
                asyncCallbackInfo->ret =
                    InnerGetFormInfosByApp(env, asyncCallbackInfo->bundleName, asyncCallbackInfo->formInfos);
            },
            [](napi_env env, napi_status status, void *data) {
                AsyncFormInfosByAppCallbackInfo *asyncCallbackInfo =
                    reinterpret_cast<AsyncFormInfosByAppCallbackInfo *>(data);
                std::unique_ptr<AsyncFormInfosByAppCallbackInfo> callbackPtr {asyncCallbackInfo};
                napi_value result[ARGS_SIZE_TWO] = {0};
                napi_value callback = 0;
                napi_value undefined = 0;
                napi_value callResult = 0;
                NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
                NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[PARAM1]));
                ProcessFormsInfo(env, result[PARAM1], asyncCallbackInfo->formInfos);
                result[PARAM0] = GetCallbackErrorValue(env, asyncCallbackInfo->ret ? CODE_SUCCESS : CODE_FAILED);
                NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->callback, &callback));
                NAPI_CALL_RETURN_VOID(env, napi_call_function(env, undefined, callback, ARGS_SIZE_TWO,
                    &result[PARAM0], &callResult));
            },
            reinterpret_cast<void*>(asyncCallbackInfo),
            &asyncCallbackInfo->asyncWork));
        NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
        callbackPtr.release();
        napi_value result;
        napi_create_int32(env, NAPI_RETURN_ONE, &result);
        return result;
    } else {
        APP_LOGI("GetFormsInfoByApp promise");
        napi_deferred deferred;
        napi_value promise;
        NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->deferred = deferred;

        napi_value resourceName;
        NAPI_CALL(env, napi_create_string_latin1(env, "GetFormsInfoByApp", NAPI_AUTO_LENGTH, &resourceName));
        NAPI_CALL(env, napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                AsyncFormInfosByAppCallbackInfo *asyncCallbackInfo =
                    reinterpret_cast<AsyncFormInfosByAppCallbackInfo *>(data);
                InnerGetFormInfosByApp(env, asyncCallbackInfo->bundleName, asyncCallbackInfo->formInfos);
            },
            [](napi_env env, napi_status status, void *data) {
                APP_LOGI("=================load=================");
                AsyncFormInfosByAppCallbackInfo *asyncCallbackInfo =
                    reinterpret_cast<AsyncFormInfosByAppCallbackInfo *>(data);
                std::unique_ptr<AsyncFormInfosByAppCallbackInfo> callbackPtr {asyncCallbackInfo};
                napi_value result;
                NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result));
                ProcessFormsInfo(env, result, asyncCallbackInfo->formInfos);
                NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred,
                    result));
            },
            reinterpret_cast<void*>(asyncCallbackInfo),
            &asyncCallbackInfo->asyncWork));
        NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
        callbackPtr.release();
        return promise;
    }
}

static bool InnerGetBundleGids(napi_env env, const std::string &bundleName, std::vector<int> &gids)
{
    auto iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return false;
    };
    auto ret = iBundleMgr->GetBundleGids(bundleName, gids);
    return ret;
}

static void ProcessGids(napi_env env, napi_value result, const std::vector<int32_t> &gids)
{
    if (gids.size() > 0) {
        APP_LOGI("-----gids is not null-----");
        size_t index = 0;
        for (const auto &item : gids) {
            napi_value value;
            napi_create_int32(env, item, &value);
            NAPI_CALL_RETURN_VOID(env, napi_set_element(env, result, index, value));
            index++;
        }
        APP_LOGI("-----gids is not null  end-----");
    } else {
        APP_LOGI("-----ShortcutInfos is null-----");
    }
}

napi_value WrapVoidToJS(napi_env env)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    return result;
}

napi_value WrapUndefinedToJS(napi_env env)
{
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_undefined(env, &result));
    return result;
}

AsyncGetBundleGidsCallbackInfo *CreateAsyncGetBundleGidsCallbackInfo(napi_env env)
{
    APP_LOGI("called");
    AsyncGetBundleGidsCallbackInfo *asyncCallbackInfo = new (std::nothrow) AsyncGetBundleGidsCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is nullptr");
        return nullptr;
    }

    APP_LOGI("end");
    return asyncCallbackInfo;
}

void GetBundleGidsExecute(napi_env env, void *data)
{
    APP_LOGI("NAPI_GetBundleGids, worker pool thread execute");
    AsyncGetBundleGidsCallbackInfo *asyncCallbackInfo = static_cast<AsyncGetBundleGidsCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("NAPI_GetBundleGids, asyncCallbackInfo == nullptr");
        return;
    }

    bool ret = InnerGetBundleGids(env, asyncCallbackInfo->bundleName, asyncCallbackInfo->gids);
    if (!ret) {
        asyncCallbackInfo->err = NAPI_RETURN_FAILED;
    }
}

void GetBundleGidsAsyncComplete(napi_env env, napi_status status, void *data)
{
    APP_LOGI("NAPI_GetBundleGids, main event thread complete");
    AsyncGetBundleGidsCallbackInfo *asyncCallbackInfo = static_cast<AsyncGetBundleGidsCallbackInfo *>(data);
    std::unique_ptr<AsyncGetBundleGidsCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value callback = nullptr;
    napi_value undefined = nullptr;
    napi_value result[ARGS_SIZE_TWO] = {nullptr};
    napi_value callResult = nullptr;
    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
    result[PARAM0] = GetCallbackErrorValue(env, asyncCallbackInfo->err);

    if (asyncCallbackInfo->err == NAPI_ERR_NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[PARAM1]));
        ProcessGids(env, result[PARAM1], asyncCallbackInfo->gids);
    } else {
        result[PARAM1] = WrapUndefinedToJS(env);
    }

    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->callback, &callback));
    NAPI_CALL_RETURN_VOID(env,
        napi_call_function(env, undefined, callback, sizeof(result) / sizeof(result[PARAM0]), result, &callResult));
    APP_LOGI("main event thread complete end");
}

void GetBundleGidsPromiseComplete(napi_env env, napi_status status, void *data)
{
    APP_LOGI("main event thread complete begin");
    AsyncGetBundleGidsCallbackInfo *asyncCallbackInfo = static_cast<AsyncGetBundleGidsCallbackInfo *>(data);
    std::unique_ptr<AsyncGetBundleGidsCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result = nullptr;
    if (asyncCallbackInfo->err == NAPI_ERR_NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result));
        ProcessGids(env, result, asyncCallbackInfo->gids);
        NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncCallbackInfo->deferred, result));
    } else {
        result = GetCallbackErrorValue(env, asyncCallbackInfo->err);
        NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncCallbackInfo->deferred, result));
    }
    APP_LOGI("main event thread complete end");
}

napi_value GetBundleGidsAsync(
    napi_env env, napi_value *args, const size_t argCallback, AsyncGetBundleGidsCallbackInfo *asyncCallbackInfo)
{
    APP_LOGI("asyncCallback");
    if (args == nullptr || asyncCallbackInfo == nullptr) {
        APP_LOGE("param == nullptr");
        return nullptr;
    }

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));

    napi_valuetype valuetype = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[argCallback], &valuetype));
    if (valuetype == napi_function) {
        NAPI_CALL(env, napi_create_reference(env, args[argCallback], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
    } else {
        return nullptr;
    }

    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName, GetBundleGidsExecute, GetBundleGidsAsyncComplete,
                       reinterpret_cast<void*>(asyncCallbackInfo), &asyncCallbackInfo->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    APP_LOGI("asyncCallback end");
    return result;
}

napi_value GetBundleGidsPromise(napi_env env, AsyncGetBundleGidsCallbackInfo *asyncCallbackInfo)
{
    APP_LOGI("promise");
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("param == nullptr");
        return nullptr;
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    napi_deferred deferred;
    napi_value promise = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    asyncCallbackInfo->deferred = deferred;

    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName,
                GetBundleGidsExecute, GetBundleGidsPromiseComplete,
                reinterpret_cast<void*>(asyncCallbackInfo), &asyncCallbackInfo->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
    APP_LOGI("promise end");
    return promise;
}

napi_value GetBundleGidsWrap(napi_env env, napi_callback_info info, AsyncGetBundleGidsCallbackInfo *asyncCallbackInfo)
{
    APP_LOGI("asyncCallback");
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is nullptr");
        return nullptr;
    }

    size_t argcAsync = ARGS_SIZE_TWO;
    const size_t argcPromise = ARGS_SIZE_ONE;
    const size_t argCountWithAsync = argcPromise + ARGS_ASYNC_COUNT;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    napi_value ret = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, nullptr, nullptr));
    if (argcAsync > argCountWithAsync) {
        APP_LOGE("Wrong argument count");
        return nullptr;
    }

    napi_valuetype valueType = napi_undefined;
    NAPI_CALL(env, napi_typeof(env, args[PARAM0], &valueType));
    if (valueType == napi_string) {
        ParseString(env, asyncCallbackInfo->bundleName, args[PARAM0]);
    } else {
        asyncCallbackInfo->err = INVALID_PARAM;
    }

    if (argcAsync > argcPromise) {
        ret = GetBundleGidsAsync(env, args, argcAsync - 1, asyncCallbackInfo);
    } else {
        ret = GetBundleGidsPromise(env, asyncCallbackInfo);
    }
    APP_LOGI("asyncCallback end");
    return ret;
}

napi_value GetBundleGids(napi_env env, napi_callback_info info)
{
    APP_LOGI("NAPI_GetBundleGids start");
    AsyncGetBundleGidsCallbackInfo *asyncCallbackInfo = CreateAsyncGetBundleGidsCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        return WrapVoidToJS(env);
    }
    std::unique_ptr<AsyncGetBundleGidsCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value ret = GetBundleGidsWrap(env, info, asyncCallbackInfo);
    if (ret == nullptr) {
        APP_LOGE("ret == nullptr");
        ret = WrapVoidToJS(env);
    } else {
        callbackPtr.release();
    }
    APP_LOGI("end");
    return ret;
}

static bool InnerSetApplicationEnabled(const std::string &bundleName, bool isEnable)
{
    auto iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return false;
    }
    ErrCode result = iBundleMgr->SetApplicationEnabled(bundleName, isEnable);
    if (result != ERR_OK) {
        APP_LOGE("InnerSetApplicationEnabled failed, bundleName is %{public}s, error is %{public}d",
            bundleName.c_str(), result);
        return false;
    }
    return true;
}

static bool InnerSetAbilityEnabled(const OHOS::AppExecFwk::AbilityInfo &abilityInfo, bool isEnable)
{
    auto iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return false;
    }
    ErrCode result = iBundleMgr->SetAbilityEnabled(abilityInfo, isEnable);
    if (result != ERR_OK) {
        APP_LOGE("InnerSetAbilityEnabled failed, error is %{public}d", result);
        return false;
    }
    return true;
}

static bool InnerCleanBundleCacheCallback(
    const std::string& bundleName, const OHOS::sptr<CleanCacheCallback> cleanCacheCallback)
{
    auto iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return false;
    }
    if (cleanCacheCallback == nullptr) {
        APP_LOGE("callback nullptr");
        return false;
    }
    int32_t userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
    ErrCode result = iBundleMgr->CleanBundleCacheFiles(bundleName, cleanCacheCallback, userId);
    if (result != ERR_OK) {
        APP_LOGE("CleanBundleDataFiles call error, bundleName is %{public}s, userId is %{public}d",
            bundleName.c_str(), userId);
        return false;
    }

    return true;
}

bool ParseModuleName(napi_env env, napi_value param, std::string &moduleName)
{
    bool hasKey = false;
    napi_has_named_property(env, param, "moduleName", &hasKey);
    if (hasKey) {
        napi_valuetype valueType;
        napi_value prop = nullptr;
        napi_get_named_property(env, param, "moduleName", &prop);
        napi_typeof(env, prop, &valueType);
        if (valueType == napi_undefined) {
            APP_LOGE("begin to parse moduleName failed");
            return false;
        }
        moduleName = GetStringFromNAPI(env, prop);
    }
    return true;
}

bool UnwrapAbilityInfo(napi_env env, napi_value param, OHOS::AppExecFwk::AbilityInfo& abilityInfo)
{
    napi_valuetype valueType;
    NAPI_CALL_BASE(env, napi_typeof(env, param, &valueType), false);
    if (valueType != napi_object) {
        APP_LOGE("param type mismatch");
        return false;
    }

    napi_value prop = nullptr;
    // parse bundleName
    napi_get_named_property(env, param, "bundleName", &prop);
    napi_typeof(env, prop, &valueType);
    if (valueType == napi_undefined) {
        return false;
    }
    std::string bundleName = GetStringFromNAPI(env, prop);
    abilityInfo.bundleName = bundleName;

    // parse moduleName
    std::string moduleName;
    if (!ParseModuleName(env, param, moduleName)) {
        return false;
    }
    abilityInfo.moduleName = moduleName;

    // parse abilityName
    napi_get_named_property(env, param, "name", &prop);
    napi_typeof(env, prop, &valueType);
    if (valueType == napi_undefined) {
        return false;
    }
    std::string name = GetStringFromNAPI(env, prop);
    abilityInfo.name = name;
    return true;
}

static bool InnerGetNameForUid(int32_t uid, std::string &bundleName)
{
    auto iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return false;
    }
    if (iBundleMgr->GetNameForUid(uid, bundleName) != ERR_OK) {
        APP_LOGE("GetNameForUid failed, uid is %{public}d, bundleName is %{public}s", uid, bundleName.c_str());
        return false;
    }
    return true;
}

napi_value ClearBundleCache(napi_env env, napi_callback_info info)
{
    size_t requireArgc = ARGS_SIZE_ONE;
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { 0 };
    napi_value thisArg = nullptr;
    void *data = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    NAPI_ASSERT(env, argc >= requireArgc, "requires 1 parameter");

    AsyncHandleBundleContext *asyncCallbackInfo = new (std::nothrow) AsyncHandleBundleContext(env);
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncHandleBundleContext> callbackPtr {asyncCallbackInfo};
    for (size_t i = 0; i < argc; ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if ((i == 0) && (valueType == napi_string)) {
            ParseString(env, asyncCallbackInfo->bundleName, argv[i]);
        } else if ((i == 1) && (valueType == napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, argv[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
        } else {
            asyncCallbackInfo->err = INVALID_PARAM;
        }
    }
    napi_value promise = nullptr;

    if (asyncCallbackInfo->callback == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncCallbackInfo->deferred, &promise));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &promise));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "JSCleanBundleCache", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resource,
        [](napi_env env, void* data) {
            AsyncHandleBundleContext* asyncCallbackInfo =
                reinterpret_cast<AsyncHandleBundleContext*>(data);
            if (asyncCallbackInfo->cleanCacheCallback == nullptr) {
                asyncCallbackInfo->cleanCacheCallback = new (std::nothrow) CleanCacheCallback(UNDEFINED_ERROR);
            }
            if (!asyncCallbackInfo->err) {
                asyncCallbackInfo->ret =
                    InnerCleanBundleCacheCallback(asyncCallbackInfo->bundleName, asyncCallbackInfo->cleanCacheCallback);
            }
        },
        [](napi_env env, napi_status status, void* data) {
            AsyncHandleBundleContext* asyncCallbackInfo =
                reinterpret_cast<AsyncHandleBundleContext*>(data);
            std::unique_ptr<AsyncHandleBundleContext> callbackPtr {asyncCallbackInfo};
            napi_value result[1] = { 0 };
            // set error code
            if (asyncCallbackInfo->err) {
                NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncCallbackInfo->err, &result[0]));
            } else {
                if (!asyncCallbackInfo->ret) {
                    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, OPERATION_FAILED, &result[0]));
                } else {
                    if (asyncCallbackInfo->cleanCacheCallback) {
                        // wait for OnCleanCacheFinished
                        uv_sem_wait(&(asyncCallbackInfo->cleanCacheCallback->uvSem_));
                        asyncCallbackInfo->ret = asyncCallbackInfo->cleanCacheCallback->GetErr() ? false : true;
                        if (!asyncCallbackInfo->cleanCacheCallback->GetErr()) {
                            NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[0]));
                        } else {
                            NAPI_CALL_RETURN_VOID(env, napi_create_int32(env,
                                asyncCallbackInfo->cleanCacheCallback->GetErr(), &result[0]));
                        }
                    }
                }
            }
            // implement callback or promise
            if (asyncCallbackInfo->deferred) {
                if (!asyncCallbackInfo->ret) {
                    NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncCallbackInfo->deferred, result[0]));
                } else {
                    NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncCallbackInfo->deferred, result[0]));
                }
            } else {
                napi_value callback = nullptr;
                napi_value placeHolder = nullptr;
                NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->callback, &callback));
                NAPI_CALL_RETURN_VOID(env, napi_call_function(env, nullptr, callback,
                    sizeof(result) / sizeof(result[0]), result, &placeHolder));
            }
        },
        reinterpret_cast<void*>(asyncCallbackInfo), &asyncCallbackInfo->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
    callbackPtr.release();
    return promise;
}

napi_value CreateAbilityTypeObject(napi_env env)
{
    APP_LOGD("enter");

    napi_value value = nullptr;
    NAPI_CALL(env, napi_create_object(env, &value));
    
    napi_value nUnknown = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AbilityType::UNKNOWN), &nUnknown));
    NAPI_CALL(env, napi_set_named_property(env, value, "UNKNOWN", nUnknown));

    napi_value nPage = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AbilityType::PAGE), &nPage));
    NAPI_CALL(env, napi_set_named_property(env, value, "PAGE", nPage));

    napi_value nService = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AbilityType::SERVICE), &nService));
    NAPI_CALL(env, napi_set_named_property(env, value, "SERVICE", nService));

    napi_value nData = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(AbilityType::DATA), &nData));
    NAPI_CALL(env, napi_set_named_property(env, value, "DATA", nData));

    return value;
}

napi_value CreateAbilitySubTypeObject(napi_env env)
{
    APP_LOGD("enter");

    napi_value value = nullptr;
    NAPI_CALL(env, napi_create_object(env, &value));

    napi_value nUnspecified = nullptr;
    NAPI_CALL(env, napi_create_int32(env, NAPI_RETURN_ZERO, &nUnspecified));
    NAPI_CALL(env, napi_set_named_property(env, value, "UNSPECIFIED", nUnspecified));

    napi_value nCa = nullptr;
    NAPI_CALL(env, napi_create_int32(env, NAPI_RETURN_ONE, &nCa));
    NAPI_CALL(env, napi_set_named_property(env, value, "CA", nCa));

    return value;
}

napi_value CreateDisplayOrientationObject(napi_env env)
{
    APP_LOGD("enter");

    napi_value value = nullptr;
    NAPI_CALL(env, napi_create_object(env, &value));

    napi_value nUnspecified = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::UNSPECIFIED), &nUnspecified));
    NAPI_CALL(env, napi_set_named_property(env, value, "UNSPECIFIED", nUnspecified));

    napi_value nLandscape = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::LANDSCAPE), &nLandscape));
    NAPI_CALL(env, napi_set_named_property(env, value, "LANDSCAPE", nLandscape));

    napi_value nPortrait = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::PORTRAIT), &nPortrait));
    NAPI_CALL(env, napi_set_named_property(env, value, "PORTRAIT", nPortrait));

    napi_value nFollowRecent = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::FOLLOWRECENT), &nFollowRecent));
    NAPI_CALL(env, napi_set_named_property(env, value, "FOLLOW_RECENT", nFollowRecent));

    napi_value nLandscapeInverted = nullptr;
    NAPI_CALL(env,
        napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::LANDSCAPE_INVERTED), &nLandscapeInverted));
    NAPI_CALL(env, napi_set_named_property(env, value, "LANDSCAPE_INVERTED", nLandscapeInverted));

    napi_value nPortraitInverted = nullptr;
    NAPI_CALL(env,
        napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::PORTRAIT_INVERTED), &nPortraitInverted));
    NAPI_CALL(env, napi_set_named_property(env, value, "PORTRAIT_INVERTED", nPortraitInverted));

    napi_value nAutoRotation = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::AUTO_ROTATION), &nAutoRotation));
    NAPI_CALL(env, napi_set_named_property(env, value, "AUTO_ROTATION", nAutoRotation));

    napi_value nAutoRotationLandscape = nullptr;
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(DisplayOrientation::AUTO_ROTATION_LANDSCAPE), &nAutoRotationLandscape));
    NAPI_CALL(env, napi_set_named_property(env, value, "AUTO_ROTATION_LANDSCAPE", nAutoRotationLandscape));

    napi_value nAutoRotationPortrait = nullptr;
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(DisplayOrientation::AUTO_ROTATION_PORTRAIT), &nAutoRotationPortrait));
    NAPI_CALL(env, napi_set_named_property(env, value, "AUTO_ROTATION_PORTRAIT", nAutoRotationPortrait));

    napi_value nAutoRotationRestricted = nullptr;
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(DisplayOrientation::AUTO_ROTATION_RESTRICTED), &nAutoRotationRestricted));
    NAPI_CALL(env, napi_set_named_property(env, value, "AUTO_ROTATION_RESTRICTED", nAutoRotationRestricted));

    napi_value nAutoRotationLandscapeR = nullptr;
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(DisplayOrientation::AUTO_ROTATION_LANDSCAPE_RESTRICTED), &nAutoRotationLandscapeR));
    NAPI_CALL(env, napi_set_named_property(env, value, "AUTO_ROTATION_LANDSCAPE_RESTRICTED", nAutoRotationLandscapeR));

    napi_value nAutoRotationPortraitR = nullptr;
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(DisplayOrientation::AUTO_ROTATION_PORTRAIT_RESTRICTED), &nAutoRotationPortraitR));
    NAPI_CALL(env, napi_set_named_property(env, value, "AUTO_ROTATION_PORTRAIT_RESTRICTED", nAutoRotationPortraitR));

    napi_value nLocked = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(DisplayOrientation::LOCKED), &nLocked));
    NAPI_CALL(env, napi_set_named_property(env, value, "LOCKED", nLocked));

    return value;
}

napi_value CreateLaunchModeObject(napi_env env)
{
    APP_LOGD("enter");

    napi_value value = nullptr;
    NAPI_CALL(env, napi_create_object(env, &value));

    napi_value nSingleton = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(LaunchMode::SINGLETON), &nSingleton));
    NAPI_CALL(env, napi_set_named_property(env, value, "SINGLETON", nSingleton));

    napi_value nStandard = nullptr;
    NAPI_CALL(env, napi_create_int32(env, static_cast<int32_t>(LaunchMode::STANDARD), &nStandard));
    NAPI_CALL(env, napi_set_named_property(env, value, "STANDARD", nStandard));

    return value;
}

void CreateFormTypeObject(napi_env env, napi_value value)
{
    napi_value nJava;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, NAPI_RETURN_ZERO, &nJava));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "JAVA", nJava));
    napi_value nJs;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, NAPI_RETURN_ONE, &nJs));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "JS", nJs));
}

napi_value CreateColorModeObject(napi_env env)
{
    APP_LOGD("enter");

    napi_value value = nullptr;
    NAPI_CALL(env, napi_create_object(env, &value));

    napi_value nAutoMode = nullptr;
    NAPI_CALL(env, napi_create_int32(env, NAPI_RETURN_FAILED, &nAutoMode));
    NAPI_CALL(env, napi_set_named_property(env, value, "AUTO_MODE", nAutoMode));

    napi_value nDarkMode = nullptr;
    NAPI_CALL(env, napi_create_int32(env, NAPI_RETURN_ZERO, &nDarkMode));
    NAPI_CALL(env, napi_set_named_property(env, value, "DARK_MODE", nDarkMode));

    napi_value nLightMode = nullptr;
    NAPI_CALL(env, napi_create_int32(env, NAPI_RETURN_ONE, &nLightMode));
    NAPI_CALL(env, napi_set_named_property(env, value, "LIGHT_MODE", nLightMode));

    return value;
}

napi_value CreateGrantStatusObject(napi_env env)
{
    APP_LOGD("enter");

    napi_value value = nullptr;
    NAPI_CALL(env, napi_create_object(env, &value));

    napi_value nPermissionDenied = nullptr;
    NAPI_CALL(env, napi_create_int32(env, NAPI_RETURN_FAILED, &nPermissionDenied));
    NAPI_CALL(env, napi_set_named_property(env, value, "PERMISSION_DENIED", nPermissionDenied));

    napi_value nPermissionGranted = nullptr;
    NAPI_CALL(env, napi_create_int32(env, NAPI_RETURN_ZERO, &nPermissionGranted));
    NAPI_CALL(env, napi_set_named_property(env, value, "PERMISSION_GRANTED", nPermissionGranted));

    return value;
}

napi_value CreateModuleRemoveFlagObject(napi_env env)
{
    APP_LOGD("enter");

    napi_value value = nullptr;
    NAPI_CALL(env, napi_create_object(env, &value));

    napi_value nNotUsedByForm = nullptr;
    NAPI_CALL(env, napi_create_int32(env, NAPI_RETURN_ZERO, &nNotUsedByForm));
    NAPI_CALL(env, napi_set_named_property(env, value, "FLAG_MODULE_NOT_USED_BY_FORM", nNotUsedByForm));

    napi_value nUsedByForm = nullptr;
    NAPI_CALL(env, napi_create_int32(env, NAPI_RETURN_ONE, &nUsedByForm));
    NAPI_CALL(env, napi_set_named_property(env, value, "FLAG_MODULE_USED_BY_FORM", nUsedByForm));

    napi_value nNotUsedByShortcut = nullptr;
    NAPI_CALL(env, napi_create_int32(env, NAPI_RETURN_TWO, &nNotUsedByShortcut));
    NAPI_CALL(env, napi_set_named_property(env, value, "FLAG_MODULE_NOT_USED_BY_SHORTCUT", nNotUsedByShortcut));

    napi_value nUsedByShortcut = nullptr;
    NAPI_CALL(env, napi_create_int32(env, NAPI_RETURN_THREE, &nUsedByShortcut));
    NAPI_CALL(env, napi_set_named_property(env, value, "FLAG_MODULE_USED_BY_SHORTCUT", nUsedByShortcut));

    return value;
}

napi_value CreateSignatureCompareResultObject(napi_env env)
{
    APP_LOGD("enter");

    napi_value value = nullptr;
    NAPI_CALL(env, napi_create_object(env, &value));

    napi_value nMatched = nullptr;
    NAPI_CALL(env, napi_create_int32(env, NAPI_RETURN_ZERO, &nMatched));
    NAPI_CALL(env, napi_set_named_property(env, value, "SIGNATURE_MATCHED", nMatched));

    napi_value nNotMatched = nullptr;
    NAPI_CALL(env, napi_create_int32(env, NAPI_RETURN_ONE, &nNotMatched));
    NAPI_CALL(env, napi_set_named_property(env, value, "SIGNATURE_NOT_MATCHED", nNotMatched));

    napi_value nUnknownBundle = nullptr;
    NAPI_CALL(env, napi_create_int32(env, NAPI_RETURN_TWO, &nUnknownBundle));
    NAPI_CALL(env, napi_set_named_property(env, value, "SIGNATURE_UNKNOWN_BUNDLE", nUnknownBundle));

    return value;
}

napi_value CreateShortcutExistenceObject(napi_env env)
{
    APP_LOGD("enter");

    napi_value value = nullptr;
    NAPI_CALL(env, napi_create_object(env, &value));

    napi_value nExists = nullptr;
    NAPI_CALL(env, napi_create_int32(env, NAPI_RETURN_ZERO, &nExists));
    NAPI_CALL(env, napi_set_named_property(env, value, "SHORTCUT_EXISTENCE_EXISTS", nExists));

    napi_value nNotExists = nullptr;
    NAPI_CALL(env, napi_create_int32(env, NAPI_RETURN_ONE, &nNotExists));
    NAPI_CALL(env, napi_set_named_property(env, value, "SHORTCUT_EXISTENCE_NOT_EXISTS", nNotExists));

    napi_value nUnknown = nullptr;
    NAPI_CALL(env, napi_create_int32(env, NAPI_RETURN_TWO, &nUnknown));
    NAPI_CALL(env, napi_set_named_property(env, value, "SHORTCUT_EXISTENCE_UNKNOW", nUnknown));

    return value;
}

napi_value CreateQueryShortCutFlagObject(napi_env env)
{
    APP_LOGD("enter");

    napi_value value = nullptr;
    NAPI_CALL(env, napi_create_object(env, &value));

    napi_value nShortcutHome = nullptr;
    NAPI_CALL(env, napi_create_int32(env, NAPI_RETURN_ZERO, &nShortcutHome));
    NAPI_CALL(env, napi_set_named_property(env, value, "QUERY_SHORTCUT_HOME", nShortcutHome));

    return value;
}

napi_value CreateBundleFlagObject(napi_env env)
{
    APP_LOGD("enter");

    napi_value value = nullptr;
    NAPI_CALL(env, napi_create_object(env, &value));

    napi_value nAllApplictionInfo = nullptr;
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(ApplicationFlag::GET_ALL_APPLICATION_INFO), &nAllApplictionInfo));
    NAPI_CALL(env, napi_set_named_property(env, value, "GET_ALL_APPLICATION_INFO", nAllApplictionInfo));

    napi_value nBundleDefault = nullptr;
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(BundleFlag::GET_BUNDLE_DEFAULT), &nBundleDefault));
    NAPI_CALL(env, napi_set_named_property(env, value, "GET_BUNDLE_DEFAULT", nBundleDefault));

    napi_value nBundleWithAbilities = nullptr;
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(BundleFlag::GET_BUNDLE_WITH_ABILITIES), &nBundleWithAbilities));
    NAPI_CALL(env, napi_set_named_property(env, value, "GET_BUNDLE_WITH_ABILITIES", nBundleWithAbilities));

    napi_value nBundleWithRequestedPermission = nullptr;
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(BundleFlag::GET_BUNDLE_WITH_REQUESTED_PERMISSION), &nBundleWithRequestedPermission));
    NAPI_CALL(env, napi_set_named_property(env, value,
        "GET_BUNDLE_WITH_REQUESTED_PERMISSION", nBundleWithRequestedPermission));

    napi_value nAbilityInfoWithPermission = nullptr;
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(AbilityInfoFlag::GET_ABILITY_INFO_WITH_PERMISSION), &nAbilityInfoWithPermission));
    NAPI_CALL(env, napi_set_named_property(env, value,
        "GET_ABILITY_INFO_WITH_PERMISSION", nAbilityInfoWithPermission));

    napi_value nAbilityInfoWithApplication = nullptr;
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(AbilityInfoFlag::GET_ABILITY_INFO_WITH_APPLICATION), &nAbilityInfoWithApplication));
    NAPI_CALL(env, napi_set_named_property(env, value,
        "GET_ABILITY_INFO_WITH_APPLICATION", nAbilityInfoWithApplication));

    napi_value nAbilityInfoSystemAppOnly = nullptr;
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(AbilityInfoFlag::GET_ABILITY_INFO_SYSTEMAPP_ONLY), &nAbilityInfoSystemAppOnly));
    NAPI_CALL(env, napi_set_named_property(env, value,
        "GET_ABILITY_INFO_SYSTEMAPP_ONLY", nAbilityInfoSystemAppOnly));

    napi_value nAbilityInfoWithMetaData = nullptr;
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(AbilityInfoFlag::GET_ABILITY_INFO_WITH_METADATA), &nAbilityInfoWithMetaData));
    NAPI_CALL(env, napi_set_named_property(env, value,
        "GET_ABILITY_INFO_WITH_METADATA", nAbilityInfoWithMetaData));
    
    napi_value nBundleWithHashValue = nullptr;
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(BundleFlag::GET_BUNDLE_WITH_HASH_VALUE), &nBundleWithHashValue));
    NAPI_CALL(env, napi_set_named_property(env, value,
        "GET_BUNDLE_WITH_HASH_VALUE", nBundleWithHashValue));

    napi_value nAbilityInfoWithDisable = nullptr;
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(AbilityInfoFlag::GET_ABILITY_INFO_WITH_DISABLE), &nAbilityInfoWithDisable));
    NAPI_CALL(env, napi_set_named_property(env, value,
        "GET_ABILITY_INFO_WITH_DISABLE", nAbilityInfoWithDisable));

    napi_value nAppInfoWithPermission = nullptr;
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(ApplicationFlag::GET_APPLICATION_INFO_WITH_PERMISSION), &nAppInfoWithPermission));
    NAPI_CALL(env, napi_set_named_property(env, value,
        "GET_APPLICATION_INFO_WITH_PERMISSION", nAppInfoWithPermission));
    
    napi_value nAppInfoWithMetaData = nullptr;
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(ApplicationFlag::GET_APPLICATION_INFO_WITH_METADATA), &nAppInfoWithMetaData));
    NAPI_CALL(env, napi_set_named_property(env, value,
        "GET_APPLICATION_INFO_WITH_METADATA", nAppInfoWithMetaData));

    napi_value nAppInfoWithDisable = nullptr;
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(ApplicationFlag::GET_APPLICATION_INFO_WITH_DISABLE), &nAppInfoWithDisable));
    NAPI_CALL(env, napi_set_named_property(env, value,
        "GET_APPLICATION_INFO_WITH_DISABLE", nAppInfoWithDisable));
    
    napi_value nAppInfoWithCertificate = nullptr;
    NAPI_CALL(env, napi_create_int32(env,
        static_cast<int32_t>(ApplicationFlag::GET_APPLICATION_INFO_WITH_CERTIFICATE_FINGERPRINT),
        &nAppInfoWithCertificate));
    NAPI_CALL(env, napi_set_named_property(env, value,
        "GET_APPLICATION_INFO_WITH_CERTIFICATE_FINGERPRINT", nAppInfoWithCertificate));
    
    return value;
}


void CreateInstallErrorCodeObject(napi_env env, napi_value value)
{
    napi_value nSuccess;
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, static_cast<int32_t>(InstallErrorCode::SUCCESS), &nSuccess));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "SUCCESS", nSuccess));
    napi_value nStatusInstallFailure;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(
            env, static_cast<int32_t>(InstallErrorCode::STATUS_INSTALL_FAILURE), &nStatusInstallFailure));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "STATUS_INSTALL_FAILURE", nStatusInstallFailure));
    napi_value nStatusInstallFailureAborted;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env,
            static_cast<int32_t>(InstallErrorCode::STATUS_INSTALL_FAILURE_ABORTED),
            &nStatusInstallFailureAborted));
    NAPI_CALL_RETURN_VOID(
        env, napi_set_named_property(env, value, "STATUS_INSTALL_FAILURE_ABORTED", nStatusInstallFailureAborted));
    napi_value nStatusInstallFailureInvalid;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env,
            static_cast<int32_t>(InstallErrorCode::STATUS_INSTALL_FAILURE_INVALID),
            &nStatusInstallFailureInvalid));
    NAPI_CALL_RETURN_VOID(
        env, napi_set_named_property(env, value, "STATUS_INSTALL_FAILURE_INVALID", nStatusInstallFailureInvalid));
    napi_value nStatusInstallFailureConflict;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env,
            static_cast<int32_t>(InstallErrorCode::STATUS_INSTALL_FAILURE_CONFLICT),
            &nStatusInstallFailureConflict));
    NAPI_CALL_RETURN_VOID(
        env, napi_set_named_property(env, value, "STATUS_INSTALL_FAILURE_CONFLICT", nStatusInstallFailureConflict));
    napi_value nStatusInstallFailureStorage;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env,
            static_cast<int32_t>(InstallErrorCode::STATUS_INSTALL_FAILURE_STORAGE),
            &nStatusInstallFailureStorage));
    NAPI_CALL_RETURN_VOID(
        env, napi_set_named_property(env, value, "STATUS_INSTALL_FAILURE_STORAGE", nStatusInstallFailureStorage));
    napi_value nStatusInstallFailureIncompatible;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env,
            static_cast<int32_t>(InstallErrorCode::STATUS_INSTALL_FAILURE_INCOMPATIBLE),
            &nStatusInstallFailureIncompatible));
    NAPI_CALL_RETURN_VOID(env,
        napi_set_named_property(env, value, "STATUS_INSTALL_FAILURE_INCOMPATIBLE", nStatusInstallFailureIncompatible));
    napi_value nStatusUninstallFailure;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(
            env, static_cast<int32_t>(InstallErrorCode::STATUS_UNINSTALL_FAILURE), &nStatusUninstallFailure));
    NAPI_CALL_RETURN_VOID(
        env, napi_set_named_property(env, value, "STATUS_UNINSTALL_FAILURE", nStatusUninstallFailure));
    napi_value nStatusUninstallFailureBlocked;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env,
            static_cast<int32_t>(InstallErrorCode::STATUS_UNINSTALL_FAILURE_BLOCKED),
            &nStatusUninstallFailureBlocked));
    NAPI_CALL_RETURN_VOID(
        env, napi_set_named_property(env, value, "STATUS_UNINSTALL_FAILURE_BLOCKED", nStatusUninstallFailureBlocked));
    napi_value nStatusUninstallFailureAborted;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env,
            static_cast<int32_t>(InstallErrorCode::STATUS_UNINSTALL_FAILURE_ABORTED),
            &nStatusUninstallFailureAborted));
    NAPI_CALL_RETURN_VOID(
        env, napi_set_named_property(env, value, "STATUS_UNINSTALL_FAILURE_ABORTED", nStatusUninstallFailureAborted));
    napi_value nStatusUninstallFailureConflict;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env,
            static_cast<int32_t>(InstallErrorCode::STATUS_UNINSTALL_FAILURE_CONFLICT),
            &nStatusUninstallFailureConflict));
    NAPI_CALL_RETURN_VOID(
        env, napi_set_named_property(
            env, value, "STATUS_UNINSTALL_FAILURE_CONFLICT", nStatusUninstallFailureConflict));
    napi_value nStatusInstallFailureDownloadTimeout;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env,
            static_cast<int32_t>(InstallErrorCode::STATUS_INSTALL_FAILURE_DOWNLOAD_TIMEOUT),
            &nStatusInstallFailureDownloadTimeout));
    NAPI_CALL_RETURN_VOID(env,
        napi_set_named_property(
            env, value, "STATUS_INSTALL_FAILURE_DOWNLOAD_TIMEOUT", nStatusInstallFailureDownloadTimeout));
    napi_value nStatusInstallFailureDownloadFailed;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env,
            static_cast<int32_t>(InstallErrorCode::STATUS_INSTALL_FAILURE_DOWNLOAD_FAILED),
            &nStatusInstallFailureDownloadFailed));
    NAPI_CALL_RETURN_VOID(env,
        napi_set_named_property(
            env, value, "STATUS_INSTALL_FAILURE_DOWNLOAD_FAILED", nStatusInstallFailureDownloadFailed));
    napi_value nStatusAbilityNotFound;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(
            env, static_cast<int32_t>(InstallErrorCode::STATUS_ABILITY_NOT_FOUND), &nStatusAbilityNotFound));
    NAPI_CALL_RETURN_VOID(
        env, napi_set_named_property(env, value, "STATUS_ABILITY_NOT_FOUND", nStatusAbilityNotFound));
    napi_value nBmsServiceError;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(InstallErrorCode::STATUS_BMS_SERVICE_ERROR), &nBmsServiceError));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "STATUS_BMS_SERVICE_ERROR", nBmsServiceError));
    napi_value nStatusGrantRequestPermissionsFailed;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(InstallErrorCode::STATUS_GRANT_REQUEST_PERMISSIONS_FAILED),
                          &nStatusGrantRequestPermissionsFailed));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "STATUS_GRANT_REQUEST_PERMISSIONS_FAILED",
                          nStatusGrantRequestPermissionsFailed));
    napi_value nStatusInstallPermissionDenied;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(InstallErrorCode::STATUS_INSTALL_PERMISSION_DENIED),
                          &nStatusInstallPermissionDenied));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "STATUS_INSTALL_PERMISSION_DENIED",
                          nStatusInstallPermissionDenied));
    napi_value nStatusUnInstallPermissionDenied;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(InstallErrorCode::STATUS_UNINSTALL_PERMISSION_DENIED),
                          &nStatusUnInstallPermissionDenied));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "STATUS_UNINSTALL_PERMISSION_DENIED",
                          nStatusUnInstallPermissionDenied));
    napi_value nNoSpaceLeft;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env, static_cast<int32_t>(InstallErrorCode::STATUS_FAILED_NO_SPACE_LEFT), &nNoSpaceLeft));
    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, value, "STATUS_FAILED_NO_SPACE_LEFT", nNoSpaceLeft));
    napi_value nRecoverFailure;
    NAPI_CALL_RETURN_VOID(env,
        napi_create_int32(env,
            static_cast<int32_t>(InstallErrorCode::STATUS_RECOVER_FAILURE_INVALID), &nRecoverFailure));
    NAPI_CALL_RETURN_VOID(env,
        napi_set_named_property(env, value, "STATUS_RECOVER_FAILURE_INVALID", nRecoverFailure));
}

static bool InnerGetApplicationInfo(
    const std::string &bundleName, int32_t flags, const int userId, ApplicationInfo &appInfo)
{
    auto iBundleMgr = GetBundleMgr();
    if (!iBundleMgr) {
        APP_LOGE("can not get iBundleMgr");
        return false;
    }
    return iBundleMgr->GetApplicationInfo(bundleName, flags, userId, appInfo);
}

static bool InnerGetBundleInfo(
    napi_env env, const std::string &bundleName, int32_t flags, BundleOptions bundleOptions, BundleInfo &bundleInfo)
{
    auto iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return false;
    }
    bool ret = iBundleMgr->GetBundleInfo(bundleName, flags, bundleInfo, bundleOptions.userId);
    if (!ret) {
        APP_LOGE("bundleInfo is not find, bundleName is %{public}s, flags is %{public}d, userId is %{public}d",
            bundleName.c_str(), flags, bundleOptions.userId);
    }
    return ret;
}

void GetAllApplicationInfoExec(napi_env env, void *data)
{
    APP_LOGD("NAPI begin");
    AsyncApplicationInfosCallbackInfo* asyncCallbackInfo =
        reinterpret_cast<AsyncApplicationInfosCallbackInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    if (asyncCallbackInfo->err == NO_ERROR) {
        asyncCallbackInfo->ret = InnerGetApplicationInfos(asyncCallbackInfo->env,
                                                          asyncCallbackInfo->flags,
                                                          asyncCallbackInfo->userId,
                                                          asyncCallbackInfo->appInfos);
    }
    APP_LOGD("NAPI end");
}

void GetAllApplicationInfoComplete(napi_env env, napi_status status, void* data)
{
    APP_LOGD("NAPI begin");
    AsyncApplicationInfosCallbackInfo* asyncCallbackInfo =
        reinterpret_cast<AsyncApplicationInfosCallbackInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<AsyncApplicationInfosCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO] = { 0 };
    if (asyncCallbackInfo->err != NO_ERROR) {
        result[0] = BusinessError::CreateError(env, asyncCallbackInfo->err, "");
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, asyncCallbackInfo->message.c_str(),
            NAPI_AUTO_LENGTH, &result[1]));
    } else {
        if (asyncCallbackInfo->ret) {
        result[0] = BusinessError::CreateError(env, 0, "");
            NAPI_CALL_RETURN_VOID(env, napi_create_array(env, &result[1]));
            ProcessApplicationInfos(env, result[1], asyncCallbackInfo->appInfos);
        } else {
        result[0] = BusinessError::CreateError(env, 1, "");
            NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
        }
    }
    if (asyncCallbackInfo->deferred) {
        if (asyncCallbackInfo->ret != NO_ERROR) {
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncCallbackInfo->deferred, result[1]));
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncCallbackInfo->deferred, result[0]));
        }
    } else {
        napi_value callback = nullptr;
        napi_value placeHolder = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->callback, &callback));
        NAPI_CALL_RETURN_VOID(env, napi_call_function(env, nullptr, callback,
            sizeof(result) / sizeof(result[0]), result, &placeHolder));
    }
    APP_LOGD("NAPI end");
}

napi_value GetAllApplicationInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI begin");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    APP_LOGI("argc = [%{public}zu]", argc);
    AsyncApplicationInfosCallbackInfo *asyncCallbackInfo = new (std::nothrow) AsyncApplicationInfosCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<AsyncApplicationInfosCallbackInfo> callbackPtr {asyncCallbackInfo};
    for (size_t i = 0; i < argc; ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if ((i == 0) && (valueType == napi_number)) {
            ParseInt(env, asyncCallbackInfo->flags, argv[i]);
            if (argc == ARGS_SIZE_ONE) {
                asyncCallbackInfo->userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
            }
        } else if ((i == ARGS_SIZE_ONE) && (valueType == napi_number)) {
            ParseInt(env, asyncCallbackInfo->userId, argv[i]);
        } else if ((i == ARGS_SIZE_ONE) && (valueType == napi_function)) {
            asyncCallbackInfo->userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
            NAPI_CALL(env, napi_create_reference(env, argv[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
        } else if ((i == ARGS_SIZE_TWO) && (valueType == napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, argv[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            break;
        } else {
            asyncCallbackInfo->err = PARAM_TYPE_ERROR;
            asyncCallbackInfo->message = TYPE_MISMATCH;
        }
    }

    if (argc == 0) {
        asyncCallbackInfo->err = PARAM_TYPE_ERROR;
        asyncCallbackInfo->message = TYPE_MISMATCH;
    }
    napi_value promise = nullptr;
    if (asyncCallbackInfo->callback == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncCallbackInfo->deferred, &promise));
    } else {
        NAPI_CALL(env, napi_get_undefined(env,  &promise));
    }

    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, NAPI_GET_APPLICATION_INFO, NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resource, GetAllApplicationInfoExec, GetAllApplicationInfoComplete,
        reinterpret_cast<void*>(asyncCallbackInfo), &asyncCallbackInfo->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
    callbackPtr.release();
    APP_LOGD("NAPI end");
    return promise;
}

void GetApplicationInfoExec(napi_env env, void *data)
{
    APP_LOGD("NAPI begin");
    AsyncApplicationInfoCallbackInfo* asyncCallbackInfo =
        reinterpret_cast<AsyncApplicationInfoCallbackInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    if (asyncCallbackInfo->err == NO_ERROR) {
        asyncCallbackInfo->ret = InnerGetApplicationInfo(asyncCallbackInfo->bundleName,
                                                         asyncCallbackInfo->flags,
                                                         asyncCallbackInfo->userId,
                                                         asyncCallbackInfo->appInfo);
    }
    APP_LOGD("NAPI end");
}

void GetApplicationInfoComplete(napi_env env, napi_status status, void *data)
{
    APP_LOGD("NAPI begin");
    AsyncApplicationInfoCallbackInfo* asyncCallbackInfo =
        reinterpret_cast<AsyncApplicationInfoCallbackInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<AsyncApplicationInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO] = { 0 };
    if (asyncCallbackInfo->err != NO_ERROR) {
        result[0] = BusinessError::CreateError(env, asyncCallbackInfo->err, "");
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, asyncCallbackInfo->message.c_str(),
            NAPI_AUTO_LENGTH, &result[1]));
    } else {
        if (asyncCallbackInfo->ret) {
            result[0] = BusinessError::CreateError(env, 0, "");
            NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result[1]));
            ConvertApplicationInfo(env, result[1], asyncCallbackInfo->appInfo);
        } else {
            result[0] = BusinessError::CreateError(env, 1, "");
            NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
        }
    }
    if (asyncCallbackInfo->deferred) {
        if (asyncCallbackInfo->ret) {
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncCallbackInfo->deferred, result[1]));
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncCallbackInfo->deferred, result[0]));
        }
    } else {
        napi_value callback = nullptr;
        napi_value placeHolder = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->callback, &callback));
        NAPI_CALL_RETURN_VOID(env, napi_call_function(env, nullptr, callback,
            sizeof(result) / sizeof(result[0]), result, &placeHolder));
    }
    APP_LOGD("NAPI end");
}

napi_value GetApplicationInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI begin");
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    APP_LOGD("argc = [%{public}zu]", argc);
    AsyncApplicationInfoCallbackInfo *asyncCallbackInfo = new (std::nothrow) AsyncApplicationInfoCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is nullptr");
        return nullptr;
    }
    std::unique_ptr<AsyncApplicationInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    for (size_t i = 0; i < argc; ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if ((i == 0) && (valueType == napi_string)) {
            ParseString(env, asyncCallbackInfo->bundleName, argv[i]);
        } else if ((i == ARGS_SIZE_ONE) && valueType == napi_number) {
            ParseInt(env, asyncCallbackInfo->flags, argv[i]);
            if (argc == ARGS_SIZE_TWO) {
                asyncCallbackInfo->userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
            }
        } else if ((i == ARGS_SIZE_TWO) && (valueType == napi_number)) {
            ParseInt(env, asyncCallbackInfo->userId, argv[i]);
        } else if ((i == ARGS_SIZE_TWO) && (valueType == napi_function)) {
            asyncCallbackInfo->userId = IPCSkeleton::GetCallingUid() / Constants::BASE_USER_RANGE;
            NAPI_CALL(env, napi_create_reference(env, argv[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
        } else if ((i == ARGS_SIZE_THREE) && (valueType == napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, argv[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            break;
        } else {
            asyncCallbackInfo->err = PARAM_TYPE_ERROR;
            asyncCallbackInfo->message = TYPE_MISMATCH;
        }
    }
    if (argc == 0) {
        asyncCallbackInfo->err = PARAM_TYPE_ERROR;
        asyncCallbackInfo->message = TYPE_MISMATCH;
    }
    napi_value promise = nullptr;
    if (asyncCallbackInfo->callback == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncCallbackInfo->deferred, &promise));
    } else {
        NAPI_CALL(env, napi_get_undefined(env,  &promise));
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, NAPI_GET_APPLICATION_INFO, NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resource, GetApplicationInfoExec, GetApplicationInfoComplete,
        reinterpret_cast<void*>(asyncCallbackInfo), &asyncCallbackInfo->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
    callbackPtr.release();
    APP_LOGD("NAPI end");
    return promise;
}

#ifdef BUNDLE_FRAMEWORK_GRAPHICS
void GetAbilityIconExec(napi_env env, void *data)
{
    APP_LOGD("NAPI begin");
    AbilityIconCallbackInfo *asyncCallbackInfo = reinterpret_cast<AbilityIconCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    if (asyncCallbackInfo->err != NO_ERROR) {
        APP_LOGE("asyncCallbackInfo->err is not NO_ERROR, but %{public}d", asyncCallbackInfo->err);
        return;
    }
    BundleGraphicsClient client;
    asyncCallbackInfo->ret = client.GetAbilityPixelMapIcon(asyncCallbackInfo->bundleName,
        asyncCallbackInfo->moduleName, asyncCallbackInfo->abilityName, asyncCallbackInfo->pixelMap);
    APP_LOGD("NAPI end");
}

void GetAbilityIconComplete(napi_env env, napi_status status, void *data)
{
    APP_LOGD("NAPI begin");
    AbilityIconCallbackInfo *asyncCallbackInfo = reinterpret_cast<AbilityIconCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<AbilityIconCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO] = {0};
    if (asyncCallbackInfo->err != NO_ERROR) {
        APP_LOGE("asyncCallbackInfo->err is %{public}d", asyncCallbackInfo->err);
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncCallbackInfo->err, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
    } else if (asyncCallbackInfo->ret != ERR_OK) {
        APP_LOGE("asyncCallbackInfo->ret is %{public}d", asyncCallbackInfo->ret);
        asyncCallbackInfo->err = OPERATION_FAILED;
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, OPERATION_FAILED, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, NO_ERROR, &result[0]));
        result[1] = Media::PixelMapNapi::CreatePixelMap(env, asyncCallbackInfo->pixelMap);
    }
    CommonFunc::NapiReturnDeferred<AbilityIconCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
    APP_LOGD("NAPI end");
}

napi_value GetAbilityIcon(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI begin");
    AbilityIconCallbackInfo *asyncCallbackInfo = new (std::nothrow) AbilityIconCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    asyncCallbackInfo->err = NO_ERROR;
    std::unique_ptr<AbilityIconCallbackInfo> callbackPtr {asyncCallbackInfo};
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_FOUR)) {
        APP_LOGE("parameters init failed");
        napi_value ret = nullptr;
        NAPI_CALL(env, napi_get_undefined(env, &ret));
        return ret;
    }
    asyncCallbackInfo->hasModuleName = false;
    napi_valuetype valueType = napi_undefined;
    napi_typeof(env, args[args.GetMaxArgc() - 1], &valueType);
    if (valueType == napi_function) {
        asyncCallbackInfo->hasModuleName = (args.GetMaxArgc() == ARGS_SIZE_FOUR) ? true : false;
    } else {
        asyncCallbackInfo->hasModuleName = (args.GetMaxArgc() == ARGS_SIZE_THREE) ? true : false;
    }
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], asyncCallbackInfo->bundleName)) {
        APP_LOGE("BundleName parse failed");
        asyncCallbackInfo->err = INVALID_PARAM;
    }
    if (asyncCallbackInfo->hasModuleName) {
        if (!CommonFunc::ParseString(env, args[ARGS_POS_ONE], asyncCallbackInfo->moduleName)) {
            APP_LOGE("ModuleName parse failed");
            asyncCallbackInfo->err = INVALID_PARAM;
        }
    } else {
        if (!CommonFunc::ParseString(env, args[ARGS_POS_ONE], asyncCallbackInfo->abilityName)) {
            APP_LOGE("AbilityName parse failed");
            asyncCallbackInfo->err = INVALID_PARAM;
        }
    }
    if (args.GetMaxArgc() >= ARGS_SIZE_THREE) {
        valueType = napi_undefined;
        napi_typeof(env, args[ARGS_POS_TWO], &valueType);
        if (valueType != napi_function) {
            if (!CommonFunc::ParseString(env, args[ARGS_POS_TWO], asyncCallbackInfo->abilityName)) {
                APP_LOGE("AbilityName parse failed");
                asyncCallbackInfo->err = INVALID_PARAM;
            }
        } else {
            NAPI_CALL(env, napi_create_reference(env, args[ARGS_POS_TWO],
                NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
        }
    }
    if (args.GetMaxArgc() >= ARGS_SIZE_FOUR) {
        valueType = napi_undefined;
        napi_typeof(env, args[ARGS_POS_THREE], &valueType);
        if (valueType == napi_function) {
            NAPI_CALL(env, napi_create_reference(env, args[ARGS_POS_THREE],
                NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
        }
    }
    
    auto promise = CommonFunc::AsyncCallNativeMethod<AbilityIconCallbackInfo>(
        env, asyncCallbackInfo, GET_ABILITY_ICON, GetAbilityIconExec, GetAbilityIconComplete);
    callbackPtr.release();
    APP_LOGD("NAPI end");
    return promise;
}
#else
void GetAbilityIconComplete(napi_env env, napi_status status, void *data)
{
    APP_LOGD("NAPI begin");
    AbilityIconCallbackInfo *asyncCallbackInfo = reinterpret_cast<AbilityIconCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<AbilityIconCallbackInfo> callbackPtr {asyncCallbackInfo};
    APP_LOGE("unsupported BundleManagerService feature");
    asyncCallbackInfo->err = UNSUPPORTED_FEATURE_ERRCODE;
    napi_value result[ARGS_SIZE_TWO] = {0};
    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, UNSUPPORTED_FEATURE_ERRCODE, &result[0]));
    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env,
        UNSUPPORTED_FEATURE_MESSAGE.c_str(), NAPI_AUTO_LENGTH, &result[1]));
    CommonFunc::NapiReturnDeferred<AbilityIconCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
    APP_LOGD("NAPI end");
}

napi_value GetAbilityIcon(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI begin");
    AbilityIconCallbackInfo *asyncCallbackInfo = new (std::nothrow) AbilityIconCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<AbilityIconCallbackInfo> callbackPtr {asyncCallbackInfo};

    auto promise = CommonFunc::AsyncCallNativeMethod<AbilityIconCallbackInfo>(
        env, asyncCallbackInfo, GET_BUNDLE_ARCHIVE_INFO, nullptr, GetAbilityIconComplete);
    callbackPtr.release();
    APP_LOGD("NAPI end");
    return promise;
}
#endif

void GetBundleArchiveInfoExec(napi_env env, void *data)
{
    APP_LOGD("NAPI begin");
    GetBundleArchiveInfoCallbackInfo *asyncCallbackInfo = reinterpret_cast<GetBundleArchiveInfoCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    if (asyncCallbackInfo->err != NO_ERROR) {
        APP_LOGE("asyncCallbackInfo->err is not NO_ERROR, but %{public}d", asyncCallbackInfo->err);
        return;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return;
    }
    APP_LOGD("start GetBundleArchiveInfo, hapFilePath %{public}s", asyncCallbackInfo->hapFilePath.c_str());
    asyncCallbackInfo->ret = iBundleMgr->GetBundleArchiveInfo(
        asyncCallbackInfo->hapFilePath, asyncCallbackInfo->flags, asyncCallbackInfo->bundleInfo);
    APP_LOGD("NAPI end");
}

void GetBundleArchiveInfoComplete(napi_env env, napi_status status, void *data)
{
    APP_LOGD("NAPI begin");
    GetBundleArchiveInfoCallbackInfo *asyncCallbackInfo = reinterpret_cast<GetBundleArchiveInfoCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<GetBundleArchiveInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO] = {0};
    if (asyncCallbackInfo->err != NO_ERROR) {
        APP_LOGE("asyncCallbackInfo->err is %{public}d", asyncCallbackInfo->err);
        result[0] = BusinessError::CreateError(env, asyncCallbackInfo->err, "type mismatch");
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
    } else if (!asyncCallbackInfo->ret) {
        APP_LOGE("asyncCallbackInfo->ret is %{public}d", asyncCallbackInfo->ret);
        asyncCallbackInfo->err = OPERATION_FAILED;
        result[0] = BusinessError::CreateError(env, OPERATION_FAILED, "GetBundleArchiveInfo falied");
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
    } else {
        result[0] = BusinessError::CreateError(env, NO_ERROR, "");
        napi_create_object(env, &result[1]);
        ConvertBundleInfo(env, result[1], asyncCallbackInfo->bundleInfo);
    }
    CommonFunc::NapiReturnDeferred<GetBundleArchiveInfoCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
    APP_LOGD("NAPI end");
}

napi_value GetBundleArchiveInfo(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI begin");
    NapiArg args(env, info);
    GetBundleArchiveInfoCallbackInfo *asyncCallbackInfo = new (std::nothrow) GetBundleArchiveInfoCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<GetBundleArchiveInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    asyncCallbackInfo->err = NO_ERROR;
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_THREE)) {
        APP_LOGE("parameters init failed");
        asyncCallbackInfo->err = PARAM_TYPE_ERROR;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if ((i == ARGS_POS_ZERO) && (valueType == napi_string)) {
            if (!CommonFunc::ParseString(env, args[i], asyncCallbackInfo->hapFilePath)) {
                APP_LOGE("hapFilePath %{public}s invalid", asyncCallbackInfo->hapFilePath.c_str());
                asyncCallbackInfo->err = PARAM_TYPE_ERROR;
            }
        } else if ((i == ARGS_POS_ONE) && (valueType == napi_number)) {
            if (!CommonFunc::ParseInt(env, args[i], asyncCallbackInfo->flags)) {
                APP_LOGE("flags %{public}d invalid", asyncCallbackInfo->flags);
                asyncCallbackInfo->err = PARAM_TYPE_ERROR;
            }
        } else if (i == ARGS_POS_TWO) {
            if (valueType == napi_function) {
                NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            }
            break;
        } else {
            APP_LOGE("parameters number error");
            asyncCallbackInfo->err = PARAM_TYPE_ERROR;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<GetBundleArchiveInfoCallbackInfo>(
        env, asyncCallbackInfo, GET_BUNDLE_ARCHIVE_INFO, GetBundleArchiveInfoExec, GetBundleArchiveInfoComplete);
    callbackPtr.release();
    APP_LOGD("NAPI end");
    return promise;
}

void GetLaunchWantForBundleExec(napi_env env, void *data)
{
    APP_LOGD("NAPI begin");
    LaunchWantCallbackInfo* asyncCallbackInfo = reinterpret_cast<LaunchWantCallbackInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    if (asyncCallbackInfo->err != NO_ERROR) {
        APP_LOGE("asyncCallbackInfo->err is not NO_ERROR, but %{public}d", asyncCallbackInfo->err);
        return;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return;
    }
    APP_LOGD("start GetLaunchWantForBundle, bundleName %{public}s", asyncCallbackInfo->bundleName.c_str());
    asyncCallbackInfo->ret = iBundleMgr->GetLaunchWantForBundle(
        asyncCallbackInfo->bundleName, asyncCallbackInfo->want, asyncCallbackInfo->userId);
    APP_LOGD("NAPI end");
}

void GetLaunchWantForBundleComplete(napi_env env, napi_status status, void *data)
{
    APP_LOGD("NAPI begin");
    LaunchWantCallbackInfo *asyncCallbackInfo = reinterpret_cast<LaunchWantCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<LaunchWantCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO] = {0};
    if (asyncCallbackInfo->err != NO_ERROR) {
        APP_LOGE("asyncCallbackInfo->err is %{public}d", asyncCallbackInfo->err);
        result[0] = BusinessError::CreateError(env, asyncCallbackInfo->err, TYPE_MISMATCH);
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
    } else if (asyncCallbackInfo->ret != ERR_OK) {
        APP_LOGE("asyncCallbackInfo->ret is %{public}d", asyncCallbackInfo->ret);
        asyncCallbackInfo->err = OPERATION_FAILED;
        result[0] = BusinessError::CreateError(env, OPERATION_FAILED, "GetLaunchWantForBundle falied");
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
    } else {
        result[0] = BusinessError::CreateError(env, NO_ERROR, "");
        NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result[1]));
        CommonFunc::ConvertWantInfo(env, result[1], asyncCallbackInfo->want);
    }
    CommonFunc::NapiReturnDeferred<LaunchWantCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
    APP_LOGD("NAPI end");
}

napi_value GetLaunchWantForBundle(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI begin");
    LaunchWantCallbackInfo *asyncCallbackInfo = new (std::nothrow) LaunchWantCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<LaunchWantCallbackInfo> callbackPtr {asyncCallbackInfo};
    asyncCallbackInfo->err = NO_ERROR;
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("parameters init failed");
        asyncCallbackInfo->err = PARAM_TYPE_ERROR;
        auto promise = CommonFunc::AsyncCallNativeMethod<LaunchWantCallbackInfo>(env,
            asyncCallbackInfo, IS_SET_APPLICATION_ENABLED, GetLaunchWantForBundleExec, GetLaunchWantForBundleComplete);
        callbackPtr.release();
        return promise;
    }
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], asyncCallbackInfo->bundleName)) {
        APP_LOGE("BundleName parse failed");
        asyncCallbackInfo->err = PARAM_TYPE_ERROR;
    }
    if (args.GetMaxArgc() >= ARGS_SIZE_TWO) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[ARGS_POS_ONE], &valueType);
        if (valueType == napi_function) {
            NAPI_CALL(env, napi_create_reference(env, args[ARGS_POS_ONE],
                NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
        }
    }
    
    auto promise = CommonFunc::AsyncCallNativeMethod<LaunchWantCallbackInfo>(
        env, asyncCallbackInfo, GET_LAUNCH_WANT_FOR_BUNDLE, GetLaunchWantForBundleExec, GetLaunchWantForBundleComplete);
    callbackPtr.release();
    APP_LOGD("NAPI end");
    return promise;
}

void IsAbilityEnabledExec(napi_env env, void *data)
{
    APP_LOGD("NAPI begin");
    AbilityEnableCallbackInfo *asyncCallbackInfo = reinterpret_cast<AbilityEnableCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    if (asyncCallbackInfo->err != NO_ERROR) {
        APP_LOGE("asyncCallbackInfo->err is not NO_ERROR, but %{public}d", asyncCallbackInfo->err);
        return;
    }
    auto bundleMgr = CommonFunc::GetBundleMgr();
    if (bundleMgr == nullptr) {
        APP_LOGE("CommonFunc::GetBundleMgr failed");
        return;
    }
    bundleMgr->IsAbilityEnabled(asyncCallbackInfo->abilityInfo, asyncCallbackInfo->isEnable);
    APP_LOGD("NAPI end");
}

void IsAbilityEnabledComplete(napi_env env, napi_status status, void *data)
{
    APP_LOGD("NAPI begin");
    AbilityEnableCallbackInfo *asyncCallbackInfo = reinterpret_cast<AbilityEnableCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<AbilityEnableCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO] = {0};
    if (asyncCallbackInfo->err != NO_ERROR) {
        APP_LOGE("asyncCallbackInfo->err is %{public}d", asyncCallbackInfo->err);
        result[0] = BusinessError::CreateError(env, asyncCallbackInfo->err, TYPE_MISMATCH);
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
    } else {
        result[0] = BusinessError::CreateError(env, NO_ERROR, "");
        NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, asyncCallbackInfo->isEnable, &result[1]));
    }
    CommonFunc::NapiReturnDeferred<AbilityEnableCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
    APP_LOGD("NAPI end");
}

napi_value IsAbilityEnabled(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI begin");
    AbilityEnableCallbackInfo *asyncCallbackInfo = new (std::nothrow) AbilityEnableCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<AbilityEnableCallbackInfo> callbackPtr {asyncCallbackInfo};
    asyncCallbackInfo->err = NO_ERROR;
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("parameters init failed");
        asyncCallbackInfo->err = INVALID_PARAM;
        auto promise = CommonFunc::AsyncCallNativeMethod<AbilityEnableCallbackInfo>(env,
            asyncCallbackInfo, IS_SET_APPLICATION_ENABLED, IsAbilityEnabledExec, IsAbilityEnabledComplete);
        callbackPtr.release();
        return promise;
    }
    if (!CommonFunc::ParseAbilityInfo(env, args[ARGS_POS_ZERO], asyncCallbackInfo->abilityInfo)) {
        APP_LOGE("AbilityInfo parse failed");
        asyncCallbackInfo->err = INVALID_PARAM;
    }
    if (args.GetMaxArgc() >= ARGS_SIZE_TWO) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[ARGS_POS_ONE], &valueType);
        if (valueType == napi_function) {
            NAPI_CALL(env, napi_create_reference(env, args[ARGS_POS_ONE],
            NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
        }
    }
    
    auto promise = CommonFunc::AsyncCallNativeMethod<AbilityEnableCallbackInfo>(
        env, asyncCallbackInfo, IS_ABILITY_ENABLED, IsAbilityEnabledExec, IsAbilityEnabledComplete);
    callbackPtr.release();
    APP_LOGD("NAPI end");
    return promise;
}

void IsApplicationEnabledExec(napi_env env, void *data)
{
    APP_LOGD("NAPI begin");
    ApplicationEnableCallbackInfo *asyncCallbackInfo = reinterpret_cast<ApplicationEnableCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    if (asyncCallbackInfo->err != NO_ERROR) {
        APP_LOGE("asyncCallbackInfo->err is not NO_ERROR, but %{public}d", asyncCallbackInfo->err);
        return;
    }
    auto bundleMgr = CommonFunc::GetBundleMgr();
    if (bundleMgr == nullptr) {
        APP_LOGE("CommonFunc::GetBundleMgr failed");
        return;
    }
    bundleMgr->IsApplicationEnabled(asyncCallbackInfo->bundleName, asyncCallbackInfo->isEnable);
    APP_LOGD("NAPI end");
}

void IsApplicationEnabledComplete(napi_env env, napi_status status, void *data)
{
    APP_LOGD("NAPI begin");
    ApplicationEnableCallbackInfo *asyncCallbackInfo = reinterpret_cast<ApplicationEnableCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return;
    }
    std::unique_ptr<ApplicationEnableCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO] = {0};
    if (asyncCallbackInfo->err != NO_ERROR) {
        APP_LOGE("asyncCallbackInfo->err is %{public}d", asyncCallbackInfo->err);
        result[0] = BusinessError::CreateError(env, asyncCallbackInfo->err, TYPE_MISMATCH);
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
    } else {
        result[0] = BusinessError::CreateError(env, NO_ERROR, "");
        NAPI_CALL_RETURN_VOID(env, napi_get_boolean(env, asyncCallbackInfo->isEnable, &result[1]));
    }
    CommonFunc::NapiReturnDeferred<ApplicationEnableCallbackInfo>(env, asyncCallbackInfo, result, ARGS_SIZE_TWO);
    APP_LOGD("NAPI end");
}

napi_value IsApplicationEnabled(napi_env env, napi_callback_info info)
{
    APP_LOGD("NAPI begin");
    ApplicationEnableCallbackInfo *asyncCallbackInfo = new (std::nothrow) ApplicationEnableCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is null");
        return nullptr;
    }
    std::unique_ptr<ApplicationEnableCallbackInfo> callbackPtr {asyncCallbackInfo};
    asyncCallbackInfo->err = NO_ERROR;
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_ONE, ARGS_SIZE_TWO)) {
        APP_LOGE("parameters init failed");
        asyncCallbackInfo->err = INVALID_PARAM;
        auto promise = CommonFunc::AsyncCallNativeMethod<ApplicationEnableCallbackInfo>(env,
            asyncCallbackInfo, IS_SET_APPLICATION_ENABLED, IsApplicationEnabledExec, IsApplicationEnabledComplete);
        callbackPtr.release();
        return promise;
    }
    if (!CommonFunc::ParseString(env, args[ARGS_POS_ZERO], asyncCallbackInfo->bundleName)) {
        APP_LOGE("BundleName parse failed");
        asyncCallbackInfo->err = INVALID_PARAM;
    }
    if (args.GetMaxArgc() >= ARGS_SIZE_TWO) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[ARGS_POS_ONE], &valueType);
        if (valueType == napi_function) {
            NAPI_CALL(env, napi_create_reference(env, args[ARGS_POS_ONE],
            NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
        }
    }
    
    auto promise = CommonFunc::AsyncCallNativeMethod<ApplicationEnableCallbackInfo>(env,
        asyncCallbackInfo, IS_SET_APPLICATION_ENABLED, IsApplicationEnabledExec, IsApplicationEnabledComplete);
    callbackPtr.release();
    APP_LOGD("NAPI end");
    return promise;
}

void GetBundleInfoExec(napi_env env, void *data)
{
    AsyncBundleInfoCallbackInfo* asyncCallbackInfo = reinterpret_cast<AsyncBundleInfoCallbackInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    if (asyncCallbackInfo->err == 0) {
        asyncCallbackInfo->ret = InnerGetBundleInfo(asyncCallbackInfo->env, asyncCallbackInfo->param,
            asyncCallbackInfo->flags, asyncCallbackInfo->bundleOptions, asyncCallbackInfo->bundleInfo);
    }
}

void GetBundleInfoForSelfExec(napi_env env, napi_status status, void* data)
{
    AsyncBundleInfoCallbackInfo* asyncCallbackInfo = reinterpret_cast<AsyncBundleInfoCallbackInfo*>(data);
    std::unique_ptr<AsyncBundleInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    napi_value result[2] = { 0 };
    if (asyncCallbackInfo->err != 0) {
        NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, static_cast<uint32_t>(asyncCallbackInfo->err),
            &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, asyncCallbackInfo->message.c_str(),
            NAPI_AUTO_LENGTH, &result[1]));
    } else {
        if (asyncCallbackInfo->ret) {
            NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, 0, &result[0]));
            NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result[1]));
            ConvertBundleInfo(env, result[1], asyncCallbackInfo->bundleInfo);
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, 1, &result[0]));
            NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
        }
    }
    if (asyncCallbackInfo->deferred) {
        if (asyncCallbackInfo->ret) {
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncCallbackInfo->deferred, result[1]));
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncCallbackInfo->deferred, result[0]));
        }
    } else {
        napi_value callback = nullptr;
        napi_value placeHolder = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->callback, &callback));
        NAPI_CALL_RETURN_VOID(env, napi_call_function(env, nullptr, callback,
            sizeof(result) / sizeof(result[0]), result, &placeHolder));
    }
}

napi_value GetBundleInfo(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = {nullptr};
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    APP_LOGD("argc = [%{public}zu]", argc);
    AsyncBundleInfoCallbackInfo *asyncCallbackInfo = new (std::nothrow) AsyncBundleInfoCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is nullptr");
        return nullptr;
    }
    std::unique_ptr<AsyncBundleInfoCallbackInfo> callbackPtr {asyncCallbackInfo};
    for (size_t i = 0; i < argc; ++i) {
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[i], &valueType));
        if ((i == PARAM0) && (valueType == napi_string)) {
            ParseString(env, asyncCallbackInfo->param, argv[i]);
        } else if ((i == PARAM1) && valueType == napi_number) {
            ParseInt(env, asyncCallbackInfo->flags, argv[i]);
        } else if ((i == PARAM2) && (valueType == napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, argv[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            break;
        } else if ((i == PARAM2) && (valueType == napi_object)) {
            bool ret = ParseBundleOptions(env, asyncCallbackInfo->bundleOptions, argv[i]);
            if (!ret) {
                asyncCallbackInfo->err = PARAM_TYPE_ERROR;
            }
        } else if ((i == PARAM3) && (valueType == napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, argv[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            break;
        } else {
            asyncCallbackInfo->err = PARAM_TYPE_ERROR;
            asyncCallbackInfo->message = TYPE_MISMATCH;
        }
    }

    auto promise = CommonFunc::AsyncCallNativeMethod<AsyncBundleInfoCallbackInfo>(
        env, asyncCallbackInfo, GET_BUNDLE_INFO, GetBundleInfoExec, GetBundleInfoForSelfExec);
    callbackPtr.release();
    return promise;
}

void GetBundleNameByUidExec(napi_env env, void *data)
{
    AsyncGetNameByUidInfo* asyncCallbackInfo =
        reinterpret_cast<AsyncGetNameByUidInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    if (asyncCallbackInfo->err == 0) {
        asyncCallbackInfo->ret = InnerGetNameForUid(asyncCallbackInfo->uid, asyncCallbackInfo->bundleName);
    }
}

void GetBundleNameByUidComplete(napi_env env, napi_status status, void *data)
{
    AsyncGetNameByUidInfo* asyncCallbackInfo =
        reinterpret_cast<AsyncGetNameByUidInfo*>(data);
    std::unique_ptr<AsyncGetNameByUidInfo> callbackPtr {asyncCallbackInfo};
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    napi_value result[ARGS_SIZE_TWO] = { 0 };
    // set error code
    if (asyncCallbackInfo->err) {
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncCallbackInfo->err, &result[PARAM0]));
    } else {
        if (!asyncCallbackInfo->ret) {
            NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, OPERATION_FAILED, &result[PARAM0]));
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, CODE_SUCCESS, &result[PARAM0]));
            NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, asyncCallbackInfo->bundleName.c_str(),
                NAPI_AUTO_LENGTH, &result[PARAM1]));
        }
    }
    // implement callback or promise
    if (asyncCallbackInfo->deferred) {
        if (!asyncCallbackInfo->ret) {
            NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncCallbackInfo->deferred, result[PARAM0]));
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncCallbackInfo->deferred, result[PARAM1]));
        }
    } else {
        napi_value callback = nullptr;
        napi_value placeHolder = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->callback, &callback));
        NAPI_CALL_RETURN_VOID(env, napi_call_function(env, nullptr, callback,
            sizeof(result) / sizeof(result[PARAM0]), result, &placeHolder));
    }
}

napi_value GetNameForUid(napi_env env, napi_callback_info info)
{
    size_t requireArgc = ARGS_SIZE_ONE;
    size_t argc = ARGS_SIZE_TWO;
    napi_value argv[ARGS_SIZE_TWO] = { 0 };
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    NAPI_ASSERT(env, argc >= requireArgc, "requires 1 parameter");
    AsyncGetNameByUidInfo *asyncCallbackInfo = new (std::nothrow) AsyncGetNameByUidInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is nullptr");
        return nullptr;
    }
    std::unique_ptr<AsyncGetNameByUidInfo> callbackPtr {asyncCallbackInfo};

    for (size_t i = 0; i < argc; ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, argv[i], &valueType);
        if ((i == 0) && (valueType == napi_number)) {
            ParseInt(env, asyncCallbackInfo->uid, argv[i]);
        } else if ((i == 1) && (valueType == napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, argv[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
        } else {
            asyncCallbackInfo->err = INVALID_PARAM;
        }
    }

    auto promise = CommonFunc::AsyncCallNativeMethod<AsyncGetNameByUidInfo>(
        env, asyncCallbackInfo, "GetNameForUid", GetBundleNameByUidExec, GetBundleNameByUidComplete);
    callbackPtr.release();
    APP_LOGD("call GetBundleNameByUid done");
    return promise;
}

static bool InnerGetAbilityInfo(const std::string &bundleName, const std::string &moduleName,
    const std::string &abilityName, AbilityInfo &abilityInfo, bool hasModuleName)
{
    auto iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return false;
    }
    if (hasModuleName) {
        return iBundleMgr->GetAbilityInfo(bundleName, moduleName, abilityName, abilityInfo);
    }
    return iBundleMgr->GetAbilityInfo(bundleName, abilityName, abilityInfo);
}

void StartGetAbilityInfoExecuteCB(napi_env env, void *data)
{
    AsyncAbilityInfosCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<AsyncAbilityInfosCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo == nullptr");
        return;
    }
    if (!asyncCallbackInfo->err) {
        asyncCallbackInfo->ret = InnerGetAbilityInfo(
            asyncCallbackInfo->bundleName, asyncCallbackInfo->moduleName,
            asyncCallbackInfo->abilityName, asyncCallbackInfo->abilityInfo,
            asyncCallbackInfo->hasModuleName);
    }
    APP_LOGD("end");
}

void StartGetAbilityInfoCompletedCB(napi_env env, napi_status status, void *data)
{
    AsyncAbilityInfosCallbackInfo *asyncCallbackInfo =
        reinterpret_cast<AsyncAbilityInfosCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    std::unique_ptr<AsyncAbilityInfosCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[2] = {0};
    if (asyncCallbackInfo->err) {
        NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, asyncCallbackInfo->err, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, asyncCallbackInfo->message.c_str(),
            NAPI_AUTO_LENGTH, &result[1]));
    } else {
        if (asyncCallbackInfo->ret) {
            NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, 0, &result[0]));
            NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result[1]));
            ConvertAbilityInfo(env, result[1], asyncCallbackInfo->abilityInfo);
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, 1, &result[0]));
            NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
        }
    }
    if (asyncCallbackInfo->deferred) {
        if (asyncCallbackInfo->ret) {
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncCallbackInfo->deferred, result[1]));
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncCallbackInfo->deferred, result[0]));
        }
    } else {
        napi_value callback = nullptr;
        napi_value placeHolder = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->callback, &callback));
        NAPI_CALL_RETURN_VOID(env, napi_call_function(env, nullptr, callback, sizeof(result) / sizeof(result[0]),
            result, &placeHolder));
    }
    APP_LOGD("end");
}

static bool HasModuleName(napi_env env, size_t argc, napi_value *argv)
{
    bool hasModuleName = false;
    if (argc > 0) {
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL_BASE(env, napi_typeof(env, argv[argc - 1], &valueType), false);
        if (valueType == napi_function) {
            hasModuleName = (argc == ARGS_SIZE_FOUR) ? true : false;
        } else {
            hasModuleName = (argc == ARGS_SIZE_THREE) ? true : false;
        }
    } else {
        APP_LOGD("error : argc < 0");
    }
    return hasModuleName;
}

napi_value GetAbilityInfo(napi_env env, napi_callback_info info)
{
    size_t requireArgc = ARGS_SIZE_TWO;
    size_t argc = ARGS_SIZE_FOUR;
    napi_value argv[ARGS_SIZE_FOUR] = { 0 };
    napi_value thisArg = nullptr;
    void *data = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    NAPI_ASSERT(env, argc >= requireArgc, "requires 2 parameter");
    AsyncAbilityInfosCallbackInfo *asyncCallbackInfo = new (std::nothrow) AsyncAbilityInfosCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGD("asyncCallbackInfo == nullptr");
        return nullptr;
    }
    std::unique_ptr<AsyncAbilityInfosCallbackInfo> callbackPtr {asyncCallbackInfo};
    asyncCallbackInfo->hasModuleName = HasModuleName(env, argc, argv);
    for (size_t i = 0; i < argc; ++i) {
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[i], &valueType));
        if ((i == PARAM0) && (valueType == napi_string)) {
            ParseString(env, asyncCallbackInfo->bundleName, argv[i]);
        } else if ((i == PARAM1) && (valueType == napi_string)) {
            if (asyncCallbackInfo->hasModuleName) {
                ParseString(env, asyncCallbackInfo->moduleName, argv[i]);
            } else {
                ParseString(env, asyncCallbackInfo->abilityName, argv[i]);
            }
        } else if ((i == PARAM2) && (valueType == napi_string)) {
            ParseString(env, asyncCallbackInfo->abilityName, argv[i]);
        } else if (((i == PARAM2) || (i == PARAM3)) && (valueType == napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, argv[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
        } else {
            asyncCallbackInfo->err = INVALID_PARAM;
            asyncCallbackInfo->message = TYPE_MISMATCH;
        }
    }

    napi_value promise = nullptr;
    if (asyncCallbackInfo->callback == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncCallbackInfo->deferred, &promise));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &promise));
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource,
              StartGetAbilityInfoExecuteCB, StartGetAbilityInfoCompletedCB,
              reinterpret_cast<void*>(asyncCallbackInfo), &asyncCallbackInfo->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
    callbackPtr.release();
    return promise;
}

AsyncAbilityLabelCallbackInfo *CreateAbilityLabelCallbackInfo(napi_env env)
{
    AsyncAbilityLabelCallbackInfo *asyncCallbackInfo = new (std::nothrow) AsyncAbilityLabelCallbackInfo(env);

    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo == nullptr");
        return nullptr;
    }

    APP_LOGD("end");
    return asyncCallbackInfo;
}

static std::string InnerGetAbilityLabel(napi_env env, std::string &bundleName, std::string &moduleName,
    std::string &abilityName, bool hasModuleName)
{
    auto iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return Constants::EMPTY_STRING;
    }
    if (!hasModuleName) {
        return iBundleMgr->GetAbilityLabel(bundleName, abilityName);
    }
    std::string label;
    ErrCode ret = iBundleMgr->GetAbilityLabel(bundleName, moduleName, abilityName, label);
    if (ret != ERR_OK) {
        APP_LOGE("can not GetAbilityLabel, bundleName is %{public}s", bundleName.c_str());
        return Constants::EMPTY_STRING;
    }
    return label;
}

void GetAbilityLabelPromiseComplete(napi_env env, napi_status status, void *data)
{
    APP_LOGD("NAPI_GetAbilityLabel, main event thread complete");
    AsyncAbilityLabelCallbackInfo *asyncCallbackInfo = static_cast<AsyncAbilityLabelCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    std::unique_ptr<AsyncAbilityLabelCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value result = nullptr;
    if (asyncCallbackInfo->err == NAPI_ERR_NO_ERROR) {
        NAPI_CALL_RETURN_VOID(
            env, napi_create_string_utf8(env, asyncCallbackInfo->abilityLabel.c_str(), NAPI_AUTO_LENGTH, &result));
        NAPI_CALL_RETURN_VOID(
            env, napi_resolve_deferred(env, asyncCallbackInfo->deferred, result));
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncCallbackInfo->err, &result));
        NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncCallbackInfo->deferred, result));
    }
    APP_LOGI("NAPI_GetAbilityLabel, main event thread complete end");
}

void GetAbilityLabelExecute(napi_env env, void *data)
{
    APP_LOGD("NAPI_GetAbilityLabel, worker pool thread execute");
    AsyncAbilityLabelCallbackInfo *asyncCallbackInfo = static_cast<AsyncAbilityLabelCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("NAPI_GetAbilityLabel, asyncCallbackInfo == nullptr");
        return;
    }
    if (!asyncCallbackInfo->err) {
        asyncCallbackInfo->abilityLabel =
        InnerGetAbilityLabel(env, asyncCallbackInfo->bundleName, asyncCallbackInfo->moduleName,
            asyncCallbackInfo->className, asyncCallbackInfo->hasModuleName);
        if (asyncCallbackInfo->abilityLabel == "") {
            asyncCallbackInfo->err = OPERATION_FAILED;
        }
    }
}

void GetAbilityLabelAsyncComplete(napi_env env, napi_status status, void *data)
{
    APP_LOGD("NAPI_GetAbilityLabel, main event thread complete");
    AsyncAbilityLabelCallbackInfo *asyncCallbackInfo = static_cast<AsyncAbilityLabelCallbackInfo *>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    std::unique_ptr<AsyncAbilityLabelCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value callback = nullptr;
    napi_value result[ARGS_SIZE_TWO] = {nullptr};
    napi_value callResult = nullptr;

    if (asyncCallbackInfo->err == NAPI_ERR_NO_ERROR) {
        NAPI_CALL_RETURN_VOID(env, napi_get_null(env, &result[PARAM0]));
        NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, asyncCallbackInfo->abilityLabel.c_str(),
            NAPI_AUTO_LENGTH, &result[PARAM1]));
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncCallbackInfo->err, &result[PARAM0]));
        result[PARAM1] = WrapUndefinedToJS(env);
    }

    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->callback, &callback));
    NAPI_CALL_RETURN_VOID(env,
        napi_call_function(env, nullptr, callback, sizeof(result) / sizeof(result[PARAM0]), result, &callResult));
    APP_LOGI("NAPI_GetAbilityLabel, main event thread complete end");
}

napi_value GetAbilityLabelAsync(
    napi_env env, AsyncAbilityLabelCallbackInfo *asyncCallbackInfo)
{
    if (asyncCallbackInfo == nullptr) {
        APP_LOGD("param == nullptr");
        return nullptr;
    }

    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));

    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName, GetAbilityLabelExecute,
            GetAbilityLabelAsyncComplete, reinterpret_cast<void*>(asyncCallbackInfo), &asyncCallbackInfo->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
    napi_value result = nullptr;
    NAPI_CALL(env, napi_get_null(env, &result));
    APP_LOGD("asyncCallback end");
    return result;
}

napi_value GetAbilityLabelPromise(napi_env env, AsyncAbilityLabelCallbackInfo *asyncCallbackInfo)
{
    if (asyncCallbackInfo == nullptr) {
        APP_LOGD("param == nullptr");
        return nullptr;
    }
    napi_value resourceName = nullptr;
    NAPI_CALL(env, napi_create_string_latin1(env, __func__, NAPI_AUTO_LENGTH, &resourceName));
    napi_deferred deferred;
    napi_value promise = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
    asyncCallbackInfo->deferred = deferred;

    NAPI_CALL(env, napi_create_async_work(env, nullptr, resourceName, GetAbilityLabelExecute,
                                          GetAbilityLabelPromiseComplete,
                                          reinterpret_cast<void*>(asyncCallbackInfo),
                                          &asyncCallbackInfo->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
    APP_LOGD("romise end");
    return promise;
}

napi_value GetAbilityLabelWrap(napi_env env, napi_callback_info info, AsyncAbilityLabelCallbackInfo *asyncCallbackInfo)
{
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo == nullptr");
        return nullptr;
    }

    size_t argcAsync = ARGS_SIZE_FOUR;
    const size_t argcPromise = ARGS_SIZE_THREE;
    const size_t argCountWithAsync = argcPromise + ARGS_ASYNC_COUNT;
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    napi_value ret = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, nullptr, nullptr));
    if (argcAsync > argCountWithAsync) {
        APP_LOGE("Wrong argument count");
        return nullptr;
    }
    asyncCallbackInfo->hasModuleName = HasModuleName(env, argcAsync, args);
    for (size_t i = 0; i < argcAsync; ++i) {
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, args[i], &valueType));
        if ((i == PARAM0) && (valueType == napi_string)) {
            ParseString(env, asyncCallbackInfo->bundleName, args[i]);
        } else if ((i == PARAM1) && (valueType == napi_string)) {
            if (asyncCallbackInfo->hasModuleName) {
                ParseString(env, asyncCallbackInfo->moduleName, args[i]);
            } else {
                ParseString(env, asyncCallbackInfo->className, args[i]);
            }
        } else if ((i == PARAM2) && (valueType == napi_string)) {
            ParseString(env, asyncCallbackInfo->className, args[i]);
        } else if (((i == PARAM2) || (i == PARAM3)) && (valueType == napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
        } else {
            asyncCallbackInfo->err = INVALID_PARAM;
            asyncCallbackInfo->message = TYPE_MISMATCH;
        }
    }
    if (asyncCallbackInfo->callback) {
        ret = GetAbilityLabelAsync(env, asyncCallbackInfo);
    } else {
        ret = GetAbilityLabelPromise(env, asyncCallbackInfo);
    }
    APP_LOGD("asyncCallback end");
    return ret;
}

napi_value GetAbilityLabel(napi_env env, napi_callback_info info)
{
    AsyncAbilityLabelCallbackInfo *asyncCallbackInfo = CreateAbilityLabelCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGD("asyncCallbackInfo == nullptr");
        return WrapVoidToJS(env);
    }
    std::unique_ptr<AsyncAbilityLabelCallbackInfo> callbackPtr {asyncCallbackInfo};
    napi_value ret = GetAbilityLabelWrap(env, info, asyncCallbackInfo);
    if (ret == nullptr) {
        APP_LOGD("ret == nullptr");
        ret = WrapVoidToJS(env);
    } else {
        callbackPtr.release();
    }
    APP_LOGD("end");
    return ret;
}

void SetApplicationEnabledExec(napi_env env, void *data)
{
    APP_LOGD("NAPI begin");
    EnabledInfo* asyncCallbackInfo =
        reinterpret_cast<EnabledInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGD("asyncCallbackInfo == nullptr");
        return;
    }
    if (!asyncCallbackInfo->errCode) {
        asyncCallbackInfo->result = InnerSetApplicationEnabled(asyncCallbackInfo->bundleName,
                                                               asyncCallbackInfo->isEnable);
        if (!asyncCallbackInfo->result) {
            asyncCallbackInfo->errCode = OPERATION_FAILED;
        }
    }
    APP_LOGD("NAPI end");
}

void SetApplicationEnabledComplete(napi_env env, napi_status status, void *data)
{
    APP_LOGD("NAPI begin");
    EnabledInfo* asyncCallbackInfo =
        reinterpret_cast<EnabledInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGD("asyncCallbackInfo == nullptr");
        return;
    }
    std::unique_ptr<EnabledInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_ONE] = { 0 };
    if (asyncCallbackInfo->errCode) {
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncCallbackInfo->errCode, &result[0]));
    }
    if (asyncCallbackInfo->callback) {
        napi_value callback = nullptr;
        napi_value placeHolder = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->callback, &callback));
        NAPI_CALL_RETURN_VOID(env, napi_call_function(env, nullptr, callback,
            sizeof(result) / sizeof(result[0]), result, &placeHolder));
    } else {
        if (asyncCallbackInfo->errCode) {
            NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncCallbackInfo->deferred, result[0]));
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[0]));
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncCallbackInfo->deferred, result[0]));
        }
    }
    APP_LOGD("NAPI end");
}

napi_value SetApplicationEnabled(napi_env env, napi_callback_info info)
{
    {
        std::lock_guard<std::mutex> lock(abilityInfoCacheMutex_);
        abilityInfoCache.clear();
    }
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = { 0 };
    napi_value thisArg = nullptr;
    void *data = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    if (argc > ARGS_SIZE_THREE || argc < ARGS_SIZE_TWO) {
        APP_LOGE("wrong number of arguments");
        return nullptr;
    }

    EnabledInfo *asyncCallbackInfo = new (std::nothrow) EnabledInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGD("asyncCallbackInfo == nullptr");
        return nullptr;
    }
    std::unique_ptr<EnabledInfo> callbackPtr {asyncCallbackInfo};
    asyncCallbackInfo->env = env;
    for (size_t i = 0; i < argc; ++i) {
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[i], &valueType));
        if ((i == PARAM0) && (valueType == napi_string)) {
            ParseString(env, asyncCallbackInfo->bundleName, argv[i]);
        } else if ((i == PARAM1) && (valueType == napi_boolean)) {
            bool isEnable = false;
            NAPI_CALL(env, napi_get_value_bool(env, argv[i], &isEnable));
            asyncCallbackInfo->isEnable = isEnable;
        } else if ((i == PARAM2) && (valueType == napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, argv[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
        } else {
            asyncCallbackInfo->errCode = INVALID_PARAM;
            asyncCallbackInfo->errMssage = TYPE_MISMATCH;
        }
    }
    napi_value promise = nullptr;

    if (asyncCallbackInfo->callback == nullptr) {
        NAPI_CALL(env, napi_create_promise(env, &asyncCallbackInfo->deferred, &promise));
    } else {
        NAPI_CALL(env, napi_get_undefined(env, &promise));
    }
    napi_value resource = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, "JSSetApplicationEnabled", NAPI_AUTO_LENGTH, &resource));
    NAPI_CALL(env, napi_create_async_work(
        env, nullptr, resource, SetApplicationEnabledExec, SetApplicationEnabledComplete,
        reinterpret_cast<void*>(asyncCallbackInfo), &asyncCallbackInfo->asyncWork));
    NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
    callbackPtr.release();
    return promise;
}

void SetAbilityEnabledExec(napi_env env, void *data)
{
    EnabledInfo* asyncCallbackInfo =
        reinterpret_cast<EnabledInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    if (!asyncCallbackInfo->errCode) {
        asyncCallbackInfo->result = InnerSetAbilityEnabled(asyncCallbackInfo->abilityInfo,
                                                           asyncCallbackInfo->isEnable);
        if (!asyncCallbackInfo->result) {
            asyncCallbackInfo->errCode = OPERATION_FAILED;
        }
    }
}

void SetAbilityEnabledComplete(napi_env env, napi_status status, void *data)
{
    EnabledInfo* asyncCallbackInfo =
        reinterpret_cast<EnabledInfo*>(data);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is nullptr");
        return;
    }
    std::unique_ptr<EnabledInfo> callbackPtr {asyncCallbackInfo};
    napi_value result[ARGS_SIZE_TWO] = { 0 };
    if (asyncCallbackInfo->errCode != ERR_OK) {
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncCallbackInfo->errCode, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
    } else if (!asyncCallbackInfo->result) {
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, OPERATION_FAILED, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &result[1]));
    } else {
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncCallbackInfo->errCode, &result[0]));
        NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncCallbackInfo->errCode, &result[1]));
    }

    if (asyncCallbackInfo->deferred) {
        if (asyncCallbackInfo->errCode == ERR_OK) {
            NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(env, asyncCallbackInfo->deferred, result[1]));
        } else {
            NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncCallbackInfo->deferred, result[0]));
        }
    } else {
        napi_value callback = nullptr;
        napi_value placeHolder = nullptr;
        NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->callback, &callback));
        NAPI_CALL_RETURN_VOID(env, napi_call_function(env, nullptr, callback, INVALID_PARAM, result, &placeHolder));
    }
}

napi_value SetAbilityEnabled(napi_env env, napi_callback_info info)
{
    {
        std::lock_guard<std::mutex> lock(abilityInfoCacheMutex_);
        abilityInfoCache.clear();
    }
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = { 0 };
    napi_value thisArg = nullptr;
    void* data = nullptr;

    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisArg, &data));
    if (argc > ARGS_SIZE_THREE || argc < ARGS_SIZE_TWO) {
        APP_LOGE("wrong number of arguments");
        return nullptr;
    }

    EnabledInfo* asyncCallbackInfo = new (std::nothrow) EnabledInfo(env);
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<EnabledInfo> callbackPtr {asyncCallbackInfo};
    asyncCallbackInfo->env = env;
    for (size_t i = 0; i < argc; ++i) {
        napi_valuetype valueType = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[i], &valueType));
        if ((i == PARAM0) && (valueType == napi_object)) {
            if (!UnwrapAbilityInfo(env, argv[i], asyncCallbackInfo->abilityInfo)) {
                asyncCallbackInfo->errCode = INVALID_PARAM;
                asyncCallbackInfo->errMssage = TYPE_MISMATCH;
            }
        } else if ((i == PARAM1) && (valueType == napi_boolean)) {
            NAPI_CALL(env, napi_get_value_bool(env, argv[i], &(asyncCallbackInfo->isEnable)));
        } else if ((i == PARAM2) && (valueType == napi_function)) {
            NAPI_CALL(env, napi_create_reference(env, argv[i], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));
            break;
        } else {
            asyncCallbackInfo->errCode = INVALID_PARAM;
            asyncCallbackInfo->errMssage = TYPE_MISMATCH;
        }
    }
    auto promise = CommonFunc::AsyncCallNativeMethod<EnabledInfo>(
        env, asyncCallbackInfo, "SetAbilityEnabled", SetAbilityEnabledExec, SetAbilityEnabledComplete);
    callbackPtr.release();
    return promise;
}

static void ConvertInstallResult(InstallResult &installResult)
{
    APP_LOGD("ConvertInstallResult = %{public}s", installResult.resultMsg.c_str());
    switch (installResult.resultCode) {
        case static_cast<int32_t>(IStatusReceiver::SUCCESS):
            installResult.resultCode = static_cast<int32_t>(InstallErrorCode::SUCCESS);
            installResult.resultMsg = "SUCCESS";
            break;
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_INTERNAL_ERROR):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_HOST_INSTALLER_FAILED):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_DISALLOWED):
            installResult.resultCode = static_cast<int32_t>(InstallErrorCode::STATUS_INSTALL_FAILURE);
            installResult.resultMsg = "STATUS_INSTALL_FAILURE";
            break;
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_PARSE_FAILED):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_VERIFICATION_FAILED):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_FAILED_INCOMPATIBLE_SIGNATURE):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_PARAM_ERROR):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_FILE_PATH_INVALID):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_INVALID_HAP_SIZE):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_INVALID_HAP_NAME):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_INVALID_BUNDLE_FILE):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_INVALID_NUMBER_OF_ENTRY_HAP):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_PARSE_UNEXPECTED):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_PARSE_MISSING_BUNDLE):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_PARSE_NO_PROFILE):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_PARSE_BAD_PROFILE):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_PARSE_PROFILE_PROP_TYPE_ERROR):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_PARSE_PROFILE_MISSING_PROP):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_PARSE_PERMISSION_ERROR):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_PARSE_RPCID_FAILED):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_PARSE_NATIVE_SO_FAILED):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_FAILED_INVALID_SIGNATURE_FILE_PATH):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_FAILED_BAD_BUNDLE_SIGNATURE_FILE):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_FAILED_NO_BUNDLE_SIGNATURE):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_FAILED_VERIFY_APP_PKCS7_FAIL):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_FAILED_PROFILE_PARSE_FAIL):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_FAILED_APP_SOURCE_NOT_TRUESTED):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_FAILED_BAD_DIGEST):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_FAILED_BUNDLE_INTEGRITY_VERIFICATION_FAILURE):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_FAILED_FILE_SIZE_TOO_LARGE):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_FAILED_BAD_PUBLICKEY):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_FAILED_BAD_BUNDLE_SIGNATURE):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_FAILED_NO_PROFILE_BLOCK_FAIL):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_FAILED_BUNDLE_SIGNATURE_VERIFICATION_FAILURE):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_FAILED_MODULE_NAME_EMPTY):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_FAILED_MODULE_NAME_DUPLICATE):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_FAILED_CHECK_HAP_HASH_PARAM):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_FAILED_VERIFY_SOURCE_INIT_FAIL):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_DEPENDENT_MODULE_NOT_EXIST):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_NATIVE_FAILED):
        case static_cast<int32_t>(IStatusReceiver::ERR_UNINSTALL_NATIVE_FAILED):
        case static_cast<int32_t>(IStatusReceiver::ERR_NATIVE_HNP_EXTRACT_FAILED):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_FAILED_DEBUG_NOT_SAME):
            installResult.resultCode = static_cast<int32_t>(InstallErrorCode::STATUS_INSTALL_FAILURE_INVALID);
            installResult.resultMsg = "STATUS_INSTALL_FAILURE_INVALID";
            break;
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_PARSE_MISSING_ABILITY):
            installResult.resultCode = static_cast<int32_t>(InstallErrorCode::STATUS_ABILITY_NOT_FOUND);
            installResult.resultMsg = "STATUS_ABILITY_NOT_FOUND";
            break;
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_VERSION_DOWNGRADE):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_FAILED_INCONSISTENT_SIGNATURE):
            installResult.resultCode = static_cast<int32_t>(InstallErrorCode::STATUS_INSTALL_FAILURE_INCOMPATIBLE);
            installResult.resultMsg = "STATUS_INSTALL_FAILURE_INCOMPATIBLE";
            break;
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_PERMISSION_DENIED):
            installResult.resultCode = static_cast<int32_t>(InstallErrorCode::STATUS_INSTALL_PERMISSION_DENIED);
            installResult.resultMsg = "STATUS_INSTALL_PERMISSION_DENIED";
            break;
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_ENTRY_ALREADY_EXIST):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_ALREADY_EXIST):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_BUNDLENAME_NOT_SAME):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_VERSIONCODE_NOT_SAME):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_VERSIONNAME_NOT_SAME):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_MINCOMPATIBLE_VERSIONCODE_NOT_SAME):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_VENDOR_NOT_SAME):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_RELEASETYPE_TARGET_NOT_SAME):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_RELEASETYPE_COMPATIBLE_NOT_SAME):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_SINGLETON_NOT_SAME):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_ZERO_USER_WITH_NO_SINGLETON):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_CHECK_SYSCAP_FAILED):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_APPTYPE_NOT_SAME):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_URI_DUPLICATE):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_VERSION_NOT_COMPATIBLE):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_APP_DISTRIBUTION_TYPE_NOT_SAME):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_APP_PROVISION_TYPE_NOT_SAME):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_SO_INCOMPATIBLE):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_TYPE_ERROR):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_NOT_UNIQUE_DISTRO_MODULE_NAME):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_SINGLETON_INCOMPATIBLE):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_INCONSISTENT_MODULE_NAME):
            installResult.resultCode = static_cast<int32_t>(InstallErrorCode::STATUS_INSTALL_FAILURE_CONFLICT);
            installResult.resultMsg = "STATUS_INSTALL_FAILURE_CONFLICT";
            break;
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALLD_PARAM_ERROR):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALLD_GET_PROXY_ERROR):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALLD_CREATE_DIR_FAILED):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALLD_SET_SELINUX_LABEL_FAILED):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALLD_CREATE_DIR_EXIST):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALLD_CHOWN_FAILED):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALLD_REMOVE_DIR_FAILED):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALLD_EXTRACT_FILES_FAILED):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALLD_RNAME_DIR_FAILED):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALLD_CLEAN_DIR_FAILED):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_STATE_ERROR):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_GENERATE_UID_ERROR):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_INSTALLD_SERVICE_ERROR):
            installResult.resultCode = static_cast<int32_t>(InstallErrorCode::STATUS_INSTALL_FAILURE_STORAGE);
            installResult.resultMsg = "STATUS_INSTALL_FAILURE_STORAGE";
            break;
        case static_cast<int32_t>(IStatusReceiver::ERR_UNINSTALL_PERMISSION_DENIED):
            installResult.resultCode = static_cast<int32_t>(InstallErrorCode::STATUS_UNINSTALL_PERMISSION_DENIED);
            installResult.resultMsg = "STATUS_UNINSTALL_PERMISSION_DENIED";
            break;
        case static_cast<int32_t>(IStatusReceiver::ERR_UNINSTALL_INVALID_NAME):
        case static_cast<int32_t>(IStatusReceiver::ERR_UNINSTALL_PARAM_ERROR):
            if (CheckIsSystemApp()) {
                installResult.resultCode = static_cast<int32_t>(InstallErrorCode::STATUS_UNINSTALL_FAILURE_ABORTED);
                installResult.resultMsg = "STATUS_UNINSTALL_FAILURE_ABORTED";
                break;
            }
            [[fallthrough]];
        case static_cast<int32_t>(IStatusReceiver::ERR_UNINSTALL_SYSTEM_APP_ERROR):
        case static_cast<int32_t>(IStatusReceiver::ERR_UNINSTALL_KILLING_APP_ERROR):
            if (CheckIsSystemApp()) {
                installResult.resultCode = static_cast<int32_t>(InstallErrorCode::STATUS_UNINSTALL_FAILURE_CONFLICT);
                installResult.resultMsg = "STATUS_UNINSTALL_FAILURE_CONFLICT";
                break;
            }
            [[fallthrough]];
        case static_cast<int32_t>(IStatusReceiver::ERR_UNINSTALL_BUNDLE_MGR_SERVICE_ERROR):
        case static_cast<int32_t>(IStatusReceiver::ERR_UNINSTALL_MISSING_INSTALLED_BUNDLE):
        case static_cast<int32_t>(IStatusReceiver::ERR_UNINSTALL_MISSING_INSTALLED_MODULE):
        case static_cast<int32_t>(IStatusReceiver::ERR_USER_NOT_INSTALL_HAP):
        case static_cast<int32_t>(IStatusReceiver::ERR_UNINSTALL_DISALLOWED):
            installResult.resultCode = static_cast<int32_t>(InstallErrorCode::STATUS_UNINSTALL_FAILURE);
            installResult.resultMsg = "STATUS_UNINSTALL_FAILURE";
            break;
        case static_cast<int32_t>(IStatusReceiver::ERR_RECOVER_GET_BUNDLEPATH_ERROR):
        case static_cast<int32_t>(IStatusReceiver::ERR_RECOVER_INVALID_BUNDLE_NAME):
        case static_cast<int32_t>(IStatusReceiver::ERR_RECOVER_NOT_ALLOWED):
            installResult.resultCode = static_cast<int32_t>(InstallErrorCode::STATUS_RECOVER_FAILURE_INVALID);
            installResult.resultMsg = "STATUS_RECOVER_FAILURE_INVALID";
            break;
        case static_cast<int32_t>(IStatusReceiver::ERR_FAILED_SERVICE_DIED):
        case static_cast<int32_t>(IStatusReceiver::ERR_FAILED_GET_INSTALLER_PROXY):
            installResult.resultCode = static_cast<int32_t>(InstallErrorCode::STATUS_BMS_SERVICE_ERROR);
            installResult.resultMsg = "STATUS_BMS_SERVICE_ERROR";
            break;
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_DISK_MEM_INSUFFICIENT):
            installResult.resultCode = static_cast<int32_t>(InstallErrorCode::STATUS_FAILED_NO_SPACE_LEFT);
            installResult.resultMsg = "STATUS_FAILED_NO_SPACE_LEFT";
            break;
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_GRANT_REQUEST_PERMISSIONS_FAILED):
        case static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_UPDATE_HAP_TOKEN_FAILED):
            installResult.resultCode = static_cast<int32_t>(InstallErrorCode::STATUS_GRANT_REQUEST_PERMISSIONS_FAILED);
            installResult.resultMsg = "STATUS_GRANT_REQUEST_PERMISSIONS_FAILED";
            break;
        case static_cast<int32_t>(IStatusReceiver::ERR_USER_NOT_EXIST):
            installResult.resultCode = static_cast<int32_t>(InstallErrorCode::STATUS_USER_NOT_EXIST);
            installResult.resultMsg = "STATUS_USER_NOT_EXIST";
            break;
        case static_cast<int32_t>(IStatusReceiver::ERR_USER_CREATE_FAILED):
            installResult.resultCode = static_cast<int32_t>(InstallErrorCode::STATUS_USER_CREATE_FAILED);
            installResult.resultMsg = "STATUS_USER_CREATE_FAILED";
            break;
        case static_cast<int32_t>(IStatusReceiver::ERR_USER_REMOVE_FAILED):
            installResult.resultCode = static_cast<int32_t>(InstallErrorCode::STATUS_USER_REMOVE_FAILED);
            installResult.resultMsg = "STATUS_USER_REMOVE_FAILED";
            break;
        default:
            installResult.resultCode = static_cast<int32_t>(InstallErrorCode::STATUS_BMS_SERVICE_ERROR);
            installResult.resultMsg = "STATUS_BMS_SERVICE_ERROR";
            break;
    }
}

static void InnerInstall(napi_env env, const std::vector<std::string> &bundleFilePath, InstallParam &installParam,
    InstallResult &installResult)
{
    if (bundleFilePath.empty()) {
        installResult.resultCode = static_cast<int32_t>(IStatusReceiver::ERR_INSTALL_FILE_PATH_INVALID);
        return;
    }
    auto iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return;
    }
    auto iBundleInstaller = iBundleMgr->GetBundleInstaller();
    if ((iBundleInstaller == nullptr) || (iBundleInstaller->AsObject() == nullptr)) {
        APP_LOGE("can not get iBundleInstaller");
        return;
    }

    if (installParam.installFlag == InstallFlag::NORMAL) {
        installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    }

    OHOS::sptr<InstallerCallback> callback = new (std::nothrow) InstallerCallback();
    if (callback == nullptr) {
        APP_LOGE("callback nullptr");
        return;
    }

    sptr<BundleDeathRecipient> recipient(new (std::nothrow) BundleDeathRecipient(callback));
    iBundleInstaller->AsObject()->AddDeathRecipient(recipient);
    ErrCode res = iBundleInstaller->StreamInstall(bundleFilePath, installParam, callback);
    if (res == ERR_APPEXECFWK_INSTALL_PARAM_ERROR) {
        APP_LOGE("install param error");
        installResult.resultCode = IStatusReceiver::ERR_INSTALL_PARAM_ERROR;
        installResult.resultMsg = "STATUS_INSTALL_FAILURE_INVALID";
    } else if (res == ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID) {
        APP_LOGE("install invalid path");
        installResult.resultCode = IStatusReceiver::ERR_INSTALL_FILE_PATH_INVALID;
        installResult.resultMsg = "STATUS_INSTALL_FAILURE_INVALID";
    } else if (res == ERR_APPEXECFWK_INSTALL_DISK_MEM_INSUFFICIENT) {
        APP_LOGE("install failed due to no space left");
        installResult.resultCode = IStatusReceiver::ERR_INSTALL_DISK_MEM_INSUFFICIENT;
        installResult.resultMsg = "STATUS_FAILED_NO_SPACE_LEFT";
    } else {
        installResult.resultCode = callback->GetResultCode();
        APP_LOGD("InnerInstall resultCode %{public}d", installResult.resultCode);
        installResult.resultMsg = callback->GetResultMsg();
        APP_LOGD("InnerInstall resultMsg %{public}s", installResult.resultMsg.c_str());
    }
}

/**
 * Promise and async callback
 */
napi_value GetBundleInstaller(napi_env env, napi_callback_info info)
{
    APP_LOGI("called");
    size_t argc = ARGS_SIZE_ONE;
    napi_value argv[ARGS_SIZE_ONE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    APP_LOGD("argc = [%{public}zu]", argc);

    AsyncGetBundleInstallerCallbackInfo *asyncCallbackInfo =
        new (std::nothrow) AsyncGetBundleInstallerCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("asyncCallbackInfo is nullptr");
        return nullptr;
    }
    std::unique_ptr<AsyncGetBundleInstallerCallbackInfo> callbackPtr {asyncCallbackInfo};
    if (argc > (ARGS_SIZE_ONE - CALLBACK_SIZE)) {
        APP_LOGI("GetBundleInstaller asyncCallback");
        napi_valuetype valuetype = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[PARAM0], &valuetype));
        NAPI_ASSERT(env, valuetype == napi_function, "Wrong argument type. Function expected");
        NAPI_CALL(env, napi_create_reference(env, argv[PARAM0], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));

        napi_value resourceName;
        NAPI_CALL(env, napi_create_string_latin1(env, "GetBundleInstaller", NAPI_AUTO_LENGTH, &resourceName));
        NAPI_CALL(env, napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {},
            [](napi_env env, napi_status status, void *data) {
                AsyncGetBundleInstallerCallbackInfo *asyncCallbackInfo =
                    reinterpret_cast<AsyncGetBundleInstallerCallbackInfo *>(data);
                if (asyncCallbackInfo == nullptr) {
                    APP_LOGE("asyncCallbackInfo is nullptr");
                    return;
                }
                std::unique_ptr<AsyncGetBundleInstallerCallbackInfo> callbackPtr {asyncCallbackInfo};
                napi_value result[ARGS_SIZE_TWO] = {0};
                napi_value callback = 0;
                napi_value undefined = 0;
                napi_value callResult = 0;
                napi_value m_classBundleInstaller = nullptr;
                if (VerifyCallingPermission(Constants::PERMISSION_INSTALL_BUNDLE) && VerifySystemApi()) {
                    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, g_classBundleInstaller,
                        &m_classBundleInstaller));
                    NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
                    NAPI_CALL_RETURN_VOID(env, napi_new_instance(
                        env, m_classBundleInstaller, 0, nullptr, &result[PARAM1]));

                    result[PARAM0] = GetCallbackErrorValue(env, CODE_SUCCESS);
                    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(
                        env, asyncCallbackInfo->callback, &callback));
                    NAPI_CALL_RETURN_VOID(env, napi_call_function(env, undefined, callback, ARGS_SIZE_TWO,
                        &result[PARAM0], &callResult));
                } else {
                    napi_value placeHolder = nullptr;
                    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, 1, &result[PARAM0]));
                    NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->callback, &callback));
                    NAPI_CALL_RETURN_VOID(env, napi_call_function(env, nullptr, callback,
                        sizeof(result) / sizeof(result[0]), result, &placeHolder));
                }
            },
            reinterpret_cast<void*>(asyncCallbackInfo),
            &asyncCallbackInfo->asyncWork));
        NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
        callbackPtr.release();
        napi_value result;
        napi_create_int32(env, NAPI_RETURN_ONE, &result);
        return result;
    } else {
        napi_deferred deferred;
        napi_value promise;
        NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->deferred = deferred;
        APP_LOGI("GetBundleInstaller promise");
        napi_value resourceName;
        NAPI_CALL(env, napi_create_string_latin1(env, "GetBundleInstaller", NAPI_AUTO_LENGTH, &resourceName));
        NAPI_CALL(env, napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) { APP_LOGI("GetBundleInstaller promise async done"); },
            [](napi_env env, napi_status status, void *data) {
                APP_LOGI("=================load=================");
                AsyncGetBundleInstallerCallbackInfo *asyncCallbackInfo =
                    reinterpret_cast<AsyncGetBundleInstallerCallbackInfo *>(data);
                if (asyncCallbackInfo == nullptr) {
                    APP_LOGE("asyncCallbackInfo is nullptr");
                    return;
                }
                std::unique_ptr<AsyncGetBundleInstallerCallbackInfo> callbackPtr {asyncCallbackInfo};
                napi_value result;
                napi_value m_classBundleInstaller = nullptr;
                if (VerifyCallingPermission(Constants::PERMISSION_INSTALL_BUNDLE) && VerifySystemApi()) {
                    napi_get_reference_value(env, g_classBundleInstaller, &m_classBundleInstaller);
                    napi_new_instance(env, m_classBundleInstaller, 0, nullptr, &result);
                    napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred, result);
                } else {
                    NAPI_CALL_RETURN_VOID(env, napi_create_uint32(env, 1, &result));
                    NAPI_CALL_RETURN_VOID(env, napi_reject_deferred(env, asyncCallbackInfo->deferred, result));
                }
            },
            reinterpret_cast<void*>(asyncCallbackInfo),
            &asyncCallbackInfo->asyncWork));
        NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
        callbackPtr.release();
        return promise;
    }
}

/**
 * Promise and async callback
 */
napi_value Install(napi_env env, napi_callback_info info)
{
    APP_LOGI("called");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    APP_LOGD("argc = [%{public}zu]", argc);
    AsyncInstallCallbackInfo *asyncCallbackInfo = new (std::nothrow) AsyncInstallCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncInstallCallbackInfo> callbackPtr {asyncCallbackInfo};

    std::vector<std::string> bundleFilePaths;
    InstallParam installParam;
    napi_value retFirst = nullptr;
    bool retSecond = true;
    retFirst = ParseStringArray(env, bundleFilePaths, argv[PARAM0]);
    retSecond = ParseInstallParam(env, installParam, argv[PARAM1]);
    if (retFirst == nullptr || !retSecond) {
        APP_LOGE("Install installParam error");
        asyncCallbackInfo->errCode = PARAM_TYPE_ERROR;
    }
    asyncCallbackInfo->hapFiles = bundleFilePaths;
    asyncCallbackInfo->installParam = installParam;
    if (argc > (ARGS_SIZE_THREE - CALLBACK_SIZE)) {
        APP_LOGI("Install asyncCallback");
        napi_valuetype valuetype = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[ARGS_SIZE_TWO], &valuetype));
        if (valuetype != napi_function) {
            APP_LOGE("Wrong argument type. Function expected");
            return nullptr;
        }
        NAPI_CALL(env, napi_create_reference(env, argv[ARGS_SIZE_TWO], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));

        napi_value resourceName;
        NAPI_CALL(env, napi_create_string_latin1(env, "Install", NAPI_AUTO_LENGTH, &resourceName));
        NAPI_CALL(env, napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                AsyncInstallCallbackInfo *asyncCallbackInfo = reinterpret_cast<AsyncInstallCallbackInfo *>(data);
                if (asyncCallbackInfo == nullptr) {
                    return;
                }
                if (!asyncCallbackInfo->errCode) {
                    InnerInstall(env,
                        asyncCallbackInfo->hapFiles,
                        asyncCallbackInfo->installParam,
                        asyncCallbackInfo->installResult);
                }
            },
            [](napi_env env, napi_status status, void *data) {
                AsyncInstallCallbackInfo *asyncCallbackInfo = reinterpret_cast<AsyncInstallCallbackInfo *>(data);
                if (asyncCallbackInfo == nullptr) {
                    return;
                }
                std::unique_ptr<AsyncInstallCallbackInfo> callbackPtr {asyncCallbackInfo};
                napi_value result[ARGS_SIZE_TWO] = {0};
                napi_value callback = 0;
                napi_value undefined = 0;
                napi_value callResult = 0;
                if (!asyncCallbackInfo->errCode) {
                    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result[PARAM1]));
                    ConvertInstallResult(asyncCallbackInfo->installResult);
                    napi_value nResultMsg;
                    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(
                        env, asyncCallbackInfo->installResult.resultMsg.c_str(), NAPI_AUTO_LENGTH, &nResultMsg));
                    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result[PARAM1], "statusMessage",
                        nResultMsg));
                    napi_value nResultCode;
                    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncCallbackInfo->installResult.resultCode,
                        &nResultCode));
                    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result[PARAM1], "status", nResultCode));
                    result[PARAM0] = GetCallbackErrorValue(
                        env, (asyncCallbackInfo->installResult.resultCode == 0) ? CODE_SUCCESS : CODE_FAILED);
                } else {
                    napi_value nResultMsg;
                    std::string msg = "error param type.";
                    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, msg.c_str(), NAPI_AUTO_LENGTH,
                        &nResultMsg));
                    result[PARAM0] = GetCallbackErrorValue(env, CODE_FAILED);
                    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result[PARAM0], "message", nResultMsg));
                }
                NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
                NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->callback, &callback));
                NAPI_CALL_RETURN_VOID(env, napi_call_function(env, undefined, callback, ARGS_SIZE_TWO,
                    &result[PARAM0], &callResult));
            },
            reinterpret_cast<void*>(asyncCallbackInfo),
            &asyncCallbackInfo->asyncWork));
        NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
        callbackPtr.release();
        napi_value result;
        napi_create_int32(env, NAPI_RETURN_ONE, &result);
        return result;
    } else {
        napi_deferred deferred;
        napi_value promise;
        NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->deferred = deferred;

        napi_value resourceName;
        NAPI_CALL(env, napi_create_string_latin1(env, "Install", NAPI_AUTO_LENGTH, &resourceName));
        NAPI_CALL(env, napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                AsyncInstallCallbackInfo *asyncCallbackInfo = reinterpret_cast<AsyncInstallCallbackInfo *>(data);
                if (asyncCallbackInfo == nullptr) {
                    return;
                }
                InnerInstall(env,
                    asyncCallbackInfo->hapFiles,
                    asyncCallbackInfo->installParam,
                    asyncCallbackInfo->installResult);
            },
            [](napi_env env, napi_status status, void *data) {
                AsyncInstallCallbackInfo *asyncCallbackInfo = reinterpret_cast<AsyncInstallCallbackInfo *>(data);
                if (asyncCallbackInfo == nullptr) {
                    return;
                }
                std::unique_ptr<AsyncInstallCallbackInfo> callbackPtr {asyncCallbackInfo};
                ConvertInstallResult(asyncCallbackInfo->installResult);
                napi_value result;
                NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result));
                napi_value nResultMsg;
                NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(
                    env, asyncCallbackInfo->installResult.resultMsg.c_str(), NAPI_AUTO_LENGTH, &nResultMsg));
                NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, "statusMessage", nResultMsg));
                napi_value nResultCode;
                NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncCallbackInfo->installResult.resultCode,
                    &nResultCode));
                NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, "status", nResultCode));
                NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred,
                    result));
            },
            reinterpret_cast<void*>(asyncCallbackInfo),
            &asyncCallbackInfo->asyncWork));
        NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
        callbackPtr.release();
        return promise;
    }
}

static void InnerRecover(napi_env env, const std::string &bundleName, InstallParam &installParam,
    InstallResult &installResult)
{
    if (bundleName.empty()) {
        installResult.resultCode = static_cast<int32_t>(IStatusReceiver::ERR_RECOVER_INVALID_BUNDLE_NAME);
        return;
    }
    auto iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return;
    }
    auto iBundleInstaller = iBundleMgr->GetBundleInstaller();
    if (iBundleInstaller == nullptr) {
        APP_LOGE("can not get iBundleInstaller");
        return;
    }

    OHOS::sptr<InstallerCallback> callback = new (std::nothrow) InstallerCallback();
    if (callback == nullptr) {
        APP_LOGE("callback nullptr");
        return;
    }
    iBundleInstaller->Recover(bundleName, installParam, callback);
    installResult.resultMsg = callback->GetResultMsg();
    APP_LOGD("InnerRecover resultMsg %{public}s", installResult.resultMsg.c_str());
    installResult.resultCode = callback->GetResultCode();
    APP_LOGD("InnerRecover resultCode %{public}d", installResult.resultCode);
}

napi_value Recover(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    APP_LOGD("argc = [%{public}zu]", argc);
    AsyncInstallCallbackInfo *asyncCallbackInfo = new (std::nothrow) AsyncInstallCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncInstallCallbackInfo> callbackPtr {asyncCallbackInfo};
    std::string bundleName;
    ParseString(env, bundleName, argv[PARAM0]);
    InstallParam installParam;
    if (!ParseInstallParam(env, installParam, argv[PARAM1])) {
        APP_LOGE("Recover installParam error, bundleName is %{public}s", bundleName.c_str());
        asyncCallbackInfo->errCode = PARAM_TYPE_ERROR;
    }

    asyncCallbackInfo->installParam = installParam;
    asyncCallbackInfo->bundleName = bundleName;
    if (argc > (ARGS_SIZE_THREE - CALLBACK_SIZE)) {
        APP_LOGD("Recover by bundleName asyncCallback");
        napi_valuetype valuetype = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[ARGS_SIZE_TWO], &valuetype));
        NAPI_ASSERT(env, valuetype == napi_function, "Wrong argument type. Function expected");
        NAPI_CALL(env, napi_create_reference(env, argv[ARGS_SIZE_TWO], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));

        napi_value resourceName;
        NAPI_CALL(env, napi_create_string_latin1(env, "Recover", NAPI_AUTO_LENGTH, &resourceName));
        NAPI_CALL(env, napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                AsyncInstallCallbackInfo *asyncCallbackInfo = reinterpret_cast<AsyncInstallCallbackInfo *>(data);
                if (asyncCallbackInfo == nullptr) {
                    return;
                }
                if (!asyncCallbackInfo->errCode) {
                    InnerRecover(env,
                        asyncCallbackInfo->bundleName,
                        asyncCallbackInfo->installParam,
                        asyncCallbackInfo->installResult);
                }
            },
            [](napi_env env, napi_status status, void *data) {
                AsyncInstallCallbackInfo *asyncCallbackInfo = reinterpret_cast<AsyncInstallCallbackInfo *>(data);
                if (asyncCallbackInfo == nullptr) {
                    return;
                }
                std::unique_ptr<AsyncInstallCallbackInfo> callbackPtr {asyncCallbackInfo};
                napi_value result[ARGS_SIZE_TWO] = {0};
                napi_value callback = 0;
                napi_value undefined = 0;
                napi_value callResult = 0;
                if (!asyncCallbackInfo->errCode) {
                    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result[PARAM1]));
                    ConvertInstallResult(asyncCallbackInfo->installResult);
                    napi_value nResultMsg;
                    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(
                        env, asyncCallbackInfo->installResult.resultMsg.c_str(), NAPI_AUTO_LENGTH, &nResultMsg));
                    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result[PARAM1], "statusMessage",
                        nResultMsg));
                    napi_value nResultCode;
                    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncCallbackInfo->installResult.resultCode,
                        &nResultCode));
                    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result[PARAM1], "status", nResultCode));
                    result[PARAM0] = GetCallbackErrorValue(
                        env, (asyncCallbackInfo->installResult.resultCode == 0) ? CODE_SUCCESS : CODE_FAILED);
                } else {
                    napi_value nResultMsg;
                    std::string msg = "error param type.";
                    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, msg.c_str(), NAPI_AUTO_LENGTH,
                        &nResultMsg));
                    result[PARAM0] = GetCallbackErrorValue(env, CODE_FAILED);
                    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result[PARAM0], "message", nResultMsg));
                }
                NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
                NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->callback, &callback));
                NAPI_CALL_RETURN_VOID(env, napi_call_function(env, undefined, callback, ARGS_SIZE_TWO,
                    &result[PARAM0], &callResult));
            },
            reinterpret_cast<void*>(asyncCallbackInfo),
            &asyncCallbackInfo->asyncWork));
        NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
        callbackPtr.release();
        napi_value result;
        napi_create_int32(env, NAPI_RETURN_ONE, &result);
        return result;
    } else {
        napi_deferred deferred;
        napi_value promise;
        NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->deferred = deferred;

        napi_value resourceName;
        NAPI_CALL(env, napi_create_string_latin1(env, "Recover", NAPI_AUTO_LENGTH, &resourceName));
        NAPI_CALL(env, napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                AsyncInstallCallbackInfo *asyncCallbackInfo = reinterpret_cast<AsyncInstallCallbackInfo *>(data);
                if (asyncCallbackInfo == nullptr) {
                    return;
                }
                InnerRecover(env,
                    asyncCallbackInfo->bundleName,
                    asyncCallbackInfo->installParam,
                    asyncCallbackInfo->installResult);
            },
            [](napi_env env, napi_status status, void *data) {
                AsyncInstallCallbackInfo *asyncCallbackInfo = reinterpret_cast<AsyncInstallCallbackInfo *>(data);
                if (asyncCallbackInfo == nullptr) {
                    return;
                }
                std::unique_ptr<AsyncInstallCallbackInfo> callbackPtr {asyncCallbackInfo};
                ConvertInstallResult(asyncCallbackInfo->installResult);
                napi_value result;
                NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result));
                napi_value nResultMsg;
                NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(
                    env, asyncCallbackInfo->installResult.resultMsg.c_str(), NAPI_AUTO_LENGTH, &nResultMsg));
                NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, "statusMessage", nResultMsg));
                napi_value nResultCode;
                NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncCallbackInfo->installResult.resultCode,
                    &nResultCode));
                NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, "status", nResultCode));
                NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred,
                    result));
            },
            reinterpret_cast<void*>(asyncCallbackInfo),
            &asyncCallbackInfo->asyncWork));
        NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
        callbackPtr.release();
        return promise;
    }
}

static void InnerUninstall(
    napi_env env, const std::string &bundleName, InstallParam &installParam, InstallResult &installResult)
{
    auto iBundleMgr = GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("can not get iBundleMgr");
        return;
    }
    auto iBundleInstaller = iBundleMgr->GetBundleInstaller();
    if ((iBundleInstaller == nullptr) || (iBundleInstaller->AsObject() == nullptr)) {
        APP_LOGE("can not get iBundleInstaller");
        return;
    }
    installParam.installFlag = InstallFlag::NORMAL;
    OHOS::sptr<InstallerCallback> callback = new (std::nothrow) InstallerCallback();
    if (callback == nullptr) {
        APP_LOGE("callback nullptr");
        return;
    }

    sptr<BundleDeathRecipient> recipient(new (std::nothrow) BundleDeathRecipient(callback));
    iBundleInstaller->AsObject()->AddDeathRecipient(recipient);
    iBundleInstaller->Uninstall(bundleName, installParam, callback);
    installResult.resultMsg = callback->GetResultMsg();
    APP_LOGD("-----InnerUninstall resultMsg %{public}s-----", installResult.resultMsg.c_str());
    installResult.resultCode = callback->GetResultCode();
    APP_LOGD("-----InnerUninstall resultCode %{public}d-----", installResult.resultCode);
}

/**
 * Promise and async callback
 */
napi_value Uninstall(napi_env env, napi_callback_info info)
{
    APP_LOGI("called");
    size_t argc = ARGS_SIZE_THREE;
    napi_value argv[ARGS_SIZE_THREE] = {nullptr};
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, NULL, NULL));
    APP_LOGD("argc = [%{public}zu]", argc);
    AsyncInstallCallbackInfo *asyncCallbackInfo = new (std::nothrow) AsyncInstallCallbackInfo(env);
    if (asyncCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncInstallCallbackInfo> callbackPtr {asyncCallbackInfo};
    std::string bundleName;
    ParseString(env, bundleName, argv[PARAM0]);
    InstallParam installParam;
    if (!ParseInstallParam(env, installParam, argv[PARAM1])) {
        APP_LOGE("Uninstall installParam error, bundleName is %{public}s", bundleName.c_str());
        asyncCallbackInfo->errCode = PARAM_TYPE_ERROR;
    }

    asyncCallbackInfo->installParam = installParam;
    asyncCallbackInfo->bundleName = bundleName;
    if (argc > (ARGS_SIZE_THREE - CALLBACK_SIZE)) {
        APP_LOGI("Uninstall asyncCallback");
        napi_valuetype valuetype = napi_undefined;
        NAPI_CALL(env, napi_typeof(env, argv[ARGS_SIZE_TWO], &valuetype));
        NAPI_ASSERT(env, valuetype == napi_function, "Wrong argument type. Function expected");
        NAPI_CALL(env, napi_create_reference(env, argv[ARGS_SIZE_TWO], NAPI_RETURN_ONE, &asyncCallbackInfo->callback));

        napi_value resourceName;
        NAPI_CALL(env, napi_create_string_latin1(env, "Uninstall", NAPI_AUTO_LENGTH, &resourceName));
        NAPI_CALL(env, napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                AsyncInstallCallbackInfo *asyncCallbackInfo = reinterpret_cast<AsyncInstallCallbackInfo *>(data);
                if (asyncCallbackInfo == nullptr) {
                    return;
                }
                if (!asyncCallbackInfo->errCode) {
                    InnerUninstall(env,
                        asyncCallbackInfo->bundleName,
                        asyncCallbackInfo->installParam,
                        asyncCallbackInfo->installResult);
                }
            },
            [](napi_env env, napi_status status, void *data) {
                AsyncInstallCallbackInfo *asyncCallbackInfo = reinterpret_cast<AsyncInstallCallbackInfo *>(data);
                if (asyncCallbackInfo == nullptr) {
                    return;
                }
                std::unique_ptr<AsyncInstallCallbackInfo> callbackPtr {asyncCallbackInfo};
                napi_value result[ARGS_SIZE_TWO] = {0};
                napi_value callback = 0;
                napi_value undefined = 0;
                napi_value callResult = 0;
                if (!asyncCallbackInfo->errCode) {
                    NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result[PARAM1]));
                    ConvertInstallResult(asyncCallbackInfo->installResult);
                    napi_value nResultMsg;
                    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(
                        env, asyncCallbackInfo->installResult.resultMsg.c_str(), NAPI_AUTO_LENGTH, &nResultMsg));
                    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result[PARAM1], "statusMessage",
                        nResultMsg));
                    napi_value nResultCode;
                    NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncCallbackInfo->installResult.resultCode,
                        &nResultCode));
                    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result[PARAM1], "status", nResultCode));
                    result[PARAM0] = GetCallbackErrorValue(
                        env, (asyncCallbackInfo->installResult.resultCode == 0) ? CODE_SUCCESS : CODE_FAILED);
                } else {
                    napi_value nResultMsg;
                    std::string msg = "error param type.";
                    NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(env, msg.c_str(), NAPI_AUTO_LENGTH,
                        &nResultMsg));
                    result[PARAM0] = GetCallbackErrorValue(env, CODE_FAILED);
                    NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result[PARAM0], "message", nResultMsg));
                }
                NAPI_CALL_RETURN_VOID(env, napi_get_undefined(env, &undefined));
                NAPI_CALL_RETURN_VOID(env, napi_get_reference_value(env, asyncCallbackInfo->callback, &callback));
                NAPI_CALL_RETURN_VOID(env, napi_call_function(env, undefined, callback, ARGS_SIZE_TWO,
                    &result[PARAM0], &callResult));
            },
            reinterpret_cast<void*>(asyncCallbackInfo),
            &asyncCallbackInfo->asyncWork));
        NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
        callbackPtr.release();
        napi_value result;
        napi_create_int32(env, NAPI_RETURN_ONE, &result);
        return result;
    } else {
        napi_deferred deferred;
        napi_value promise;
        NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
        asyncCallbackInfo->deferred = deferred;

        napi_value resourceName;
        NAPI_CALL(env, napi_create_string_latin1(env, "Install", NAPI_AUTO_LENGTH, &resourceName));
        NAPI_CALL(env, napi_create_async_work(
            env,
            nullptr,
            resourceName,
            [](napi_env env, void *data) {
                AsyncInstallCallbackInfo *asyncCallbackInfo = reinterpret_cast<AsyncInstallCallbackInfo *>(data);
                if (asyncCallbackInfo == nullptr) {
                    return;
                }
                InnerUninstall(
                    env, asyncCallbackInfo->param, asyncCallbackInfo->installParam, asyncCallbackInfo->installResult);
            },
            [](napi_env env, napi_status status, void *data) {
                AsyncInstallCallbackInfo *asyncCallbackInfo = reinterpret_cast<AsyncInstallCallbackInfo *>(data);
                if (asyncCallbackInfo == nullptr) {
                    return;
                }
                std::unique_ptr<AsyncInstallCallbackInfo> callbackPtr {asyncCallbackInfo};
                ConvertInstallResult(asyncCallbackInfo->installResult);
                napi_value result;
                NAPI_CALL_RETURN_VOID(env, napi_create_object(env, &result));
                napi_value nResultMsg;
                NAPI_CALL_RETURN_VOID(env, napi_create_string_utf8(
                    env, asyncCallbackInfo->installResult.resultMsg.c_str(), NAPI_AUTO_LENGTH, &nResultMsg));
                NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, "statusMessage", nResultMsg));
                napi_value nResultCode;
                NAPI_CALL_RETURN_VOID(env, napi_create_int32(env, asyncCallbackInfo->installResult.resultCode,
                    &nResultCode));
                NAPI_CALL_RETURN_VOID(env, napi_set_named_property(env, result, "status", nResultCode));
                NAPI_CALL_RETURN_VOID(env, napi_resolve_deferred(asyncCallbackInfo->env, asyncCallbackInfo->deferred,
                    result));
            },
            reinterpret_cast<void*>(asyncCallbackInfo),
            &asyncCallbackInfo->asyncWork));
        NAPI_CALL(env, napi_queue_async_work(env, asyncCallbackInfo->asyncWork));
        callbackPtr.release();
        return promise;
    }
}

napi_value BundleInstallerConstructor(napi_env env, napi_callback_info info)
{
    napi_value jsthis = nullptr;
    NAPI_CALL(env, napi_get_cb_info(env, info, nullptr, nullptr, &jsthis, nullptr));
    return jsthis;
}
}  // namespace AppExecFwk
}  // namespace OHOS