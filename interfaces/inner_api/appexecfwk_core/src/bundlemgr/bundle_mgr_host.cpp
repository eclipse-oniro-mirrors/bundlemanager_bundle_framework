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

#include "bundle_mgr_host.h"

#include <cinttypes>
#include <unistd.h>

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "hitrace_meter.h"
#include "datetime_ex.h"
#include "ipc_types.h"
#include "json_util.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const int32_t LIMIT_PARCEL_SIZE = 1024;
const int32_t ASHMEM_LEN = 16;

void SplitString(const std::string &source, std::vector<std::string> &strings)
{
    int splitSize = (source.size() / LIMIT_PARCEL_SIZE);
    if ((source.size() % LIMIT_PARCEL_SIZE) != 0) {
        splitSize++;
    }
    APP_LOGD("the dump string split into %{public}d size", splitSize);
    for (int i = 0; i < splitSize; i++) {
        int32_t start = LIMIT_PARCEL_SIZE * i;
        strings.emplace_back(source.substr(start, LIMIT_PARCEL_SIZE));
    }
}

inline void ClearAshmem(sptr<Ashmem> &optMem)
{
    if (optMem != nullptr) {
        optMem->UnmapAshmem();
        optMem->CloseAshmem();
    }
}
}  // namespace

BundleMgrHost::BundleMgrHost()
{
    APP_LOGD("create bundle manager host ");
    init();
}

void BundleMgrHost::init()
{
    funcMap_.emplace(IBundleMgr::Message::GET_APPLICATION_INFO, &BundleMgrHost::HandleGetApplicationInfo);
    funcMap_.emplace(IBundleMgr::Message::GET_APPLICATION_INFO_WITH_INT_FLAGS,
        &BundleMgrHost::HandleGetApplicationInfoWithIntFlags);
    funcMap_.emplace(IBundleMgr::Message::GET_APPLICATION_INFOS, &BundleMgrHost::HandleGetApplicationInfos);
    funcMap_.emplace(IBundleMgr::Message::GET_APPLICATION_INFO_WITH_INT_FLAGS_V9,
        &BundleMgrHost::HandleGetApplicationInfoWithIntFlagsV9);
    funcMap_.emplace(IBundleMgr::Message::GET_APPLICATION_INFOS_WITH_INT_FLAGS,
        &BundleMgrHost::HandleGetApplicationInfosWithIntFlags);
    funcMap_.emplace(IBundleMgr::Message::GET_APPLICATION_INFOS_WITH_INT_FLAGS_V9,
        &BundleMgrHost::HandleGetApplicationInfosWithIntFlagsV9);
    funcMap_.emplace(IBundleMgr::Message::GET_BUNDLE_INFO, &BundleMgrHost::HandleGetBundleInfo);
    funcMap_.emplace(IBundleMgr::Message::GET_BUNDLE_INFO_WITH_INT_FLAGS,
        &BundleMgrHost::HandleGetBundleInfoWithIntFlags);
    funcMap_.emplace(IBundleMgr::Message::GET_BUNDLE_INFO_WITH_INT_FLAGS_V9,
        &BundleMgrHost::HandleGetBundleInfoWithIntFlagsV9);
    funcMap_.emplace(IBundleMgr::Message::GET_BUNDLE_PACK_INFO, &BundleMgrHost::HandleGetBundlePackInfo);
    funcMap_.emplace(IBundleMgr::Message::GET_BUNDLE_PACK_INFO_WITH_INT_FLAGS,
        &BundleMgrHost::HandleGetBundlePackInfoWithIntFlags);
    funcMap_.emplace(IBundleMgr::Message::GET_BUNDLE_INFOS, &BundleMgrHost::HandleGetBundleInfos);
    funcMap_.emplace(IBundleMgr::Message::GET_BUNDLE_INFOS_WITH_INT_FLAGS,
        &BundleMgrHost::HandleGetBundleInfosWithIntFlags);
    funcMap_.emplace(IBundleMgr::Message::GET_BUNDLE_INFOS_WITH_INT_FLAGS_V9,
        &BundleMgrHost::HandleGetBundleInfosWithIntFlagsV9);
    funcMap_.emplace(IBundleMgr::Message::GET_BUNDLE_NAME_FOR_UID, &BundleMgrHost::HandleGetBundleNameForUid);
    funcMap_.emplace(IBundleMgr::Message::GET_BUNDLES_FOR_UID, &BundleMgrHost::HandleGetBundlesForUid);
    funcMap_.emplace(IBundleMgr::Message::GET_NAME_FOR_UID, &BundleMgrHost::HandleGetNameForUid);
    funcMap_.emplace(IBundleMgr::Message::GET_BUNDLE_GIDS, &BundleMgrHost::HandleGetBundleGids);
    funcMap_.emplace(IBundleMgr::Message::GET_BUNDLE_GIDS_BY_UID, &BundleMgrHost::HandleGetBundleGidsByUid);
    funcMap_.emplace(IBundleMgr::Message::GET_BUNDLE_INFOS_BY_METADATA,
        &BundleMgrHost::HandleGetBundleInfosByMetaData);
    funcMap_.emplace(IBundleMgr::Message::QUERY_ABILITY_INFO, &BundleMgrHost::HandleQueryAbilityInfo);
    funcMap_.emplace(IBundleMgr::Message::QUERY_ABILITY_INFO_MUTI_PARAM,
        &BundleMgrHost::HandleQueryAbilityInfoMutiparam);
    funcMap_.emplace(IBundleMgr::Message::QUERY_ABILITY_INFOS, &BundleMgrHost::HandleQueryAbilityInfos);
    funcMap_.emplace(IBundleMgr::Message::QUERY_ABILITY_INFOS_MUTI_PARAM,
        &BundleMgrHost::HandleQueryAbilityInfosMutiparam);
    funcMap_.emplace(IBundleMgr::Message::QUERY_ABILITY_INFOS_V9, &BundleMgrHost::HandleQueryAbilityInfosV9);
    funcMap_.emplace(IBundleMgr::Message::QUERY_ALL_ABILITY_INFOS, &BundleMgrHost::HandleQueryAllAbilityInfos);
    funcMap_.emplace(IBundleMgr::Message::QUERY_ABILITY_INFO_BY_URI, &BundleMgrHost::HandleQueryAbilityInfoByUri);
    funcMap_.emplace(IBundleMgr::Message::QUERY_ABILITY_INFOS_BY_URI, &BundleMgrHost::HandleQueryAbilityInfosByUri);
    funcMap_.emplace(IBundleMgr::Message::QUERY_ABILITY_INFO_BY_URI_FOR_USERID,
        &BundleMgrHost::HandleQueryAbilityInfoByUriForUserId);
    funcMap_.emplace(IBundleMgr::Message::QUERY_KEEPALIVE_BUNDLE_INFOS,
        &BundleMgrHost::HandleQueryKeepAliveBundleInfos);
    funcMap_.emplace(IBundleMgr::Message::GET_ABILITY_LABEL, &BundleMgrHost::HandleGetAbilityLabel);
    funcMap_.emplace(IBundleMgr::Message::GET_ABILITY_LABEL_WITH_MODULE_NAME,
        &BundleMgrHost::HandleGetAbilityLabelWithModuleName);
    funcMap_.emplace(IBundleMgr::Message::CHECK_IS_SYSTEM_APP_BY_UID, &BundleMgrHost::HandleCheckIsSystemAppByUid);
    funcMap_.emplace(IBundleMgr::Message::GET_BUNDLE_ARCHIVE_INFO, &BundleMgrHost::HandleGetBundleArchiveInfo);
    funcMap_.emplace(IBundleMgr::Message::GET_BUNDLE_ARCHIVE_INFO_WITH_INT_FLAGS,
        &BundleMgrHost::HandleGetBundleArchiveInfoWithIntFlags);
    funcMap_.emplace(IBundleMgr::Message::GET_BUNDLE_ARCHIVE_INFO_WITH_INT_FLAGS_V9,
        &BundleMgrHost::HandleGetBundleArchiveInfoWithIntFlagsV9);
    funcMap_.emplace(IBundleMgr::Message::GET_HAP_MODULE_INFO, &BundleMgrHost::HandleGetHapModuleInfo);
    funcMap_.emplace(IBundleMgr::Message::GET_LAUNCH_WANT_FOR_BUNDLE, &BundleMgrHost::HandleGetLaunchWantForBundle);
    funcMap_.emplace(IBundleMgr::Message::CHECK_PUBLICKEYS, &BundleMgrHost::HandleCheckPublicKeys);
    funcMap_.emplace(IBundleMgr::Message::GET_PERMISSION_DEF, &BundleMgrHost::HandleGetPermissionDef);
    funcMap_.emplace(IBundleMgr::Message::HAS_SYSTEM_CAPABILITY, &BundleMgrHost::HandleHasSystemCapability);
    funcMap_.emplace(IBundleMgr::Message::GET_SYSTEM_AVAILABLE_CAPABILITIES,
        &BundleMgrHost::HandleGetSystemAvailableCapabilities);
    funcMap_.emplace(IBundleMgr::Message::IS_SAFE_MODE, &BundleMgrHost::HandleIsSafeMode);
    funcMap_.emplace(IBundleMgr::Message::CLEAN_BUNDLE_CACHE_FILES, &BundleMgrHost::HandleCleanBundleCacheFiles);
    funcMap_.emplace(IBundleMgr::Message::CLEAN_BUNDLE_DATA_FILES, &BundleMgrHost::HandleCleanBundleDataFiles);
    funcMap_.emplace(IBundleMgr::Message::REGISTER_BUNDLE_STATUS_CALLBACK,
        &BundleMgrHost::HandleRegisterBundleStatusCallback);
    funcMap_.emplace(IBundleMgr::Message::REGISTER_BUNDLE_EVENT_CALLBACK,
        &BundleMgrHost::HandleRegisterBundleEventCallback);
    funcMap_.emplace(IBundleMgr::Message::UNREGISTER_BUNDLE_EVENT_CALLBACK,
        &BundleMgrHost::HandleUnregisterBundleEventCallback);
    funcMap_.emplace(IBundleMgr::Message::CLEAR_BUNDLE_STATUS_CALLBACK,
        &BundleMgrHost::HandleClearBundleStatusCallback);
    funcMap_.emplace(IBundleMgr::Message::UNREGISTER_BUNDLE_STATUS_CALLBACK,
        &BundleMgrHost::HandleUnregisterBundleStatusCallback);
    funcMap_.emplace(IBundleMgr::Message::IS_APPLICATION_ENABLED, &BundleMgrHost::HandleIsApplicationEnabled);
    funcMap_.emplace(IBundleMgr::Message::SET_APPLICATION_ENABLED, &BundleMgrHost::HandleSetApplicationEnabled);
    funcMap_.emplace(IBundleMgr::Message::IS_ABILITY_ENABLED, &BundleMgrHost::HandleIsAbilityEnabled);
    funcMap_.emplace(IBundleMgr::Message::SET_ABILITY_ENABLED, &BundleMgrHost::HandleSetAbilityEnabled);
    funcMap_.emplace(IBundleMgr::Message::GET_ABILITY_INFO, &BundleMgrHost::HandleGetAbilityInfo);
    funcMap_.emplace(IBundleMgr::Message::GET_ABILITY_INFO_WITH_MODULE_NAME,
        &BundleMgrHost::HandleGetAbilityInfoWithModuleName);
    funcMap_.emplace(IBundleMgr::Message::DUMP_INFOS, &BundleMgrHost::HandleDumpInfos);
    funcMap_.emplace(IBundleMgr::Message::GET_BUNDLE_INSTALLER, &BundleMgrHost::HandleGetBundleInstaller);
    funcMap_.emplace(IBundleMgr::Message::GET_ALL_FORMS_INFO, &BundleMgrHost::HandleGetAllFormsInfo);
    funcMap_.emplace(IBundleMgr::Message::GET_FORMS_INFO_BY_APP, &BundleMgrHost::HandleGetFormsInfoByApp);
    funcMap_.emplace(IBundleMgr::Message::GET_FORMS_INFO_BY_MODULE, &BundleMgrHost::HandleGetFormsInfoByModule);
    funcMap_.emplace(IBundleMgr::Message::GET_SHORTCUT_INFO, &BundleMgrHost::HandleGetShortcutInfos);
    funcMap_.emplace(IBundleMgr::Message::GET_SHORTCUT_INFO_V9, &BundleMgrHost::HandleGetShortcutInfoV9);
    funcMap_.emplace(IBundleMgr::Message::GET_ALL_COMMON_EVENT_INFO, &BundleMgrHost::HandleGetAllCommonEventInfo);
    funcMap_.emplace(IBundleMgr::Message::GET_BUNDLE_USER_MGR, &BundleMgrHost::HandleGetBundleUserMgr);
    funcMap_.emplace(IBundleMgr::Message::GET_DISTRIBUTE_BUNDLE_INFO, &BundleMgrHost::HandleGetDistributedBundleInfo);
    funcMap_.emplace(IBundleMgr::Message::GET_APPLICATION_PRIVILEGE_LEVEL, &BundleMgrHost::HandleGetAppPrivilegeLevel);
    funcMap_.emplace(IBundleMgr::Message::QUERY_EXTENSION_INFO_WITHOUT_TYPE,
        &BundleMgrHost::HandleQueryExtAbilityInfosWithoutType);
    funcMap_.emplace(IBundleMgr::Message::QUERY_EXTENSION_INFO_WITHOUT_TYPE_V9,
        &BundleMgrHost::HandleQueryExtAbilityInfosWithoutTypeV9);
    funcMap_.emplace(IBundleMgr::Message::QUERY_EXTENSION_INFO, &BundleMgrHost::HandleQueryExtAbilityInfos);
    funcMap_.emplace(IBundleMgr::Message::QUERY_EXTENSION_INFO_V9, &BundleMgrHost::HandleQueryExtAbilityInfosV9);
    funcMap_.emplace(IBundleMgr::Message::QUERY_EXTENSION_INFO_BY_TYPE,
        &BundleMgrHost::HandleQueryExtAbilityInfosByType);
    funcMap_.emplace(IBundleMgr::Message::VERIFY_CALLING_PERMISSION, &BundleMgrHost::HandleVerifyCallingPermission);
    funcMap_.emplace(IBundleMgr::Message::GET_ACCESSIBLE_APP_CODE_PATH,
        &BundleMgrHost::HandleGetAccessibleAppCodePaths);
    funcMap_.emplace(IBundleMgr::Message::QUERY_EXTENSION_ABILITY_INFO_BY_URI,
        &BundleMgrHost::HandleQueryExtensionAbilityInfoByUri);
    funcMap_.emplace(IBundleMgr::Message::GET_APPID_BY_BUNDLE_NAME, &BundleMgrHost::HandleGetAppIdByBundleName);
    funcMap_.emplace(IBundleMgr::Message::GET_APP_TYPE, &BundleMgrHost::HandleGetAppType);
    funcMap_.emplace(IBundleMgr::Message::GET_UID_BY_BUNDLE_NAME, &BundleMgrHost::HandleGetUidByBundleName);
    funcMap_.emplace(IBundleMgr::Message::IS_MODULE_REMOVABLE, &BundleMgrHost::HandleIsModuleRemovable);
    funcMap_.emplace(IBundleMgr::Message::SET_MODULE_REMOVABLE, &BundleMgrHost::HandleSetModuleRemovable);
    funcMap_.emplace(IBundleMgr::Message::QUERY_ABILITY_INFO_WITH_CALLBACK,
        &BundleMgrHost::HandleQueryAbilityInfoWithCallback);
    funcMap_.emplace(IBundleMgr::Message::UPGRADE_ATOMIC_SERVICE, &BundleMgrHost::HandleUpgradeAtomicService);
    funcMap_.emplace(IBundleMgr::Message::IS_MODULE_NEED_UPDATE, &BundleMgrHost::HandleGetModuleUpgradeFlag);
    funcMap_.emplace(IBundleMgr::Message::SET_MODULE_NEED_UPDATE, &BundleMgrHost::HandleSetModuleUpgradeFlag);
    funcMap_.emplace(IBundleMgr::Message::GET_HAP_MODULE_INFO_WITH_USERID,
        &BundleMgrHost::HandleGetHapModuleInfoWithUserId);
    funcMap_.emplace(IBundleMgr::Message::IMPLICIT_QUERY_INFO_BY_PRIORITY,
        &BundleMgrHost::HandleImplicitQueryInfoByPriority);
    funcMap_.emplace(IBundleMgr::Message::IMPLICIT_QUERY_INFOS,
        &BundleMgrHost::HandleImplicitQueryInfos);
    funcMap_.emplace(IBundleMgr::Message::GET_ALL_DEPENDENT_MODULE_NAMES,
        &BundleMgrHost::HandleGetAllDependentModuleNames);
    funcMap_.emplace(IBundleMgr::Message::GET_SANDBOX_APP_BUNDLE_INFO, &BundleMgrHost::HandleGetSandboxBundleInfo);
    funcMap_.emplace(IBundleMgr::Message::SET_DISPOSED_STATUS, &BundleMgrHost::HandleSetDisposedStatus);
    funcMap_.emplace(IBundleMgr::Message::GET_DISPOSED_STATUS, &BundleMgrHost::HandleGetDisposedStatus);
    funcMap_.emplace(IBundleMgr::Message::QUERY_CALLING_BUNDLE_NAME, &BundleMgrHost::HandleObtainCallingBundleName);
    funcMap_.emplace(IBundleMgr::Message::GET_BUNDLE_STATS, &BundleMgrHost::HandleGetBundleStats);
    funcMap_.emplace(IBundleMgr::Message::CHECK_ABILITY_ENABLE_INSTALL,
        &BundleMgrHost::HandleCheckAbilityEnableInstall);
    funcMap_.emplace(IBundleMgr::Message::GET_STRING_BY_ID, &BundleMgrHost::HandleGetStringById);
    funcMap_.emplace(IBundleMgr::Message::GET_ICON_BY_ID, &BundleMgrHost::HandleGetIconById);
#ifdef BUNDLE_FRAMEWORK_DEFAULT_APP
    funcMap_.emplace(IBundleMgr::Message::GET_DEFAULT_APP_PROXY, &BundleMgrHost::HandleGetDefaultAppProxy);
#endif
    funcMap_.emplace(IBundleMgr::Message::GET_SANDBOX_APP_ABILITY_INFO, &BundleMgrHost::HandleGetSandboxAbilityInfo);
    funcMap_.emplace(IBundleMgr::Message::GET_SANDBOX_APP_EXTENSION_INFOS,
        &BundleMgrHost::HandleGetSandboxExtAbilityInfos);
    funcMap_.emplace(IBundleMgr::Message::GET_SANDBOX_MODULE_INFO, &BundleMgrHost::HandleGetSandboxHapModuleInfo);
    funcMap_.emplace(IBundleMgr::Message::GET_MEDIA_DATA, &BundleMgrHost::HandleGetMediaData);
    funcMap_.emplace(IBundleMgr::Message::GET_QUICK_FIX_MANAGER_PROXY, &BundleMgrHost::HandleGetQuickFixManagerProxy);
    funcMap_.emplace(IBundleMgr::Message::GET_UDID_BY_NETWORK_ID, &BundleMgrHost::HandleGetUdidByNetworkId);
#ifdef BUNDLE_FRAMEWORK_APP_CONTROL
    funcMap_.emplace(IBundleMgr::Message::GET_APP_CONTROL_PROXY, &BundleMgrHost::HandleGetAppControlProxy);
#endif
    funcMap_.emplace(IBundleMgr::Message::SET_DEBUG_MODE, &BundleMgrHost::HandleSetDebugMode);
    funcMap_.emplace(IBundleMgr::Message::GET_BUNDLE_INFO_FOR_SELF, &BundleMgrHost::HandleGetBundleInfoForSelf);
    funcMap_.emplace(IBundleMgr::Message::VERIFY_SYSTEM_API, &BundleMgrHost::HandleVerifySystemApi);
    funcMap_.emplace(IBundleMgr::Message::PROCESS_PRELOAD, &BundleMgrHost::HandleProcessPreload);
    funcMap_.emplace(IBundleMgr::Message::GET_PROVISION_METADATA, &BundleMgrHost::HandleGetProvisionMetadata);
    funcMap_.emplace(IBundleMgr::Message::SILENT_INSTALL, &BundleMgrHost::HandleSilentInstall);
    funcMap_.emplace(IBundleMgr::Message::GET_UID_BY_DEBUG_BUNDLE_NAME, &BundleMgrHost::HandleGetUidByDebugBundleName);
}

int BundleMgrHost::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    APP_LOGD("bundle mgr host onReceived message, the message code is %{public}u", code);
    std::u16string descripter = BundleMgrHost::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (descripter != remoteDescripter) {
        APP_LOGE("fail to write reply message in bundle mgr host due to the reply is nullptr");
        return OBJECT_NULL;
    }

    ErrCode errCode = ERR_OK;
    if (funcMap_.find(code) != funcMap_.end() && funcMap_[code] != nullptr) {
        errCode = (this->*funcMap_[code])(data, reply);
    } else {
        APP_LOGW("bundlemgr host receives unknown code, code = %{public}u", code);
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    APP_LOGD("bundlemgr host finish to process message");
    return (errCode == ERR_OK) ? NO_ERROR : UNKNOWN_ERROR;
}

ErrCode BundleMgrHost::HandleGetApplicationInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string name = data.ReadString();
    ApplicationFlag flag = static_cast<ApplicationFlag>(data.ReadInt32());
    int userId = data.ReadInt32();
    APP_LOGI("name %{public}s, flag %{public}d, userId %{public}d", name.c_str(), flag, userId);

    ApplicationInfo info;
    bool ret = GetApplicationInfo(name, flag, userId, info);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!reply.WriteParcelable(&info)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetApplicationInfoWithIntFlags(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string name = data.ReadString();
    int flags = data.ReadInt32();
    int userId = data.ReadInt32();
    APP_LOGD("name %{public}s, flags %{public}d, userId %{public}d", name.c_str(), flags, userId);

    ApplicationInfo info;
    bool ret = GetApplicationInfo(name, flags, userId, info);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!reply.WriteParcelable(&info)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetApplicationInfoWithIntFlagsV9(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string name = data.ReadString();
    int32_t flags = data.ReadInt32();
    int32_t userId = data.ReadInt32();
    APP_LOGD("name %{public}s, flags %{public}d, userId %{public}d", name.c_str(), flags, userId);

    ApplicationInfo info;
    auto ret = GetApplicationInfoV9(name, flags, userId, info);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        if (!reply.WriteParcelable(&info)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetApplicationInfos(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    ApplicationFlag flag = static_cast<ApplicationFlag>(data.ReadInt32());
    int userId = data.ReadInt32();
    std::vector<ApplicationInfo> infos;
    bool ret = GetApplicationInfos(flag, userId, infos);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!WriteParcelableVector(infos, reply)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetApplicationInfosWithIntFlags(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    int flags = data.ReadInt32();
    int userId = data.ReadInt32();
    std::vector<ApplicationInfo> infos;
    bool ret = GetApplicationInfos(flags, userId, infos);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!WriteParcelableVectorIntoAshmem(infos, __func__, reply)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetApplicationInfosWithIntFlagsV9(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    int32_t flags = data.ReadInt32();
    int32_t userId = data.ReadInt32();
    std::vector<ApplicationInfo> infos;
    auto ret = GetApplicationInfosV9(flags, userId, infos);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        if (!WriteParcelableVectorIntoAshmem(infos, __func__, reply)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetBundleInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string name = data.ReadString();
    BundleFlag flag = static_cast<BundleFlag>(data.ReadInt32());
    int userId = data.ReadInt32();
    APP_LOGI("name %{public}s, flag %{public}d", name.c_str(), flag);
    BundleInfo info;
    reply.SetDataCapacity(Constants::CAPACITY_SIZE);
    bool ret = GetBundleInfo(name, flag, info, userId);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!reply.WriteParcelable(&info)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetBundleInfoForSelf(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    int32_t flags = data.ReadInt32();
    APP_LOGD("GetBundleInfoForSelf, flags %{public}d", flags);
    BundleInfo info;
    reply.SetDataCapacity(Constants::CAPACITY_SIZE);
    auto ret = GetBundleInfoForSelf(flags, info);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK && !reply.WriteParcelable(&info)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetBundleInfoWithIntFlags(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string name = data.ReadString();
    int flags = data.ReadInt32();
    int userId = data.ReadInt32();
    APP_LOGD("name %{public}s, flags %{public}d", name.c_str(), flags);
    BundleInfo info;
    reply.SetDataCapacity(Constants::CAPACITY_SIZE);
    bool ret = GetBundleInfo(name, flags, info, userId);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!reply.WriteParcelable(&info)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetBundleInfoWithIntFlagsV9(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string name = data.ReadString();
    if (name.empty()) {
        APP_LOGE("bundleName is empty");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    int32_t flags = data.ReadInt32();
    int32_t userId = data.ReadInt32();
    APP_LOGD("name %{public}s, flags %{public}d", name.c_str(), flags);
    BundleInfo info;
    reply.SetDataCapacity(Constants::CAPACITY_SIZE);
    auto ret = GetBundleInfoV9(name, flags, info, userId);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK && !reply.WriteParcelable(&info)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetBundlePackInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string name = data.ReadString();
    BundlePackFlag flag = static_cast<BundlePackFlag>(data.ReadInt32());
    int userId = data.ReadInt32();
    APP_LOGD("name %{public}s, flag %{public}d", name.c_str(), flag);
    BundlePackInfo info;
    ErrCode ret = GetBundlePackInfo(name, flag, info, userId);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        if (!reply.WriteParcelable(&info)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetBundlePackInfoWithIntFlags(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string name = data.ReadString();
    int flags = data.ReadInt32();
    int userId = data.ReadInt32();
    APP_LOGD("name %{public}s, flags %{public}d", name.c_str(), flags);
    BundlePackInfo info;
    ErrCode ret = GetBundlePackInfo(name, flags, info, userId);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        if (!reply.WriteParcelable(&info)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetBundleInfos(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    BundleFlag flag = static_cast<BundleFlag>(data.ReadInt32());
    int userId = data.ReadInt32();

    std::vector<BundleInfo> infos;
    reply.SetDataCapacity(Constants::MAX_CAPACITY_BUNDLES);
    bool ret = GetBundleInfos(flag, infos, userId);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!WriteParcelableVectorIntoAshmem(infos, __func__, reply)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetBundleInfosWithIntFlags(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    int flags = data.ReadInt32();
    int userId = data.ReadInt32();

    std::vector<BundleInfo> infos;
    reply.SetDataCapacity(Constants::MAX_CAPACITY_BUNDLES);
    bool ret = GetBundleInfos(flags, infos, userId);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!WriteParcelableVectorIntoAshmem(infos, __func__, reply)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetBundleInfosWithIntFlagsV9(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    int32_t flags = data.ReadInt32();
    int32_t userId = data.ReadInt32();

    std::vector<BundleInfo> infos;
    auto ret = GetBundleInfosV9(flags, infos, userId);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        if (!WriteParcelableVectorIntoAshmem(infos, __func__, reply)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetBundleNameForUid(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    int uid = data.ReadInt32();
    std::string name;
    bool ret = GetBundleNameForUid(uid, name);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!reply.WriteString(name)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetBundlesForUid(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    int uid = data.ReadInt32();
    std::vector<std::string> names;
    bool ret = GetBundlesForUid(uid, names);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!reply.WriteStringVector(names)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetNameForUid(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    int uid = data.ReadInt32();
    std::string name;
    ErrCode ret = GetNameForUid(uid, name);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        if (!reply.WriteString(name)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetBundleGids(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string name = data.ReadString();

    std::vector<int> gids;
    bool ret = GetBundleGids(name, gids);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!reply.WriteInt32Vector(gids)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetBundleGidsByUid(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string name = data.ReadString();
    int uid = data.ReadInt32();

    std::vector<int> gids;
    bool ret = GetBundleGidsByUid(name, uid, gids);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!reply.WriteInt32Vector(gids)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetBundleInfosByMetaData(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string metaData = data.ReadString();

    std::vector<BundleInfo> infos;
    bool ret = GetBundleInfosByMetaData(metaData, infos);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!WriteParcelableVector(infos, reply)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleQueryAbilityInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        APP_LOGE("ReadParcelable<want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    AbilityInfo info;
    bool ret = QueryAbilityInfo(*want, info);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!reply.WriteParcelable(&info)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleQueryAbilityInfoMutiparam(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        APP_LOGE("ReadParcelable<want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t flags = data.ReadInt32();
    int32_t userId = data.ReadInt32();
    AbilityInfo info;
    bool ret = QueryAbilityInfo(*want, flags, userId, info);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!reply.WriteParcelable(&info)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleQueryAbilityInfos(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        APP_LOGE("ReadParcelable<want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    std::vector<AbilityInfo> abilityInfos;
    bool ret = QueryAbilityInfos(*want, abilityInfos);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!WriteParcelableVector(abilityInfos, reply)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleQueryAbilityInfosMutiparam(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        APP_LOGE("ReadParcelable<want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t flags = data.ReadInt32();
    int32_t userId = data.ReadInt32();
    std::vector<AbilityInfo> abilityInfos;
    bool ret = QueryAbilityInfos(*want, flags, userId, abilityInfos);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!WriteParcelableVectorIntoAshmem(abilityInfos, __func__, reply)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleQueryAbilityInfosV9(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        APP_LOGE("ReadParcelable<want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t flags = data.ReadInt32();
    int32_t userId = data.ReadInt32();
    std::vector<AbilityInfo> abilityInfos;
    ErrCode ret = QueryAbilityInfosV9(*want, flags, userId, abilityInfos);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        if (!WriteParcelableVectorIntoAshmem(abilityInfos, __func__, reply)) {
            APP_LOGE("writeParcelableVectorIntoAshmem failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleQueryAllAbilityInfos(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        APP_LOGE("ReadParcelable<want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t userId = data.ReadInt32();
    std::vector<AbilityInfo> abilityInfos;
    bool ret = QueryAllAbilityInfos(*want, userId, abilityInfos);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!WriteParcelableVectorIntoAshmem(abilityInfos, __func__, reply)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleQueryAbilityInfoByUri(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string abilityUri = data.ReadString();
    AbilityInfo info;
    bool ret = QueryAbilityInfoByUri(abilityUri, info);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!reply.WriteParcelable(&info)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleQueryAbilityInfosByUri(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string abilityUri = data.ReadString();
    std::vector<AbilityInfo> abilityInfos;
    bool ret = QueryAbilityInfosByUri(abilityUri, abilityInfos);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!WriteParcelableVector(abilityInfos, reply)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleQueryAbilityInfoByUriForUserId(MessageParcel &data, MessageParcel &reply)
{
    std::string abilityUri = data.ReadString();
    int32_t userId = data.ReadInt32();
    AbilityInfo info;
    bool ret = QueryAbilityInfoByUri(abilityUri, userId, info);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!reply.WriteParcelable(&info)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleQueryKeepAliveBundleInfos(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::vector<BundleInfo> infos;
    bool ret = QueryKeepAliveBundleInfos(infos);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!WriteParcelableVector(infos, reply)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetAbilityLabel(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    std::string abilityName = data.ReadString();

    APP_LOGI("bundleName %{public}s, abilityName %{public}s", bundleName.c_str(), abilityName.c_str());
    BundleInfo info;
    std::string label = GetAbilityLabel(bundleName, abilityName);
    if (!reply.WriteString(label)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetAbilityLabelWithModuleName(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    std::string moduleName = data.ReadString();
    std::string abilityName = data.ReadString();
    if (bundleName.empty() || moduleName.empty() || abilityName.empty()) {
        APP_LOGE("fail to GetAbilityLabel due to params empty");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    APP_LOGD("GetAbilityLabe bundleName %{public}s, moduleName %{public}s, abilityName %{public}s",
        bundleName.c_str(), moduleName.c_str(), abilityName.c_str());
    std::string label;
    ErrCode ret = GetAbilityLabel(bundleName, moduleName, abilityName, label);
    if (!reply.WriteInt32(ret)) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if ((ret == ERR_OK) && !reply.WriteString(label)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleCheckIsSystemAppByUid(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    int uid = data.ReadInt32();
    bool ret = CheckIsSystemAppByUid(uid);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetBundleArchiveInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string hapFilePath = data.ReadString();
    BundleFlag flag = static_cast<BundleFlag>(data.ReadInt32());
    APP_LOGD("hapFilePath %{private}s, flag %{public}d", hapFilePath.c_str(), flag);

    BundleInfo info;
    bool ret = GetBundleArchiveInfo(hapFilePath, flag, info);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!reply.WriteParcelable(&info)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetBundleArchiveInfoWithIntFlags(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string hapFilePath = data.ReadString();
    int32_t flags = data.ReadInt32();
    APP_LOGD("hapFilePath %{private}s, flagS %{public}d", hapFilePath.c_str(), flags);

    BundleInfo info;
    bool ret = GetBundleArchiveInfo(hapFilePath, flags, info);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!reply.WriteParcelable(&info)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetBundleArchiveInfoWithIntFlagsV9(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string hapFilePath = data.ReadString();
    int32_t flags = data.ReadInt32();
    APP_LOGD("hapFilePath %{private}s, flags %{public}d", hapFilePath.c_str(), flags);

    BundleInfo info;
    ErrCode ret = GetBundleArchiveInfoV9(hapFilePath, flags, info);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        if (!reply.WriteParcelable(&info)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetHapModuleInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::unique_ptr<AbilityInfo> abilityInfo(data.ReadParcelable<AbilityInfo>());
    if (!abilityInfo) {
        APP_LOGE("ReadParcelable<abilityInfo> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    HapModuleInfo info;
    bool ret = GetHapModuleInfo(*abilityInfo, info);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!reply.WriteParcelable(&info)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetHapModuleInfoWithUserId(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::unique_ptr<AbilityInfo> abilityInfo(data.ReadParcelable<AbilityInfo>());
    if (abilityInfo == nullptr) {
        APP_LOGE("ReadParcelable<abilityInfo> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t userId = data.ReadInt32();
    HapModuleInfo info;
    bool ret = GetHapModuleInfo(*abilityInfo, userId, info);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!reply.WriteParcelable(&info)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetLaunchWantForBundle(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    int32_t userId = data.ReadInt32();
    APP_LOGI("name %{public}s", bundleName.c_str());

    Want want;
    ErrCode ret = GetLaunchWantForBundle(bundleName, want, userId);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        if (!reply.WriteParcelable(&want)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleCheckPublicKeys(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string firstBundleName = data.ReadString();
    std::string secondBundleName = data.ReadString();

    APP_LOGI(
        "firstBundleName %{public}s, secondBundleName %{public}s", firstBundleName.c_str(), secondBundleName.c_str());
    int ret = CheckPublicKeys(firstBundleName, secondBundleName);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetPermissionDef(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string permissionName = data.ReadString();
    APP_LOGI("name %{public}s", permissionName.c_str());

    PermissionDef permissionDef;
    ErrCode ret = GetPermissionDef(permissionName, permissionDef);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        if (!reply.WriteParcelable(&permissionDef)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleHasSystemCapability(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string capName = data.ReadString();

    bool ret = HasSystemCapability(capName);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetSystemAvailableCapabilities(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::vector<std::string> caps;
    bool ret = GetSystemAvailableCapabilities(caps);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!reply.WriteStringVector(caps)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleIsSafeMode(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    bool ret = IsSafeMode();
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleCleanBundleCacheFiles(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    sptr<IRemoteObject> object = data.ReadObject<IRemoteObject>();
    if (object == nullptr) {
        APP_LOGE("read failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<ICleanCacheCallback> cleanCacheCallback = iface_cast<ICleanCacheCallback>(object);
    int32_t userId = data.ReadInt32();

    ErrCode ret = CleanBundleCacheFiles(bundleName, cleanCacheCallback, userId);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleCleanBundleDataFiles(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    int userId = data.ReadInt32();

    bool ret = CleanBundleDataFiles(bundleName, userId);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleRegisterBundleStatusCallback(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    sptr<IRemoteObject> object = data.ReadObject<IRemoteObject>();
    if (object == nullptr) {
        APP_LOGE("read failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IBundleStatusCallback> BundleStatusCallback = iface_cast<IBundleStatusCallback>(object);

    bool ret = false;
    if (bundleName.empty() || !BundleStatusCallback) {
        APP_LOGE("Get BundleStatusCallback failed");
    } else {
        BundleStatusCallback->SetBundleName(bundleName);
        ret = RegisterBundleStatusCallback(BundleStatusCallback);
    }
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleRegisterBundleEventCallback(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    sptr<IRemoteObject> object = data.ReadObject<IRemoteObject>();
    if (object == nullptr) {
        APP_LOGE("read IRemoteObject failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IBundleEventCallback> bundleEventCallback = iface_cast<IBundleEventCallback>(object);
    if (bundleEventCallback == nullptr) {
        APP_LOGE("Get bundleEventCallback failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    bool ret = RegisterBundleEventCallback(bundleEventCallback);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleUnregisterBundleEventCallback(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    sptr<IRemoteObject> object = data.ReadObject<IRemoteObject>();
    if (object == nullptr) {
        APP_LOGE("read IRemoteObject failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IBundleEventCallback> bundleEventCallback = iface_cast<IBundleEventCallback>(object);

    bool ret = UnregisterBundleEventCallback(bundleEventCallback);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleClearBundleStatusCallback(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    sptr<IRemoteObject> object = data.ReadObject<IRemoteObject>();
    if (object == nullptr) {
        APP_LOGE("read failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<IBundleStatusCallback> BundleStatusCallback = iface_cast<IBundleStatusCallback>(object);

    bool ret = ClearBundleStatusCallback(BundleStatusCallback);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleUnregisterBundleStatusCallback(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    bool ret = UnregisterBundleStatusCallback();
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleDumpInfos(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    DumpFlag flag = static_cast<DumpFlag>(data.ReadInt32());
    std::string bundleName = data.ReadString();
    int32_t userId = data.ReadInt32();

    std::string result;
    APP_LOGI("dump info name %{public}s", bundleName.c_str());
    bool ret = DumpInfos(flag, bundleName, userId, result);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        std::vector<std::string> dumpInfos;
        SplitString(result, dumpInfos);
        if (!reply.WriteStringVector(dumpInfos)) {
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleIsApplicationEnabled(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    if (bundleName.empty()) {
        APP_LOGE("fail to IsApplicationEnabled due to params empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    bool isEnable = false;
    ErrCode ret = IsApplicationEnabled(bundleName, isEnable);
    if (!reply.WriteInt32(ret)) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!reply.WriteBool(isEnable)) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleSetApplicationEnabled(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    if (bundleName.empty()) {
        APP_LOGE("fail to SetApplicationEnabled due to params empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    bool isEnable = data.ReadBool();
    int32_t userId = data.ReadInt32();
    ErrCode ret = SetApplicationEnabled(bundleName, isEnable, userId);
    if (!reply.WriteInt32(ret)) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleIsAbilityEnabled(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::unique_ptr<AbilityInfo> abilityInfo(data.ReadParcelable<AbilityInfo>());
    if (abilityInfo == nullptr) {
        APP_LOGE("ReadParcelable<abilityInfo> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    bool isEnable = false;
    ErrCode ret = IsAbilityEnabled(*abilityInfo, isEnable);
    if (!reply.WriteInt32(ret)) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!reply.WriteBool(isEnable)) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleSetAbilityEnabled(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::unique_ptr<AbilityInfo> abilityInfo(data.ReadParcelable<AbilityInfo>());
    if (abilityInfo == nullptr) {
        APP_LOGE("ReadParcelable<abilityInfo> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    bool isEnabled = data.ReadBool();
    int32_t userId = data.ReadInt32();
    ErrCode ret = SetAbilityEnabled(*abilityInfo, isEnabled, userId);
    if (!reply.WriteInt32(ret)) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetAbilityInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    AbilityInfo info;
    std::string bundleName = data.ReadString();
    std::string abilityName = data.ReadString();
    bool ret = GetAbilityInfo(bundleName, abilityName, info);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!reply.WriteParcelable(&info)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetAbilityInfoWithModuleName(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    AbilityInfo info;
    std::string bundleName = data.ReadString();
    std::string moduleName = data.ReadString();
    std::string abilityName = data.ReadString();
    bool ret = GetAbilityInfo(bundleName, moduleName, abilityName, info);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!reply.WriteParcelable(&info)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetBundleInstaller(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    sptr<IBundleInstaller> installer = GetBundleInstaller();
    if (installer == nullptr) {
        APP_LOGE("bundle installer is nullptr");
        return ERR_APPEXECFWK_INSTALL_HOST_INSTALLER_FAILED;
    }

    if (!reply.WriteObject<IRemoteObject>(installer->AsObject())) {
        APP_LOGE("failed to reply bundle installer to client, for write MessageParcel error");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetBundleUserMgr(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    sptr<IBundleUserMgr> bundleUserMgr = GetBundleUserMgr();
    if (bundleUserMgr == nullptr) {
        APP_LOGE("bundle installer is nullptr");
        return ERR_APPEXECFWK_INSTALL_HOST_INSTALLER_FAILED;
    }

    if (!reply.WriteObject<IRemoteObject>(bundleUserMgr->AsObject())) {
        APP_LOGE("failed to reply bundle installer to client, for write MessageParcel error");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetAllFormsInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::vector<FormInfo> infos;
    bool ret = GetAllFormsInfo(infos);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (ret) {
        if (!WriteParcelableVector(infos, reply)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetFormsInfoByApp(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundlename = data.ReadString();
    std::vector<FormInfo> infos;
    bool ret = GetFormsInfoByApp(bundlename, infos);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (ret) {
        if (!WriteParcelableVector(infos, reply)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetFormsInfoByModule(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundlename = data.ReadString();
    std::string modulename = data.ReadString();
    std::vector<FormInfo> infos;
    bool ret = GetFormsInfoByModule(bundlename, modulename, infos);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (ret) {
        if (!WriteParcelableVector(infos, reply)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetShortcutInfos(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundlename = data.ReadString();
    std::vector<ShortcutInfo> infos;
    bool ret = GetShortcutInfos(bundlename, infos);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (ret) {
        if (!WriteParcelableVector(infos, reply)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetShortcutInfoV9(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundlename = data.ReadString();
    std::vector<ShortcutInfo> infos;
    ErrCode ret = GetShortcutInfoV9(bundlename, infos);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK && !WriteParcelableVector(infos, reply)) {
        APP_LOGE("write shortcut infos failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetAllCommonEventInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string eventKey = data.ReadString();
    std::vector<CommonEventInfo> infos;
    bool ret = GetAllCommonEventInfo(eventKey, infos);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (ret) {
        if (!WriteParcelableVector(infos, reply)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetDistributedBundleInfo(MessageParcel &data, MessageParcel &reply)
{
    std::string networkId = data.ReadString();
    std::string bundleName = data.ReadString();
    if (networkId.empty() || bundleName.empty()) {
        APP_LOGE("networkId or bundleName is invalid");
        return ERR_INVALID_VALUE;
    }
    DistributedBundleInfo distributedBundleInfo;
    bool ret = GetDistributedBundleInfo(networkId, bundleName, distributedBundleInfo);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!reply.WriteParcelable(&distributedBundleInfo)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetAppPrivilegeLevel(MessageParcel &data, MessageParcel &reply)
{
    std::string bundleName = data.ReadString();
    int32_t userId = data.ReadInt32();
    auto ret = GetAppPrivilegeLevel(bundleName, userId);
    if (!reply.WriteString(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleQueryExtAbilityInfosWithoutType(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (!want) {
        APP_LOGE("ReadParcelable<want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t flag = data.ReadInt32();
    int32_t userId = data.ReadInt32();
    std::vector<ExtensionAbilityInfo> infos;
    bool ret = QueryExtensionAbilityInfos(*want, flag, userId, infos);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret && !WriteParcelableVector(infos, reply)) {
        APP_LOGE("write extension infos failed");

        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleQueryExtAbilityInfosWithoutTypeV9(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (!want) {
        APP_LOGE("ReadParcelable<want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t flags = data.ReadInt32();
    int32_t userId = data.ReadInt32();
    std::vector<ExtensionAbilityInfo> infos;
    ErrCode ret = QueryExtensionAbilityInfosV9(*want, flags, userId, infos);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK && !WriteParcelableVector(infos, reply)) {
        APP_LOGE("write extension infos failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleQueryExtAbilityInfos(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        APP_LOGE("ReadParcelable<want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    ExtensionAbilityType type = static_cast<ExtensionAbilityType>(data.ReadInt32());
    int32_t flag = data.ReadInt32();
    int32_t userId = data.ReadInt32();
    std::vector<ExtensionAbilityInfo> infos;
    bool ret = QueryExtensionAbilityInfos(*want, type, flag, userId, infos);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret && !WriteParcelableVector(infos, reply)) {
        APP_LOGE("write extension infos failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleQueryExtAbilityInfosV9(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        APP_LOGE("ReadParcelable<want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    ExtensionAbilityType type = static_cast<ExtensionAbilityType>(data.ReadInt32());
    int32_t flags = data.ReadInt32();
    int32_t userId = data.ReadInt32();
    std::vector<ExtensionAbilityInfo> infos;
    ErrCode ret = QueryExtensionAbilityInfosV9(*want, type, flags, userId, infos);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK && !WriteParcelableVector(infos, reply)) {
        APP_LOGE("write extension infos failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleQueryExtAbilityInfosByType(MessageParcel &data, MessageParcel &reply)
{
    ExtensionAbilityType type = static_cast<ExtensionAbilityType>(data.ReadInt32());
    int32_t userId = data.ReadInt32();
    std::vector<ExtensionAbilityInfo> infos;

    bool ret = QueryExtensionAbilityInfos(type, userId, infos);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret && !WriteParcelableVector(infos, reply)) {
        APP_LOGE("write extension infos failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleVerifyCallingPermission(MessageParcel &data, MessageParcel &reply)
{
    std::string permission = data.ReadString();

    bool ret = VerifyCallingPermission(permission);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetAccessibleAppCodePaths(MessageParcel &data, MessageParcel &reply)
{
    int32_t userId = data.ReadInt32();
    std::vector<std::string> vec = GetAccessibleAppCodePaths(userId);
    bool ret = vec.empty() ? false : true;
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret && !reply.WriteStringVector(vec)) {
        APP_LOGE("write code paths failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleQueryExtensionAbilityInfoByUri(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string uri = data.ReadString();
    int32_t userId = data.ReadInt32();
    ExtensionAbilityInfo extensionAbilityInfo;
    bool ret = QueryExtensionAbilityInfoByUri(uri, userId, extensionAbilityInfo);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!reply.WriteParcelable(&extensionAbilityInfo)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetAppIdByBundleName(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    int32_t userId = data.ReadInt32();
    std::string appId = GetAppIdByBundleName(bundleName, userId);
    APP_LOGD("appId is %{private}s", appId.c_str());
    if (!reply.WriteString(appId)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetAppType(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    std::string appType = GetAppType(bundleName);
    APP_LOGD("appType is %{public}s", appType.c_str());
    if (!reply.WriteString(appType)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetUidByBundleName(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    int32_t userId = data.ReadInt32();
    int32_t uid = GetUidByBundleName(bundleName, userId);
    APP_LOGD("uid is %{public}d", uid);
    if (!reply.WriteInt32(uid)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetUidByDebugBundleName(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    int32_t userId = data.ReadInt32();
    int32_t uid = GetUidByDebugBundleName(bundleName, userId);
    APP_LOGD("uid is %{public}d", uid);
    if (!reply.WriteInt32(uid)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleIsModuleRemovable(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    std::string moduleName = data.ReadString();

    APP_LOGD("bundleName %{public}s, moduleName %{public}s", bundleName.c_str(), moduleName.c_str());
    bool isRemovable = false;
    ErrCode ret = IsModuleRemovable(bundleName, moduleName, isRemovable);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!reply.WriteBool(isRemovable)) {
        APP_LOGE("write isRemovable failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleSetModuleRemovable(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    std::string moduleName = data.ReadString();
    bool isEnable = data.ReadBool();
    APP_LOGD("bundleName %{public}s, moduleName %{public}s", bundleName.c_str(), moduleName.c_str());
    bool ret = SetModuleRemovable(bundleName, moduleName, isEnable);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetModuleUpgradeFlag(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    std::string moduleName = data.ReadString();

    APP_LOGD("bundleName %{public}s, moduleName %{public}s", bundleName.c_str(), moduleName.c_str());
    bool ret = GetModuleUpgradeFlag(bundleName, moduleName);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleSetModuleUpgradeFlag(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    std::string moduleName = data.ReadString();
    int32_t upgradeFlag = data.ReadInt32();
    APP_LOGD("bundleName %{public}s, moduleName %{public}s", bundleName.c_str(), moduleName.c_str());
    ErrCode ret = SetModuleUpgradeFlag(bundleName, moduleName, upgradeFlag);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleImplicitQueryInfoByPriority(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        APP_LOGE("ReadParcelable<want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t flags = data.ReadInt32();
    int32_t userId = data.ReadInt32();
    AbilityInfo abilityInfo;
    ExtensionAbilityInfo extensionInfo;
    bool ret = ImplicitQueryInfoByPriority(*want, flags, userId, abilityInfo, extensionInfo);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!reply.WriteParcelable(&abilityInfo)) {
            APP_LOGE("write AbilityInfo failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        if (!reply.WriteParcelable(&extensionInfo)) {
            APP_LOGE("write ExtensionAbilityInfo failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleImplicitQueryInfos(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        APP_LOGE("ReadParcelable want failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t flags = data.ReadInt32();
    int32_t userId = data.ReadInt32();
    std::vector<AbilityInfo> abilityInfos;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    bool ret = ImplicitQueryInfos(*want, flags, userId, abilityInfos, extensionInfos);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("WriteBool ret failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!WriteParcelableVector(abilityInfos, reply)) {
            APP_LOGE("WriteParcelableVector abilityInfos failed.");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        if (!WriteParcelableVector(extensionInfos, reply)) {
            APP_LOGE("WriteParcelableVector extensionInfo failed.");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetAllDependentModuleNames(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    std::string moduleName = data.ReadString();
    std::vector<std::string> dependentModuleNames;
    bool ret = GetAllDependentModuleNames(bundleName, moduleName, dependentModuleNames);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret && !reply.WriteStringVector(dependentModuleNames)) {
        APP_LOGE("write dependentModuleNames failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetSandboxBundleInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    int32_t appIndex = data.ReadInt32();
    int32_t userId = data.ReadInt32();

    BundleInfo info;
    auto res = GetSandboxBundleInfo(bundleName, appIndex, userId, info);
    if (!reply.WriteInt32(res)) {
        return ERR_APPEXECFWK_SANDBOX_INSTALL_WRITE_PARCEL_ERROR;
    }
    if ((res == ERR_OK) && (!reply.WriteParcelable(&info))) {
        return ERR_APPEXECFWK_SANDBOX_INSTALL_WRITE_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleSetDisposedStatus(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    int32_t status = data.ReadInt32();
    bool ret = SetDisposedStatus(bundleName, status);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("HandleSetDisposedStatus write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetDisposedStatus(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();

    int32_t ret = GetDisposedStatus(bundleName);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("HandleGetDisposedStatus write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleObtainCallingBundleName(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = "";
    auto ret = ObtainCallingBundleName(bundleName);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret && !reply.WriteString(bundleName)) {
        APP_LOGE("write bundleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleCheckAbilityEnableInstall(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        APP_LOGE("ReadParcelable<want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t missionId = data.ReadInt32();
    int32_t userId = data.ReadInt32();
    sptr<IRemoteObject> object = data.ReadObject<IRemoteObject>();

    auto ret = CheckAbilityEnableInstall(*want, missionId, userId, object);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetStringById(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    std::string moduleName = data.ReadString();
    uint32_t resId = data.ReadUint32();
    int32_t userId = data.ReadInt32();
    std::string localeInfo = data.ReadString();
    APP_LOGD("GetStringById bundleName: %{public}s, moduleName: %{public}s, resId:%{public}d",
        bundleName.c_str(), moduleName.c_str(), resId);
    if (bundleName.empty() || moduleName.empty()) {
        APP_LOGW("fail to GetStringById due to params empty");
        return ERR_INVALID_VALUE;
    }
    std::string label = GetStringById(bundleName, moduleName, resId, userId, localeInfo);
    if (!reply.WriteString(label)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetIconById(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    std::string moduleName = data.ReadString();
    uint32_t resId = data.ReadUint32();
    uint32_t density = data.ReadUint32();
    int32_t userId = data.ReadInt32();
    APP_LOGD("GetStringById bundleName: %{public}s, moduleName: %{public}s, resId:%{public}d, density:%{public}d",
        bundleName.c_str(), moduleName.c_str(), resId, density);
    if (bundleName.empty() || moduleName.empty()) {
        APP_LOGW("fail to GetStringById due to params empty");
        return ERR_INVALID_VALUE;
    }
    std::string label = GetIconById(bundleName, moduleName, resId, density, userId);
    if (!reply.WriteString(label)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetUdidByNetworkId(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string networkId = data.ReadString();
    if (networkId.empty()) {
        return ERR_INVALID_VALUE;
    }
    std::string udid;
    int32_t ret = GetUdidByNetworkId(networkId, udid);
    if (ret == ERR_OK) {
        if (!reply.WriteString(udid)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ret;
}

#ifdef BUNDLE_FRAMEWORK_DEFAULT_APP
ErrCode BundleMgrHost::HandleGetDefaultAppProxy(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    sptr<IDefaultApp> defaultAppProxy = GetDefaultAppProxy();
    if (defaultAppProxy == nullptr) {
        APP_LOGE("defaultAppProxy is nullptr.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!reply.WriteObject<IRemoteObject>(defaultAppProxy->AsObject())) {
        APP_LOGE("WriteObject failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}
#endif

#ifdef BUNDLE_FRAMEWORK_APP_CONTROL
ErrCode BundleMgrHost::HandleGetAppControlProxy(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    sptr<IAppControlMgr> appControlProxy = GetAppControlProxy();
    if (appControlProxy == nullptr) {
        APP_LOGE("appControlProxy is nullptr.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!reply.WriteObject<IRemoteObject>(appControlProxy->AsObject())) {
        APP_LOGE("WriteObject failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}
#endif

ErrCode BundleMgrHost::HandleGetSandboxAbilityInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        APP_LOGE("ReadParcelable<want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t appIndex = data.ReadInt32();
    int32_t flag = data.ReadInt32();
    int32_t userId = data.ReadInt32();
    AbilityInfo info;
    auto res = GetSandboxAbilityInfo(*want, appIndex, flag, userId, info);
    if (!reply.WriteInt32(res)) {
        APP_LOGE("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if ((res == ERR_OK) && (!reply.WriteParcelable(&info))) {
        APP_LOGE("write ability info failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetSandboxExtAbilityInfos(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (!want) {
        APP_LOGE("ReadParcelable<want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t appIndex = data.ReadInt32();
    int32_t flag = data.ReadInt32();
    int32_t userId = data.ReadInt32();
    std::vector<ExtensionAbilityInfo> infos;
    auto res = GetSandboxExtAbilityInfos(*want, appIndex, flag, userId, infos);
    if (!reply.WriteInt32(res)) {
        APP_LOGE("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if ((res == ERR_OK) && (!WriteParcelableVector(infos, reply))) {
        APP_LOGE("write extension infos failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetSandboxHapModuleInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::unique_ptr<AbilityInfo> abilityInfo(data.ReadParcelable<AbilityInfo>());
    if (abilityInfo == nullptr) {
        APP_LOGE("ReadParcelable<abilityInfo> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t appIndex = data.ReadInt32();
    int32_t userId = data.ReadInt32();
    HapModuleInfo info;
    auto res = GetSandboxHapModuleInfo(*abilityInfo, appIndex, userId, info);
    if (!reply.WriteInt32(res)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if ((res == ERR_OK) && (!reply.WriteParcelable(&info))) {
        APP_LOGE("write hap module info failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetQuickFixManagerProxy(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    sptr<IQuickFixManager> quickFixManagerProxy = GetQuickFixManagerProxy();
    if (quickFixManagerProxy == nullptr) {
        APP_LOGE("quickFixManagerProxy is nullptr.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!reply.WriteObject<IRemoteObject>(quickFixManagerProxy->AsObject())) {
        APP_LOGE("WriteObject failed.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleVerifySystemApi(MessageParcel &data, MessageParcel &reply)
{
    int32_t beginApiVersion = data.ReadInt32();

    bool ret = VerifySystemApi(beginApiVersion);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

template<typename T>
bool BundleMgrHost::WriteParcelableVector(std::vector<T> &parcelableVector, MessageParcel &reply)
{
    if (!reply.WriteInt32(parcelableVector.size())) {
        APP_LOGE("write ParcelableVector failed");
        return false;
    }

    for (auto &parcelable : parcelableVector) {
        if (!reply.WriteParcelable(&parcelable)) {
            APP_LOGE("write ParcelableVector failed");
            return false;
        }
    }
    return true;
}

template<typename T>
bool BundleMgrHost::WriteParcelableVectorIntoAshmem(
    std::vector<T> &parcelableVector, const char *ashmemName, MessageParcel &reply)
{
    APP_LOGD("Write parcelable vector into ashmem");
    if (ashmemName == nullptr) {
        APP_LOGE("AshmemName is null");
        return false;
    }

    if (!reply.WriteInt32(parcelableVector.size())) {
        APP_LOGE("Write parcelable vector size failed");
        return false;
    }

    MessageParcel *messageParcel = reinterpret_cast<MessageParcel *>(&reply);
    if (messageParcel == nullptr) {
        APP_LOGE("Type conversion failed");
        return false;
    }

    // Calculate the size of the ashmem,
    // and get content that needs to be stored in ashmem.
    int32_t totalSize = 0;
    std::vector<std::string> infoStrs;
    for (auto &parcelable : parcelableVector) {
        auto str = GetJsonStrFromInfo<T>(parcelable);
        infoStrs.emplace_back(str);
        totalSize += ASHMEM_LEN;
        totalSize += strlen(str.c_str());
    }

    if (infoStrs.empty() || totalSize <= 0) {
        APP_LOGE("The size of the ashmem is invalid or the content is empty");
        return false;
    }

    // The ashmem name must be unique.
    sptr<Ashmem> ashmem = Ashmem::CreateAshmem(
        (ashmemName + std::to_string(AllocatAshmemNum())).c_str(), totalSize);
    if (ashmem == nullptr) {
        APP_LOGE("Create shared memory fail");
        return false;
    }

    // Set the read/write mode of the ashme.
    bool ret = ashmem->MapReadAndWriteAshmem();
    if (!ret) {
        APP_LOGE("Map shared memory fail");
        return false;
    }

    // Write the size and content of each item to the ashmem.
    // The size of item use ASHMEM_LEN.
    int32_t offset = 0;
    for (auto &infoStr : infoStrs) {
        int itemLen = static_cast<int>(strlen(infoStr.c_str()));
        std::string strLen = std::to_string(itemLen);
        strLen = std::string(std::max(0, static_cast<int32_t>(ASHMEM_LEN - strLen.size())), '0') + strLen;
        ret = ashmem->WriteToAshmem(std::to_string(itemLen).c_str(), ASHMEM_LEN, offset);
        if (!ret) {
            APP_LOGE("Write itemLen to shared memory fail");
            ClearAshmem(ashmem);
            return false;
        }

        offset += ASHMEM_LEN;
        ret = ashmem->WriteToAshmem(infoStr.c_str(), itemLen, offset);
        if (!ret) {
            APP_LOGE("Write info to shared memory fail");
            ClearAshmem(ashmem);
            return false;
        }

        offset += itemLen;
    }

    ret = messageParcel->WriteAshmem(ashmem);
    ClearAshmem(ashmem);
    if (!ret) {
        APP_LOGE("Write ashmem to MessageParcel fail");
        return false;
    }

    APP_LOGD("Write parcelable vector into ashmem success");
    return true;
}

int32_t BundleMgrHost::AllocatAshmemNum()
{
    std::lock_guard<std::mutex> lock(bundleAshmemMutex_);
    return ashmemNum_++;
}

ErrCode BundleMgrHost::HandleQueryAbilityInfoWithCallback(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        APP_LOGE("ReadParcelable<want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t flags = data.ReadInt32();
    int32_t userId = data.ReadInt32();
    sptr<IRemoteObject> object = data.ReadObject<IRemoteObject>();
    AbilityInfo info;
    bool ret = QueryAbilityInfo(*want, flags, userId, info, object);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!reply.WriteParcelable(&info)) {
            APP_LOGE("write info failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleSilentInstall(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        APP_LOGE("ReadParcelable<want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t userId = data.ReadInt32();
    sptr<IRemoteObject> object = data.ReadObject<IRemoteObject>();
    bool ret = SilentInstall(*want, userId, object);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleUpgradeAtomicService(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        APP_LOGE("read parcelable want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t userId = data.ReadInt32();
    UpgradeAtomicService(*want, userId);
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetBundleStats(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    int32_t userId = data.ReadInt32();
    std::vector<int64_t> bundleStats;
    bool ret = GetBundleStats(bundleName, userId, bundleStats);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret && !reply.WriteInt64Vector(bundleStats)) {
        APP_LOGE("write bundleStats failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetMediaData(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    std::string abilityName = data.ReadString();
    std::string moduleName = data.ReadString();
    int32_t userId = data.ReadInt32();
    APP_LOGI("HandleGetMediaData:%{public}s, %{public}s, %{public}s", bundleName.c_str(),
        abilityName.c_str(), moduleName.c_str());
    std::unique_ptr<uint8_t[]> mediaDataPtr = nullptr;
    size_t len = 0;
    ErrCode ret = GetMediaData(bundleName, moduleName, abilityName, mediaDataPtr, len, userId);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret != ERR_OK) {
        return ret;
    }
    if (mediaDataPtr == nullptr || len == 0) {
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    // write ashMem
    sptr<Ashmem> ashMem = Ashmem::CreateAshmem((__func__ + std::to_string(AllocatAshmemNum())).c_str(), len);
    if (ashMem == nullptr) {
        APP_LOGE("CreateAshmem failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!ashMem->MapReadAndWriteAshmem()) {
        APP_LOGE("MapReadAndWriteAshmem failed");
        ClearAshmem(ashMem);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t offset = 0;
    if (!ashMem->WriteToAshmem(mediaDataPtr.get(), len, offset)) {
        APP_LOGE("MapReadAndWriteAshmem failed");
        ClearAshmem(ashMem);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel *messageParcel = &reply;
    if (messageParcel == nullptr || !messageParcel->WriteAshmem(ashMem)) {
        APP_LOGE("WriteAshmem failed");
        ClearAshmem(ashMem);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ClearAshmem(ashMem);
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleSetDebugMode(MessageParcel &data, MessageParcel &reply)
{
    APP_LOGI("start to process HandleSetDebugMode message");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    bool enable = data.ReadBool();
    auto ret = SetDebugMode(enable);
    if (ret != ERR_OK) {
        APP_LOGE("SetDebugMode failed");
    }
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_BUNDLEMANAGER_SET_DEBUG_MODE_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleProcessPreload(MessageParcel &data, MessageParcel &reply)
{
    APP_LOGD("start to process HandleProcessPreload message");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        APP_LOGE("ReadParcelable<want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto ret = ProcessPreload(*want);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetProvisionMetadata(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    int32_t userId = data.ReadInt32();
    APP_LOGI("start to get provision metadata, bundleName is %{public}s, userId is %{public}d",
        bundleName.c_str(), userId);
    std::vector<Metadata> provisionMetadatas;
    ErrCode ret = GetProvisionMetadata(bundleName, userId, provisionMetadatas);
    if (ret != ERR_OK) {
        APP_LOGE("GetProvisionMetadata failed");
    }
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        if (!WriteParcelableVector(provisionMetadatas, reply)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
