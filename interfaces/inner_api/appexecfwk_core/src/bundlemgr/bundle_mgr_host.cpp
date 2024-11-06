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

#include "bundle_mgr_host.h"

#include <algorithm>
#include <cinttypes>
#include <unistd.h>

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "bundle_memory_guard.h"
#include "hitrace_meter.h"
#include "datetime_ex.h"
#include "ipc_types.h"
#include "json_util.h"
#include "preinstalled_application_info.h"
#include "string_ex.h"
#include "securec.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const int16_t LIMIT_PARCEL_SIZE = 1024;
const int8_t ASHMEM_LEN = 16;
constexpr size_t MAX_PARCEL_CAPACITY = 100 * 1024 * 1024; // 100M
constexpr int32_t ASHMEM_THRESHOLD  = 200 * 1024; // 200K
constexpr int32_t PREINSTALL_PARCEL_CAPACITY  = 400 * 1024; // 400K
constexpr int32_t MAX_CAPACITY_BUNDLES = 5 * 1024 * 1000; // 5M
constexpr int16_t MAX_BATCH_QUERY_BUNDLE_SIZE = 1000;
const int16_t MAX_STATUS_VECTOR_NUM = 1000;
constexpr int16_t MAX_BATCH_QUERY_ABILITY_SIZE = 1000;

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

bool GetData(void *&buffer, size_t size, const void *data)
{
    if (data == nullptr) {
        APP_LOGE("GetData failed due to null data");
        return false;
    }
    if (size == 0 || size > MAX_PARCEL_CAPACITY) {
        APP_LOGE("GetData failed due to zero size");
        return false;
    }
    buffer = malloc(size);
    if (buffer == nullptr) {
        APP_LOGE("GetData failed due to malloc buffer failed");
        return false;
    }
    if (memcpy_s(buffer, size, data, size) != EOK) {
        free(buffer);
        APP_LOGE("GetData failed due to memcpy_s failed");
        return false;
    }
    return true;
}
}  // namespace

BundleMgrHost::BundleMgrHost()
{
    APP_LOGD("create bundle manager host ");
}

int BundleMgrHost::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    BundleMemoryGuard memoryGuard;
    APP_LOGD("bundle mgr host onReceived message, the message code is %{public}u", code);
    std::u16string descriptor = BundleMgrHost::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        APP_LOGE("fail to write reply message in bundle mgr host due to the reply is nullptr");
        return OBJECT_NULL;
    }

    ErrCode errCode = ERR_OK;
    switch (code) {
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_APPLICATION_INFO):
            errCode = this->HandleGetApplicationInfo(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_APPLICATION_INFO_WITH_INT_FLAGS):
            errCode = this->HandleGetApplicationInfoWithIntFlags(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_APPLICATION_INFOS):
            errCode = this->HandleGetApplicationInfos(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_APPLICATION_INFO_WITH_INT_FLAGS_V9):
            errCode = this->HandleGetApplicationInfoWithIntFlagsV9(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_APPLICATION_INFOS_WITH_INT_FLAGS):
            errCode = this->HandleGetApplicationInfosWithIntFlags(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_APPLICATION_INFOS_WITH_INT_FLAGS_V9):
            errCode = this->HandleGetApplicationInfosWithIntFlagsV9(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_INFO):
            errCode = this->HandleGetBundleInfo(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_INFO_WITH_INT_FLAGS):
            errCode = this->HandleGetBundleInfoWithIntFlags(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_INFO_WITH_INT_FLAGS_V9):
            errCode = this->HandleGetBundleInfoWithIntFlagsV9(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::BATCH_GET_BUNDLE_INFO):
            errCode = this->HandleBatchGetBundleInfo(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_PACK_INFO):
            errCode = this->HandleGetBundlePackInfo(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_PACK_INFO_WITH_INT_FLAGS):
            errCode = this->HandleGetBundlePackInfoWithIntFlags(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_INFOS):
            errCode = this->HandleGetBundleInfos(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_INFOS_WITH_INT_FLAGS):
            errCode = this->HandleGetBundleInfosWithIntFlags(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_INFOS_WITH_INT_FLAGS_V9):
            errCode = this->HandleGetBundleInfosWithIntFlagsV9(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_NAME_FOR_UID):
            errCode = this->HandleGetBundleNameForUid(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLES_FOR_UID):
            errCode = this->HandleGetBundlesForUid(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_NAME_FOR_UID):
            errCode = this->HandleGetNameForUid(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_NAME_AND_APPINDEX_FOR_UID):
            errCode = this->HandleGetNameAndIndexForUid(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_GIDS):
            errCode = this->HandleGetBundleGids(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_GIDS_BY_UID):
            errCode = this->HandleGetBundleGidsByUid(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_INFOS_BY_METADATA):
            errCode = this->HandleGetBundleInfosByMetaData(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_ABILITY_INFO):
            errCode = this->HandleQueryAbilityInfo(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_ABILITY_INFO_MUTI_PARAM):
            errCode = this->HandleQueryAbilityInfoMutiparam(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_ABILITY_INFOS):
            errCode = this->HandleQueryAbilityInfos(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_ABILITY_INFOS_MUTI_PARAM):
            errCode = this->HandleQueryAbilityInfosMutiparam(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_ABILITY_INFOS_V9):
            errCode = this->HandleQueryAbilityInfosV9(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::BATCH_QUERY_ABILITY_INFOS):
            errCode = this->HandleBatchQueryAbilityInfos(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_LAUNCHER_ABILITY_INFO):
            errCode = this->HandleQueryLauncherAbilityInfos(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_ALL_ABILITY_INFOS):
            errCode = this->HandleQueryAllAbilityInfos(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_ABILITY_INFO_BY_URI):
            errCode = this->HandleQueryAbilityInfoByUri(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_ABILITY_INFOS_BY_URI):
            errCode = this->HandleQueryAbilityInfosByUri(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_ABILITY_INFO_BY_URI_FOR_USERID):
            errCode = this->HandleQueryAbilityInfoByUriForUserId(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_KEEPALIVE_BUNDLE_INFOS):
            errCode = this->HandleQueryKeepAliveBundleInfos(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ABILITY_LABEL):
            errCode = this->HandleGetAbilityLabel(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ABILITY_LABEL_WITH_MODULE_NAME):
            errCode = this->HandleGetAbilityLabelWithModuleName(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::CHECK_IS_SYSTEM_APP_BY_UID):
            errCode = this->HandleCheckIsSystemAppByUid(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_ARCHIVE_INFO):
            errCode = this->HandleGetBundleArchiveInfo(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_ARCHIVE_INFO_WITH_INT_FLAGS):
            errCode = this->HandleGetBundleArchiveInfoWithIntFlags(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_ARCHIVE_INFO_WITH_INT_FLAGS_V9):
            errCode = this->HandleGetBundleArchiveInfoWithIntFlagsV9(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_HAP_MODULE_INFO):
            errCode = this->HandleGetHapModuleInfo(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_LAUNCH_WANT_FOR_BUNDLE):
            errCode = this->HandleGetLaunchWantForBundle(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_PERMISSION_DEF):
            errCode = this->HandleGetPermissionDef(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::AUTO_CLEAN_CACHE_BY_SIZE):
            errCode = this->HandleCleanBundleCacheFilesAutomatic(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::CLEAN_BUNDLE_CACHE_FILES):
            errCode = this->HandleCleanBundleCacheFiles(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::CREATE_BUNDLE_DATA_DIR):
            errCode = this->HandleCreateBundleDataDir(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::CLEAN_BUNDLE_DATA_FILES):
            errCode = this->HandleCleanBundleDataFiles(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::REGISTER_BUNDLE_STATUS_CALLBACK):
            errCode = this->HandleRegisterBundleStatusCallback(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::REGISTER_BUNDLE_EVENT_CALLBACK):
            errCode = this->HandleRegisterBundleEventCallback(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::UNREGISTER_BUNDLE_EVENT_CALLBACK):
            errCode = this->HandleUnregisterBundleEventCallback(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::CLEAR_BUNDLE_STATUS_CALLBACK):
            errCode = this->HandleClearBundleStatusCallback(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::UNREGISTER_BUNDLE_STATUS_CALLBACK):
            errCode = this->HandleUnregisterBundleStatusCallback(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::IS_APPLICATION_ENABLED):
            errCode = this->HandleIsApplicationEnabled(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::SET_APPLICATION_ENABLED):
            errCode = this->HandleSetApplicationEnabled(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::IS_ABILITY_ENABLED):
            errCode = this->HandleIsAbilityEnabled(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::SET_ABILITY_ENABLED):
            errCode = this->HandleSetAbilityEnabled(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ABILITY_INFO):
            errCode = this->HandleGetAbilityInfo(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ABILITY_INFO_WITH_MODULE_NAME):
            errCode = this->HandleGetAbilityInfoWithModuleName(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::DUMP_INFOS):
            errCode = this->HandleDumpInfos(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_INSTALLER):
            errCode = this->HandleGetBundleInstaller(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ALL_FORMS_INFO):
            errCode = this->HandleGetAllFormsInfo(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_FORMS_INFO_BY_APP):
            errCode = this->HandleGetFormsInfoByApp(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_FORMS_INFO_BY_MODULE):
            errCode = this->HandleGetFormsInfoByModule(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_SHORTCUT_INFO):
            errCode = this->HandleGetShortcutInfos(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_SHORTCUT_INFO_V9):
            errCode = this->HandleGetShortcutInfoV9(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ALL_COMMON_EVENT_INFO):
            errCode = this->HandleGetAllCommonEventInfo(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_USER_MGR):
            errCode = this->HandleGetBundleUserMgr(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_DISTRIBUTE_BUNDLE_INFO):
            errCode = this->HandleGetDistributedBundleInfo(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_APPLICATION_PRIVILEGE_LEVEL):
            errCode = this->HandleGetAppPrivilegeLevel(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_EXTENSION_INFO_WITHOUT_TYPE):
            errCode = this->HandleQueryExtAbilityInfosWithoutType(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_EXTENSION_INFO_WITHOUT_TYPE_V9):
            errCode = this->HandleQueryExtAbilityInfosWithoutTypeV9(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_EXTENSION_INFO):
            errCode = this->HandleQueryExtAbilityInfos(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_EXTENSION_INFO_V9):
            errCode = this->HandleQueryExtAbilityInfosV9(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_EXTENSION_INFO_BY_TYPE):
            errCode = this->HandleQueryExtAbilityInfosByType(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::VERIFY_CALLING_PERMISSION):
            errCode = this->HandleVerifyCallingPermission(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_EXTENSION_ABILITY_INFO_BY_URI):
            errCode = this->HandleQueryExtensionAbilityInfoByUri(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_APPID_BY_BUNDLE_NAME):
            errCode = this->HandleGetAppIdByBundleName(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_APP_TYPE):
            errCode = this->HandleGetAppType(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_UID_BY_BUNDLE_NAME):
            errCode = this->HandleGetUidByBundleName(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::IS_MODULE_REMOVABLE):
            errCode = this->HandleIsModuleRemovable(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::SET_MODULE_REMOVABLE):
            errCode = this->HandleSetModuleRemovable(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_ABILITY_INFO_WITH_CALLBACK):
            errCode = this->HandleQueryAbilityInfoWithCallback(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::UPGRADE_ATOMIC_SERVICE):
            errCode = this->HandleUpgradeAtomicService(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::IS_MODULE_NEED_UPDATE):
            errCode = this->HandleGetModuleUpgradeFlag(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::SET_MODULE_NEED_UPDATE):
            errCode = this->HandleSetModuleUpgradeFlag(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_HAP_MODULE_INFO_WITH_USERID):
            errCode = this->HandleGetHapModuleInfoWithUserId(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::IMPLICIT_QUERY_INFO_BY_PRIORITY):
            errCode = this->HandleImplicitQueryInfoByPriority(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::IMPLICIT_QUERY_INFOS):
            errCode = this->HandleImplicitQueryInfos(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ALL_DEPENDENT_MODULE_NAMES):
            errCode = this->HandleGetAllDependentModuleNames(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_SANDBOX_APP_BUNDLE_INFO):
            errCode = this->HandleGetSandboxBundleInfo(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_CALLING_BUNDLE_NAME):
            errCode = this->HandleObtainCallingBundleName(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_STATS):
            errCode = this->HandleGetBundleStats(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ALL_BUNDLE_STATS):
            errCode = this->HandleGetAllBundleStats(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::CHECK_ABILITY_ENABLE_INSTALL):
            errCode = this->HandleCheckAbilityEnableInstall(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_STRING_BY_ID):
            errCode = this->HandleGetStringById(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ICON_BY_ID):
            errCode = this->HandleGetIconById(data, reply);
            break;
#ifdef BUNDLE_FRAMEWORK_DEFAULT_APP
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_DEFAULT_APP_PROXY):
            errCode = this->HandleGetDefaultAppProxy(data, reply);
            break;
#endif
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_SANDBOX_APP_ABILITY_INFO):
            errCode = this->HandleGetSandboxAbilityInfo(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_SANDBOX_APP_EXTENSION_INFOS):
            errCode = this->HandleGetSandboxExtAbilityInfos(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_SANDBOX_MODULE_INFO):
            errCode = this->HandleGetSandboxHapModuleInfo(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_MEDIA_DATA):
            errCode = this->HandleGetMediaData(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_QUICK_FIX_MANAGER_PROXY):
            errCode = this->HandleGetQuickFixManagerProxy(data, reply);
            break;
#ifdef BUNDLE_FRAMEWORK_APP_CONTROL
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_APP_CONTROL_PROXY):
            errCode = this->HandleGetAppControlProxy(data, reply);
            break;
#endif
        case static_cast<uint32_t>(BundleMgrInterfaceCode::SET_DEBUG_MODE):
            errCode = this->HandleSetDebugMode(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_INFO_FOR_SELF):
            errCode = this->HandleGetBundleInfoForSelf(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::VERIFY_SYSTEM_API):
            errCode = this->HandleVerifySystemApi(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_OVERLAY_MANAGER_PROXY):
            errCode = this->HandleGetOverlayManagerProxy(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::SILENT_INSTALL):
            errCode = this->HandleSilentInstall(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::PROCESS_PRELOAD):
            errCode = this->HandleProcessPreload(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_APP_PROVISION_INFO):
            errCode = this->HandleGetAppProvisionInfo(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_PROVISION_METADATA):
            errCode = this->HandleGetProvisionMetadata(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BASE_SHARED_BUNDLE_INFOS):
            errCode = this->HandleGetBaseSharedBundleInfos(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ALL_SHARED_BUNDLE_INFO):
            errCode = this->HandleGetAllSharedBundleInfo(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_SHARED_BUNDLE_INFO):
            errCode = this->HandleGetSharedBundleInfo(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_SHARED_BUNDLE_INFO_BY_SELF):
            errCode = this->HandleGetSharedBundleInfoBySelf(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_SHARED_DEPENDENCIES):
            errCode = this->HandleGetSharedDependencies(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_DEPENDENT_BUNDLE_INFO):
            errCode = this->HandleGetDependentBundleInfo(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_UID_BY_DEBUG_BUNDLE_NAME):
            errCode = this->HandleGetUidByDebugBundleName(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_PROXY_DATA_INFOS):
            errCode = this->HandleGetProxyDataInfos(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ALL_PROXY_DATA_INFOS):
            errCode = this->HandleGetAllProxyDataInfos(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_SPECIFIED_DISTRIBUTED_TYPE):
            errCode = this->HandleGetSpecifiedDistributionType(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ADDITIONAL_INFO):
            errCode = this->HandleGetAdditionalInfo(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::SET_EXT_NAME_OR_MIME_TO_APP):
            errCode = this->HandleSetExtNameOrMIMEToApp(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::DEL_EXT_NAME_OR_MIME_TO_APP):
            errCode = this->HandleDelExtNameOrMIMEToApp(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_DATA_GROUP_INFOS):
            errCode = this->HandleQueryDataGroupInfos(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_PREFERENCE_DIR_BY_GROUP_ID):
            errCode = this->HandleGetPreferenceDirByGroupId(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_APPGALLERY_BUNDLE_NAME):
            errCode = this->HandleQueryAppGalleryBundleName(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_EXTENSION_ABILITY_INFO_WITH_TYPE_NAME):
            errCode = this->HandleQueryExtensionAbilityInfosWithTypeName(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_EXTENSION_ABILITY_INFO_ONLY_WITH_TYPE_NAME):
            errCode = this->HandleQueryExtensionAbilityInfosOnlyWithTypeName(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::RESET_AOT_COMPILE_STATUS):
            errCode = this->HandleResetAOTCompileStatus(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_JSON_PROFILE):
            errCode = this->HandleGetJsonProfile(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_RESOURCE_PROXY):
            errCode = this->HandleGetBundleResourceProxy(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_VERIFY_MANAGER):
            errCode = this->HandleGetVerifyManager(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_RECOVERABLE_APPLICATION_INFO):
            errCode = this->HandleGetRecoverableApplicationInfo(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_UNINSTALLED_BUNDLE_INFO):
            errCode = this->HandleGetUninstalledBundleInfo(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::SET_ADDITIONAL_INFO):
            errCode = this->HandleSetAdditionalInfo(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::COMPILE_PROCESSAOT):
            errCode = this->HandleCompileProcessAOT(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::COMPILE_RESET):
            errCode = this->HandleCompileReset(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::CAN_OPEN_LINK):
            errCode = this->HandleCanOpenLink(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ODID):
            errCode = this->HandleGetOdid(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_PREINSTALLED_APPLICATION_INFO):
            errCode = this->HandleGetAllPreinstalledApplicationInfos(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_EXTEND_RESOURCE_MANAGER):
            errCode = this->HandleGetExtendResourceManager(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ALL_BUNDLE_INFO_BY_DEVELOPER_ID):
            errCode = this->HandleGetAllBundleInfoByDeveloperId(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_DEVELOPER_IDS):
            errCode = this->HandleGetDeveloperIds(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::SWITCH_UNINSTALL_STATE):
            errCode = this->HandleSwitchUninstallState(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_ABILITY_INFO_BY_CONTINUE_TYPE):
            errCode = this->HandleQueryAbilityInfoByContinueType(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_CLONE_ABILITY_INFO):
            errCode = this->HandleQueryCloneAbilityInfo(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_CLONE_BUNDLE_INFO):
            errCode = this->HandleGetCloneBundleInfo(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::COPY_AP):
            errCode = this->HandleCopyAp(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_CLONE_APP_INDEXES):
            errCode = this->HandleGetCloneAppIndexes(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_LAUNCH_WANT):
            errCode = this->HandleGetLaunchWant(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_CLONE_EXTENSION_ABILITY_INFO_WITH_APP_INDEX):
            errCode = this->HandleQueryCloneExtensionAbilityInfoWithAppIndex(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_SIGNATURE_INFO):
            errCode = this->HandleGetSignatureInfoByBundleName(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::SET_CLONE_APPLICATION_ENABLED):
            errCode = this->HandleSetCloneApplicationEnabled(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::IS_CLONE_APPLICATION_ENABLED):
            errCode = this->HandleIsCloneApplicationEnabled(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::SET_CLONE_ABILITY_ENABLED):
            errCode = this->HandleSetCloneAbilityEnabled(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::IS_CLONE_ABILITY_ENABLED):
            errCode = this->HandleIsCloneAbilityEnabled(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::ADD_DESKTOP_SHORTCUT_INFO):
            errCode = this->HandleAddDesktopShortcutInfo(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::DELETE_DESKTOP_SHORTCUT_INFO):
            errCode = this->HandleDeleteDesktopShortcutInfo(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ALL_DESKTOP_SHORTCUT_INFO):
            errCode = this->HandleGetAllDesktopShortcutInfo(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ODID_BY_BUNDLENAME):
            errCode = this->HandleGetOdidByBundleName(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_INFOS_FOR_CONTINUATION):
            errCode = this->HandleGetBundleInfosForContinuation(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::GET_CONTINUE_BUNDLE_NAMES):
            errCode = HandleGetContinueBundleNames(data, reply);
            break;
        case static_cast<uint32_t>(BundleMgrInterfaceCode::IS_BUNDLE_INSTALLED):
            errCode = HandleIsBundleInstalled(data, reply);
            break;
        default :
            APP_LOGW("bundleMgr host receives unknown code %{public}u", code);
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    APP_LOGD("bundleMgr host finish to process message, errCode: %{public}d", errCode);
    return (errCode == ERR_OK) ? NO_ERROR : UNKNOWN_ERROR;
}

ErrCode BundleMgrHost::HandleGetApplicationInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string name = data.ReadString();
    ApplicationFlag flag = static_cast<ApplicationFlag>(data.ReadInt32());
    int userId = data.ReadInt32();
    APP_LOGD("name %{public}s, flag %{public}d, userId %{public}d", name.c_str(), flag, userId);

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
        if (!WriteVectorToParcelIntelligent(infos, reply)) {
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
        if (!WriteVectorToParcelIntelligent(infos, reply)) {
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
    APP_LOGD("name %{public}s, flag %{public}d", name.c_str(), flag);
    BundleInfo info;
    bool ret = GetBundleInfo(name, flag, info, userId);
    if (ret) {
        WRITE_PARCEL(reply.WriteInt32(ERR_OK));
        return WriteParcelInfoIntelligent(info, reply);
    }
    WRITE_PARCEL(reply.WriteInt32(ERR_APPEXECFWK_PARCEL_ERROR));
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

ErrCode BundleMgrHost::HandleGetDependentBundleInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string name = data.ReadString();
    GetDependentBundleInfoFlag flag = static_cast<GetDependentBundleInfoFlag>(data.ReadUint32());
    APP_LOGD("GetDependentBundleInfo, bundle %{public}s", name.c_str());
    BundleInfo info;
    reply.SetDataCapacity(Constants::CAPACITY_SIZE);
    auto ret = GetDependentBundleInfo(name, info, flag);
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
    if (ret) {
        WRITE_PARCEL(reply.WriteInt32(ERR_OK));
        return WriteParcelInfoIntelligent(info, reply);
    }
    WRITE_PARCEL(reply.WriteInt32(ERR_APPEXECFWK_PARCEL_ERROR));
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
    if (ret == ERR_OK) {
        return WriteParcelInfoIntelligent<BundleInfo>(info, reply);
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleBatchGetBundleInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    int32_t bundleNameCount = data.ReadInt32();
    if (bundleNameCount <= 0 || bundleNameCount > MAX_BATCH_QUERY_BUNDLE_SIZE) {
        APP_LOGE("bundleName count is error");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    std::vector<std::string> bundleNames;
    for (int i = 0; i < bundleNameCount; i++) {
        std::string bundleName = data.ReadString();
        if (bundleName.empty()) {
            APP_LOGE("bundleName %{public}d is empty", i);
            return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
        }
        bundleNames.push_back(bundleName);
    }

    int32_t flags = data.ReadInt32();
    int32_t userId = data.ReadInt32();
    std::vector<BundleInfo> bundleInfos;
    reply.SetDataCapacity(Constants::CAPACITY_SIZE);
    auto ret = BatchGetBundleInfo(bundleNames, flags, bundleInfos, userId);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        if (!WriteVectorToParcelIntelligent(bundleInfos, reply)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
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
    reply.SetDataCapacity(MAX_CAPACITY_BUNDLES);
    bool ret = GetBundleInfos(flag, infos, userId);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!WriteVectorToParcelIntelligent(infos, reply)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    APP_LOGI("bundles %{public}zu, size %{public}zu", infos.size(), reply.GetRawDataSize());
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetBundleInfosWithIntFlags(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    int flags = data.ReadInt32();
    int userId = data.ReadInt32();

    std::vector<BundleInfo> infos;
    reply.SetDataCapacity(MAX_CAPACITY_BUNDLES);
    bool ret = GetBundleInfos(flags, infos, userId);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!WriteVectorToParcelIntelligent(infos, reply)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    APP_LOGI("bundles %{public}zu, size %{public}zu", infos.size(), reply.GetRawDataSize());
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
        if (!WriteVectorToParcelIntelligent(infos, reply)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    APP_LOGI("bundles %{public}zu, size %{public}zu", infos.size(), reply.GetRawDataSize());
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetBundleNameForUid(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    auto uid = data.ReadInt32();
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

ErrCode BundleMgrHost::HandleGetNameAndIndexForUid(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    int uid = data.ReadInt32();
    std::string bundleName;
    int32_t appIndex;
    ErrCode ret = GetNameAndIndexForUid(uid, bundleName, appIndex);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        if (!reply.WriteString(bundleName)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        if (!reply.WriteInt32(appIndex)) {
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
        if (!WriteVectorToParcelIntelligent(abilityInfos, reply)) {
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
        if (!WriteVectorToParcelIntelligent(abilityInfos, reply)) {
            APP_LOGE("WriteVectorToParcelIntelligent failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleBatchQueryAbilityInfos(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    int32_t wantCount = data.ReadInt32();
    if (wantCount <= 0 || wantCount > MAX_BATCH_QUERY_ABILITY_SIZE) {
        APP_LOGE("want count is error");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    std::vector<Want> wants;
    for (int i = 0; i < wantCount; i++) {
        std::unique_ptr<Want> want(data.ReadParcelable<Want>());
        if (want == nullptr) {
            APP_LOGE("ReadParcelable<want> failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        wants.push_back(*want);
    }

    int32_t flags = data.ReadInt32();
    int32_t userId = data.ReadInt32();
    std::vector<AbilityInfo> abilityInfos;
    ErrCode ret = BatchQueryAbilityInfos(wants, flags, userId, abilityInfos);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        if (!WriteVectorToParcelIntelligent(abilityInfos, reply)) {
            APP_LOGE("WriteVectorToParcelIntelligent failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleQueryLauncherAbilityInfos(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        APP_LOGE("ReadParcelable<want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t userId = data.ReadInt32();
    std::vector<AbilityInfo> abilityInfos;
    ErrCode ret = QueryLauncherAbilityInfos(*want, userId, abilityInfos);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        if (!WriteVectorToParcelIntelligent(abilityInfos, reply)) {
            APP_LOGE("WriteVectorToParcelIntelligent failed");
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
        if (!WriteVectorToParcelIntelligent(abilityInfos, reply)) {
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

    APP_LOGD("bundleName %{public}s, abilityName %{public}s", bundleName.c_str(), abilityName.c_str());
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
    APP_LOGD("name %{public}s", bundleName.c_str());

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

ErrCode BundleMgrHost::HandleGetPermissionDef(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string permissionName = data.ReadString();
    APP_LOGD("name %{public}s", permissionName.c_str());

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

ErrCode BundleMgrHost::HandleCleanBundleCacheFilesAutomatic(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);

    uint64_t cacheSize = data.ReadUint64();
    ErrCode ret = CleanBundleCacheFilesAutomatic(cacheSize);

    if (!reply.WriteInt32(ret)) {
        APP_LOGE("WriteInt32 failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleCleanBundleCacheFiles(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    sptr<IRemoteObject> object = data.ReadRemoteObject();
    if (object == nullptr) {
        APP_LOGE("read failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    sptr<ICleanCacheCallback> cleanCacheCallback = iface_cast<ICleanCacheCallback>(object);
    int32_t userId = data.ReadInt32();
    int32_t appIndex = data.ReadInt32();

    ErrCode ret = CleanBundleCacheFiles(bundleName, cleanCacheCallback, userId, appIndex);
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
    int appIndex = data.ReadInt32();

    bool ret = CleanBundleDataFiles(bundleName, userId, appIndex);
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
    int32_t userId = data.ReadInt32();
    sptr<IRemoteObject> object = data.ReadRemoteObject();
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
        BundleStatusCallback->SetUserId(userId);
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
    sptr<IRemoteObject> object = data.ReadRemoteObject();
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
    sptr<IRemoteObject> object = data.ReadRemoteObject();
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
    sptr<IRemoteObject> object = data.ReadRemoteObject();
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

ErrCode BundleMgrHost::HandleCompileProcessAOT(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    std::string compileMode = data.ReadString();
    bool isAllBundle = data.ReadBool();
    std::vector<std::string> compileResults;

    APP_LOGI("compile info %{public}s", bundleName.c_str());
    ErrCode ret = CompileProcessAOT(bundleName, compileMode, isAllBundle, compileResults);
    APP_LOGI("ret %{public}d", ret);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret != ERR_OK) {
        if (!reply.WriteStringVector(compileResults)) {
            APP_LOGE("write compile process AOT results failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleCompileReset(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    bool isAllBundle = data.ReadBool();

    APP_LOGI("reset info %{public}s", bundleName.c_str());
    ErrCode ret = CompileReset(bundleName, isAllBundle);
    APP_LOGI("ret %{public}d", ret);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleCopyAp(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    bool isAllBundle = data.ReadBool();
    std::vector<std::string> results;
    ErrCode ret = CopyAp(bundleName, isAllBundle, results);
    APP_LOGI("ret %{public}d", ret);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("HandleCopyAp write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK && !reply.WriteStringVector(results)) {
        APP_LOGE("write HandleCopyAp results failed");
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
    APP_LOGI("dump info %{public}s", bundleName.c_str());
    bool ret = DumpInfos(flag, bundleName, userId, result);
    (void)reply.SetMaxCapacity(MAX_PARCEL_CAPACITY);
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
        APP_LOGE("WriteInt32 failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!reply.WriteBool(isEnable)) {
        APP_LOGE("WriteBool failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleIsCloneApplicationEnabled(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    if (bundleName.empty()) {
        APP_LOGE("fail to HandleIsCloneApplicationEnabled due to params empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    int32_t appIndex = data.ReadInt32();
    bool isEnable = false;
    ErrCode ret = IsCloneApplicationEnabled(bundleName, appIndex, isEnable);
    if (!reply.WriteInt32(ret)) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if ((ret == ERR_OK) && !reply.WriteBool(isEnable)) {
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
        APP_LOGE("WriteInt32 failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleSetCloneApplicationEnabled(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    if (bundleName.empty()) {
        APP_LOGE("fail to SetCloneApplicationEnabled due to params empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    int32_t appIndex = data.ReadInt32();
    bool isEnable = data.ReadBool();
    int32_t userId = data.ReadInt32();
    ErrCode ret = SetCloneApplicationEnabled(bundleName, appIndex, isEnable, userId);
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
        APP_LOGE("WriteInt32 failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!reply.WriteBool(isEnable)) {
        APP_LOGE("WriteBool failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleIsCloneAbilityEnabled(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::unique_ptr<AbilityInfo> abilityInfo(data.ReadParcelable<AbilityInfo>());
    if (abilityInfo == nullptr) {
        APP_LOGE("ReadParcelable<abilityInfo> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t appIndex = data.ReadInt32();
    bool isEnable = false;
    ErrCode ret = IsCloneAbilityEnabled(*abilityInfo, appIndex, isEnable);
    if (!reply.WriteInt32(ret)) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if ((ret == ERR_OK) && !reply.WriteBool(isEnable)) {
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
        APP_LOGE("WriteInt32 failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleSetCloneAbilityEnabled(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::unique_ptr<AbilityInfo> abilityInfo(data.ReadParcelable<AbilityInfo>());
    if (abilityInfo == nullptr) {
        APP_LOGE("ReadParcelable<abilityInfo> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t appIndex = data.ReadInt32();
    bool isEnabled = data.ReadBool();
    int32_t userId = data.ReadInt32();
    ErrCode ret = SetCloneAbilityEnabled(*abilityInfo, appIndex, isEnabled, userId);
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

    if (!reply.WriteRemoteObject(installer->AsObject())) {
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

    if (!reply.WriteRemoteObject(bundleUserMgr->AsObject())) {
        APP_LOGE("failed to reply bundle installer to client, for write MessageParcel error");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetVerifyManager(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    sptr<IVerifyManager> verifyManager = GetVerifyManager();
    if (verifyManager == nullptr) {
        APP_LOGE("verifyManager is nullptr");
        return ERR_BUNDLE_MANAGER_VERIFY_GET_VERIFY_MGR_FAILED;
    }

    if (!reply.WriteRemoteObject(verifyManager->AsObject())) {
        APP_LOGE("failed to reply bundle installer to client, for write MessageParcel error");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetExtendResourceManager(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    sptr<IExtendResourceManager> extendResourceManager = GetExtendResourceManager();
    if (extendResourceManager == nullptr) {
        APP_LOGE("extendResourceManager is nullptr");
        return ERR_EXT_RESOURCE_MANAGER_GET_EXT_RESOURCE_MGR_FAILED;
    }

    if (!reply.WriteRemoteObject(extendResourceManager->AsObject())) {
        APP_LOGE("failed to reply extendResourceManager, for write MessageParcel error");
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
    int32_t userId = data.ReadInt32();
    std::vector<ShortcutInfo> infos;
    ErrCode ret = GetShortcutInfoV9(bundlename, infos, userId);
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
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
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
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
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
    int32_t appIndex = data.ReadInt32();
    int32_t uid = GetUidByBundleName(bundleName, userId, appIndex);
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
        APP_LOGE("ReadParcelable want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t flags = data.ReadInt32();
    int32_t userId = data.ReadInt32();
    bool withDefault = data.ReadBool();
    bool findDefaultApp = false;
    std::vector<AbilityInfo> abilityInfos;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    bool ret = ImplicitQueryInfos(*want, flags, userId, withDefault, abilityInfos, extensionInfos, findDefaultApp);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("WriteBool ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!WriteParcelableVector(abilityInfos, reply)) {
            APP_LOGE("WriteParcelableVector abilityInfos failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        if (!WriteParcelableVector(extensionInfos, reply)) {
            APP_LOGE("WriteParcelableVector extensionInfo failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        if (!reply.WriteBool(findDefaultApp)) {
            APP_LOGE("write findDefaultApp failed");
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
        APP_LOGE("WriteInt32 failed");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_WRITE_PARCEL_ERROR;
    }
    if ((res == ERR_OK) && (!reply.WriteParcelable(&info))) {
        return ERR_APPEXECFWK_SANDBOX_INSTALL_WRITE_PARCEL_ERROR;
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
    sptr<IRemoteObject> object = data.ReadRemoteObject();

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

#ifdef BUNDLE_FRAMEWORK_DEFAULT_APP
ErrCode BundleMgrHost::HandleGetDefaultAppProxy(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    sptr<IDefaultApp> defaultAppProxy = GetDefaultAppProxy();
    if (defaultAppProxy == nullptr) {
        APP_LOGE("defaultAppProxy is nullptr");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!reply.WriteRemoteObject(defaultAppProxy->AsObject())) {
        APP_LOGE("WriteRemoteObject failed");
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
        APP_LOGE("appControlProxy is nullptr");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!reply.WriteRemoteObject(appControlProxy->AsObject())) {
        APP_LOGE("WriteRemoteObject failed");
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
        APP_LOGE("quickFixManagerProxy is nullptr");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!reply.WriteRemoteObject(quickFixManagerProxy->AsObject())) {
        APP_LOGE("WriteRemoteObject failed");
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
bool BundleMgrHost::WriteVectorToParcelIntelligent(std::vector<T> &parcelableVector, MessageParcel &reply)
{
    Parcel tempParcel;
    (void)tempParcel.SetMaxCapacity(MAX_PARCEL_CAPACITY);
    if (!tempParcel.WriteInt32(parcelableVector.size())) {
        APP_LOGE("write ParcelableVector failed");
        return false;
    }

    for (auto &parcelable : parcelableVector) {
        if (!tempParcel.WriteParcelable(&parcelable)) {
            APP_LOGE("write ParcelableVector failed");
            return false;
        }
    }

    size_t dataSize = tempParcel.GetDataSize();
    if (!reply.WriteInt32(static_cast<int32_t>(dataSize))) {
        APP_LOGE("write WriteInt32 failed");
        return false;
    }

    if (!reply.WriteRawData(
        reinterpret_cast<uint8_t *>(tempParcel.GetData()), dataSize)) {
        APP_LOGE("Failed to write data");
        return false;
    }

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
    sptr<IRemoteObject> object = data.ReadRemoteObject();
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
    sptr<IRemoteObject> object = data.ReadRemoteObject();
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
    int32_t appIndex = data.ReadInt32();
    uint32_t statFlag = data.ReadUint32();
    std::vector<int64_t> bundleStats;
    bool ret = GetBundleStats(bundleName, userId, bundleStats, appIndex, statFlag);
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

ErrCode BundleMgrHost::HandleGetAllBundleStats(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    int32_t userId = data.ReadInt32();
    std::vector<int64_t> bundleStats;
    bool ret = GetAllBundleStats(userId, bundleStats);
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
    APP_LOGD("HandleGetMediaData:%{public}s, %{public}s, %{public}s", bundleName.c_str(),
        abilityName.c_str(), moduleName.c_str());
    std::unique_ptr<uint8_t[]> mediaDataPtr = nullptr;
    size_t len = 0;
    ErrCode ret = GetMediaData(bundleName, moduleName, abilityName, mediaDataPtr, len, userId);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret != ERR_OK) {
        return ERR_OK;
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

ErrCode BundleMgrHost::HandleGetOverlayManagerProxy(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    sptr<IOverlayManager> overlayManagerProxy = GetOverlayManagerProxy();
    if (overlayManagerProxy == nullptr) {
        APP_LOGE("overlayManagerProxy is nullptr");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!reply.WriteRemoteObject(overlayManagerProxy->AsObject())) {
        APP_LOGE("WriteRemoteObject failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
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

ErrCode BundleMgrHost::HandleGetAppProvisionInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    int32_t userId = data.ReadInt32();
    AppProvisionInfo appProvisionInfo;
    ErrCode ret = GetAppProvisionInfo(bundleName, userId, appProvisionInfo);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("HandleGetAppProvisionInfo write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if ((ret == ERR_OK) && !reply.WriteParcelable(&appProvisionInfo)) {
        APP_LOGE("write appProvisionInfo failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetProvisionMetadata(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    int32_t userId = data.ReadInt32();
    APP_LOGD("start to get provision metadata, bundleName is %{public}s, userId is %{public}d",
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

ErrCode BundleMgrHost::HandleGetBaseSharedBundleInfos(MessageParcel &data, MessageParcel &reply)
{
    APP_LOGD("start to process HandleGetBaseSharedBundleInfos message");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    GetDependentBundleInfoFlag flag = static_cast<GetDependentBundleInfoFlag>(data.ReadUint32());

    std::vector<BaseSharedBundleInfo> infos;
    ErrCode ret = GetBaseSharedBundleInfos(bundleName, infos, flag);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret != ERR_OK) {
        return ERR_OK;
    }
    if (!WriteParcelableVector(infos, reply)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetAllSharedBundleInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::vector<SharedBundleInfo> infos;
    ErrCode ret = GetAllSharedBundleInfo(infos);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("HandleGetAllSharedBundleInfo write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if ((ret == ERR_OK) && !WriteParcelableVector(infos, reply)) {
        APP_LOGE("write infos failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetSharedBundleInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    std::string moduleName = data.ReadString();
    std::vector<SharedBundleInfo> infos;
    ErrCode ret = GetSharedBundleInfo(bundleName, moduleName, infos);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("HandleGetSharedBundleInfo write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if ((ret == ERR_OK) && !WriteParcelableVector(infos, reply)) {
        APP_LOGE("write infos failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetSharedBundleInfoBySelf(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    SharedBundleInfo shareBundleInfo;
    ErrCode ret = GetSharedBundleInfoBySelf(bundleName, shareBundleInfo);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("HandleGetSharedBundleInfoBySelf write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if ((ret == ERR_OK) && !reply.WriteParcelable(&shareBundleInfo)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetSharedDependencies(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    std::string moduleName = data.ReadString();
    std::vector<Dependency> dependencies;
    ErrCode ret = GetSharedDependencies(bundleName, moduleName, dependencies);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("HandleGetSharedDependencies write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if ((ret == ERR_OK) && !WriteParcelableVector(dependencies, reply)) {
        APP_LOGE("write dependencies failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetProxyDataInfos(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    std::string moduleName = data.ReadString();
    int32_t userId = data.ReadInt32();
    std::vector<ProxyData> proxyDatas;
    ErrCode ret = GetProxyDataInfos(bundleName, moduleName, proxyDatas, userId);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("HandleGetProxyDataInfos write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if ((ret == ERR_OK) && !WriteParcelableVector(proxyDatas, reply)) {
        APP_LOGE("write proxyDatas failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetAllProxyDataInfos(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::vector<ProxyData> proxyDatas;
    int32_t userId = data.ReadInt32();
    ErrCode ret = GetAllProxyDataInfos(proxyDatas, userId);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("HandleGetProxyDataInfos write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if ((ret == ERR_OK) && !WriteParcelableVector(proxyDatas, reply)) {
        APP_LOGE("write proxyDatas failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetSpecifiedDistributionType(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    std::string specifiedDistributedType;
    ErrCode ret = GetSpecifiedDistributionType(bundleName, specifiedDistributedType);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("HandleGetSpecifiedDistributionType write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if ((ret == ERR_OK) && !reply.WriteString(specifiedDistributedType)) {
        APP_LOGE("write specifiedDistributedType failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetAdditionalInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    std::string additionalInfo;
    ErrCode ret = GetAdditionalInfo(bundleName, additionalInfo);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("HandleGetAdditionalInfo write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if ((ret == ERR_OK) && !reply.WriteString(additionalInfo)) {
        APP_LOGE("write additionalInfo failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleSetExtNameOrMIMEToApp(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    std::string moduleName = data.ReadString();
    std::string abilityName = data.ReadString();
    std::string extName = data.ReadString();
    std::string mimeType = data.ReadString();
    ErrCode ret = SetExtNameOrMIMEToApp(bundleName, moduleName, abilityName, extName, mimeType);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("HandleSetExtNameOrMIMEToApp write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleDelExtNameOrMIMEToApp(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    std::string moduleName = data.ReadString();
    std::string abilityName = data.ReadString();
    std::string extName = data.ReadString();
    std::string mimeType = data.ReadString();
    ErrCode ret = DelExtNameOrMIMEToApp(bundleName, moduleName, abilityName, extName, mimeType);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("HandleDelExtNameOrMIMEToApp write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleQueryDataGroupInfos(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    int32_t userId = data.ReadInt32();

    std::vector<DataGroupInfo> infos;
    bool ret = QueryDataGroupInfos(bundleName, userId, infos);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret && !WriteParcelableVector(infos, reply)) {
        APP_LOGE("write dataGroupInfo failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetPreferenceDirByGroupId(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string dataGroupId = data.ReadString();
    std::string dir;
    bool ret = GetGroupDir(dataGroupId, dir);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!reply.WriteString(dir)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleQueryAppGalleryBundleName(MessageParcel &data, MessageParcel &reply)
{
    APP_LOGD("QueryAppGalleryBundleName in bundle mgr hoxt start");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName;
    bool ret = QueryAppGalleryBundleName(bundleName);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!reply.WriteString(bundleName)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    APP_LOGD("BundleName is %{public}s", bundleName.c_str());
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleQueryExtensionAbilityInfosWithTypeName(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<Want> want(data.ReadParcelable<Want>());
    if (want == nullptr) {
        APP_LOGE("ReadParcelable<want> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    std::string extensionTypeName = data.ReadString();
    int32_t flags = data.ReadInt32();
    int32_t userId = data.ReadInt32();
    std::vector<ExtensionAbilityInfo> extensionAbilityInfos;
    ErrCode ret =
        QueryExtensionAbilityInfosWithTypeName(*want, extensionTypeName, flags, userId, extensionAbilityInfos);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("Write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK && !WriteParcelableVector(extensionAbilityInfos, reply)) {
        APP_LOGE("Write extension infos failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleQueryExtensionAbilityInfosOnlyWithTypeName(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string extensionTypeName = data.ReadString();
    uint32_t flags = data.ReadUint32();
    int32_t userId = data.ReadInt32();
    std::vector<ExtensionAbilityInfo> extensionAbilityInfos;
    ErrCode ret =
        QueryExtensionAbilityInfosOnlyWithTypeName(extensionTypeName, flags, userId, extensionAbilityInfos);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("Write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK && !WriteVectorToParcelIntelligent(extensionAbilityInfos, reply)) {
        APP_LOGE("Write extension infos failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleResetAOTCompileStatus(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    std::string moduleName = data.ReadString();
    int32_t triggerMode = data.ReadInt32();
    APP_LOGD("bundleName : %{public}s, moduleName : %{public}s, triggerMode : %{public}d",
        bundleName.c_str(), moduleName.c_str(), triggerMode);
    ErrCode ret = ResetAOTCompileStatus(bundleName, moduleName, triggerMode);
    APP_LOGD("ret : %{public}d", ret);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write ret failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetJsonProfile(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    ProfileType profileType = static_cast<ProfileType>(data.ReadInt32());
    std::string bundleName = data.ReadString();
    std::string moduleName = data.ReadString();
    int32_t userId = data.ReadInt32();
    std::string profile;
    ErrCode ret = GetJsonProfile(profileType, bundleName, moduleName, profile, userId);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK && WriteBigString(profile, reply) != ERR_OK) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetBundleResourceProxy(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    sptr<IBundleResource> bundleResourceProxy = GetBundleResourceProxy();
    if (bundleResourceProxy == nullptr) {
        APP_LOGE("bundleResourceProxy is nullptr");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!reply.WriteRemoteObject(bundleResourceProxy->AsObject())) {
        APP_LOGE("WriteRemoteObject failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetRecoverableApplicationInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::vector<RecoverableApplicationInfo> infos;
    ErrCode ret = GetRecoverableApplicationInfo(infos);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("HandleGetRecoverableApplicationInfo write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if ((ret == ERR_OK) && !WriteParcelableVector(infos, reply)) {
        APP_LOGE("write infos failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetUninstalledBundleInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string name = data.ReadString();
    if (name.empty()) {
        APP_LOGE("bundleName is empty");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    BundleInfo info;
    reply.SetDataCapacity(Constants::CAPACITY_SIZE);
    auto ret = GetUninstalledBundleInfo(name, info);
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

ErrCode BundleMgrHost::HandleSetAdditionalInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    std::string additionalInfo = data.ReadString();
    ErrCode ret = SetAdditionalInfo(bundleName, additionalInfo);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("Write reply failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleCreateBundleDataDir(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGI("CreateBundleDataDir called");
    int32_t userId = data.ReadInt32();
    ErrCode ret = CreateBundleDataDir(userId);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("Write reply failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

template<typename T>
bool BundleMgrHost::WriteParcelableIntoAshmem(
    T &parcelable, const char *ashmemName, MessageParcel &reply)
{
    APP_LOGE("Write parcelable into ashmem");
    if (ashmemName == nullptr) {
        APP_LOGE("AshmemName is null");
        return false;
    }

    MessageParcel *messageParcel = reinterpret_cast<MessageParcel *>(&reply);
    if (messageParcel == nullptr) {
        APP_LOGE("Type conversion failed");
        return false;
    }

    int32_t totalSize = 0;
    auto infoStr = GetJsonStrFromInfo<T>(parcelable);
    totalSize += ASHMEM_LEN;
    totalSize += strlen(infoStr.c_str());
    if (totalSize <= 0) {
        APP_LOGE("The size of the ashmem is invalid or the content is empty");
        return false;
    }

    // The ashmem name must be unique.
    sptr<Ashmem> ashmem = Ashmem::CreateAshmem(
        (ashmemName + std::to_string(AllocatAshmemNum())).c_str(), totalSize);
    if (ashmem == nullptr) {
        APP_LOGE("Create shared memory failed");
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
    int itemLen = static_cast<int>(strlen(infoStr.c_str()));
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

    ret = messageParcel->WriteAshmem(ashmem);
    ClearAshmem(ashmem);
    if (!ret) {
        APP_LOGE("Write ashmem to MessageParcel fail");
        return false;
    }

    APP_LOGE("Write parcelable vector into ashmem success");
    return true;
}

template<typename T>
ErrCode BundleMgrHost::WriteBigParcelable(T &parcelable, const char *ashmemName, MessageParcel &reply)
{
    auto size = sizeof(reply);
    APP_LOGD("reply size is %{public}lu", static_cast<unsigned long>(size));
    bool useAshMem = size > ASHMEM_THRESHOLD;
    if (!reply.WriteBool(useAshMem)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (useAshMem) {
        APP_LOGI("reply size %{public}lu, writing ashmem", static_cast<unsigned long>(size));
        if (!WriteParcelableIntoAshmem(parcelable, ashmemName, reply)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    } else {
        if (!reply.WriteParcelable(&parcelable)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

template<typename T>
ErrCode BundleMgrHost::WriteParcelInfoIntelligent(const T &parcelInfo, MessageParcel &reply) const
{
    Parcel tmpParcel;
    (void)tmpParcel.SetMaxCapacity(MAX_PARCEL_CAPACITY);
    if (!tmpParcel.WriteParcelable(&parcelInfo)) {
        APP_LOGE("write parcel failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    size_t dataSize = tmpParcel.GetDataSize();
    if (!reply.WriteUint32(dataSize)) {
        APP_LOGE("write parcel failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!reply.WriteRawData(reinterpret_cast<uint8_t *>(tmpParcel.GetData()), dataSize)) {
        APP_LOGE("write parcel failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

template<typename T>
ErrCode BundleMgrHost::WriteParcelInfo(const T &parcelInfo, MessageParcel &reply) const
{
    Parcel tmpParcel;
    (void)tmpParcel.SetMaxCapacity(MAX_PARCEL_CAPACITY);
    WRITE_PARCEL(tmpParcel.WriteParcelable(&parcelInfo));
    size_t dataSize = tmpParcel.GetDataSize();

    WRITE_PARCEL(reply.WriteUint32(dataSize));
    WRITE_PARCEL(reply.WriteRawData(reinterpret_cast<uint8_t *>(tmpParcel.GetData()), dataSize));
    return ERR_OK;
}

ErrCode BundleMgrHost::WriteBigString(const std::string &str, MessageParcel &reply) const
{
    WRITE_PARCEL(reply.WriteUint32(str.size() + 1));
    WRITE_PARCEL(reply.WriteRawData(str.c_str(), str.size() + 1));
    return ERR_OK;
}

template<typename T>
ErrCode BundleMgrHost::ReadParcelInfoIntelligent(MessageParcel &data, T &parcelInfo)
{
    size_t dataSize = data.ReadUint32();
    void *buffer = nullptr;
    if (!GetData(buffer, dataSize, data.ReadRawData(dataSize))) {
        APP_LOGE("GetData failed dataSize : %{public}zu", dataSize);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel tempParcel;
    if (!tempParcel.ParseFrom(reinterpret_cast<uintptr_t>(buffer), dataSize)) {
        APP_LOGE("ParseFrom failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    std::unique_ptr<T> info(tempParcel.ReadParcelable<T>());
    if (info == nullptr) {
        APP_LOGE("ReadParcelable failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    parcelInfo = *info;
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleCanOpenLink(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string link = data.ReadString();
    bool canOpen = false;
    ErrCode ret = CanOpenLink(link, canOpen);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!reply.WriteBool(canOpen)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetOdid(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string odid;
    auto ret = GetOdid(odid);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!reply.WriteString(odid)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    APP_LOGD("odid is %{private}s", odid.c_str());
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetAllPreinstalledApplicationInfos(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("Called");
    std::vector<PreinstalledApplicationInfo> preinstalledApplicationInfos;
    ErrCode ret = GetAllPreinstalledApplicationInfos(preinstalledApplicationInfos);
    int32_t vectorSize = static_cast<int32_t>(preinstalledApplicationInfos.size());
    if (vectorSize > MAX_STATUS_VECTOR_NUM) {
        APP_LOGE("PreinstallApplicationInfos vector is over size");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    constexpr int32_t VECTOR_SIZE_UNDER_DEFAULT_DATA = 500;
    if (vectorSize > VECTOR_SIZE_UNDER_DEFAULT_DATA &&
        !reply.SetDataCapacity(PREINSTALL_PARCEL_CAPACITY)) {
        APP_LOGE("SetDataCapacity failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("Write reply failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK && !WriteParcelableVector(preinstalledApplicationInfos, reply)) {
        APP_LOGE("Write preinstalled app infos failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetAllBundleInfoByDeveloperId(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string developerId = data.ReadString();
    int32_t userId = data.ReadInt32();
    std::vector<BundleInfo> infos;
    auto ret = GetAllBundleInfoByDeveloperId(developerId, infos, userId);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        if (!WriteVectorToParcelIntelligent(infos, reply)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetDeveloperIds(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string appDistributionType = data.ReadString();
    int32_t userId = data.ReadInt32();
    std::vector<std::string> developerIdList;
    auto ret = GetDeveloperIds(appDistributionType, developerIdList, userId);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        if (!reply.WriteStringVector(developerIdList)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleSwitchUninstallState(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    bool state = data.ReadBool();
    bool isNeedSendNotify = data.ReadBool();
    ErrCode ret = SwitchUninstallState(bundleName, state, isNeedSendNotify);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleQueryAbilityInfoByContinueType(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    std::string continueType = data.ReadString();
    int32_t userId = data.ReadInt32();
    AbilityInfo abilityInfo;
    auto ret = QueryAbilityInfoByContinueType(bundleName, continueType, abilityInfo, userId);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK && !reply.WriteParcelable(&abilityInfo)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleQueryCloneAbilityInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);

    std::unique_ptr<ElementName> elementNamePtr(data.ReadParcelable<ElementName>());
    if (!elementNamePtr) {
        APP_LOGE("ReadParcelable<ElementName> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t flags = data.ReadInt32();
    int32_t appIndex = data.ReadInt32();
    int32_t userId = data.ReadInt32();

    AbilityInfo abilityInfo;
    auto ret = QueryCloneAbilityInfo(*elementNamePtr, flags, appIndex, abilityInfo, userId);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK && !reply.WriteParcelable(&abilityInfo)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetCloneBundleInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    int32_t flags = data.ReadInt32();
    int32_t appIndex = data.ReadInt32();
    int32_t userId = data.ReadInt32();

    BundleInfo bundleInfo;
    auto ret = GetCloneBundleInfo(bundleName, flags, appIndex, bundleInfo, userId);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK && !reply.WriteParcelable(&bundleInfo)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetCloneAppIndexes(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    int32_t userId = data.ReadInt32();

    std::vector<int32_t> appIndexes;
    auto ret = GetCloneAppIndexes(bundleName, appIndexes, userId);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK && !reply.WriteInt32Vector(appIndexes)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetLaunchWant(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    Want want;
    ErrCode ret = GetLaunchWant(want);
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

ErrCode BundleMgrHost::HandleQueryCloneExtensionAbilityInfoWithAppIndex(MessageParcel &data, MessageParcel &reply)
{
    std::unique_ptr<ElementName> element(data.ReadParcelable<ElementName>());
    if (!element) {
        APP_LOGE("ReadParcelable<ElementName> failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t flag = data.ReadInt32();
    int32_t appIndex = data.ReadInt32();
    int32_t userId = data.ReadInt32();
    ExtensionAbilityInfo extensionAbilityInfo;
    auto ret = QueryCloneExtensionAbilityInfoWithAppIndex(*element, flag, appIndex, extensionAbilityInfo, userId);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK && !reply.WriteParcelable(&extensionAbilityInfo)) {
        APP_LOGE("write extension infos failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetSignatureInfoByBundleName(MessageParcel &data, MessageParcel &reply)
{
    std::string name = data.ReadString();
    SignatureInfo info;
    ErrCode ret = GetSignatureInfoByBundleName(name, info);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK) {
        return WriteParcelInfoIntelligent<SignatureInfo>(info, reply);
    }
    return ret;
}

ErrCode BundleMgrHost::HandleAddDesktopShortcutInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    ShortcutInfo shortcutInfo;
    auto ret = ReadParcelInfoIntelligent(data, shortcutInfo);
    if (ret != ERR_OK) {
        APP_LOGE("Read ParcelInfo failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t userId = data.ReadInt32();
    ret = AddDesktopShortcutInfo(shortcutInfo, userId);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("Write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleDeleteDesktopShortcutInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    ShortcutInfo shortcutInfo;
    auto ret = ReadParcelInfoIntelligent(data, shortcutInfo);
    if (ret != ERR_OK) {
        APP_LOGE("Read ParcelInfo failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t userId = data.ReadInt32();
    ret = DeleteDesktopShortcutInfo(shortcutInfo, userId);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("Write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetAllDesktopShortcutInfo(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    int32_t userId = data.ReadInt32();
    std::vector<ShortcutInfo> infos;
    auto ret = GetAllDesktopShortcutInfo(userId, infos);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("Write result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK && !WriteVectorToParcelIntelligent(infos, reply)) {
        APP_LOGE("Write shortcut infos failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetOdidByBundleName(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    std::string odid;
    auto ret = GetOdidByBundleName(bundleName, odid);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!reply.WriteString(odid)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    APP_LOGD("odid is %{private}s", odid.c_str());
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetBundleInfosForContinuation(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    int flags = data.ReadInt32();
    int userId = data.ReadInt32();
 
    std::vector<BundleInfo> infos;
    reply.SetDataCapacity(MAX_CAPACITY_BUNDLES);
    bool ret = GetBundleInfosForContinuation(flags, infos, userId);
    if (!reply.WriteBool(ret)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret) {
        if (!WriteVectorToParcelIntelligent(infos, reply)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleGetContinueBundleNames(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string continueBundleName = data.ReadString();
    int userId = data.ReadInt32();

    reply.SetDataCapacity(MAX_CAPACITY_BUNDLES);
    std::vector<std::string> bundleNames;

    auto ret = GetContinueBundleNames(continueBundleName, bundleNames, userId);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("GetContinueBundleNames write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (ret == ERR_OK && !reply.WriteStringVector(bundleNames)) {
        APP_LOGE("Write bundleNames results failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleIsBundleInstalled(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    int32_t userId = data.ReadInt32();
    int32_t apppIndex = data.ReadInt32();
    bool isBundleInstalled = false;
    auto ret = IsBundleInstalled(bundleName, userId, apppIndex, isBundleInstalled);
    if (!reply.WriteInt32(ret)) {
        APP_LOGE("IsBundleInstalled write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if ((ret == ERR_OK) && !reply.WriteBool(isBundleInstalled)) {
        APP_LOGE("Write isInstalled result failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS