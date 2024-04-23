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
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const int32_t LIMIT_PARCEL_SIZE = 1024;
const int32_t ASHMEM_LEN = 16;
constexpr size_t MAX_PARCEL_CAPACITY = 100 * 1024 * 1024; // 100M

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
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_APPLICATION_INFO),
        &BundleMgrHost::HandleGetApplicationInfo);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_APPLICATION_INFO_WITH_INT_FLAGS),
        &BundleMgrHost::HandleGetApplicationInfoWithIntFlags);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_APPLICATION_INFOS),
        &BundleMgrHost::HandleGetApplicationInfos);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_APPLICATION_INFO_WITH_INT_FLAGS_V9),
        &BundleMgrHost::HandleGetApplicationInfoWithIntFlagsV9);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_APPLICATION_INFOS_WITH_INT_FLAGS),
        &BundleMgrHost::HandleGetApplicationInfosWithIntFlags);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_APPLICATION_INFOS_WITH_INT_FLAGS_V9),
        &BundleMgrHost::HandleGetApplicationInfosWithIntFlagsV9);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_INFO),
        &BundleMgrHost::HandleGetBundleInfo);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_INFO_WITH_INT_FLAGS),
        &BundleMgrHost::HandleGetBundleInfoWithIntFlags);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_INFO_WITH_INT_FLAGS_V9),
        &BundleMgrHost::HandleGetBundleInfoWithIntFlagsV9);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::BATCH_GET_BUNDLE_INFO),
        &BundleMgrHost::HandleBatchGetBundleInfo);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_PACK_INFO),
        &BundleMgrHost::HandleGetBundlePackInfo);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_PACK_INFO_WITH_INT_FLAGS),
        &BundleMgrHost::HandleGetBundlePackInfoWithIntFlags);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_INFOS),
        &BundleMgrHost::HandleGetBundleInfos);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_INFOS_WITH_INT_FLAGS),
        &BundleMgrHost::HandleGetBundleInfosWithIntFlags);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_INFOS_WITH_INT_FLAGS_V9),
        &BundleMgrHost::HandleGetBundleInfosWithIntFlagsV9);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_NAME_FOR_UID),
        &BundleMgrHost::HandleGetBundleNameForUid);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLES_FOR_UID),
        &BundleMgrHost::HandleGetBundlesForUid);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_NAME_FOR_UID),
        &BundleMgrHost::HandleGetNameForUid);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_GIDS),
        &BundleMgrHost::HandleGetBundleGids);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_GIDS_BY_UID),
        &BundleMgrHost::HandleGetBundleGidsByUid);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_INFOS_BY_METADATA),
        &BundleMgrHost::HandleGetBundleInfosByMetaData);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_ABILITY_INFO),
        &BundleMgrHost::HandleQueryAbilityInfo);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_ABILITY_INFO_MUTI_PARAM),
        &BundleMgrHost::HandleQueryAbilityInfoMutiparam);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_ABILITY_INFOS),
        &BundleMgrHost::HandleQueryAbilityInfos);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_ABILITY_INFOS_MUTI_PARAM),
        &BundleMgrHost::HandleQueryAbilityInfosMutiparam);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_ABILITY_INFOS_V9),
        &BundleMgrHost::HandleQueryAbilityInfosV9);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::BATCH_QUERY_ABILITY_INFOS_V9),
        &BundleMgrHost::HandleBatchQueryAbilityInfosV9);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_LAUNCHER_ABILITY_INFO),
        &BundleMgrHost::HandleQueryLauncherAbilityInfos);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_ALL_ABILITY_INFOS),
        &BundleMgrHost::HandleQueryAllAbilityInfos);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_ABILITY_INFO_BY_URI),
        &BundleMgrHost::HandleQueryAbilityInfoByUri);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_ABILITY_INFOS_BY_URI),
        &BundleMgrHost::HandleQueryAbilityInfosByUri);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_ABILITY_INFO_BY_URI_FOR_USERID),
        &BundleMgrHost::HandleQueryAbilityInfoByUriForUserId);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_KEEPALIVE_BUNDLE_INFOS),
        &BundleMgrHost::HandleQueryKeepAliveBundleInfos);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ABILITY_LABEL),
        &BundleMgrHost::HandleGetAbilityLabel);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ABILITY_LABEL_WITH_MODULE_NAME),
        &BundleMgrHost::HandleGetAbilityLabelWithModuleName);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::CHECK_IS_SYSTEM_APP_BY_UID),
        &BundleMgrHost::HandleCheckIsSystemAppByUid);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_ARCHIVE_INFO),
        &BundleMgrHost::HandleGetBundleArchiveInfo);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_ARCHIVE_INFO_WITH_INT_FLAGS),
        &BundleMgrHost::HandleGetBundleArchiveInfoWithIntFlags);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_ARCHIVE_INFO_WITH_INT_FLAGS_V9),
        &BundleMgrHost::HandleGetBundleArchiveInfoWithIntFlagsV9);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_HAP_MODULE_INFO),
        &BundleMgrHost::HandleGetHapModuleInfo);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_LAUNCH_WANT_FOR_BUNDLE),
        &BundleMgrHost::HandleGetLaunchWantForBundle);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_PERMISSION_DEF),
        &BundleMgrHost::HandleGetPermissionDef);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::CLEAN_BUNDLE_CACHE_FILES),
        &BundleMgrHost::HandleCleanBundleCacheFiles);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::CREATE_BUNDLE_DATA_DIR),
        &BundleMgrHost::HandleCreateBundleDataDir);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::CLEAN_BUNDLE_DATA_FILES),
        &BundleMgrHost::HandleCleanBundleDataFiles);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::REGISTER_BUNDLE_STATUS_CALLBACK),
        &BundleMgrHost::HandleRegisterBundleStatusCallback);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::REGISTER_BUNDLE_EVENT_CALLBACK),
        &BundleMgrHost::HandleRegisterBundleEventCallback);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::UNREGISTER_BUNDLE_EVENT_CALLBACK),
        &BundleMgrHost::HandleUnregisterBundleEventCallback);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::CLEAR_BUNDLE_STATUS_CALLBACK),
        &BundleMgrHost::HandleClearBundleStatusCallback);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::UNREGISTER_BUNDLE_STATUS_CALLBACK),
        &BundleMgrHost::HandleUnregisterBundleStatusCallback);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::IS_APPLICATION_ENABLED),
        &BundleMgrHost::HandleIsApplicationEnabled);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::SET_APPLICATION_ENABLED),
        &BundleMgrHost::HandleSetApplicationEnabled);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::IS_ABILITY_ENABLED),
        &BundleMgrHost::HandleIsAbilityEnabled);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::SET_ABILITY_ENABLED),
        &BundleMgrHost::HandleSetAbilityEnabled);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ABILITY_INFO),
        &BundleMgrHost::HandleGetAbilityInfo);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ABILITY_INFO_WITH_MODULE_NAME),
        &BundleMgrHost::HandleGetAbilityInfoWithModuleName);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::DUMP_INFOS),
        &BundleMgrHost::HandleDumpInfos);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_INSTALLER),
        &BundleMgrHost::HandleGetBundleInstaller);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ALL_FORMS_INFO),
        &BundleMgrHost::HandleGetAllFormsInfo);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_FORMS_INFO_BY_APP),
        &BundleMgrHost::HandleGetFormsInfoByApp);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_FORMS_INFO_BY_MODULE),
        &BundleMgrHost::HandleGetFormsInfoByModule);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_SHORTCUT_INFO),
        &BundleMgrHost::HandleGetShortcutInfos);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_SHORTCUT_INFO_V9),
        &BundleMgrHost::HandleGetShortcutInfoV9);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ALL_COMMON_EVENT_INFO),
        &BundleMgrHost::HandleGetAllCommonEventInfo);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_USER_MGR),
        &BundleMgrHost::HandleGetBundleUserMgr);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_DISTRIBUTE_BUNDLE_INFO),
        &BundleMgrHost::HandleGetDistributedBundleInfo);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_APPLICATION_PRIVILEGE_LEVEL),
        &BundleMgrHost::HandleGetAppPrivilegeLevel);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_EXTENSION_INFO_WITHOUT_TYPE),
        &BundleMgrHost::HandleQueryExtAbilityInfosWithoutType);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_EXTENSION_INFO_WITHOUT_TYPE_V9),
        &BundleMgrHost::HandleQueryExtAbilityInfosWithoutTypeV9);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_EXTENSION_INFO),
        &BundleMgrHost::HandleQueryExtAbilityInfos);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_EXTENSION_INFO_V9),
        &BundleMgrHost::HandleQueryExtAbilityInfosV9);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_EXTENSION_INFO_BY_TYPE),
        &BundleMgrHost::HandleQueryExtAbilityInfosByType);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::VERIFY_CALLING_PERMISSION),
        &BundleMgrHost::HandleVerifyCallingPermission);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_EXTENSION_ABILITY_INFO_BY_URI),
        &BundleMgrHost::HandleQueryExtensionAbilityInfoByUri);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_APPID_BY_BUNDLE_NAME),
        &BundleMgrHost::HandleGetAppIdByBundleName);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_APP_TYPE),
        &BundleMgrHost::HandleGetAppType);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_UID_BY_BUNDLE_NAME),
        &BundleMgrHost::HandleGetUidByBundleName);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::IS_MODULE_REMOVABLE),
        &BundleMgrHost::HandleIsModuleRemovable);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::SET_MODULE_REMOVABLE),
        &BundleMgrHost::HandleSetModuleRemovable);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_ABILITY_INFO_WITH_CALLBACK),
        &BundleMgrHost::HandleQueryAbilityInfoWithCallback);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::UPGRADE_ATOMIC_SERVICE),
        &BundleMgrHost::HandleUpgradeAtomicService);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::IS_MODULE_NEED_UPDATE),
        &BundleMgrHost::HandleGetModuleUpgradeFlag);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::SET_MODULE_NEED_UPDATE),
        &BundleMgrHost::HandleSetModuleUpgradeFlag);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_HAP_MODULE_INFO_WITH_USERID),
        &BundleMgrHost::HandleGetHapModuleInfoWithUserId);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::IMPLICIT_QUERY_INFO_BY_PRIORITY),
        &BundleMgrHost::HandleImplicitQueryInfoByPriority);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::IMPLICIT_QUERY_INFOS),
        &BundleMgrHost::HandleImplicitQueryInfos);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ALL_DEPENDENT_MODULE_NAMES),
        &BundleMgrHost::HandleGetAllDependentModuleNames);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_SANDBOX_APP_BUNDLE_INFO),
        &BundleMgrHost::HandleGetSandboxBundleInfo);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_CALLING_BUNDLE_NAME),
        &BundleMgrHost::HandleObtainCallingBundleName);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_STATS),
        &BundleMgrHost::HandleGetBundleStats);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ALL_BUNDLE_STATS),
        &BundleMgrHost::HandleGetAllBundleStats);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::CHECK_ABILITY_ENABLE_INSTALL),
        &BundleMgrHost::HandleCheckAbilityEnableInstall);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_STRING_BY_ID),
        &BundleMgrHost::HandleGetStringById);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ICON_BY_ID),
        &BundleMgrHost::HandleGetIconById);
#ifdef BUNDLE_FRAMEWORK_DEFAULT_APP
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_DEFAULT_APP_PROXY),
        &BundleMgrHost::HandleGetDefaultAppProxy);
#endif
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_SANDBOX_APP_ABILITY_INFO),
        &BundleMgrHost::HandleGetSandboxAbilityInfo);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_SANDBOX_APP_EXTENSION_INFOS),
        &BundleMgrHost::HandleGetSandboxExtAbilityInfos);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_SANDBOX_MODULE_INFO),
        &BundleMgrHost::HandleGetSandboxHapModuleInfo);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_MEDIA_DATA),
        &BundleMgrHost::HandleGetMediaData);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_QUICK_FIX_MANAGER_PROXY),
        &BundleMgrHost::HandleGetQuickFixManagerProxy);
#ifdef BUNDLE_FRAMEWORK_APP_CONTROL
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_APP_CONTROL_PROXY),
        &BundleMgrHost::HandleGetAppControlProxy);
#endif
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::SET_DEBUG_MODE),
        &BundleMgrHost::HandleSetDebugMode);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_INFO_FOR_SELF),
        &BundleMgrHost::HandleGetBundleInfoForSelf);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::VERIFY_SYSTEM_API),
        &BundleMgrHost::HandleVerifySystemApi);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_OVERLAY_MANAGER_PROXY),
        &BundleMgrHost::HandleGetOverlayManagerProxy);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::SILENT_INSTALL),
        &BundleMgrHost::HandleSilentInstall);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::PROCESS_PRELOAD),
        &BundleMgrHost::HandleProcessPreload);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_APP_PROVISION_INFO),
        &BundleMgrHost::HandleGetAppProvisionInfo);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_PROVISION_METADATA),
        &BundleMgrHost::HandleGetProvisionMetadata);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BASE_SHARED_BUNDLE_INFOS),
        &BundleMgrHost::HandleGetBaseSharedBundleInfos);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ALL_SHARED_BUNDLE_INFO),
        &BundleMgrHost::HandleGetAllSharedBundleInfo);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_SHARED_BUNDLE_INFO),
        &BundleMgrHost::HandleGetSharedBundleInfo);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_SHARED_BUNDLE_INFO_BY_SELF),
        &BundleMgrHost::HandleGetSharedBundleInfoBySelf);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_SHARED_DEPENDENCIES),
        &BundleMgrHost::HandleGetSharedDependencies);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_DEPENDENT_BUNDLE_INFO),
        &BundleMgrHost::HandleGetDependentBundleInfo);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_UID_BY_DEBUG_BUNDLE_NAME),
        &BundleMgrHost::HandleGetUidByDebugBundleName);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_PROXY_DATA_INFOS),
        &BundleMgrHost::HandleGetProxyDataInfos);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ALL_PROXY_DATA_INFOS),
        &BundleMgrHost::HandleGetAllProxyDataInfos);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_SPECIFIED_DISTRIBUTED_TYPE),
        &BundleMgrHost::HandleGetSpecifiedDistributionType);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ADDITIONAL_INFO),
        &BundleMgrHost::HandleGetAdditionalInfo);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::SET_EXT_NAME_OR_MIME_TO_APP),
        &BundleMgrHost::HandleSetExtNameOrMIMEToApp);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::DEL_EXT_NAME_OR_MIME_TO_APP),
        &BundleMgrHost::HandleDelExtNameOrMIMEToApp);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_DATA_GROUP_INFOS),
        &BundleMgrHost::HandleQueryDataGroupInfos);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_PREFERENCE_DIR_BY_GROUP_ID),
        &BundleMgrHost::HandleGetPreferenceDirByGroupId);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_APPGALLERY_BUNDLE_NAME),
        &BundleMgrHost::HandleQueryAppGalleryBundleName);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_EXTENSION_ABILITY_INFO_WITH_TYPE_NAME),
        &BundleMgrHost::HandleQueryExtensionAbilityInfosWithTypeName);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_EXTENSION_ABILITY_INFO_ONLY_WITH_TYPE_NAME),
        &BundleMgrHost::HandleQueryExtensionAbilityInfosOnlyWithTypeName);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::RESET_AOT_COMPILE_STATUS),
        &BundleMgrHost::HandleResetAOTCompileStatus);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_JSON_PROFILE),
        &BundleMgrHost::HandleGetJsonProfile);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_BUNDLE_RESOURCE_PROXY),
        &BundleMgrHost::HandleGetBundleResourceProxy);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_VERIFY_MANAGER),
        &BundleMgrHost::HandleGetVerifyManager);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_RECOVERABLE_APPLICATION_INFO),
        &BundleMgrHost::HandleGetRecoverableApplicationInfo);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_UNINSTALLED_BUNDLE_INFO),
        &BundleMgrHost::HandleGetUninstalledBundleInfo);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::SET_ADDITIONAL_INFO),
        &BundleMgrHost::HandleSetAdditionalInfo);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::COMPILE_PROCESSAOT),
        &BundleMgrHost::HandleCompileProcessAOT);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::COMPILE_RESET),
        &BundleMgrHost::HandleCompileReset);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::CAN_OPEN_LINK),
        &BundleMgrHost::HandleCanOpenLink);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ODID),
        &BundleMgrHost::HandleGetOdid);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_EXTEND_RESOURCE_MANAGER),
        &BundleMgrHost::HandleGetExtendResourceManager);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_ALL_BUNDLE_INFO_BY_DEVELOPER_ID),
        &BundleMgrHost::HandleGetAllBundleInfoByDeveloperId);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_DEVELOPER_IDS),
        &BundleMgrHost::HandleGetDeveloperIds);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::SWITCH_UNINSTALL_STATE),
        &BundleMgrHost::HandleSwitchUninstallState);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::QUERY_ABILITY_INFO_BY_CONTINUE_TYPE),
        &BundleMgrHost::HandleQueryAbilityInfoByContinueType);
    funcMap_.emplace(static_cast<uint32_t>(BundleMgrInterfaceCode::GET_CLONE_ABILITY_INFO),
        &BundleMgrHost::HandleQueryCloneAbilityInfo);
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
    if (funcMap_.find(code) != funcMap_.end() && funcMap_[code] != nullptr) {
        errCode = (this->*funcMap_[code])(data, reply);
    } else {
        APP_LOGW("bundleMgr host receives unknown code, code = %{public}u", code);
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
    if (bundleNameCount <= 0) {
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
    reply.SetDataCapacity(Constants::MAX_CAPACITY_BUNDLES);
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
        if (!WriteVectorToParcelIntelligent(infos, reply)) {
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
        if (!WriteVectorToParcelIntelligent(infos, reply)) {
            APP_LOGE("write failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
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

ErrCode BundleMgrHost::HandleBatchQueryAbilityInfosV9(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    int32_t wantCount = data.ReadInt32();
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
    ErrCode ret = BatchQueryAbilityInfosV9(wants, flags, userId, abilityInfos);
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

    APP_LOGI("compile info name %{public}s", bundleName.c_str());
    ErrCode ret = CompileProcessAOT(bundleName, compileMode, isAllBundle);
    APP_LOGI("ret is %{public}d", ret);
    if (!reply.WriteInt32(ret)) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrHost::HandleCompileReset(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    std::string bundleName = data.ReadString();
    bool isAllBundle = data.ReadBool();

    APP_LOGI("reset info name %{public}s", bundleName.c_str());
    ErrCode ret = CompileReset(bundleName, isAllBundle);
    APP_LOGI("ret is %{public}d", ret);
    if (!reply.WriteInt32(ret)) {
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
    bool withDefault = data.ReadBool();
    std::vector<AbilityInfo> abilityInfos;
    std::vector<ExtensionAbilityInfo> extensionInfos;
    bool ret = ImplicitQueryInfos(*want, flags, userId, withDefault, abilityInfos, extensionInfos);
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
        APP_LOGE("defaultAppProxy is nullptr.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!reply.WriteRemoteObject(defaultAppProxy->AsObject())) {
        APP_LOGE("WriteRemoteObject failed.");
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

    if (!reply.WriteRemoteObject(appControlProxy->AsObject())) {
        APP_LOGE("WriteRemoteObject failed.");
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

    if (!reply.WriteRemoteObject(quickFixManagerProxy->AsObject())) {
        APP_LOGE("WriteRemoteObject failed.");
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

ErrCode BundleMgrHost::HandleGetOverlayManagerProxy(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    sptr<IOverlayManager> overlayManagerProxy = GetOverlayManagerProxy();
    if (overlayManagerProxy == nullptr) {
        APP_LOGE("overlayManagerProxy is nullptr.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!reply.WriteRemoteObject(overlayManagerProxy->AsObject())) {
        APP_LOGE("WriteRemoteObject failed.");
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
        return ret;
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
    return ret;
}

ErrCode BundleMgrHost::HandleGetBundleResourceProxy(MessageParcel &data, MessageParcel &reply)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    sptr<IBundleResource> bundleResourceProxy = GetBundleResourceProxy();
    if (bundleResourceProxy == nullptr) {
        APP_LOGE("bundleResourceProxy is nullptr.");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!reply.WriteRemoteObject(bundleResourceProxy->AsObject())) {
        APP_LOGE("WriteRemoteObject failed.");
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
    bool useAshMem = size > Constants::ASHMEM_THRESHOLD;
    if (!reply.WriteBool(useAshMem)) {
        APP_LOGE("write failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (useAshMem) {
        APP_LOGI("reply size %{public}lu, writing into ashmem", static_cast<unsigned long>(size));
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
    ErrCode ret = SwitchUninstallState(bundleName, state);
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
    return ret;
}
}  // namespace AppExecFwk
}  // namespace OHOS