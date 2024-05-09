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

#include "bundle_data_mgr.h"

#include <algorithm>
#include <chrono>
#include <cinttypes>
#include <sstream>

#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
#ifdef ACCOUNT_ENABLE
#include "os_account_info.h"
#endif
#endif
#include "account_helper.h"
#include "app_log_wrapper.h"
#include "app_log_tag_wrapper.h"
#include "app_provision_info_manager.h"
#include "bms_extension_data_mgr.h"
#include "bundle_constants.h"
#include "bundle_data_storage_rdb.h"
#include "preinstall_data_storage_rdb.h"
#include "bundle_event_callback_death_recipient.h"
#include "bundle_mgr_service.h"
#include "bundle_parser.h"
#include "bundle_permission_mgr.h"
#include "bundle_status_callback_death_recipient.h"
#include "bundle_util.h"
#ifdef BUNDLE_FRAMEWORK_DEFAULT_APP
#include "default_app_mgr.h"
#endif
#include "installd_client.h"
#include "ipc_skeleton.h"
#include "json_serializer.h"
#ifdef GLOBAL_I18_ENABLE
#include "locale_config.h"
#include "locale_info.h"
#endif
#include "mime_type_mgr.h"
#include "nlohmann/json.hpp"
#include "free_install_params.h"
#include "parameters.h"
#include "router_map_helper.h"
#include "singleton.h"
#ifdef BUNDLE_FRAMEWORK_OVERLAY_INSTALLATION
#include "bundle_overlay_data_manager.h"
#endif
#include "bundle_extractor.h"

#ifdef APP_DOMAIN_VERIFY_ENABLED
#include "app_domain_verify_mgr_client.h"
#endif

#ifdef BUNDLE_FRAMEWORK_UDMF_ENABLED
#include "type_descriptor.h"
#include "utd_client.h"
#endif

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int MAX_EVENT_CALL_BACK_SIZE = 100;
constexpr int32_t DATA_GROUP_INDEX_START = 1;
constexpr int32_t UUID_LENGTH = 36;
constexpr int32_t PROFILE_PREFIX_LENGTH = 9;
constexpr const char* GLOBAL_RESOURCE_BUNDLE_NAME = "ohos.global.systemres";
// freeInstall action
constexpr const char* FREE_INSTALL_ACTION = "ohos.want.action.hapFreeInstall";
// share action
constexpr const char* SHARE_ACTION = "ohos.want.action.sendData";
const std::string WANT_PARAM_PICKER_SUMMARY = "ability.picker.summary";
const std::string SUMMARY_TOTAL_COUNT = "totalCount";
const std::string WANT_PARAM_SUMMARY = "summary";
constexpr int32_t DEFAULT_SUMMARY_COUNT = 0;
// data share
constexpr const char* DATA_PROXY_URI_PREFIX = "datashareproxy://";
constexpr int32_t DATA_PROXY_URI_PREFIX_LEN = 17;
// profile path
constexpr const char* INTENT_PROFILE_PATH = "resources/base/profile/insight_intent.json";
constexpr const char* ADDITION_PROFILE_PATH = "resources/base/profile/addition.json";
constexpr const char* NETWORK_PROFILE_PATH = "resources/base/profile/network_config.json";
constexpr const char* UTD_SDT_PROFILE_PATH = "resources/rawfile/arkdata/utd/utd.json5";
constexpr const char* PKG_CONTEXT_PROFILE_PATH = "pkgContextInfo.json";
constexpr const char* PROFILE_PATH = "resources/base/profile/";
constexpr const char* PROFILE_PREFIX = "$profile:";
constexpr const char* JSON_SUFFIX = ".json";
const std::string BMS_EVENT_ADDITIONAL_INFO_CHANGED = "bms.event.ADDITIONAL_INFO_CHANGED";
const std::string ENTRY = "entry";

const std::map<ProfileType, const char*> PROFILE_TYPE_MAP = {
    { ProfileType::INTENT_PROFILE, INTENT_PROFILE_PATH },
    { ProfileType::ADDITION_PROFILE, ADDITION_PROFILE_PATH},
    { ProfileType::NETWORK_PROFILE, NETWORK_PROFILE_PATH },
    { ProfileType::UTD_SDT_PROFILE, UTD_SDT_PROFILE_PATH },
    { ProfileType::PKG_CONTEXT_PROFILE, PKG_CONTEXT_PROFILE_PATH }
};
const std::string SCHEME_END = "://";
constexpr const char* PARAM_URI_SEPARATOR = ":///";
constexpr const char* URI_SEPARATOR = "://";
constexpr uint32_t PARAM_URI_SEPARATOR_LEN = 4;
constexpr int32_t INVALID_BUNDLEID = -1;
constexpr int32_t DATA_GROUP_UID_OFFSET = 100000;
constexpr int32_t MAX_APP_UID = 65535;
}

BundleDataMgr::BundleDataMgr()
{
    InitStateTransferMap();
    dataStorage_ = std::make_shared<BundleDataStorageRdb>();
    preInstallDataStorage_ = std::make_shared<PreInstallDataStorageRdb>();
    sandboxAppHelper_ = DelayedSingleton<BundleSandboxAppHelper>::GetInstance();
    bundleStateStorage_ = std::make_shared<BundleStateStorage>();
    baseAppUid_ = system::GetIntParameter<int32_t>("const.product.baseappid", Constants::BASE_APP_UID);
    if (baseAppUid_ < Constants::BASE_APP_UID || baseAppUid_ >= MAX_APP_UID) {
        baseAppUid_ = Constants::BASE_APP_UID;
    }
    APP_LOGI("BundleDataMgr instance is created");
}

BundleDataMgr::~BundleDataMgr()
{
    APP_LOGI("BundleDataMgr instance is destroyed");
    installStates_.clear();
    transferStates_.clear();
    bundleInfos_.clear();
}

bool BundleDataMgr::LoadDataFromPersistentStorage()
{
    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
    // Judge whether bundleState json db exists.
    // If it does not exist, create it and return the judgment result.
    bool bundleStateDbExist = bundleStateStorage_->HasBundleUserInfoJsonDb();
    if (!dataStorage_->LoadAllData(bundleInfos_)) {
        APP_LOGW("LoadAllData failed");
        return false;
    }

    if (bundleInfos_.empty()) {
        APP_LOGW("persistent data is empty");
        return false;
    }

    for (const auto &item : bundleInfos_) {
        std::lock_guard<std::mutex> stateLock(stateMutex_);
        installStates_.emplace(item.first, InstallState::INSTALL_SUCCESS);
        AddAppHspBundleName(item.second.GetApplicationBundleType(), item.first);
    }

    RestoreUidAndGid();
    if (!bundleStateDbExist) {
        // Compatible old bundle status in kV db
        CompatibleOldBundleStateInKvDb();
    } else {
        ResetBundleStateData();
        // Load all bundle status from json db.
        LoadAllBundleStateDataFromJsonDb();
    }

    SetInitialUserFlag(true);

    RestoreSandboxUidAndGid(bundleIdMap_);
    return true;
}

void BundleDataMgr::CompatibleOldBundleStateInKvDb()
{
    for (auto& bundleInfoItem : bundleInfos_) {
        for (auto& innerBundleUserInfoItem : bundleInfoItem.second.GetInnerBundleUserInfos()) {
            auto& bundleUserInfo = innerBundleUserInfoItem.second.bundleUserInfo;
            if (bundleUserInfo.IsInitialState()) {
                continue;
            }

            // save old bundle state to json db
            bundleStateStorage_->SaveBundleStateStorage(
                bundleInfoItem.first, bundleUserInfo.userId, bundleUserInfo);
        }
    }
}

void BundleDataMgr::LoadAllBundleStateDataFromJsonDb()
{
    APP_LOGD("Load all bundle state start");
    std::map<std::string, std::map<int32_t, BundleUserInfo>> bundleStateInfos;
    if (!bundleStateStorage_->LoadAllBundleStateData(bundleStateInfos) || bundleStateInfos.empty()) {
        APP_LOGW("Load all bundle state failed");
        return;
    }

    for (auto& bundleState : bundleStateInfos) {
        auto infoItem = bundleInfos_.find(bundleState.first);
        if (infoItem == bundleInfos_.end()) {
            APP_LOGW("BundleName(%{public}s) not exist in cache", bundleState.first.c_str());
            continue;
        }

        InnerBundleInfo& newInfo = infoItem->second;
        for (auto& bundleUserState : bundleState.second) {
            auto& tempUserInfo = bundleUserState.second;
            newInfo.SetApplicationEnabled(tempUserInfo.enabled, bundleUserState.first);
            for (auto& disabledAbility : tempUserInfo.disabledAbilities) {
                newInfo.SetAbilityEnabled("", disabledAbility, false, bundleUserState.first);
            }
        }
    }

    APP_LOGD("Load all bundle state end");
}

void BundleDataMgr::ResetBundleStateData()
{
    for (auto& bundleInfoItem : bundleInfos_) {
        bundleInfoItem.second.ResetBundleState(Constants::ALL_USERID);
    }
}

bool BundleDataMgr::UpdateBundleInstallState(const std::string &bundleName, const InstallState state)
{
    if (bundleName.empty()) {
        APP_LOGW("update result:fail, reason:bundle name is empty");
        return false;
    }
    // always keep lock bundleInfoMutex_ before locking stateMutex_ to avoid deadlock
    std::unique_lock<std::shared_mutex> lck(bundleInfoMutex_);
    std::lock_guard<std::mutex> lock(stateMutex_);
    auto item = installStates_.find(bundleName);
    if (item == installStates_.end()) {
        if (state == InstallState::INSTALL_START) {
            installStates_.emplace(bundleName, state);
            APP_LOGD("update result:success, state:INSTALL_START");
            return true;
        }
        APP_LOGW("update result:fail, reason:incorrect state, bundleName: %{public}s", bundleName.c_str());
        return false;
    }

    auto stateRange = transferStates_.equal_range(state);
    for (auto previousState = stateRange.first; previousState != stateRange.second; ++previousState) {
        if (item->second == previousState->second) {
            APP_LOGD("update result:success, current:%{public}d, state:%{public}d", previousState->second, state);
            if (IsDeleteDataState(state)) {
                installStates_.erase(item);
                DeleteBundleInfo(bundleName, state);
                return true;
            }
            item->second = state;
            return true;
        }
    }
    APP_LOGW("bundleName: %{public}s, update result:fail, reason:incorrect current:%{public}d, state:%{public}d",
        bundleName.c_str(), item->second, state);
    return false;
}

bool BundleDataMgr::AddInnerBundleInfo(const std::string &bundleName, InnerBundleInfo &info)
{
    APP_LOGD("to save info:%{public}s", info.GetBundleName().c_str());
    if (bundleName.empty()) {
        APP_LOGW("save info fail, empty bundle name");
        return false;
    }

    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem != bundleInfos_.end()) {
        APP_LOGW("bundleName: %{public}s : bundle info already exist", bundleName.c_str());
        return false;
    }
    std::lock_guard<std::mutex> stateLock(stateMutex_);
    auto statusItem = installStates_.find(bundleName);
    if (statusItem == installStates_.end()) {
        APP_LOGW("save info fail, bundleName:%{public}s is not installed", bundleName.c_str());
        return false;
    }
    if (statusItem->second == InstallState::INSTALL_START) {
        APP_LOGD("save bundle:%{public}s info", bundleName.c_str());
        if (info.GetBaseApplicationInfo().needAppDetail) {
            AddAppDetailAbilityInfo(info);
        }
#ifdef BUNDLE_FRAMEWORK_OVERLAY_INSTALLATION
        if (info.GetOverlayType() == OVERLAY_EXTERNAL_BUNDLE) {
            InnerBundleInfo newInfo = info;
            std::string targetBundleName = newInfo.GetTargetBundleName();
            auto targetInfoItem = bundleInfos_.find(targetBundleName);
            if (targetInfoItem != bundleInfos_.end()) {
                OverlayDataMgr::GetInstance()->UpdateExternalOverlayInfo(newInfo, info, targetInfoItem->second);
                // storage target bundle info
                dataStorage_->SaveStorageBundleInfo(targetInfoItem->second);
            }
        }
        if (info.GetOverlayType() == OVERLAY_INTERNAL_BUNDLE) {
            info.SetOverlayModuleState(info.GetCurrentModulePackage(), OverlayState::OVERLAY_INVALID,
                info.GetUserId());
        }
        if (info.GetOverlayType() == NON_OVERLAY_TYPE) {
            // build overlay connection for external overlay
            BuildExternalOverlayConnection(info.GetCurrentModulePackage(), info, info.GetUserId());
        }
#endif
        if (dataStorage_->SaveStorageBundleInfo(info)) {
            APP_LOGD("write storage success bundle:%{public}s", bundleName.c_str());
            bundleInfos_.emplace(bundleName, info);
            AddAppHspBundleName(info.GetApplicationBundleType(), bundleName);
            return true;
        }
    }
    return false;
}

bool BundleDataMgr::AddNewModuleInfo(
    const std::string &bundleName, const InnerBundleInfo &newInfo, InnerBundleInfo &oldInfo)
{
    APP_LOGD("add new module info module name %{public}s ", newInfo.GetCurrentModulePackage().c_str());
    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("bundleName: %{public}s : bundle info not exist", bundleName.c_str());
        return false;
    }
    std::lock_guard<std::mutex> stateLock(stateMutex_);
    auto statusItem = installStates_.find(bundleName);
    if (statusItem == installStates_.end()) {
        APP_LOGW("save info fail, app:%{public}s is not updated", bundleName.c_str());
        return false;
    }
    if (statusItem->second == InstallState::UPDATING_SUCCESS) {
        APP_LOGD("save bundle:%{public}s info", bundleName.c_str());
        updateTsanEnabled(newInfo, oldInfo);
        ProcessAllowedAcls(newInfo, oldInfo);
        updateAppEnvironments(newInfo, oldInfo);
        updateMaxChildProcess(newInfo, oldInfo);
        if (IsUpdateInnerBundleInfoSatisified(oldInfo, newInfo)) {
            oldInfo.UpdateBaseBundleInfo(newInfo.GetBaseBundleInfo(), newInfo.HasEntry());
            oldInfo.UpdateBaseApplicationInfo(newInfo.GetBaseApplicationInfo(), newInfo.HasEntry());
            oldInfo.UpdateRemovable(newInfo.GetIsPreInstallApp(), newInfo.GetRemovable());
        }
        if (oldInfo.GetOldAppIds().empty()) {
            oldInfo.AddOldAppId(oldInfo.GetAppId());
        }
        oldInfo.SetProvisionId(newInfo.GetProvisionId());
        oldInfo.SetCertificateFingerprint(newInfo.GetCertificateFingerprint());
        oldInfo.SetAppIdentifier(newInfo.GetAppIdentifier());
        oldInfo.AddOldAppId(newInfo.GetAppId());
        oldInfo.SetAppPrivilegeLevel(newInfo.GetAppPrivilegeLevel());
        oldInfo.UpdateNativeLibAttrs(newInfo.GetBaseApplicationInfo());
        oldInfo.UpdateArkNativeAttrs(newInfo.GetBaseApplicationInfo());
        oldInfo.SetAsanLogPath(newInfo.GetAsanLogPath());
        oldInfo.SetBundlePackInfo(newInfo.GetBundlePackInfo());
        oldInfo.AddModuleInfo(newInfo);
        oldInfo.UpdateAppDetailAbilityAttrs();
        if (oldInfo.GetBaseApplicationInfo().needAppDetail) {
            AddAppDetailAbilityInfo(oldInfo);
        }
        oldInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::ENABLED);
        oldInfo.SetIsNewVersion(newInfo.GetIsNewVersion());
        oldInfo.UpdateOdidByBundleInfo(newInfo);
        oldInfo.SetAsanEnabled(oldInfo.IsAsanEnabled());
        oldInfo.SetGwpAsanEnabled(oldInfo.IsGwpAsanEnabled());
#ifdef BUNDLE_FRAMEWORK_OVERLAY_INSTALLATION
        if ((oldInfo.GetOverlayType() == NON_OVERLAY_TYPE) && (newInfo.GetOverlayType() != NON_OVERLAY_TYPE)) {
            oldInfo.SetOverlayType(newInfo.GetOverlayType());
        }
        if (!UpdateOverlayInfo(newInfo, oldInfo)) {
            APP_LOGD("bundleName: %{public}s : update overlay info failed", bundleName.c_str());
            return false;
        }
#endif
        if (dataStorage_->SaveStorageBundleInfo(oldInfo)) {
            APP_LOGD("update storage success bundle:%{public}s", bundleName.c_str());
            bundleInfos_.at(bundleName) = oldInfo;
            return true;
        }
    }
    return false;
}

bool BundleDataMgr::RemoveModuleInfo(
    const std::string &bundleName, const std::string &modulePackage, InnerBundleInfo &oldInfo)
{
    APP_LOGD("remove module info:%{public}s/%{public}s", bundleName.c_str(), modulePackage.c_str());
    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("bundleName: %{public}s bundle info not exist", bundleName.c_str());
        return false;
    }
    std::lock_guard<std::mutex> stateLock(stateMutex_);
    auto statusItem = installStates_.find(bundleName);
    if (statusItem == installStates_.end()) {
        APP_LOGW("save info fail, app:%{public}s is not updated", bundleName.c_str());
        return false;
    }
    if (statusItem->second == InstallState::UNINSTALL_START || statusItem->second == InstallState::ROLL_BACK) {
        APP_LOGD("save bundle:%{public}s info", bundleName.c_str());
#ifdef BUNDLE_FRAMEWORK_OVERLAY_INSTALLATION
        std::string targetBundleName = oldInfo.GetTargetBundleName();
        InnerBundleInfo targetInnerBundleInfo;
        if (bundleInfos_.find(targetBundleName) != bundleInfos_.end()) {
            targetInnerBundleInfo = bundleInfos_.at(targetBundleName);
        }
        OverlayDataMgr::GetInstance()->RemoveOverlayModuleInfo(bundleName, modulePackage, oldInfo,
            targetInnerBundleInfo);
        if ((oldInfo.GetOverlayType() == OVERLAY_EXTERNAL_BUNDLE) && !targetInnerBundleInfo.GetBundleName().empty()) {
            // save target innerBundleInfo
            if (dataStorage_->SaveStorageBundleInfo(targetInnerBundleInfo)) {
                APP_LOGD("update storage success bundle:%{public}s", targetBundleName.c_str());
                bundleInfos_.at(targetBundleName) = targetInnerBundleInfo;
            }
        }
        // remove target module and overlay module state will change to OVERLAY_INVALID
        if (oldInfo.GetOverlayType() == NON_OVERLAY_TYPE) {
            ResetExternalOverlayModuleState(bundleName, modulePackage);
        }
#endif
        oldInfo.RemoveModuleInfo(modulePackage);
        oldInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::ENABLED);
        if (!oldInfo.isExistedOverlayModule()) {
            oldInfo.SetOverlayType(NON_OVERLAY_TYPE);
        }
        oldInfo.SetAsanEnabled(oldInfo.IsAsanEnabled());
        oldInfo.SetGwpAsanEnabled(oldInfo.IsGwpAsanEnabled());
        if (dataStorage_->SaveStorageBundleInfo(oldInfo)) {
            APP_LOGD("update storage success bundle:%{public}s", bundleName.c_str());
            bundleInfos_.at(bundleName) = oldInfo;
            return true;
        }
        APP_LOGD("after delete modulePackage:%{public}s info", modulePackage.c_str());
    }
    return true;
}

bool BundleDataMgr::RemoveHspModuleByVersionCode(int32_t versionCode, InnerBundleInfo &info)
{
    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
    std::string bundleName = info.GetBundleName();
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("bundleName: %{public}s bundle info not exist", bundleName.c_str());
        return false;
    }
    std::lock_guard<std::mutex> stateLock(stateMutex_);
    auto statusItem = installStates_.find(bundleName);
    if (statusItem == installStates_.end()) {
        APP_LOGW("save info fail, app:%{public}s is not updated", bundleName.c_str());
        return false;
    }
    if (statusItem->second == InstallState::UNINSTALL_START || statusItem->second == InstallState::ROLL_BACK) {
        info.DeleteHspModuleByVersion(versionCode);
        info.SetBundleStatus(InnerBundleInfo::BundleStatus::ENABLED);
        if (dataStorage_->SaveStorageBundleInfo(info)) {
            APP_LOGD("update storage success bundle:%{public}s", bundleName.c_str());
            bundleInfos_.at(bundleName) = info;
            return true;
        }
    }
    return true;
}

bool BundleDataMgr::AddInnerBundleUserInfo(
    const std::string &bundleName, const InnerBundleUserInfo& newUserInfo)
{
    APP_LOGD("AddInnerBundleUserInfo:%{public}s", bundleName.c_str());
    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("bundleName: %{public}s bundle info not exist", bundleName.c_str());
        return false;
    }

    std::lock_guard<std::mutex> stateLock(stateMutex_);
    auto& info = bundleInfos_.at(bundleName);
    info.AddInnerBundleUserInfo(newUserInfo);
    info.SetBundleStatus(InnerBundleInfo::BundleStatus::ENABLED);
    if (!dataStorage_->SaveStorageBundleInfo(info)) {
        APP_LOGW("update storage failed bundle:%{public}s", bundleName.c_str());
        return false;
    }
    return true;
}

bool BundleDataMgr::RemoveInnerBundleUserInfo(
    const std::string &bundleName, int32_t userId)
{
    APP_LOGD("RemoveInnerBundleUserInfo:%{public}s", bundleName.c_str());
    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("bundleName: %{public}s bundle info not exist", bundleName.c_str());
        return false;
    }

    std::lock_guard<std::mutex> stateLock(stateMutex_);
    auto& info = bundleInfos_.at(bundleName);
    info.RemoveInnerBundleUserInfo(userId);
    info.SetBundleStatus(InnerBundleInfo::BundleStatus::ENABLED);
    if (!dataStorage_->SaveStorageBundleInfo(info)) {
        APP_LOGW("update storage failed bundle:%{public}s", bundleName.c_str());
        return false;
    }

    bundleStateStorage_->DeleteBundleState(bundleName, userId);
    return true;
}

bool BundleDataMgr::UpdateInnerBundleInfo(
    const std::string &bundleName, InnerBundleInfo &newInfo, InnerBundleInfo &oldInfo)
{
    APP_LOGD("UpdateInnerBundleInfo:%{public}s", bundleName.c_str());
    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("bundleName: %{public}s bundle info not exist", bundleName.c_str());
        return false;
    }
    std::lock_guard<std::mutex> stateLock(stateMutex_);
    auto statusItem = installStates_.find(bundleName);
    if (statusItem == installStates_.end()) {
        APP_LOGW("save info fail, app:%{public}s is not updated", bundleName.c_str());
        return false;
    }
    // ROLL_BACK and USER_CHANGE should not be here
    if (statusItem->second == InstallState::UPDATING_SUCCESS
        || statusItem->second == InstallState::ROLL_BACK
        || statusItem->second == InstallState::USER_CHANGE) {
        APP_LOGD("begin to update, bundleName : %{public}s, moduleName : %{public}s",
            bundleName.c_str(), newInfo.GetCurrentModulePackage().c_str());
        if (newInfo.GetOverlayType() == NON_OVERLAY_TYPE) {
            oldInfo.KeepOldOverlayConnection(newInfo);
        }
        ProcessAllowedAcls(newInfo, oldInfo);
        oldInfo.UpdateModuleInfo(newInfo);
        oldInfo.SetAsanEnabled(oldInfo.IsAsanEnabled());
        oldInfo.SetGwpAsanEnabled(oldInfo.IsGwpAsanEnabled());
        updateTsanEnabled(newInfo, oldInfo);
        updateAppEnvironments(newInfo, oldInfo);
        updateMaxChildProcess(newInfo, oldInfo);
        // 1.exist entry, update entry.
        // 2.only exist feature, update feature.
        if (IsUpdateInnerBundleInfoSatisified(oldInfo, newInfo)) {
            oldInfo.UpdateBaseBundleInfo(newInfo.GetBaseBundleInfo(), newInfo.HasEntry());
            oldInfo.UpdateBaseApplicationInfo(
                newInfo.GetBaseApplicationInfo(), newInfo.HasEntry());
            oldInfo.UpdateRemovable(
                newInfo.GetIsPreInstallApp(), newInfo.GetRemovable());
            oldInfo.SetAppType(newInfo.GetAppType());
            oldInfo.SetAppFeature(newInfo.GetAppFeature());
        }
        oldInfo.SetCertificateFingerprint(newInfo.GetCertificateFingerprint());
        if (oldInfo.GetOldAppIds().empty()) {
            oldInfo.AddOldAppId(oldInfo.GetAppId());
        }
        oldInfo.AddOldAppId(newInfo.GetAppId());
        oldInfo.SetProvisionId(newInfo.GetProvisionId());
        oldInfo.SetAppIdentifier(newInfo.GetAppIdentifier());
        oldInfo.SetAppPrivilegeLevel(newInfo.GetAppPrivilegeLevel());
        oldInfo.UpdateAppDetailAbilityAttrs();
        oldInfo.UpdateDataGroupInfos(newInfo.GetDataGroupInfos());
        if (oldInfo.GetBaseApplicationInfo().needAppDetail) {
            AddAppDetailAbilityInfo(oldInfo);
        }
        oldInfo.UpdateNativeLibAttrs(newInfo.GetBaseApplicationInfo());
        oldInfo.UpdateArkNativeAttrs(newInfo.GetBaseApplicationInfo());
        oldInfo.SetAsanLogPath(newInfo.GetAsanLogPath());
        if (newInfo.GetAppCrowdtestDeadline() != Constants::INHERIT_CROWDTEST_DEADLINE) {
            oldInfo.SetAppCrowdtestDeadline(newInfo.GetAppCrowdtestDeadline());
        }
        oldInfo.SetBundlePackInfo(newInfo.GetBundlePackInfo());
        // clear apply quick fix frequency
        oldInfo.ResetApplyQuickFixFrequency();
        oldInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::ENABLED);
        oldInfo.SetIsNewVersion(newInfo.GetIsNewVersion());
        oldInfo.SetAppProvisionMetadata(newInfo.GetAppProvisionMetadata());
        oldInfo.UpdateOdidByBundleInfo(newInfo);
#ifdef BUNDLE_FRAMEWORK_OVERLAY_INSTALLATION
        if (newInfo.GetIsNewVersion() && newInfo.GetOverlayType() == NON_OVERLAY_TYPE) {
            if (!UpdateOverlayInfo(newInfo, oldInfo)) {
                APP_LOGD("update overlay info failed");
                return false;
            }
        }

        if ((newInfo.GetOverlayType() != NON_OVERLAY_TYPE) && (!UpdateOverlayInfo(newInfo, oldInfo))) {
            APP_LOGD("update overlay info failed");
            return false;
        }
#endif
        if (!dataStorage_->SaveStorageBundleInfo(oldInfo)) {
            APP_LOGW("update storage failed bundle:%{public}s", bundleName.c_str());
            return false;
        }
        APP_LOGD("update storage success bundle:%{public}s", bundleName.c_str());
        bundleInfos_.at(bundleName) = oldInfo;
        return true;
    }
    return false;
}

bool BundleDataMgr::QueryAbilityInfo(const Want &want, int32_t flags, int32_t userId, AbilityInfo &abilityInfo,
    int32_t appIndex) const
{
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return false;
    }

    ElementName element = want.GetElement();
    std::string bundleName = element.GetBundleName();
    std::string abilityName = element.GetAbilityName();
    LOG_D(BMS_TAG_QUERY_ABILITY, "QueryAbilityInfo bundleName:%{public}s abilityName:%{public}s",
        bundleName.c_str(), abilityName.c_str());
    // explicit query
    if (!bundleName.empty() && !abilityName.empty()) {
        bool ret = ExplicitQueryAbilityInfo(want, flags, requestUserId, abilityInfo, appIndex);
        if (!ret) {
            LOG_D(BMS_TAG_QUERY_ABILITY,
                "explicit queryAbilityInfo error bundleName:%{public}s abilityName:%{public}s",
                bundleName.c_str(), abilityName.c_str());
            return false;
        }
        return true;
    }
    std::vector<AbilityInfo> abilityInfos;
    bool ret = ImplicitQueryAbilityInfos(want, flags, requestUserId, abilityInfos, appIndex);
    if (!ret) {
        LOG_D(BMS_TAG_QUERY_ABILITY,
            "implicit queryAbilityInfos error action:%{public}s uri:%{private}s type:%{public}s",
            want.GetAction().c_str(), want.GetUriString().c_str(), want.GetType().c_str());
        return false;
    }
    if (abilityInfos.size() == 0) {
        LOG_W(BMS_TAG_QUERY_ABILITY, "no matching abilityInfo action:%{public}s uri:%{private}s type:%{public}s",
            want.GetAction().c_str(), want.GetUriString().c_str(), want.GetType().c_str());
        return false;
    }
    abilityInfo = abilityInfos[0];
    return true;
}

void BundleDataMgr::GetCloneAbilityInfos(std::vector<AbilityInfo> &abilityInfos, const std::string &bundleName,
    const ElementName &element, int32_t flags, int32_t userId) const
{
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return;
    }
    std::vector<int32_t> cloneAppIndexes = GetCloneAppIndexes(bundleName, requestUserId);
    if (cloneAppIndexes.empty()) {
        return;
    }
    for (int32_t appIndex: cloneAppIndexes) {
        AbilityInfo cloneAbilityInfo;
        auto ret = QueryCloneAbilityInfo(element, flags, userId, appIndex, cloneAbilityInfo);
        if (ret == ERR_OK) {
            abilityInfos.emplace_back(cloneAbilityInfo);
        }
    }
}

bool BundleDataMgr::QueryAbilityInfos(
    const Want &want, int32_t flags, int32_t userId, std::vector<AbilityInfo> &abilityInfos) const
{
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return false;
    }

    ElementName element = want.GetElement();
    std::string bundleName = element.GetBundleName();
    std::string abilityName = element.GetAbilityName();
    LOG_D(BMS_TAG_QUERY_ABILITY, "QueryAbilityInfos bundleName:%{public}s abilityName:%{public}s",
        bundleName.c_str(), abilityName.c_str());
    // explicit query
    if (!bundleName.empty() && !abilityName.empty()) {
        AbilityInfo abilityInfo;
        bool ret = ExplicitQueryAbilityInfo(want, flags, requestUserId, abilityInfo);
        if (!ret) {
            LOG_D(BMS_TAG_QUERY_ABILITY, "explicit query error bundleName:%{public}s abilityName:%{public}s",
                bundleName.c_str(), abilityName.c_str());
            return false;
        }
        abilityInfos.emplace_back(abilityInfo);
        // get cloneApp's abilityInfos
        GetCloneAbilityInfos(abilityInfos, bundleName, element, flags, userId);
        return true;
    }
    // implicit query
    bool ret = ImplicitQueryAbilityInfos(want, flags, requestUserId, abilityInfos);
    if (!ret) {
        LOG_D(BMS_TAG_QUERY_ABILITY, "implicit query error action:%{public}s uri:%{private}s type:%{public}s",
            want.GetAction().c_str(), want.GetUriString().c_str(), want.GetType().c_str());
        return false;
    }
    if (abilityInfos.size() == 0) {
        LOG_W(BMS_TAG_QUERY_ABILITY, "no matching abilityInfo action:%{public}s uri:%{private}s type:%{public}s",
            want.GetAction().c_str(), want.GetUriString().c_str(), want.GetType().c_str());
        return false;
    }
    return true;
}

ErrCode BundleDataMgr::QueryAbilityInfosV9(
    const Want &want, int32_t flags, int32_t userId, std::vector<AbilityInfo> &abilityInfos) const
{
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }

    ElementName element = want.GetElement();
    std::string bundleName = element.GetBundleName();
    std::string abilityName = element.GetAbilityName();
    LOG_D(BMS_TAG_QUERY_ABILITY, "QueryAbilityInfosV9 bundleName:%{public}s abilityName:%{public}s",
        bundleName.c_str(), abilityName.c_str());
    // explicit query
    if (!bundleName.empty() && !abilityName.empty()) {
        AbilityInfo abilityInfo;
        ErrCode ret = ExplicitQueryAbilityInfoV9(want, flags, requestUserId, abilityInfo);
        if (ret != ERR_OK) {
            LOG_D(BMS_TAG_QUERY_ABILITY, "explicit queryV9 error bundleName:%{public}s abilityName:%{public}s",
                bundleName.c_str(), abilityName.c_str());
            return ret;
        }
        abilityInfos.emplace_back(abilityInfo);
        // get cloneApp's abilityInfos
        GetCloneAbilityInfos(abilityInfos, bundleName, element, flags, userId);
        return ERR_OK;
    }
    // implicit query
    ErrCode ret = ImplicitQueryAbilityInfosV9(want, flags, requestUserId, abilityInfos);
    if (ret != ERR_OK) {
        LOG_D(BMS_TAG_QUERY_ABILITY, "implicit queryV9 error action:%{public}s uri:%{private}s type:%{public}s",
            want.GetAction().c_str(), want.GetUriString().c_str(), want.GetType().c_str());
        return ret;
    }
    if (abilityInfos.empty()) {
        LOG_W(BMS_TAG_QUERY_ABILITY, "no matching abilityInfo action:%{public}s uri:%{private}s type:%{public}s",
            want.GetAction().c_str(), want.GetUriString().c_str(), want.GetType().c_str());
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }
    return ERR_OK;
}

ErrCode BundleDataMgr::BatchQueryAbilityInfos(
    const std::vector<Want> &wants, int32_t flags, int32_t userId, std::vector<AbilityInfo> &abilityInfos) const
{
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }

    for (size_t i = 0; i < wants.size(); i++) {
        std::vector<AbilityInfo> tmpAbilityInfos;
        ElementName element = wants[i].GetElement();
        std::string bundleName = element.GetBundleName();
        std::string abilityName = element.GetAbilityName();
        APP_LOGD("QueryAbilityInfosV9 bundle name:%{public}s, ability name:%{public}s",
            bundleName.c_str(), abilityName.c_str());
        // explicit query
        if (!bundleName.empty() && !abilityName.empty()) {
            AbilityInfo abilityInfo;
            ErrCode ret = ExplicitQueryAbilityInfoV9(wants[i], flags, requestUserId, abilityInfo);
            if (ret != ERR_OK) {
                APP_LOGE("explicit queryAbilityInfoV9 error:%{public}d, bundleName:%{public}s, abilityName:%{public}s",
                    ret, bundleName.c_str(), abilityName.c_str());
                return ret;
            }
            tmpAbilityInfos.emplace_back(abilityInfo);
        } else {
            // implicit query
            ErrCode ret = ImplicitQueryAbilityInfosV9(wants[i], flags, requestUserId, tmpAbilityInfos);
            if (ret != ERR_OK) {
                APP_LOGD("implicit queryAbilityInfosV9 error. action:%{public}s, uri:%{private}s, type:%{public}s",
                    wants[i].GetAction().c_str(), wants[i].GetUriString().c_str(), wants[i].GetType().c_str());
                return ret;
            }
        }
        for (int j = 0; j < tmpAbilityInfos.size(); j++) {
            auto it = std::find_if(abilityInfos.begin(), abilityInfos.end(),
                [&](const AbilityInfo& info) {
                    return tmpAbilityInfos[j].bundleName == info.bundleName &&
                        tmpAbilityInfos[j].moduleName == info.moduleName &&
                        tmpAbilityInfos[j].name == info.name;
                });
            if (it == abilityInfos.end()) {
                abilityInfos.push_back(tmpAbilityInfos[j]);
            }
        }
    }

    if (abilityInfos.empty()) {
        APP_LOGW("no matching abilityInfo.");
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }

    return ERR_OK;
}

bool BundleDataMgr::ExplicitQueryAbilityInfo(const Want &want, int32_t flags, int32_t userId,
    AbilityInfo &abilityInfo, int32_t appIndex) const
{
    ElementName element = want.GetElement();
    std::string bundleName = element.GetBundleName();
    std::string abilityName = element.GetAbilityName();
    std::string moduleName = element.GetModuleName();
    LOG_D(BMS_TAG_QUERY_ABILITY,
        "ExplicitQueryAbilityInfo bundleName:%{public}s moduleName:%{public}s abilityName:%{public}s",
        bundleName.c_str(), moduleName.c_str(), abilityName.c_str());
    LOG_D(BMS_TAG_QUERY_ABILITY, "flags:%{public}d userId:%{public}d", flags, userId);

    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return false;
    }

    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    InnerBundleInfo innerBundleInfo;
    if ((appIndex == 0) && (!GetInnerBundleInfoWithFlags(bundleName, flags, innerBundleInfo, requestUserId))) {
        LOG_D(BMS_TAG_QUERY_ABILITY, "ExplicitQueryAbilityInfo failed, bundleName:%{public}s", bundleName.c_str());
        return false;
    }
    // explict query from sandbox manager
    if (appIndex > 0) {
        if (sandboxAppHelper_ == nullptr) {
            LOG_W(BMS_TAG_QUERY_ABILITY, "sandboxAppHelper_ is nullptr");
            return false;
        }
        auto ret = sandboxAppHelper_->GetSandboxAppInfo(bundleName, appIndex, requestUserId, innerBundleInfo);
        if (ret != ERR_OK) {
            LOG_D(BMS_TAG_QUERY_ABILITY, "GetSandboxAppInfo failed errCode %{public}d, bundleName:%{public}s",
                ret, bundleName.c_str());
            return false;
        }
    }

    int32_t responseUserId = innerBundleInfo.GetResponseUserId(requestUserId);
    auto ability = innerBundleInfo.FindAbilityInfo(moduleName, abilityName, responseUserId);
    if (!ability) {
        LOG_W(BMS_TAG_QUERY_ABILITY, "not found bundleName:%{public}s moduleName:%{public}s abilityName:%{public}s",
            bundleName.c_str(), moduleName.c_str(), abilityName.c_str());
        return false;
    }
    return QueryAbilityInfoWithFlags(ability, flags, responseUserId, innerBundleInfo, abilityInfo);
}

ErrCode BundleDataMgr::ExplicitQueryAbilityInfoV9(const Want &want, int32_t flags, int32_t userId,
    AbilityInfo &abilityInfo, int32_t appIndex) const
{
    ElementName element = want.GetElement();
    std::string bundleName = element.GetBundleName();
    std::string abilityName = element.GetAbilityName();
    std::string moduleName = element.GetModuleName();
    LOG_D(BMS_TAG_QUERY_ABILITY,
        "ExplicitQueryAbilityInfoV9 bundleName:%{public}s moduleName:%{public}s abilityName:%{public}s",
        bundleName.c_str(), moduleName.c_str(), abilityName.c_str());
    LOG_D(BMS_TAG_QUERY_ABILITY, "flags:%{public}d userId:%{public}d", flags, userId);
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    InnerBundleInfo innerBundleInfo;
    if (appIndex == 0) {
        ErrCode ret = GetInnerBundleInfoWithFlagsV9(bundleName, flags, innerBundleInfo, requestUserId);
        if (ret != ERR_OK) {
            LOG_D(BMS_TAG_QUERY_ABILITY, "ExplicitQueryAbilityInfoV9 fail bundleName:%{public}s", bundleName.c_str());
            return ret;
        }
    }
    // explict query from sandbox manager
    if (appIndex > 0) {
        if (sandboxAppHelper_ == nullptr) {
            LOG_W(BMS_TAG_QUERY_ABILITY, "sandboxAppHelper_ is nullptr");
            return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
        }
        auto ret = sandboxAppHelper_->GetSandboxAppInfo(bundleName, appIndex, requestUserId, innerBundleInfo);
        if (ret != ERR_OK) {
            LOG_D(BMS_TAG_QUERY_ABILITY, "GetSandboxAppInfo failed errCode %{public}d, bundleName:%{public}s",
                ret, bundleName.c_str());
            return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
        }
    }

    int32_t responseUserId = innerBundleInfo.GetResponseUserId(requestUserId);
    auto ability = innerBundleInfo.FindAbilityInfoV9(moduleName, abilityName);
    if (!ability) {
        LOG_W(BMS_TAG_QUERY_ABILITY, "not found bundleName:%{public}s moduleName:%{public}s abilityName:%{public}s",
            bundleName.c_str(), moduleName.c_str(), abilityName.c_str());
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }

    return QueryAbilityInfoWithFlagsV9(ability, flags, responseUserId, innerBundleInfo, abilityInfo);
}

void BundleDataMgr::FilterAbilityInfosByModuleName(const std::string &moduleName,
    std::vector<AbilityInfo> &abilityInfos) const
{
    LOG_D(BMS_TAG_QUERY_ABILITY, "FilterAbilityInfosByModuleName moduleName: %{public}s", moduleName.c_str());
    if (moduleName.empty()) {
        return;
    }
    for (auto iter = abilityInfos.begin(); iter != abilityInfos.end();) {
        if (iter->moduleName != moduleName) {
            iter = abilityInfos.erase(iter);
        } else {
            ++iter;
        }
    }
}

bool BundleDataMgr::ImplicitQueryAbilityInfos(
    const Want &want, int32_t flags, int32_t userId, std::vector<AbilityInfo> &abilityInfos, int32_t appIndex) const
{
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return false;
    }

    if (want.GetAction().empty() && want.GetEntities().empty()
        && want.GetUriString().empty() && want.GetType().empty()) {
        LOG_E(BMS_TAG_QUERY_ABILITY, "param invalid");
        return false;
    }
    LOG_D(BMS_TAG_QUERY_ABILITY, "action:%{public}s, uri:%{private}s, type:%{public}s",
        want.GetAction().c_str(), want.GetUriString().c_str(), want.GetType().c_str());
    LOG_D(BMS_TAG_QUERY_ABILITY, "flags:%{public}d, userId:%{public}d", flags, userId);
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    if (bundleInfos_.empty()) {
        LOG_W(BMS_TAG_QUERY_ABILITY, "bundleInfos_ is empty");
        return false;
    }
    std::string bundleName = want.GetElement().GetBundleName();
    if (!bundleName.empty()) {
        // query in current bundleName
        if (!ImplicitQueryCurAbilityInfos(want, flags, requestUserId, abilityInfos, appIndex)) {
            LOG_D(BMS_TAG_QUERY_ABILITY, "ImplicitQueryCurAbilityInfos failed bundleName:%{public}s",
                bundleName.c_str());
            return false;
        }
    } else {
        // query all
        ImplicitQueryAllAbilityInfos(want, flags, requestUserId, abilityInfos, appIndex);
    }
    FilterAbilityInfosByAppLinking(want, flags, abilityInfos);
    // sort by priority, descending order.
    if (abilityInfos.size() > 1) {
        std::stable_sort(abilityInfos.begin(), abilityInfos.end(),
            [](AbilityInfo a, AbilityInfo b) { return a.priority > b.priority; });
    }
    return true;
}

ErrCode BundleDataMgr::ImplicitQueryAbilityInfosV9(
    const Want &want, int32_t flags, int32_t userId, std::vector<AbilityInfo> &abilityInfos, int32_t appIndex) const
{
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }

    if (want.GetAction().empty() && want.GetEntities().empty()
        && want.GetUriString().empty() && want.GetType().empty()) {
        LOG_E(BMS_TAG_QUERY_ABILITY, "param invalid");
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }
    LOG_D(BMS_TAG_QUERY_ABILITY, "action:%{public}s uri:%{private}s type:%{public}s",
        want.GetAction().c_str(), want.GetUriString().c_str(), want.GetType().c_str());
    LOG_D(BMS_TAG_QUERY_ABILITY, "flags:%{public}d userId:%{public}d", flags, userId);
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    if (bundleInfos_.empty()) {
        APP_LOGW("bundleInfos_ is empty");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    std::string bundleName = want.GetElement().GetBundleName();
    if (!bundleName.empty()) {
        // query in current bundleName
        ErrCode ret = ImplicitQueryCurAbilityInfosV9(want, flags, requestUserId, abilityInfos, appIndex);
        if (ret != ERR_OK) {
            LOG_D(BMS_TAG_QUERY_ABILITY, "ImplicitQueryCurAbilityInfosV9 failed bundleName:%{public}s",
                bundleName.c_str());
            return ret;
        }
    } else {
        // query all
        ImplicitQueryAllAbilityInfosV9(want, flags, requestUserId, abilityInfos, appIndex);
    }
    FilterAbilityInfosByAppLinking(want, flags, abilityInfos);
    // sort by priority, descending order.
    if (abilityInfos.size() > 1) {
        std::stable_sort(abilityInfos.begin(), abilityInfos.end(),
            [](AbilityInfo a, AbilityInfo b) { return a.priority > b.priority; });
    }
    return ERR_OK;
}

bool BundleDataMgr::QueryAbilityInfoWithFlags(const std::optional<AbilityInfo> &option, int32_t flags, int32_t userId,
    const InnerBundleInfo &innerBundleInfo, AbilityInfo &info) const
{
    LOG_D(BMS_TAG_QUERY_ABILITY, "begin to QueryAbilityInfoWithFlags.");
    if ((static_cast<uint32_t>(flags) & GET_ABILITY_INFO_SYSTEMAPP_ONLY) == GET_ABILITY_INFO_SYSTEMAPP_ONLY &&
        !innerBundleInfo.IsSystemApp()) {
        LOG_W(BMS_TAG_QUERY_ABILITY, "no system app ability info for this calling");
        return false;
    }
    if (!(static_cast<uint32_t>(flags) & GET_ABILITY_INFO_WITH_DISABLE)) {
        if (!innerBundleInfo.IsAbilityEnabled((*option), userId)) {
            LOG_W(BMS_TAG_QUERY_ABILITY, "bundleName:%{public}s ability:%{public}s is disabled",
                option->bundleName.c_str(), option->name.c_str());
            return false;
        }
    }
    info = (*option);
    if ((static_cast<uint32_t>(flags) & GET_ABILITY_INFO_WITH_PERMISSION) != GET_ABILITY_INFO_WITH_PERMISSION) {
        info.permissions.clear();
    }
    if ((static_cast<uint32_t>(flags) & GET_ABILITY_INFO_WITH_METADATA) != GET_ABILITY_INFO_WITH_METADATA) {
        info.metaData.customizeData.clear();
        info.metadata.clear();
    }
    if ((static_cast<uint32_t>(flags) & GET_ABILITY_INFO_WITH_SKILL) != GET_ABILITY_INFO_WITH_SKILL) {
        info.skills.clear();
    }
    if ((static_cast<uint32_t>(flags) & GET_ABILITY_INFO_WITH_APPLICATION) == GET_ABILITY_INFO_WITH_APPLICATION) {
        innerBundleInfo.GetApplicationInfo(
            ApplicationFlag::GET_APPLICATION_INFO_WITH_CERTIFICATE_FINGERPRINT, userId, info.applicationInfo);
    }
    // set uid for NAPI cache use
    InnerBundleUserInfo innerBundleUserInfo;
    if (innerBundleInfo.GetInnerBundleUserInfo(userId, innerBundleUserInfo)) {
        info.uid = innerBundleUserInfo.uid;
    }
    return true;
}

ErrCode BundleDataMgr::QueryAbilityInfoWithFlagsV9(const std::optional<AbilityInfo> &option,
    int32_t flags, int32_t userId, const InnerBundleInfo &innerBundleInfo, AbilityInfo &info,
    int32_t appIndex) const
{
    LOG_D(BMS_TAG_QUERY_ABILITY, "begin to QueryAbilityInfoWithFlagsV9.");
    if ((static_cast<uint32_t>(flags) & static_cast<uint32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_ONLY_SYSTEM_APP)) ==
        static_cast<uint32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_ONLY_SYSTEM_APP) &&
        !innerBundleInfo.IsSystemApp()) {
        LOG_W(BMS_TAG_QUERY_ABILITY, "target not system app");
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }
    if (!(static_cast<uint32_t>(flags) & static_cast<uint32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_DISABLE))) {
        if (!innerBundleInfo.IsAbilityEnabled((*option), userId, appIndex)) {
            LOG_W(BMS_TAG_QUERY_ABILITY, "bundleName:%{public}s ability:%{public}s is disabled",
                option->bundleName.c_str(), option->name.c_str());
            return ERR_BUNDLE_MANAGER_ABILITY_DISABLED;
        }
    }
    info = (*option);
    if ((static_cast<uint32_t>(flags) & static_cast<uint32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_PERMISSION)) !=
        static_cast<uint32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_PERMISSION)) {
        info.permissions.clear();
    }
    if ((static_cast<uint32_t>(flags) & static_cast<uint32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_METADATA)) !=
        static_cast<uint32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_METADATA)) {
        info.metaData.customizeData.clear();
        info.metadata.clear();
    }
    if ((static_cast<uint32_t>(flags) & static_cast<uint32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_SKILL)) !=
        static_cast<uint32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_SKILL)) {
        info.skills.clear();
    }
    if ((static_cast<uint32_t>(flags) & static_cast<uint32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_APPLICATION)) ==
        static_cast<uint32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_APPLICATION)) {
        innerBundleInfo.GetApplicationInfoV9(static_cast<int32_t>(GetApplicationFlag::GET_APPLICATION_INFO_DEFAULT),
            userId, info.applicationInfo, appIndex);
    }
    // set uid for NAPI cache use
    InnerBundleUserInfo innerBundleUserInfo;
    if (innerBundleInfo.GetInnerBundleUserInfo(userId, innerBundleUserInfo)) {
        if (appIndex == 0) {
            info.uid = innerBundleUserInfo.uid;
        } else {
            std::string appIndexKey = InnerBundleUserInfo::AppIndexToKey(appIndex);
            if (innerBundleUserInfo.cloneInfos.find(appIndexKey) != innerBundleUserInfo.cloneInfos.end()) {
                auto cloneInfo = innerBundleUserInfo.cloneInfos.at(appIndexKey);
                info.uid = cloneInfo.uid;
                info.appIndex = cloneInfo.appIndex;
            } else {
                return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
            }
        }
    }
    return ERR_OK;
}

bool BundleDataMgr::ImplicitQueryCurAbilityInfos(const Want &want, int32_t flags, int32_t userId,
    std::vector<AbilityInfo> &abilityInfos, int32_t appIndex) const
{
    LOG_D(BMS_TAG_QUERY_ABILITY, "begin to ImplicitQueryCurAbilityInfos.");
    std::string bundleName = want.GetElement().GetBundleName();
    InnerBundleInfo innerBundleInfo;
    if ((appIndex == 0) && (!GetInnerBundleInfoWithFlags(bundleName, flags, innerBundleInfo, userId))) {
        LOG_W(BMS_TAG_QUERY_ABILITY, "ImplicitQueryCurAbilityInfos failed bundleName:%{public}s", bundleName.c_str());
        return false;
    }
    if (appIndex > 0) {
        if (sandboxAppHelper_ == nullptr) {
            LOG_W(BMS_TAG_QUERY_ABILITY, "sandboxAppHelper_ is nullptr");
            return false;
        }
        auto ret = sandboxAppHelper_->GetSandboxAppInfo(bundleName, appIndex, userId, innerBundleInfo);
        if (ret != ERR_OK) {
            LOG_D(BMS_TAG_QUERY_ABILITY, "GetSandboxAppInfo failed errCode:%{public}d bundleName:%{public}s",
                ret, bundleName.c_str());
            return false;
        }
    }
    int32_t responseUserId = innerBundleInfo.GetResponseUserId(userId);
    GetMatchAbilityInfos(want, flags, innerBundleInfo, responseUserId, abilityInfos);
    FilterAbilityInfosByModuleName(want.GetElement().GetModuleName(), abilityInfos);
    return true;
}

ErrCode BundleDataMgr::ImplicitQueryCurAbilityInfosV9(const Want &want, int32_t flags, int32_t userId,
    std::vector<AbilityInfo> &abilityInfos, int32_t appIndex) const
{
    LOG_D(BMS_TAG_QUERY_ABILITY, "begin to ImplicitQueryCurAbilityInfosV9.");
    std::string bundleName = want.GetElement().GetBundleName();
    InnerBundleInfo innerBundleInfo;
    if (appIndex == 0) {
        ErrCode ret = GetInnerBundleInfoWithFlagsV9(bundleName, flags, innerBundleInfo, userId);
        if (ret != ERR_OK) {
            LOG_D(BMS_TAG_QUERY_ABILITY, "ImplicitQueryCurAbilityInfosV9 failed, bundleName:%{public}s",
                bundleName.c_str());
            return ret;
        }
    }
    if (appIndex > 0) {
        if (sandboxAppHelper_ == nullptr) {
            LOG_W(BMS_TAG_QUERY_ABILITY, "sandboxAppHelper_ is nullptr");
            return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
        }
        auto ret = sandboxAppHelper_->GetSandboxAppInfo(bundleName, appIndex, userId, innerBundleInfo);
        if (ret != ERR_OK) {
            LOG_D(BMS_TAG_QUERY_ABILITY, "GetSandboxAppInfo failed errCode %{public}d bundleName:%{public}s",
                ret, bundleName.c_str());
            return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
        }
    }
    int32_t responseUserId = innerBundleInfo.GetResponseUserId(userId);
    GetMatchAbilityInfosV9(want, flags, innerBundleInfo, responseUserId, abilityInfos);
    FilterAbilityInfosByModuleName(want.GetElement().GetModuleName(), abilityInfos);
    return ERR_OK;
}

void BundleDataMgr::ImplicitQueryAllAbilityInfos(const Want &want, int32_t flags, int32_t userId,
    std::vector<AbilityInfo> &abilityInfos, int32_t appIndex) const
{
    LOG_D(BMS_TAG_QUERY_ABILITY, "begin to ImplicitQueryAllAbilityInfos.");
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        LOG_W(BMS_TAG_QUERY_ABILITY, "invalid userId");
        return;
    }

    // query from bundleInfos_
    if (appIndex == 0) {
        for (const auto &item : bundleInfos_) {
            const InnerBundleInfo &innerBundleInfo = item.second;
            int32_t responseUserId = innerBundleInfo.GetResponseUserId(requestUserId);
            if (CheckInnerBundleInfoWithFlags(innerBundleInfo, flags, responseUserId) != ERR_OK) {
                LOG_D(BMS_TAG_QUERY_ABILITY,
                    "ImplicitQueryAllAbilityInfos failed, bundleName:%{public}s, responseUserId:%{public}d",
                    innerBundleInfo.GetBundleName().c_str(), responseUserId);
                continue;
            }

            GetMatchAbilityInfos(want, flags, innerBundleInfo, responseUserId, abilityInfos);
        }
    } else {
        // query from sandbox manager for sandbox bundle
        if (sandboxAppHelper_ == nullptr) {
            LOG_W(BMS_TAG_QUERY_ABILITY, "sandboxAppHelper_ is nullptr");
            return;
        }
        auto sandboxMap = sandboxAppHelper_->GetSandboxAppInfoMap();
        for (const auto &item : sandboxMap) {
            InnerBundleInfo info;
            size_t pos = item.first.rfind(Constants::FILE_UNDERLINE);
            if (pos == std::string::npos) {
                LOG_D(BMS_TAG_QUERY_ABILITY, "sandbox map contains invalid element");
                continue;
            }
            std::string innerBundleName = item.first.substr(pos + 1);
            if (sandboxAppHelper_->GetSandboxAppInfo(innerBundleName, appIndex, userId, info) != ERR_OK) {
                LOG_D(BMS_TAG_QUERY_ABILITY, "obtain innerBundleInfo of sandbox app failed");
                continue;
            }

            int32_t responseUserId = info.GetResponseUserId(userId);
            GetMatchAbilityInfos(want, flags, info, responseUserId, abilityInfos);
        }
    }
    APP_LOGD("finish to ImplicitQueryAllAbilityInfos.");
}

void BundleDataMgr::ImplicitQueryAllAbilityInfosV9(const Want &want, int32_t flags, int32_t userId,
    std::vector<AbilityInfo> &abilityInfos, int32_t appIndex) const
{
    LOG_D(BMS_TAG_QUERY_ABILITY, "begin to ImplicitQueryAllAbilityInfosV9.");
    // query from bundleInfos_
    if (appIndex == 0) {
        for (const auto &item : bundleInfos_) {
            InnerBundleInfo innerBundleInfo;
            ErrCode ret = GetInnerBundleInfoWithFlagsV9(item.first, flags, innerBundleInfo, userId);
            if (ret != ERR_OK) {
                LOG_W(BMS_TAG_QUERY_ABILITY, "failed, bundleName:%{public}s", item.first.c_str());
                continue;
            }

            int32_t responseUserId = innerBundleInfo.GetResponseUserId(userId);
            GetMatchAbilityInfosV9(want, flags, innerBundleInfo, responseUserId, abilityInfos);
        }
    } else {
        // query from sandbox manager for sandbox bundle
        if (sandboxAppHelper_ == nullptr) {
            LOG_W(BMS_TAG_QUERY_ABILITY, "sandboxAppHelper_ is nullptr");
            return;
        }
        auto sandboxMap = sandboxAppHelper_->GetSandboxAppInfoMap();
        for (const auto &item : sandboxMap) {
            InnerBundleInfo info;
            size_t pos = item.first.rfind(Constants::FILE_UNDERLINE);
            if (pos == std::string::npos) {
                LOG_W(BMS_TAG_QUERY_ABILITY, "sandbox map contains invalid element");
                continue;
            }
            std::string innerBundleName = item.first.substr(pos + 1);
            if (sandboxAppHelper_->GetSandboxAppInfo(innerBundleName, appIndex, userId, info) != ERR_OK) {
                LOG_D(BMS_TAG_QUERY_ABILITY, "obtain innerBundleInfo of sandbox app failed");
                continue;
            }

            int32_t responseUserId = info.GetResponseUserId(userId);
            GetMatchAbilityInfosV9(want, flags, info, responseUserId, abilityInfos);
        }
    }
    LOG_D(BMS_TAG_QUERY_ABILITY, "finish to ImplicitQueryAllAbilityInfosV9.");
}

bool BundleDataMgr::CheckAbilityInfoFlagExist(int32_t flags, AbilityInfoFlag abilityInfoFlag) const
{
    return (static_cast<uint32_t>(flags) & abilityInfoFlag) == abilityInfoFlag;
}

void BundleDataMgr::GetMatchAbilityInfos(const Want &want, int32_t flags,
    const InnerBundleInfo &info, int32_t userId, std::vector<AbilityInfo> &abilityInfos) const
{
    if (CheckAbilityInfoFlagExist(flags, GET_ABILITY_INFO_SYSTEMAPP_ONLY) && !info.IsSystemApp()) {
        return;
    }
    std::map<std::string, std::vector<Skill>> skillInfos = info.GetInnerSkillInfos();
    for (const auto &abilityInfoPair : info.GetInnerAbilityInfos()) {
        bool isPrivateType = MatchPrivateType(
            want, abilityInfoPair.second.supportExtNames, abilityInfoPair.second.supportMimeTypes);
        auto skillsPair = skillInfos.find(abilityInfoPair.first);
        if (skillsPair == skillInfos.end()) {
            continue;
        }
        for (size_t skillIndex = 0; skillIndex < skillsPair->second.size(); ++skillIndex) {
            const Skill &skill = skillsPair->second[skillIndex];
            size_t matchUriIndex = 0;
            if (isPrivateType || skill.Match(want, matchUriIndex)) {
                AbilityInfo abilityinfo = abilityInfoPair.second;
                if (abilityinfo.name == Constants::APP_DETAIL_ABILITY) {
                    continue;
                }
                if (!CheckAbilityInfoFlagExist(flags, GET_ABILITY_INFO_WITH_DISABLE)) {
                    if (!info.IsAbilityEnabled(abilityinfo, GetUserId(userId))) {
                        LOG_W(BMS_TAG_QUERY_ABILITY, "Ability %{public}s is disabled", abilityinfo.name.c_str());
                        continue;
                    }
                }
                if (CheckAbilityInfoFlagExist(flags, GET_ABILITY_INFO_WITH_APPLICATION)) {
                    info.GetApplicationInfo(
                        ApplicationFlag::GET_APPLICATION_INFO_WITH_CERTIFICATE_FINGERPRINT, userId,
                        abilityinfo.applicationInfo);
                }
                if (!CheckAbilityInfoFlagExist(flags, GET_ABILITY_INFO_WITH_PERMISSION)) {
                    abilityinfo.permissions.clear();
                }
                if (!CheckAbilityInfoFlagExist(flags, GET_ABILITY_INFO_WITH_METADATA)) {
                    abilityinfo.metaData.customizeData.clear();
                    abilityinfo.metadata.clear();
                }
                if (!CheckAbilityInfoFlagExist(flags, GET_ABILITY_INFO_WITH_SKILL)) {
                    abilityinfo.skills.clear();
                }
                if (CheckAbilityInfoFlagExist(flags, GET_ABILITY_INFO_WITH_SKILL_URI)) {
                    AddSkillUrisInfo(skillsPair->second, abilityinfo.skillUri, skillIndex, matchUriIndex);
                }
                abilityInfos.emplace_back(abilityinfo);
                break;
            }
        }
    }
}

void BundleDataMgr::AddSkillUrisInfo(const std::vector<Skill> &skills,
    std::vector<SkillUriForAbilityAndExtension> &skillUris,
    std::optional<size_t> matchSkillIndex, std::optional<size_t> matchUriIndex) const
{
    for (size_t skillIndex = 0; skillIndex < skills.size(); ++skillIndex) {
        const Skill &skill = skills[skillIndex];
        for (size_t uriIndex = 0; uriIndex < skill.uris.size(); ++uriIndex) {
            const SkillUri &uri = skill.uris[uriIndex];
            SkillUriForAbilityAndExtension skillinfo;
            skillinfo.scheme = uri.scheme;
            skillinfo.host = uri.host;
            skillinfo.port = uri.port;
            skillinfo.path = uri.path;
            skillinfo.pathStartWith = uri.pathStartWith;
            skillinfo.pathRegex = uri.pathRegex;
            skillinfo.type = uri.type;
            skillinfo.utd = uri.utd;
            skillinfo.maxFileSupported = uri.maxFileSupported;
            skillinfo.linkFeature = uri.linkFeature;
            if (matchSkillIndex.has_value() && matchUriIndex.has_value() &&
                skillIndex == matchSkillIndex.value() && uriIndex == matchUriIndex.value()) {
                skillinfo.isMatch = true;
            }
            skillUris.emplace_back(skillinfo);
        }
    }
}

void BundleDataMgr::EmplaceAbilityInfo(const InnerBundleInfo &info, const std::vector<Skill> &skills,
    AbilityInfo &abilityInfo, int32_t flags, int32_t userId, std::vector<AbilityInfo> &infos,
    std::optional<size_t> matchSkillIndex, std::optional<size_t> matchUriIndex) const
{
    if (!(static_cast<uint32_t>(flags) & static_cast<uint32_t>(
        GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_DISABLE))) {
        if (!info.IsAbilityEnabled(abilityInfo, GetUserId(userId))) {
            LOG_W(BMS_TAG_QUERY_ABILITY, "Ability %{public}s is disabled", abilityInfo.name.c_str());
            return;
        }
    }
    if ((static_cast<uint32_t>(flags) &
        static_cast<uint32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_APPLICATION)) ==
        static_cast<uint32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_APPLICATION)) {
        info.GetApplicationInfoV9(static_cast<int32_t>(GetApplicationFlag::GET_APPLICATION_INFO_DEFAULT),
            userId, abilityInfo.applicationInfo);
    }
    if ((static_cast<uint32_t>(flags) &
        static_cast<uint32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_PERMISSION)) !=
        static_cast<uint32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_PERMISSION)) {
        abilityInfo.permissions.clear();
    }
    if ((static_cast<uint32_t>(flags) &
        static_cast<uint32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_METADATA)) !=
        static_cast<uint32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_METADATA)) {
        abilityInfo.metaData.customizeData.clear();
        abilityInfo.metadata.clear();
    }
    if ((static_cast<uint32_t>(flags) &
        static_cast<uint32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_SKILL)) !=
        static_cast<uint32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_SKILL)) {
        abilityInfo.skills.clear();
    }
    if ((static_cast<uint32_t>(flags) &
        static_cast<uint32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_SKILL_URI)) ==
        static_cast<uint32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_SKILL_URI)) {
        AddSkillUrisInfo(skills, abilityInfo.skillUri, matchSkillIndex, matchUriIndex);
    }
    infos.emplace_back(abilityInfo);
}

void BundleDataMgr::GetMatchAbilityInfosV9(const Want &want, int32_t flags,
    const InnerBundleInfo &info, int32_t userId, std::vector<AbilityInfo> &abilityInfos) const
{
    if ((static_cast<uint32_t>(flags) & static_cast<uint32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_ONLY_SYSTEM_APP)) ==
        static_cast<uint32_t>((GetAbilityInfoFlag::GET_ABILITY_INFO_ONLY_SYSTEM_APP)) && !info.IsSystemApp()) {
        LOG_W(BMS_TAG_QUERY_ABILITY, "target not system app");
        return;
    }
    std::map<std::string, std::vector<Skill>> skillInfos = info.GetInnerSkillInfos();
    for (const auto &abilityInfoPair : info.GetInnerAbilityInfos()) {
        AbilityInfo abilityinfo = abilityInfoPair.second;
        auto skillsPair = skillInfos.find(abilityInfoPair.first);
        if (skillsPair == skillInfos.end()) {
            continue;
        }
        bool isPrivateType = MatchPrivateType(
            want, abilityInfoPair.second.supportExtNames, abilityInfoPair.second.supportMimeTypes);
        if (isPrivateType) {
            EmplaceAbilityInfo(info, skillsPair->second, abilityinfo, flags, userId, abilityInfos,
                std::nullopt, std::nullopt);
            continue;
        }
        if (want.GetAction() == SHARE_ACTION) {
            if (!MatchShare(want, skillsPair->second)) {
                continue;
            }
            EmplaceAbilityInfo(info, skillsPair->second, abilityinfo, flags, userId, abilityInfos,
                std::nullopt, std::nullopt);
            continue;
        }
        for (size_t skillIndex = 0; skillIndex < skillsPair->second.size(); ++skillIndex) {
            const Skill &skill = skillsPair->second[skillIndex];
            size_t matchUriIndex = 0;
            if (skill.Match(want, matchUriIndex)) {
                if (abilityinfo.name == Constants::APP_DETAIL_ABILITY) {
                    continue;
                }
                EmplaceAbilityInfo(info, skillsPair->second, abilityinfo, flags, userId, abilityInfos,
                    skillIndex, matchUriIndex);
                break;
            }
        }
    }
}

bool BundleDataMgr::MatchShare(const Want &want, const std::vector<Skill> &skills) const
{
    if (want.GetAction() != SHARE_ACTION) {
        return false;
    }
    std::vector<Skill> shareActionSkills = FindSkillsContainShareAction(skills);
    if (shareActionSkills.empty()) {
        return false;
    }
    auto wantParams = want.GetParams();
    auto pickerSummary = wantParams.GetWantParams(WANT_PARAM_PICKER_SUMMARY);
    int32_t totalCount = pickerSummary.GetIntParam(SUMMARY_TOTAL_COUNT, DEFAULT_SUMMARY_COUNT);
    if (totalCount <= DEFAULT_SUMMARY_COUNT) {
        LOG_W(BMS_TAG_QUERY_ABILITY, "Invalid total count");
    }
    auto shareSummary = pickerSummary.GetWantParams(WANT_PARAM_SUMMARY);
    auto utds = shareSummary.KeySet();
    for (const auto &utd : utds) {
        int32_t count = shareSummary.GetIntParam(utd, DEFAULT_SUMMARY_COUNT);
        if (count <= DEFAULT_SUMMARY_COUNT) {
            LOG_W(BMS_TAG_QUERY_ABILITY, "invalid utd count");
            return false;
        }
        bool match = false;
        for (const auto &skill : shareActionSkills) {
            if (MatchUtd(skill, utd, count)) {
                match = true;
                break;
            }
        }
        if (!match) {
            LOG_D(BMS_TAG_QUERY_ABILITY, "match failed");
            return false;
        }
    }
    return true;
}

bool BundleDataMgr::MatchUtd(const Skill &skill, const std::string &utd, int32_t count) const
{
    for (const SkillUri &skillUri : skill.uris) {
        if (skillUri.maxFileSupported < count) {
            continue;
        }
        if (!skillUri.utd.empty()) {
            if (MatchUtd(skillUri.utd, utd)) {
                return true;
            }
        } else {
            if (MatchTypeWithUtd(skillUri.type, utd)) {
                return true;
            }
        }
    }
    return false;
}

bool BundleDataMgr::MatchUtd(const std::string &skillUtd, const std::string &wantUtd) const
{
#ifdef BUNDLE_FRAMEWORK_UDMF_ENABLED
    LOG_W(BMS_TAG_QUERY_ABILITY, "skillUtd %{public}s, wantUtd %{public}s", skillUtd.c_str(), wantUtd.c_str());
    std::shared_ptr<UDMF::TypeDescriptor> wantTypeDescriptor;
    auto ret = UDMF::UtdClient::GetInstance().GetTypeDescriptor(wantUtd, wantTypeDescriptor);
    if (ret != ERR_OK || wantTypeDescriptor == nullptr) {
        LOG_W(BMS_TAG_QUERY_ABILITY, "GetTypeDescriptor failed");
        return false;
    }
    bool matchRet = false;
    ret = wantTypeDescriptor->BelongsTo(skillUtd, matchRet);
    if (ret != ERR_OK) {
        LOG_W(BMS_TAG_QUERY_ABILITY, "GetTypeDescriptor failed");
        return false;
    }
    return matchRet;
#endif
    return false;
}

bool BundleDataMgr::MatchTypeWithUtd(const std::string &mimeType, const std::string &wantUtd) const
{
#ifdef BUNDLE_FRAMEWORK_UDMF_ENABLED
    LOG_W(BMS_TAG_QUERY_ABILITY, "mimeType %{public}s, wantUtd %{public}s", mimeType.c_str(), wantUtd.c_str());
    std::string typeUtd;
    auto ret = UDMF::UtdClient::GetInstance().GetUniformDataTypeByMIMEType(mimeType, typeUtd);
    if (ret != ERR_OK) {
        LOG_W(BMS_TAG_QUERY_ABILITY, "GetUniformDataTypeByMIMEType failed");
        return false;
    }
    return MatchUtd(typeUtd, wantUtd);
#endif
    return false;
}

std::vector<Skill> BundleDataMgr::FindSkillsContainShareAction(const std::vector<Skill> &skills) const
{
    std::vector<Skill> shareActionSkills;
    for (const auto &skill : skills) {
        auto &actions = skill.actions;
        auto matchAction = std::find_if(std::begin(actions), std::end(actions), [](const auto &action) {
            return SHARE_ACTION == action;
        });
        if (matchAction == actions.end()) {
            continue;
        }
        shareActionSkills.emplace_back(skill);
    }
    return shareActionSkills;
}

void BundleDataMgr::ModifyLauncherAbilityInfo(bool isStage, AbilityInfo &abilityInfo) const
{
    if (abilityInfo.labelId == 0) {
        if (isStage) {
            abilityInfo.labelId = abilityInfo.applicationInfo.labelId;
            abilityInfo.label = abilityInfo.applicationInfo.label;
        } else {
            abilityInfo.applicationInfo.label = abilityInfo.bundleName;
            abilityInfo.label = abilityInfo.bundleName;
        }
    }

    if (abilityInfo.iconId == 0) {
        abilityInfo.iconId = abilityInfo.applicationInfo.iconId;
    }
}

void BundleDataMgr::GetMatchLauncherAbilityInfos(const Want& want,
    const InnerBundleInfo& info, std::vector<AbilityInfo>& abilityInfos,
    int64_t installTime, int32_t userId) const
{
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return;
    }
    int32_t responseUserId = info.GetResponseUserId(requestUserId);
    if (responseUserId == Constants::INVALID_USERID) {
        return;
    }
    bool isExist = false;
    bool isStage = info.GetIsNewVersion();
    // get clone bundle info
    InnerBundleUserInfo bundleUserInfo;
    (void)info.GetInnerBundleUserInfo(responseUserId, bundleUserInfo);
    std::map<std::string, std::vector<Skill>> skillInfos = info.GetInnerSkillInfos();
    for (const auto& abilityInfoPair : info.GetInnerAbilityInfos()) {
        auto skillsPair = skillInfos.find(abilityInfoPair.first);
        if (skillsPair == skillInfos.end()) {
            continue;
        }
        for (const Skill& skill : skillsPair->second) {
            if (skill.MatchLauncher(want) && (abilityInfoPair.second.type == AbilityType::PAGE)) {
                isExist = true;
                AbilityInfo abilityinfo = abilityInfoPair.second;
                info.GetApplicationInfo(ApplicationFlag::GET_APPLICATION_INFO_WITH_CERTIFICATE_FINGERPRINT,
                    responseUserId, abilityinfo.applicationInfo);
                abilityinfo.installTime = installTime;
                // fix labelId or iconId is equal 0
                ModifyLauncherAbilityInfo(isStage, abilityinfo);
                abilityInfos.emplace_back(abilityinfo);
                GetMatchLauncherAbilityInfosForCloneInfos(info, abilityInfoPair.second, bundleUserInfo, abilityInfos);
                break;
            }
        }
    }
    // add app detail ability
    if (!isExist && info.GetBaseApplicationInfo().needAppDetail) {
        LOG_D(BMS_TAG_QUERY_ABILITY, "bundleName: %{public}s add detail ability info.", info.GetBundleName().c_str());
        std::string moduleName = "";
        auto ability = info.FindAbilityInfo(moduleName, Constants::APP_DETAIL_ABILITY, responseUserId);
        if (!ability) {
            LOG_D(BMS_TAG_QUERY_ABILITY, "bundleName: %{public}s cant find ability.", info.GetBundleName().c_str());
            return;
        }
        if (!info.GetIsNewVersion()) {
            ability->applicationInfo.label = info.GetBundleName();
        }
        ability->installTime = installTime;
        abilityInfos.emplace_back(*ability);
    }
}

void BundleDataMgr::GetMatchLauncherAbilityInfosForCloneInfos(
    const InnerBundleInfo& info,
    const AbilityInfo &abilityInfo,
    const InnerBundleUserInfo &bundleUserInfo,
    std::vector<AbilityInfo>& abilityInfos) const
{
    for (const auto &item : bundleUserInfo.cloneInfos) {
        APP_LOGD("bundleName:%{public}s appIndex:%{public}d start", info.GetBundleName().c_str(), item.second.appIndex);
        AbilityInfo cloneAbilityInfo = abilityInfo;
        info.GetApplicationInfo(ApplicationFlag::GET_APPLICATION_INFO_WITH_CERTIFICATE_FINGERPRINT,
            bundleUserInfo.bundleUserInfo.userId, cloneAbilityInfo.applicationInfo, item.second.appIndex);
        cloneAbilityInfo.installTime = item.second.installTime;
        cloneAbilityInfo.uid =  item.second.uid;
        cloneAbilityInfo.appIndex = item.second.appIndex;
        // fix labelId or iconId is equal 0
        ModifyLauncherAbilityInfo(info.GetIsNewVersion(), cloneAbilityInfo);
        abilityInfos.emplace_back(cloneAbilityInfo);
    }
}

void BundleDataMgr::ModifyApplicationInfoByCloneInfo(const InnerBundleCloneInfo &cloneInfo,
    ApplicationInfo &applicationInfo) const
{
    if (applicationInfo.removable && !cloneInfo.isRemovable) {
        applicationInfo.removable = false;
    }
    applicationInfo.accessTokenId = cloneInfo.accessTokenId;
    applicationInfo.accessTokenIdEx = cloneInfo.accessTokenIdEx;
    applicationInfo.enabled = cloneInfo.enabled;
    applicationInfo.uid = cloneInfo.uid;
    applicationInfo.appIndex = cloneInfo.appIndex;
}

void BundleDataMgr::ModifyBundleInfoByCloneInfo(const InnerBundleCloneInfo &cloneInfo,
    BundleInfo &bundleInfo) const
{
    bundleInfo.uid = cloneInfo.uid;
    bundleInfo.gid = cloneInfo.uid; // no gids, need add
    bundleInfo.installTime = cloneInfo.installTime;
    bundleInfo.updateTime = cloneInfo.updateTime;
    bundleInfo.appIndex = cloneInfo.appIndex;
    if (!bundleInfo.applicationInfo.bundleName.empty()) {
        ModifyApplicationInfoByCloneInfo(cloneInfo, bundleInfo.applicationInfo);
    }
}

void BundleDataMgr::GetCloneBundleInfos(const InnerBundleInfo& info, int32_t userId,
    BundleInfo &bundleInfo, std::vector<BundleInfo> &bundleInfos) const
{
    // get clone bundle info
    InnerBundleUserInfo bundleUserInfo;
    (void)info.GetInnerBundleUserInfo(userId, bundleUserInfo);
    if (bundleUserInfo.cloneInfos.empty()) {
        return;
    }
    LOG_D(BMS_TAG_QUERY_BUNDLE, "app %{public}s start get bundle clone info",
        info.GetBundleName().c_str());
    for (const auto &item : bundleUserInfo.cloneInfos) {
        ModifyBundleInfoByCloneInfo(item.second, bundleInfo);
        bundleInfos.emplace_back(bundleInfo);
    }
}

void BundleDataMgr::GetBundleNameAndIndexByName(
    const std::string &keyName, std::string &bundleName, int32_t &appIndex) const
{
    bundleName = keyName;
    appIndex = 0;
    // for clone bundle name
    auto pos = keyName.find(Constants::CLONE_BUNDLE_PREFIX);
    if ((pos == std::string::npos) || (pos == 0)) {
        return;
    }
    std::string index = keyName.substr(0, pos);
    if (!OHOS::StrToInt(index, appIndex)) {
        appIndex = 0;
        return;
    }
    bundleName = keyName.substr(pos + Constants::CLONE_BUNDLE_PREFIX.size());
}

std::vector<int32_t> BundleDataMgr::GetCloneAppIndexes(const std::string &bundleName, int32_t requestUserId) const
{
    std::vector<int32_t> cloneAppIndexes;
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        LOG_W(BMS_TAG_QUERY_ABILITY, "no bundleName %{public}s found", bundleName.c_str());
        return cloneAppIndexes;
    }
    const InnerBundleInfo &bundleInfo = infoItem->second;
    InnerBundleUserInfo innerBundleUserInfo;
    if (!bundleInfo.GetInnerBundleUserInfo(requestUserId, innerBundleUserInfo)) {
        return cloneAppIndexes;
    }
    const std::map<std::string, InnerBundleCloneInfo> &cloneInfos = innerBundleUserInfo.cloneInfos;
    if (cloneInfos.empty()) {
        return cloneAppIndexes;
    }
    for (const auto &cloneInfo : cloneInfos) {
        LOG_I(BMS_TAG_QUERY_ABILITY, "get cloneAppIndexes: %{public}d", cloneInfo.second.appIndex);
        cloneAppIndexes.emplace_back(cloneInfo.second.appIndex);
    }
    return cloneAppIndexes;
}

void BundleDataMgr::AddAppDetailAbilityInfo(InnerBundleInfo &info) const
{
    AbilityInfo appDetailAbility;
    appDetailAbility.name = Constants::APP_DETAIL_ABILITY;
    appDetailAbility.bundleName = info.GetBundleName();
    appDetailAbility.enabled = true;
    appDetailAbility.type = AbilityType::PAGE;
    appDetailAbility.isNativeAbility = true;

    ApplicationInfo applicationInfo = info.GetBaseApplicationInfo();
    appDetailAbility.applicationName = applicationInfo.name;
    appDetailAbility.labelId = applicationInfo.labelResource.id;
    if (!info.GetIsNewVersion()) {
        appDetailAbility.labelId = 0;
        appDetailAbility.label = info.GetBundleName();
    }
    appDetailAbility.iconId = applicationInfo.iconResource.id;
    appDetailAbility.moduleName = applicationInfo.iconResource.moduleName;

    if ((appDetailAbility.iconId == 0) || !info.GetIsNewVersion()) {
        LOG_D(BMS_TAG_QUERY_ABILITY, "AddAppDetailAbilityInfo appDetailAbility.iconId is 0.");
        // get system resource icon Id
        auto iter = bundleInfos_.find(GLOBAL_RESOURCE_BUNDLE_NAME);
        if (iter != bundleInfos_.end()) {
            LOG_D(BMS_TAG_QUERY_ABILITY, "AddAppDetailAbilityInfo get system resource iconId");
            appDetailAbility.iconId = iter->second.GetBaseApplicationInfo().iconId;
        } else {
            LOG_W(BMS_TAG_QUERY_ABILITY, "AddAppDetailAbilityInfo error: ohos.global.systemres does not exist.");
        }
    }
    // not show in the mission list
    appDetailAbility.removeMissionAfterTerminate = true;
    // set hapPath, for label resource
    auto innerModuleInfo = info.GetInnerModuleInfoByModuleName(appDetailAbility.moduleName);
    if (innerModuleInfo) {
        appDetailAbility.package = innerModuleInfo->modulePackage;
        appDetailAbility.hapPath = innerModuleInfo->hapPath;
    }
    appDetailAbility.visible = true;
    std::string keyName;
    keyName.append(appDetailAbility.bundleName).append(".")
        .append(appDetailAbility.package).append(".").append(appDetailAbility.name);
    info.InsertAbilitiesInfo(keyName, appDetailAbility);
}

void BundleDataMgr::GetAllLauncherAbility(const Want &want, std::vector<AbilityInfo> &abilityInfos,
    const int32_t userId, const int32_t requestUserId) const
{
    for (const auto &item : bundleInfos_) {
        const InnerBundleInfo &info = item.second;
        if (info.IsDisabled()) {
            LOG_W(BMS_TAG_QUERY_ABILITY, "app %{public}s is disabled", info.GetBundleName().c_str());
            continue;
        }
        if (info.GetBaseApplicationInfo().hideDesktopIcon) {
            LOG_D(BMS_TAG_QUERY_ABILITY, "Bundle(%{public}s) hide desktop icon", info.GetBundleName().c_str());
            continue;
        }
        if (info.GetBaseBundleInfo().entryInstallationFree) {
            LOG_D(BMS_TAG_QUERY_ABILITY, "Bundle(%{public}s) is atomic service, hide desktop icon",
                info.GetBundleName().c_str());
            continue;
        }

        // get installTime from innerBundleUserInfo
        int64_t installTime = 0;
        std::string userIdKey = info.GetBundleName() + "_" + std::to_string(userId);
        std::string userZeroKey = info.GetBundleName() + "_" + std::to_string(0);
        auto iter = std::find_if(info.GetInnerBundleUserInfos().begin(), info.GetInnerBundleUserInfos().end(),
            [&userIdKey, &userZeroKey](const std::pair<std::string, InnerBundleUserInfo> &infoMap) {
            return (infoMap.first == userIdKey || infoMap.first == userZeroKey);
        });
        if (iter != info.GetInnerBundleUserInfos().end()) {
            installTime = iter->second.installTime;
        }
        GetMatchLauncherAbilityInfos(want, info, abilityInfos, installTime, userId);
    }
}

ErrCode BundleDataMgr::GetLauncherAbilityByBundleName(const Want &want, std::vector<AbilityInfo> &abilityInfos,
    const int32_t userId, const int32_t requestUserId) const
{
    ElementName element = want.GetElement();
    std::string bundleName = element.GetBundleName();
    const auto &item = bundleInfos_.find(bundleName);
    if (item == bundleInfos_.end()) {
        LOG_W(BMS_TAG_QUERY_ABILITY, "no bundleName %{public}s found", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    const InnerBundleInfo &info = item->second;
    if (info.IsDisabled()) {
        LOG_W(BMS_TAG_QUERY_ABILITY, "app %{public}s is disabled", info.GetBundleName().c_str());
        return ERR_BUNDLE_MANAGER_APPLICATION_DISABLED;
    }
    if (info.GetBaseApplicationInfo().hideDesktopIcon) {
        LOG_D(BMS_TAG_QUERY_ABILITY, "Bundle(%{public}s) hide desktop icon", bundleName.c_str());
        return ERR_OK;
    }
    if (info.GetBaseBundleInfo().entryInstallationFree) {
        LOG_D(BMS_TAG_QUERY_ABILITY, "Bundle(%{public}s) is atomic service, hide desktop icon", bundleName.c_str());
        return ERR_OK;
    }
    // get installTime from innerBundleUserInfo
    int64_t installTime = 0;
    std::string userIdKey = info.GetBundleName() + "_" + std::to_string(userId);
    std::string userZeroKey = info.GetBundleName() + "_" + std::to_string(0);
    auto iter = std::find_if(info.GetInnerBundleUserInfos().begin(), info.GetInnerBundleUserInfos().end(),
        [&userIdKey, &userZeroKey](const std::pair<std::string, InnerBundleUserInfo> &infoMap) {
        return (infoMap.first == userIdKey || infoMap.first == userZeroKey);
    });
    if (iter != info.GetInnerBundleUserInfos().end()) {
        installTime = iter->second.installTime;
    }
    GetMatchLauncherAbilityInfos(want, item->second, abilityInfos, installTime, userId);
    FilterAbilityInfosByModuleName(element.GetModuleName(), abilityInfos);
    return ERR_OK;
}

ErrCode BundleDataMgr::QueryLauncherAbilityInfos(
    const Want &want, int32_t userId, std::vector<AbilityInfo> &abilityInfos) const
{
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    if (bundleInfos_.empty()) {
        LOG_W(BMS_TAG_QUERY_ABILITY, "bundleInfos_ is empty");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    ElementName element = want.GetElement();
    std::string bundleName = element.GetBundleName();
    if (bundleName.empty()) {
        // query all launcher ability
        GetAllLauncherAbility(want, abilityInfos, userId, requestUserId);
        return ERR_OK;
    }
    // query definite abilities by bundle name
    ErrCode ret = GetLauncherAbilityByBundleName(want, abilityInfos, userId, requestUserId);
    if (ret == ERR_OK) {
        LOG_D(BMS_TAG_QUERY_ABILITY, "ability infos have been found");
    }
    return ret;
}

bool BundleDataMgr::QueryAbilityInfoByUri(
    const std::string &abilityUri, int32_t userId, AbilityInfo &abilityInfo) const
{
    LOG_D(BMS_TAG_QUERY_ABILITY, "abilityUri is %{private}s", abilityUri.c_str());
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return false;
    }

    if (abilityUri.empty()) {
        return false;
    }
    if (abilityUri.find(Constants::DATA_ABILITY_URI_PREFIX) == std::string::npos) {
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    if (bundleInfos_.empty()) {
        LOG_W(BMS_TAG_QUERY_ABILITY, "bundleInfos_ data is empty");
        return false;
    }
    std::string noPpefixUri = abilityUri.substr(strlen(Constants::DATA_ABILITY_URI_PREFIX));
    auto posFirstSeparator = noPpefixUri.find(Constants::FILE_SEPARATOR_CHAR);
    if (posFirstSeparator == std::string::npos) {
        return false;
    }
    auto posSecondSeparator = noPpefixUri.find(Constants::FILE_SEPARATOR_CHAR, posFirstSeparator + 1);
    std::string uri;
    if (posSecondSeparator == std::string::npos) {
        uri = noPpefixUri.substr(posFirstSeparator + 1, noPpefixUri.size() - posFirstSeparator - 1);
    } else {
        uri = noPpefixUri.substr(posFirstSeparator + 1, posSecondSeparator - posFirstSeparator - 1);
    }
    for (const auto &item : bundleInfos_) {
        const InnerBundleInfo &info = item.second;
        if (info.IsDisabled()) {
            LOG_D(BMS_TAG_QUERY_ABILITY, "app %{public}s is disabled", info.GetBundleName().c_str());
            continue;
        }

        int32_t responseUserId = info.GetResponseUserId(requestUserId);
        if (!info.GetApplicationEnabled(responseUserId)) {
            continue;
        }

        auto ability = info.FindAbilityInfoByUri(uri);
        if (!ability) {
            continue;
        }

        abilityInfo = (*ability);
        info.GetApplicationInfo(
            ApplicationFlag::GET_APPLICATION_INFO_WITH_CERTIFICATE_FINGERPRINT, responseUserId,
            abilityInfo.applicationInfo);
        return true;
    }

    LOG_W(BMS_TAG_QUERY_ABILITY, "query abilityUri(%{private}s) failed.", abilityUri.c_str());
    return false;
}

bool BundleDataMgr::QueryAbilityInfosByUri(const std::string &abilityUri, std::vector<AbilityInfo> &abilityInfos)
{
    LOG_D(BMS_TAG_QUERY_ABILITY, "abilityUri is %{private}s", abilityUri.c_str());
    if (abilityUri.empty()) {
        return false;
    }
    if (abilityUri.find(Constants::DATA_ABILITY_URI_PREFIX) == std::string::npos) {
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    if (bundleInfos_.empty()) {
        LOG_W(BMS_TAG_QUERY_ABILITY, "bundleInfos_ data is empty");
        return false;
    }
    std::string noPpefixUri = abilityUri.substr(strlen(Constants::DATA_ABILITY_URI_PREFIX));
    auto posFirstSeparator = noPpefixUri.find(Constants::FILE_SEPARATOR_CHAR);
    if (posFirstSeparator == std::string::npos) {
        return false;
    }
    auto posSecondSeparator = noPpefixUri.find(Constants::FILE_SEPARATOR_CHAR, posFirstSeparator + 1);
    std::string uri;
    if (posSecondSeparator == std::string::npos) {
        uri = noPpefixUri.substr(posFirstSeparator + 1, noPpefixUri.size() - posFirstSeparator - 1);
    } else {
        uri = noPpefixUri.substr(posFirstSeparator + 1, posSecondSeparator - posFirstSeparator - 1);
    }

    for (auto &item : bundleInfos_) {
        InnerBundleInfo &info = item.second;
        if (info.IsDisabled()) {
            LOG_D(BMS_TAG_QUERY_ABILITY, "app %{public}s is disabled", info.GetBundleName().c_str());
            continue;
        }
        info.FindAbilityInfosByUri(uri, abilityInfos, GetUserId());
    }
    if (abilityInfos.size() == 0) {
        return false;
    }

    return true;
}

bool BundleDataMgr::GetApplicationInfo(
    const std::string &appName, int32_t flags, const int userId, ApplicationInfo &appInfo) const
{
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return false;
    }

    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    InnerBundleInfo innerBundleInfo;
    if (!GetInnerBundleInfoWithFlags(appName, flags, innerBundleInfo, requestUserId)) {
        LOG_D(BMS_TAG_QUERY_APPLICATION, "GetApplicationInfo failed, bundleName:%{public}s", appName.c_str());
        return false;
    }

    int32_t responseUserId = innerBundleInfo.GetResponseUserId(requestUserId);
    innerBundleInfo.GetApplicationInfo(flags, responseUserId, appInfo);
    return true;
}

ErrCode BundleDataMgr::GetApplicationInfoV9(
    const std::string &appName, int32_t flags, int32_t userId, ApplicationInfo &appInfo) const
{
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }

    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    InnerBundleInfo innerBundleInfo;
    int32_t flag = 0;
    if ((static_cast<uint32_t>(flags) & static_cast<uint32_t>(GetApplicationFlag::GET_APPLICATION_INFO_WITH_DISABLE))
        == static_cast<uint32_t>(GetApplicationFlag::GET_APPLICATION_INFO_WITH_DISABLE)) {
        flag = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE);
    }
    auto ret = GetInnerBundleInfoWithBundleFlagsV9(appName, flag, innerBundleInfo, requestUserId);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_QUERY_APPLICATION,
            "GetApplicationInfoV9 failed, bundleName:%{public}s, requestUserId:%{public}d",
            appName.c_str(), requestUserId);
        return ret;
    }

    int32_t responseUserId = innerBundleInfo.GetResponseUserId(requestUserId);
    ret = innerBundleInfo.GetApplicationInfoV9(flags, responseUserId, appInfo);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_QUERY_APPLICATION,
            "GetApplicationInfoV9 failed, bundleName:%{public}s, responseUserId:%{public}d",
            appName.c_str(), responseUserId);
        return ret;
    }
    return ret;
}

ErrCode BundleDataMgr::GetApplicationInfoWithResponseId(
    const std::string &appName, int32_t flags, int32_t &userId, ApplicationInfo &appInfo) const
{
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }

    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    InnerBundleInfo innerBundleInfo;
    int32_t flag = 0;
    if ((static_cast<uint32_t>(flags) & static_cast<uint32_t>(GetApplicationFlag::GET_APPLICATION_INFO_WITH_DISABLE))
        == static_cast<uint32_t>(GetApplicationFlag::GET_APPLICATION_INFO_WITH_DISABLE)) {
        flag = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE);
    }
    auto ret = GetInnerBundleInfoWithBundleFlagsV9(appName, flag, innerBundleInfo, requestUserId);
    if (ret != ERR_OK) {
        LOG_D(BMS_TAG_QUERY_APPLICATION,
            "GetApplicationInfoV9 failed, bundleName:%{public}s, requestUserId:%{public}d",
            appName.c_str(), requestUserId);
        return ret;
    }

    int32_t responseUserId = innerBundleInfo.GetResponseUserId(requestUserId);
    ret = innerBundleInfo.GetApplicationInfoV9(flags, responseUserId, appInfo);
    if (ret != ERR_OK) {
        LOG_D(BMS_TAG_QUERY_APPLICATION,
            "GetApplicationInfoV9 failed, bundleName:%{public}s, responseUserId:%{public}d",
            appName.c_str(), responseUserId);
        return ret;
    }
    userId = responseUserId;
    return ret;
}

bool BundleDataMgr::GetApplicationInfos(
    int32_t flags, const int userId, std::vector<ApplicationInfo> &appInfos) const
{
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return false;
    }

    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    if (bundleInfos_.empty()) {
        LOG_W(BMS_TAG_QUERY_APPLICATION, "bundleInfos_ data is empty");
        return false;
    }

    bool find = false;
    for (const auto &item : bundleInfos_) {
        const InnerBundleInfo &info = item.second;
        if (info.IsDisabled()) {
            LOG_D(BMS_TAG_QUERY_APPLICATION, "app %{public}s is disabled", info.GetBundleName().c_str());
            continue;
        }
        int32_t responseUserId = info.GetResponseUserId(requestUserId);
        if (!(static_cast<uint32_t>(flags) & GET_APPLICATION_INFO_WITH_DISABLE)
            && !info.GetApplicationEnabled(responseUserId)) {
            LOG_D(BMS_TAG_QUERY_APPLICATION, "bundleName: %{public}s userId: %{public}d incorrect",
                info.GetBundleName().c_str(), responseUserId);
            continue;
        }
        ApplicationInfo appInfo;
        info.GetApplicationInfo(flags, responseUserId, appInfo);
        appInfos.emplace_back(appInfo);
        find = true;
    }
    LOG_D(BMS_TAG_QUERY_APPLICATION, "get installed bundles success");
    return find;
}

bool BundleDataMgr::UpateExtResources(const std::string &bundleName,
    const std::vector<ExtendResourceInfo> &extendResourceInfos)
{
    if (bundleName.empty()) {
        APP_LOGW("bundleName is empty");
        return false;
    }

    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("can not find bundle %{public}s", bundleName.c_str());
        return false;
    }

    auto info = infoItem->second;
    info.AddExtendResourceInfos(extendResourceInfos);
    if (!dataStorage_->SaveStorageBundleInfo(info)) {
        APP_LOGW("SaveStorageBundleInfo failed %{public}s", bundleName.c_str());
        return false;
    }

    bundleInfos_.at(bundleName) = info;
    return true;
}

bool BundleDataMgr::RemoveExtResources(const std::string &bundleName,
    const std::vector<std::string> &moduleNames)
{
    if (bundleName.empty()) {
        APP_LOGW("bundleName is empty");
        return false;
    }

    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("can not find bundle %{public}s", bundleName.c_str());
        return false;
    }

    auto info = infoItem->second;
    info.RemoveExtendResourceInfos(moduleNames);
    if (!dataStorage_->SaveStorageBundleInfo(info)) {
        APP_LOGW("SaveStorageBundleInfo failed %{public}s", bundleName.c_str());
        return false;
    }

    bundleInfos_.at(bundleName) = info;
    return true;
}

bool BundleDataMgr::UpateCurDynamicIconModule(
    const std::string &bundleName, const std::string &moduleName)
{
    if (bundleName.empty()) {
        APP_LOGW("bundleName is empty");
        return false;
    }

    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("can not find bundle %{public}s", bundleName.c_str());
        return false;
    }

    auto info = infoItem->second;
    info.SetCurDynamicIconModule(moduleName);
    if (!dataStorage_->SaveStorageBundleInfo(info)) {
        APP_LOGW("SaveStorageBundleInfo failed %{public}s", bundleName.c_str());
        return false;
    }

    bundleInfos_.at(bundleName) = info;
    return true;
}

ErrCode BundleDataMgr::GetApplicationInfosV9(
    int32_t flags, int32_t userId, std::vector<ApplicationInfo> &appInfos) const
{
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }

    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    if (bundleInfos_.empty()) {
        APP_LOGW("bundleInfos_ data is empty");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    for (const auto &item : bundleInfos_) {
        const InnerBundleInfo &info = item.second;
        if (info.IsDisabled()) {
            APP_LOGD("app %{public}s is disabled", info.GetBundleName().c_str());
            continue;
        }
        int32_t responseUserId = info.GetResponseUserId(requestUserId);
        if (!(static_cast<uint32_t>(flags) &
            static_cast<uint32_t>(GetApplicationFlag::GET_APPLICATION_INFO_WITH_DISABLE))
            && !info.GetApplicationEnabled(responseUserId)) {
            APP_LOGD("bundleName: %{public}s userId: %{public}d incorrect",
                info.GetBundleName().c_str(), responseUserId);
            continue;
        }
        ApplicationInfo appInfo;
        if (info.GetApplicationInfoV9(flags, responseUserId, appInfo) != ERR_OK) {
            continue;
        }
        appInfos.emplace_back(appInfo);
    }
    APP_LOGD("get installed bundles success");
    return ERR_OK;
}

bool BundleDataMgr::GetBundleInfo(
    const std::string &bundleName, int32_t flags, BundleInfo &bundleInfo, int32_t userId) const
{
    std::vector<InnerBundleUserInfo> innerBundleUserInfos;
    if (userId == Constants::ANY_USERID) {
        if (!GetInnerBundleUserInfos(bundleName, innerBundleUserInfos)) {
            LOG_W(BMS_TAG_QUERY_BUNDLE, "no userInfos for this bundle(%{public}s)", bundleName.c_str());
            return false;
        }
        userId = innerBundleUserInfos.begin()->bundleUserInfo.userId;
    }

    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    InnerBundleInfo innerBundleInfo;
    if (!GetInnerBundleInfoWithFlags(bundleName, flags, innerBundleInfo, requestUserId)) {
        LOG_W(BMS_TAG_QUERY_BUNDLE, "GetBundleInfo failed, bundleName:%{public}s, requestUserId:%{public}d",
            bundleName.c_str(), requestUserId);
        return false;
    }

    int32_t responseUserId = innerBundleInfo.GetResponseUserId(requestUserId);
    innerBundleInfo.GetBundleInfo(flags, bundleInfo, responseUserId);

    if ((static_cast<uint32_t>(flags) & BundleFlag::GET_BUNDLE_WITH_MENU) == BundleFlag::GET_BUNDLE_WITH_MENU) {
        ProcessBundleMenu(bundleInfo, flags, false);
    }
    if ((static_cast<uint32_t>(flags) & BundleFlag::GET_BUNDLE_WITH_ROUTER_MAP) ==
        BundleFlag::GET_BUNDLE_WITH_ROUTER_MAP) {
        ProcessBundleRouterMap(bundleInfo, static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) |
            static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_ROUTER_MAP));
    }
    LOG_D(BMS_TAG_QUERY_BUNDLE, "get bundleInfo(%{public}s) successfully in user(%{public}d)",
        bundleName.c_str(), userId);
    return true;
}

ErrCode BundleDataMgr::GetBundleInfoV9(
    const std::string &bundleName, int32_t flags, BundleInfo &bundleInfo, int32_t userId, int32_t appIndex) const
{
    std::vector<InnerBundleUserInfo> innerBundleUserInfos;
    if (userId == Constants::ANY_USERID) {
        if (!GetInnerBundleUserInfos(bundleName, innerBundleUserInfos)) {
            LOG_W(BMS_TAG_QUERY_BUNDLE, "no userInfos for this bundle(%{public}s)", bundleName.c_str());
            return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
        }
        userId = innerBundleUserInfos.begin()->bundleUserInfo.userId;
    }

    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    InnerBundleInfo innerBundleInfo;

    auto ret = GetInnerBundleInfoWithBundleFlagsV9(bundleName, flags, innerBundleInfo, requestUserId);
    if (ret != ERR_OK) {
        LOG_D(BMS_TAG_QUERY_BUNDLE, "GetBundleInfoV9 failed, error code: %{public}d, bundleName:%{public}s",
            ret, bundleName.c_str());
        return ret;
    }

    int32_t responseUserId = innerBundleInfo.GetResponseUserId(requestUserId);
    innerBundleInfo.GetBundleInfoV9(flags, bundleInfo, responseUserId, appIndex);

    ProcessBundleMenu(bundleInfo, flags, true);
    ProcessBundleRouterMap(bundleInfo, flags);
    LOG_D(BMS_TAG_QUERY_BUNDLE, "get bundleInfo(%{public}s) successfully in user(%{public}d)",
        bundleName.c_str(), userId);
    return ERR_OK;
}

ErrCode BundleDataMgr::BatchGetBundleInfo(const std::vector<std::string> &bundleNames, int32_t flags,
    std::vector<BundleInfo> &bundleInfos, int32_t userId) const
{
    for (size_t i = 0; i < bundleNames.size(); i++) {
        auto it = std::find_if(bundleInfos.begin(), bundleInfos.end(),
            [&](const BundleInfo& info) {
                return bundleNames[i] == info.name;
            });
        if (it == bundleInfos.end()) {
            BundleInfo bundleInfo;
            ErrCode ret = GetBundleInfoV9(bundleNames[i], flags, bundleInfo, userId);
            if (ret != ERR_OK && ret != ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST) {
                APP_LOGE("BatchGetBundleInfo failed, error code: %{public}d", ret);
                return ret;
            }
            if (ret == ERR_OK) {
                bundleInfos.push_back(bundleInfo);
            }
        }
    }
    APP_LOGD("BatchGetBundleInfo successfully in user(%{public}d)", userId);
    return ERR_OK;
}

ErrCode BundleDataMgr::ProcessBundleMenu(BundleInfo &bundleInfo, int32_t flags, bool clearData) const
{
    if (clearData) {
        if ((static_cast<uint32_t>(flags) & static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE))
            != static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE)) {
            return ERR_OK;
        }
        if ((static_cast<uint32_t>(flags) & static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_MENU))
            != static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_MENU)) {
            APP_LOGD("no GET_BUNDLE_INFO_WITH_MENU flag, remove menu content");
            std::for_each(bundleInfo.hapModuleInfos.begin(), bundleInfo.hapModuleInfos.end(), [](auto &hapModuleInfo) {
                hapModuleInfo.fileContextMenu = Constants::EMPTY_STRING;
            });
            return ERR_OK;
        }
    }
    for (auto &hapModuleInfo : bundleInfo.hapModuleInfos) {
        std::string menuProfile = hapModuleInfo.fileContextMenu;
        auto pos = menuProfile.find(PROFILE_PREFIX);
        if (pos == std::string::npos) {
            APP_LOGD("invalid menu profile");
            continue;
        }
        std::string menuFileName = menuProfile.substr(pos + PROFILE_PREFIX_LENGTH);
        std::string menuFilePath = PROFILE_PATH + menuFileName + JSON_SUFFIX;

        std::string menuProfileContent;
        GetJsonProfileByExtractor(hapModuleInfo.hapPath, menuFilePath, menuProfileContent);
        hapModuleInfo.fileContextMenu = menuProfileContent;
    }
    return ERR_OK;
}

void BundleDataMgr::ProcessBundleRouterMap(BundleInfo& bundleInfo, int32_t flag) const
{
    APP_LOGD("ProcessBundleRouterMap with flags: %{public}d", flag);
    if ((static_cast<uint32_t>(flag) & static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE))
        != static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE)) {
        return;
    }
    if ((static_cast<uint32_t>(flag) & static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_ROUTER_MAP))
        != static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_ROUTER_MAP)) {
        return;
    }
    for (auto &hapModuleInfo : bundleInfo.hapModuleInfos) {
        std::string routerPath = hapModuleInfo.routerMap;
        auto pos = routerPath.find(PROFILE_PREFIX);
        if (pos == std::string::npos) {
            APP_LOGD("invalid router profile");
            continue;
        }
        std::string routerJsonName = routerPath.substr(pos + PROFILE_PREFIX_LENGTH);
        std::string routerJsonPath = PROFILE_PATH + routerJsonName + JSON_SUFFIX;

        std::string routerMapString;
        if (GetJsonProfileByExtractor(hapModuleInfo.hapPath, routerJsonPath, routerMapString) != ERR_OK) {
            APP_LOGW("get json string from %{public}s failed", routerJsonPath.c_str());
            continue;
        }

        BundleParser bundleParser;
        if (bundleParser.ParseRouterArray(routerMapString, hapModuleInfo.routerArray) != ERR_OK) {
            APP_LOGE("parse router array from json file %{public}s failed", routerJsonPath.c_str());
        }
    }
    RouterMapHelper::MergeRouter(bundleInfo);
}

ErrCode BundleDataMgr::GetBaseSharedBundleInfos(const std::string &bundleName,
    std::vector<BaseSharedBundleInfo> &baseSharedBundleInfos, GetDependentBundleInfoFlag flag) const
{
    APP_LOGD("start, bundleName:%{public}s", bundleName.c_str());
    if ((flag == GetDependentBundleInfoFlag::GET_APP_SERVICE_HSP_BUNDLE_INFO) ||
        (flag == GetDependentBundleInfoFlag::GET_ALL_DEPENDENT_BUNDLE_INFO)) {
        // for app service hsp
        std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
        std::lock_guard<std::mutex> hspLock(hspBundleNameMutex_);
        for (const std::string &hspName : appServiceHspBundleName_) {
            APP_LOGD("get hspBundleName: %{public}s", hspName.c_str());
            auto infoItem = bundleInfos_.find(hspName);
            if (infoItem == bundleInfos_.end()) {
                APP_LOGW("get hsp bundleInfo failed, hspName:%{public}s", hspName.c_str());
                continue;
            }
            ConvertServiceHspToSharedBundleInfo(infoItem->second, baseSharedBundleInfos);
        }
    }
    if (flag == GetDependentBundleInfoFlag::GET_APP_CROSS_HSP_BUNDLE_INFO ||
        flag == GetDependentBundleInfoFlag::GET_ALL_DEPENDENT_BUNDLE_INFO) {
        std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
        auto infoItem = bundleInfos_.find(bundleName);
        if (infoItem == bundleInfos_.end()) {
            APP_LOGW("GetBaseSharedBundleInfos get bundleInfo failed, bundleName:%{public}s", bundleName.c_str());
            return (flag == GetDependentBundleInfoFlag::GET_APP_CROSS_HSP_BUNDLE_INFO) ?
                ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST : ERR_OK;
        }
        const InnerBundleInfo &innerBundleInfo = infoItem->second;
        std::vector<Dependency> dependencies = innerBundleInfo.GetDependencies();
        for (const auto &item : dependencies) {
            BaseSharedBundleInfo baseSharedBundleInfo;
            if (GetBaseSharedBundleInfo(item, baseSharedBundleInfo)) {
                baseSharedBundleInfos.emplace_back(baseSharedBundleInfo);
            }
        }
    }
    APP_LOGD("GetBaseSharedBundleInfos(%{public}s) successfully", bundleName.c_str());
    return ERR_OK;
}

bool BundleDataMgr::GetBaseSharedBundleInfo(const Dependency &dependency,
    BaseSharedBundleInfo &baseSharedBundleInfo) const
{
    auto infoItem = bundleInfos_.find(dependency.bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGD("GetBaseSharedBundleInfo failed, can not find dependency bundle %{public}s",
            dependency.bundleName.c_str());
        return false;
    }
    const InnerBundleInfo &innerBundleInfo = infoItem->second;
    if (innerBundleInfo.GetApplicationBundleType() == BundleType::SHARED) {
        innerBundleInfo.GetMaxVerBaseSharedBundleInfo(dependency.moduleName, baseSharedBundleInfo);
    } else {
        APP_LOGW("GetBaseSharedBundleInfo failed, can not find bundleType %{public}d",
            innerBundleInfo.GetApplicationBundleType());
        return false;
    }
    APP_LOGD("GetBaseSharedBundleInfo(%{public}s) successfully)", dependency.bundleName.c_str());
    return true;
}

bool BundleDataMgr::DeleteSharedBundleInfo(const std::string &bundleName)
{
    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem != bundleInfos_.end()) {
        APP_LOGD("del bundle name:%{public}s", bundleName.c_str());
        const InnerBundleInfo &innerBundleInfo = infoItem->second;
        bool ret = dataStorage_->DeleteStorageBundleInfo(innerBundleInfo);
        if (!ret) {
            APP_LOGW("delete storage error name:%{public}s", bundleName.c_str());
        }
        bundleInfos_.erase(bundleName);
        return ret;
    }
    return false;
}

ErrCode BundleDataMgr::GetBundlePackInfo(
    const std::string &bundleName, int32_t flags, BundlePackInfo &bundlePackInfo, int32_t userId) const
{
    APP_LOGD("Service BundleDataMgr GetBundlePackInfo start");
    int32_t requestUserId;
    if (userId == Constants::UNSPECIFIED_USERID) {
        requestUserId = GetUserIdByCallingUid();
    } else {
        requestUserId = userId;
    }

    if (requestUserId == Constants::INVALID_USERID) {
        APP_LOGW("getBundlePackInfo userId is invalid");
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    InnerBundleInfo innerBundleInfo;
    if (!GetInnerBundleInfoWithFlags(bundleName, flags, innerBundleInfo, requestUserId)) {
        APP_LOGW("GetBundlePackInfo failed, bundleName:%{public}s", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    BundlePackInfo innerBundlePackInfo = innerBundleInfo.GetBundlePackInfo();
    if (static_cast<uint32_t>(flags) & GET_PACKAGES) {
        bundlePackInfo.packages = innerBundlePackInfo.packages;
        return ERR_OK;
    }
    if (static_cast<uint32_t>(flags) & GET_BUNDLE_SUMMARY) {
        bundlePackInfo.summary.app = innerBundlePackInfo.summary.app;
        bundlePackInfo.summary.modules = innerBundlePackInfo.summary.modules;
        return ERR_OK;
    }
    if (static_cast<uint32_t>(flags) & GET_MODULE_SUMMARY) {
        bundlePackInfo.summary.modules = innerBundlePackInfo.summary.modules;
        return ERR_OK;
    }
    bundlePackInfo = innerBundlePackInfo;
    return ERR_OK;
}

bool BundleDataMgr::GetBundleInfosByMetaData(
    const std::string &metaData, std::vector<BundleInfo> &bundleInfos) const
{
    if (metaData.empty()) {
        APP_LOGW("bundle name is empty");
        return false;
    }

    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    if (bundleInfos_.empty()) {
        APP_LOGW("bundleInfos_ data is empty");
        return false;
    }

    bool find = false;
    int32_t requestUserId = GetUserId();
    for (const auto &item : bundleInfos_) {
        const InnerBundleInfo &info = item.second;
        if (info.IsDisabled()) {
            APP_LOGD("app %{public}s is disabled", info.GetBundleName().c_str());
            continue;
        }
        if (info.CheckSpecialMetaData(metaData)) {
            BundleInfo bundleInfo;
            int32_t responseUserId = info.GetResponseUserId(requestUserId);
            info.GetBundleInfo(
                BundleFlag::GET_BUNDLE_WITH_ABILITIES, bundleInfo, responseUserId);
            bundleInfos.emplace_back(bundleInfo);
            find = true;
        }
    }
    return find;
}

bool BundleDataMgr::GetBundleList(
    std::vector<std::string> &bundleNames, int32_t userId) const
{
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return false;
    }

    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    if (bundleInfos_.empty()) {
        APP_LOGW("bundleInfos_ data is empty");
        return false;
    }

    bool find = false;
    for (const auto &infoItem : bundleInfos_) {
        const InnerBundleInfo &innerBundleInfo = infoItem.second;
        int32_t responseUserId = innerBundleInfo.GetResponseUserId(requestUserId);
        if (CheckInnerBundleInfoWithFlags(
            innerBundleInfo, BundleFlag::GET_BUNDLE_DEFAULT, responseUserId) != ERR_OK) {
            continue;
        }

        bundleNames.emplace_back(infoItem.first);
        find = true;
    }
    APP_LOGD("user(%{public}d) get installed bundles list result(%{public}d)", userId, find);
    return find;
}

bool BundleDataMgr::GetBundleInfos(
    int32_t flags, std::vector<BundleInfo> &bundleInfos, int32_t userId) const
{
    if (userId == Constants::ALL_USERID) {
        return GetAllBundleInfos(flags, bundleInfos);
    }

    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return false;
    }

    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    if (bundleInfos_.empty()) {
        LOG_W(BMS_TAG_QUERY_BUNDLE, "bundleInfos_ data is empty");
        return false;
    }

    bool find = false;
    for (const auto &item : bundleInfos_) {
        const InnerBundleInfo &innerBundleInfo = item.second;
        if (innerBundleInfo.GetApplicationBundleType() == BundleType::SHARED) {
            LOG_D(BMS_TAG_QUERY_BUNDLE, "app %{public}s is cross-app shared bundle, ignore",
                innerBundleInfo.GetBundleName().c_str());
            continue;
        }

        int32_t responseUserId = innerBundleInfo.GetResponseUserId(requestUserId);
        if (CheckInnerBundleInfoWithFlags(innerBundleInfo, flags, responseUserId) != ERR_OK) {
            continue;
        }

        BundleInfo bundleInfo;
        if (!innerBundleInfo.GetBundleInfo(flags, bundleInfo, responseUserId)) {
            continue;
        }

        bundleInfos.emplace_back(bundleInfo);
        find = true;
        // add clone bundle info
        GetCloneBundleInfos(innerBundleInfo, responseUserId, bundleInfo, bundleInfos);
    }

    LOG_D(BMS_TAG_QUERY_BUNDLE, "get bundleInfos result(%{public}d) in user(%{public}d).", find, userId);
    return find;
}

ErrCode BundleDataMgr::CheckInnerBundleInfoWithFlags(
    const InnerBundleInfo &innerBundleInfo, const int32_t flags, int32_t userId) const
{
    if (userId == Constants::INVALID_USERID) {
        APP_LOGD("userId is invalid");
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }

    if (innerBundleInfo.IsDisabled()) {
        APP_LOGW("bundleName: %{public}s status is disabled", innerBundleInfo.GetBundleName().c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    if (!(static_cast<uint32_t>(flags) & GET_APPLICATION_INFO_WITH_DISABLE)
        && !innerBundleInfo.GetApplicationEnabled(userId)) {
        APP_LOGW("bundleName: %{public}s userId: %{public}d incorrect",
            innerBundleInfo.GetBundleName().c_str(), userId);
        return ERR_BUNDLE_MANAGER_APPLICATION_DISABLED;
    }

    return ERR_OK;
}

bool BundleDataMgr::GetAllBundleInfos(int32_t flags, std::vector<BundleInfo> &bundleInfos) const
{
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    if (bundleInfos_.empty()) {
        APP_LOGW("bundleInfos_ data is empty");
        return false;
    }

    bool find = false;
    for (const auto &item : bundleInfos_) {
        const InnerBundleInfo &info = item.second;
        if (info.IsDisabled()) {
            APP_LOGD("app %{public}s is disabled", info.GetBundleName().c_str());
            continue;
        }
        if (info.GetApplicationBundleType() == BundleType::SHARED) {
            APP_LOGD("app %{public}s is cross-app shared bundle, ignore", info.GetBundleName().c_str());
            continue;
        }
        BundleInfo bundleInfo;
        info.GetBundleInfo(flags, bundleInfo, Constants::ALL_USERID);
        bundleInfos.emplace_back(bundleInfo);
        find = true;
        // add clone bundle info
        GetCloneBundleInfos(info, Constants::ALL_USERID, bundleInfo, bundleInfos);
    }

    APP_LOGD("get all bundleInfos result(%{public}d).", find);
    return find;
}

ErrCode BundleDataMgr::GetBundleInfosV9(int32_t flags, std::vector<BundleInfo> &bundleInfos, int32_t userId) const
{
    if (userId == Constants::ALL_USERID) {
        return GetAllBundleInfosV9(flags, bundleInfos);
    }

    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }

    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    if (bundleInfos_.empty()) {
        LOG_W(BMS_TAG_QUERY_BUNDLE, "bundleInfos_ data is empty");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }

    for (const auto &item : bundleInfos_) {
        const InnerBundleInfo &innerBundleInfo = item.second;
        if (innerBundleInfo.GetApplicationBundleType() == BundleType::SHARED) {
            LOG_D(BMS_TAG_QUERY_BUNDLE, "app %{public}s is cross-app shared bundle, ignore",
                innerBundleInfo.GetBundleName().c_str());
            continue;
        }

        int32_t responseUserId = innerBundleInfo.GetResponseUserId(requestUserId);
        auto flag = GET_BASIC_APPLICATION_INFO;
        if ((static_cast<uint32_t>(flags) & static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE))
            == static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE)) {
            flag = GET_APPLICATION_INFO_WITH_DISABLE;
        }
        if (CheckInnerBundleInfoWithFlags(innerBundleInfo, flag, responseUserId) != ERR_OK) {
            continue;
        }

        BundleInfo bundleInfo;
        if (innerBundleInfo.GetBundleInfoV9(flags, bundleInfo, responseUserId) != ERR_OK) {
            continue;
        }
        ProcessBundleMenu(bundleInfo, flags, true);
        ProcessBundleRouterMap(bundleInfo, flags);
        bundleInfos.emplace_back(bundleInfo);
        // add clone bundle info
        GetCloneBundleInfos(innerBundleInfo, responseUserId, bundleInfo, bundleInfos);
    }
    if (bundleInfos.empty()) {
        LOG_W(BMS_TAG_QUERY_BUNDLE, "bundleInfos is empty");
    }
    return ERR_OK;
}

ErrCode BundleDataMgr::GetAllBundleInfosV9(int32_t flags, std::vector<BundleInfo> &bundleInfos) const
{
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    if (bundleInfos_.empty()) {
        APP_LOGW("bundleInfos_ data is empty");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }

    for (const auto &item : bundleInfos_) {
        const InnerBundleInfo &info = item.second;
        if (info.IsDisabled()) {
            APP_LOGD("app %{public}s is disabled", info.GetBundleName().c_str());
            continue;
        }
        if (info.GetApplicationBundleType() == BundleType::SHARED) {
            APP_LOGD("app %{public}s is cross-app shared bundle, ignore", info.GetBundleName().c_str());
            continue;
        }
        BundleInfo bundleInfo;
        info.GetBundleInfoV9(flags, bundleInfo, Constants::ALL_USERID);
        auto ret = ProcessBundleMenu(bundleInfo, flags, true);
        if (ret == ERR_OK) {
            bundleInfos.emplace_back(bundleInfo);
            // add clone bundle info
            GetCloneBundleInfos(info, Constants::ALL_USERID, bundleInfo, bundleInfos);
        }
    }
    if (bundleInfos.empty()) {
        APP_LOGW("bundleInfos is empty");
    }
    return ERR_OK;
}

bool BundleDataMgr::GetBundleNameForUid(const int32_t uid, std::string &bundleName) const
{
    int32_t appIndex = 0;
    return GetBundleNameAndIndexForUid(uid, bundleName, appIndex) == ERR_OK;
}

ErrCode BundleDataMgr::GetBundleNameAndIndexForUid(const int32_t uid, std::string &bundleName,
    int32_t &appIndex) const
{
    InnerBundleInfo innerBundleInfo;
    if (GetInnerBundleInfoAndIndexByUid(uid, innerBundleInfo, appIndex) != ERR_OK) {
        if (sandboxAppHelper_ == nullptr) {
            return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
        }
        if (sandboxAppHelper_->GetInnerBundleInfoByUid(uid, innerBundleInfo) != ERR_OK) {
            return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
        }
    }

    bundleName = innerBundleInfo.GetBundleName();
    APP_LOGD("GetBundleNameForUid, uid %{public}d, bundleName %{public}s", uid, bundleName.c_str());
    return ERR_OK;
}

ErrCode BundleDataMgr::GetInnerBundleInfoAndIndexByUid(const int32_t uid, InnerBundleInfo &innerBundleInfo,
    int32_t &appIndex) const
{
    if (uid < Constants::BASE_APP_UID) {
        APP_LOGD("the uid(%{public}d) is not an application.", uid);
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    int32_t userId = GetUserIdByUid(uid);
    int32_t bundleId = uid - userId * Constants::BASE_USER_RANGE;

    std::string keyName;
    {
        std::lock_guard<std::mutex> bundleIdLock(bundleIdMapMutex_);
        auto bundleIdIter = bundleIdMap_.find(bundleId);
        if (bundleIdIter == bundleIdMap_.end()) {
            APP_LOGW("uid %{public}d is not existed.", uid);
            return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
        }
        keyName = bundleIdIter->second;
    }
    std::string bundleName = keyName;
    GetBundleNameAndIndexByName(keyName, bundleName, appIndex);

    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto bundleInfoIter = bundleInfos_.find(bundleName);
    if (bundleInfoIter == bundleInfos_.end()) {
        APP_LOGE("bundleName %{public}s is not existed in bundleInfos_.", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    if (bundleInfoIter->second.IsDisabled()) {
        APP_LOGD("app %{public}s is disabled", bundleInfoIter->second.GetBundleName().c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    if (bundleInfoIter->second.GetUid(userId, appIndex) == uid) {
        innerBundleInfo = bundleInfoIter->second;
        return ERR_OK;
    }

    APP_LOGW("the uid(%{public}d) is not exists.", uid);
    return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
}

ErrCode BundleDataMgr::GetInnerBundleInfoByUid(const int32_t uid, InnerBundleInfo &innerBundleInfo) const
{
    int32_t appIndex = 0;
    return GetInnerBundleInfoAndIndexByUid(uid, innerBundleInfo, appIndex);
}

const std::vector<PreInstallBundleInfo> BundleDataMgr::GetRecoverablePreInstallBundleInfos()
{
    std::vector<PreInstallBundleInfo> recoverablePreInstallBundleInfos;
    int32_t userId = AccountHelper::GetCurrentActiveUserId();
    if (userId == Constants::INVALID_USERID) {
        APP_LOGW("userId %{public}d is invalid", userId);
        return recoverablePreInstallBundleInfos;
    }
    std::vector<PreInstallBundleInfo> preInstallBundleInfos = GetAllPreInstallBundleInfos();
    for (auto preInstallBundleInfo: preInstallBundleInfos) {
        if (!preInstallBundleInfo.GetRemovable()) {
            continue;
        }
        std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
        auto infoItem = bundleInfos_.find(preInstallBundleInfo.GetBundleName());
        if (infoItem == bundleInfos_.end()) {
            recoverablePreInstallBundleInfos.emplace_back(preInstallBundleInfo);
            continue;
        }
        if (!infoItem->second.HasInnerBundleUserInfo(Constants::DEFAULT_USERID) &&
            !infoItem->second.HasInnerBundleUserInfo(userId)) {
            recoverablePreInstallBundleInfos.emplace_back(preInstallBundleInfo);
        }
    }
    return recoverablePreInstallBundleInfos;
}

bool BundleDataMgr::IsBundleExist(const std::string &bundleName) const
{
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    return bundleInfos_.find(bundleName) != bundleInfos_.end();
}

bool BundleDataMgr::HasUserInstallInBundle(
    const std::string &bundleName, const int32_t userId) const
{
    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        return false;
    }

    return infoItem->second.HasInnerBundleUserInfo(userId);
}

bool BundleDataMgr::GetBundleStats(
    const std::string &bundleName, const int32_t userId, std::vector<int64_t> &bundleStats) const
{
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        return false;
    }
    int32_t responseUserId = infoItem->second.GetResponseUserId(userId);
    int32_t uid = infoItem->second.GetUid(responseUserId);
    if (InstalldClient::GetInstance()->GetBundleStats(bundleName, responseUserId, bundleStats, uid) != ERR_OK) {
        APP_LOGW("bundle%{public}s GetBundleStats failed ", bundleName.c_str());
        return false;
    }
    if (infoItem->second.GetIsPreInstallApp() && !bundleStats.empty()) {
        for (const auto &innerModuleInfo : infoItem->second.GetInnerModuleInfos()) {
            bundleStats[0] += BundleUtil::GetFileSize(innerModuleInfo.second.hapPath);
        }
    }
    return true;
}

bool BundleDataMgr::GetAllBundleStats(const int32_t userId, std::vector<int64_t> &bundleStats) const
{
    std::vector<std::string> bundleNames;
    std::vector<int32_t> uids;
    int32_t responseUserId = userId;
    GetBundleList(bundleNames, userId);
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    for (const auto &bundleName : bundleNames) {
        auto infoItem = bundleInfos_.find(bundleName);
        if (infoItem == bundleInfos_.end()) {
            return false;
        }
        responseUserId = infoItem->second.GetResponseUserId(userId);
        int32_t uid = infoItem->second.GetUid(responseUserId);
        uids.emplace_back(uid);
    }
    if (InstalldClient::GetInstance()->GetAllBundleStats(bundleNames, responseUserId, bundleStats, uids) != ERR_OK) {
        APP_LOGW("GetAllBundleStats failed, userId: %{public}d", responseUserId);
        return false;
    }
    if (bundleStats.empty()) {
        return true;
    }
    for (const auto &bundleName : bundleNames) {
        auto infoItem = bundleInfos_.find(bundleName);
        if (infoItem == bundleInfos_.end()) {
            return false;
        }
        if (infoItem->second.GetIsPreInstallApp()) {
            for (const auto &innerModuleInfo : infoItem->second.GetInnerModuleInfos()) {
                bundleStats[0] += BundleUtil::GetFileSize(innerModuleInfo.second.hapPath);
            }
        }
    }
    return true;
}

#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
int64_t BundleDataMgr::GetBundleSpaceSize(const std::string &bundleName) const
{
    return GetBundleSpaceSize(bundleName, AccountHelper::GetCurrentActiveUserId());
}

int64_t BundleDataMgr::GetBundleSpaceSize(const std::string &bundleName, int32_t userId) const
{
    int64_t spaceSize = 0;
    if (userId != Constants::ALL_USERID) {
        std::vector<int64_t> bundleStats;
        if (!GetBundleStats(bundleName, userId, bundleStats) || bundleStats.empty()) {
            APP_LOGW("GetBundleStats: bundleName: %{public}s failed", bundleName.c_str());
            return spaceSize;
        }

        spaceSize = std::accumulate(bundleStats.begin(), bundleStats.end(), spaceSize);
        return spaceSize;
    }

    for (const auto &iterUserId : GetAllUser()) {
        std::vector<int64_t> bundleStats;
        if (!GetBundleStats(bundleName, iterUserId, bundleStats) || bundleStats.empty()) {
            APP_LOGW("GetBundleStats: bundleName: %{public}s failed", bundleName.c_str());
            continue;
        }

        auto startIter = bundleStats.begin();
        auto endIter = bundleStats.end();
        if (spaceSize == 0) {
            spaceSize = std::accumulate(startIter, endIter, spaceSize);
        } else {
            spaceSize = std::accumulate(++startIter, endIter, spaceSize);
        }
    }

    return spaceSize;
}

int64_t BundleDataMgr::GetAllFreeInstallBundleSpaceSize() const
{
    int64_t allSize = 0;
    std::map<std::string, std::vector<std::string>> freeInstallModules;
    if (!GetFreeInstallModules(freeInstallModules)) {
        APP_LOGW("no removable bundles");
        return allSize;
    }

    for (const auto &iter : freeInstallModules) {
        APP_LOGD("%{public}s is freeInstall bundle", iter.first.c_str());
        allSize += GetBundleSpaceSize(iter.first, Constants::ALL_USERID);
    }

    APP_LOGI("All freeInstall app size:%{public}" PRId64, allSize);
    return allSize;
}

bool BundleDataMgr::GetFreeInstallModules(
    std::map<std::string, std::vector<std::string>> &freeInstallModules) const
{
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    if (bundleInfos_.empty()) {
        APP_LOGW("bundleInfos_ is data is empty.");
        return false;
    }

    for (const auto &iter : bundleInfos_) {
        std::vector<std::string> modules;
        if (!iter.second.GetFreeInstallModules(modules)) {
            continue;
        }

        freeInstallModules.emplace(iter.first, modules);
    }

    return !freeInstallModules.empty();
}
#endif

bool BundleDataMgr::GetBundlesForUid(const int uid, std::vector<std::string> &bundleNames) const
{
    InnerBundleInfo innerBundleInfo;
    if (GetInnerBundleInfoByUid(uid, innerBundleInfo) != ERR_OK) {
        APP_LOGD("get innerBundleInfo by uid :%{public}d failed.", uid);
        return false;
    }

    bundleNames.emplace_back(innerBundleInfo.GetBundleName());
    return true;
}

ErrCode BundleDataMgr::GetNameForUid(const int uid, std::string &name) const
{
    InnerBundleInfo innerBundleInfo;
    ErrCode ret = GetInnerBundleInfoByUid(uid, innerBundleInfo);
    if (ret != ERR_OK) {
        APP_LOGD("get innerBundleInfo from bundleInfo_ by uid failed.");
        if (sandboxAppHelper_ == nullptr) {
            APP_LOGW("sandboxAppHelper_ is nullptr");
            return ERR_BUNDLE_MANAGER_INVALID_UID;
        }
        if (sandboxAppHelper_->GetInnerBundleInfoByUid(uid, innerBundleInfo) != ERR_OK) {
            return ERR_BUNDLE_MANAGER_INVALID_UID;
        }
    }

    name = innerBundleInfo.GetBundleName();
    return ERR_OK;
}

bool BundleDataMgr::GetBundleGids(const std::string &bundleName, std::vector<int> &gids) const
{
    int32_t requestUserId = GetUserId();
    InnerBundleUserInfo innerBundleUserInfo;
    if (!GetInnerBundleUserInfoByUserId(bundleName, requestUserId, innerBundleUserInfo)) {
        APP_LOGW("the user(%{public}d) is not exists in bundleName(%{public}s) .",
            requestUserId, bundleName.c_str());
        return false;
    }

    gids = innerBundleUserInfo.gids;
    return true;
}

bool BundleDataMgr::GetBundleGidsByUid(
    const std::string &bundleName, const int &uid, std::vector<int> &gids) const
{
    return true;
}

bool BundleDataMgr::QueryKeepAliveBundleInfos(std::vector<BundleInfo> &bundleInfos) const
{
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    if (bundleInfos_.empty()) {
        APP_LOGW("bundleInfos_ data is empty");
        return false;
    }

    int32_t requestUserId = GetUserId();
    for (const auto &info : bundleInfos_) {
        if (info.second.IsDisabled()) {
            APP_LOGD("app %{public}s is disabled", info.second.GetBundleName().c_str());
            continue;
        }
        if (info.second.GetIsKeepAlive()) {
            BundleInfo bundleInfo;
            int32_t responseUserId = info.second.GetResponseUserId(requestUserId);
            info.second.GetBundleInfo(BundleFlag::GET_BUNDLE_WITH_ABILITIES, bundleInfo, responseUserId);
            if (bundleInfo.name == "") {
                continue;
            }
            bundleInfos.emplace_back(bundleInfo);
        }
    }
    return !(bundleInfos.empty());
}

ErrCode BundleDataMgr::GetAbilityLabel(const std::string &bundleName, const std::string &moduleName,
    const std::string &abilityName, std::string &label) const
{
#ifdef GLOBAL_RESMGR_ENABLE
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    int32_t requestUserId = GetUserId();
    if (requestUserId == Constants::INVALID_USERID) {
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }
    InnerBundleInfo innerBundleInfo;
    ErrCode ret =
        GetInnerBundleInfoWithFlagsV9(bundleName, BundleFlag::GET_BUNDLE_DEFAULT, innerBundleInfo, requestUserId);
    if (ret != ERR_OK) {
        return ret;
    }
    AbilityInfo abilityInfo;
    ret = FindAbilityInfoInBundleInfo(innerBundleInfo, moduleName, abilityName, abilityInfo);
    if (ret != ERR_OK) {
        APP_LOGD("Find ability failed. bundleName: %{public}s, moduleName: %{public}s, abilityName: %{public}s",
            bundleName.c_str(), moduleName.c_str(), abilityName.c_str());
        return ret;
    }
    int32_t responseUserId = innerBundleInfo.GetResponseUserId(requestUserId);
    bool isEnable = false;
    ret = innerBundleInfo.IsAbilityEnabledV9(abilityInfo, responseUserId, isEnable);
    if (ret != ERR_OK) {
        return ret;
    }
    if (!isEnable) {
        APP_LOGW("%{public}s ability disabled: %{public}s", bundleName.c_str(), abilityName.c_str());
        return ERR_BUNDLE_MANAGER_ABILITY_DISABLED;
    }
    if (abilityInfo.labelId == 0) {
        label = abilityInfo.label;
        return ERR_OK;
    }
    std::shared_ptr<OHOS::Global::Resource::ResourceManager> resourceManager =
        GetResourceManager(bundleName, abilityInfo.moduleName, responseUserId);
    if (resourceManager == nullptr) {
        APP_LOGW("InitResourceManager failed");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    auto state = resourceManager->GetStringById(static_cast<uint32_t>(abilityInfo.labelId), label);
    if (state != OHOS::Global::Resource::RState::SUCCESS) {
        APP_LOGW("ResourceManager GetStringById failed");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return ERR_OK;
#else
    APP_LOGW("GLOBAL_RES_MGR_ENABLE is false");
    return ERR_BUNDLE_MANAGER_GLOBAL_RES_MGR_ENABLE_DISABLED;
#endif
}

bool BundleDataMgr::GetHapModuleInfo(
    const AbilityInfo &abilityInfo, HapModuleInfo &hapModuleInfo, int32_t userId) const
{
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return false;
    }

    if (bundleInfos_.empty()) {
        APP_LOGW("bundleInfos_ data is empty");
        return false;
    }

    APP_LOGD("GetHapModuleInfo bundleName: %{public}s", abilityInfo.bundleName.c_str());
    auto infoItem = bundleInfos_.find(abilityInfo.bundleName);
    if (infoItem == bundleInfos_.end()) {
        return false;
    }

    const InnerBundleInfo &innerBundleInfo = infoItem->second;
    if (innerBundleInfo.IsDisabled()) {
        APP_LOGW("app %{public}s is disabled", innerBundleInfo.GetBundleName().c_str());
        return false;
    }

    int32_t responseUserId = innerBundleInfo.GetResponseUserId(requestUserId);
    auto module = innerBundleInfo.FindHapModuleInfo(abilityInfo.package, responseUserId);
    if (!module) {
        APP_LOGW("can not find module %{public}s, bundleName:%{public}s", abilityInfo.package.c_str(),
            abilityInfo.bundleName.c_str());
        return false;
    }
    hapModuleInfo = *module;
    return true;
}

ErrCode BundleDataMgr::GetLaunchWantForBundle(
    const std::string &bundleName, Want &want, int32_t userId) const
{
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    InnerBundleInfo innerBundleInfo;
    ErrCode ret = GetInnerBundleInfoWithFlagsV9(
        bundleName, BundleFlag::GET_BUNDLE_DEFAULT, innerBundleInfo, userId);
    if (ret != ERR_OK) {
        APP_LOGD("GetInnerBundleInfoWithFlagsV9 failed, bundleName:%{public}s", bundleName.c_str());
        return ret;
    }

    std::string mainAbility = innerBundleInfo.GetMainAbility();
    if (mainAbility.empty()) {
        APP_LOGW("no main ability in the bundle %{public}s", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }

    want.SetElementName("", bundleName, mainAbility);
    want.SetAction(Constants::ACTION_HOME);
    want.AddEntity(Constants::ENTITY_HOME);
    return ERR_OK;
}

bool BundleDataMgr::CheckIsSystemAppByUid(const int uid) const
{
    // If the value of uid is 0 (ROOT_UID) or 1000 (BMS_UID),
    // the uid should be the system uid.
    if (uid == Constants::ROOT_UID || uid == Constants::BMS_UID) {
        return true;
    }

    InnerBundleInfo innerBundleInfo;
    if (GetInnerBundleInfoByUid(uid, innerBundleInfo) != ERR_OK) {
        return false;
    }

    return innerBundleInfo.IsSystemApp();
}

void BundleDataMgr::InitStateTransferMap()
{
    transferStates_.emplace(InstallState::INSTALL_SUCCESS, InstallState::INSTALL_START);
    transferStates_.emplace(InstallState::INSTALL_FAIL, InstallState::INSTALL_START);
    transferStates_.emplace(InstallState::UNINSTALL_START, InstallState::INSTALL_SUCCESS);
    transferStates_.emplace(InstallState::UNINSTALL_START, InstallState::INSTALL_START);
    transferStates_.emplace(InstallState::UNINSTALL_START, InstallState::UPDATING_SUCCESS);
    transferStates_.emplace(InstallState::UNINSTALL_FAIL, InstallState::UNINSTALL_START);
    transferStates_.emplace(InstallState::UNINSTALL_START, InstallState::UNINSTALL_START);
    transferStates_.emplace(InstallState::UNINSTALL_SUCCESS, InstallState::UNINSTALL_START);
    transferStates_.emplace(InstallState::UPDATING_START, InstallState::INSTALL_SUCCESS);
    transferStates_.emplace(InstallState::UPDATING_SUCCESS, InstallState::UPDATING_START);
    transferStates_.emplace(InstallState::UPDATING_FAIL, InstallState::UPDATING_START);
    transferStates_.emplace(InstallState::UPDATING_FAIL, InstallState::INSTALL_START);
    transferStates_.emplace(InstallState::UPDATING_START, InstallState::INSTALL_START);
    transferStates_.emplace(InstallState::INSTALL_SUCCESS, InstallState::UPDATING_START);
    transferStates_.emplace(InstallState::INSTALL_SUCCESS, InstallState::UPDATING_SUCCESS);
    transferStates_.emplace(InstallState::INSTALL_SUCCESS, InstallState::UNINSTALL_START);
    transferStates_.emplace(InstallState::UPDATING_START, InstallState::UPDATING_SUCCESS);
    transferStates_.emplace(InstallState::ROLL_BACK, InstallState::UPDATING_START);
    transferStates_.emplace(InstallState::ROLL_BACK, InstallState::UPDATING_SUCCESS);
    transferStates_.emplace(InstallState::UPDATING_FAIL, InstallState::UPDATING_SUCCESS);
    transferStates_.emplace(InstallState::INSTALL_SUCCESS, InstallState::ROLL_BACK);
    transferStates_.emplace(InstallState::UNINSTALL_START, InstallState::USER_CHANGE);
    transferStates_.emplace(InstallState::UPDATING_START, InstallState::USER_CHANGE);
    transferStates_.emplace(InstallState::INSTALL_SUCCESS, InstallState::USER_CHANGE);
    transferStates_.emplace(InstallState::UPDATING_SUCCESS, InstallState::USER_CHANGE);
    transferStates_.emplace(InstallState::USER_CHANGE, InstallState::INSTALL_SUCCESS);
    transferStates_.emplace(InstallState::USER_CHANGE, InstallState::UPDATING_SUCCESS);
    transferStates_.emplace(InstallState::USER_CHANGE, InstallState::UPDATING_START);
}

bool BundleDataMgr::IsDeleteDataState(const InstallState state) const
{
    return (state == InstallState::INSTALL_FAIL || state == InstallState::UNINSTALL_FAIL ||
            state == InstallState::UNINSTALL_SUCCESS || state == InstallState::UPDATING_FAIL);
}

bool BundleDataMgr::IsDisableState(const InstallState state) const
{
    if (state == InstallState::UPDATING_START || state == InstallState::UNINSTALL_START) {
        return true;
    }
    return false;
}

void BundleDataMgr::DeleteBundleInfo(const std::string &bundleName, const InstallState state)
{
    if (InstallState::INSTALL_FAIL == state) {
        APP_LOGW("del fail, bundle:%{public}s has no installed info", bundleName.c_str());
        return;
    }

    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("create infoItem fail, bundleName:%{public}s", bundleName.c_str());
        return;
    }
#ifdef BUNDLE_FRAMEWORK_OVERLAY_INSTALLATION
    // remove external overlay bundle info and connection
    RemoveOverlayInfoAndConnection(infoItem->second, bundleName);
#endif
    APP_LOGD("del bundle name:%{public}s", bundleName.c_str());
    const InnerBundleInfo &innerBundleInfo = infoItem->second;
    RecycleUidAndGid(innerBundleInfo);
    bool ret = dataStorage_->DeleteStorageBundleInfo(innerBundleInfo);
    if (!ret) {
        APP_LOGW("delete storage error name:%{public}s", bundleName.c_str());
    }
    bundleInfos_.erase(bundleName);
    std::lock_guard<std::mutex> hspLock(hspBundleNameMutex_);
    if (appServiceHspBundleName_.find(bundleName) != appServiceHspBundleName_.end()) {
        appServiceHspBundleName_.erase(bundleName);
    }
}

bool BundleDataMgr::IsAppOrAbilityInstalled(const std::string &bundleName) const
{
    if (bundleName.empty()) {
        APP_LOGW("IsAppOrAbilityInstalled bundleName empty");
        return false;
    }

    std::lock_guard<std::mutex> lock(stateMutex_);
    auto statusItem = installStates_.find(bundleName);
    if (statusItem == installStates_.end()) {
        APP_LOGW("name:%{public}s not find", bundleName.c_str());
        return false;
    }

    if (statusItem->second == InstallState::INSTALL_SUCCESS) {
        return true;
    }

    APP_LOGW("name:%{public}s not install success", bundleName.c_str());
    return false;
}

bool BundleDataMgr::GetInnerBundleInfoWithFlags(const std::string &bundleName,
    const int32_t flags, InnerBundleInfo &info, int32_t userId) const
{
    if (bundleName.empty()) {
        return false;
    }
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return false;
    }

    if (bundleInfos_.empty()) {
        APP_LOGW("bundleInfos_ data is empty");
        return false;
    }
    APP_LOGD("GetInnerBundleInfoWithFlags: %{public}s", bundleName.c_str());
    auto item = bundleInfos_.find(bundleName);
    if (item == bundleInfos_.end()) {
        APP_LOGW("bundleName %{public}s not find", bundleName.c_str());
        return false;
    }
    const InnerBundleInfo &innerBundleInfo = item->second;
    if (innerBundleInfo.IsDisabled()) {
        APP_LOGD("bundleName: %{public}s status is disabled", innerBundleInfo.GetBundleName().c_str());
        return false;
    }

    int32_t responseUserId = innerBundleInfo.GetResponseUserId(requestUserId);
    if (!(static_cast<uint32_t>(flags) & GET_APPLICATION_INFO_WITH_DISABLE)
        && !innerBundleInfo.GetApplicationEnabled(responseUserId)) {
        APP_LOGW("bundleName: %{public}s userId: %{public}d incorrect",
            innerBundleInfo.GetBundleName().c_str(), requestUserId);
        return false;
    }
    info = innerBundleInfo;
    return true;
}

bool BundleDataMgr::GetInnerBundleInfoWithBundleFlagsAndLock(const std::string &bundleName,
    const int32_t flags, InnerBundleInfo &info, int32_t userId) const
{
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    bool res = GetInnerBundleInfoWithFlags(bundleName, flags, info, userId);
    if (!res) {
        APP_LOGD("GetInnerBundleInfoWithBundleFlagsAndLock: bundleName %{public}s not find", bundleName.c_str());
        return res;
    }
    return true;
}

ErrCode BundleDataMgr::GetInnerBundleInfoWithFlagsV9(const std::string &bundleName,
    const int32_t flags, InnerBundleInfo &info, int32_t userId) const
{
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }

    if (bundleInfos_.empty()) {
        APP_LOGD("bundleInfos_ data is empty");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    APP_LOGD("GetInnerBundleInfoWithFlagsV9: %{public}s", bundleName.c_str());
    auto item = bundleInfos_.find(bundleName);
    if (item == bundleInfos_.end()) {
        APP_LOGD("GetInnerBundleInfoWithFlagsV9: bundleName %{public}s not find", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    const InnerBundleInfo &innerBundleInfo = item->second;
    if (innerBundleInfo.IsDisabled()) {
        APP_LOGD("bundleName: %{public}s status is disabled", innerBundleInfo.GetBundleName().c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    int32_t responseUserId = innerBundleInfo.GetResponseUserId(requestUserId);
    bool isEnabled = false;
    auto ret = innerBundleInfo.GetApplicationEnabledV9(responseUserId, isEnabled);
    if (ret != ERR_OK) {
        return ret;
    }
    if (!(static_cast<uint32_t>(flags) & static_cast<uint32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_DISABLE))
        && !isEnabled) {
        APP_LOGD("bundleName: %{public}s is disabled", innerBundleInfo.GetBundleName().c_str());
        return ERR_BUNDLE_MANAGER_APPLICATION_DISABLED;
    }
    info = innerBundleInfo;
    return ERR_OK;
}

ErrCode BundleDataMgr::GetInnerBundleInfoWithBundleFlagsV9(const std::string &bundleName,
    const int32_t flags, InnerBundleInfo &info, int32_t userId, int32_t appIndex) const
{
    if (bundleName.empty()) {
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }

    if (bundleInfos_.empty()) {
        APP_LOGW("bundleInfos_ data is empty, bundleName: %{public}s", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    APP_LOGD("GetInnerBundleInfoWithFlagsV9: %{public}s", bundleName.c_str());
    auto item = bundleInfos_.find(bundleName);
    if (item == bundleInfos_.end()) {
        APP_LOGW("GetInnerBundleInfoWithFlagsV9: bundleName %{public}s not find", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    const InnerBundleInfo &innerBundleInfo = item->second;
    if (innerBundleInfo.IsDisabled()) {
        APP_LOGW("bundleName: %{public}s status is disabled", innerBundleInfo.GetBundleName().c_str());
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }

    int32_t responseUserId = innerBundleInfo.GetResponseUserId(requestUserId);
    bool isEnabled = false;
    auto ret = innerBundleInfo.GetApplicationEnabledV9(responseUserId, isEnabled, appIndex);
    if (ret != ERR_OK) {
        return ret;
    }
    if (!(static_cast<uint32_t>(flags) & static_cast<uint32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE))
        && !isEnabled) {
        APP_LOGW("bundleName: %{public}s is disabled", innerBundleInfo.GetBundleName().c_str());
        return ERR_BUNDLE_MANAGER_APPLICATION_DISABLED;
    }
    info = innerBundleInfo;
    return ERR_OK;
}

bool BundleDataMgr::GetInnerBundleInfo(const std::string &bundleName, InnerBundleInfo &info)
{
    APP_LOGD("GetInnerBundleInfo %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        APP_LOGW("bundleName is empty");
        return false;
    }

    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("can not find bundle %{public}s", bundleName.c_str());
        return false;
    }
    infoItem->second.SetBundleStatus(InnerBundleInfo::BundleStatus::DISABLED);
    info = infoItem->second;
    info.SetBundleStatus(InnerBundleInfo::BundleStatus::ENABLED);
    return true;
}

bool BundleDataMgr::DisableBundle(const std::string &bundleName)
{
    APP_LOGD("DisableBundle %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        APP_LOGW("bundleName empty");
        return false;
    }

    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("can not find bundle %{public}s", bundleName.c_str());
        return false;
    }
    infoItem->second.SetBundleStatus(InnerBundleInfo::BundleStatus::DISABLED);
    return true;
}

bool BundleDataMgr::EnableBundle(const std::string &bundleName)
{
    APP_LOGD("EnableBundle %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        APP_LOGW("bundleName empty");
        return false;
    }

    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("can not find bundle %{public}s", bundleName.c_str());
        return false;
    }
    infoItem->second.SetBundleStatus(InnerBundleInfo::BundleStatus::ENABLED);
    return true;
}

ErrCode BundleDataMgr::IsApplicationEnabled(const std::string &bundleName, bool &isEnabled) const
{
    APP_LOGD("IsApplicationEnabled %{public}s", bundleName.c_str());
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("can not find bundle %{public}s", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    int32_t responseUserId = infoItem->second.GetResponseUserId(GetUserId());
    ErrCode ret = infoItem->second.GetApplicationEnabledV9(responseUserId, isEnabled);
    if (ret != ERR_OK) {
        APP_LOGW("GetApplicationEnabled failed: %{public}s", bundleName.c_str());
    }
    return ret;
}

ErrCode BundleDataMgr::SetApplicationEnabled(const std::string &bundleName, bool isEnable, int32_t userId)
{
    APP_LOGD("SetApplicationEnabled %{public}s", bundleName.c_str());
    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        APP_LOGW("Request userId is invalid, bundleName:%{public}s", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("can not find bundle %{public}s", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    InnerBundleInfo& newInfo = infoItem->second;
    auto ret = newInfo.SetApplicationEnabled(isEnable, requestUserId);
    if (ret != ERR_OK) {
        return ret;
    }
    InnerBundleUserInfo innerBundleUserInfo;
    if (!newInfo.GetInnerBundleUserInfo(requestUserId, innerBundleUserInfo)) {
        APP_LOGW("can not find bundleUserInfo in userId: %{public}d", requestUserId);
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    if (innerBundleUserInfo.bundleUserInfo.IsInitialState()) {
        bundleStateStorage_->DeleteBundleState(bundleName, requestUserId);
    } else {
        bundleStateStorage_->SaveBundleStateStorage(
            bundleName, requestUserId, innerBundleUserInfo.bundleUserInfo);
    }
    return ERR_OK;
}

bool BundleDataMgr::SetModuleRemovable(const std::string &bundleName, const std::string &moduleName, bool isEnable)
{
    if (bundleName.empty() || moduleName.empty()) {
        APP_LOGW("bundleName or moduleName is empty");
        return false;
    }
    int32_t userId = AccountHelper::GetCurrentActiveUserId();
    if (userId == Constants::INVALID_USERID) {
        APP_LOGW("get a invalid userid, bundleName: %{public}s", bundleName.c_str());
        return false;
    }
    APP_LOGD("bundleName:%{public}s, moduleName:%{public}s, userId:%{public}d",
        bundleName.c_str(), moduleName.c_str(), userId);
    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("can not find bundle %{public}s", bundleName.c_str());
        return false;
    }
    InnerBundleInfo newInfo = infoItem->second;
    bool ret = newInfo.SetModuleRemovable(moduleName, isEnable, userId);
    if (ret && dataStorage_->SaveStorageBundleInfo(newInfo)) {
        ret = infoItem->second.SetModuleRemovable(moduleName, isEnable, userId);
#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
        if (isEnable) {
            // call clean task
            APP_LOGD("bundle:%{public}s isEnable:%{public}d ret:%{public}d call clean task",
                bundleName.c_str(), isEnable, ret);
            DelayedSingleton<BundleMgrService>::GetInstance()->GetAgingMgr()->Start(
                BundleAgingMgr::AgingTriggertype::UPDATE_REMOVABLE_FLAG);
        }
#endif
        return ret;
    } else {
        APP_LOGW("bundle:%{public}s SetModuleRemoved failed", bundleName.c_str());
        return false;
    }
}

ErrCode BundleDataMgr::IsModuleRemovable(const std::string &bundleName, const std::string &moduleName,
    bool &isRemovable) const
{
    if (bundleName.empty() || moduleName.empty()) {
        APP_LOGW("bundleName or moduleName is empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    int32_t userId = AccountHelper::GetCurrentActiveUserId();
    if (userId == Constants::INVALID_USERID) {
        APP_LOGW("get a invalid userid, bundleName: %{public}s", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    APP_LOGD("bundleName:%{public}s, moduleName:%{public}s, userId:%{public}d",
        bundleName.c_str(), moduleName.c_str(), userId);
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("can not find bundle %{public}s", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    InnerBundleInfo newInfo = infoItem->second;
    return newInfo.IsModuleRemovable(moduleName, userId, isRemovable);
}

ErrCode BundleDataMgr::IsAbilityEnabled(const AbilityInfo &abilityInfo, bool &isEnable) const
{
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(abilityInfo.bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("can not find bundle %{public}s", abilityInfo.bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    InnerBundleInfo innerBundleInfo = infoItem->second;
    auto ability = innerBundleInfo.FindAbilityInfoV9(
        abilityInfo.moduleName, abilityInfo.name);
    if (!ability) {
        APP_LOGW("ability not found, bundleName:%{public}s, moduleName:%{public}s, abilityName:%{public}s",
            abilityInfo.bundleName.c_str(), abilityInfo.moduleName.c_str(), abilityInfo.name.c_str());
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }
    int32_t responseUserId = innerBundleInfo.GetResponseUserId(GetUserId());
    return innerBundleInfo.IsAbilityEnabledV9((*ability), responseUserId, isEnable);
}

ErrCode BundleDataMgr::SetAbilityEnabled(const AbilityInfo &abilityInfo, bool isEnabled, int32_t userId)
{
    APP_LOGD("SetAbilityEnabled %{public}s", abilityInfo.name.c_str());
    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        APP_LOGW("Request userId is invalid, bundleName:%{public}s, abilityName:%{public}s",
            abilityInfo.bundleName.c_str(), abilityInfo.name.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    auto infoItem = bundleInfos_.find(abilityInfo.bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("can not find bundle %{public}s", abilityInfo.bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    InnerBundleInfo& newInfo = infoItem->second;
    ErrCode ret = newInfo.SetAbilityEnabled(
        abilityInfo.moduleName, abilityInfo.name, isEnabled, userId);
    if (ret != ERR_OK) {
        return ret;
    }
    InnerBundleUserInfo innerBundleUserInfo;
    if (!newInfo.GetInnerBundleUserInfo(requestUserId, innerBundleUserInfo)) {
        APP_LOGW("can not find bundleUserInfo in userId: %{public}d, bundleName:%{public}s, abilityName:%{public}s",
            requestUserId, abilityInfo.bundleName.c_str(), abilityInfo.name.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    if (innerBundleUserInfo.bundleUserInfo.IsInitialState()) {
        bundleStateStorage_->DeleteBundleState(abilityInfo.bundleName, requestUserId);
    } else {
        bundleStateStorage_->SaveBundleStateStorage(
            abilityInfo.bundleName, requestUserId, innerBundleUserInfo.bundleUserInfo);
    }
    return ERR_OK;
}

std::shared_ptr<BundleSandboxAppHelper> BundleDataMgr::GetSandboxAppHelper() const
{
    return sandboxAppHelper_;
}

bool BundleDataMgr::RegisterBundleStatusCallback(const sptr<IBundleStatusCallback> &bundleStatusCallback)
{
    APP_LOGD("RegisterBundleStatusCallback %{public}s", bundleStatusCallback->GetBundleName().c_str());
    std::unique_lock<std::shared_mutex> lock(callbackMutex_);
    callbackList_.emplace_back(bundleStatusCallback);
    if (bundleStatusCallback->AsObject() != nullptr) {
        sptr<BundleStatusCallbackDeathRecipient> deathRecipient =
            new (std::nothrow) BundleStatusCallbackDeathRecipient();
        if (deathRecipient == nullptr) {
            APP_LOGW("deathRecipient is null");
            return false;
        }
        bundleStatusCallback->AsObject()->AddDeathRecipient(deathRecipient);
    }
    return true;
}

bool BundleDataMgr::RegisterBundleEventCallback(const sptr<IBundleEventCallback> &bundleEventCallback)
{
    if (bundleEventCallback == nullptr) {
        APP_LOGW("bundleEventCallback is null");
        return false;
    }
    std::lock_guard lock(eventCallbackMutex_);
    if (eventCallbackList_.size() >= MAX_EVENT_CALL_BACK_SIZE) {
        APP_LOGW("eventCallbackList_ reach max size %{public}d", MAX_EVENT_CALL_BACK_SIZE);
        return false;
    }
    if (bundleEventCallback->AsObject() != nullptr) {
        sptr<BundleEventCallbackDeathRecipient> deathRecipient =
            new (std::nothrow) BundleEventCallbackDeathRecipient();
        if (deathRecipient == nullptr) {
            APP_LOGW("deathRecipient is null");
            return false;
        }
        bundleEventCallback->AsObject()->AddDeathRecipient(deathRecipient);
    }
    eventCallbackList_.emplace_back(bundleEventCallback);
    return true;
}

bool BundleDataMgr::UnregisterBundleEventCallback(const sptr<IBundleEventCallback> &bundleEventCallback)
{
    APP_LOGD("begin to UnregisterBundleEventCallback");
    if (bundleEventCallback == nullptr) {
        APP_LOGW("bundleEventCallback is null");
        return false;
    }
    std::lock_guard lock(eventCallbackMutex_);
    eventCallbackList_.erase(std::remove_if(eventCallbackList_.begin(), eventCallbackList_.end(),
        [&bundleEventCallback](const sptr<IBundleEventCallback> &callback) {
            return callback->AsObject() == bundleEventCallback->AsObject();
        }), eventCallbackList_.end());
    return true;
}

void BundleDataMgr::NotifyBundleEventCallback(const EventFwk::CommonEventData &eventData) const
{
    APP_LOGD("begin to NotifyBundleEventCallback");
    std::lock_guard lock(eventCallbackMutex_);
    for (const auto &callback : eventCallbackList_) {
        callback->OnReceiveEvent(eventData);
    }
    APP_LOGD("finish to NotifyBundleEventCallback");
}

bool BundleDataMgr::ClearBundleStatusCallback(const sptr<IBundleStatusCallback> &bundleStatusCallback)
{
    APP_LOGD("ClearBundleStatusCallback %{public}s", bundleStatusCallback->GetBundleName().c_str());
    std::unique_lock<std::shared_mutex> lock(callbackMutex_);
    callbackList_.erase(std::remove_if(callbackList_.begin(),
        callbackList_.end(),
        [&](const sptr<IBundleStatusCallback> &callback) {
            return callback->AsObject() == bundleStatusCallback->AsObject();
        }),
        callbackList_.end());
    return true;
}

bool BundleDataMgr::UnregisterBundleStatusCallback()
{
    std::unique_lock<std::shared_mutex> lock(callbackMutex_);
    callbackList_.clear();
    return true;
}

bool BundleDataMgr::GenerateUidAndGid(InnerBundleUserInfo &innerBundleUserInfo)
{
    if (innerBundleUserInfo.bundleName.empty()) {
        APP_LOGW("bundleName is null.");
        return false;
    }

    int32_t bundleId = INVALID_BUNDLEID;
    if (!GenerateBundleId(innerBundleUserInfo.bundleName, bundleId)) {
        APP_LOGW("Generate bundleId failed, bundleName: %{public}s", innerBundleUserInfo.bundleName.c_str());
        return false;
    }

    innerBundleUserInfo.uid = innerBundleUserInfo.bundleUserInfo.userId * Constants::BASE_USER_RANGE
        + bundleId % Constants::BASE_USER_RANGE;
    innerBundleUserInfo.gids.emplace_back(innerBundleUserInfo.uid);
    return true;
}

bool BundleDataMgr::GenerateBundleId(const std::string &bundleName, int32_t &bundleId)
{
    std::lock_guard<std::mutex> lock(bundleIdMapMutex_);
    if (bundleIdMap_.empty()) {
        APP_LOGD("first app install");
        bundleId = baseAppUid_;
        bundleIdMap_.emplace(bundleId, bundleName);
        return true;
    }

    for (const auto &innerBundleId : bundleIdMap_) {
        if (innerBundleId.second == bundleName) {
            bundleId = innerBundleId.first;
            return true;
        }
    }

    for (int32_t i = baseAppUid_; i < bundleIdMap_.rbegin()->first; ++i) {
        if (bundleIdMap_.find(i) == bundleIdMap_.end()) {
            APP_LOGD("the %{public}d app install bundleName:%{public}s", i, bundleName.c_str());
            bundleId = i;
            bundleIdMap_.emplace(bundleId, bundleName);
            BundleUtil::MakeFsConfig(bundleName, bundleId, Constants::HMDFS_CONFIG_PATH);
            BundleUtil::MakeFsConfig(bundleName, bundleId, Constants::SHAREFS_CONFIG_PATH);
            return true;
        }
    }

    if (bundleIdMap_.rbegin()->first == MAX_APP_UID) {
        APP_LOGW("the bundleId exceeding the maximum value, bundleName:%{public}s", bundleName.c_str());
        return false;
    }

    bundleId = bundleIdMap_.rbegin()->first + 1;
    bundleIdMap_.emplace(bundleId, bundleName);
    BundleUtil::MakeFsConfig(bundleName, bundleId, Constants::HMDFS_CONFIG_PATH);
    BundleUtil::MakeFsConfig(bundleName, bundleId, Constants::SHAREFS_CONFIG_PATH);
    return true;
}

ErrCode BundleDataMgr::SetModuleUpgradeFlag(const std::string &bundleName,
    const std::string &moduleName, const int32_t upgradeFlag)
{
    APP_LOGD("SetModuleUpgradeFlag %{public}d", upgradeFlag);
    if (bundleName.empty() || moduleName.empty()) {
        APP_LOGW("bundleName or moduleName is empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    InnerBundleInfo &newInfo = infoItem->second;
    ErrCode setFlag = newInfo.SetModuleUpgradeFlag(moduleName, upgradeFlag);
    if (setFlag == ERR_OK) {
        if (dataStorage_->SaveStorageBundleInfo(newInfo)) {
            return ERR_OK;
        }
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    APP_LOGW("dataStorage SetModuleUpgradeFlag %{public}s failed", bundleName.c_str());
    return setFlag;
}

int32_t BundleDataMgr::GetModuleUpgradeFlag(const std::string &bundleName, const std::string &moduleName) const
{
    APP_LOGD("bundleName is bundleName:%{public}s, moduleName:%{public}s", bundleName.c_str(), moduleName.c_str());
    if (bundleName.empty() || moduleName.empty()) {
        APP_LOGW("bundleName or moduleName is empty");
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("can not find bundle %{public}s", bundleName.c_str());
        return false;
    }
    InnerBundleInfo newInfo = infoItem->second;
    return newInfo.GetModuleUpgradeFlag(moduleName);
}

void BundleDataMgr::RecycleUidAndGid(const InnerBundleInfo &info)
{
    auto userInfos = info.GetInnerBundleUserInfos();
    if (userInfos.empty()) {
        return;
    }

    auto innerBundleUserInfo = userInfos.begin()->second;
    int32_t bundleId = innerBundleUserInfo.uid -
        innerBundleUserInfo.bundleUserInfo.userId * Constants::BASE_USER_RANGE;
    std::lock_guard<std::mutex> lock(bundleIdMapMutex_);
    auto infoItem = bundleIdMap_.find(bundleId);
    if (infoItem == bundleIdMap_.end()) {
        return;
    }

    bundleIdMap_.erase(bundleId);
    BundleUtil::RemoveFsConfig(innerBundleUserInfo.bundleName, Constants::HMDFS_CONFIG_PATH);
    BundleUtil::RemoveFsConfig(innerBundleUserInfo.bundleName, Constants::SHAREFS_CONFIG_PATH);
}

bool BundleDataMgr::RestoreUidAndGid()
{
    for (const auto &info : bundleInfos_) {
        bool onlyInsertOne = false;
        for (auto infoItem : info.second.GetInnerBundleUserInfos()) {
            auto innerBundleUserInfo = infoItem.second;
            AddUserId(innerBundleUserInfo.bundleUserInfo.userId);
            if (!onlyInsertOne) {
                onlyInsertOne = true;
                int32_t bundleId = innerBundleUserInfo.uid -
                    innerBundleUserInfo.bundleUserInfo.userId * Constants::BASE_USER_RANGE;
                std::lock_guard<std::mutex> lock(bundleIdMapMutex_);
                auto item = bundleIdMap_.find(bundleId);
                if (item == bundleIdMap_.end()) {
                    bundleIdMap_.emplace(bundleId, innerBundleUserInfo.bundleName);
                } else {
                    bundleIdMap_[bundleId] = innerBundleUserInfo.bundleName;
                }
                BundleUtil::MakeFsConfig(innerBundleUserInfo.bundleName, bundleId, Constants::HMDFS_CONFIG_PATH);
                BundleUtil::MakeFsConfig(innerBundleUserInfo.bundleName, bundleId, Constants::SHAREFS_CONFIG_PATH);
            }
        }
    }
    return true;
}

void BundleDataMgr::RestoreSandboxUidAndGid(std::map<int32_t, std::string> &bundleIdMap)
{
    if (sandboxAppHelper_ != nullptr) {
        std::lock_guard<std::mutex> lock(bundleIdMapMutex_);
        sandboxAppHelper_->RestoreSandboxUidAndGid(bundleIdMap);
    }
}

std::mutex &BundleDataMgr::GetBundleMutex(const std::string &bundleName)
{
    bundleMutex_.lock_shared();
    auto it = bundleMutexMap_.find(bundleName);
    if (it == bundleMutexMap_.end()) {
        bundleMutex_.unlock_shared();
        std::unique_lock lock {bundleMutex_};
        return bundleMutexMap_[bundleName];
    }
    bundleMutex_.unlock_shared();
    return it->second;
}

bool BundleDataMgr::GetProvisionId(const std::string &bundleName, std::string &provisionId) const
{
    APP_LOGD("GetProvisionId %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        APP_LOGW("bundleName empty");
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("can not find bundle %{public}s", bundleName.c_str());
        return false;
    }
    provisionId = infoItem->second.GetProvisionId();
    return true;
}

bool BundleDataMgr::GetAppFeature(const std::string &bundleName, std::string &appFeature) const
{
    APP_LOGD("GetAppFeature %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        APP_LOGW("bundleName empty");
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("can not find bundle %{public}s", bundleName.c_str());
        return false;
    }
    appFeature = infoItem->second.GetAppFeature();
    return true;
}

void BundleDataMgr::SetInitialUserFlag(bool flag)
{
    APP_LOGD("SetInitialUserFlag %{public}d", flag);
    if (!initialUserFlag_ && flag && bundlePromise_ != nullptr) {
        bundlePromise_->NotifyAllTasksExecuteFinished();
    }

    initialUserFlag_ = flag;
}

std::shared_ptr<IBundleDataStorage> BundleDataMgr::GetDataStorage() const
{
    return dataStorage_;
}

bool BundleDataMgr::GetAllFormsInfo(std::vector<FormInfo> &formInfos) const
{
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    if (bundleInfos_.empty()) {
        APP_LOGW("bundleInfos_ data is empty");
        return false;
    }
    auto result = false;
    for (const auto &item : bundleInfos_) {
        if (item.second.IsDisabled()) {
            APP_LOGD("app %{public}s is disabled", item.second.GetBundleName().c_str());
            continue;
        }
        item.second.GetFormsInfoByApp(formInfos);
        result = true;
    }
    APP_LOGD("all the form infos find success");
    return result;
}

bool BundleDataMgr::GetFormsInfoByModule(
    const std::string &bundleName, const std::string &moduleName, std::vector<FormInfo> &formInfos) const
{
    if (bundleName.empty()) {
        APP_LOGW("bundle name is empty");
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    if (bundleInfos_.empty()) {
        APP_LOGW("bundleInfos_ data is empty");
        return false;
    }
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("bundleName %{public}s not exist", bundleName.c_str());
        return false;
    }
    if (infoItem->second.IsDisabled()) {
        APP_LOGW("app %{public}s is disabled", infoItem->second.GetBundleName().c_str());
        return false;
    }
    infoItem->second.GetFormsInfoByModule(moduleName, formInfos);
    if (formInfos.empty()) {
        return false;
    }
    APP_LOGD("module forminfo find success");
    return true;
}

bool BundleDataMgr::GetFormsInfoByApp(const std::string &bundleName, std::vector<FormInfo> &formInfos) const
{
    if (bundleName.empty()) {
        APP_LOGW("bundle name is empty");
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    if (bundleInfos_.empty()) {
        APP_LOGW("bundleInfos_ data is empty");
        return false;
    }
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("bundleName %{public}s not exist", bundleName.c_str());
        return false;
    }
    if (infoItem->second.IsDisabled()) {
        APP_LOGW("app %{public}s is disabled", infoItem->second.GetBundleName().c_str());
        return false;
    }
    infoItem->second.GetFormsInfoByApp(formInfos);
    APP_LOGD("App forminfo find success");
    return true;
}

bool BundleDataMgr::GetShortcutInfos(
    const std::string &bundleName, int32_t userId, std::vector<ShortcutInfo> &shortcutInfos) const
{
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        APP_LOGW("input invalid userid, bundleName:%{public}s, userId:%{public}d", bundleName.c_str(), userId);
        return false;
    }

    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    InnerBundleInfo innerBundleInfo;
    if (!GetInnerBundleInfoWithFlags(
        bundleName, BundleFlag::GET_BUNDLE_DEFAULT, innerBundleInfo, requestUserId)) {
        APP_LOGW("GetShortcutInfos failed, bundleName:%{public}s, requestUserId:%{public}d",
            bundleName.c_str(), requestUserId);
        return false;
    }
    innerBundleInfo.GetShortcutInfos(shortcutInfos);
    return true;
}

ErrCode BundleDataMgr::GetShortcutInfoV9(
    const std::string &bundleName, int32_t userId, std::vector<ShortcutInfo> &shortcutInfos) const
{
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        APP_LOGW("input invalid userid, bundleName:%{public}s, userId:%{public}d", bundleName.c_str(), userId);
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    InnerBundleInfo innerBundleInfo;
    ErrCode ret = GetInnerBundleInfoWithFlagsV9(bundleName,
        BundleFlag::GET_BUNDLE_DEFAULT, innerBundleInfo, requestUserId);
    if (ret != ERR_OK) {
        APP_LOGD("GetInnerBundleInfoWithFlagsV9 failed, bundleName:%{public}s, requestUserId:%{public}d",
            bundleName.c_str(), requestUserId);
        return ret;
    }

    innerBundleInfo.GetShortcutInfos(shortcutInfos);
    return ERR_OK;
}

bool BundleDataMgr::GetAllCommonEventInfo(const std::string &eventKey,
    std::vector<CommonEventInfo> &commonEventInfos) const
{
    if (eventKey.empty()) {
        APP_LOGW("event key is empty");
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    if (bundleInfos_.empty()) {
        APP_LOGW("bundleInfos_ data is empty");
        return false;
    }
    for (const auto &item : bundleInfos_) {
        const InnerBundleInfo &info = item.second;
        if (info.IsDisabled()) {
            APP_LOGD("app %{public}s is disabled", info.GetBundleName().c_str());
            continue;
        }
        info.GetCommonEvents(eventKey, commonEventInfos);
    }
    if (commonEventInfos.size() == 0) {
        APP_LOGW("commonEventInfos is empty");
        return false;
    }
    APP_LOGE("commonEventInfos find success");
    return true;
}

bool BundleDataMgr::SavePreInstallBundleInfo(
    const std::string &bundleName, const PreInstallBundleInfo &preInstallBundleInfo)
{
    if (preInstallDataStorage_ == nullptr) {
        return false;
    }

    if (preInstallDataStorage_->SavePreInstallStorageBundleInfo(preInstallBundleInfo)) {
        APP_LOGD("write storage success bundle:%{public}s", bundleName.c_str());
        return true;
    }

    return false;
}

bool BundleDataMgr::DeletePreInstallBundleInfo(
    const std::string &bundleName, const PreInstallBundleInfo &preInstallBundleInfo)
{
    if (preInstallDataStorage_ == nullptr) {
        return false;
    }

    if (preInstallDataStorage_->DeletePreInstallStorageBundleInfo(preInstallBundleInfo)) {
        APP_LOGD("Delete PreInstall Storage success bundle:%{public}s", bundleName.c_str());
        return true;
    }

    return false;
}

bool BundleDataMgr::GetPreInstallBundleInfo(
    const std::string &bundleName, PreInstallBundleInfo &preInstallBundleInfo)
{
    if (bundleName.empty()) {
        APP_LOGW("bundleName is empty");
        return false;
    }
    if (preInstallDataStorage_ == nullptr) {
        return false;
    }
    if (!preInstallDataStorage_->LoadPreInstallBundleInfo(bundleName, preInstallBundleInfo)) {
        APP_LOGW("get preInstall bundleInfo failed by bundle(%{public}s).", bundleName.c_str());
        return false;
    }
    return true;
}

bool BundleDataMgr::LoadAllPreInstallBundleInfos(std::vector<PreInstallBundleInfo> &preInstallBundleInfos)
{
    if (preInstallDataStorage_ == nullptr) {
        return false;
    }

    if (preInstallDataStorage_->LoadAllPreInstallBundleInfos(preInstallBundleInfos)) {
        APP_LOGD("load all storage success");
        return true;
    }

    return false;
}

bool BundleDataMgr::SaveInnerBundleInfo(const InnerBundleInfo &info) const
{
    APP_LOGD("write install InnerBundleInfo to storage with bundle:%{public}s", info.GetBundleName().c_str());
    if (dataStorage_->SaveStorageBundleInfo(info)) {
        APP_LOGD("save install InnerBundleInfo successfully");
        return true;
    }
    APP_LOGW("save install InnerBundleInfo failed, bundleName:%{public}s", info.GetBundleName().c_str());
    return false;
}

bool BundleDataMgr::GetInnerBundleUserInfoByUserId(const std::string &bundleName,
    int32_t userId, InnerBundleUserInfo &innerBundleUserInfo) const
{
    APP_LOGD("get user info start: bundleName: (%{public}s)  userId: (%{public}d) ",
        bundleName.c_str(), userId);
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return false;
    }

    if (bundleName.empty()) {
        APP_LOGW("bundle name is empty");
        return false;
    }

    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    if (bundleInfos_.empty()) {
        APP_LOGW("bundleInfos data is empty, bundleName:%{public}s", bundleName.c_str());
        return false;
    }

    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("bundleName:%{public}s not exist", bundleName.c_str());
        return false;
    }
    if (infoItem->second.IsDisabled()) {
        APP_LOGW("app %{public}s is disabled", infoItem->second.GetBundleName().c_str());
        return false;
    }

    return infoItem->second.GetInnerBundleUserInfo(requestUserId, innerBundleUserInfo);
}

int32_t BundleDataMgr::GetUserId(int32_t userId) const
{
    if (userId == Constants::ANY_USERID || userId == Constants::ALL_USERID) {
        return userId;
    }

    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = GetUserIdByCallingUid();
    }

    if (!HasUserId(userId)) {
        APP_LOGD("user is not existed.");
        userId = Constants::INVALID_USERID;
    }

    return userId;
}

int32_t BundleDataMgr::GetUserIdByUid(int32_t uid) const
{
    return BundleUtil::GetUserIdByUid(uid);
}

void BundleDataMgr::AddUserId(int32_t userId)
{
    std::lock_guard<std::mutex> lock(multiUserIdSetMutex_);
    auto item = multiUserIdsSet_.find(userId);
    if (item != multiUserIdsSet_.end()) {
        return;
    }

    multiUserIdsSet_.insert(userId);
}

void BundleDataMgr::RemoveUserId(int32_t userId)
{
    std::lock_guard<std::mutex> lock(multiUserIdSetMutex_);
    auto item = multiUserIdsSet_.find(userId);
    if (item == multiUserIdsSet_.end()) {
        return;
    }

    multiUserIdsSet_.erase(item);
}

bool BundleDataMgr::HasUserId(int32_t userId) const
{
    std::lock_guard<std::mutex> lock(multiUserIdSetMutex_);
    return multiUserIdsSet_.find(userId) != multiUserIdsSet_.end();
}

int32_t BundleDataMgr::GetUserIdByCallingUid() const
{
    return BundleUtil::GetUserIdByCallingUid();
}

std::set<int32_t> BundleDataMgr::GetAllUser() const
{
    std::lock_guard<std::mutex> lock(multiUserIdSetMutex_);
    return multiUserIdsSet_;
}

bool BundleDataMgr::GetInnerBundleUserInfos(
    const std::string &bundleName, std::vector<InnerBundleUserInfo> &innerBundleUserInfos) const
{
    APP_LOGD("get all user info in bundle(%{public}s)", bundleName.c_str());
    if (bundleName.empty()) {
        APP_LOGW("bundle name is empty");
        return false;
    }

    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    if (bundleInfos_.empty()) {
        APP_LOGW("bundleInfos data is empty, bundleName:%{public}s", bundleName.c_str());
        return false;
    }

    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("bundleName:%{public}s not exist", bundleName.c_str());
        return false;
    }
    if (infoItem->second.IsDisabled()) {
        APP_LOGW("app %{public}s is disabled", infoItem->second.GetBundleName().c_str());
        return false;
    }

    for (auto userInfo : infoItem->second.GetInnerBundleUserInfos()) {
        innerBundleUserInfos.emplace_back(userInfo.second);
    }

    return !innerBundleUserInfos.empty();
}

std::string BundleDataMgr::GetAppPrivilegeLevel(const std::string &bundleName, int32_t userId)
{
    APP_LOGD("GetAppPrivilegeLevel:%{public}s, userId:%{public}d", bundleName.c_str(), userId);
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    InnerBundleInfo info;
    if (!GetInnerBundleInfoWithFlags(bundleName, 0, info, userId)) {
        return Constants::EMPTY_STRING;
    }

    return info.GetAppPrivilegeLevel();
}

bool BundleDataMgr::QueryExtensionAbilityInfos(const Want &want, int32_t flags, int32_t userId,
    std::vector<ExtensionAbilityInfo> &extensionInfos, int32_t appIndex) const
{
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return false;
    }

    ElementName element = want.GetElement();
    std::string bundleName = element.GetBundleName();
    std::string extensionName = element.GetAbilityName();
    LOG_D(BMS_TAG_QUERY_EXTENSION, "bundleName:%{public}s extensionName:%{public}s",
        bundleName.c_str(), extensionName.c_str());
    // explicit query
    if (!bundleName.empty() && !extensionName.empty()) {
        ExtensionAbilityInfo info;
        bool ret = ExplicitQueryExtensionInfo(want, flags, requestUserId, info, appIndex);
        if (!ret) {
            LOG_D(BMS_TAG_QUERY_EXTENSION, "explicit query error bundleName:%{public}s extensionName:%{public}s",
                bundleName.c_str(), extensionName.c_str());
            return false;
        }
        extensionInfos.emplace_back(info);
        return true;
    }

    bool ret = ImplicitQueryExtensionInfos(want, flags, requestUserId, extensionInfos, appIndex);
    if (!ret) {
        LOG_D(BMS_TAG_QUERY_EXTENSION,
            "implicit queryExtension error action:%{public}s uri:%{private}s type:%{public}s",
            want.GetAction().c_str(), want.GetUriString().c_str(), want.GetType().c_str());
        return false;
    }
    if (extensionInfos.size() == 0) {
        LOG_W(BMS_TAG_QUERY_EXTENSION, "no matching abilityInfo, action:%{public}s uri:%{private}s type:%{public}s",
            want.GetAction().c_str(), want.GetUriString().c_str(), want.GetType().c_str());
        return false;
    }
    LOG_D(BMS_TAG_QUERY_EXTENSION, "query extensionAbilityInfo successfully");
    return true;
}

ErrCode BundleDataMgr::QueryExtensionAbilityInfosV9(const Want &want, int32_t flags, int32_t userId,
    std::vector<ExtensionAbilityInfo> &extensionInfos, int32_t appIndex) const
{
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }

    ElementName element = want.GetElement();
    std::string bundleName = element.GetBundleName();
    std::string extensionName = element.GetAbilityName();
    LOG_D(BMS_TAG_QUERY_EXTENSION, "bundle name:%{public}s, extension name:%{public}s",
        bundleName.c_str(), extensionName.c_str());
    // explicit query
    if (!bundleName.empty() && !extensionName.empty()) {
        ExtensionAbilityInfo info;
        ErrCode ret = ExplicitQueryExtensionInfoV9(want, flags, requestUserId, info, appIndex);
        if (ret != ERR_OK) {
            LOG_D(BMS_TAG_QUERY_EXTENSION, "explicit queryExtensionInfo error");
            return ret;
        }
        extensionInfos.emplace_back(info);
        return ERR_OK;
    }
    ErrCode ret = ImplicitQueryExtensionInfosV9(want, flags, requestUserId, extensionInfos, appIndex);
    if (ret != ERR_OK) {
        LOG_D(BMS_TAG_QUERY_EXTENSION, "ImplicitQueryExtensionInfosV9 error");
        return ret;
    }
    if (extensionInfos.empty()) {
        LOG_W(BMS_TAG_QUERY_EXTENSION, "no matching abilityInfo");
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }
    LOG_D(BMS_TAG_QUERY_EXTENSION, "QueryExtensionAbilityInfosV9 success");
    return ERR_OK;
}

ErrCode BundleDataMgr::QueryExtensionAbilityInfos(uint32_t flags, int32_t userId,
    std::vector<ExtensionAbilityInfo> &extensionInfos, int32_t appIndex) const
{
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }

    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    ErrCode ret = ImplicitQueryAllExtensionInfos(flags, requestUserId, extensionInfos, appIndex);
    if (ret != ERR_OK) {
        LOG_D(BMS_TAG_QUERY_EXTENSION, "QueryExtensionAbilityInfos error");
        return ret;
    }
    if (extensionInfos.empty()) {
        LOG_W(BMS_TAG_QUERY_EXTENSION, "no matching abilityInfo");
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }
    LOG_D(BMS_TAG_QUERY_EXTENSION, "QueryExtensionAbilityInfos success");
    return ERR_OK;
}

bool BundleDataMgr::ExplicitQueryExtensionInfo(const Want &want, int32_t flags, int32_t userId,
    ExtensionAbilityInfo &extensionInfo, int32_t appIndex) const
{
    ElementName element = want.GetElement();
    std::string bundleName = element.GetBundleName();
    std::string moduleName = element.GetModuleName();
    std::string extensionName = element.GetAbilityName();
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    InnerBundleInfo innerBundleInfo;
    if ((appIndex == 0) && (!GetInnerBundleInfoWithFlags(bundleName, flags, innerBundleInfo, requestUserId))) {
        LOG_W(BMS_TAG_QUERY_EXTENSION, "ExplicitQueryExtensionInfo failed");
        return false;
    }
    if (appIndex > 0) {
        if (sandboxAppHelper_ == nullptr) {
            LOG_W(BMS_TAG_QUERY_EXTENSION, "sandboxAppHelper_ is nullptr");
            return false;
        }
        auto ret = sandboxAppHelper_->GetSandboxAppInfo(bundleName, appIndex, requestUserId, innerBundleInfo);
        if (ret != ERR_OK) {
            LOG_D(BMS_TAG_QUERY_EXTENSION, "GetSandboxAppInfo failed errCode %{public}d", ret);
            return false;
        }
    }
    auto extension = innerBundleInfo.FindExtensionInfo(moduleName, extensionName);
    if (!extension) {
        LOG_W(BMS_TAG_QUERY_EXTENSION, "extensionAbility not found or disabled");
        return false;
    }
    if ((static_cast<uint32_t>(flags) & GET_ABILITY_INFO_WITH_PERMISSION) != GET_ABILITY_INFO_WITH_PERMISSION) {
        extension->permissions.clear();
    }
    if ((static_cast<uint32_t>(flags) & GET_ABILITY_INFO_WITH_METADATA) != GET_ABILITY_INFO_WITH_METADATA) {
        extension->metadata.clear();
    }
    if ((static_cast<uint32_t>(flags) & GET_ABILITY_INFO_WITH_SKILL) != GET_ABILITY_INFO_WITH_SKILL) {
        extension->skills.clear();
    }
    extensionInfo = (*extension);
    if ((static_cast<uint32_t>(flags) & GET_ABILITY_INFO_WITH_APPLICATION) == GET_ABILITY_INFO_WITH_APPLICATION) {
        int32_t responseUserId = innerBundleInfo.GetResponseUserId(requestUserId);
        innerBundleInfo.GetApplicationInfo(ApplicationFlag::GET_BASIC_APPLICATION_INFO |
            ApplicationFlag::GET_APPLICATION_INFO_WITH_CERTIFICATE_FINGERPRINT, responseUserId,
            extensionInfo.applicationInfo);
    }
    return true;
}

ErrCode BundleDataMgr::ExplicitQueryExtensionInfoV9(const Want &want, int32_t flags, int32_t userId,
    ExtensionAbilityInfo &extensionInfo, int32_t appIndex) const
{
    ElementName element = want.GetElement();
    std::string bundleName = element.GetBundleName();
    std::string moduleName = element.GetModuleName();
    std::string extensionName = element.GetAbilityName();
    LOG_D(BMS_TAG_QUERY_EXTENSION, "bundleName:%{public}s, moduleName:%{public}s, abilityName:%{public}s",
        bundleName.c_str(), moduleName.c_str(), extensionName.c_str());
    LOG_D(BMS_TAG_QUERY_EXTENSION, "flags:%{public}d, userId:%{public}d", flags, userId);
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    InnerBundleInfo innerBundleInfo;
    if (appIndex == 0) {
        ErrCode ret = GetInnerBundleInfoWithFlagsV9(bundleName, flags, innerBundleInfo, requestUserId);
        if (ret != ERR_OK) {
            LOG_D(BMS_TAG_QUERY_EXTENSION, "ExplicitQueryExtensionInfoV9 failed");
            return ret;
        }
    }
    if (appIndex > 0) {
        if (sandboxAppHelper_ == nullptr) {
            LOG_W(BMS_TAG_QUERY_EXTENSION, "sandboxAppHelper_ is nullptr");
            return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
        }
        auto ret = sandboxAppHelper_->GetSandboxAppInfo(bundleName, appIndex, requestUserId, innerBundleInfo);
        if (ret != ERR_OK) {
            LOG_D(BMS_TAG_QUERY_EXTENSION, "GetSandboxAppInfo failed errCode %{public}d", ret);
            return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
        }
    }
    auto extension = innerBundleInfo.FindExtensionInfo(moduleName, extensionName);
    if (!extension) {
        LOG_W(BMS_TAG_QUERY_EXTENSION, "extensionAbility not found or disabled");
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }
    if ((static_cast<uint32_t>(flags) &
        static_cast<uint32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_PERMISSION)) !=
        static_cast<uint32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_PERMISSION)) {
        extension->permissions.clear();
    }
    if ((static_cast<uint32_t>(flags) &
        static_cast<uint32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_METADATA)) !=
        static_cast<uint32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_METADATA)) {
        extension->metadata.clear();
    }
    if ((static_cast<uint32_t>(flags) &
        static_cast<uint32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_SKILL)) !=
        static_cast<uint32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_SKILL)) {
        extension->skills.clear();
    }
    extensionInfo = (*extension);
    if ((static_cast<uint32_t>(flags) &
        static_cast<uint32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_APPLICATION)) ==
        static_cast<uint32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_APPLICATION)) {
        int32_t responseUserId = innerBundleInfo.GetResponseUserId(requestUserId);
        innerBundleInfo.GetApplicationInfoV9(static_cast<int32_t>(
            GetApplicationFlag::GET_APPLICATION_INFO_DEFAULT), responseUserId, extensionInfo.applicationInfo);
    }
    // set uid for NAPI cache use
    InnerBundleUserInfo innerBundleUserInfo;
    if (innerBundleInfo.GetInnerBundleUserInfo(userId, innerBundleUserInfo)) {
        extensionInfo.uid = innerBundleUserInfo.uid;
    }
    return ERR_OK;
}

void BundleDataMgr::FilterExtensionAbilityInfosByModuleName(const std::string &moduleName,
    std::vector<ExtensionAbilityInfo> &extensionInfos) const
{
    LOG_D(BMS_TAG_QUERY_EXTENSION, "FilterExtensionAbilityInfos moduleName: %{public}s", moduleName.c_str());
    if (moduleName.empty()) {
        return;
    }
    for (auto iter = extensionInfos.begin(); iter != extensionInfos.end();) {
        if (iter->moduleName != moduleName) {
            iter = extensionInfos.erase(iter);
        } else {
            ++iter;
        }
    }
}

bool BundleDataMgr::ImplicitQueryExtensionInfos(const Want &want, int32_t flags, int32_t userId,
    std::vector<ExtensionAbilityInfo> &extensionInfos, int32_t appIndex) const
{
    if (want.GetAction().empty() && want.GetEntities().empty()
        && want.GetUriString().empty() && want.GetType().empty()) {
        LOG_W(BMS_TAG_QUERY_EXTENSION, "param invalid");
        return false;
    }
    LOG_D(BMS_TAG_QUERY_EXTENSION, "action:%{public}s, uri:%{private}s, type:%{public}s",
        want.GetAction().c_str(), want.GetUriString().c_str(), want.GetType().c_str());
    LOG_D(BMS_TAG_QUERY_EXTENSION, "flags:%{public}d, userId:%{public}d", flags, userId);

    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    std::string bundleName = want.GetElement().GetBundleName();
    if (!bundleName.empty()) {
        // query in current bundle
        if (!ImplicitQueryCurExtensionInfos(want, flags, requestUserId, extensionInfos, appIndex)) {
            LOG_D(BMS_TAG_QUERY_EXTENSION, "ImplicitQueryCurExtension failed, bundleName:%{public}s",
                bundleName.c_str());
            return false;
        }
    } else {
        // query all
        ImplicitQueryAllExtensionInfos(want, flags, requestUserId, extensionInfos, appIndex);
    }
    // sort by priority, descending order.
    if (extensionInfos.size() > 1) {
        std::stable_sort(extensionInfos.begin(), extensionInfos.end(),
            [](ExtensionAbilityInfo a, ExtensionAbilityInfo b) { return a.priority > b.priority; });
    }
    return true;
}

ErrCode BundleDataMgr::ImplicitQueryExtensionInfosV9(const Want &want, int32_t flags, int32_t userId,
    std::vector<ExtensionAbilityInfo> &extensionInfos, int32_t appIndex) const
{
    if (want.GetAction().empty() && want.GetEntities().empty()
        && want.GetUriString().empty() && want.GetType().empty()) {
        LOG_W(BMS_TAG_QUERY_EXTENSION, "param invalid");
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }
    LOG_D(BMS_TAG_QUERY_EXTENSION, "action:%{public}s, uri:%{private}s, type:%{public}s",
        want.GetAction().c_str(), want.GetUriString().c_str(), want.GetType().c_str());
    LOG_D(BMS_TAG_QUERY_EXTENSION, "flags:%{public}d, userId:%{public}d", flags, userId);

    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    std::string bundleName = want.GetElement().GetBundleName();
    if (!bundleName.empty()) {
        // query in current bundle
        ErrCode ret = ImplicitQueryCurExtensionInfosV9(want, flags, requestUserId, extensionInfos, appIndex);
        if (ret != ERR_OK) {
            LOG_D(BMS_TAG_QUERY_EXTENSION, "ImplicitQueryCurExtensionInfos failed, bundleName:%{public}s",
                bundleName.c_str());
            return ret;
        }
    } else {
        // query all
        ImplicitQueryAllExtensionInfosV9(want, flags, requestUserId, extensionInfos, appIndex);
    }
    // sort by priority, descending order.
    if (extensionInfos.size() > 1) {
        std::stable_sort(extensionInfos.begin(), extensionInfos.end(),
            [](ExtensionAbilityInfo a, ExtensionAbilityInfo b) { return a.priority > b.priority; });
    }
    return ERR_OK;
}

bool BundleDataMgr::ImplicitQueryCurExtensionInfos(const Want &want, int32_t flags, int32_t userId,
    std::vector<ExtensionAbilityInfo> &infos, int32_t appIndex) const
{
    LOG_D(BMS_TAG_QUERY_EXTENSION, "begin to ImplicitQueryCurExtensionInfos");
    std::string bundleName = want.GetElement().GetBundleName();
    InnerBundleInfo innerBundleInfo;
    if ((appIndex == 0) && (!GetInnerBundleInfoWithFlags(bundleName, flags, innerBundleInfo, userId))) {
        LOG_D(BMS_TAG_QUERY_EXTENSION, "ImplicitQueryExtensionAbilityInfos failed, bundleName:%{public}s",
            bundleName.c_str());
        return false;
    }
    if (appIndex > 0) {
        if (sandboxAppHelper_ == nullptr) {
            LOG_W(BMS_TAG_QUERY_EXTENSION, "sandboxAppHelper_ is nullptr");
            return false;
        }
        auto ret = sandboxAppHelper_->GetSandboxAppInfo(bundleName, appIndex, userId, innerBundleInfo);
        if (ret != ERR_OK) {
            LOG_D(BMS_TAG_QUERY_EXTENSION, "GetSandboxAppInfo failed errCode %{public}d", ret);
            return false;
        }
    }
    int32_t responseUserId = innerBundleInfo.GetResponseUserId(userId);
    GetMatchExtensionInfos(want, flags, responseUserId, innerBundleInfo, infos);
    FilterExtensionAbilityInfosByModuleName(want.GetElement().GetModuleName(), infos);
    LOG_D(BMS_TAG_QUERY_EXTENSION, "finish to ImplicitQueryCurExtensionInfos");
    return true;
}

ErrCode BundleDataMgr::ImplicitQueryCurExtensionInfosV9(const Want &want, int32_t flags, int32_t userId,
    std::vector<ExtensionAbilityInfo> &infos, int32_t appIndex) const
{
    LOG_D(BMS_TAG_QUERY_EXTENSION, "begin to ImplicitQueryCurExtensionInfosV9");
    std::string bundleName = want.GetElement().GetBundleName();
    InnerBundleInfo innerBundleInfo;
    if (appIndex == 0) {
        ErrCode ret = GetInnerBundleInfoWithFlagsV9(bundleName, flags, innerBundleInfo, userId);
        if (ret != ERR_OK) {
            LOG_W(BMS_TAG_QUERY_EXTENSION, "GetInnerBundleInfoWithFlagsV9 failed, bundleName:%{public}s",
                bundleName.c_str());
            return ret;
        }
    }
    if (appIndex > 0) {
        if (sandboxAppHelper_ == nullptr) {
            LOG_W(BMS_TAG_QUERY_EXTENSION, "sandboxAppHelper_ is nullptr");
            return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
        }
        auto ret = sandboxAppHelper_->GetSandboxAppInfo(bundleName, appIndex, userId, innerBundleInfo);
        if (ret != ERR_OK) {
            LOG_D(BMS_TAG_QUERY_EXTENSION, "GetSandboxAppInfo failed errCode %{public}d", ret);
            return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
        }
    }
    int32_t responseUserId = innerBundleInfo.GetResponseUserId(userId);
    GetMatchExtensionInfosV9(want, flags, responseUserId, innerBundleInfo, infos);
    FilterExtensionAbilityInfosByModuleName(want.GetElement().GetModuleName(), infos);
    LOG_D(BMS_TAG_QUERY_EXTENSION, "finish to ImplicitQueryCurExtensionInfosV9");
    return ERR_OK;
}

void BundleDataMgr::ImplicitQueryAllExtensionInfos(const Want &want, int32_t flags, int32_t userId,
    std::vector<ExtensionAbilityInfo> &infos, int32_t appIndex) const
{
    LOG_D(BMS_TAG_QUERY_EXTENSION, "begin to ImplicitQueryAllExtensionInfos");
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        LOG_E(BMS_TAG_QUERY_EXTENSION, "invalid userId, userId:%{public}d", userId);
        return;
    }

    // query from bundleInfos_
    if (appIndex == 0) {
        for (const auto &item : bundleInfos_) {
            const InnerBundleInfo &innerBundleInfo = item.second;
            int32_t responseUserId = innerBundleInfo.GetResponseUserId(requestUserId);
            if (CheckInnerBundleInfoWithFlags(innerBundleInfo, flags, responseUserId) != ERR_OK) {
                continue;
            }
            GetMatchExtensionInfos(want, flags, responseUserId, innerBundleInfo, infos);
        }
    } else {
        // query from sandbox manager for sandbox bundle
        if (sandboxAppHelper_ == nullptr) {
            LOG_W(BMS_TAG_QUERY_EXTENSION, "sandboxAppHelper_ is nullptr");
            return;
        }
        auto sandboxMap = sandboxAppHelper_->GetSandboxAppInfoMap();
        for (const auto &item : sandboxMap) {
            InnerBundleInfo info;
            size_t pos = item.first.rfind(Constants::FILE_UNDERLINE);
            if (pos == std::string::npos) {
                LOG_W(BMS_TAG_QUERY_EXTENSION, "sandbox map contains invalid element");
                continue;
            }
            std::string innerBundleName = item.first.substr(pos + 1);
            if (sandboxAppHelper_->GetSandboxAppInfo(innerBundleName, appIndex, userId, info) != ERR_OK) {
                LOG_D(BMS_TAG_QUERY_EXTENSION, "obtain innerBundleInfo of sandbox app failed");
                continue;
            }

            int32_t responseUserId = info.GetResponseUserId(userId);
            GetMatchExtensionInfos(want, flags, responseUserId, info, infos);
        }
    }
    LOG_D(BMS_TAG_QUERY_EXTENSION, "finish to ImplicitQueryAllExtensionInfos");
}

void BundleDataMgr::ImplicitQueryAllExtensionInfosV9(const Want &want, int32_t flags, int32_t userId,
    std::vector<ExtensionAbilityInfo> &infos, int32_t appIndex) const
{
    LOG_D(BMS_TAG_QUERY_EXTENSION, "begin to ImplicitQueryAllExtensionInfosV9");
    // query from bundleInfos_
    if (appIndex == 0) {
        for (const auto &item : bundleInfos_) {
            InnerBundleInfo innerBundleInfo;
            ErrCode ret = GetInnerBundleInfoWithFlagsV9(item.first, flags, innerBundleInfo, userId);
            if (ret != ERR_OK) {
                LOG_D(BMS_TAG_QUERY_EXTENSION, "ImplicitQueryExtensionAbilityInfos failed, bundleName:%{public}s",
                    item.first.c_str());
                continue;
            }
            int32_t responseUserId = innerBundleInfo.GetResponseUserId(userId);
            GetMatchExtensionInfosV9(want, flags, responseUserId, innerBundleInfo, infos);
        }
    } else {
        // query from sandbox manager for sandbox bundle
        if (sandboxAppHelper_ == nullptr) {
            LOG_W(BMS_TAG_QUERY_EXTENSION, "sandboxAppHelper_ is nullptr");
            return;
        }
        auto sandboxMap = sandboxAppHelper_->GetSandboxAppInfoMap();
        for (const auto &item : sandboxMap) {
            InnerBundleInfo info;
            size_t pos = item.first.rfind(Constants::FILE_UNDERLINE);
            if (pos == std::string::npos) {
                LOG_W(BMS_TAG_QUERY_EXTENSION, "sandbox map contains invalid element");
                continue;
            }
            std::string innerBundleName = item.first.substr(pos + 1);
            if (sandboxAppHelper_->GetSandboxAppInfo(innerBundleName, appIndex, userId, info) != ERR_OK) {
                LOG_D(BMS_TAG_QUERY_EXTENSION, "obtain innerBundleInfo of sandbox app failed");
                continue;
            }

            int32_t responseUserId = info.GetResponseUserId(userId);
            GetMatchExtensionInfosV9(want, flags, responseUserId, info, infos);
        }
    }
    LOG_D(BMS_TAG_QUERY_EXTENSION, "finish to ImplicitQueryAllExtensionInfosV9");
}

ErrCode BundleDataMgr::ImplicitQueryAllExtensionInfos(uint32_t flags, int32_t userId,
    std::vector<ExtensionAbilityInfo> &infos, int32_t appIndex) const
{
    LOG_D(BMS_TAG_QUERY_EXTENSION, "begin to ImplicitQueryAllExtensionInfos");
    // query from bundleInfos_
    if (appIndex == 0) {
        for (const auto &item : bundleInfos_) {
            InnerBundleInfo innerBundleInfo;
            ErrCode ret = GetInnerBundleInfoWithFlagsV9(item.first, flags, innerBundleInfo, userId);
            if (ret != ERR_OK) {
                LOG_D(BMS_TAG_QUERY_EXTENSION, "GetInnerBundleInfoWithFlagsV9 failed, bundleName:%{public}s",
                    item.first.c_str());
                continue;
            }
            int32_t responseUserId = innerBundleInfo.GetResponseUserId(userId);
            GetAllExtensionInfos(flags, responseUserId, innerBundleInfo, infos);
        }
    } else {
        // query from sandbox manager for sandbox bundle
        if (sandboxAppHelper_ == nullptr) {
            LOG_W(BMS_TAG_QUERY_EXTENSION, "sandboxAppHelper_ is nullptr");
            return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
        }
        auto sandboxMap = sandboxAppHelper_->GetSandboxAppInfoMap();
        for (const auto &item : sandboxMap) {
            InnerBundleInfo info;
            size_t pos = item.first.rfind(Constants::FILE_UNDERLINE);
            if (pos == std::string::npos) {
                LOG_W(BMS_TAG_QUERY_EXTENSION, "sandbox map contains invalid element");
                continue;
            }
            std::string innerBundleName = item.first.substr(pos + 1);
            if (sandboxAppHelper_->GetSandboxAppInfo(innerBundleName, appIndex, userId, info) != ERR_OK) {
                LOG_D(BMS_TAG_QUERY_EXTENSION, "obtain innerBundleInfo of sandbox app failed");
                continue;
            }
            int32_t responseUserId = info.GetResponseUserId(userId);
            GetAllExtensionInfos(flags, responseUserId, info, infos);
        }
    }
    LOG_D(BMS_TAG_QUERY_EXTENSION, "finish to ImplicitQueryAllExtensionInfos");
    return ERR_OK;
}

void BundleDataMgr::GetMatchExtensionInfos(const Want &want, int32_t flags, const int32_t &userId,
    const InnerBundleInfo &info, std::vector<ExtensionAbilityInfo> &infos) const
{
    auto extensionSkillInfos = info.GetExtensionSkillInfos();
    auto extensionInfos = info.GetInnerExtensionInfos();
    for (const auto &skillInfos : extensionSkillInfos) {
        for (size_t skillIndex = 0; skillIndex < skillInfos.second.size(); ++skillIndex) {
            const Skill &skill = skillInfos.second[skillIndex];
            size_t matchUriIndex = 0;
            if (!skill.Match(want, matchUriIndex)) {
                continue;
            }
            if (extensionInfos.find(skillInfos.first) == extensionInfos.end()) {
                LOG_W(BMS_TAG_QUERY_EXTENSION, "cannot find the extension info with %{public}s",
                    skillInfos.first.c_str());
                break;
            }
            ExtensionAbilityInfo extensionInfo = extensionInfos[skillInfos.first];
            if ((static_cast<uint32_t>(flags) & GET_EXTENSION_INFO_WITH_APPLICATION) ==
                GET_EXTENSION_INFO_WITH_APPLICATION) {
                info.GetApplicationInfo(
                    ApplicationFlag::GET_BASIC_APPLICATION_INFO |
                    ApplicationFlag::GET_APPLICATION_INFO_WITH_CERTIFICATE_FINGERPRINT, userId,
                    extensionInfo.applicationInfo);
            }
            if ((static_cast<uint32_t>(flags) & GET_EXTENSION_INFO_WITH_PERMISSION) !=
                GET_EXTENSION_INFO_WITH_PERMISSION) {
                extensionInfo.permissions.clear();
            }
            if ((static_cast<uint32_t>(flags) & GET_EXTENSION_INFO_WITH_METADATA) != GET_EXTENSION_INFO_WITH_METADATA) {
                extensionInfo.metadata.clear();
            }
            if ((static_cast<uint32_t>(flags) & GET_EXTENSION_INFO_WITH_SKILL) != GET_EXTENSION_INFO_WITH_SKILL) {
                extensionInfo.skills.clear();
            }
            if ((static_cast<uint32_t>(flags) &
                GET_EXTENSION_INFO_WITH_SKILL_URI) == GET_EXTENSION_INFO_WITH_SKILL_URI) {
                AddSkillUrisInfo(skillInfos.second, extensionInfo.skillUri, skillIndex, matchUriIndex);
            }
            infos.emplace_back(extensionInfo);
            break;
        }
    }
}

void BundleDataMgr::EmplaceExtensionInfo(const InnerBundleInfo &info, const std::vector<Skill> &skills,
    ExtensionAbilityInfo &extensionInfo, int32_t flags, int32_t userId, std::vector<ExtensionAbilityInfo> &infos,
    std::optional<size_t> matchSkillIndex, std::optional<size_t> matchUriIndex) const
{
    if ((static_cast<uint32_t>(flags) &
        static_cast<uint32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_APPLICATION)) ==
        static_cast<uint32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_APPLICATION)) {
        info.GetApplicationInfoV9(static_cast<int32_t>(
            GetApplicationFlag::GET_APPLICATION_INFO_DEFAULT), userId, extensionInfo.applicationInfo);
    }
    if ((static_cast<uint32_t>(flags) &
        static_cast<uint32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_PERMISSION)) !=
        static_cast<uint32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_PERMISSION)) {
        extensionInfo.permissions.clear();
    }
    if ((static_cast<uint32_t>(flags) &
        static_cast<uint32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_METADATA)) !=
        static_cast<uint32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_METADATA)) {
        extensionInfo.metadata.clear();
    }
    if ((static_cast<uint32_t>(flags) &
        static_cast<uint32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_SKILL)) !=
        static_cast<uint32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_SKILL)) {
        extensionInfo.skills.clear();
    }
    if ((static_cast<uint32_t>(flags) &
        static_cast<uint32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_SKILL_URI)) ==
        static_cast<uint32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_SKILL_URI)) {
        AddSkillUrisInfo(skills, extensionInfo.skillUri, matchSkillIndex, matchUriIndex);
    }
    infos.emplace_back(extensionInfo);
}

void BundleDataMgr::GetMatchExtensionInfosV9(const Want &want, int32_t flags, int32_t userId,
    const InnerBundleInfo &info, std::vector<ExtensionAbilityInfo> &infos) const
{
    auto extensionSkillInfos = info.GetExtensionSkillInfos();
    auto extensionInfos = info.GetInnerExtensionInfos();
    for (const auto &skillInfos : extensionSkillInfos) {
        if (want.GetAction() == SHARE_ACTION) {
            if (!MatchShare(want, skillInfos.second)) {
                continue;
            }
            if (extensionInfos.find(skillInfos.first) == extensionInfos.end()) {
                LOG_W(BMS_TAG_QUERY_EXTENSION, "cannot find the extension info with %{public}s",
                    skillInfos.first.c_str());
                continue;
            }
            ExtensionAbilityInfo extensionInfo = extensionInfos[skillInfos.first];
            EmplaceExtensionInfo(info, skillInfos.second, extensionInfo, flags, userId, infos,
                std::nullopt, std::nullopt);
            continue;
        }
        for (size_t skillIndex = 0; skillIndex < skillInfos.second.size(); ++skillIndex) {
            const Skill &skill = skillInfos.second[skillIndex];
            size_t matchUriIndex = 0;
            if (!skill.Match(want, matchUriIndex)) {
                continue;
            }
            if (extensionInfos.find(skillInfos.first) == extensionInfos.end()) {
                LOG_W(BMS_TAG_QUERY_EXTENSION, "cannot find the extension info with %{public}s",
                    skillInfos.first.c_str());
                break;
            }
            ExtensionAbilityInfo extensionInfo = extensionInfos[skillInfos.first];
            EmplaceExtensionInfo(info, skillInfos.second, extensionInfo, flags, userId, infos,
                skillIndex, matchUriIndex);
            break;
        }
    }
}

void BundleDataMgr::GetAllExtensionInfos(uint32_t flags, int32_t userId,
    const InnerBundleInfo &info, std::vector<ExtensionAbilityInfo> &infos) const
{
    auto extensionInfos = info.GetInnerExtensionInfos();
    for (const auto &extensionAbilityInfo : extensionInfos) {
        ExtensionAbilityInfo extensionInfo = extensionAbilityInfo.second;
        if ((flags &
            static_cast<uint32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_APPLICATION)) ==
            static_cast<uint32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_APPLICATION)) {
            info.GetApplicationInfoV9(static_cast<int32_t>(
                GetApplicationFlag::GET_APPLICATION_INFO_DEFAULT), userId, extensionInfo.applicationInfo);
        }
        if ((flags &
            static_cast<uint32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_PERMISSION)) !=
            static_cast<uint32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_PERMISSION)) {
            extensionInfo.permissions.clear();
        }
        if ((flags &
            static_cast<uint32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_METADATA)) !=
            static_cast<uint32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_METADATA)) {
            extensionInfo.metadata.clear();
        }
        if ((flags &
            static_cast<uint32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_SKILL)) !=
            static_cast<uint32_t>(GetExtensionAbilityInfoFlag::GET_EXTENSION_ABILITY_INFO_WITH_SKILL)) {
            extensionInfo.skills.clear();
        }
        infos.emplace_back(extensionInfo);
    }
}

bool BundleDataMgr::QueryExtensionAbilityInfos(const ExtensionAbilityType &extensionType, const int32_t &userId,
    std::vector<ExtensionAbilityInfo> &extensionInfos) const
{
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    for (const auto &item : bundleInfos_) {
        const InnerBundleInfo &innerBundleInfo = item.second;
        int32_t responseUserId = innerBundleInfo.GetResponseUserId(requestUserId);
        if (CheckInnerBundleInfoWithFlags(innerBundleInfo, 0, responseUserId) != ERR_OK) {
            continue;
        }
        auto innerExtensionInfos = innerBundleInfo.GetInnerExtensionInfos();
        for (const auto &info : innerExtensionInfos) {
            if (info.second.type == extensionType) {
                ExtensionAbilityInfo extensionAbilityInfo = info.second;
                innerBundleInfo.GetApplicationInfo(
                    ApplicationFlag::GET_APPLICATION_INFO_WITH_CERTIFICATE_FINGERPRINT, responseUserId,
                    extensionAbilityInfo.applicationInfo);
                extensionInfos.emplace_back(extensionAbilityInfo);
            }
        }
    }
    return true;
}

bool BundleDataMgr::QueryExtensionAbilityInfoByUri(const std::string &uri, int32_t userId,
    ExtensionAbilityInfo &extensionAbilityInfo) const
{
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        LOG_W(BMS_TAG_QUERY_EXTENSION, "invalid userId -1");
        return false;
    }
    if (uri.empty()) {
        LOG_W(BMS_TAG_QUERY_EXTENSION, "uri empty");
        return false;
    }
    std::string convertUri = uri;
    // example of valid param uri : fileShare:///com.example.FileShare/person/10
    // example of convertUri : fileShare://com.example.FileShare
    size_t schemePos = uri.find(PARAM_URI_SEPARATOR);
    if (schemePos != uri.npos) {
        // 1. cut string
        size_t cutPos = uri.find(Constants::PATH_SEPARATOR, schemePos + PARAM_URI_SEPARATOR_LEN);
        if (cutPos != uri.npos) {
            convertUri = uri.substr(0, cutPos);
        }
        // 2. replace :/// with ://
        convertUri.replace(schemePos, PARAM_URI_SEPARATOR_LEN, URI_SEPARATOR);
    } else {
        if (convertUri.compare(0, DATA_PROXY_URI_PREFIX_LEN, DATA_PROXY_URI_PREFIX) != 0) {
            LOG_W(BMS_TAG_QUERY_EXTENSION, "invalid uri : %{private}s", uri.c_str());
            return false;
        }
    }
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    if (bundleInfos_.empty()) {
        LOG_W(BMS_TAG_QUERY_EXTENSION, "bundleInfos_ data is empty, uri:%{public}s", uri.c_str());
        return false;
    }
    for (const auto &item : bundleInfos_) {
        const InnerBundleInfo &info = item.second;
        if (info.IsDisabled()) {
            LOG_D(BMS_TAG_QUERY_EXTENSION, "app %{public}s is disabled", info.GetBundleName().c_str());
            continue;
        }

        int32_t responseUserId = info.GetResponseUserId(requestUserId);
        if (!info.GetApplicationEnabled(responseUserId)) {
            continue;
        }

        bool ret = info.FindExtensionAbilityInfoByUri(convertUri, extensionAbilityInfo);
        if (!ret) {
            continue;
        }
        info.GetApplicationInfo(
            ApplicationFlag::GET_APPLICATION_INFO_WITH_CERTIFICATE_FINGERPRINT, responseUserId,
            extensionAbilityInfo.applicationInfo);
        return true;
    }
    LOG_W(BMS_TAG_QUERY_EXTENSION, "QueryExtensionAbilityInfoByUri (%{public}s) failed.", convertUri.c_str());
    return false;
}

std::string BundleDataMgr::GetStringById(const std::string &bundleName, const std::string &moduleName,
    uint32_t resId, int32_t userId, const std::string &localeInfo)
{
    APP_LOGD("GetStringById:%{public}s , %{public}s, %{public}d", bundleName.c_str(), moduleName.c_str(), resId);
#ifdef GLOBAL_RESMGR_ENABLE
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    std::shared_ptr<OHOS::Global::Resource::ResourceManager> resourceManager =
        GetResourceManager(bundleName, moduleName, userId);
    if (resourceManager == nullptr) {
        APP_LOGW("InitResourceManager failed");
        return Constants::EMPTY_STRING;
    }
    std::string label;
    OHOS::Global::Resource::RState errValue = resourceManager->GetStringById(resId, label);
    if (errValue != OHOS::Global::Resource::RState::SUCCESS) {
        APP_LOGW("GetStringById failed, bundleName:%{public}s, id:%{public}d", bundleName.c_str(), resId);
        return Constants::EMPTY_STRING;
    }
    return label;
#else
    APP_LOGW("GLOBAL_RESMGR_ENABLE is false");
    return Constants::EMPTY_STRING;
#endif
}

std::string BundleDataMgr::GetIconById(
    const std::string &bundleName, const std::string &moduleName, uint32_t resId, uint32_t density, int32_t userId)
{
    APP_LOGI("GetIconById bundleName:%{public}s, moduleName:%{public}s, resId:%{public}d, density:%{public}d",
        bundleName.c_str(), moduleName.c_str(), resId, density);
#ifdef GLOBAL_RESMGR_ENABLE
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    std::shared_ptr<OHOS::Global::Resource::ResourceManager> resourceManager =
        GetResourceManager(bundleName, moduleName, userId);
    if (resourceManager == nullptr) {
        APP_LOGW("InitResourceManager failed");
        return Constants::EMPTY_STRING;
    }
    std::string base64;
    OHOS::Global::Resource::RState errValue = resourceManager->GetMediaBase64DataById(resId, base64, density);
    if (errValue != OHOS::Global::Resource::RState::SUCCESS) {
        APP_LOGW("GetIconById failed, bundleName:%{public}s, id:%{public}d", bundleName.c_str(), resId);
        return Constants::EMPTY_STRING;
    }
    return base64;
#else
    APP_LOGW("GLOBAL_RESMGR_ENABLE is false");
    return Constants::EMPTY_STRING;
#endif
}

#ifdef GLOBAL_RESMGR_ENABLE
std::shared_ptr<Global::Resource::ResourceManager> BundleDataMgr::GetResourceManager(
    const std::string &bundleName, const std::string &moduleName, int32_t userId, const std::string &localeInfo) const
{
    InnerBundleInfo innerBundleInfo;
    if (!GetInnerBundleInfoWithFlags(bundleName, BundleFlag::GET_BUNDLE_DEFAULT, innerBundleInfo, userId)) {
        APP_LOGW("can not find bundle %{public}s", bundleName.c_str());
        return nullptr;
    }
    int32_t responseUserId = innerBundleInfo.GetResponseUserId(userId);
    BundleInfo bundleInfo;
    innerBundleInfo.GetBundleInfo(BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, responseUserId);
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager(Global::Resource::CreateResourceManager());
    for (auto hapModuleInfo : bundleInfo.hapModuleInfos) {
        std::string moduleResPath;
        if (moduleName.empty() || moduleName == hapModuleInfo.moduleName) {
            moduleResPath = hapModuleInfo.hapPath.empty() ? hapModuleInfo.resourcePath : hapModuleInfo.hapPath;
        }
        if (!moduleResPath.empty()) {
            APP_LOGD("DistributedBms::InitResourceManager, moduleResPath: %{public}s", moduleResPath.c_str());
            if (!resourceManager->AddResource(moduleResPath.c_str())) {
                APP_LOGW("DistributedBms::InitResourceManager AddResource failed");
            }
        }
    }

    std::unique_ptr<Global::Resource::ResConfig> resConfig(Global::Resource::CreateResConfig());
#ifdef GLOBAL_I18_ENABLE
    std::map<std::string, std::string> configs;
    OHOS::Global::I18n::LocaleInfo locale(
        localeInfo.empty() ? Global::I18n::LocaleConfig::GetSystemLocale() : localeInfo, configs);
    resConfig->SetLocaleInfo(locale.GetLanguage().c_str(), locale.GetScript().c_str(), locale.GetRegion().c_str());
#endif
    resourceManager->UpdateResConfig(*resConfig);
    return resourceManager;
}
#endif

const std::vector<PreInstallBundleInfo> BundleDataMgr::GetAllPreInstallBundleInfos()
{
    std::vector<PreInstallBundleInfo> preInstallBundleInfos;
    LoadAllPreInstallBundleInfos(preInstallBundleInfos);
    return preInstallBundleInfos;
}

bool BundleDataMgr::ImplicitQueryInfoByPriority(const Want &want, int32_t flags, int32_t userId,
    AbilityInfo &abilityInfo, ExtensionAbilityInfo &extensionInfo) const
{
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        APP_LOGW("invalid userId");
        return false;
    }
    std::vector<AbilityInfo> abilityInfos;
    bool abilityValid =
        ImplicitQueryAbilityInfos(want, flags, requestUserId, abilityInfos) && (abilityInfos.size() > 0);
    std::vector<ExtensionAbilityInfo> extensionInfos;
    bool extensionValid =
        ImplicitQueryExtensionInfos(want, flags, requestUserId, extensionInfos) && (extensionInfos.size() > 0);
    if (!abilityValid && !extensionValid) {
        // both invalid
        APP_LOGW("can't find target AbilityInfo or ExtensionAbilityInfo");
        return false;
    }
    if (abilityValid && extensionValid) {
        // both valid
        if (abilityInfos[0].priority >= extensionInfos[0].priority) {
            APP_LOGD("find target AbilityInfo with higher priority, name : %{public}s", abilityInfos[0].name.c_str());
            abilityInfo = abilityInfos[0];
        } else {
            APP_LOGD("find target ExtensionAbilityInfo with higher priority, name : %{public}s",
                extensionInfos[0].name.c_str());
            extensionInfo = extensionInfos[0];
        }
    } else if (abilityValid) {
        // only ability valid
        APP_LOGD("find target AbilityInfo, name : %{public}s", abilityInfos[0].name.c_str());
        abilityInfo = abilityInfos[0];
    } else {
        // only extension valid
        APP_LOGD("find target ExtensionAbilityInfo, name : %{public}s", extensionInfos[0].name.c_str());
        extensionInfo = extensionInfos[0];
    }
    return true;
}

bool BundleDataMgr::ImplicitQueryInfos(const Want &want, int32_t flags, int32_t userId, bool withDefault,
    std::vector<AbilityInfo> &abilityInfos, std::vector<ExtensionAbilityInfo> &extensionInfos, bool &findDefaultApp)
{
    APP_LOGI("want : %{public}s, flags : %{public}d, userId : %{public}d, withDefault(bool) : %{public}d",
        want.ToString().c_str(), flags, userId, withDefault);
#ifdef BUNDLE_FRAMEWORK_DEFAULT_APP
    // step1 : find default infos
    if (withDefault && DefaultAppMgr::GetInstance().GetDefaultApplication(want, userId, abilityInfos, extensionInfos)) {
        APP_LOGI("find target default application");
        findDefaultApp = true;
        return true;
    }
    // step2 : find backup default infos
    if (withDefault &&
        DefaultAppMgr::GetInstance().GetDefaultApplication(want, userId, abilityInfos, extensionInfos, true)) {
        APP_LOGI("find target backup default application");
        findDefaultApp = true;
        return true;
    }
#endif
    // step3 : implicit query infos
    bool abilityRet =
        ImplicitQueryAbilityInfos(want, flags, userId, abilityInfos) && (abilityInfos.size() > 0);
    APP_LOGD("abilityRet: %{public}d, abilityInfos size: %{public}zu", abilityRet, abilityInfos.size());

    bool extensionRet =
        ImplicitQueryExtensionInfos(want, flags, userId, extensionInfos) && (extensionInfos.size() > 0);
    APP_LOGD("extensionRet: %{public}d, extensionInfos size: %{public}zu", extensionRet, extensionInfos.size());
    return abilityRet || extensionRet;
}

bool BundleDataMgr::GetAllDependentModuleNames(const std::string &bundleName, const std::string &moduleName,
    std::vector<std::string> &dependentModuleNames)
{
    APP_LOGD("GetAllDependentModuleNames bundleName: %{public}s, moduleName: %{public}s",
        bundleName.c_str(), moduleName.c_str());
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto item = bundleInfos_.find(bundleName);
    if (item == bundleInfos_.end()) {
        APP_LOGW("GetAllDependentModuleNames: bundleName:%{public}s not find", bundleName.c_str());
        return false;
    }
    const InnerBundleInfo &innerBundleInfo = item->second;
    return innerBundleInfo.GetAllDependentModuleNames(moduleName, dependentModuleNames);
}

void BundleDataMgr::UpdateRemovable(
    const std::string &bundleName, bool removable)
{
    APP_LOGD("UpdateRemovable %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        APP_LOGW("bundleName is empty");
        return;
    }

    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("can not find bundle %{public}s", bundleName.c_str());
        return;
    }

    if (infoItem->second.GetRemovable() != removable) {
        infoItem->second.UpdateRemovable(true, removable);
        SaveInnerBundleInfo(infoItem->second);
    }
}

void BundleDataMgr::UpdatePrivilegeCapability(
    const std::string &bundleName, const ApplicationInfo &appInfo)
{
    APP_LOGD("UpdatePrivilegeCapability %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        APP_LOGW("bundleName is empty");
        return;
    }

    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("can not find bundle %{public}s", bundleName.c_str());
        return;
    }

    infoItem->second.UpdatePrivilegeCapability(appInfo);
}

bool BundleDataMgr::FetchInnerBundleInfo(
    const std::string &bundleName, InnerBundleInfo &innerBundleInfo)
{
    APP_LOGD("FetchInnerBundleInfo %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        APP_LOGW("bundleName is empty");
        return false;
    }

    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("can not find bundle %{public}s", bundleName.c_str());
        return false;
    }

    innerBundleInfo = infoItem->second;
    return true;
}

#ifdef BUNDLE_FRAMEWORK_DEFAULT_APP
bool BundleDataMgr::QueryInfoAndSkillsByElement(int32_t userId, const Element& element,
    AbilityInfo& abilityInfo, ExtensionAbilityInfo& extensionInfo, std::vector<Skill>& skills) const
{
    APP_LOGD("begin to QueryInfoAndSkillsByElement.");
    const std::string& bundleName = element.bundleName;
    const std::string& moduleName = element.moduleName;
    const std::string& abilityName = element.abilityName;
    const std::string& extensionName = element.extensionName;
    Want want;
    ElementName elementName("", bundleName, abilityName, moduleName);
    want.SetElement(elementName);
    bool isAbility = !element.abilityName.empty();
    bool ret = false;
    if (isAbility) {
        // get ability info
        ret = ExplicitQueryAbilityInfo(want, GET_ABILITY_INFO_DEFAULT, userId, abilityInfo);
        if (!ret) {
            APP_LOGD("ExplicitQueryAbilityInfo failed, abilityName:%{public}s", element.abilityName.c_str());
            return false;
        }
    } else {
        // get extension info
        elementName.SetAbilityName(extensionName);
        want.SetElement(elementName);
        ret = ExplicitQueryExtensionInfo(want, GET_EXTENSION_INFO_DEFAULT, userId, extensionInfo);
        if (!ret) {
            APP_LOGD("ExplicitQueryExtensionInfo failed, extensionName:%{public}s", extensionName.c_str());
            return false;
        }
    }

    // get skills info
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    if (bundleInfos_.empty()) {
        APP_LOGW("bundleInfos_ is empty.");
        return false;
    }
    auto item = bundleInfos_.find(bundleName);
    if (item == bundleInfos_.end()) {
        APP_LOGW("can't find bundleName : %{public}s.", bundleName.c_str());
        return false;
    }
    const InnerBundleInfo& innerBundleInfo = item->second;
    if (isAbility) {
        std::string key;
        key.append(bundleName).append(".").append(abilityInfo.package).append(".").append(abilityName);
        APP_LOGD("begin to find ability skills, key : %{public}s.", key.c_str());
        for (const auto& infoItem : innerBundleInfo.GetInnerSkillInfos()) {
            if (infoItem.first == key) {
                skills = infoItem.second;
                APP_LOGD("find ability skills success.");
                break;
            }
        }
    } else {
        std::string key;
        key.append(bundleName).append(".").append(moduleName).append(".").append(extensionName);
        APP_LOGD("begin to find extension skills, key : %{public}s.", key.c_str());
        for (const auto& infoItem : innerBundleInfo.GetExtensionSkillInfos()) {
            if (infoItem.first == key) {
                skills = infoItem.second;
                APP_LOGD("find extension skills success.");
                break;
            }
        }
    }
    APP_LOGD("QueryInfoAndSkillsByElement success.");
    return true;
}

bool BundleDataMgr::GetElement(int32_t userId, const ElementName& elementName, Element& element) const
{
    APP_LOGD("begin to GetElement.");
    const std::string& bundleName = elementName.GetBundleName();
    const std::string& moduleName = elementName.GetModuleName();
    const std::string& abilityName = elementName.GetAbilityName();
    if (bundleName.empty() || moduleName.empty() || abilityName.empty()) {
        APP_LOGW("bundleName or moduleName or abilityName is empty.");
        return false;
    }
    Want want;
    want.SetElement(elementName);
    AbilityInfo abilityInfo;
    bool ret = ExplicitQueryAbilityInfo(want, GET_ABILITY_INFO_DEFAULT, userId, abilityInfo);
    if (ret) {
        APP_LOGD("ElementName is ability.");
        element.bundleName = bundleName;
        element.moduleName = moduleName;
        element.abilityName = abilityName;
        return true;
    }

    ExtensionAbilityInfo extensionInfo;
    ret = ExplicitQueryExtensionInfo(want, GET_EXTENSION_INFO_DEFAULT, userId, extensionInfo);
    if (ret) {
        APP_LOGD("ElementName is extension.");
        element.bundleName = bundleName;
        element.moduleName = moduleName;
        element.extensionName = abilityName;
        return true;
    }

    APP_LOGW("ElementName doesn't exist.");
    return false;
}
#endif

ErrCode BundleDataMgr::GetMediaData(const std::string &bundleName, const std::string &moduleName,
    const std::string &abilityName, std::unique_ptr<uint8_t[]> &mediaDataPtr, size_t &len, int32_t userId) const
{
    APP_LOGI("begin");
#ifdef GLOBAL_RESMGR_ENABLE
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }
    InnerBundleInfo innerBundleInfo;
    ErrCode errCode = GetInnerBundleInfoWithFlagsV9(
        bundleName, BundleFlag::GET_BUNDLE_DEFAULT, innerBundleInfo, requestUserId);
    if (errCode != ERR_OK) {
        return errCode;
    }
    AbilityInfo abilityInfo;
    errCode = FindAbilityInfoInBundleInfo(innerBundleInfo, moduleName, abilityName, abilityInfo);
    if (errCode != ERR_OK) {
        return errCode;
    }
    bool isEnable = false;
    int32_t responseUserId = innerBundleInfo.GetResponseUserId(requestUserId);
    errCode = innerBundleInfo.IsAbilityEnabledV9(abilityInfo, responseUserId, isEnable);
    if (errCode != ERR_OK) {
        return errCode;
    }
    if (!isEnable) {
        APP_LOGE("%{public}s ability disabled: %{public}s", bundleName.c_str(), abilityName.c_str());
        return ERR_BUNDLE_MANAGER_ABILITY_DISABLED;
    }
    std::shared_ptr<Global::Resource::ResourceManager> resourceManager =
        GetResourceManager(bundleName, abilityInfo.moduleName, responseUserId);
    if (resourceManager == nullptr) {
        APP_LOGE("InitResourceManager failed, bundleName:%{public}s", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    OHOS::Global::Resource::RState ret =
        resourceManager->GetMediaDataById(static_cast<uint32_t>(abilityInfo.iconId), len, mediaDataPtr);
    if (ret != OHOS::Global::Resource::RState::SUCCESS || mediaDataPtr == nullptr || len == 0) {
        APP_LOGE("GetMediaDataById failed, bundleName:%{public}s", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return ERR_OK;
#else
    return ERR_BUNDLE_MANAGER_GLOBAL_RES_MGR_ENABLE_DISABLED;
#endif
}

std::shared_mutex &BundleDataMgr::GetStatusCallbackMutex()
{
    return callbackMutex_;
}

std::vector<sptr<IBundleStatusCallback>> BundleDataMgr::GetCallBackList() const
{
    return callbackList_;
}

bool BundleDataMgr::UpdateQuickFixInnerBundleInfo(const std::string &bundleName,
    const InnerBundleInfo &innerBundleInfo)
{
    APP_LOGD("to update info:%{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        APP_LOGW("update info fail, empty bundle name");
        return false;
    }

    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("bundle:%{public}s info is not existed", bundleName.c_str());
        return false;
    }

    if (dataStorage_->SaveStorageBundleInfo(innerBundleInfo)) {
        bundleInfos_.at(bundleName) = innerBundleInfo;
        return true;
    }
    APP_LOGE("to update info:%{public}s failed", bundleName.c_str());
    return false;
}

bool BundleDataMgr::UpdateInnerBundleInfo(const InnerBundleInfo &innerBundleInfo)
{
    std::string bundleName = innerBundleInfo.GetBundleName();
    if (bundleName.empty()) {
        APP_LOGW("UpdateInnerBundleInfo failed, empty bundle name");
        return false;
    }
    APP_LOGD("UpdateInnerBundleInfo:%{public}s", bundleName.c_str());
    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("bundle:%{public}s info is not existed", bundleName.c_str());
        return false;
    }

    if (dataStorage_->SaveStorageBundleInfo(innerBundleInfo)) {
        bundleInfos_.at(bundleName) = innerBundleInfo;
        return true;
    }
    APP_LOGE("to update InnerBundleInfo:%{public}s failed", bundleName.c_str());
    return false;
}

bool BundleDataMgr::QueryOverlayInnerBundleInfo(const std::string &bundleName, InnerBundleInfo &info)
{
    APP_LOGD("start to query overlay innerBundleInfo");
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    if (bundleInfos_.find(bundleName) != bundleInfos_.end()) {
        info = bundleInfos_.at(bundleName);
        return true;
    }

    APP_LOGW("can not find bundle %{public}s", bundleName.c_str());
    return false;
}

void BundleDataMgr::SaveOverlayInfo(const std::string &bundleName, InnerBundleInfo &innerBundleInfo)
{
    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::ENABLED);
    if (!dataStorage_->SaveStorageBundleInfo(innerBundleInfo)) {
        APP_LOGE("update storage failed bundle:%{public}s", bundleName.c_str());
        return;
    }
    bundleInfos_.at(bundleName) = innerBundleInfo;
}

ErrCode BundleDataMgr::GetAppProvisionInfo(const std::string &bundleName, int32_t userId,
    AppProvisionInfo &appProvisionInfo)
{
    if (!HasUserId(userId)) {
        APP_LOGW("GetAppProvisionInfo user is not existed. bundleName:%{public}s", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("bundleName:%{public}s not exist", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    if (infoItem->second.GetApplicationBundleType() != BundleType::SHARED) {
        int32_t responseUserId = infoItem->second.GetResponseUserId(userId);
        if (responseUserId == Constants::INVALID_USERID) {
            return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
        }
    }
    if (!DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAppProvisionInfo(bundleName, appProvisionInfo)) {
        APP_LOGW("bundleName:%{public}s GetAppProvisionInfo failed.", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleDataMgr::GetProvisionMetadata(const std::string &bundleName, int32_t userId,
    std::vector<Metadata> &provisionMetadatas) const
{
    // Reserved interface
    return ERR_OK;
}

ErrCode BundleDataMgr::GetAllSharedBundleInfo(std::vector<SharedBundleInfo> &sharedBundles) const
{
    APP_LOGD("GetAllSharedBundleInfo");
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);

    for (const auto& [key, innerBundleInfo] : bundleInfos_) {
        if (innerBundleInfo.GetApplicationBundleType() != BundleType::SHARED) {
            continue;
        }
        SharedBundleInfo sharedBundleInfo;
        innerBundleInfo.GetSharedBundleInfo(sharedBundleInfo);
        sharedBundles.emplace_back(sharedBundleInfo);
    }

    return ERR_OK;
}

ErrCode BundleDataMgr::GetSharedBundleInfo(const std::string &bundleName, const std::string &moduleName,
    std::vector<SharedBundleInfo> &sharedBundles)
{
    APP_LOGD("GetSharedBundleInfo");
    if (bundleName.empty() || moduleName.empty()) {
        APP_LOGW("bundleName or moduleName is empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }

    std::vector<Dependency> dependencies;
    ErrCode errCode = GetSharedDependencies(bundleName, moduleName, dependencies);
    if (errCode != ERR_OK) {
        APP_LOGD("GetSharedDependencies failed errCode is %{public}d, bundleName:%{public}s",
            errCode, bundleName.c_str());
        return errCode;
    }

    for (const auto& dep : dependencies) {
        SharedBundleInfo sharedBundleInfo;
        errCode = GetSharedBundleInfoBySelf(dep.bundleName, sharedBundleInfo);
        if (errCode != ERR_OK) {
            APP_LOGD("GetSharedBundleInfoBySelf failed errCode is %{public}d, bundleName:%{public}s",
                errCode, bundleName.c_str());
            return errCode;
        }
        sharedBundles.emplace_back(sharedBundleInfo);
    }

    return ERR_OK;
}

ErrCode BundleDataMgr::GetSharedBundleInfoBySelf(const std::string &bundleName, SharedBundleInfo &sharedBundleInfo)
{
    APP_LOGD("GetSharedBundleInfoBySelf bundleName: %{public}s", bundleName.c_str());
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("GetSharedBundleInfoBySelf failed, can not find bundle %{public}s",
            bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    const InnerBundleInfo &innerBundleInfo = infoItem->second;
    if (innerBundleInfo.GetApplicationBundleType() != BundleType::SHARED) {
        APP_LOGW("GetSharedBundleInfoBySelf failed, the bundle(%{public}s) is not shared library",
            bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    innerBundleInfo.GetSharedBundleInfo(sharedBundleInfo);
    APP_LOGD("GetSharedBundleInfoBySelf(%{public}s) successfully)", bundleName.c_str());
    return ERR_OK;
}

ErrCode BundleDataMgr::GetSharedDependencies(const std::string &bundleName, const std::string &moduleName,
    std::vector<Dependency> &dependencies)
{
    APP_LOGD("GetSharedDependencies bundleName: %{public}s, moduleName: %{public}s",
        bundleName.c_str(), moduleName.c_str());
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto item = bundleInfos_.find(bundleName);
    if (item == bundleInfos_.end()) {
        APP_LOGW("GetSharedDependencies failed, can not find bundle %{public}s", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    const InnerBundleInfo &innerBundleInfo = item->second;
    if (!innerBundleInfo.GetAllSharedDependencies(moduleName, dependencies)) {
        APP_LOGW("GetSharedDependencies failed, can not find module %{public}s", moduleName.c_str());
        return ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST;
    }
    APP_LOGD("GetSharedDependencies(bundle %{public}s, module %{public}s) successfully)",
        bundleName.c_str(), moduleName.c_str());
    return ERR_OK;
}

bool BundleDataMgr::CheckHspVersionIsRelied(int32_t versionCode, const InnerBundleInfo &info) const
{
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    std::string hspBundleName = info.GetBundleName();
    if (versionCode == Constants::ALL_VERSIONCODE) {
        // uninstall hsp bundle, check other bundle denpendency
        return CheckHspBundleIsRelied(hspBundleName);
    }
    std::vector<std::string> hspModules = info.GetAllHspModuleNamesForVersion(static_cast<uint32_t>(versionCode));
    // check whether has higher version
    std::vector<uint32_t> versionCodes = info.GetAllHspVersion();
    for (const auto &item : versionCodes) {
        if (item > static_cast<uint32_t>(versionCode)) {
            return false;
        }
    }
    // check other bundle denpendency
    for (const auto &[bundleName, innerBundleInfo] : bundleInfos_) {
        if (bundleName == hspBundleName) {
            continue;
        }
        std::vector<Dependency> dependencyList = innerBundleInfo.GetDependencies();
        for (const auto &dependencyItem : dependencyList) {
            if (dependencyItem.bundleName == hspBundleName &&
                std::find(hspModules.begin(), hspModules.end(), dependencyItem.moduleName) != hspModules.end()) {
                return true;
            }
        }
    }
    return false;
}

bool BundleDataMgr::CheckHspBundleIsRelied(const std::string &hspBundleName) const
{
    for (const auto &[bundleName, innerBundleInfo] : bundleInfos_) {
        if (bundleName == hspBundleName) {
            continue;
        }
        std::vector<Dependency> dependencyList = innerBundleInfo.GetDependencies();
        for (const auto &dependencyItem : dependencyList) {
            if (dependencyItem.bundleName == hspBundleName) {
                return true;
            }
        }
    }
    return false;
}

ErrCode BundleDataMgr::GetSharedBundleInfo(const std::string &bundleName, int32_t flags, BundleInfo &bundleInfo)
{
    if (bundleName.empty()) {
        APP_LOGW("bundleName is empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }

    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("can not find bundle %{public}s", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    const InnerBundleInfo &innerBundleInfo = infoItem->second;
    innerBundleInfo.GetSharedBundleInfo(flags, bundleInfo);
    return ERR_OK;
}

bool BundleDataMgr::IsPreInstallApp(const std::string &bundleName)
{
    APP_LOGD("IsPreInstallApp bundleName: %{public}s", bundleName.c_str());
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto item = bundleInfos_.find(bundleName);
    if (item == bundleInfos_.end()) {
        APP_LOGW("IsPreInstallApp failed, can not find bundle %{public}s",
            bundleName.c_str());
        return false;
    }
    return item->second.GetIsPreInstallApp();
}

ErrCode BundleDataMgr::GetProxyDataInfos(const std::string &bundleName, const std::string &moduleName,
    int32_t userId, std::vector<ProxyData> &proxyDatas) const
{
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    InnerBundleInfo info;
    auto ret = GetInnerBundleInfoWithBundleFlagsV9(
        bundleName, static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE), info, userId);
    if (ret != ERR_OK) {
        APP_LOGD("GetProxyData failed for GetInnerBundleInfo failed, bundleName:%{public}s", bundleName.c_str());
        return ret;
    }
    return info.GetProxyDataInfos(moduleName, proxyDatas);
}

ErrCode BundleDataMgr::GetAllProxyDataInfos(int32_t userId, std::vector<ProxyData> &proxyDatas) const
{
    std::vector<BundleInfo> bundleInfos;
    auto ret = GetBundleInfosV9(
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE), bundleInfos, userId);
    if (ret != ERR_OK) {
        APP_LOGD("GetAllProxyDataInfos failed for GetBundleInfos failed");
        return ret;
    }
    for (const auto &bundleInfo : bundleInfos) {
        for (const auto &hapModuleInfo : bundleInfo.hapModuleInfos) {
            proxyDatas.insert(
                proxyDatas.end(), hapModuleInfo.proxyDatas.begin(), hapModuleInfo.proxyDatas.end());
        }
    }
    return ERR_OK;
}

std::string BundleDataMgr::GetBundleNameByAppId(const std::string &appId) const
{
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto it = std::find_if(bundleInfos_.cbegin(), bundleInfos_.cend(), [&appId](const auto &pair) {
        return appId == pair.second.GetAppId();
    });
    if (it == bundleInfos_.cend()) {
        APP_LOGW("invalid appId, can't find bundleName");
        return Constants::EMPTY_STRING;
    }
    return it->second.GetBundleName();
}

void BundleDataMgr::SetAOTCompileStatus(const std::string &bundleName, const std::string &moduleName,
    AOTCompileStatus aotCompileStatus, uint32_t versionCode)
{
    APP_LOGD("SetAOTCompileStatus, bundleName : %{public}s, moduleName : %{public}s, aotCompileStatus : %{public}d",
        bundleName.c_str(), moduleName.c_str(), aotCompileStatus);
    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto item = bundleInfos_.find(bundleName);
    if (item == bundleInfos_.end()) {
        APP_LOGW("bundleName %{public}s not exist", bundleName.c_str());
        (void)InstalldClient::GetInstance()->RemoveDir(Constants::ARK_CACHE_PATH + bundleName);
        return;
    }
    if (item->second.GetVersionCode() != versionCode) {
        APP_LOGW("versionCode inconsistent, param : %{public}u, current : %{public}u, bundleName:%{public}s",
            versionCode, item->second.GetVersionCode(), bundleName.c_str());
        return;
    }
    item->second.SetAOTCompileStatus(moduleName, aotCompileStatus);
    std::string abi;
    std::string path;
    if (aotCompileStatus == AOTCompileStatus::COMPILE_SUCCESS) {
        abi = Constants::ARM64_V8A;
        path = Constants::ARM64 + Constants::PATH_SEPARATOR;
    }
    item->second.SetArkNativeFileAbi(abi);
    item->second.SetArkNativeFilePath(path);
    if (!dataStorage_->SaveStorageBundleInfo(item->second)) {
        APP_LOGW("SaveStorageBundleInfo failed bundleName:%{public}s", bundleName.c_str());
    }
}

void BundleDataMgr::ResetAOTFlags()
{
    APP_LOGI("ResetAOTFlags begin");
    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
    std::for_each(bundleInfos_.begin(), bundleInfos_.end(), [this](auto &item) {
        item.second.ResetAOTFlags();
        if (!dataStorage_->SaveStorageBundleInfo(item.second)) {
            APP_LOGW("SaveStorageBundleInfo failed, bundleName : %{public}s", item.second.GetBundleName().c_str());
        }
    });
    APP_LOGI("ResetAOTFlags end");
}

void BundleDataMgr::ResetAOTFlagsCommand(const std::string &bundleName)
{
    APP_LOGI("ResetAOTFlagsCommand begin");
    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto item = bundleInfos_.find(bundleName);
    if (item == bundleInfos_.end()) {
        APP_LOGE("bundleName %{public}s not exist", bundleName.c_str());
        return;
    }
    item->second.ResetAOTFlags();
    if (!dataStorage_->SaveStorageBundleInfo(item->second)) {
        APP_LOGW("SaveStorageBundleInfo failed, bundleName : %{public}s", item->second.GetBundleName().c_str());
        return;
    }
    APP_LOGI("ResetAOTFlagsCommand end");
}

ErrCode BundleDataMgr::ResetAOTCompileStatus(const std::string &bundleName, const std::string &moduleName,
    int32_t triggerMode)
{
    APP_LOGI("ResetAOTCompileStatus begin");
    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto item = bundleInfos_.find(bundleName);
    if (item == bundleInfos_.end()) {
        APP_LOGE("bundleName %{public}s not exist", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    ErrCode ret = item->second.ResetAOTCompileStatus(moduleName);
    if (ret != ERR_OK) {
        return ret;
    }
    if (!dataStorage_->SaveStorageBundleInfo(item->second)) {
        APP_LOGW("SaveStorageBundleInfo failed, bundleName : %{public}s", item->second.GetBundleName().c_str());
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    APP_LOGI("ResetAOTCompileStatus end");
    return ERR_OK;
}

std::vector<std::string> BundleDataMgr::GetAllBundleName() const
{
    APP_LOGD("GetAllBundleName begin");
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    std::vector<std::string> bundleNames;
    bundleNames.reserve(bundleInfos_.size());
    std::transform(bundleInfos_.cbegin(), bundleInfos_.cend(), std::back_inserter(bundleNames), [](const auto &item) {
        return item.first;
    });
    return bundleNames;
}

bool BundleDataMgr::QueryInnerBundleInfo(const std::string &bundleName, InnerBundleInfo &info) const
{
    APP_LOGD("QueryInnerBundleInfo begin, bundleName : %{public}s", bundleName.c_str());
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto item = bundleInfos_.find(bundleName);
    if (item == bundleInfos_.end()) {
        APP_LOGW("QueryInnerBundleInfo failed, bundleName:%{public}s", bundleName.c_str());
        return false;
    }
    info = item->second;
    return true;
}

std::vector<int32_t> BundleDataMgr::GetUserIds(const std::string &bundleName) const
{
    APP_LOGD("GetUserIds begin, bundleName : %{public}s", bundleName.c_str());
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    std::vector<int32_t> userIds;
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("can't find bundleName : %{public}s", bundleName.c_str());
        return userIds;
    }
    auto userInfos = infoItem->second.GetInnerBundleUserInfos();
    std::transform(userInfos.cbegin(), userInfos.cend(), std::back_inserter(userIds), [](const auto &item) {
        return item.second.bundleUserInfo.userId;
    });
    return userIds;
}

ErrCode BundleDataMgr::GetSpecifiedDistributionType(
    const std::string &bundleName, std::string &specifiedDistributionType)
{
    APP_LOGD("GetSpecifiedDistributionType bundleName: %{public}s", bundleName.c_str());
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("bundleName: %{public}s does not exist", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    if (infoItem->second.GetApplicationBundleType() != BundleType::SHARED) {
        int32_t userId = AccountHelper::GetCurrentActiveUserId();
        int32_t responseUserId = infoItem->second.GetResponseUserId(userId);
        if (responseUserId == Constants::INVALID_USERID) {
            APP_LOGW("bundleName: %{public}s does not exist in current userId", bundleName.c_str());
            return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
        }
    }
    if (!DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetSpecifiedDistributionType(bundleName,
        specifiedDistributionType)) {
        APP_LOGW("bundleName:%{public}s GetSpecifiedDistributionType failed.", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleDataMgr::GetAdditionalInfo(
    const std::string &bundleName, std::string &additionalInfo)
{
    APP_LOGD("GetAdditionalInfo bundleName: %{public}s", bundleName.c_str());
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("bundleName: %{public}s does not exist", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    if (infoItem->second.GetApplicationBundleType() != BundleType::SHARED) {
        int32_t userId = AccountHelper::GetCurrentActiveUserId();
        int32_t responseUserId = infoItem->second.GetResponseUserId(userId);
        if (responseUserId == Constants::INVALID_USERID) {
            APP_LOGW("bundleName: %{public}s does not exist in current userId", bundleName.c_str());
            return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
        }
    }
    if (!DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAdditionalInfo(bundleName,
        additionalInfo)) {
        APP_LOGW("bundleName:%{public}s GetAdditionalInfo failed.", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleDataMgr::SetExtNameOrMIMEToApp(const std::string &bundleName, const std::string &moduleName,
    const std::string &abilityName, const std::string &extName, const std::string &mimeType)
{
    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto item = bundleInfos_.find(bundleName);
    if (item == bundleInfos_.end()) {
        APP_LOGW("bundleName %{public}s not exist", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    ErrCode ret;
    if (!extName.empty()) {
        ret = item->second.SetExtName(moduleName, abilityName, extName);
        if (ret != ERR_OK) {
            APP_LOGD("set ext name to app failed, bundleName:%{public}s", bundleName.c_str());
            return ret;
        }
    }
    if (!mimeType.empty()) {
        ret = item->second.SetMimeType(moduleName, abilityName, mimeType);
        if (ret != ERR_OK) {
            APP_LOGD("set mime type to app failed, bundleName:%{public}s", bundleName.c_str());
            return ret;
        }
    }
    if (!dataStorage_->SaveStorageBundleInfo(item->second)) {
        APP_LOGE("SaveStorageBundleInfo failed, bundleName:%{public}s", bundleName.c_str());
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleDataMgr::DelExtNameOrMIMEToApp(const std::string &bundleName, const std::string &moduleName,
    const std::string &abilityName, const std::string &extName, const std::string &mimeType)
{
    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto item = bundleInfos_.find(bundleName);
    if (item == bundleInfos_.end()) {
        APP_LOGW("bundleName %{public}s not exist", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    ErrCode ret;
    if (!extName.empty()) {
        ret = item->second.DelExtName(moduleName, abilityName, extName);
        if (ret != ERR_OK) {
            APP_LOGD("delete ext name to app failed, bundleName:%{public}s", bundleName.c_str());
            return ret;
        }
    }
    if (!mimeType.empty()) {
        ret = item->second.DelMimeType(moduleName, abilityName, mimeType);
        if (ret != ERR_OK) {
            APP_LOGD("delete mime type to app failed, bundleName:%{public}s", bundleName.c_str());
            return ret;
        }
    }
    if (!dataStorage_->SaveStorageBundleInfo(item->second)) {
        APP_LOGE("SaveStorageBundleInfo failed, bundleName:%{public}s", bundleName.c_str());
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    return ERR_OK;
}

bool BundleDataMgr::MatchPrivateType(const Want &want,
    const std::vector<std::string> &supportExtNames, const std::vector<std::string> &supportMimeTypes) const
{
    APP_LOGD("MatchPrivateType, uri is %{public}s", want.GetUriString().c_str());
    std::string uri = want.GetUriString();
    auto suffixIndex = uri.rfind('.');
    if (suffixIndex == std::string::npos) {
        return false;
    }
    std::string suffix = uri.substr(suffixIndex + 1);
    bool supportPrivateType = std::any_of(supportExtNames.begin(), supportExtNames.end(), [&](const auto &extName) {
        return extName == suffix;
    });
    if (supportPrivateType) {
        APP_LOGI("uri is a supported private-type file");
        return true;
    }
    std::vector<std::string> mimeTypes;
    bool ret = MimeTypeMgr::GetMimeTypeByUri(uri, mimeTypes);
    if (!ret) {
        return false;
    }
    auto iter = std::find_first_of(
        mimeTypes.begin(), mimeTypes.end(), supportMimeTypes.begin(), supportMimeTypes.end());
    if (iter != mimeTypes.end()) {
        APP_LOGI("uri is a supported mime-type file");
        return true;
    }
    return false;
}

bool BundleDataMgr::QueryAppGalleryAbilityName(std::string &bundleName, std::string &abilityName)
{
    APP_LOGD("QueryAppGalleryAbilityName called");
    AbilityInfo abilityInfo;
    ExtensionAbilityInfo extensionInfo;
    Want want;
    want.SetAction(FREE_INSTALL_ACTION);
    if (!ImplicitQueryInfoByPriority(
        want, 0, Constants::ANY_USERID, abilityInfo, extensionInfo)) {
        APP_LOGD("ImplicitQueryInfoByPriority for action %{public}s failed", FREE_INSTALL_ACTION);
        return false;
    }
    if (!abilityInfo.name.empty()) {
        bundleName = abilityInfo.bundleName;
        abilityName = abilityInfo.name;
    } else {
        bundleName = extensionInfo.bundleName;
        abilityName = extensionInfo.name;
    }

    if (bundleName.empty() || abilityName.empty()) {
        APP_LOGW("bundleName: %{public}s or abilityName: %{public}s is empty()",
            bundleName.c_str(), abilityName.c_str());
        return false;
    }
    APP_LOGD("QueryAppGalleryAbilityName bundleName: %{public}s, abilityName: %{public}s",
        bundleName.c_str(), abilityName.c_str());
    return true;
}

ErrCode BundleDataMgr::GetJsonProfile(ProfileType profileType, const std::string &bundleName,
    const std::string &moduleName, std::string &profile, int32_t userId) const
{
    APP_LOGD("profileType: %{public}d, bundleName: %{public}s, moduleName: %{public}s",
        profileType, bundleName.c_str(), moduleName.c_str());
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }
    auto mapItem = PROFILE_TYPE_MAP.find(profileType);
    if (mapItem == PROFILE_TYPE_MAP.end()) {
        APP_LOGE("profileType: %{public}d is invalid", profileType);
        return ERR_BUNDLE_MANAGER_PROFILE_NOT_EXIST;
    }
    std::string profilePath = mapItem->second;
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    const auto &item = bundleInfos_.find(bundleName);
    if (item == bundleInfos_.end()) {
        APP_LOGE("bundleName: %{public}s is not found", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    const InnerBundleInfo &bundleInfo = item->second;
    bool isEnabled = false;
    int32_t responseUserId = bundleInfo.GetResponseUserId(requestUserId);
    ErrCode res = bundleInfo.GetApplicationEnabledV9(responseUserId, isEnabled);
    if (res != ERR_OK) {
        APP_LOGE("check application enabled failed, bundleName: %{public}s", bundleName.c_str());
        return res;
    }
    if (!isEnabled) {
        APP_LOGE("bundleName: %{public}s is disabled", bundleInfo.GetBundleName().c_str());
        return ERR_BUNDLE_MANAGER_APPLICATION_DISABLED;
    }
    std::string moduleNameTmp = moduleName;
    if (moduleName.empty()) {
        APP_LOGW("moduleName is empty, try to get profile from entry module");
        std::map<std::string, InnerModuleInfo> moduleInfos = bundleInfo.GetInnerModuleInfos();
        for (const auto &info : moduleInfos) {
            if (info.second.isEntry) {
                moduleNameTmp = info.second.moduleName;
                APP_LOGW("try to get profile from entry module: %{public}s", moduleNameTmp.c_str());
                break;
            }
        }
    }
    auto moduleInfo = bundleInfo.GetInnerModuleInfoByModuleName(moduleNameTmp);
    if (!moduleInfo) {
        APP_LOGE("moduleName: %{public}s is not found", moduleNameTmp.c_str());
        return ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST;
    }
    return GetJsonProfileByExtractor(moduleInfo->hapPath, profilePath, profile);
}

ErrCode __attribute__((no_sanitize("cfi"))) BundleDataMgr::GetJsonProfileByExtractor(const std::string &hapPath,
    const std::string &profilePath, std::string &profile) const
{
    APP_LOGD("GetJsonProfileByExtractor with hapPath %{private}s and profilePath %{private}s",
        hapPath.c_str(), profilePath.c_str());
    BundleExtractor bundleExtractor(hapPath);
    if (!bundleExtractor.Init()) {
        APP_LOGE("bundle extractor init failed");
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    if (!bundleExtractor.HasEntry(profilePath)) {
        APP_LOGE("profile not exist");
        return ERR_BUNDLE_MANAGER_PROFILE_NOT_EXIST;
    }
    std::stringstream profileStream;
    if (!bundleExtractor.ExtractByName(profilePath, profileStream)) {
        APP_LOGE("extract profile failed");
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    profile = profileStream.str();
    return ERR_OK;
}

bool BundleDataMgr::QueryDataGroupInfos(const std::string &bundleName, int32_t userId,
    std::vector<DataGroupInfo> &infos) const
{
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGW("bundleName: %{public}s is not existed", bundleName.c_str());
        return false;
    }
    auto dataGroupInfos = infoItem->second.GetDataGroupInfos();
    for (const auto &item : dataGroupInfos) {
        auto dataGroupIter = std::find_if(std::begin(item.second), std::end(item.second),
            [userId](const DataGroupInfo &info) {
            return info.userId == userId;
        });
        if (dataGroupIter != std::end(item.second)) {
            infos.push_back(*dataGroupIter);
        }
    }
    return true;
}

bool BundleDataMgr::GetGroupDir(const std::string &dataGroupId, std::string &dir, int32_t userId) const
{
    if (userId == Constants::UNSPECIFIED_USERID) {
        userId = AccountHelper::GetCurrentActiveUserId();
    }
    std::string uuid;
    if (BundlePermissionMgr::IsSystemApp() &&
        BundlePermissionMgr::VerifyCallingPermissionForAll(Constants::PERMISSION_GET_BUNDLE_INFO_PRIVILEGED)) {
        std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
        for (const auto &item : bundleInfos_) {
            const auto &dataGroupInfos = item.second.GetDataGroupInfos();
            auto dataGroupInfosIter = dataGroupInfos.find(dataGroupId);
            if (dataGroupInfosIter == dataGroupInfos.end()) {
                continue;
            }
            auto dataInUserIter = std::find_if(std::begin(dataGroupInfosIter->second),
                std::end(dataGroupInfosIter->second),
                [userId](const DataGroupInfo &info) { return info.userId == userId; });
            if (dataInUserIter != std::end(dataGroupInfosIter->second)) {
                uuid = dataInUserIter->uuid;
                break;
            }
        }
    } else {
        int32_t callingUid = IPCSkeleton::GetCallingUid();
        InnerBundleInfo innerBundleInfo;
        if (GetInnerBundleInfoByUid(callingUid, innerBundleInfo) != ERR_OK) {
            APP_LOGD("verify uid failed, callingUid is %{public}d", callingUid);
            return false;
        }
        const auto &dataGroupInfos = innerBundleInfo.GetDataGroupInfos();
        auto dataGroupInfosIter = dataGroupInfos.find(dataGroupId);
        if (dataGroupInfosIter == dataGroupInfos.end()) {
            APP_LOGW("calling bundle do not have dataGroupId: %{public}s", dataGroupId.c_str());
            return false;
        }
        auto dataGroupIter = std::find_if(std::begin(dataGroupInfosIter->second), std::end(dataGroupInfosIter->second),
            [userId](const DataGroupInfo &info) {
            return info.userId == userId;
        });
        if (dataGroupIter != std::end(dataGroupInfosIter->second)) {
            uuid = dataGroupIter->uuid;
        }
    }
    if (uuid.empty()) {
        APP_LOGW("get uuid by data group id failed");
        return false;
    }
    dir = Constants::REAL_DATA_PATH + Constants::PATH_SEPARATOR + std::to_string(userId)
        + Constants::DATA_GROUP_PATH + uuid;
    APP_LOGD("groupDir: %{private}s", dir.c_str());
    return true;
}

void BundleDataMgr::GenerateDataGroupUuidAndUid(DataGroupInfo &dataGroupInfo, int32_t userId,
    std::map<std::string, std::pair<int32_t, std::string>> &dataGroupIndexMap) const
{
    std::set<int32_t> indexList;
    for (auto iter = dataGroupIndexMap.begin(); iter != dataGroupIndexMap.end(); iter++) {
        indexList.emplace(iter->second.first);
    }
    int32_t index = DATA_GROUP_INDEX_START;
    for (int32_t i = DATA_GROUP_INDEX_START; i < DATA_GROUP_UID_OFFSET; i++) {
        if (indexList.find(i) == indexList.end()) {
            index = i;
            break;
        }
    }

    int32_t uid = userId * Constants::BASE_USER_RANGE + index + DATA_GROUP_UID_OFFSET;
    dataGroupInfo.uid = uid;
    dataGroupInfo.gid = uid;

    std::string str = BundleUtil::GenerateUuid();
    dataGroupInfo.uuid = str;
    dataGroupIndexMap[dataGroupInfo.dataGroupId] = std::pair<int32_t, std::string>(index, str);
}

void BundleDataMgr::GenerateDataGroupInfos(InnerBundleInfo &innerBundleInfo,
    const std::vector<std::string> &dataGroupIdList, int32_t userId) const
{
    APP_LOGD("GenerateDataGroupInfos called for user: %{public}d", userId);
    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
    if (dataGroupIdList.empty() || bundleInfos_.empty()) {
        APP_LOGW("dataGroupIdList or bundleInfos_ data is empty");
        return;
    }
    std::map<std::string, std::pair<int32_t, std::string>> dataGroupIndexMap;
    GetDataGroupIndexMap(dataGroupIndexMap);
    for (const std::string &groupId : dataGroupIdList) {
        DataGroupInfo dataGroupInfo;
        dataGroupInfo.dataGroupId = groupId;
        dataGroupInfo.userId = userId;
        auto iter = dataGroupIndexMap.find(groupId);
        if (iter != dataGroupIndexMap.end()) {
            dataGroupInfo.uuid = iter->second.second;
            int32_t uid = iter->second.first + userId * Constants::BASE_USER_RANGE + DATA_GROUP_UID_OFFSET;
            dataGroupInfo.uid = uid;
            dataGroupInfo.gid = uid;
            innerBundleInfo.AddDataGroupInfo(groupId, dataGroupInfo);
            continue;
        }
        GenerateDataGroupUuidAndUid(dataGroupInfo, userId, dataGroupIndexMap);
        innerBundleInfo.AddDataGroupInfo(groupId, dataGroupInfo);
    }
}

void BundleDataMgr::GetDataGroupIndexMap(
    std::map<std::string, std::pair<int32_t, std::string>> &dataGroupIndexMap) const
{
    for (const auto &bundleInfo : bundleInfos_) {
        for (const auto &infoItem : bundleInfo.second.GetDataGroupInfos()) {
            for_each(std::begin(infoItem.second), std::end(infoItem.second), [&](const DataGroupInfo &dataGroupInfo) {
                int32_t index = dataGroupInfo.uid - dataGroupInfo.userId * Constants::BASE_USER_RANGE
                    - DATA_GROUP_UID_OFFSET;
                dataGroupIndexMap[dataGroupInfo.dataGroupId] =
                    std::pair<int32_t, std::string>(index, dataGroupInfo.uuid);
            });
        }
    }
}

bool BundleDataMgr::IsShareDataGroupId(const std::string &dataGroupId, int32_t userId) const
{
    APP_LOGD("IsShareDataGroupId, dataGroupId is %{public}s", dataGroupId.c_str());
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    int32_t count = 0;
    for (const auto &info : bundleInfos_) {
        auto dataGroupInfos = info.second.GetDataGroupInfos();
        auto iter = dataGroupInfos.find(dataGroupId);
        if (iter == dataGroupInfos.end()) {
            continue;
        }

        auto dataGroupIter = std::find_if(std::begin(iter->second), std::end(iter->second),
            [userId](const DataGroupInfo &dataGroupInfo) {
            return dataGroupInfo.userId == userId;
        });
        if (dataGroupIter == std::end(iter->second)) {
            continue;
        }
        count++;
        if (count > 1) {
            APP_LOGW("dataGroupId: %{public}s is shared", dataGroupId.c_str());
            return true;
        }
    }
    return false;
}

ErrCode BundleDataMgr::FindAbilityInfoInBundleInfo(const InnerBundleInfo &innerBundleInfo,
    const std::string &moduleName, const std::string &abilityName, AbilityInfo &abilityInfo) const
{
    if (moduleName.empty()) {
        auto ability = innerBundleInfo.FindAbilityInfoV9(moduleName, abilityName);
        if (!ability) {
            return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
        }
        abilityInfo = *ability;
        return ERR_OK;
    }

    ErrCode ret = innerBundleInfo.FindAbilityInfo(moduleName, abilityName, abilityInfo);
    if (ret != ERR_OK) {
        APP_LOGD("%{public}s:FindAbilityInfo failed: %{public}d", innerBundleInfo.GetBundleName().c_str(), ret);
    }
    return ret;
}

#ifdef BUNDLE_FRAMEWORK_OVERLAY_INSTALLATION
bool BundleDataMgr::UpdateOverlayInfo(const InnerBundleInfo &newInfo, InnerBundleInfo &oldInfo)
{
    InnerBundleInfo targetInnerBundleInfo;
    std::string targetBundleName = newInfo.GetTargetBundleName();
    auto targetInfoItem = bundleInfos_.find(targetBundleName);
    if (targetInfoItem != bundleInfos_.end()) {
        targetInnerBundleInfo = targetInfoItem->second;
    }

    if (OverlayDataMgr::GetInstance()->UpdateOverlayInfo(newInfo, oldInfo, targetInnerBundleInfo) != ERR_OK) {
        APP_LOGW("update overlay info failed");
        return false;
    }
    // storage target bundle info
    if (!targetInnerBundleInfo.GetBundleName().empty() &&
        dataStorage_->SaveStorageBundleInfo(targetInnerBundleInfo)) {
        bundleInfos_.at(targetInnerBundleInfo.GetBundleName()) = targetInnerBundleInfo;
    }
    // build overlay connection for external overlay
    if (newInfo.GetOverlayType() == NON_OVERLAY_TYPE) {
        const auto &moduleInfos = newInfo.GetInnerModuleInfos();
        std::string moduleName = (moduleInfos.begin()->second).moduleName;
        BuildExternalOverlayConnection(moduleName, oldInfo, newInfo.GetUserId());
    }
    return true;
}

void BundleDataMgr::ResetExternalOverlayModuleState(const std::string &bundleName, const std::string &modulePackage)
{
    for (auto &info : bundleInfos_) {
        if (info.second.GetTargetBundleName() != bundleName) {
            continue;
        }
        const auto &innerModuleInfos = info.second.GetInnerModuleInfos();
        for (const auto &moduleInfo : innerModuleInfos) {
            if (moduleInfo.second.targetModuleName == modulePackage) {
                info.second.SetOverlayModuleState(moduleInfo.second.moduleName, OverlayState::OVERLAY_INVALID);
                break;
            }
        }
        if (!dataStorage_->SaveStorageBundleInfo(info.second)) {
            APP_LOGW("update storage success bundle:%{public}s", info.second.GetBundleName().c_str());
        }
    }
}

void BundleDataMgr::BuildExternalOverlayConnection(const std::string &moduleName, InnerBundleInfo &oldInfo,
    int32_t userId)
{
    APP_LOGD("start to update external overlay connection of module %{public}s under user %{public}d",
        moduleName.c_str(), userId);
    for (auto &info : bundleInfos_) {
        if (info.second.GetTargetBundleName() != oldInfo.GetBundleName()) {
            continue;
        }
        // check target bundle is preInstall application
        if (!oldInfo.GetIsPreInstallApp()) {
            APP_LOGW("target bundle is not preInstall application");
            return;
        }

        // check fingerprint of current bundle with target bundle
        if (oldInfo.GetCertificateFingerprint() != info.second.GetCertificateFingerprint()) {
            APP_LOGW("target bundle has different fingerprint with current bundle");
            return;
        }
        // external overlay does not support FA model
        if (!oldInfo.GetIsNewVersion()) {
            APP_LOGW("target bundle is not stage model");
            return;
        }
        // external overlay does not support service
        if (oldInfo.GetEntryInstallationFree()) {
            APP_LOGW("target bundle is service");
            return;
        }

        const auto &innerModuleInfos = info.second.GetInnerModuleInfos();
        std::vector<std::string> overlayModuleVec;
        for (const auto &moduleInfo : innerModuleInfos) {
            if (moduleInfo.second.targetModuleName != moduleName) {
                continue;
            }
            OverlayModuleInfo overlayModuleInfo;
            overlayModuleInfo.bundleName = info.second.GetBundleName();
            overlayModuleInfo.moduleName = moduleInfo.second.moduleName;
            overlayModuleInfo.targetModuleName = moduleInfo.second.targetModuleName;
            overlayModuleInfo.hapPath = info.second.GetModuleHapPath(moduleInfo.second.moduleName);
            overlayModuleInfo.priority = moduleInfo.second.targetPriority;
            oldInfo.AddOverlayModuleInfo(overlayModuleInfo);
            overlayModuleVec.emplace_back(moduleInfo.second.moduleName);
        }
        std::string bundleDir;
        const std::string &moduleHapPath =
            info.second.GetModuleHapPath((innerModuleInfos.begin()->second).moduleName);
        OverlayDataMgr::GetInstance()->GetBundleDir(moduleHapPath, bundleDir);
        OverlayBundleInfo overlayBundleInfo;
        overlayBundleInfo.bundleName = info.second.GetBundleName();
        overlayBundleInfo.bundleDir = bundleDir;
        overlayBundleInfo.state = info.second.GetOverlayState();
        overlayBundleInfo.priority = info.second.GetTargetPriority();
        oldInfo.AddOverlayBundleInfo(overlayBundleInfo);
        auto userSet = GetAllUser();
        for (const auto &innerUserId : userSet) {
            for (const auto &overlayModule : overlayModuleVec) {
                int32_t state = OverlayState::OVERLAY_INVALID;
                info.second.GetOverlayModuleState(overlayModule, innerUserId, state);
                if (state == OverlayState::OVERLAY_INVALID) {
                    info.second.SetOverlayModuleState(overlayModule, OVERLAY_ENABLE, innerUserId);
                }
            }
            dataStorage_->SaveStorageBundleInfo(info.second);
        }
    }
}

void BundleDataMgr::RemoveOverlayInfoAndConnection(const InnerBundleInfo &innerBundleInfo,
    const std::string &bundleName)
{
    if (innerBundleInfo.GetOverlayType() == OVERLAY_EXTERNAL_BUNDLE) {
        std::string targetBundleName = innerBundleInfo.GetTargetBundleName();
        auto targetInfoItem = bundleInfos_.find(targetBundleName);
        if (targetInfoItem == bundleInfos_.end()) {
            APP_LOGW("target bundle(%{public}s) is not installed", targetBundleName.c_str());
        } else {
            InnerBundleInfo targetInnerBundleInfo = bundleInfos_.at(targetBundleName);
            OverlayDataMgr::GetInstance()->RemoveOverlayBundleInfo(bundleName, targetInnerBundleInfo);
            if (dataStorage_->SaveStorageBundleInfo(targetInnerBundleInfo)) {
                APP_LOGD("update storage success bundle:%{public}s", bundleName.c_str());
                bundleInfos_.at(targetBundleName) = targetInnerBundleInfo;
            }
        }
    }

    if (innerBundleInfo.GetOverlayType() == NON_OVERLAY_TYPE) {
        for (auto &info : bundleInfos_) {
            if (info.second.GetTargetBundleName() != bundleName) {
                continue;
            }
            const auto &innerModuleInfos = info.second.GetInnerModuleInfos();
            for (const auto &moduleInfo : innerModuleInfos) {
                info.second.SetOverlayModuleState(moduleInfo.second.moduleName, OverlayState::OVERLAY_INVALID);
            }
            dataStorage_->SaveStorageBundleInfo(info.second);
        }
    }
}
#endif

bool BundleDataMgr::GetOldAppIds(const std::string &bundleName, std::vector<std::string> &appIds) const
{
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty.");
        return false;
    }
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto innerBundleInfo = bundleInfos_.find(bundleName);
    if (innerBundleInfo == bundleInfos_.end()) {
        APP_LOGE("can not find bundle %{public}s.", bundleName.c_str());
        return false;
    }
    appIds = innerBundleInfo->second.GetOldAppIds();
    return true;
}

bool BundleDataMgr::IsUpdateInnerBundleInfoSatisified(const InnerBundleInfo &oldInfo,
    const InnerBundleInfo &newInfo) const
{
    return newInfo.GetApplicationBundleType() == BundleType::APP_SERVICE_FWK ||
        !oldInfo.HasEntry() || oldInfo.GetEntryInstallationFree() || newInfo.HasEntry();
}

std::string BundleDataMgr::GetModuleNameByBundleAndAbility(
    const std::string& bundleName, const std::string& abilityName)
{
    if (bundleName.empty() || abilityName.empty()) {
        APP_LOGE("bundleName or abilityName is empty");
        return std::string();
    }
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto innerBundleInfo = bundleInfos_.find(bundleName);
    if (innerBundleInfo == bundleInfos_.end()) {
        APP_LOGE("can not find bundle %{public}s.", bundleName.c_str());
        return std::string();
    }
    auto abilityInfo = innerBundleInfo->second.FindAbilityInfoV9(Constants::EMPTY_STRING, abilityName);
    if (!abilityInfo) {
        APP_LOGE("bundleName:%{public}s, abilityName:%{public}s can find moduleName",
            bundleName.c_str(), abilityName.c_str());
        return std::string();
    }
    return abilityInfo->moduleName;
}

ErrCode BundleDataMgr::SetAdditionalInfo(const std::string& bundleName, const std::string& additionalInfo) const
{
    APP_LOGD("Called. BundleName: %{public}s", bundleName.c_str());
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGE("BundleName: %{public}s does not exist", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    if (infoItem->second.GetApplicationBundleType() != BundleType::SHARED) {
        int32_t userId = AccountHelper::GetCurrentActiveUserId();
        int32_t responseUserId = infoItem->second.GetResponseUserId(userId);
        if (responseUserId == Constants::INVALID_USERID) {
            APP_LOGE("BundleName: %{public}s does not exist in current userId", bundleName.c_str());
            return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
        }
    }

    auto appProvisionInfoManager = DelayedSingleton<AppProvisionInfoManager>::GetInstance();
    if (appProvisionInfoManager == nullptr) {
        APP_LOGE("Failed, appProvisionInfoManager is nullptr.");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }

    if (!appProvisionInfoManager->SetAdditionalInfo(bundleName, additionalInfo)) {
        APP_LOGE("BundleName: %{public}s set additional info failed.", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }

    ElementName element;
    element.SetBundleName(bundleName);
    OHOS::AAFwk::Want want;
    want.SetAction(BMS_EVENT_ADDITIONAL_INFO_CHANGED);
    want.SetElement(element);
    EventFwk::CommonEventData commonData { want };
    NotifyBundleEventCallback(commonData);
    return ERR_OK;
}

ErrCode BundleDataMgr::GetAppServiceHspBundleInfo(const std::string &bundleName, BundleInfo &bundleInfo)
{
    APP_LOGD("start, bundleName:%{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }

    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGD("can not find bundle %{public}s", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    const InnerBundleInfo &innerBundleInfo = infoItem->second;
    if (innerBundleInfo.GetAppServiceHspInfo(bundleInfo) != ERR_OK) {
        APP_LOGD("failed");
        return ERR_BUNDLE_MANAGER_PERMISSION_DENIED;
    }
    return ERR_OK;
}

void BundleDataMgr::ConvertServiceHspToSharedBundleInfo(const InnerBundleInfo &innerBundleInfo,
    std::vector<BaseSharedBundleInfo> &baseSharedBundleInfos) const
{
    APP_LOGD("start");
    BundleInfo bundleInfo;
    if (innerBundleInfo.GetAppServiceHspInfo(bundleInfo) == ERR_OK) {
        APP_LOGD("get app service hsp bundleName:%{public}s", innerBundleInfo.GetBundleName().c_str());
        for (const auto &hapModule : bundleInfo.hapModuleInfos) {
            BaseSharedBundleInfo baseSharedBundleInfo;
            baseSharedBundleInfo.bundleName = bundleInfo.name;
            baseSharedBundleInfo.moduleName = hapModule.moduleName;
            baseSharedBundleInfo.versionCode = bundleInfo.versionCode;
            baseSharedBundleInfo.nativeLibraryPath = hapModule.nativeLibraryPath;
            baseSharedBundleInfo.hapPath = hapModule.hapPath;
            baseSharedBundleInfo.compressNativeLibs = hapModule.compressNativeLibs;
            baseSharedBundleInfo.nativeLibraryFileNames = hapModule.nativeLibraryFileNames;
            baseSharedBundleInfos.emplace_back(baseSharedBundleInfo);
        }
        return;
    }
    APP_LOGW("GetAppServiceHspInfo failed, bundleName:%{public}s", innerBundleInfo.GetBundleName().c_str());
}

void BundleDataMgr::AddAppHspBundleName(const BundleType type, const std::string &bundleName)
{
    if (type == BundleType::APP_SERVICE_FWK) {
        APP_LOGD("add app hsp bundleName:%{pubcli}s", bundleName.c_str());
        std::lock_guard<std::mutex> hspLock(hspBundleNameMutex_);
        appServiceHspBundleName_.insert(bundleName);
    }
}

ErrCode BundleDataMgr::CreateBundleDataDir(int32_t userId) const
{
    APP_LOGI("CreateBundleDataDir with userId %{public}d begin", userId);
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    std::vector<CreateDirParam> createDirParams;
    for (const auto &item : bundleInfos_) {
        const InnerBundleInfo &info = item.second;
        int32_t responseUserId = info.GetResponseUserId(userId);
        if (responseUserId == Constants::INVALID_USERID) {
            APP_LOGW("bundle %{public}s is not installed in user %{public}d or 0",
                info.GetBundleName().c_str(), userId);
            continue;
        }
        CreateDirParam createDirParam;
        createDirParam.bundleName = info.GetBundleName();
        createDirParam.userId = responseUserId;
        createDirParam.uid = info.GetUid(responseUserId);
        createDirParam.gid = info.GetGid(responseUserId);
        createDirParam.apl = info.GetAppPrivilegeLevel();
        createDirParam.isPreInstallApp = info.GetIsPreInstallApp();
        createDirParam.debug = info.GetBaseApplicationInfo().debug;
        createDirParam.createDirFlag = CreateDirFlag::CREATE_DIR_UNLOCKED;
        createDirParams.emplace_back(createDirParam);
    }
    lock.unlock();
    auto res = InstalldClient::GetInstance()->CreateBundleDataDirWithVector(createDirParams);
    APP_LOGI("CreateBundleDataDir result: %{public}d", res);
    return res;
}

ErrCode BundleDataMgr::CanOpenLink(
    const std::string &link, bool &canOpen) const
{
    APP_LOGI("CanOpenLink link: %{public}s", link.c_str());
    auto uid = IPCSkeleton::GetCallingUid();
    InnerBundleInfo innerBundleInfo;
    if (GetInnerBundleInfoByUid(uid, innerBundleInfo) != ERR_OK) {
        APP_LOGE("get innerBundleInfo by uid :%{public}d failed.", uid);
        return ERR_BUNDLE_MANAGER_SCHEME_NOT_IN_QUERYSCHEMES;
    }
    auto querySchemes = innerBundleInfo.GetQuerySchemes();
    if (querySchemes.empty()) {
        APP_LOGI("querySchemes is empty.");
        return ERR_BUNDLE_MANAGER_SCHEME_NOT_IN_QUERYSCHEMES;
    }

    size_t pos = link.find(SCHEME_END);
    if (pos == std::string::npos) {
        APP_LOGE("parse link : %{public}s failed.", link.c_str());
        return ERR_BUNDLE_MANAGER_INVALID_SCHEME;
    }
    std::string scheme = link.substr(0, pos);
    transform(scheme.begin(), scheme.end(), scheme.begin(), ::tolower);
    if (std::find(querySchemes.begin(), querySchemes.end(), scheme) == querySchemes.end()) {
        APP_LOGI("scheme :%{public}s is not in the querySchemes.", scheme.c_str());
        return ERR_BUNDLE_MANAGER_SCHEME_NOT_IN_QUERYSCHEMES;
    }

    Want want;
    want.SetUri(link);
    std::vector<AbilityInfo> abilityInfos;
    // implicit query
    ErrCode ret = ImplicitQueryAbilityInfosV9(
        want, static_cast<uint32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_DEFAULT), GetUserIdByUid(uid), abilityInfos);
    if (ret != ERR_OK) {
        APP_LOGD("implicit queryAbilityInfosV9 error");
        return ERR_BUNDLE_MANAGER_SCHEME_NOT_IN_QUERYSCHEMES;
    }

    canOpen = !abilityInfos.empty();
    APP_LOGI("canOpen : %{public}d", canOpen);
    return ERR_OK;
}

void BundleDataMgr::GenerateOdid(const std::string &developerId, std::string &odid) const
{
    APP_LOGD("start, developerId:%{public}s", developerId.c_str());
    if (developerId.empty()) {
        APP_LOGE("developerId is empty");
        return;
    }
    std::string groupId = BundleUtil::ExtractGroupIdByDevelopId(developerId);
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    for (const auto &item : bundleInfos_) {
        std::string developerIdExist;
        std::string odidExist;
        item.second.GetDeveloperidAndOdid(developerIdExist, odidExist);
        std::string groupIdExist = BundleUtil::ExtractGroupIdByDevelopId(developerIdExist);
        if (groupId == groupIdExist) {
            odid = odidExist;
            return;
        }
    }
    odid = BundleUtil::GenerateUuid();
    APP_LOGI("developerId:%{public}s is not existed local, need to generate an odid %{private}s",
        developerId.c_str(), odid.c_str());
}

ErrCode BundleDataMgr::GetOdid(std::string &odid) const
{
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    APP_LOGI("start GetOdid, callingUid %{public}d", callingUid);
    InnerBundleInfo innerBundleInfo;
    if (GetInnerBundleInfoByUid(callingUid, innerBundleInfo) != ERR_OK) {
        if (sandboxAppHelper_ == nullptr) {
            APP_LOGE("sandboxAppHelper_ is nullptr");
            return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
        }
        if (sandboxAppHelper_->GetInnerBundleInfoByUid(callingUid, innerBundleInfo) != ERR_OK) {
            APP_LOGW("app that corresponds to the callingUid %{public}d could not be found", callingUid);
            return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
        }
    }
    std::string developerId;
    innerBundleInfo.GetDeveloperidAndOdid(developerId, odid);
    return ERR_OK;
}

void BundleDataMgr::updateTsanEnabled(const InnerBundleInfo &newInfo, InnerBundleInfo &oldInfo) const
{
    if (newInfo.GetTsanEnabled()) {
        oldInfo.SetTsanEnabled(true);
    }
    if (oldInfo.GetVersionCode() < newInfo.GetVersionCode()) {
        oldInfo.SetTsanEnabled(newInfo.GetTsanEnabled());
    }
}

void BundleDataMgr::ProcessAllowedAcls(const InnerBundleInfo &newInfo, InnerBundleInfo &oldInfo) const
{
    if (oldInfo.GetVersionCode() < newInfo.GetVersionCode()) {
        oldInfo.SetAllowedAcls(newInfo.GetAllowedAcls());
        return;
    }
    oldInfo.AddAllowedAcls(newInfo.GetAllowedAcls());
}

void BundleDataMgr::updateAppEnvironments(const InnerBundleInfo &newInfo, InnerBundleInfo &oldInfo) const
{
    const auto &innerModuleInfos = oldInfo.GetInnerModuleInfos();
    bool flag = true;
    for (const auto &innerModuleInfo : oldInfo.GetInnerModuleInfos()) {
        if (innerModuleInfo.second.distro.moduleType == ENTRY) {
            flag = false;
        }
    }
    if (flag || (oldInfo.GetVersionCode() < newInfo.GetVersionCode())) {
        oldInfo.SetAppEnvironments(newInfo.GetAppEnvironments());
    }
}

void BundleDataMgr::updateMaxChildProcess(const InnerBundleInfo &newInfo, InnerBundleInfo &oldInfo) const
{
    const auto &innerModuleInfos = oldInfo.GetInnerModuleInfos();
    bool flag = true;
    for (const auto &innerModuleInfo : oldInfo.GetInnerModuleInfos()) {
        if (innerModuleInfo.second.distro.moduleType == ENTRY) {
            flag = false;
        }
    }
    if (flag || (oldInfo.GetVersionCode() < newInfo.GetVersionCode())) {
        oldInfo.SetMaxChildProcess(newInfo.GetMaxChildProcess());
    }
}

ErrCode BundleDataMgr::GetAllBundleInfoByDeveloperId(const std::string &developerId,
    std::vector<BundleInfo> &bundleInfos, int32_t userId)
{
    int32_t requestUserId = GetUserId(userId);
    APP_LOGI("requestUserId: %{public}d", requestUserId);
    if (requestUserId == Constants::INVALID_USERID) {
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }

    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    if (bundleInfos_.empty()) {
        APP_LOGW("bundleInfos_ data is empty");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    for (const auto &item : bundleInfos_) {
        const InnerBundleInfo &innerBundleInfo = item.second;
        if (innerBundleInfo.GetApplicationBundleType() == BundleType::SHARED ||
            innerBundleInfo.GetApplicationBundleType() == BundleType::APP_SERVICE_FWK) {
            APP_LOGD("app %{public}s is cross-app shared bundle or appService, ignore",
                innerBundleInfo.GetBundleName().c_str());
            continue;
        }

        int32_t responseUserId = innerBundleInfo.GetResponseUserId(requestUserId);
        auto flag = GET_BASIC_APPLICATION_INFO;
        if (CheckInnerBundleInfoWithFlags(innerBundleInfo, flag, responseUserId) != ERR_OK) {
            continue;
        }
        // check developerId
        std::string developerIdExist;
        std::string odidExist;
        innerBundleInfo.GetDeveloperidAndOdid(developerIdExist, odidExist);
        if (developerIdExist != developerId) {
            continue;
        }

        BundleInfo bundleInfo;

        if (innerBundleInfo.GetBundleInfoV9(static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION),
            bundleInfo, responseUserId) != ERR_OK) {
            continue;
        }
        bundleInfos.emplace_back(bundleInfo);
    }
    if (bundleInfos.empty()) {
        APP_LOGW("bundleInfos is empty");
        return ERR_BUNDLE_MANAGER_INVALID_DEVELOPERID;
    }
    APP_LOGI("have %{public}d applications, their developerId is %{public}s", requestUserId, developerId.c_str());
    return ERR_OK;
}

ErrCode BundleDataMgr::GetDeveloperIds(const std::string &appDistributionType,
    std::vector<std::string> &developerIdList, int32_t userId)
{
    int32_t requestUserId = GetUserId(userId);
    APP_LOGI("requestUserId: %{public}d", requestUserId);
    if (requestUserId == Constants::INVALID_USERID) {
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }

    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    if (bundleInfos_.empty()) {
        APP_LOGW("bundleInfos_ data is empty");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    std::set<std::string> developerIdSet;
    for (const auto &item : bundleInfos_) {
        const InnerBundleInfo &innerBundleInfo = item.second;
        if (innerBundleInfo.GetApplicationBundleType() == BundleType::SHARED ||
            innerBundleInfo.GetApplicationBundleType() == BundleType::APP_SERVICE_FWK) {
            APP_LOGD("app %{public}s is cross-app shared bundle or appService, ignore",
                innerBundleInfo.GetBundleName().c_str());
            continue;
        }

        int32_t responseUserId = innerBundleInfo.GetResponseUserId(requestUserId);
        auto flag = GET_BASIC_APPLICATION_INFO;
        if (CheckInnerBundleInfoWithFlags(innerBundleInfo, flag, responseUserId) != ERR_OK) {
            continue;
        }
        // check appDistributionType
        if (!appDistributionType.empty() && innerBundleInfo.GetAppDistributionType() != appDistributionType) {
            continue;
        }

        std::string developerIdExist;
        std::string odidExist;
        innerBundleInfo.GetDeveloperidAndOdid(developerIdExist, odidExist);
        developerIdSet.emplace(developerIdExist);
    }
    for (const std::string &developerId : developerIdSet) {
        developerIdList.emplace_back(developerId);
    }
    APP_LOGI("have %{public}d developers, their appDistributionType is %{public}s",
        static_cast<int32_t>(developerIdList.size()), appDistributionType.c_str());
    return ERR_OK;
}

ErrCode BundleDataMgr::SwitchUninstallState(const std::string &bundleName, const bool &state)
{
    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGE("BundleName: %{public}s does not exist", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    InnerBundleInfo &innerBundleInfo = infoItem->second;
    if (!innerBundleInfo.GetRemovable() && state) {
        APP_LOGW("the bundle : %{public}s is not removable", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_CAN_NOT_BE_UNINSTALLED;
    }
    if (innerBundleInfo.GetUninstallState() == state) {
        return ERR_OK;
    }
    innerBundleInfo.SetUninstallState(state);
    if (!dataStorage_->SaveStorageBundleInfo(innerBundleInfo)) {
        APP_LOGW("update storage failed bundle:%{public}s", bundleName.c_str());
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    return ERR_OK;
}

void BundleDataMgr::FilterAbilityInfosByAppLinking(const Want &want, int32_t flags,
    std::vector<AbilityInfo> &abilityInfos) const
{
#ifdef APP_DOMAIN_VERIFY_ENABLED
    APP_LOGD("FilterAbility start");
    if (abilityInfos.empty()) {
        APP_LOGD("abilityInfos is empty");
        return;
    }
    std::vector<AbilityInfo> filteredAbilityInfos;
    // call FiltedAbilityInfos
    APP_LOGI("call FilterAbilities");
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    if (!DelayedSingleton<AppDomainVerify::AppDomainVerifyMgrClient>::GetInstance()->FilterAbilities(
        want, abilityInfos, filteredAbilityInfos)) {
        APP_LOGE("FilterAbilities failed");
    }
    IPCSkeleton::SetCallingIdentity(identity);
    if ((static_cast<uint32_t>(flags) &
        static_cast<uint32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_APP_LINKING)) ==
        static_cast<uint32_t>(GetAbilityInfoFlag::GET_ABILITY_INFO_WITH_APP_LINKING)) {
        APP_LOGD("return filteredAbilityInfos");
        abilityInfos = filteredAbilityInfos;
        for (auto &abilityInfo : abilityInfos) {
            abilityInfo.linkType = LinkType::APP_LINK;
        }
        return;
    }
    for (auto &filteredAbilityInfo : filteredAbilityInfos) {
        for (auto &abilityInfo : abilityInfos) {
            if (filteredAbilityInfo.name == abilityInfo.name) {
                abilityInfo.linkType = LinkType::APP_LINK;
                break;
            }
        }
    }
    return;
#else
    APP_LOGI("AppDomainVerify is not enabled");
    return;
#endif
}

ErrCode BundleDataMgr::AddCloneBundle(const std::string &bundleName, const InnerBundleCloneInfo &attr)
{
    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGE("BundleName: %{public}s does not exist", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    InnerBundleInfo &innerBundleInfo = infoItem->second;
    ErrCode res = innerBundleInfo.AddCloneBundle(attr);
    if (res != ERR_OK) {
        APP_LOGE("innerBundleInfo addCloneBundleInfo fail");
        return res;
    }
    APP_LOGD("update bundle info in memory for add clone, userId: %{public}d, appIndex: %{public}d",
        attr.userId, attr.appIndex);
    auto nowBundleStatus = innerBundleInfo.GetBundleStatus();
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::ENABLED);
    if (!dataStorage_->SaveStorageBundleInfo(innerBundleInfo)) {
        innerBundleInfo.SetBundleStatus(nowBundleStatus);
        APP_LOGW("update storage failed bundle:%{public}s", bundleName.c_str());
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    innerBundleInfo.SetBundleStatus(nowBundleStatus);
    APP_LOGD("update bundle info in storage for add clone, userId: %{public}d, appIndex: %{public}d",
        attr.userId, attr.appIndex);
    return ERR_OK;
}

ErrCode BundleDataMgr::RemoveCloneBundle(const std::string &bundleName, const int32_t userId, int32_t appIndex)
{
    std::unique_lock<std::shared_mutex> lock(bundleInfoMutex_);
    auto infoItem = bundleInfos_.find(bundleName);
    if (infoItem == bundleInfos_.end()) {
        APP_LOGE("BundleName: %{public}s does not exist", bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    InnerBundleInfo &innerBundleInfo = infoItem->second;
    ErrCode res = innerBundleInfo.RemoveCloneBundle(userId, appIndex);
    if (res != ERR_OK) {
        APP_LOGE("innerBundleInfo RemoveCloneBundle fail");
        return res;
    }
    auto nowBundleStatus = innerBundleInfo.GetBundleStatus();
    innerBundleInfo.SetBundleStatus(InnerBundleInfo::BundleStatus::ENABLED);
    if (!dataStorage_->SaveStorageBundleInfo(innerBundleInfo)) {
        innerBundleInfo.SetBundleStatus(nowBundleStatus);
        APP_LOGW("update storage failed bundle:%{public}s", bundleName.c_str());
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    innerBundleInfo.SetBundleStatus(nowBundleStatus);
    return ERR_OK;
}

ErrCode BundleDataMgr::QueryAbilityInfoByContinueType(const std::string &bundleName,
    const std::string &continueType, AbilityInfo &abilityInfo, int32_t userId, int32_t appIndex) const
{
    int32_t requestUserId = GetUserId(userId);
    APP_LOGI("requestUserId: %{public}d", requestUserId);
    if (requestUserId == Constants::INVALID_USERID) {
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }

    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    if (bundleInfos_.empty()) {
        APP_LOGW("bundleInfos_ data is empty");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    InnerBundleInfo innerBundleInfo;
    if (appIndex == 0) {
        ErrCode ret = GetInnerBundleInfoWithFlagsV9(bundleName, 0, innerBundleInfo, requestUserId);
        if (ret != ERR_OK) {
            APP_LOGD("QueryAbilityInfoByContinueType failed, bundleName:%{public}s", bundleName.c_str());
            return ret;
        }
    }
    if (appIndex > 0) {
        if (sandboxAppHelper_ == nullptr) {
            APP_LOGW("sandboxAppHelper_ is nullptr");
            return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
        }
        auto ret = sandboxAppHelper_->GetSandboxAppInfo(bundleName, appIndex, requestUserId, innerBundleInfo);
        if (ret != ERR_OK) {
            APP_LOGD("obtain innerBundleInfo of sandbox app failed due to errCode %{public}d, bundleName:%{public}s",
                ret, bundleName.c_str());
            return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
        }
    }
    auto ability = innerBundleInfo.FindAbilityInfo(continueType, requestUserId);
    if (!ability) {
        APP_LOGW("ability not found, bundleName:%{public}s, coutinueType:%{public}s",
            bundleName.c_str(), continueType.c_str());
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }
    abilityInfo = (*ability);
    InnerBundleUserInfo innerBundleUserInfo;
    if (innerBundleInfo.GetInnerBundleUserInfo(userId, innerBundleUserInfo)) {
        abilityInfo.uid = innerBundleUserInfo.uid;
    }
    return ERR_OK;
}

ErrCode BundleDataMgr::QueryCloneAbilityInfo(const ElementName &element, int32_t flags, int32_t userId,
    int32_t appIndex, AbilityInfo &abilityInfo) const
{
    std::string bundleName = element.GetBundleName();
    std::string abilityName = element.GetAbilityName();
    std::string moduleName = element.GetModuleName();
    LOG_D(BMS_TAG_QUERY_ABILITY,
        "QueryCloneAbilityInfo bundleName:%{public}s moduleName:%{public}s abilityName:%{public}s",
        bundleName.c_str(), moduleName.c_str(), abilityName.c_str());
    LOG_D(BMS_TAG_QUERY_ABILITY, "flags:%{public}d userId:%{public}d", flags, userId);
    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    InnerBundleInfo innerBundleInfo;

    ErrCode ret = GetInnerBundleInfoWithFlagsV9(bundleName, flags, innerBundleInfo, requestUserId);
    if (ret != ERR_OK) {
        LOG_D(BMS_TAG_QUERY_ABILITY, "QueryCloneAbilityInfo fail bundleName:%{public}s", bundleName.c_str());
        return ret;
    }

    int32_t responseUserId = innerBundleInfo.GetResponseUserId(requestUserId);
    auto ability = innerBundleInfo.FindAbilityInfoV9(moduleName, abilityName);
    if (!ability) {
        LOG_W(BMS_TAG_QUERY_ABILITY, "not found bundleName:%{public}s moduleName:%{public}s abilityName:%{public}s",
            bundleName.c_str(), moduleName.c_str(), abilityName.c_str());
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }
    return QueryAbilityInfoWithFlagsV9(ability, flags, responseUserId, innerBundleInfo, abilityInfo, appIndex);
}

ErrCode BundleDataMgr::GetCloneBundleInfo(
    const std::string &bundleName, int32_t flags, int32_t appIndex, BundleInfo &bundleInfo, int32_t userId) const
{
    std::vector<InnerBundleUserInfo> innerBundleUserInfos;
    if (userId == Constants::ANY_USERID) {
        if (!GetInnerBundleUserInfos(bundleName, innerBundleUserInfos)) {
            LOG_W(BMS_TAG_QUERY_BUNDLE, "no userInfos for this bundle(%{public}s)", bundleName.c_str());
            return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
        }
        userId = innerBundleUserInfos.begin()->bundleUserInfo.userId;
    }

    int32_t requestUserId = GetUserId(userId);
    if (requestUserId == Constants::INVALID_USERID) {
        return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
    }
    std::shared_lock<std::shared_mutex> lock(bundleInfoMutex_);
    InnerBundleInfo innerBundleInfo;

    auto ret = GetInnerBundleInfoWithBundleFlagsV9(bundleName, flags, innerBundleInfo, requestUserId, appIndex);
    if (ret != ERR_OK) {
        LOG_D(BMS_TAG_QUERY_BUNDLE, "GetCloneBundleInfo failed, error code: %{public}d, bundleName:%{public}s",
            ret, bundleName.c_str());
        return ret;
    }

    int32_t responseUserId = innerBundleInfo.GetResponseUserId(requestUserId);
    innerBundleInfo.GetBundleInfoV9(flags, bundleInfo, responseUserId, appIndex);

    ProcessBundleMenu(bundleInfo, flags, true);
    ProcessBundleRouterMap(bundleInfo, flags);
    LOG_D(BMS_TAG_QUERY_BUNDLE, "get bundleInfo(%{public}s) successfully in user(%{public}d)",
        bundleName.c_str(), userId);
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS