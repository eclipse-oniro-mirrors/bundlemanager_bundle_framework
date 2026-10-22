/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

#include "bundle_mgr_service_event_handler.h"
#include "rdb_recover_manager.h"

#include <algorithm>
#include <chrono>
#include <map>
#include <set>
#include <sstream>
#include <sys/stat.h>
#include <thread>
#include <unordered_map>

#include "account_helper.h"
#include "access_token_error.h"
#include "aot/aot_handler.h"
#include "app_log_tag_wrapper.h"
#include "app_provision_info_manager.h"
#include "app_service_fwk_installer.h"
#include "access_token_error.h"
#include "accesstoken_kit.h"
#include "bms_extension_data_mgr.h"
#include "bms_key_event_mgr.h"
#include "dual_mode_helper.h"
#include "independent_skills_installer.h"
#include "skills_installer_util.h"
#include "bundle_access_token_recovery_mgr.h"
#include "bundle_install_checker.h"
#include "bundle_installer.h"
#include "bundle_parser.h"
#include "bundle_permission_mgr.h"
#include "bundle_resource_helper.h"
#include "bundle_resource_constants.h"
#include "bundle_spm_manager.h"
#include "bundle_scanner.h"
#include "event_report.h"
#include "on_demand_install_data_mgr.h"
#ifdef CONFIG_POLOCY_ENABLE
#include "config_policy_utils.h"
#endif
#include "datetime_ex.h"
#include "directory_ex.h"
#include "dual_mode_helper.h"
#if defined (BUNDLE_FRAMEWORK_SANDBOX_APP) && defined (DLP_PERMISSION_ENABLE)
#include "dlp_permission_kit.h"
#endif
#include "hmp_bundle_installer.h"
#include "idle_condition_mgr/idle_condition_event_subscribe.h"
#include "inner_bundle_clone_common.h"
#include "inner_patch_info.h"
#include "installd_client.h"
#include "install_exception_mgr.h"
#include "memory/memory_compactor.h"
#include "module_json_updater.h"
#include "new_bundle_data_dir_mgr.h"
#include "parameter.h"
#include "parameters.h"
#include "patch_data_mgr.h"
#include "perf_profile.h"
#ifdef WINDOW_ENABLE
#include "scene_board_judgement.h"
#endif
#include "scope_guard.h"
#include "status_receiver_host.h"
#include "system_bundle_installer.h"
#ifdef BUNDLE_FRAMEWORK_QUICK_FIX
#include "quick_fix_boot_scanner.h"
#endif
#include "user_unlocked_event_subscriber.h"
#include "xcollie_helper.h"
#include "xml_util.h"
#ifdef STORAGE_SERVICE_ENABLE
#include "storage_manager_proxy.h"
#include "iservice_registry.h"
#endif
#ifdef WEBVIEW_ENABLE
#include "app_fwk_update_client.h"
#endif

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* APP_SUFFIX = "/app";
constexpr const char* TEMP_PREFIX = "temp_";
constexpr const char* MODULE_PREFIX = "module_";
constexpr const char* PRE_INSTALL_HSP_PATH = "/shared_bundles/";
constexpr const char* BMS_TEST_UPGRADE = "persist.bms.test-upgrade";
constexpr const char* MODULE_UPDATE_PATH = "module_update";
constexpr const char* MODULE_UPDATE_PARAM = "persist.moduleupdate.bms.scan";
constexpr const char* MODULE_UPDATE_VALUE_UPDATE = "update";
constexpr const char* MODULE_UPDATE_VALUE_REVERT_BMS = "revert_bms";
constexpr const char* MODULE_UPDATE_VALUE_REVERT = "revert";
constexpr const char* MODULE_UPDATE_APP_SERVICE_DIR = "appServiceFwk";
constexpr const char* MODULE_UPDATE_INSTALL_RESULT = "persist.moduleupdate.bms.install.";
constexpr const char* MODULE_UPDATE_INSTALL_RESULT_FALSE = "false";
constexpr const char* MODULE_UPDATE_PARAM_EMPTY = "";
constexpr const char* FINGERPRINT = "fingerprint";
constexpr const char* UNKNOWN = "";
constexpr const char* VALUE_TRUE = "true";
constexpr const char* HAP_PATH_DATA_AREA = "/data/app/el1/bundle/public";
constexpr const char* DEVICE_TYPE_PHONE = "phone";

constexpr int8_t VERSION_LEN = 64;
const std::vector<std::string> FINGERPRINTS = {
    "const.product.software.version",
    "const.product.build.type",
    "const.product.brand",
    "const.product.name",
    "const.product.devicetype",
    "const.product.incremental.version",
    "const.comp.hl.product_base_version.real"
};
constexpr const char* OTA_FLAG = "otaFlag";
// pre bundle profile
constexpr const char* DEFAULT_PRE_BUNDLE_ROOT_DIR = "/system";
constexpr const char* MODULE_UPDATE_PRODUCT_SUFFIX = "/etc/app/module_update";
constexpr const char* INSTALL_LIST_CONFIG = "/install_list.json";
constexpr const char* APP_SERVICE_FWK_INSTALL_LIST_CONFIG = "/app_service_fwk_install_list.json";
constexpr const char* SKILLS_INSTALL_LIST_CONFIG = "/skill_install_list.json";
constexpr const char* UNINSTALL_LIST_CONFIG = "/uninstall_list.json";
constexpr const char* INSTALL_LIST_CAPABILITY_CONFIG = "/install_list_capability.json";
constexpr const char* EXTENSION_TYPE_LIST_CONFIG = "/extension_type_config.json";
constexpr const char* SHARED_BUNDLES_INSTALL_LIST_CONFIG = "/shared_bundles_install_list.json";
constexpr const char* SYSTEM_RESOURCES_APP_PATH = "/system/app/ohos.global.systemres";
constexpr const char* QUICK_FIX_APP_PATH = "/data/update/quickfix/app/temp/cold";
constexpr const char* SYSTEM_BUNDLE_PATH = "/internal";
constexpr const char* SHARED_BUNDLE_PATH = "/shared_bundles";
constexpr const char* VERSION_SPECIAL_CUSTOM_APP_DIR = "/version/special_cust/app/";
constexpr const char* RESTOR_BUNDLE_NAME_LIST = "list";
constexpr const char* QUICK_FIX_APP_RECOVER_FILE = "/data/update/quickfix/app/temp/quickfix_app_recover.json";
constexpr char SEPARATOR = '/';
constexpr const char* SYSTEM_RESOURCES_APP = "ohos.global.systemres";
constexpr const char* FOUNDATION_PROCESS_NAME = "foundation";
constexpr int32_t SCENE_ID_OTA_INSTALL = 3;
constexpr const char* PGO_FILE_PATH = "pgo_files";
constexpr const char* BUNDLE_SCAN_PARAM = "bms.scanning_apps.status";
constexpr const char* BUNDLE_SCAN_START = "0";
constexpr const char* BUNDLE_SCAN_FINISH = "1";
constexpr const char* CODE_PROTECT_FLAG = "codeProtectFlag";
constexpr const char* CODE_PROTECT_FLAG_CHECKED = "checked";
// db rebuild mark in bms_param table: set before rebuild writes anything into
// installed_bundle table, removed only after every bundle info is verified saved.
// Shared with RdbDataManager salvage recovery through ServiceConstants.
constexpr const char* KEY_STORAGE_SIZE = "storageSize";
constexpr int32_t USER_ID_SIZE = 1;
constexpr const char* APPSPAWN_PRELOAD_ARKWEB_ENGINE = "const.startup.appspawn.preload.arkwebEngine";
constexpr const char* OTA_NEW_INSTALL_ENABLE_PARAM = "const.bms.ota_new_install_enable";
constexpr const char* OTA_NEW_INSTALL_MULTIUSER_PARAM = "const.bms.multiUserInstallThirdPreloadApp";
constexpr const char* OOBE_AGREE_TERMS_EVENT = "custom.event.OOBE.HWSTARTUPGUIDE.FINISHED";
constexpr int32_t OTA_TIMEOUT_SECONDS = 60 * 9;
constexpr const char* OTA_SYSTEM_HSP_TASK = "OTA_SYSTEM_HSP_TASK";
constexpr const char* OTA_SHARED_HSP_TASK = "OTA_SHARED_HSP_TASK";
constexpr const char* OTA_PREINSTALL_BUNDLE_TASK = "OTA_PREINSTALL_BUNDLE_TASK";
constexpr const char* OTA_PATCH_BUNDLE_TASK = "OTA_PATCH_BUNDLE_TASK";
constexpr int64_t SCAN_TIMEOUT_MS = 5 * 60 * 1000;

std::set<PreScanInfo> installList_;
std::set<PreScanInfo> onDemandInstallList_;
std::set<PreScanInfo> systemHspList_;
std::set<PreScanInfo> skillsList_;
std::set<std::string> uninstallList_;
std::set<PreBundleConfigInfo> installListCapabilities_;
std::set<std::string> extensiontype_;
bool hasLoadPreInstallProFile_ = false;
std::vector<std::string> bundleNameList_;
std::set<int32_t> allUserIds_;
std::unordered_map<int32_t, std::vector<std::string>> xmlMap_;
std::unordered_map<std::string, std::set<int32_t>> needInstallUserIds_;

#ifdef STORAGE_SERVICE_ENABLE
#ifdef QUOTA_PARAM_SET_ENABLE
const std::string SYSTEM_PARAM_ATOMICSERVICE_DATASIZE_THRESHOLD =
    "persist.sys.bms.aging.policy.atomicservice.datasize.threshold";
const int32_t THRESHOLD_VAL_LEN = 20;
#endif // QUOTA_PARAM_SET_ENABLE
const int32_t STORAGE_MANAGER_MANAGER_ID = 5003;
#endif // STORAGE_SERVICE_ENABLE
const int32_t ATOMIC_SERVICE_DATASIZE_THRESHOLD_MB_PRESET = 1024;

void MoveTempPath(const std::vector<std::string> &fromPaths,
    const std::string &bundleName, std::vector<std::string> &toPaths)
{
    std::string tempDir =
        std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR + TEMP_PREFIX + bundleName;
    if (!BundleUtil::CreateDir(tempDir)) {
        LOG_E(BMS_TAG_DEFAULT, "create tempdir failed %{public}s", tempDir.c_str());
        return;
    }

    int32_t hapIndex = 0;
    for (const auto &path : fromPaths) {
        auto toPath = tempDir + ServiceConstants::PATH_SEPARATOR + MODULE_PREFIX
            + std::to_string(hapIndex) + ServiceConstants::INSTALL_FILE_SUFFIX;
        hapIndex++;
        if (InstalldClient::GetInstance()->MoveFile(path, toPath, BundleDirScene::MOVE_HAP_TO_TEMP_DIR, bundleName) !=
            ERR_OK) {
            LOG_W(BMS_TAG_DEFAULT, "move from %{public}s to %{public}s failed", path.c_str(), toPath.c_str());
            continue;
        }

        toPaths.emplace_back(toPath);
    }
}

// Fill the label/icon/description/moduleName/systemApp/bundleType fields of a
// PreInstallBundleInfo from the parsed haps, preferring the entry hap. Shared
// by the guard-recovery population (PopulatePreInstallInfoFromParse) and the
// on-demand install info conversion (ConvertToOnDemandInstallBundleInfo);
// mirrors the install-time needSavePreInstallInfo block in
// base_bundle_installer.cpp — keep the copies in sync when fields change.
void FillPreInstallResourceInfo(const std::unordered_map<std::string, InnerBundleInfo> &hapInfos,
    PreInstallBundleInfo &preInstallBundleInfo)
{
    for (const auto &hapInfo : hapInfos) {
        auto applicationInfo = hapInfo.second.GetBaseApplicationInfo();
        if (hapInfo.second.HasEntry() || preInstallBundleInfo.GetModuleName().empty()) {
            hapInfo.second.AdaptMainLauncherResourceInfo(applicationInfo, true);
            preInstallBundleInfo.SetLabelId(applicationInfo.labelResource.id);
            preInstallBundleInfo.SetIconId(applicationInfo.iconResource.id);
            preInstallBundleInfo.SetDescriptionId(applicationInfo.descriptionId);
            preInstallBundleInfo.SetModuleName(applicationInfo.labelResource.moduleName);
        }
        preInstallBundleInfo.SetSystemApp(applicationInfo.isSystemApp);
        auto moduleMap = hapInfo.second.GetInnerModuleInfos();
        if (hapInfo.second.GetIsNewVersion()) {
            preInstallBundleInfo.SetBundleType(hapInfo.second.GetApplicationBundleType());
        } else if (!moduleMap.empty() && moduleMap.begin()->second.distro.installationFree) {
            preInstallBundleInfo.SetBundleType(BundleType::ATOMIC_SERVICE);
        }
        if (!moduleMap.empty() && moduleMap.begin()->second.distro.moduleType == Profile::MODULE_TYPE_ENTRY) {
            break;
        }
    }
}

class InnerReceiverImpl : public StatusReceiverHost {
public:
    InnerReceiverImpl() = default;
    virtual ~InnerReceiverImpl() override = default;

    void SetBundleName(const std::string &bundleName)
    {
        bundleName_ = bundleName;
    }

    virtual void OnStatusNotify(const int progress) override {}
    virtual void OnFinished(
        const int32_t resultCode, const std::string &resultMsg) override
    {
        if (bundleName_.empty()) {
            LOG_D(BMS_TAG_DEFAULT, "bundleName_ is empty");
            return;
        }

        std::string tempDir = std::string(ServiceConstants::HAP_COPY_PATH)
            + ServiceConstants::PATH_SEPARATOR + TEMP_PREFIX + bundleName_;
        LOG_D(BMS_TAG_DEFAULT, "delete tempDir %{public}s", tempDir.c_str());
        BundleUtil::DeleteDir(tempDir);
    }

private:
    std::string bundleName_;
};
}

BMSEventHandler::BMSEventHandler()
{
    LOG_D(BMS_TAG_DEFAULT, "instance is created");
}

BMSEventHandler::~BMSEventHandler()
{
    LOG_D(BMS_TAG_DEFAULT, "instance is destroyed");
}

std::shared_ptr<BundleDataMgr> BMSEventHandler::GetDataMgrFromService()
{
    auto service = DelayedSingleton<BundleMgrService>::GetInstance();
    if (service == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "BundleMgrService instance is null");
        return nullptr;
    }
    return service->GetDataMgr();
}

void BMSEventHandler::BmsStartEvent()
{
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "BmsStartEvent start");
    BeforeBmsStart();
    OnBmsStarting();
    AfterBmsStart();
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "BmsStartEvent end");
}

void BMSEventHandler::BeforeBmsStart()
{
    needNotifyBundleScanStatus_ = false;
    if (!BundlePermissionMgr::Init()) {
        LOG_W(BMS_TAG_DEFAULT, "BundlePermissionMgr::Init failed");
    }

    scanStartTime_ = BundleUtil::GetCurrentTimeMs();
    EventReport::SendScanSysEvent(BMSEventType::BOOT_SCAN_START);
    if (SetParameter(BUNDLE_SCAN_PARAM, BUNDLE_SCAN_START) != 0) {
        LOG_E(BMS_TAG_DEFAULT, "set bms.scanning_apps.status 0 failed");
    }
}

void BMSEventHandler::OnBmsStarting()
{
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "BMSEventHandler OnBmsStarting start");
    ProcessCheckSystemOptimizeDir();
    // Judge whether there is install info in the persistent Db
    if (LoadInstallInfosFromDb()) {
        LOG_NOFUNC_I(BMS_TAG_DEFAULT, "OnBmsStarting Load install info from db success");
        BundleRebootStartEvent();
        return;
    }

    // If the preInstall infos does not exist in preInstall db,
    // all preInstall directory applications will be reinstalled.
    if (!LoadAllPreInstallBundleInfos()) {
        LOG_NOFUNC_E(BMS_TAG_DEFAULT, "OnBmsStarting Load all preInstall bundleInfos failed");
        needRebootOta_ = true;
    }

    /* Guard against install infos lossed strategy.
     * 1. Scan user data dir
     *   1.1. If no data, first boot.
     *   1.2. If has data, but parse data to InnerBundleUserInfos failed,
     *        reInstall all app from install dir and preInstall dir
     *   1.3. If has data and parse data to InnerBundleUserInfos success, goto 2
     * 2. Scan installDir include common install dir and preInstall dir
     *    And the parse the hap to InnerBundleInfos
     * 3. Combine InnerBundleInfos and InnerBundleUserInfos to cache and db
     * 4. According to needRebootOta determine whether OTA detection is required
     */
    ResultCode resultCode = GuardAgainstInstallInfosLossedStrategy();
    switch (resultCode) {
        case ResultCode::RECOVER_OK: {
            LOG_NOFUNC_I(BMS_TAG_DEFAULT, "OnBmsStarting Guard against install infos lossed strategy take effect");
            if (needRebootOta_) {
                BundleRebootStartEvent();
            } else {
                needNotifyBundleScanStatus_ = true;
                // Guard recover path does not go through BundleRebootStartEvent,
                // report main bundle status here, otherwise bootevent.bms.main.
                // bundles.ready will never be set and boot.completed can not fire.
                BmsKeyEventMgr::ProcessMainBundleStatusFinally();
            }

            break;
        }
        case ResultCode::REINSTALL_OK: {
            LOG_NOFUNC_I(BMS_TAG_DEFAULT, "OnBmsStarting ReInstall all haps");
            needNotifyBundleScanStatus_ = true;
            // Reinstall path does not go through BundleRebootStartEvent,
            // report main bundle status here, otherwise bootevent.bms.main.
            // bundles.ready will never be set and boot.completed can not fire.
            BmsKeyEventMgr::ProcessMainBundleStatusFinally();
            break;
        }
        case ResultCode::NO_INSTALLED_DATA: {
            // First boot
            LOG_NOFUNC_I(BMS_TAG_DEFAULT, "OnBmsStarting first boot");
            BundleBootStartEvent();
            break;
        }
        default:
            LOG_NOFUNC_E(BMS_TAG_DEFAULT, "System internal error, install informations missing");
            break;
    }

    SaveSystemFingerprint();
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "BMSEventHandler OnBmsStarting end");
}

void BMSEventHandler::AfterBmsStart()
{
    LOG_I(BMS_TAG_DEFAULT, "BMSEventHandler AfterBmsStart start");
    // need process install exception bundle
    DelayedSingleton<InstallExceptionMgr>::GetInstance()->HandleAllBundleExceptionInfo();
    DelayedSingleton<BundleMgrService>::GetInstance()->CheckAllUser();
    // process is online theme
    BundleResourceHelper::SetIsOnlineThemeWhenBoot();
    CreateAppInstallDir();
    SetAllInstallFlag();
    HandleSceneBoard();
    CleanTempDir();
    // Single mount point, placed right before the service is published: once RegisterService
    // makes BMS visible, dependents (launcher, appspawn) may query packages and spawn apps,
    // which requires valid tokens. Every startup path (db-loaded, guard recover, reinstall,
    // first boot) converges here. If the reset fails the persist parameter stays set and the
    // next boot retries the whole pass idempotently (mostly already-exist).
    BundleAccessTokenRecoveryMgr::ProcessRecovery(
        GetDataMgrFromService(), "AfterBmsStart");
    DelayedSingleton<BundleMgrService>::GetInstance()->RegisterService();
    // delay after regist
#ifdef BUNDLE_FRAMEWORK_QUICK_FIX
    if (OHOS::system::GetBoolParameter(ServiceConstants::DEVELOPERMODE_STATE, false)) {
        DelayedSingleton<QuickFixBootScanner>::GetInstance()->ProcessQuickFixBootUp();
    }
#endif
    BundleResourceHelper::RegisterCommonEventSubscriber();
    BundleResourceHelper::RegisterConfigurationObserver();
    EventReport::SendScanSysEvent(BMSEventType::BOOT_SCAN_END);
    if (SetParameter(BUNDLE_SCAN_PARAM, BUNDLE_SCAN_FINISH) != 0) {
        LOG_E(BMS_TAG_DEFAULT, "set bms.scanning_apps.status 1 failed");
    }
    ClearCache();
    if (needNotifyBundleScanStatus_) {
        int64_t endTime = BundleUtil::GetCurrentTimeMs();
        if (endTime - scanStartTime_ > SCAN_TIMEOUT_MS) {
            EventReport::SendScanTimeoutEvent(
                IsSystemUpgrade()? HighRiskOperationType::OTA_SCAN_TIMEOUT: HighRiskOperationType::BOOT_SCAN_TIMEOUT,
                scanStartTime_, endTime);
        }
        DelayedSingleton<BundleMgrService>::GetInstance()->NotifyBundleScanStatus();
    }
    BmsExtensionDataMgr bmsExtensionDataMgr;
    bmsExtensionDataMgr.BmsExtensionInit();
    ListeningUserUnlocked();
    RegisterOobeAgreeTermsEvent();
    RemoveUnreservedSandbox();
    ProcessCheckAppEl1Dir();
    ProcessCheckSystemOptimizeDir();
#ifdef WEBVIEW_ENABLE
    NotifyFWKAfterBmsStart();
#endif
    if (OHOS::system::GetBoolParameter(ServiceConstants::BMS_RELABEL_PARAM, false) ||
        OHOS::system::GetBoolParameter(ServiceConstants::BMS_SCAN_APP_DATA_PARAM, false) ||
        OHOS::system::GetBoolParameter(ServiceConstants::BMS_SCAN_FILE_CATEGORY_PARAM, false)) {
        APP_LOGI_NOFUNC("relabel or scan_app_data or scan_file_category is true");
        RegisterIdleConditionEvent();
    }
    MemoryCompactor::RegisterScreenOffListener();
    LOG_I(BMS_TAG_DEFAULT, "BMSEventHandler AfterBmsStart end");
}

#ifdef WEBVIEW_ENABLE
void BMSEventHandler::NotifyFWKAfterBmsStart()
{
    if (!OHOS::system::GetBoolParameter(APPSPAWN_PRELOAD_ARKWEB_ENGINE, false)) {
        LOG_W(BMS_TAG_DEFAULT, "APPSPAWN_PRELOAD_ARKWEB_ENGINE is false");
        return;
    }
    NWeb::AppFwkUpdateClient::GetInstance().NotifyFWKAfterBmsStart();
}
#endif

void BMSEventHandler::ClearCache()
{
    hapParseInfoMap_.clear();
    loadExistData_.clear();
    hasLoadAllPreInstallBundleInfosFromDb_ = false;
}

bool BMSEventHandler::LoadInstallInfosFromDb()
{
    // A leftover rebuild mark means the last rebuild was interrupted, so the
    // installed_bundle table may only hold part of the bundles. The db cannot
    // be trusted in this case, fall back to rebuild from install dirs again.
    if (IsRebuildInterrupted()) {
        LOG_E(BMS_TAG_DEFAULT, "last db rebuild was interrupted, need to rebuild again");
        return false;
    }
    LOG_I(BMS_TAG_DEFAULT, "Load install infos from db");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return false;
    }

    return dataMgr->LoadDataFromPersistentStorage();
}

bool BMSEventHandler::IsRebuildInterrupted()
{
    std::string failedSnapshot = RdbRecoverManager::BuildFailedSnapshotPath(
        ServiceConstants::BUNDLE_MANAGER_SERVICE_PATH, ServiceConstants::BUNDLE_RDB_NAME);
    return IsRebuildInterrupted(failedSnapshot);
}

bool BMSEventHandler::IsRebuildInterrupted(const std::string &failedSnapshotPath)
{
    auto bmsPara = DelayedSingleton<BundleMgrService>::GetInstance()->GetBmsParam();
    if (bmsPara != nullptr) {
        std::string mark;
        if (bmsPara->GetBmsParam(ServiceConstants::DB_REBUILD_MARK, mark) &&
            mark == ServiceConstants::DB_REBUILD_MARK_DOING) {
            return true;
        }
    }
    // a broken salvage snapshot means the rdb recovery gave up with possibly
    // incomplete data, the db cannot be trusted even though it is readable
    if (access(failedSnapshotPath.c_str(), F_OK) == 0) {
        LOG_W(BMS_TAG_DEFAULT, "salvage snapshot failed file exists, need to rebuild again");
        return true;
    }
    return false;
}

void BMSEventHandler::MarkRebuildStart()
{
    auto bmsPara = DelayedSingleton<BundleMgrService>::GetInstance()->GetBmsParam();
    if (bmsPara == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "bmsPara is nullptr");
        return;
    }

    if (!bmsPara->SaveBmsParam(ServiceConstants::DB_REBUILD_MARK,
        ServiceConstants::DB_REBUILD_MARK_DOING)) {
        LOG_E(BMS_TAG_DEFAULT, "save db rebuild mark failed");
    }
}

void BMSEventHandler::MarkRebuildFinish()
{
    std::string failedSnapshot = RdbRecoverManager::BuildFailedSnapshotPath(
        ServiceConstants::BUNDLE_MANAGER_SERVICE_PATH, ServiceConstants::BUNDLE_RDB_NAME);
    MarkRebuildFinish(failedSnapshot);
}

void BMSEventHandler::MarkRebuildFinish(const std::string &failedSnapshotPath)
{
    auto bmsPara = DelayedSingleton<BundleMgrService>::GetInstance()->GetBmsParam();
    if (bmsPara == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "bmsPara is nullptr");
        return;
    }

    if (!bmsPara->DeleteBmsParam(ServiceConstants::DB_REBUILD_MARK)) {
        LOG_E(BMS_TAG_DEFAULT, "delete db rebuild mark failed");
    }
    // the rebuild from install dirs just re-verified every bundle info, the
    // leftover failed salvage snapshot is no longer needed
    if (access(failedSnapshotPath.c_str(), F_OK) == 0 && unlink(failedSnapshotPath.c_str()) != 0) {
        LOG_E(BMS_TAG_DEFAULT, "delete failed salvage snapshot failed, errno:%{public}d", errno);
        // a leftover failed snapshot makes every boot distrust the db and run
        // the full install dir rescan, keep the failure visible in the events
        EventReport::SendDbErrorEvent(ServiceConstants::BUNDLE_RDB_NAME,
            static_cast<int32_t>(DB_OPERATION_TYPE::REBUILD), NativeRdb::E_SQLITE_IOERR);
    }
}

void BMSEventHandler::BundleBootStartEvent()
{
    EventReport::SendCpuSceneEvent(FOUNDATION_PROCESS_NAME, SCENE_ID_OTA_INSTALL);
    OnBundleBootStart(Constants::DEFAULT_USERID);
    InstalldClient::GetInstance()->ResetBmsDBSecurity();
#ifdef CHECK_ELDIR_ENABLED
    UpdateOtaFlag(OTAFlag::CHECK_ELDIR);
#endif
    UpdateOtaFlag(OTAFlag::CHECK_LOG_DIR);
    UpdateOtaFlag(OTAFlag::CHECK_FILE_MANAGER_DIR);
    UpdateOtaFlag(OTAFlag::CHECK_PREINSTALL_DATA);
    UpdateOtaFlag(OTAFlag::CHECK_SYSTEM_OPTIMIZE_SHADER_CAHCE_DIR);
    UpdateOtaFlag(OTAFlag::CHECK_BACK_UP_DIR);
    UpdateOtaFlag(OTAFlag::CHECK_RECOVERABLE_APPLICATION_INFO);
    UpdateOtaFlag(OTAFlag::CHECK_INSTALL_SOURCE);
    UpdateOtaFlag(OTAFlag::DELETE_DEPRECATED_ARK_PATHS);
    UpdateOtaFlag(OTAFlag::PROCESS_DYNAMIC_ICON);
    UpdateOtaFlag(OTAFlag::PROCESS_THEME_AND_DYNAMIC_ICON);
    (void)SaveBmsSystemTimeForShortcut();
    UpdateOtaFlag(OTAFlag::CHECK_EXTENSION_ABILITY);
    UpdateOtaFlag(OTAFlag::UPDATE_MODULE_JSON);
    UpdateOtaFlag(OTAFlag::PROCESS_ROUTER_MAP);
    UpdateOtaFlag(OTAFlag::UPDATE_EXTENSION_DIRS_SELINUX_APL);
    UpdateOtaFlag(OTAFlag::ADD_IDLE_INFO);
    UpdateOtaFlag(OTAFlag::UPDATE_ALTERNATE_ICONS);
    UpdateOtaFlag(OTAFlag::UPDATE_MODULE_JSON_EXTEND_FIELDS);
    UpdateOtaFlag(OTAFlag::DELETE_RESOURCE_SLAVE_DB);
    UpdateOtaFlag(OTAFlag::MIGRATE_UNINSTALL_BUNDLE_RESOURCE);
    UpdateOtaFlag(OTAFlag::MIGRATE_SKILL_DIR);
    (void)SaveUpdatePermissionsFlag();
    PerfProfile::GetInstance().Dump();
}

void BMSEventHandler::BundleRebootStartEvent()
{
#ifdef USE_PRE_BUNDLE_PROFILE
    if (LoadPreInstallProFile()) {
        UpdateAllPrivilegeCapability();
    }
#endif
    if (IsSystemUpgrade()) {
        EventReport::SendCpuSceneEvent(FOUNDATION_PROCESS_NAME, SCENE_ID_OTA_INSTALL);
        ProcessAccessTokenMigration();
        OnBundleRebootStart();
        HandlePreInstallException(false);
        HandleOTACodeEncryption();
        HandleDetermineCloneNumList();
        SaveSystemFingerprint();
        (void)SaveBmsSystemTimeForShortcut();
        AOTHandler::GetInstance().HandleOTA();
        ModuleJsonUpdater::UpdateModuleJsonAsync();
        ProcessDeleteResourceSlaveDb();
        ProcessMigrateUninstallBundleResource();
    } else {
        HandlePreInstallException();
        ProcessRebootQuickFixBundleInstall(QUICK_FIX_APP_PATH, false);
        ProcessRebootQuickFixUnInstallAndRecover(QUICK_FIX_APP_RECOVER_FILE);
        CheckBundleProvisionInfo();
        CheckALLResourceInfo();
        RemoveUninstalledPreloadFile();
        ProcessRouterMap();
        ProcessEmptyOdid();
    }
    // need process main bundle status
    BmsKeyEventMgr::ProcessMainBundleStatusFinally();

    if (IsModuleUpdate()) {
        HandleModuleUpdate();
    }

    // need check /data/service/el1/public/bms/bundle_manager_service/app_temp
    ProcessAppTmpPath();
    ProcessUpdateExtensionDirsApl();
    ProcessCheckAppSkillDir();
    needNotifyBundleScanStatus_ = true;
    allUserIds_.clear();
    xmlMap_.clear();
    needInstallUserIds_.clear();
}

void BMSEventHandler::ReportInfosLossedEvent(HighRiskOperationType operation, int32_t userId)
{
    EventInfo eventInfo;
    eventInfo.actionType = static_cast<int32_t>(HighRiskActionType::TRIGGER_FALLBACK);
    eventInfo.operationType = static_cast<int32_t>(operation);
    eventInfo.userId = userId;
    EventReport::SendHighRiskEvent(eventInfo);
}

ResultCode BMSEventHandler::GuardAgainstInstallInfosLossedStrategy()
{
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "GuardAgainstInstallInfosLossedStrategy start");
    // Check user path, and parse userData to InnerBundleUserInfo
    std::map<std::string, std::vector<InnerBundleUserInfo>> innerBundleUserInfoMaps;
    ScanResultCode scanResultCode = ScanAndAnalyzeUserDatas(innerBundleUserInfoMaps);
    if (scanResultCode == ScanResultCode::SCAN_NO_DATA) {
        LOG_NOFUNC_E(BMS_TAG_DEFAULT, "Scan the user data directory failed");
        return ResultCode::NO_INSTALLED_DATA;
    }

    ReportInfosLossedEvent(HighRiskOperationType::USER_DATA_PARSE_FAILED, Constants::INVALID_USERID);

    // From here on bundle infos will be written into db. Persist the rebuild mark
    // first: if the process dies halfway, next boot must not treat the partially
    // written db as complete, but redo the rebuild (redo is idempotent).
    MarkRebuildStart();

    // When data exist, but parse all userinfo fails, reinstall all app.
    // For example: the AT database is lost or others.
    if (scanResultCode == ScanResultCode::SCAN_HAS_DATA_PARSE_FAILED) {
        // Reinstall all app from install dir. Unlike the preinstall branch
        // below, a failed reinstall here KEEPS the rebuild mark on purpose:
        // the installed side has not been verified in this branch, so the
        // next boot must distrust the db and redo the whole recovery.
        ResultCode reinstallResult = ReInstallAllInstallDirApps();
        if (reinstallResult == ResultCode::REINSTALL_OK) {
            MarkRebuildFinish();
        }
        return reinstallResult;
    }

    // When data exist and parse all userinfo success,
    // it can be judged that some bundles has installed.
    // Check install dir, and parse the hap in install dir to InnerBundleInfo
    std::map<std::string, std::vector<InnerBundleInfo>> installInfos;
    std::map<std::string, PreInstallParsedInfo> preInstallParsedInfos;
    ScanAndAnalyzeInstallInfos(installInfos, preInstallParsedInfos);
    if (installInfos.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "check bundle path failed due to hap lossd or parse failed");
        return ResultCode::SYSTEM_ERROR;
    }

    // Combine InnerBundleInfo and InnerBundleUserInfo.
    if (!CombineBundleInfoAndUserInfo(installInfos, innerBundleUserInfoMaps)) {
        LOG_E(BMS_TAG_DEFAULT, "System internal error");
        return ResultCode::SYSTEM_ERROR;
    }

    // Recover system-level HSP and inter-app shared bundles which are not scanned
    ReInstallSystemHspAndSharedBundles();

    // The rdb salvage recovery may have restored preinstalled_bundle only
    // partially while the rescan above rebuilt installed_bundle only: rebuild
    // the lost preinstall rows before the rebuild mark is cleared, otherwise
    // the partial table is trusted as complete from now on.
    if (!RebuildPreInstallBundleInfos(preInstallParsedInfos, innerBundleUserInfoMaps)) {
        // Never keep the rebuild mark for failed preinstall rows: the installed
        // side has been verified and saved, and the mark would make the next
        // boot distrust the db and redo the whole recovery, whose rescan would
        // overwrite the bundle infos written by the user's install/uninstall/
        // update operations since this boot (and resurrect keep-data
        // uninstalled bundles from the preinstall dirs). The rows that could
        // not be saved stay missing until the next OTA rebuilds them.
        LOG_E(BMS_TAG_DEFAULT, "rebuild preinstall infos failed, the failed rows stay missing "
            "until the next OTA");
    }

    // Resync the in-memory snapshot with the db: rows written earlier in this
    // recovery by ReInstallSystemHspAndSharedBundles (e.g. system HSPs, whose
    // dirs are not part of the scanned preinstall dirs) are not in the
    // snapshot yet, and the same-boot consumers (preinstall exception
    // handling, OTA install decisions) must see them.
    hasLoadAllPreInstallBundleInfosFromDb_ = false;
    LoadAllPreInstallBundleInfos();

    // Every bundle info has been verified written into db, rebuild is complete.
    MarkRebuildFinish();
    return ResultCode::RECOVER_OK;
}

bool BMSEventHandler::RebuildPreInstallBundleInfos(
    const std::map<std::string, PreInstallParsedInfo> &preInstallParsedInfos,
    const std::map<std::string, std::vector<InnerBundleUserInfo>> &userInfoMaps)
{
    if (preInstallParsedInfos.empty()) {
        return true;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "dataMgr is null");
        return false;
    }
    bool allSaved = true;
    int32_t failedCount = 0;
    for (const auto &parsedIter : preInstallParsedInfos) {
        const std::string &bundleName = parsedIter.first;
        if (bundleName.empty() || parsedIter.second.hapInfos.empty()) {
            continue;
        }
        // query the current row directly instead of trusting the loadExistData_
        // snapshot: rows written earlier in this recovery (e.g. by
        // ReInstallSystemHspAndSharedBundles) are not in the snapshot yet
        PreInstallBundleInfo currentInfo;
        if (dataMgr->GetPreInstallBundleInfo(bundleName, currentInfo)) {
            if (!RefreshPreInstallBundleInfo(dataMgr, bundleName, parsedIter.second, currentInfo)) {
                allSaved = false;
                failedCount++;
            }
            continue;
        }
        PreInstallBundleInfo preInstallBundleInfo;
        // handle the lost row the way the first-boot preinstall does
        PopulatePreInstallInfoFromParse(parsedIter.second, preInstallBundleInfo);
        // no user data dir means the bundle is not installed for any user:
        // keep the row as recoverable instead of marking it installed
        preInstallBundleInfo.SetIsUninstalled(userInfoMaps.find(bundleName) == userInfoMaps.end());
        if (!dataMgr->SavePreInstallBundleInfo(bundleName, preInstallBundleInfo)) {
            LOG_E(BMS_TAG_DEFAULT, "rebuild preInstall info of %{public}s failed", bundleName.c_str());
            allSaved = false;
            failedCount++;
            continue;
        }
        loadExistData_[bundleName] = preInstallBundleInfo;
    }
    LOG_I(BMS_TAG_DEFAULT, "rebuild preinstall infos finished, total:%{public}zu failed:%{public}d",
        preInstallParsedInfos.size(), failedCount);
    return allSaved;
}

bool BMSEventHandler::RefreshPreInstallBundleInfo(
    const std::shared_ptr<BundleDataMgr> &dataMgr,
    const std::string &bundleName, const PreInstallParsedInfo &parsedInfo, PreInstallBundleInfo &currentInfo)
{
    // keep the in-memory snapshot coherent with the row just read from db
    loadExistData_[bundleName] = currentInfo;
    // handle the row the way the first-boot preinstall does: refresh the
    // fields derived from the current preinstall source and accumulate the
    // paths, while the runtime state (uninstalled flag, force uninstalled
    // users, ota new install users) is kept because no real install happened
    PreInstallBundleInfo beforeInfo = currentInfo;
    PopulatePreInstallInfoFromParse(parsedInfo, currentInfo);
    // most rows are already in sync with their preinstall source: skip the
    // write when the refreshed content is identical to the row read from db,
    // the whole recovery must not rewrite the table row by row
    if (beforeInfo.ToString() == currentInfo.ToString()) {
        return true;
    }
    if (!dataMgr->SavePreInstallBundleInfo(bundleName, currentInfo)) {
        LOG_E(BMS_TAG_DEFAULT, "refresh preInstall info of %{public}s failed", bundleName.c_str());
        return false;
    }
    loadExistData_[bundleName] = currentInfo;
    LOG_D(BMS_TAG_DEFAULT, "preInstall info of %{public}s exists, refreshed from the current preinstall source",
        bundleName.c_str());
    return true;
}

// Populate the fields derived from the current preinstall source onto the row,
// mirroring the install-time needSavePreInstallInfo block of the first-boot
// preinstall. Fields only a real install may change (isUninstalled, force
// uninstalled users, ota new install users) are left
// untouched: an existing row keeps its runtime state, a fresh row leaves them
// at their defaults.
void BMSEventHandler::PopulatePreInstallInfoFromParse(const PreInstallParsedInfo &parsedInfo,
    PreInstallBundleInfo &preInstallBundleInfo)
{
    const auto &hapInfos = parsedInfo.hapInfos;
    // defensive only: both call sites filter empty hapInfos beforehand
    if (hapInfos.empty()) {
        return;
    }
    std::unique_ptr<BundleInstallChecker> bundleInstallChecker = std::make_unique<BundleInstallChecker>();
    const InnerBundleInfo &representativeInfo = hapInfos.begin()->second;
    preInstallBundleInfo.SetBundleName(representativeInfo.GetBundleName());
    preInstallBundleInfo.SetAppType(representativeInfo.GetAppType());
    preInstallBundleInfo.SetVersionCode(bundleInstallChecker->GetVersionCode(hapInfos));
    // a preinstall bundle may be preinstalled from several different dirs:
    // the paths accumulate across the dirs like the first-boot installs do,
    // never replace the collected set. This intentionally diverges from the
    // OTA path (UpdatePreinstallDBForNotUpdatedBundle) which clears the paths
    // and re-adds the current ones: a stale path of a removed preinstall dir
    // is pruned by the next OTA, not by this recovery.
    for (const auto &hapInfo : hapInfos) {
        preInstallBundleInfo.AddBundlePath(hapInfo.first);
    }
#ifdef USE_PRE_BUNDLE_PROFILE
    // the removable config is looked up by the FIRST dir of the bundle, the
    // same first-wins rule the OTA needInstallMap accumulation applies; the
    // sequential first-boot installs end up with the LAST dir's config, the
    // divergence is accepted for the recovery
    preInstallBundleInfo.SetRemovable(IsPreInstallRemovable(parsedInfo.bundleDir));
#else
    preInstallBundleInfo.SetRemovable(representativeInfo.IsRemovable());
#endif
    FillPreInstallResourceInfo(hapInfos, preInstallBundleInfo);
    preInstallBundleInfo.SetU1Enable(representativeInfo.IsU1Enable());
}

ScanResultCode BMSEventHandler::ScanAndAnalyzeUserDatas(
    std::map<std::string, std::vector<InnerBundleUserInfo>> &userMaps)
{
    ScanResultCode scanResultCode = ScanResultCode::SCAN_NO_DATA;
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "dataMgr is null");
        return scanResultCode;
    }

    std::string baseDataDir = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR + ServiceConstants::BUNDLE_EL[0];
    std::vector<std::string> userIds;
    if (!ScanDir(baseDataDir, ScanMode::SUB_FILE_DIR, ResultMode::RELATIVE_PATH, userIds)) {
        LOG_D(BMS_TAG_DEFAULT, "Check the base user directory(%{public}s) failed", baseDataDir.c_str());
        return scanResultCode;
    }

    for (const auto &userId : userIds) {
        int32_t userIdInt = Constants::INVALID_USERID;
        if (!StrToInt(userId, userIdInt)) {
            LOG_NOFUNC_E(BMS_TAG_DEFAULT, "UserId(%{public}s) strToInt failed", userId.c_str());
            continue;
        }

        dataMgr->AddUserId(userIdInt);
        std::vector<std::string> userDataBundleNames;
        std::string userDataDir = baseDataDir + ServiceConstants::PATH_SEPARATOR + userId + ServiceConstants::BASE;
        if (!ScanDir(userDataDir, ScanMode::SUB_FILE_DIR, ResultMode::RELATIVE_PATH, userDataBundleNames)) {
            LOG_D(BMS_TAG_DEFAULT, "Check the user installation directory(%{public}s) failed", userDataDir.c_str());
            continue;
        }

        for (const auto &userDataBundleName : userDataBundleNames) {
            if (scanResultCode == ScanResultCode::SCAN_NO_DATA) {
                scanResultCode = ScanResultCode::SCAN_HAS_DATA_PARSE_FAILED;
            }

            if (AnalyzeUserData(userIdInt, userDataDir, userDataBundleName, userMaps)) {
                scanResultCode = ScanResultCode::SCAN_HAS_DATA_PARSE_SUCCESS;
            }
        }
    }

    return scanResultCode;
}

bool BMSEventHandler::AnalyzeUserData(
    int32_t userId, const std::string &userDataDir, const std::string &userDataBundleName,
    std::map<std::string, std::vector<InnerBundleUserInfo>> &userMaps)
{
    if (userDataDir.empty() || userDataBundleName.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "UserDataDir or UserDataBundleName is empty");
        return false;
    }

    // Clone app data dirs are named "+clone-{appIndex}+{bundleName}"; recover the
    // clone's InnerBundleCloneInfo and merge it into the main app's user record.
    if (userDataBundleName.find(ServiceConstants::CLONE_PREFIX) == 0) {
        return AnalyzeCloneUserData(userId, userDataDir, userDataBundleName, userMaps);
    }

    std::string userDataBundlePath = userDataDir + userDataBundleName;
    LOG_D(BMS_TAG_DEFAULT, "Analyze user data path(%{public}s)", userDataBundlePath.c_str());
    FileStat fileStat;
    if (InstalldClient::GetInstance()->GetFileStat(
        userDataBundlePath, BundleDirScene::GET_USER_DATA_FILE_STAT, fileStat) != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "GetFileStat path(%{public}s) failed", userDataBundlePath.c_str());
        return false;
    }

    // It should be a bundleName dir
    if (!fileStat.isDir) {
        LOG_E(BMS_TAG_DEFAULT, "UserDataBundlePath(%{public}s) is not dir", userDataBundlePath.c_str());
        return false;
    }

    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleName = userDataBundleName;
    innerBundleUserInfo.bundleUserInfo.userId = userId;
    innerBundleUserInfo.uid = fileStat.uid;
    innerBundleUserInfo.gids.emplace_back(fileStat.gid);
    innerBundleUserInfo.installTime = fileStat.lastModifyTime;
    innerBundleUserInfo.updateTime = innerBundleUserInfo.installTime;
    auto accessTokenIdEx = OHOS::Security::AccessToken::AccessTokenKit::GetHapTokenIDEx(
        innerBundleUserInfo.bundleUserInfo.userId, userDataBundleName, 0);
    if (accessTokenIdEx.tokenIdExStruct.tokenID == 0) {
        LOG_E(BMS_TAG_DEFAULT, "get tokenId failed");
        return false;
    }

    innerBundleUserInfo.accessTokenId = accessTokenIdEx.tokenIdExStruct.tokenID;
    innerBundleUserInfo.accessTokenIdEx = accessTokenIdEx.tokenIDEx;
    auto userIter = userMaps.find(userDataBundleName);
    if (userIter == userMaps.end()) {
        userMaps.emplace(userDataBundleName, std::vector<InnerBundleUserInfo>{innerBundleUserInfo});
        return true;
    }
    // A clone scan may have created this entry first (clone data dirs may be
    // scanned before or after the main app dir, as readdir() order is
    // filesystem-dependent); fill the main-app fields while keeping the
    // cloneInfos already collected intact, instead of appending a duplicate entry.
    for (auto &existing : userIter->second) {
        if (existing.bundleUserInfo.userId == userId) {
            existing.uid = innerBundleUserInfo.uid;
            existing.gids = innerBundleUserInfo.gids;
            existing.installTime = innerBundleUserInfo.installTime;
            existing.updateTime = innerBundleUserInfo.updateTime;
            existing.accessTokenId = innerBundleUserInfo.accessTokenId;
            existing.accessTokenIdEx = innerBundleUserInfo.accessTokenIdEx;
            return true;
        }
    }
    userIter->second.emplace_back(innerBundleUserInfo);
    return true;
}

bool BMSEventHandler::AnalyzeCloneUserData(
    int32_t userId, const std::string &userDataDir, const std::string &userDataBundleName,
    std::map<std::string, std::vector<InnerBundleUserInfo>> &userMaps)
{
    std::string realBundleName;
    int32_t appIndex = 0;
    if (!BundleCloneCommonHelper::ParseCloneDataDir(userDataBundleName, realBundleName, appIndex)) {
        LOG_E(BMS_TAG_DEFAULT, "parse clone data dir(%{public}s) failed", userDataBundleName.c_str());
        return false;
    }
    if (realBundleName.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "bundleName is empty %{public}s", userDataBundleName.c_str());
        return false;
    }
    // Only the normal app-clone range [CLONE_APP_INDEX_MIN, CLONE_APP_INDEX_MAX] is
    // recovered here. Dual-mode (DUAL_MODE_CLONE_APP_INDEX) and CLI sandbox
    // ([CLI_SANDBOX_APP_INDEX_MIN, CLI_SANDBOX_APP_INDEX_MAX]) have their own flows.
    if (appIndex < ServiceConstants::CLONE_APP_INDEX_MIN ||
        appIndex > ServiceConstants::CLONE_APP_INDEX_MAX) {
        LOG_D(BMS_TAG_DEFAULT, "clone appIndex(%{public}d) out of app-clone range, skip bundle:%{public}s",
            appIndex, realBundleName.c_str());
        return false;
    }

    std::string userDataBundlePath = userDataDir + userDataBundleName;
    LOG_D(BMS_TAG_DEFAULT, "Analyze clone user data path(%{public}s)", userDataBundlePath.c_str());
    FileStat fileStat;
    if (InstalldClient::GetInstance()->GetFileStat(
        userDataBundlePath, BundleDirScene::GET_USER_DATA_FILE_STAT, fileStat) != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "GetFileStat clone path(%{public}s) failed", userDataBundlePath.c_str());
        return false;
    }
    if (!fileStat.isDir) {
        LOG_E(BMS_TAG_DEFAULT, "CloneUserDataPath(%{public}s) is not dir", userDataBundlePath.c_str());
        return false;
    }

    auto accessTokenIdEx = OHOS::Security::AccessToken::AccessTokenKit::GetHapTokenIDEx(
        userId, realBundleName, appIndex);
    if (accessTokenIdEx.tokenIdExStruct.tokenID == 0) {
        LOG_E(BMS_TAG_DEFAULT, "get clone tokenId failed, bundle:%{public}s appIndex:%{public}d",
            realBundleName.c_str(), appIndex);
        return false;
    }

    InnerBundleCloneInfo cloneInfo = {
        .userId = userId,
        .appIndex = appIndex,
        .uid = fileStat.uid,
        .accessTokenId = accessTokenIdEx.tokenIdExStruct.tokenID,
        .installTime = fileStat.lastModifyTime,
        .accessTokenIdEx = accessTokenIdEx.tokenIDEx,
        .gids = {fileStat.gid},
    };

    // Merge the clone info into the main app's user record (keyed by bundleName +
    // userId). If the main app dir is scanned later, AnalyzeUserData fills the
    // main-app fields while keeping the cloneInfos collected here intact.
    auto userIter = userMaps.find(realBundleName);
    if (userIter != userMaps.end()) {
        for (auto &userInfo : userIter->second) {
            if (userInfo.bundleUserInfo.userId == userId) {
                userInfo.cloneInfos.emplace(InnerBundleUserInfo::AppIndexToKey(appIndex), cloneInfo);
                return true;
            }
        }
    }
    InnerBundleUserInfo innerBundleUserInfo;
    innerBundleUserInfo.bundleName = realBundleName;
    innerBundleUserInfo.bundleUserInfo.userId = userId;
    innerBundleUserInfo.cloneInfos.emplace(InnerBundleUserInfo::AppIndexToKey(appIndex), cloneInfo);
    userMaps[realBundleName].emplace_back(innerBundleUserInfo);
    return true;
}

ResultCode BMSEventHandler::ReInstallAllInstallDirApps()
{
    ReInstallSystemHspAndSharedBundles();
    // First, reinstall all preInstall app from preInstall dir
    std::vector<std::string> preInstallDirs;
    GetPreInstallDir(preInstallDirs);
    for (const auto &preInstallDir : preInstallDirs) {
        std::vector<std::string> filePaths { preInstallDir };
        bool removable = IsPreInstallRemovable(preInstallDir);
        if (!OTAInstallSystemBundle(
            filePaths, Constants::AppType::SYSTEM_APP, removable)) {
            LOG_E(BMS_TAG_DEFAULT, "Reinstall bundle(%{public}s) error", preInstallDir.c_str());
            SavePreInstallException(preInstallDir);
            continue;
        }
    }

    auto installer = DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleInstaller();
    if (installer == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "installer is nullptr");
        return ResultCode::SYSTEM_ERROR;
    }

    // Second, reInstall all common install app from install dir
    std::map<std::string, std::vector<std::string>> hapPathsMap;
    ScanInstallDir(hapPathsMap);
    for (const auto &hapPaths : hapPathsMap) {
        InstallParam installParam;
        installParam.userId = Constants::ALL_USERID;
        installParam.installFlag = InstallFlag::REPLACE_EXISTING;
        sptr<InnerReceiverImpl> innerReceiverImpl(new (std::nothrow) InnerReceiverImpl());
        if (innerReceiverImpl == nullptr) {
            LOG_E(BMS_TAG_DEFAULT, "InnerReceiverImpl create fail");
            continue;
        }
        innerReceiverImpl->SetBundleName(hapPaths.first);
        std::vector<std::string> tempHaps;
        MoveTempPath(hapPaths.second, hapPaths.first, tempHaps);
        installer->Install(tempHaps, installParam, innerReceiverImpl);
    }

    return ResultCode::REINSTALL_OK;
}

void BMSEventHandler::ScanAndAnalyzeInstallInfos(
    std::map<std::string, std::vector<InnerBundleInfo>> &installInfos,
    std::map<std::string, PreInstallParsedInfo> &preInstallParsedInfos)
{
    // Scan the installed directory
    std::map<std::string, std::vector<std::string>> hapPathsMap;
    ScanInstallDir(hapPathsMap);
    AnalyzeHaps(false, hapPathsMap, installInfos);

    // Scan preBundle directory
    std::vector<std::string> preInstallDirs;
    GetPreInstallDir(preInstallDirs);
    AnalyzeHaps(true, preInstallDirs, installInfos, preInstallParsedInfos);
}

void BMSEventHandler::ScanInstallDir(
    std::map<std::string, std::vector<std::string>> &hapPathsMap)
{
    LOG_D(BMS_TAG_DEFAULT, "Scan the installed directory start");
    std::vector<std::string> bundleNameList;
    if (!ScanDir(Constants::BUNDLE_CODE_DIR, ScanMode::SUB_FILE_DIR, ResultMode::RELATIVE_PATH, bundleNameList)) {
        LOG_E(BMS_TAG_DEFAULT, "Check the bundle directory(%{public}s) failed", Constants::BUNDLE_CODE_DIR);
        return;
    }

    for (const auto &bundleName : bundleNameList) {
        std::vector<std::string> hapPaths;
        auto appCodePath = std::string(Constants::BUNDLE_CODE_DIR) + ServiceConstants::PATH_SEPARATOR + bundleName;
        // skills root dir under BUNDLE_CODE_DIR is not a bundle dir
        if (appCodePath == Constants::BASE_SKILL_DIR) {
            continue;
        }
        if (!ScanDir(appCodePath, ScanMode::SUB_FILE_FILE, ResultMode::ABSOLUTE_PATH, hapPaths)) {
            LOG_E(BMS_TAG_DEFAULT, "Scan the appCodePath(%{public}s) failed", appCodePath.c_str());
            continue;
        }

        if (hapPaths.empty()) {
            LOG_D(BMS_TAG_DEFAULT, "The directory(%{public}s) scan result is empty", appCodePath.c_str());
            continue;
        }

        std::vector<std::string> checkHapPaths = CheckHapPaths(hapPaths);
        hapPathsMap.emplace(bundleName, checkHapPaths);
    }

    LOG_D(BMS_TAG_DEFAULT, "Scan the installed directory end");
}

std::vector<std::string> BMSEventHandler::CheckHapPaths(
    const std::vector<std::string> &hapPaths)
{
    std::vector<std::string> checkHapPaths;
    for (const auto &hapPath : hapPaths) {
        if (!BundleUtil::CheckFileType(hapPath, ServiceConstants::INSTALL_FILE_SUFFIX) &&
            !BundleUtil::CheckFileType(hapPath, ServiceConstants::HSP_FILE_SUFFIX)) {
            LOG_E(BMS_TAG_DEFAULT, "Check hapPath(%{public}s) failed", hapPath.c_str());
            continue;
        }

        checkHapPaths.emplace_back(hapPath);
    }

    return checkHapPaths;
}

void BMSEventHandler::GetPreInstallRootDirList(std::vector<std::string> &rootDirList)
{
#ifdef CONFIG_POLOCY_ENABLE
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "print GetPreInstallRootDirList");
    auto cfgDirList = GetCfgDirList();
    if (cfgDirList != nullptr) {
        for (const auto &cfgDir : cfgDirList->paths) {
            if (cfgDir == nullptr) {
                continue;
            }

            LOG_NOFUNC_I(BMS_TAG_DEFAULT, "%{public}s", cfgDir);
            rootDirList.emplace_back(cfgDir);
        }

        FreeCfgDirList(cfgDirList);
    }
#endif
    bool ret = std::find(
        rootDirList.begin(), rootDirList.end(), DEFAULT_PRE_BUNDLE_ROOT_DIR) != rootDirList.end();
    if (!ret) {
        rootDirList.emplace_back(DEFAULT_PRE_BUNDLE_ROOT_DIR);
    }
}

void BMSEventHandler::ClearPreInstallCache()
{
    if (!hasLoadPreInstallProFile_) {
        return;
    }

    installList_.clear();
    uninstallList_.clear();
    systemHspList_.clear();
    skillsList_.clear();
    installListCapabilities_.clear();
    extensiontype_.clear();
    hasLoadPreInstallProFile_ = false;
}

bool BMSEventHandler::LoadPreInstallProFile()
{
    if (hasLoadPreInstallProFile_) {
        return !installList_.empty();
    }

    std::vector<std::string> rootDirList;
    GetPreInstallRootDirList(rootDirList);
    if (rootDirList.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "dirList is empty");
        return false;
    }

    for (const auto &rootDir : rootDirList) {
        ParsePreBundleProFile(rootDir + ServiceConstants::PRODUCT_SUFFIX);
        ParsePreBundleProFile(rootDir + MODULE_UPDATE_PRODUCT_SUFFIX);
    }

    hasLoadPreInstallProFile_ = true;
    return !installList_.empty();
}

bool BMSEventHandler::HasPreInstallProfile()
{
    return !installList_.empty();
}

void BMSEventHandler::ParsePreBundleProFile(const std::string &dir)
{
    if (!BundleUtil::IsExistDirNoLog(dir)) {
        LOG_NOFUNC_W(BMS_TAG_DEFAULT, "parse dir %{public}s not exist", dir.c_str());
        return;
    }
    BundleParser bundleParser;
    bundleParser.ParsePreInstallConfig(
        dir + INSTALL_LIST_CONFIG, installList_);
    bundleParser.ParsePreInstallConfig(
        dir + APP_SERVICE_FWK_INSTALL_LIST_CONFIG, systemHspList_);
    bundleParser.ParsePreInstallConfig(
        dir + SKILLS_INSTALL_LIST_CONFIG, skillsList_);
    bundleParser.ParsePreUnInstallConfig(
        dir + UNINSTALL_LIST_CONFIG, uninstallList_);
    bundleParser.ParsePreInstallAbilityConfig(
        dir + INSTALL_LIST_CAPABILITY_CONFIG, installListCapabilities_);
    bundleParser.ParseExtTypeConfig(
        dir + EXTENSION_TYPE_LIST_CONFIG, extensiontype_);
    bundleParser.ParsePreInstallConfig(
        dir + SHARED_BUNDLES_INSTALL_LIST_CONFIG, installList_);
    bundleParser.ParseDemandInstallConfig(dir + INSTALL_LIST_CONFIG, onDemandInstallList_);

    std::string oldSystemFingerprint = GetOldSystemFingerprint();
    if (oldSystemFingerprint.empty()) {
        LOG_W(BMS_TAG_DEFAULT, "only scan app_list.json on first startup");
        bundleParser.ParsePreAppListConfig(dir + ServiceConstants::DEFAULT_DATA_PRE_BUNDLE_DIR, installList_,
            onDemandInstallList_);
    } else {
        LOG_W(BMS_TAG_DEFAULT, "data preload app is not support OTA");
    }
    FilterVersionSpecialCustomApps(installList_);
    if (!installList_.empty() && !onDemandInstallList_.empty()) {
        for (const auto &preScanInfo : installList_) {
            auto iter = std::find(onDemandInstallList_.begin(), onDemandInstallList_.end(), preScanInfo);
            if (iter != onDemandInstallList_.end()) {
                onDemandInstallList_.erase(iter);
            }
        }
    }
}

void BMSEventHandler::GetPreInstallDir(std::vector<std::string> &bundleDirs)
{
#ifdef USE_PRE_BUNDLE_PROFILE
    if (LoadPreInstallProFile()) {
        GetPreInstallDirFromLoadProFile(bundleDirs);
        return;
    }
#endif

    GetPreInstallDirFromScan(bundleDirs);
}

void BMSEventHandler::GetPreInstallDirFromLoadProFile(std::vector<std::string> &bundleDirs)
{
    for (const auto &installInfo : installList_) {
        if (uninstallList_.find(installInfo.bundleDir) != uninstallList_.end()) {
            LOG_W(BMS_TAG_DEFAULT, "bundle(%{public}s) not allowed installed", installInfo.bundleDir.c_str());
            continue;
        }

        bundleDirs.emplace_back(installInfo.bundleDir);
    }
}

void BMSEventHandler::GetPreInstallDirFromScan(std::vector<std::string> &bundleDirs)
{
    std::list<std::string> scanbundleDirs;
    GetBundleDirFromScan(scanbundleDirs);
    std::copy(scanbundleDirs.begin(), scanbundleDirs.end(), std::back_inserter(bundleDirs));
}

void BMSEventHandler::AnalyzeHaps(
    bool isPreInstallApp,
    const std::map<std::string, std::vector<std::string>> &hapPathsMap,
    std::map<std::string, std::vector<InnerBundleInfo>> &installInfos)
{
    for (const auto &hapPaths : hapPathsMap) {
        std::unordered_map<std::string, InnerBundleInfo> hapInfos;
        if (!CheckAndParseHapFiles(hapPaths.second, isPreInstallApp, hapInfos) || hapInfos.empty()) {
            LOG_E(BMS_TAG_DEFAULT, "Parse bundleDir failed");
            continue;
        }

        CollectInstallInfos(hapInfos, installInfos);
    }
}

void BMSEventHandler::AnalyzeHaps(
    bool isPreInstallApp,
    const std::vector<std::string> &bundleDirs,
    std::map<std::string, std::vector<InnerBundleInfo>> &installInfos,
    std::map<std::string, PreInstallParsedInfo> &preInstallParsedInfos)
{
    for (const auto &bundleDir : bundleDirs) {
        std::unordered_map<std::string, InnerBundleInfo> hapInfos;
        if (!CheckAndParseHapFiles(bundleDir, isPreInstallApp, hapInfos) || hapInfos.empty()) {
            LOG_E(BMS_TAG_DEFAULT, "Parse bundleDir(%{public}s) failed", bundleDir.c_str());
            continue;
        }
        // the copy (CollectInstallInfos) must run before the move
        // (CollectPreInstallParsedInfos): a reorder would silently leave
        // installInfos with moved-from empty entries
        CollectInstallInfos(hapInfos, installInfos);
        if (!isPreInstallApp) {
            continue;
        }
        CollectPreInstallParsedInfos(bundleDir, hapInfos, preInstallParsedInfos);
    }
}

void BMSEventHandler::CollectPreInstallParsedInfos(const std::string &bundleDir,
    std::unordered_map<std::string, InnerBundleInfo> &hapInfos,
    std::map<std::string, PreInstallParsedInfo> &preInstallParsedInfos)
{
    for (auto &hapInfo : hapInfos) {
        std::string parsedBundleName = hapInfo.second.GetBundleName();
        auto resultIter = preInstallParsedInfos.find(parsedBundleName);
        if (resultIter == preInstallParsedInfos.end()) {
            PreInstallParsedInfo parsedInfo;
            parsedInfo.bundleDir = bundleDir;
            parsedInfo.hapInfos.emplace(hapInfo.first, std::move(hapInfo.second));
            preInstallParsedInfos.emplace(parsedBundleName, std::move(parsedInfo));
            continue;
        }
        // a second preinstall dir of the same bundle (e.g. module update):
        // merge the hap paths and keep the first dir for the removable lookup
        resultIter->second.hapInfos.emplace(hapInfo.first, std::move(hapInfo.second));
    }
}

void BMSEventHandler::CollectInstallInfos(
    const std::unordered_map<std::string, InnerBundleInfo> &hapInfos,
    std::map<std::string, std::vector<InnerBundleInfo>> &installInfos)
{
    for (const auto &hapInfoIter : hapInfos) {
        auto bundleName = hapInfoIter.second.GetBundleName();
        if (installInfos.find(bundleName) == installInfos.end()) {
            std::vector<InnerBundleInfo> innerBundleInfos { hapInfoIter.second };
            installInfos.emplace(bundleName, innerBundleInfos);
            continue;
        } else {
            std::vector<InnerBundleInfo> &infos = installInfos.at(bundleName);
            if (!infos.empty() && hapInfoIter.second.GetVersionCode() < infos[0].GetVersionCode()) {
                continue;
            }
            if (std::find_if(infos.begin(), infos.end(), [&hapInfoIter](const InnerBundleInfo &info) {
                    return info.GetCurModuleName() == hapInfoIter.second.GetCurModuleName();
                }) == infos.end()) {
                installInfos.at(bundleName).emplace_back(hapInfoIter.second);
            }
        }
    }
}

bool BMSEventHandler::CombineBundleInfoAndUserInfo(
    const std::map<std::string, std::vector<InnerBundleInfo>> &installInfos,
    const std::map<std::string, std::vector<InnerBundleUserInfo>> &userInfoMaps)
{
    LOG_D(BMS_TAG_DEFAULT, "Combine code information and user data start");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "dataMgr is null");
        return false;
    }

    if (installInfos.empty() || userInfoMaps.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "bundleInfos or userInfos is empty");
        return false;
    }

    for (auto hasInstallInfo : installInfos) {
        auto bundleName = hasInstallInfo.first;
        auto userIter = userInfoMaps.find(bundleName);

        bool isCloneApp = false;
        if (userIter == userInfoMaps.end() && DualModeHelper::IsDualModeDevice()) {
            std::string effectiveName = DualModeHelper::GetDualModeBundleName(bundleName);
            userIter = userInfoMaps.find(effectiveName);
            if (userIter != userInfoMaps.end()) {
                isCloneApp = true;
            }
        }
        if (userIter == userInfoMaps.end()) {
            LOG_E(BMS_TAG_DEFAULT, "User data directory missing with bundle %{public}s ", bundleName.c_str());
            needRebootOta_ = true;
            continue;
        }

        for (auto &info : hasInstallInfo.second) {
            // Set the clone flag so SaveInstallInfoToCache uses the effective name for directories.
            if (isCloneApp) {
                info.SetDualModeCloneApp(true);
                info.SetAppIndex(ServiceConstants::DUAL_MODE_CLONE_APP_INDEX);
            }
            SaveInstallInfoToCache(info);
        }

        for (const auto &userInfo : userIter->second) {
            dataMgr->AddInnerBundleUserInfo(bundleName, userInfo);
        }
    }

    // Parsing uid, gids and other user information
    dataMgr->RestoreUidAndGid();
    // Load all bundle state data from jsonDb
    dataMgr->LoadAllBundleStateDataFromJsonDb();
    LOG_D(BMS_TAG_DEFAULT, "Combine code information and user data end");
    return true;
}

void BMSEventHandler::SaveInstallInfoToCache(InnerBundleInfo &info)
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "dataMgr is null");
        return;
    }

    // dual-mode: dirs + installStates_ use the effective name; bundleInfos_ ops + mutex use the
    // original name (AddInnerBundleInfo derives the installStates_ key from it; passing effective
    // would double-prefix and break the lookup).
    const std::string originalName = info.GetBundleName();
    std::string effectiveName = info.IsDualModeCloneApp()
        ? DualModeHelper::GetDualModeBundleName(originalName)
        : originalName;
    auto appCodePath = std::string(Constants::BUNDLE_CODE_DIR) + ServiceConstants::PATH_SEPARATOR + effectiveName;
    info.SetAppCodePath(appCodePath);

    std::string dataBaseDir = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR + ServiceConstants::BUNDLE_EL[1]
        + ServiceConstants::DATABASE + effectiveName;
    info.SetAppDataBaseDir(dataBaseDir);

    auto moduleDir = info.GetAppCodePath() + ServiceConstants::PATH_SEPARATOR + info.GetCurrentModulePackage();
    info.AddModuleSrcDir(moduleDir);
    info.AddModuleResPath(moduleDir);

    bool bundleExist = false;
    InnerBundleInfo dbInfo;
    {
        auto &mtx = dataMgr->GetBundleMutex(originalName);
        std::lock_guard lock { mtx };
        bundleExist = dataMgr->FetchInnerBundleInfo(originalName, dbInfo);
    }

    if (!bundleExist) {
        dataMgr->UpdateBundleInstallState(effectiveName, InstallState::INSTALL_START);
        if (!dataMgr->AddInnerBundleInfo(originalName, info)) {
            LOG_E(BMS_TAG_DEFAULT, "add bundle %{public}s failed", originalName.c_str());
            dataMgr->UpdateBundleInstallState(effectiveName, InstallState::INSTALL_FAIL);
            return;
        }
        dataMgr->UpdateBundleInstallState(effectiveName, InstallState::INSTALL_SUCCESS);
        return;
    }

    std::string developerId = info.GetDeveloperId();
    if (!developerId.empty()) {
        std::string odid;
        dataMgr->GenerateOdid(developerId, odid);
        info.UpdateOdid(developerId, odid);
    }
    auto& hapModuleName = info.GetCurModuleName();
    std::vector<std::string> dbModuleNames;
    dbInfo.GetModuleNames(dbModuleNames);
    auto iter = std::find(dbModuleNames.begin(), dbModuleNames.end(), hapModuleName);
    if (iter != dbModuleNames.end()) {
        LOG_E(BMS_TAG_DEFAULT, "module(%{public}s) has install", hapModuleName.c_str());
        return;
    }

    dataMgr->UpdateBundleInstallState(effectiveName, InstallState::UPDATING_START);
    dataMgr->UpdateBundleInstallState(effectiveName, InstallState::UPDATING_SUCCESS);
    dataMgr->AddNewModuleInfo(originalName, info, dbInfo);
}

bool BMSEventHandler::ScanDir(
    const std::string& dir, ScanMode scanMode, ResultMode resultMode, std::vector<std::string> &resultList)
{
    LOG_D(BMS_TAG_DEFAULT, "Scan the directory(%{public}s) start", dir.c_str());
    ErrCode result = InstalldClient::GetInstance()->ScanDir(dir, scanMode, resultMode, resultList);
    if (result != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "Scan the directory(%{public}s) failed", dir.c_str());
        return false;
    }

    return true;
}

void BMSEventHandler::OnBundleBootStart(int32_t userId)
{
#ifdef USE_PRE_BUNDLE_PROFILE
    if (LoadPreInstallProFile()) {
        LOG_I(BMS_TAG_DEFAULT, "Process boot bundle install from pre bundle proFile for userId:%{public}d", userId);
        InnerProcessBootSystemHspInstall();
        InnerProcessBootSkillsInstall(userId);
        InnerProcessBootPreBundleProFileInstall(userId);
        ProcessRebootQuickFixBundleInstall(QUICK_FIX_APP_PATH, true);
        ProcessRebootQuickFixUnInstallAndRecover(QUICK_FIX_APP_RECOVER_FILE);
        InnerProcessBootCheckOnDemandBundle();
        return;
    }
#else
    ProcessBootBundleInstallFromScan(userId);
#endif
}

void BMSEventHandler::ProcessBootBundleInstallFromScan(int32_t userId)
{
    LOG_D(BMS_TAG_DEFAULT, "Process boot bundle install from scan");
    std::list<std::string> bundleDirs;
    GetBundleDirFromScan(bundleDirs);
    for (auto item : bundleDirs) {
        ProcessSystemBundleInstall(item, Constants::AppType::SYSTEM_APP, userId);
    }
}

void BMSEventHandler::GetBundleDirFromScan(std::list<std::string> &bundleDirs)
{
    std::vector<std::string> rootDirList;
    GetPreInstallRootDirList(rootDirList);
    if (rootDirList.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "rootDirList is empty");
        return;
    }

    for (const auto &rootDir : rootDirList) {
        ProcessScanDir(rootDir + APP_SUFFIX, bundleDirs);
    }

    auto iter = std::find(bundleDirs.begin(), bundleDirs.end(), SYSTEM_RESOURCES_APP_PATH);
    if (iter != bundleDirs.end()) {
        bundleDirs.erase(iter);
        bundleDirs.insert(bundleDirs.begin(), SYSTEM_RESOURCES_APP_PATH);
    }
}

void BMSEventHandler::ProcessScanDir(const std::string &dir, std::list<std::string> &bundleDirs)
{
    BundleScanner scanner;
    std::list<std::string> bundleList = scanner.Scan(dir);
    for (const auto &item : bundleList) {
        auto iter = std::find(bundleDirs.begin(), bundleDirs.end(), item);
        if (iter == bundleDirs.end()) {
            bundleDirs.push_back(item);
        }
    }
}

void BMSEventHandler::InnerProcessBootSystemHspInstall()
{
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "boot install appServiceFwk size:%{public}zu", systemHspList_.size());
    for (const auto &systemHspPath : systemHspList_) {
        ProcessSystemHspInstall(systemHspPath);
    }
}

void BMSEventHandler::ProcessSystemHspInstall(const PreScanInfo &preScanInfo)
{
    InstallParam installParam;
    installParam.isPreInstallApp = true;
    installParam.isFirstBootInstall = true;
    installParam.removable = false;
    installParam.copyHapToInstallPath = false;
    installParam.needSavePreInstallInfo = true;
    installParam.preinstallSourceFlag = ApplicationInfoFlag::FLAG_BOOT_INSTALLED;
    AppServiceFwkInstaller installer;
    SavePreInstallExceptionAppService(preScanInfo.bundleDir);
    ErrCode ret = installer.Install({preScanInfo.bundleDir}, installParam);
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "Install systemHsp %{public}s result %{public}d", preScanInfo.bundleDir.c_str(), ret);
    if (ret == ERR_OK) {
        DeletePreInstallExceptionAppService(preScanInfo.bundleDir);
    }
}

bool BMSEventHandler::ProcessSystemHspInstall(const std::string &systemHspDir)
{
    LOG_I(BMS_TAG_DEFAULT, "Install systemHsp by bundleDir(%{public}s)", systemHspDir.c_str());
    InstallParam installParam;
    installParam.isPreInstallApp = true;
    installParam.removable = false;
    installParam.copyHapToInstallPath = false;
    installParam.needSavePreInstallInfo = true;
    installParam.preinstallSourceFlag = ApplicationInfoFlag::FLAG_BOOT_INSTALLED;
    AppServiceFwkInstaller installer;
    ErrCode ret = installer.Install({systemHspDir}, installParam);
    if (ret != ERR_OK) {
        LOG_W(BMS_TAG_DEFAULT, "Install systemHsp %{public}s error", systemHspDir.c_str());
        return false;
    }
    return true;
}

void BMSEventHandler::InnerProcessBootSkillsInstall(int32_t userId)
{
    LOG_NOFUNC_I(BMS_TAG_INSTALLER, "boot install skills size:%{public}zu", skillsList_.size());
    for (const auto &skillsPath : skillsList_) {
        ProcessSystemSkillsInstall(skillsPath, userId);
    }
}

void BMSEventHandler::ProcessSystemSkillsInstall(const PreScanInfo &preScanInfo, int32_t userId)
{
    InstallParam installParam;
    installParam.isPreInstallApp = true;
    installParam.isFirstBootInstall = true;
    installParam.removable = false;
    installParam.copyHapToInstallPath = false;
    installParam.needSavePreInstallInfo = true;
    installParam.preinstallSourceFlag = ApplicationInfoFlag::FLAG_BOOT_INSTALLED;
    installParam.needSendEvent = false;
    installParam.userId = userId;
    IndependentSkillsInstaller installer;
    ErrCode ret = installer.Install({preScanInfo.bundleDir}, installParam);
    LOG_NOFUNC_I(BMS_TAG_INSTALLER, "Install skills %{public}s result %{public}d", preScanInfo.bundleDir.c_str(), ret);
}

void BMSEventHandler::InnerProcessBootPreBundleProFileInstall(int32_t userId)
{
    // Sort in descending order of install priority
    std::map<int32_t, std::vector<PreScanInfo>, std::greater<int32_t>> taskMap;
    std::list<std::string> hspDirs;
    for (const auto &installInfo : installList_) {
        LOG_D(BMS_TAG_DEFAULT, "Inner process boot preBundle proFile install %{public}s",
            installInfo.ToString().c_str());
        if (uninstallList_.find(installInfo.bundleDir) != uninstallList_.end()) {
            LOG_I(BMS_TAG_DEFAULT, "bundle(%{public}s) not allowed installed when boot", installInfo.bundleDir.c_str());
            continue;
        }
        if (installInfo.bundleDir.find(PRE_INSTALL_HSP_PATH) != std::string::npos) {
            hspDirs.emplace_back(installInfo.bundleDir);
        } else {
            taskMap[installInfo.priority].emplace_back(installInfo);
        }
    }
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "boot install shared hsp size:%{public}zu", hspDirs.size());
    for (const auto &hspDir : hspDirs) {
        ProcessSystemSharedBundleInstall(hspDir, Constants::AppType::SYSTEM_APP);
    }

    if (taskMap.size() <= 0) {
        LOG_W(BMS_TAG_DEFAULT, "taskMap is empty");
        return;
    }
    AddTasks(taskMap, userId);
}

void BMSEventHandler::AddTasks(
    const std::map<int32_t, std::vector<PreScanInfo>, std::greater<int32_t>> &taskMap, int32_t userId)
{
    for (const auto &tasks : taskMap) {
        AddTaskParallel(tasks.first, tasks.second, userId);
    }
}

void BMSEventHandler::AddTaskParallel(
    int32_t taskPriority, const std::vector<PreScanInfo> &tasks, int32_t userId)
{
    int32_t taskTotalNum = static_cast<int32_t>(tasks.size());
    if (taskTotalNum <= 0) {
        LOG_E(BMS_TAG_DEFAULT, "The number of tasks is empty");
        return;
    }

    auto bundleMgrService = DelayedSingleton<BundleMgrService>::GetInstance();
    if (bundleMgrService == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "bundleMgrService is nullptr");
        return;
    }

    sptr<BundleInstallerHost> installerHost = bundleMgrService->GetBundleInstaller();
    if (installerHost == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "installerHost is nullptr");
        return;
    }

    size_t threadsNum = static_cast<size_t>(installerHost->GetThreadsNum());
    LOG_I(BMS_TAG_DEFAULT, "priority: %{public}d, tasks: %{public}zu, userId: %{public}d, threadsNum: %{public}zu",
        taskPriority, tasks.size(), userId, threadsNum);
    std::atomic_uint taskEndNum = 0;
    std::shared_ptr<BundlePromise> bundlePromise = std::make_shared<BundlePromise>();
    for (const auto &installInfo : tasks) {
        if (installerHost->GetCurTaskNum() >= threadsNum) {
            BMSEventHandler::ProcessSystemBundleInstall(installInfo, Constants::AppType::SYSTEM_APP, userId);
            taskEndNum++;
            continue;
        }

        auto task = [installInfo, userId, taskTotalNum, &taskEndNum, &bundlePromise]() {
            BMSEventHandler::ProcessSystemBundleInstall(installInfo, Constants::AppType::SYSTEM_APP, userId);
            taskEndNum++;
            if (bundlePromise && static_cast<int32_t>(taskEndNum) >= taskTotalNum) {
                bundlePromise->NotifyAllTasksExecuteFinished();
                LOG_I(BMS_TAG_DEFAULT, "All tasks has executed and notify promise in priority(%{public}d)",
                    installInfo.priority);
            }
            g_taskCounter--;
        };

        installerHost->AddTask(task, "BootStartInstall : " + installInfo.bundleDir);
    }

    if (static_cast<int32_t>(taskEndNum) < taskTotalNum) {
        bundlePromise->WaitForAllTasksExecute();
        LOG_I(BMS_TAG_DEFAULT, "Wait for all tasks execute in priority(%{public}d)", taskPriority);
    }
}

void BMSEventHandler::ProcessSystemBundleInstall(
    const PreScanInfo &preScanInfo, Constants::AppType appType, int32_t userId)
{
    LOG_D(BMS_TAG_DEFAULT, "Process system bundle install by bundleDir(%{public}s)", preScanInfo.bundleDir.c_str());
    InstallParam installParam;
    installParam.userId = userId;
    installParam.isPreInstallApp = true;
    installParam.isFirstBootInstall = true;
    installParam.SetKillProcess(false);
    installParam.needSendEvent = false;
    installParam.removable = preScanInfo.removable;
    installParam.needSavePreInstallInfo = true;
    installParam.copyHapToInstallPath = false;
    installParam.isDataPreloadHap = preScanInfo.isDataPreloadHap;
    installParam.appIdentifier = preScanInfo.appIdentifier;
    installParam.preinstallSourceFlag = ApplicationInfoFlag::FLAG_BOOT_INSTALLED;
    SystemBundleInstaller installer;
    ErrCode ret = installer.InstallSystemBundle(preScanInfo.bundleDir, installParam, appType);
    if (ret != ERR_OK && ret != ERR_APPEXECFWK_INSTALL_ZERO_USER_WITH_NO_SINGLETON && !preScanInfo.isDataPreloadHap) {
        LOG_W(BMS_TAG_DEFAULT, "Install System app:%{public}s error", preScanInfo.bundleDir.c_str());
        SavePreInstallException(preScanInfo.bundleDir);
    }
}

void BMSEventHandler::ProcessSystemBundleInstall(
    const std::string &bundleDir, Constants::AppType appType, int32_t userId)
{
    LOG_I(BMS_TAG_DEFAULT, "Process system bundle install by bundleDir(%{public}s)", bundleDir.c_str());
    InstallParam installParam;
    installParam.userId = userId;
    installParam.isPreInstallApp = true;
    installParam.isFirstBootInstall = true;
    installParam.SetKillProcess(false);
    installParam.needSendEvent = false;
    installParam.removable = false;
    installParam.needSavePreInstallInfo = true;
    installParam.copyHapToInstallPath = false;
    installParam.preinstallSourceFlag = ApplicationInfoFlag::FLAG_BOOT_INSTALLED;
    SystemBundleInstaller installer;
    ErrCode ret = installer.InstallSystemBundle(bundleDir, installParam, appType);
    if (ret != ERR_OK && ret != ERR_APPEXECFWK_INSTALL_ZERO_USER_WITH_NO_SINGLETON) {
        LOG_W(BMS_TAG_DEFAULT, "Install System app:%{public}s error", bundleDir.c_str());
        SavePreInstallException(bundleDir);
    }
}

void BMSEventHandler::ProcessSystemSharedBundleInstall(const std::string &sharedBundlePath, Constants::AppType appType)
{
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "Process shared bundle by sharedBundlePath(%{public}s)", sharedBundlePath.c_str());
    InstallParam installParam;
    installParam.isPreInstallApp = true;
    installParam.isFirstBootInstall = true;
    installParam.SetKillProcess(false);
    installParam.needSendEvent = false;
    installParam.removable = false;
    installParam.needSavePreInstallInfo = true;
    installParam.sharedBundleDirPaths = {sharedBundlePath};
    installParam.preinstallSourceFlag = ApplicationInfoFlag::FLAG_BOOT_INSTALLED;
    SavePreInstallExceptionShared(sharedBundlePath);
    SystemBundleInstaller installer;
    if (!installer.InstallSystemSharedBundle(installParam, false, appType)) {
        LOG_W(BMS_TAG_DEFAULT, "install system shared bundle: %{public}s error", sharedBundlePath.c_str());
    } else {
        DeletePreInstallExceptionShared(sharedBundlePath);
    }
}

void BMSEventHandler::ReInstallSystemHspAndSharedBundles()
{
    if (!LoadPreInstallProFile()) {
        LOG_W(BMS_TAG_DEFAULT, "LoadPreInstallProFile failed, skip system HSP install");
        return;
    }

    // Install system-level HSP from systemHspList_
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "ReInstallSystemHspAndSharedBundles start");
    InnerProcessBootSystemHspInstall();

    // Install shared bundles from installList_
    std::list<std::string> sharedBundleDirs;
    for (const auto &installInfo : installList_) {
        if (installInfo.bundleDir.find(PRE_INSTALL_HSP_PATH) != std::string::npos) {
            sharedBundleDirs.emplace_back(installInfo.bundleDir);
        }
    }
    if (!sharedBundleDirs.empty()) {
        InnerProcessRebootSharedBundleInstall(sharedBundleDirs, Constants::AppType::SYSTEM_APP);
    }
}

void BMSEventHandler::CreateAppInstallDir() const
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }

    std::set<int32_t> userIds = dataMgr->GetAllUser();
    for (const auto &userId : userIds) {
        if (userId == Constants::DEFAULT_USERID || userId == Constants::U1) {
            continue;
        }
        dataMgr->CreateAppInstallDir(userId);
    }
}

void BMSEventHandler::SetAllInstallFlag() const
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }

    dataMgr->SetInitialUserFlag(true);
}

void BMSEventHandler::FilterVersionSpecialCustomApps(std::set<PreScanInfo> &installList)
{
    const bool isRetailMode = system::GetBoolParameter(ServiceConstants::RETAIL_MODE_KEY, false);
    if (!isRetailMode) {
        return;
    }
    std::string deviceType = OHOS::system::GetDeviceType();
    if (deviceType != DEVICE_TYPE_PHONE) {
        LOG_D(BMS_TAG_DEFAULT, "deviceType not phone");
        return;
    }
    BmsExtensionDataMgr bmsExtensionDataMgr;
    const bool isMCFlagSet = bmsExtensionDataMgr.IsMCFlagSet();
    if (isMCFlagSet) {
        return;
    }
    for (auto it = installList.begin(); it != installList.end();) {
        bool isVersionSpecialCustomApp = it->bundleDir.rfind(VERSION_SPECIAL_CUSTOM_APP_DIR, 0) == 0;
        if (isVersionSpecialCustomApp) {
            LOG_I(BMS_TAG_DEFAULT, "filter version special custom app, %{public}s", it->bundleDir.c_str());
            it = installList.erase(it);
        } else {
            ++it;
        }
    }
}

void BMSEventHandler::OnBundleRebootStart()
{
    InstalldClient::GetInstance()->ResetBmsDBSecurity();
    ProcessRebootBundle();
}

void BMSEventHandler::ProcessRebootBundle()
{
    LOG_I(BMS_TAG_DEFAULT, "BMSEventHandler Process reboot bundle start");
    LoadAllPreInstallBundleInfos();
    BundleResourceHelper::DeleteNotExistResourceInfo();
    InnerProcessRebootUninstallWrongBundle();
    ProcessRebootCheckOnDemandBundle();
    XCollieHelper::PauseFoundationWatchdog();
    ProcessRebootBundleInstall();
    ProcessRebootBundleUninstall();
    ProcessRebootAppServiceUninstall();
    ProcessRebootSkillsUninstall();
    //refresh application permissions
    ProcessUpdatePermissions();
    //refresh pre-authorization for all installed apps during OTA (every OTA)
    if (BundlePermissionMgr::RefreshPreAuthorizationForOTA()) {
        LOG_NOFUNC_I(BMS_TAG_DEFAULT, "Refresh pre-authorization success");
    } else {
        LOG_NOFUNC_W(BMS_TAG_DEFAULT, "Refresh pre-authorization failed");
    }
    ProcessRebootQuickFixBundleInstall(QUICK_FIX_APP_PATH, true);
    ProcessRebootQuickFixUnInstallAndRecover(QUICK_FIX_APP_RECOVER_FILE);
    ProcessMigrateSkillDir();
    XCollieHelper::ResumeFoundationWatchdog();
    ProcessBundleResourceInfo();
    ProcessAllBundleDataGroupInfo();
#ifdef CHECK_ELDIR_ENABLED
    ProcessCheckAppDataDir();
#endif
    ProcessCheckAppLogDir();
    ProcessCheckAppFileManagerDir();
    ProcessCheckPrintServiceDir();
    ProcessCheckPreinstallData();
    ProcessCheckSystemOptimizeDir();
    ProcessCheckSystemOptimizeShaderCacheDir();
    ProcessNewBackupDir();
    CheckAndCreateShareFilesSubDataDirs();
    RefreshQuotaForAllUid();
    ProcessCheckRecoverableApplicationInfo();
    ProcessCheckInstallSource();
    ProcessCheckAppExtensionAbility();
    ProcessRouterMap();
    ProcessEmptyOdid();
    // Driver update may cause shader cache invalidity and need to be cleared
    CleanSystemOptimizeShaderCache();
    CleanAllBundleEl1ArkStartupCacheLocal();
    if (OHOS::system::GetBoolParameter(ServiceConstants::BMS_RELABEL_PARAM, false)) {
        (void)ProcessIdleInfo();
    }
}

bool BMSEventHandler::CheckOtaFlag(OTAFlag flag, bool &result)
{
    auto bmsPara = DelayedSingleton<BundleMgrService>::GetInstance()->GetBmsParam();
    if (bmsPara == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "bmsPara is nullptr");
        return false;
    }

    std::string val;
    if (!bmsPara->GetBmsParam(OTA_FLAG, val)) {
        LOG_I(BMS_TAG_DEFAULT, "GetBmsParam OTA_FLAG failed");
        return false;
    }

    int32_t valInt = 0;
    if (!StrToInt(val, valInt)) {
        LOG_E(BMS_TAG_DEFAULT, "val(%{public}s) strToInt failed", val.c_str());
        return false;
    }

    result = static_cast<uint32_t>(flag) & static_cast<uint32_t>(valInt);
    return true;
}

bool BMSEventHandler::UpdateOtaFlag(OTAFlag flag)
{
    auto bmsPara = DelayedSingleton<BundleMgrService>::GetInstance()->GetBmsParam();
    if (bmsPara == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "bmsPara is nullptr");
        return false;
    }

    std::string val;
    if (!bmsPara->GetBmsParam(OTA_FLAG, val)) {
        LOG_I(BMS_TAG_DEFAULT, "GetBmsParam OTA_FLAG failed");
        return bmsPara->SaveBmsParam(OTA_FLAG, std::to_string(flag));
    }

    int32_t valInt = 0;
    if (!StrToInt(val, valInt)) {
        LOG_E(BMS_TAG_DEFAULT, "val(%{public}s) strToInt failed", val.c_str());
        return bmsPara->SaveBmsParam(OTA_FLAG, std::to_string(flag));
    }

    return bmsPara->SaveBmsParam(
        OTA_FLAG, std::to_string(static_cast<uint32_t>(flag) | static_cast<uint32_t>(valInt)));
}

void BMSEventHandler::ProcessCheckAppDataDir()
{
    bool checkElDir = false;
    CheckOtaFlag(OTAFlag::CHECK_ELDIR, checkElDir);
    if (checkElDir) {
        LOG_I(BMS_TAG_DEFAULT, "Not need to check data dir due to has checked");
        return;
    }

    LOG_I(BMS_TAG_DEFAULT, "Need to check data dir");
    InnerProcessCheckAppDataDir();
    UpdateOtaFlag(OTAFlag::CHECK_ELDIR);
}

void BMSEventHandler::InnerProcessCheckAppDataDir()
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }

    std::set<int32_t> userIds = dataMgr->GetAllUser();
    for (const auto &userId : userIds) {
        std::vector<BundleInfo> bundleInfos;
        if (!dataMgr->GetBundleInfos(static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE),
            bundleInfos, userId)) {
            LOG_W(BMS_TAG_DEFAULT, "UpdateAppDataDir GetAllBundleInfos failed");
            continue;
        }

        UpdateAppDataMgr::ProcessUpdateAppDataDir(
            userId, bundleInfos, ServiceConstants::DIR_EL3);
        UpdateAppDataMgr::ProcessUpdateAppDataDir(
            userId, bundleInfos, ServiceConstants::DIR_EL4);
    }
}

void BMSEventHandler::ProcessCheckPreinstallData()
{
    bool checkPreinstallData = false;
    CheckOtaFlag(OTAFlag::CHECK_PREINSTALL_DATA, checkPreinstallData);
    if (checkPreinstallData) {
        LOG_I(BMS_TAG_DEFAULT, "Not need to check preinstall app data due to has checked");
        return;
    }
    LOG_I(BMS_TAG_DEFAULT, "Need to check preinstall data");
    InnerProcessCheckPreinstallData();
    UpdateOtaFlag(OTAFlag::CHECK_PREINSTALL_DATA);
}

void BMSEventHandler::InnerProcessCheckPreinstallData()
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }
    std::vector<PreInstallBundleInfo> preInstallBundleInfos = dataMgr->GetAllPreInstallBundleInfos();
    for (auto &preInstallBundleInfo : preInstallBundleInfos) {
        BundleInfo bundleInfo;
        if (dataMgr->GetBundleInfo(preInstallBundleInfo.GetBundleName(),
            static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE),
            bundleInfo, Constants::ALL_USERID)) {
            preInstallBundleInfo.SetIconId(bundleInfo.applicationInfo.iconResource.id);
            preInstallBundleInfo.SetLabelId(bundleInfo.applicationInfo.labelResource.id);
            preInstallBundleInfo.SetDescriptionId(bundleInfo.applicationInfo.descriptionId);
            preInstallBundleInfo.SetModuleName(bundleInfo.applicationInfo.labelResource.moduleName);
            dataMgr->SavePreInstallBundleInfo(bundleInfo.name, preInstallBundleInfo);
            continue;
        }
        BundleMgrHostImpl impl;
        BundleInfo resultBundleInfo;
        auto preinstalledAppPaths = preInstallBundleInfo.GetBundlePaths();
        for (auto preinstalledAppPath: preinstalledAppPaths) {
            if (!impl.GetBundleArchiveInfo(preinstalledAppPath, GET_BUNDLE_DEFAULT, resultBundleInfo)) {
                LOG_E(BMS_TAG_DEFAULT, "Get bundle archive info fail");
                break;
            }
            preInstallBundleInfo.SetLabelId(resultBundleInfo.applicationInfo.labelResource.id);
            preInstallBundleInfo.SetIconId(resultBundleInfo.applicationInfo.iconResource.id);
            preInstallBundleInfo.SetDescriptionId(resultBundleInfo.applicationInfo.descriptionId);
            preInstallBundleInfo.SetModuleName(resultBundleInfo.applicationInfo.labelResource.moduleName);
            if (!resultBundleInfo.hapModuleInfos.empty() &&
                resultBundleInfo.hapModuleInfos[0].moduleType == ModuleType::ENTRY) {
                break;
            }
        }
        // Use pre-install record key; resultBundleInfo.name may be empty if no path parsed successfully.
        dataMgr->SavePreInstallBundleInfo(preInstallBundleInfo.GetBundleName(), preInstallBundleInfo);
    }
}

void BMSEventHandler::ProcessCheckAppLogDir()
{
    bool checkLogDir = false;
    CheckOtaFlag(OTAFlag::CHECK_LOG_DIR, checkLogDir);
    if (checkLogDir) {
        LOG_I(BMS_TAG_DEFAULT, "Not need to check log dir due to has checked");
        return;
    }
    LOG_I(BMS_TAG_DEFAULT, "Need to check log dir");
    InnerProcessCheckAppLogDir();
    UpdateOtaFlag(OTAFlag::CHECK_LOG_DIR);
}

void BMSEventHandler::InnerProcessCheckAppLogDir()
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }
    std::vector<BundleInfo> bundleInfos;
    if (!dataMgr->GetBundleInfos(static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE),
        bundleInfos, Constants::DEFAULT_USERID)) {
        LOG_E(BMS_TAG_DEFAULT, "GetAllBundleInfos for u0 failed");
        return;
    }
    UpdateAppDataMgr::ProcessUpdateAppLogDir(bundleInfos, Constants::DEFAULT_USERID);

    bundleInfos.clear();
    if (!dataMgr->GetBundleInfos(static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE),
        bundleInfos, Constants::U1)) {
        LOG_E(BMS_TAG_DEFAULT, "GetAllBundleInfos for user 1 failed");
        return;
    }
    UpdateAppDataMgr::ProcessUpdateAppLogDir(bundleInfos, Constants::U1);
}

void BMSEventHandler::ProcessCheckAppFileManagerDir()
{
    bool checkDir = false;
    CheckOtaFlag(OTAFlag::CHECK_FILE_MANAGER_DIR, checkDir);
    if (checkDir) {
        LOG_I(BMS_TAG_DEFAULT, "Not need to check file manager dir due to has checked");
        return;
    }
    LOG_I(BMS_TAG_DEFAULT, "Need to check file manager dir");
    InnerProcessCheckAppFileManagerDir();
    UpdateOtaFlag(OTAFlag::CHECK_FILE_MANAGER_DIR);
}

void BMSEventHandler::InnerProcessCheckAppFileManagerDir()
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }
    std::vector<BundleInfo> bundleInfos;
    if (!dataMgr->GetBundleInfos(static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE),
        bundleInfos, Constants::DEFAULT_USERID)) {
        LOG_E(BMS_TAG_DEFAULT, "GetAllBundleInfos for u0 failed");
        return;
    }
    UpdateAppDataMgr::ProcessFileManagerDir(bundleInfos, Constants::DEFAULT_USERID);

    bundleInfos.clear();
    if (!dataMgr->GetBundleInfos(static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE),
        bundleInfos, Constants::U1)) {
        LOG_E(BMS_TAG_DEFAULT, "GetAllBundleInfos  for u1 failed");
        return;
    }
    UpdateAppDataMgr::ProcessFileManagerDir(bundleInfos, Constants::U1);
}

void BMSEventHandler::ProcessCheckPrintServiceDir()
{
    bool checkPrintServiceDir = false;
    CheckOtaFlag(OTAFlag::CHECK_PRINT_SERVICE_DIR, checkPrintServiceDir);
    if (checkPrintServiceDir) {
        LOG_I(BMS_TAG_DEFAULT, "Not need to check print service dir due to has checked");
        return;
    }
    LOG_I(BMS_TAG_DEFAULT, "Need to check print service dir");
    if (!InnerProcessCheckPrintServiceDir()) {
        LOG_W(BMS_TAG_DEFAULT, "check print service dir not finished, retry on next reboot");
        return;
    }
    UpdateOtaFlag(OTAFlag::CHECK_PRINT_SERVICE_DIR);
}

bool BMSEventHandler::InnerProcessCheckPrintServiceDir()
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return false;
    }
    std::vector<PrintServiceDirInfo> printDirInfos;
    dataMgr->GetDriverBundlePrintDirInfos(printDirInfos);
    bool allSuccess = true;
    for (const auto &dirInfo : printDirInfos) {
        ErrCode result = InstalldClient::GetInstance()->CreatePrintServiceDir(
            dirInfo.bundleName, dirInfo.userId, dirInfo.appIndex, dirInfo.uid);
        if (result != ERR_OK) {
            allSuccess = false;
            LOG_W(BMS_TAG_DEFAULT, "check print service dir failed, bundle: %{public}s, "
                "userId: %{public}d, appIndex: %{public}d, error is %{public}d",
                dirInfo.bundleName.c_str(), dirInfo.userId, dirInfo.appIndex, result);
        }
    }
    return allSuccess;
}

void BMSEventHandler::ProcessCheckSystemOptimizeShaderCacheDir()
{
    bool checkShaderCache = false;
    CheckOtaFlag(OTAFlag::CHECK_SYSTEM_OPTIMIZE_SHADER_CAHCE_DIR, checkShaderCache);
    if (checkShaderCache) {
        LOG_NOFUNC_I(BMS_TAG_DEFAULT, "Not need to check system optimize shader cache dir due to has checked");
        return;
    }
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "Need to check system optimize shader cache dir");
    CheckSystemOptimizeShaderCache();
    UpdateOtaFlag(OTAFlag::CHECK_SYSTEM_OPTIMIZE_SHADER_CAHCE_DIR);
}

void BMSEventHandler::ProcessNewBackupDir()
{
    bool checkBackup = false;
    CheckOtaFlag(OTAFlag::CHECK_BACK_UP_DIR, checkBackup);
    if (checkBackup) {
        LOG_D(BMS_TAG_DEFAULT, "Not need to check back up dir due to has checked");
        return;
    }
    LOG_I(BMS_TAG_DEFAULT, "Need to check back up dir");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }
    std::set<int32_t> userIds = dataMgr->GetAllUser();
    for (const auto &userId : userIds) {
        if (userId == Constants::DEFAULT_USERID || userId == Constants::U1) {
            continue;
        }
        std::vector<BundleInfo> bundleInfos;
        if (!dataMgr->GetBundleInfos(static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE),
            bundleInfos, userId)) {
            LOG_W(BMS_TAG_DEFAULT, "ProcessNewBackupDir GetAllBundleInfos failed");
            continue;
        }
        UpdateAppDataMgr::ProcessNewBackupDir(bundleInfos, userId);
    }
    UpdateOtaFlag(OTAFlag::CHECK_BACK_UP_DIR);
}
void BMSEventHandler::ProcessCheckRecoverableApplicationInfo()
{
    bool hasCheck = false;
    CheckOtaFlag(OTAFlag::CHECK_RECOVERABLE_APPLICATION_INFO, hasCheck);
    if (hasCheck) {
        LOG_D(BMS_TAG_DEFAULT, "recoverable app info has checked");
        return;
    }
    LOG_D(BMS_TAG_DEFAULT, "Need to check recoverable app info");
    InnerProcessCheckRecoverableApplicationInfo();
    UpdateOtaFlag(OTAFlag::CHECK_RECOVERABLE_APPLICATION_INFO);
}

void BMSEventHandler::InnerProcessCheckRecoverableApplicationInfo()
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }
    std::vector<PreInstallBundleInfo> preInstallBundleInfos = dataMgr->GetAllPreInstallBundleInfos();
    for (auto &preInstallBundleInfo : preInstallBundleInfos) {
        BundleInfo bundleInfo;
        if (dataMgr->GetBundleInfo(preInstallBundleInfo.GetBundleName(),
            static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE),
            bundleInfo, Constants::ALL_USERID)) {
            preInstallBundleInfo.SetSystemApp(bundleInfo.applicationInfo.isSystemApp);
            if (bundleInfo.isNewVersion) {
                preInstallBundleInfo.SetBundleType(bundleInfo.applicationInfo.bundleType);
            } else if (!bundleInfo.hapModuleInfos.empty() &&
                bundleInfo.hapModuleInfos[0].installationFree) {
                preInstallBundleInfo.SetBundleType(BundleType::ATOMIC_SERVICE);
            }
            dataMgr->SavePreInstallBundleInfo(preInstallBundleInfo.GetBundleName(), preInstallBundleInfo);
            continue;
        }
        BundleMgrHostImpl impl;
        auto preinstalledAppPaths = preInstallBundleInfo.GetBundlePaths();
        for (auto preinstalledAppPath: preinstalledAppPaths) {
            BundleInfo archiveBundleInfo;
            if (!impl.GetBundleArchiveInfo(preinstalledAppPath, GET_BUNDLE_DEFAULT, archiveBundleInfo)) {
                LOG_E(BMS_TAG_DEFAULT, "Get bundle archive info fail");
                break;
            }
            preInstallBundleInfo.SetSystemApp(archiveBundleInfo.applicationInfo.isSystemApp);
            if (archiveBundleInfo.isNewVersion) {
                preInstallBundleInfo.SetBundleType(archiveBundleInfo.applicationInfo.bundleType);
            } else if (!archiveBundleInfo.hapModuleInfos.empty() &&
                archiveBundleInfo.hapModuleInfos[0].installationFree) {
                preInstallBundleInfo.SetBundleType(BundleType::ATOMIC_SERVICE);
            }
            if (!archiveBundleInfo.hapModuleInfos.empty() &&
                archiveBundleInfo.hapModuleInfos[0].moduleType == ModuleType::ENTRY) {
                break;
            }
        }
        dataMgr->SavePreInstallBundleInfo(preInstallBundleInfo.GetBundleName(), preInstallBundleInfo);
    }
}

void BMSEventHandler::ProcessCheckInstallSource()
{
    bool hasCheck = false;
    CheckOtaFlag(OTAFlag::CHECK_INSTALL_SOURCE, hasCheck);
    if (hasCheck) {
        LOG_D(BMS_TAG_DEFAULT, "install source has checked");
        return;
    }
    LOG_D(BMS_TAG_DEFAULT, "Need to check install source");
    InnerProcessCheckInstallSource();
    UpdateOtaFlag(OTAFlag::CHECK_INSTALL_SOURCE);
}

void BMSEventHandler::InnerProcessCheckInstallSource()
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }
    std::vector<PreInstallBundleInfo> preInstallBundleInfos = dataMgr->GetAllPreInstallBundleInfos();
    for (const auto &preInstallBundleInfo : preInstallBundleInfos) {
        InnerBundleInfo innerBundleInfo;
        if (!dataMgr->FetchInnerBundleInfo(preInstallBundleInfo.GetBundleName(), innerBundleInfo)) {
            LOG_NOFUNC_W(BMS_TAG_DEFAULT, "update installSorce FetchInnerBundleInfo fail -n %{public}s",
                preInstallBundleInfo.GetBundleName().c_str());
            continue;
        }
        std::string installSource = ConvertApplicationFlagToInstallSource(innerBundleInfo.GetApplicationFlags());
        if (installSource.empty()) {
            continue;
        }
        innerBundleInfo.SetInstallSource(installSource);
        if (!dataMgr->UpdateInnerBundleInfo(innerBundleInfo)) {
            LOG_NOFUNC_W(BMS_TAG_DEFAULT, "update installSorce UpdateInnerBundleInfo fail -n %{public}s",
                preInstallBundleInfo.GetBundleName().c_str());
        }
    }
}

std::string BMSEventHandler::ConvertApplicationFlagToInstallSource(int32_t flag)
{
    if (static_cast<uint32_t>(flag) & static_cast<uint32_t>(ApplicationInfoFlag::FLAG_BOOT_INSTALLED)) {
        return ServiceConstants::INSTALL_SOURCE_PREINSTALL;
    }
    if (static_cast<uint32_t>(flag) & static_cast<uint32_t>(ApplicationInfoFlag::FLAG_OTA_INSTALLED)) {
        return ServiceConstants::INSTALL_SOURCE_OTA;
    }
    if (static_cast<uint32_t>(flag) & static_cast<uint32_t>(ApplicationInfoFlag::FLAG_RECOVER_INSTALLED)) {
        return ServiceConstants::INSTALL_SOURCE_RECOVERY;
    }
    return Constants::EMPTY_STRING;
}

static void SendToStorageQuota(const std::string &bundleName, const int32_t uid,
    const std::string &bundleDataDirPath, const int32_t limitSizeMb)
{
#ifdef STORAGE_SERVICE_ENABLE
    auto systemAbilityManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        LOG_W(BMS_TAG_DEFAULT, "SendToStorageQuota, systemAbilityManager error");
        return;
    }

    auto remote = systemAbilityManager->CheckSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    if (!remote) {
        LOG_W(BMS_TAG_DEFAULT, "SendToStorageQuota, CheckSystemAbility error");
        return;
    }

    auto proxy = iface_cast<StorageManager::IStorageManager>(remote);
    if (!proxy) {
        LOG_W(BMS_TAG_DEFAULT, "SendToStorageQuotactl, proxy get error");
        return;
    }

    int err = proxy->SetBundleQuota(bundleName, uid, bundleDataDirPath, limitSizeMb);
    if (err != ERR_OK) {
        LOG_W(BMS_TAG_DEFAULT, "SendToStorageQuota, SetBundleQuota error, err=%{public}d, uid=%{public}d", err, uid);
    }
#endif // STORAGE_SERVICE_ENABLE
}

void BMSEventHandler::PrepareBundleDirQuota(const std::string &bundleName, const int32_t uid,
    const std::string &bundleDataDirPath, const int32_t limitSize) const
{
    if (limitSize == 0) {
        SendToStorageQuota(bundleName, uid, bundleDataDirPath, 0);
        return;
    }
    int32_t atomicserviceDatasizeThreshold = limitSize;
#ifdef STORAGE_SERVICE_ENABLE
#ifdef QUOTA_PARAM_SET_ENABLE
    char szAtomicDatasizeThresholdMb[THRESHOLD_VAL_LEN] = {0};
    int32_t ret = GetParameter(SYSTEM_PARAM_ATOMICSERVICE_DATASIZE_THRESHOLD.c_str(), "",
        szAtomicDatasizeThresholdMb, THRESHOLD_VAL_LEN);
    if (ret <= 0) {
        LOG_I(BMS_TAG_DEFAULT, "GetParameter failed");
    } else if (strcmp(szAtomicDatasizeThresholdMb, "") != 0) {
        atomicserviceDatasizeThreshold = atoi(szAtomicDatasizeThresholdMb);
        LOG_I(BMS_TAG_DEFAULT, "InstalldQuotaUtils init atomicserviceDataThreshold mb success");
    }
    if (atomicserviceDatasizeThreshold <= 0) {
        LOG_W(BMS_TAG_DEFAULT, "no need to prepare quota");
        return;
    }
#endif // QUOTA_PARAM_SET_ENABLE
#endif // STORAGE_SERVICE_ENABLE
    ParseSizeFromProvision(bundleName, uid, atomicserviceDatasizeThreshold);
    SendToStorageQuota(bundleName, uid, bundleDataDirPath, atomicserviceDatasizeThreshold);
}

void BMSEventHandler::ParseSizeFromProvision(const std::string &bundleName, const int32_t uid, int32_t &sizeMb) const
{
    AppProvisionInfo provisionInfo;
    if (!DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAppProvisionInfo(bundleName, provisionInfo)) {
        LOG_W(BMS_TAG_DEFAULT, "GetAppProvisionInfo failed");
        return;
    }
    if (provisionInfo.appServiceCapabilities.empty()) {
        return;
    }
    auto appServiceCapabilityMap = BundleUtil::ParseMapFromJson(provisionInfo.appServiceCapabilities);
    for (auto &item : appServiceCapabilityMap) {
        if (item.first != ServiceConstants::PERMISSION_MANAGE_STORAGE) {
            continue;
        }
        if (BundlePermissionMgr::VerifyPermission(bundleName, ServiceConstants::PERMISSION_MANAGE_STORAGE,
            uid / Constants::BASE_USER_RANGE) != Security::AccessToken::PermissionState::PERMISSION_GRANTED) {
            APP_LOGW("no manage storage permission for %{public}s", bundleName.c_str());
            return;
        }
        std::unordered_map<std::string, std::string> storageMap = BundleUtil::ParseMapFromJson(item.second);
        auto it = storageMap.find(KEY_STORAGE_SIZE);
        if (it == storageMap.end()) {
            LOG_W(BMS_TAG_INSTALLER, "storageSize not found");
            return;
        }
        int32_t tempSize = atoi(it->second.c_str());
        if (tempSize >= sizeMb) {
            sizeMb = tempSize;
            LOG_I(BMS_TAG_INSTALLER, "set %{public}s quota to %{public}d", bundleName.c_str(), sizeMb);
        } else {
            LOG_W(BMS_TAG_INSTALLER, "%{public}s storageSize %{public}d is not valid", bundleName.c_str(), tempSize);
        }
        return;
    }
}

void BMSEventHandler::RefreshQuotaForAllUid()
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }
    std::map<std::string, InnerBundleInfo> infos = dataMgr->GetAllInnerBundleInfos();
    for (auto &infoPair : infos) {
        auto &info = infoPair.second;
        std::map<std::string, InnerBundleUserInfo> userInfos = info.GetInnerBundleUserInfos();
        for (auto &userInfoPair : userInfos) {
            auto &userInfo = userInfoPair.second;
            std::string bundleDataDir = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR + ServiceConstants::BUNDLE_EL[0] +
                ServiceConstants::PATH_SEPARATOR + std::to_string(userInfo.bundleUserInfo.userId) +
                ServiceConstants::BASE + info.GetBundleName();
            if (info.GetApplicationBundleType() != BundleType::ATOMIC_SERVICE) {
                PrepareBundleDirQuota(info.GetBundleName(), info.GetUid(userInfo.bundleUserInfo.userId),
                    bundleDataDir, 0);
            } else {
                PrepareBundleDirQuota(info.GetBundleName(), info.GetUid(userInfo.bundleUserInfo.userId),
                    bundleDataDir, ATOMIC_SERVICE_DATASIZE_THRESHOLD_MB_PRESET);
            }
        }
    }
}

bool BMSEventHandler::LoadAllPreInstallBundleInfos()
{
    if (hasLoadAllPreInstallBundleInfosFromDb_) {
        LOG_I(BMS_TAG_DEFAULT, "Has load all preInstall bundleInfos from db");
        return true;
    }

    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return false;
    }

    std::vector<PreInstallBundleInfo> preInstallBundleInfos = dataMgr->GetAllPreInstallBundleInfos();
    for (auto &iter : preInstallBundleInfos) {
        // Dual-mode: key by the storage key (clone-prefixed name for the secondary variant) so
        // primary and clone entries — both carrying the same original bundleName — coexist in
        // the map. HandlePreInstallBundleNamesException looks up by the exception bundle name
        // (clone key for the secondary variant), so the clone entry must be findable.
        std::string storageKey = iter.IsDualModeCloneApp()
            ? DualModeHelper::GetDualModeBundleName(iter.GetBundleName())
            : iter.GetBundleName();
        LOG_D(BMS_TAG_DEFAULT, "load preInstallBundleInfos: %{public}s ", storageKey.c_str());
        loadExistData_.emplace(storageKey, iter);
    }

    hasLoadAllPreInstallBundleInfosFromDb_ = true;
    return !preInstallBundleInfos.empty();
}

void BMSEventHandler::LoadPreInstallWhiteList()
{
    allUserIds_.clear();
    xmlMap_.clear();
    needInstallUserIds_.clear();
    std::unordered_map<uint64_t, std::vector<std::string>> logicalIdWhiteListMap;
    bool isWhiteListExist = XmlUtil::PatchReadWhiteListXml(logicalIdWhiteListMap);
    if (!isWhiteListExist) {
        LOG_NOFUNC_E(BMS_TAG_DEFAULT, "load preInstallWhiteListMap fail or whiteList not exist");
        return;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_NOFUNC_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }
    allUserIds_ = dataMgr->GetAllUser();
    for (const auto &logicalIdWhiteList : logicalIdWhiteListMap) {
        uint64_t logicalId = logicalIdWhiteList.first;
        int32_t userId = AccountHelper::GetUserIdByDisplayIdWithRetry(logicalId);
        if (userId == Constants::INVALID_USERID) {
            LOG_NOFUNC_E(BMS_TAG_DEFAULT, "get userId by displayId fail");
            continue;
        } else {
            xmlMap_[userId] = logicalIdWhiteList.second;
        }
    }
}

void BMSEventHandler::LoadOtaNewInstallWhitelist()
{
    if (otaNewInstallWhitelistLoaded_) {
        return;
    }
    otaNewInstallWhitelistLoaded_ = true;
    otaNewInstallEnable_ = false;
    otaNewInstallWhitelist_.clear();

    multiUserInstallThirdPreloadApp_ = OHOS::system::GetBoolParameter(OTA_NEW_INSTALL_MULTIUSER_PARAM, true);

    if (OHOS::system::GetBoolParameter(OTA_NEW_INSTALL_ENABLE_PARAM, false)) {
        LOG_NOFUNC_I(BMS_TAG_DEFAULT, "OTA_NEW_INSTALL_ENABLE_PARAM is true");
        otaNewInstallEnable_ = true;
        return;
    }

    if (!BundleParser::LoadWhitelistFromFile(
        ServiceConstants::ALLOW_OTA_NEW_INSTALL_WHITELIST_PATH, otaNewInstallWhitelist_)) {
        return;
    }
    if (otaNewInstallWhitelist_.empty()) {
        LOG_NOFUNC_W(BMS_TAG_DEFAULT, "OTA_NEW_INSTALL_WHITELIST_PATH empty");
    }
}

bool BMSEventHandler::NeedProcessOtaNewPreloadInstall(const std::string &bundleName,
    const std::string &scanPath) const
{
    if (bundleName.empty()) {
        LOG_NOFUNC_W(BMS_TAG_DEFAULT, "bundleName is empty");
        return false;
    }
    if (scanPath.find(ServiceConstants::PRELOAD_APP_DIR) != 0) {
        return false;
    }
    if (otaNewInstallEnable_) {
        return true;
    }
    bool bypassByHideDesktopIcon = false;
    PreBundleConfigInfo preBundleConfigInfo;
    preBundleConfigInfo.bundleName = bundleName;
    if (GetPreInstallCapability(preBundleConfigInfo)) {
        bypassByHideDesktopIcon = preBundleConfigInfo.hideDesktopIcon;
    } else {
        bool hideDesktopIcon = false;
        BundleInstallChecker bundleInstallChecker;
        std::vector<std::string> filePaths;
        ErrCode checkRet = BundleUtil::CheckFilePath({scanPath}, filePaths);
        if (checkRet != ERR_OK || filePaths.empty()) {
            LOG_NOFUNC_W(BMS_TAG_DEFAULT, "obtain real path failed : %{public}s", bundleName.c_str());
            return false;
        }
        if (bundleInstallChecker.GetHideDesktopIconByBundlePath(filePaths.front(), hideDesktopIcon)) {
            bypassByHideDesktopIcon = hideDesktopIcon;
        }
    }
    // hideDesktopIcon=true bypasses whitelist and other gating checks.
    if (bypassByHideDesktopIcon) {
        return true;
    }
    if (otaNewInstallWhitelist_.find(bundleName) == otaNewInstallWhitelist_.end()) {
        LOG_NOFUNC_W(BMS_TAG_DEFAULT, "bundleName not in otaNewInstallWhitelist_");
        return false;
    }
    return true;
}

void BMSEventHandler::ProcessRebootBundleInstall()
{
    LOG_I(BMS_TAG_DEFAULT, "BMSEventHandler Process reboot bundle install start");
    LoadPreInstallWhiteList();
    // Ota whitelist depends on installListCapabilities_ (hideDesktopIcon) which requires profile load.
    LoadOtaNewInstallWhitelist();
#ifdef USE_PRE_BUNDLE_PROFILE
    if (LoadPreInstallProFile()) {
        ProcessReBootPreBundleProFileInstall();
        return;
    }
#else
    ProcessRebootBundleInstallFromScan();
#endif
}

void BMSEventHandler::ProcessReBootPreBundleProFileInstall()
{
    std::list<std::string> bundleDirs;
    std::list<std::string> sharedBundleDirs;
    for (const auto &installInfo : installList_) {
        if (uninstallList_.find(installInfo.bundleDir) != uninstallList_.end()) {
            LOG_NOFUNC_W(BMS_TAG_DEFAULT, "(%{public}s) not allowed installed when reboot",
                installInfo.bundleDir.c_str());
            continue;
        }

        if (installInfo.bundleDir.find(PRE_INSTALL_HSP_PATH) != std::string::npos) {
            LOG_NOFUNC_I(BMS_TAG_DEFAULT, "found shared bundle path: %{public}s", installInfo.bundleDir.c_str());
            sharedBundleDirs.emplace_back(installInfo.bundleDir);
        } else {
            bundleDirs.emplace_back(installInfo.bundleDir);
        }
    }

    std::list<std::string> systemHspDirs;
    for (const auto &systemHspScanInfo : systemHspList_) {
        systemHspDirs.emplace_back(systemHspScanInfo.bundleDir);
    }

    std::list<std::string> skillsDirs;
    for (const auto &skillsScanInfo : skillsList_) {
        skillsDirs.emplace_back(skillsScanInfo.bundleDir);
    }

    InnerProcessRebootSystemHspInstall(systemHspDirs);
    InnerProcessRebootSkillsInstall(skillsDirs);
    InnerProcessRebootSharedBundleInstall(sharedBundleDirs, Constants::AppType::SYSTEM_APP);
    InnerProcessRebootBundleInstall(bundleDirs, Constants::AppType::SYSTEM_APP);
    InnerProcessStockBundleProvisionInfo();
    InnerProcessStockBundleRouterInfo();
}

void BMSEventHandler::ProcessRebootBundleInstallFromScan()
{
    LOG_D(BMS_TAG_DEFAULT, "Process reboot bundle install from scan");
    std::list<std::string> bundleDirs;
    GetBundleDirFromScan(bundleDirs);
    InnerProcessRebootBundleInstall(bundleDirs, Constants::AppType::SYSTEM_APP);
    InnerProcessStockBundleProvisionInfo();
    InnerProcessStockBundleRouterInfo();
}

bool BMSEventHandler::GetBundleNameAndUserIdFromPath(const std::string &path,
    std::vector<int32_t> &userIds, std::string &bundleName)
{
    if (bundleName.empty()) {
        std::unordered_map<std::string, InnerBundleInfo> infos;
        if (!ParseHapFiles(path, infos) || infos.empty()) {
            LOG_NOFUNC_E(BMS_TAG_DEFAULT, "obtain bundleinfo failed : %{public}s ", path.c_str());
            return false;
        }
        bundleName = infos.begin()->second.GetBundleName();
    }

    userIds.clear();
    for (const auto &userId : allUserIds_) {
        if (userId == Constants::DEFAULT_USERID) {
            continue;
        }
        if (xmlMap_.find(userId) != xmlMap_.end() && std::find(xmlMap_[userId].begin(),
            xmlMap_[userId].end(), bundleName) == xmlMap_[userId].end()) {
            continue;
        }
        if (needInstallUserIds_.find(bundleName) != needInstallUserIds_.end()
            && needInstallUserIds_[bundleName].count(userId) == 0) {
            continue;
        }
        userIds.emplace_back(userId);
    }
    return true;
}

void BMSEventHandler::InnerProcessRebootBundleInstall(
    const std::list<std::string> &scanPathList, Constants::AppType appType)
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }
    auto newBundleDirMgr = DelayedSingleton<NewBundleDataDirMgr>::GetInstance();
    if (newBundleDirMgr != nullptr) {
        (void)newBundleDirMgr->AddAllUserId(dataMgr->GetAllUser());
    }

    std::unique_ptr<BundleInstallChecker> bundleInstallChecker =
        std::make_unique<BundleInstallChecker>();
    GetInstallAndRecoverListForAllUser(userInstallAndRecoverMap_);
    std::unordered_map<std::string, std::pair<std::vector<std::string>, bool>> needInstallMap;
    std::unordered_map<std::string, std::pair<std::vector<std::string>, bool>> needInstallSysMap;
    // Dual-mode OTA: record bundleName -> distribution policy for new installs, passed to installParam.
    std::unordered_map<std::string, DeviceModeDistributionPolicy> dualModePolicyForNewMap;
    // Dual-mode OTA: pending cross-mode install/update tasks (key is the target-side storage name,
    // the +clone-10000+ prefixed name for the secondary-mode side).
    std::unordered_map<std::string, CrossModeOtaTask> crossModeOtaTasks;
    std::unordered_set<std::string> overlayBundles;
    // new OTA bundles, install for target users
    std::unordered_map<std::string, std::vector<int32_t>> blackListBundles;
    // OTA new-preload whitelist: target install users for newly allowed bundles
    std::unordered_map<std::string, std::vector<int32_t>> otaNewInstallTargetUsersForNew;
    auto canMarkOtaNewInstallUser = [&dataMgr](const std::string &bundleName) {
        if (dataMgr->IsHideDesktopIconForEvent(bundleName)) {
            LOG_NOFUNC_I(BMS_TAG_DEFAULT, "skip ota new-install marking for hideDesktopIcon app %{public}s",
                bundleName.c_str());
            return false;
        }
        return true;
    };
    auto markOtaNewInstallUser = [&dataMgr](const std::string &bundleName, const std::vector<int32_t> &userIds)->void {
        PreInstallBundleInfo preInstallBundleInfo;
        if (!dataMgr->GetPreInstallBundleInfo(bundleName, preInstallBundleInfo)) {
            return;
        }
        InnerBundleInfo innerBundleInfo;
        if (!dataMgr->FetchInnerBundleInfo(bundleName, innerBundleInfo)) {
            return;
        }
        if (innerBundleInfo.IsSingleton()) {
            preInstallBundleInfo.AddOtaNewInstallUser(Constants::DEFAULT_USERID);
        } else if (innerBundleInfo.IsU1Enable()) {
            preInstallBundleInfo.AddOtaNewInstallUser(Constants::U1);
        } else {
            for (auto userId : userIds) {
                preInstallBundleInfo.AddOtaNewInstallUser(userId);
            }
        }
        (void)dataMgr->SavePreInstallBundleInfo(bundleName, preInstallBundleInfo);
    };
    std::unordered_map<int32_t, bool> isPrivateUserCache;
    auto isPrivateUser = [&isPrivateUserCache](int32_t userId) {
        auto iter = isPrivateUserCache.find(userId);
        if (iter != isPrivateUserCache.end()) {
            return iter->second;
        }
        bool isPrivate = AccountHelper::IsPrivateSpaceUser(userId);
        isPrivateUserCache.emplace(userId, isPrivate);
        return isPrivate;
    };

    for (auto &scanPathIter : scanPathList) {
        LOG_NOFUNC_I(BMS_TAG_DEFAULT, "reboot scan bundle path: %{public}s ", scanPathIter.c_str());
        bool removable = IsPreInstallRemovable(scanPathIter);
        std::unordered_map<std::string, InnerBundleInfo> infos;
        if (!ParseHapFiles(scanPathIter, infos) || infos.empty()) {
            LOG_NOFUNC_E(BMS_TAG_DEFAULT, "obtain bundleinfo failed : %{public}s ", scanPathIter.c_str());
            BmsKeyEventMgr::ProcessMainBundleInstallFailed(scanPathIter, ERR_APPEXECFWK_PARSE_UNEXPECTED);
            SavePreInstallException(scanPathIter);
            continue;
        }

        auto bundleName = infos.begin()->second.GetBundleName();
        auto hapVersionCode = bundleInstallChecker->GetVersionCode(infos);
        bool needOtaNewInstall = NeedProcessOtaNewPreloadInstall(bundleName, scanPathIter);
        AddParseInfosToMap(bundleName, infos);
        // 1. Parse the distribution policy of the haps. Same-name-different-package yields two
        // per-mode hap lists (the package paths of each mode); same-name-same-package keeps the hap
        // path as scanPathIter itself. Different-package policies are 4/6/8.
        DualModePackageInfo pkgInfo = ParseDualModePackageInfo(bundleName, scanPathIter, infos);

        auto mapIter = loadExistData_.find(bundleName);
        if (mapIter == loadExistData_.end()) {
            if (dataMgr->GetAllUser().size() > USER_ID_SIZE
                && scanPathIter.find(ServiceConstants::PRELOAD_APP_DIR) == 0
                && !needOtaNewInstall) {
                LOG_NOFUNC_I(BMS_TAG_DEFAULT, "ota skip new preload app: %{public}s", scanPathIter.c_str());
                continue;
            }
            std::vector<int32_t> emptyRecoverListUserIds;
            if (!IsRecoverListEmpty(bundleName, emptyRecoverListUserIds)) {
                ProcessRecoverList(bundleName, scanPathIter, removable, appType, emptyRecoverListUserIds, infos);
                continue;
            }
            LOG_NOFUNC_I(BMS_TAG_DEFAULT, "OTA Install new -n %{public}s by path:%{public}s",
                bundleName.c_str(), scanPathIter.c_str());
            const auto allUsers = dataMgr->GetAllUser();
            if (needOtaNewInstall) {
                std::vector<int32_t> targetUserIds;
                if (multiUserInstallThirdPreloadApp_) {
                    for (auto userId : allUsers) {
                        if (userId <= Constants::U1 || isPrivateUser(userId)) {
                            continue;
                        }
                        targetUserIds.emplace_back(userId);
                    }
                } else {
                    targetUserIds.emplace_back(Constants::START_USERID);
                }
                if (!targetUserIds.empty()) {
                    otaNewInstallTargetUsersForNew[bundleName] = targetUserIds;
                }
            }
            std::vector<int32_t> userIdsForNewInstall;
            if (ProcessNewInstallForBlackList(bundleName, allUsers, userIdsForNewInstall)) {
                blackListBundles[bundleName] = userIdsForNewInstall;
            }
            // 2. Judge the current mode. For same-name-different-package, put the current-mode haps
            // into needInstallSysMap and the cross-mode package into a separate task map; for
            // MAIN_ONLY/SUB_ONLY packages, install directly when the policy matches the current mode,
            // otherwise queue a cross-mode task.
            if (DualModeHelper::IsDualModeDevice() && pkgInfo.policy != DeviceModeDistributionPolicy::UNSPECIFIED) {
                HandleDualModeNewInstall(pkgInfo, bundleName, scanPathIter, removable,
                    needInstallSysMap, dualModePolicyForNewMap, crossModeOtaTasks);
                continue;
            }
            std::vector<std::string> filePaths { scanPathIter };
            auto iter = needInstallSysMap.find(bundleName);
            if (iter == needInstallSysMap.end()) {
                std::vector<std::string> filePaths = {scanPathIter};
                needInstallSysMap[bundleName] = std::make_pair(filePaths, removable);
            } else {
                iter->second.first.emplace_back(scanPathIter);
            }
            continue;
        }

        LOG_NOFUNC_I(BMS_TAG_DEFAULT, "OTA process -n %{public}s path:%{public}s",
            bundleName.c_str(), scanPathIter.c_str());
        if (!IsForceInstallListEmpty(bundleName)) {
            LOG_NOFUNC_I(BMS_TAG_DEFAULT, "app(%{public}s) in force install list and need OTA install",
                bundleName.c_str());
            std::vector<std::string> filePaths { scanPathIter };
            int32_t timerId = XCollieHelper::SetOTATimer(OTA_PREINSTALL_BUNDLE_TASK, OTA_TIMEOUT_SECONDS);
            ScopeGuard cancelTimerIdGuard([timerId] { XCollieHelper::CancelTimer(timerId); });
            if (!OTAInstallSystemBundle(filePaths, appType, removable)) {
                LOG_E(BMS_TAG_DEFAULT, "OTA force Install bundle(%{public}s) error", bundleName.c_str());
                SavePreInstallException(scanPathIter);
            }
            continue;
        }
        ProcessUpdateDualPolicy(pkgInfo, bundleName);
        ProcessDualModeCrossUpdateIfNeeded(pkgInfo, infos, bundleName,
            removable, hapVersionCode, crossModeOtaTasks);
        // MAIN_ONLY/SUB_ONLY package that does not match the current mode: skip the remaining flow.
        if (IsSkipNormalOtaFlow(pkgInfo)) {
            continue;
        }
        BundleInfo hasInstalledInfo;
        auto hasBundleInstalled = dataMgr->GetBundleInfo(
            bundleName, static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE),
            hasInstalledInfo, Constants::ANY_USERID);
        if (!hasBundleInstalled && mapIter->second.IsUninstalled()) {
            LOG_NOFUNC_W(BMS_TAG_DEFAULT, "app(%{public}s) has been uninstalled and do not OTA install",
                bundleName.c_str());
            continue;
        }
        if (!xmlMap_.empty()) {
            bool needInstallForUser = false;
            for (const auto &[userId, bundleNames] : xmlMap_) {
                if (std::find(bundleNames.begin(), bundleNames.end(), bundleName) == bundleNames.end()) {
                    continue;
                }
                const auto userIds = dataMgr->GetUserIds(bundleName);
                if (std::find(userIds.begin(), userIds.end(), userId) != userIds.end()) {
                    continue;
                }
                needInstallUserIds_[bundleName].insert(userId);
                needInstallForUser = true;
            }
            if (needInstallForUser) {
                auto iter = needInstallSysMap.find(bundleName);
                if (iter == needInstallSysMap.end()) {
                    std::vector<std::string> filePaths = {scanPathIter};
                    needInstallSysMap[bundleName] = std::make_pair(filePaths, removable);
                } else {
                    iter->second.first.emplace_back(scanPathIter);
                }
            }
        }
        if (!hasBundleInstalled && scanPathIter.find(ServiceConstants::PRELOAD_APP_DIR) == 0 &&
            dataMgr->GetAllUser().size() > USER_ID_SIZE) {
            LOG_NOFUNC_W(BMS_TAG_DEFAULT, "app(%{public}s) is new preload app and do not need OTA install",
                bundleName.c_str());
            continue;
        }

        std::vector<std::string> filePaths;
        bool updateSelinuxLabel = false;
        bool updateBundle = false;
        bool hasEntry = false;
        for (auto item : infos) {
            if (item.second.HasEntry()) {
                hasEntry = true;
                break;
            }
        }
        for (auto item : infos) {
            auto parserModuleNames = item.second.GetModuleNameVec();
            if (parserModuleNames.empty()) {
                LOG_E(BMS_TAG_DEFAULT, "module is empty when parser path(%{public}s)", item.first.c_str());
                continue;
            }
            // Generally, when the versionCode of Hap is greater than the installed versionCode,
            // Except for the uninstalled app, they can be installed or upgraded directly by OTA.
            if (hasInstalledInfo.versionCode < hapVersionCode) {
                LOG_NOFUNC_I(BMS_TAG_DEFAULT, "OTA update module(%{public}s) by path(%{public}s)",
                    parserModuleNames[0].c_str(), item.first.c_str());
                updateBundle = true;
                break;
            }

            // When the accessTokenIdEx is equal to 0, the old application needs to be updated.
            if (hasInstalledInfo.applicationInfo.accessTokenIdEx == 0) {
                LOG_I(BMS_TAG_DEFAULT, "OTA update module %{public}s by path %{public}s, accessTokenIdEx is equal to 0",
                    parserModuleNames[0].c_str(), item.first.c_str());
                updateBundle = true;
                break;
            }

            // The versionCode of Hap is equal to the installed versionCode.
            // You can only install new modules by OTA
            if (hasInstalledInfo.versionCode == hapVersionCode) {
                LOG_NOFUNC_W(BMS_TAG_DEFAULT, "versionCode same -n %{public}s -v %{public}d",
                    bundleName.c_str(), hapVersionCode);
                InnerBundleInfo info;
                if (dataMgr->FetchInnerBundleInfo(bundleName, info) &&
                    info.GetInstallMark().status != InstallExceptionStatus::INSTALL_FINISH) {
                    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "OTA status error: %{public}s %{public}d",
                        bundleName.c_str(), info.GetInstallMark().status);
                    updateBundle = true;
                    break;
                }
                if (!IsPathExistInInstalledBundleInfo(item.first, hasInstalledInfo)) {
                    updateBundle = true;
                    break;
                }
                // update pre install app data dir selinux label
                if (!updateSelinuxLabel) {
                    UpdateAppDataSelinuxLabel(bundleName, hasInstalledInfo.applicationInfo.appPrivilegeLevel,
                        hasInstalledInfo.isPreInstallApp,
                        hasInstalledInfo.applicationInfo.appProvisionType == Constants::APP_PROVISION_TYPE_DEBUG);
                    updateSelinuxLabel = true;
                }
                // Used to judge whether the module has been installed.
                bool hasModuleInstalled = std::find(
                    hasInstalledInfo.hapModuleNames.begin(), hasInstalledInfo.hapModuleNames.end(),
                    parserModuleNames[0]) != hasInstalledInfo.hapModuleNames.end();
                if (hasModuleInstalled) {
                    if (UpdateModuleByHash(hasInstalledInfo, item.second) || (!hasEntry && item.second.IsHsp())) {
                        updateBundle = true;
                        break;
                    }
                    LOG_D(BMS_TAG_DEFAULT, "module(%{public}s) has been installed and versionCode is same",
                        parserModuleNames[0].c_str());
                    continue;
                }

                LOG_I(BMS_TAG_DEFAULT, "OTA install module(%{public}s) by path(%{public}s)",
                    parserModuleNames[0].c_str(), item.first.c_str());
                updateBundle = true;
                break;
            }

            if (hasInstalledInfo.versionCode > hapVersionCode) {
                updateBundle = false;
                if (CheckIsBundleUpdatedByHapPath(hasInstalledInfo)) {
                    break;
                }
                if (item.second.IsHsp()) {
                    updateBundle = true;
                    continue;
                }
                LOG_NOFUNC_E(BMS_TAG_DEFAULT, "-n %{public}s update failed versionCode:%{public}d lower than "
                    "current:%{public}d", bundleName.c_str(), hapVersionCode, hasInstalledInfo.versionCode);
                SendBundleUpdateFailedEvent(hasInstalledInfo);
                break;
            }
        }
        // process patch bundle
        std::vector<int32_t> currentBundleUserIds;
        if (!updateBundle && HotPatchAppProcessing(bundleName, hasInstalledInfo.versionCode,
            hapVersionCode, currentBundleUserIds)) {
            LOG_I(BMS_TAG_DEFAULT, "OTA Install prefab bundle(%{public}s) by path(%{public}s) for hotPatch upgrade",
                bundleName.c_str(), scanPathIter.c_str());
            // Support patch app downgrade install, no need to uninstall first.
            std::vector<std::string> filePaths{scanPathIter};
            int32_t timerId = XCollieHelper::SetOTATimer(OTA_PATCH_BUNDLE_TASK, OTA_TIMEOUT_SECONDS);
            ScopeGuard cancelTimerIdGuard([timerId] { XCollieHelper::CancelTimer(timerId); });
            if (!OTAInstallSystemBundleTargetUser(filePaths, bundleName, appType, removable,
                currentBundleUserIds, true)) {
                LOG_E(BMS_TAG_DEFAULT, "OTA install prefab bundle(%{public}s) error", bundleName.c_str());
                SavePreInstallException(scanPathIter);
            }
            continue;
        }
        if (!updateBundle) {
#ifdef USE_PRE_BUNDLE_PROFILE
            UpdateRemovable(bundleName, removable);
#endif
            continue;
        }
        // system resource need update first
        if (bundleName == SYSTEM_RESOURCES_APP) {
            std::vector<std::string> filePaths = {scanPathIter};
            (void)BMSEventHandler::OTAInstallSystemBundleNeedCheckUser(filePaths, bundleName, appType, removable);
            continue;
        }
        if (infos.begin()->second.GetOverlayType() == OverlayType::OVERLAY_EXTERNAL_BUNDLE) {
            overlayBundles.insert(bundleName);
        }
        std::vector<std::string> bundlePaths;
        if (DualModeHelper::IsDualModeDevice() && pkgInfo.isDiffPackage) {
            bundlePaths = DualModeHelper::IsSecondaryMode() ? pkgInfo.subModeHaps : pkgInfo.mainModeHaps;
        } else {
            bundlePaths.push_back(scanPathIter);
        }
        auto iter = needInstallMap.find(bundleName);
        if (iter == needInstallMap.end()) {
            needInstallMap[bundleName] = std::make_pair(bundlePaths, removable);
        } else {
            iter->second.first.insert(iter->second.first.end(), bundlePaths.begin(), bundlePaths.end());
        }
        dualModePolicyForNewMap[bundleName] = pkgInfo.policy;
    }
    for (auto &item : needInstallSysMap) {
        std::string bundleName = item.first;
        auto path = BMSEventHandler::ObtainRealPath(item.second.first);
        if (path.empty()) {
            LOG_E(BMS_TAG_DEFAULT, "OTA install skip, real path empty for bundle(%{public}s)", bundleName.c_str());
            SavePreInstallExceptionBundleName(bundleName);
            continue;
        }
        bool ret = false;
        int32_t timerId = XCollieHelper::SetOTATimer(OTA_PREINSTALL_BUNDLE_TASK, OTA_TIMEOUT_SECONDS);
        ScopeGuard cancelTimerIdGuard([timerId] { XCollieHelper::CancelTimer(timerId); });
        // Dual-mode: pass the policy recorded for the new install (UNSPECIFIED means original flow).
        DeviceModeDistributionPolicy newPolicy = DeviceModeDistributionPolicy::UNSPECIFIED;
        auto policyIter = dualModePolicyForNewMap.find(bundleName);
        if (policyIter != dualModePolicyForNewMap.end()) {
            newPolicy = policyIter->second;
        }
        auto targetUsersIter = otaNewInstallTargetUsersForNew.find(bundleName);
        bool hasinstalledOnStartUser = dataMgr->HasUserInstallInBundle(bundleName, Constants::START_USERID);
        auto blackListIter = blackListBundles.find(bundleName);
        if (targetUsersIter != otaNewInstallTargetUsersForNew.end()) {
            ret = OTAInstallSystemBundleTargetUser(path, bundleName, appType, item.second.second,
                targetUsersIter->second);
        } else if (!xmlMap_.empty()) {
            std::vector<int32_t> userIds;
            GetBundleNameAndUserIdFromPath(path.front(), userIds, bundleName);
            ret = OTAInstallSystemBundleTargetUser(path, item.first, appType, item.second.second, userIds);
        } else if (blackListIter != blackListBundles.end()) {
            ret = OTAInstallSystemBundleTargetUser(path, bundleName, appType, item.second.second,
                blackListIter->second);
        } else {
            ret = OTAInstallSystemBundle(path, appType, item.second.second, false, newPolicy);
        }
        if (!ret) {
            LOG_E(BMS_TAG_DEFAULT, "OTA Install new bundle(%{public}s) error", bundleName.c_str());
            SavePreInstallExceptionBundleName(bundleName);
        } else {
            auto targetUsersIter = otaNewInstallTargetUsersForNew.find(bundleName);
            if (targetUsersIter != otaNewInstallTargetUsersForNew.end() && !targetUsersIter->second.empty() &&
                canMarkOtaNewInstallUser(bundleName) && !hasinstalledOnStartUser) {
                markOtaNewInstallUser(bundleName, targetUsersIter->second);
            }
            if (newBundleDirMgr != nullptr) {
                (void)newBundleDirMgr->AddNewBundleDirInfo(bundleName,
                    static_cast<uint32_t>(CreateBundleDirType::CREATE_ALL_DIR));
            }
        }
    }
    // Process cross-mode installation map for dual mode OTA
    for (auto &item : crossModeOtaTasks) {
        const std::string &taskKey = item.first;
        const CrossModeOtaTask &task = item.second;
        int32_t timerId = XCollieHelper::SetOTATimer(OTA_PREINSTALL_BUNDLE_TASK, OTA_TIMEOUT_SECONDS);
        ScopeGuard cancelTimerIdGuard([timerId] { XCollieHelper::CancelTimer(timerId); });
        bool ret = OTAInstallSystemBundleForDualApp(task.filePaths, task, appType);
        if (!ret) {
            LOG_E(BMS_TAG_DEFAULT, "OTA cross-mode install(%{public}s) error", taskKey.c_str());
            SavePreInstallExceptionBundleName(taskKey);
        } else {
            LOG_I(BMS_TAG_DEFAULT, "OTA cross-mode install(%{public}s) success", taskKey.c_str());
        }
    }

    std::unordered_map<std::string, std::pair<std::vector<std::string>, bool>> needInstallMapFirst;
    std::unordered_map<std::string, std::pair<std::vector<std::string>, bool>> needInstallMapOverlay;
    for (auto &item : needInstallMap) {
        auto iter = overlayBundles.find(item.first);
        if (iter != overlayBundles.end()) {
            needInstallMapOverlay[item.first] = item.second;
        } else {
            needInstallMapFirst[item.first] = item.second;
        }
    }
    if (!InnerMultiProcessBundleInstall(needInstallMapFirst, appType, dualModePolicyForNewMap)) {
        LOG_E(BMS_TAG_DEFAULT, "multi needInstallMapFirst failed");
    }
    for (auto iter = needInstallMapOverlay.begin(); iter != needInstallMapOverlay.end(); ++iter) {
        (void)BMSEventHandler::OTAInstallSystemBundleNeedCheckUser(
            BMSEventHandler::ObtainRealPath(iter->second.first), iter->first, appType, iter->second.second);
    }

    UpdatePreinstallDB(needInstallMap);
    // process bundle theme and dynamic resource
    InnerProcessAllThemeAndDynamicIconInfoWhenOta(needInstallMap);

    std::set<std::string> updateBundleNames;
    for (const auto &item : needInstallMap) {
        updateBundleNames.insert(item.first);
    }
    ModuleJsonUpdater::SetIgnoreBundleNames(updateBundleNames);
}

bool BMSEventHandler::CheckIsBundleUpdatedByHapPath(const BundleInfo &bundleInfo)
{
    for (const auto &hapModuleInfo : bundleInfo.hapModuleInfos) {
        if (hapModuleInfo.hapPath.find(Constants::BUNDLE_CODE_DIR) != 0) {
            return false;
        }
    }
    return true;
}

bool BMSEventHandler::HotPatchAppProcessing(const std::string &bundleName, uint32_t hasInstallVersionCode,
    uint32_t hapVersionCode, std::vector<int32_t> &userIds)
{
    if (bundleName.empty()) {
        LOG_W(BMS_TAG_DEFAULT, "bundleName: %{public}s empty", bundleName.c_str());
        return false;
    }
    // obtains the users to which the app is installed
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return false;
    }
    userIds = dataMgr->GetUserIds(bundleName);

    if (IsQuickfixPatchApp(bundleName, hasInstallVersionCode)) {
        LOG_I(BMS_TAG_DEFAULT, "hasInstallVersionCode: %{public}u, hapVersionCode: %{public}u",
            hasInstallVersionCode, hapVersionCode);
        // installed patch application version greater than OTA Preconfigured APP Version
        // support downgrade install for patch app, no need to uninstall first
        if (hasInstallVersionCode > hapVersionCode) {
            LOG_I(BMS_TAG_DEFAULT, "patch app downgrade install, bundleName: %{public}s", bundleName.c_str());
        }
        // delete patch data
        if (!PatchDataMgr::GetInstance().DeleteInnerPatchInfo(bundleName)) {
            LOG_W(BMS_TAG_DEFAULT, "DeleteInnerPatchInfo failed, bundleName: %{public}s", bundleName.c_str());
        }
        return true;
    }
    return false;
}

std::vector<std::string> BMSEventHandler::ObtainRealPath(const std::vector<std::string> &paths)
{
    std::vector<std::string> filePaths = paths;
    if (filePaths.size() > 1) {
        // If the bundle exists in different directories, the real hap file path needs to be obtained
        std::vector<std::string> realHapPaths;
        for (const auto &path : filePaths) {
            std::vector<std::string> hapFilePathVec = {path};
            (void)BundleUtil::CheckFilePath(hapFilePathVec, realHapPaths);
        }
        filePaths = realHapPaths.empty() ? filePaths : realHapPaths;
    }
    return filePaths;
}

bool BMSEventHandler::InnerMultiProcessBundleInstall(
    const std::unordered_map<std::string, std::pair<std::vector<std::string>, bool>> &needInstallMap,
    Constants::AppType appType,
    const std::unordered_map<std::string, DeviceModeDistributionPolicy> &dualModePolicyForNewMap)
{
    if (needInstallMap.empty()) {
        LOG_I(BMS_TAG_DEFAULT, "no bundle need to update when ota");
        return true;
    }
    auto bundleMgrService = DelayedSingleton<BundleMgrService>::GetInstance();
    if (bundleMgrService == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "bundleMgrService is nullptr");
        return false;
    }

    sptr<BundleInstallerHost> installerHost = bundleMgrService->GetBundleInstaller();
    if (installerHost == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "installerHost is nullptr");
        return false;
    }

    size_t taskTotalNum = needInstallMap.size();
    size_t threadsNum = static_cast<size_t>(installerHost->GetThreadsNum());
    LOG_I(BMS_TAG_DEFAULT, "multi install start, totalNum: %{public}zu, num: %{public}zu", taskTotalNum, threadsNum);
    std::atomic_uint taskEndNum = 0;
    std::shared_ptr<BundlePromise> bundlePromise = std::make_shared<BundlePromise>();
    for (auto iter = needInstallMap.begin(); iter != needInstallMap.end(); ++iter) {
        std::string bundleName = iter->first;
        std::pair pair = iter->second;
        std::vector<std::string> filePaths = BMSEventHandler::ObtainRealPath(pair.first);
        DeviceModeDistributionPolicy newPolicy = DeviceModeDistributionPolicy::UNSPECIFIED;
        auto policyIter = dualModePolicyForNewMap.find(bundleName);
        if (policyIter != dualModePolicyForNewMap.end()) {
            newPolicy = policyIter->second;
        }
        auto task = [bundleName, pair, filePaths, taskTotalNum, appType, newPolicy, &taskEndNum, &bundlePromise]() {
            (void)BMSEventHandler::OTAInstallSystemBundleNeedCheckUser(filePaths, bundleName, appType,
                pair.second, newPolicy);
            taskEndNum++;
            if (bundlePromise && taskEndNum >= taskTotalNum) {
                bundlePromise->NotifyAllTasksExecuteFinished();
                LOG_I(BMS_TAG_DEFAULT, "All tasks has executed and notify promise when ota");
            }
            g_taskCounter--;
        };

        installerHost->AddTask(task, "BootRebootStartInstall : " + bundleName);
    }

    if (taskEndNum < taskTotalNum) {
        bundlePromise->WaitForAllTasksExecute();
        LOG_I(BMS_TAG_DEFAULT, "Wait for all tasks execute when ota");
    }
    LOG_I(BMS_TAG_DEFAULT, "multi install end");
    return true;
}

bool BMSEventHandler::UpdateModuleByHash(const BundleInfo &oldBundleInfo, const InnerBundleInfo &newInfo) const
{
    auto moduleName = newInfo.GetModuleNameVec().at(0);
    std::string existModuleHash;
    for (auto hapInfo : oldBundleInfo.hapModuleInfos) {
        if (hapInfo.package == moduleName) {
            existModuleHash = hapInfo.buildHash;
        }
    }
    std::string curModuleHash;
    if (!newInfo.GetModuleBuildHash(moduleName, curModuleHash)) {
        LOG_D(BMS_TAG_DEFAULT, "module(%{public}s) is not existed", moduleName.c_str());
        return false;
    }
    if (existModuleHash != curModuleHash) {
        LOG_D(BMS_TAG_DEFAULT, "(%{public}s) buildHash changed update corresponding hap or hsp", moduleName.c_str());
        return true;
    }
    return false;
}

void BMSEventHandler::InnerProcessRebootSharedBundleInstall(
    const std::list<std::string> &scanPathList, Constants::AppType appType)
{
    LOG_I(BMS_TAG_DEFAULT, "InnerProcessRebootSharedBundleInstall");
    int32_t timerId = XCollieHelper::SetOTATimer(OTA_SHARED_HSP_TASK, OTA_TIMEOUT_SECONDS);
    ScopeGuard cancelTimerIdGuard([timerId] { XCollieHelper::CancelTimer(timerId); });
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }
    for (const auto &scanPath : scanPathList) {
        bool removable = IsPreInstallRemovable(scanPath);
        std::unordered_map<std::string, InnerBundleInfo> infos;
        if (!ParseHapFiles(scanPath, infos) || infos.empty()) {
            LOG_E(BMS_TAG_DEFAULT, "obtain bundleinfo failed : %{public}s ", scanPath.c_str());
            SavePreInstallExceptionShared(scanPath);
            continue;
        }

        auto bundleName = infos.begin()->second.GetBundleName();
        auto versionCode = infos.begin()->second.GetVersionCode();
        AddParseInfosToMap(bundleName, infos);
        auto mapIter = loadExistData_.find(bundleName);
        if (mapIter == loadExistData_.end()) {
            LOG_I(BMS_TAG_DEFAULT, "OTA Install new shared bundle(%{public}s) by path(%{public}s)",
                bundleName.c_str(), scanPath.c_str());
            SavePreInstallExceptionShared(scanPath);
            if (!OTAInstallSystemSharedBundle({scanPath}, appType, removable)) {
                LOG_E(BMS_TAG_DEFAULT, "OTA Install new shared bundle(%{public}s) error", bundleName.c_str());
            } else {
                DeletePreInstallExceptionShared(scanPath);
            }
            continue;
        }

        InnerBundleInfo oldBundleInfo;
        bool hasInstalled = dataMgr->FetchInnerBundleInfo(bundleName, oldBundleInfo);
        if (!hasInstalled && mapIter->second.IsUninstalled()) {
            LOG_W(BMS_TAG_DEFAULT, "app(%{public}s) has been uninstalled and do not OTA install", bundleName.c_str());
            continue;
        }

        if (oldBundleInfo.GetVersionCode() > versionCode) {
            LOG_D(BMS_TAG_DEFAULT, "the installed version is up-to-date");
            continue;
        }

        SavePreInstallExceptionShared(scanPath);
        if (!OTAInstallSystemSharedBundle({scanPath}, appType, removable)) {
            LOG_E(BMS_TAG_DEFAULT, "OTA update shared bundle(%{public}s) error", bundleName.c_str());
        } else {
            DeletePreInstallExceptionShared(scanPath);
        }
    }
}

void BMSEventHandler::InnerProcessRebootSystemHspInstall(const std::list<std::string> &scanPathList)
{
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "InnerProcessRebootSystemHspInstall");
    int32_t timerId = XCollieHelper::SetOTATimer(OTA_SYSTEM_HSP_TASK, OTA_TIMEOUT_SECONDS);
    ScopeGuard cancelTimerIdGuard([timerId] { XCollieHelper::CancelTimer(timerId); });
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }
    for (const auto &scanPath : scanPathList) {
        std::unordered_map<std::string, InnerBundleInfo> infos;
        if (!ParseHapFiles(scanPath, infos) || infos.empty()) {
            LOG_E(BMS_TAG_DEFAULT, "obtain bundleinfo failed : %{public}s ", scanPath.c_str());
            SavePreInstallExceptionAppService(scanPath);
            continue;
        }
        auto bundleName = infos.begin()->second.GetBundleName();
        auto versionCode = infos.begin()->second.GetVersionCode();
        AddParseInfosToMap(bundleName, infos);
        auto mapIter = loadExistData_.find(bundleName);
        if (mapIter == loadExistData_.end()) {
            SavePreInstallExceptionAppService(scanPath);
            auto ret = OTAInstallSystemHsp({scanPath});
            LOG_NOFUNC_I(BMS_TAG_DEFAULT, "OTA Install new system hsp(%{public}s) by path(%{public}s) ret %{public}d",
                bundleName.c_str(), scanPath.c_str(), ret);
            if (ret == ERR_OK) {
                DeletePreInstallExceptionAppService(scanPath);
            }
            continue;
        }
        InnerBundleInfo oldBundleInfo;
        bool hasInstalled = dataMgr->FetchInnerBundleInfo(bundleName, oldBundleInfo);
        if (hasInstalled && oldBundleInfo.GetVersionCode() > versionCode) {
            LOG_NOFUNC_I(BMS_TAG_DEFAULT, "%{public}s installed version %{public}d is greater then curVer %{public}d",
                bundleName.c_str(), oldBundleInfo.GetVersionCode(), versionCode);
            continue;
        }
        SavePreInstallExceptionAppService(scanPath);
        auto ret = OTAInstallSystemHsp({scanPath});
        LOG_NOFUNC_I(BMS_TAG_DEFAULT, "OTA Install system hsp(%{public}s) by path(%{public}s) ret %{public}d",
            bundleName.c_str(), scanPath.c_str(), ret);
        if (ret == ERR_OK) {
            DeletePreInstallExceptionAppService(scanPath);
        }
    }
}

void BMSEventHandler::InnerProcessRebootSkillsInstall(const std::list<std::string> &scanPathList)
{
    LOG_NOFUNC_I(BMS_TAG_INSTALLER, "InnerProcessRebootSkillsInstall");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "DataMgr is nullptr");
        return;
    }

    for (const auto &scanPath : scanPathList) {
        std::unordered_map<std::string, InnerBundleInfo> infos;
        if (!ParseHapFiles(scanPath, infos) || infos.empty()) {
            LOG_E(BMS_TAG_INSTALLER, "obtain bundleinfo failed : %{public}s ", scanPath.c_str());
            continue;
        }
        auto bundleName = infos.begin()->second.GetBundleName();
        auto versionCode = infos.begin()->second.GetVersionCode();
        AddParseInfosToMap(bundleName, infos);
        auto mapIter = loadExistData_.find(bundleName);
        if (mapIter == loadExistData_.end()) {
            auto ret = OTAInstallSystemSkills({scanPath}, dataMgr->GetAllUser());
            LOG_NOFUNC_I(BMS_TAG_INSTALLER, "OTA Install new skills(%{public}s) by path(%{public}s) ret %{public}d",
                bundleName.c_str(), scanPath.c_str(), ret);
            continue;
        }
        InnerBundleInfo oldBundleInfo;
        bool hasInstalled = dataMgr->FetchInnerBundleInfo(bundleName, oldBundleInfo);
        if (hasInstalled && oldBundleInfo.GetVersionCode() > versionCode) {
            LOG_NOFUNC_I(BMS_TAG_INSTALLER, "%{public}s installed version %{public}d is greater then curVer %{public}d",
                bundleName.c_str(), oldBundleInfo.GetVersionCode(), versionCode);
            continue;
        }
        std::set<int32_t> userIds;
        for (const auto userId : dataMgr->GetUserIds(bundleName)) {
            userIds.insert(userId);
        }
        if (userIds.empty()) {
            userIds = dataMgr->GetAllUser();
        }
        auto ret = OTAInstallSystemSkills({scanPath}, userIds);
        LOG_NOFUNC_I(BMS_TAG_INSTALLER, "OTA Install skills(%{public}s) by path(%{public}s) ret %{public}d",
            bundleName.c_str(), scanPath.c_str(), ret);
    }
}

void BMSEventHandler::ProcessRebootAppServiceUninstall()
{
    APP_LOGI("Reboot scan and OTA uninstall for appServiceFwk start");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        APP_LOGE("DataMgr is nullptr");
        return;
    }
    for (const auto &loadIter : loadExistData_) {
        std::string bundleName = loadIter.first;
        auto listIter = hapParseInfoMap_.find(bundleName);
        if (listIter == hapParseInfoMap_.end()) {
            continue;
        }

        InnerBundleInfo info;
        if (!dataMgr->FetchInnerBundleInfo(bundleName, info)) {
            APP_LOGW("app(%{public}s) maybe has been uninstall.", bundleName.c_str());
            continue;
        }
        if (info.GetApplicationBundleType() != BundleType::APP_SERVICE_FWK) {
            continue;
        }
        // Check the installed module
        bool isDownGrade = false;
        if (InnerProcessUninstallAppServiceModule(info, listIter->second, isDownGrade)) {
            APP_LOGI("bundleName:%{public}s need delete module", bundleName.c_str());
        }
        if (isDownGrade) {
            APP_LOGI("bundleName:%{public}s is being downgraded for ota", bundleName.c_str());
            continue;
        }
        // Check the preInstall path in Db.
        // If the corresponding Hap does not exist, it should be deleted.
        auto parserInfoMap = listIter->second;
        for (const auto &preBundlePath : loadIter.second.GetBundlePaths()) {
            auto parserInfoIter = parserInfoMap.find(preBundlePath);
            if (parserInfoIter != parserInfoMap.end()) {
                LOG_NOFUNC_I(BMS_TAG_COMMON, "OTA no need delete appService %{public}s module path %{public}s",
                    bundleName.c_str(), preBundlePath.c_str());
                continue;
            }

            LOG_NOFUNC_I(BMS_TAG_COMMON, "OTA appService %{public}s delete path %{public}s",
                bundleName.c_str(), preBundlePath.c_str());
            DeletePreInfoInDb(bundleName, preBundlePath, false);
        }
    }
    APP_LOGI("Reboot scan and OTA uninstall for appServiceFwk success");
}

bool BMSEventHandler::InnerProcessUninstallAppServiceModule(const InnerBundleInfo &innerBundleInfo,
    const std::unordered_map<std::string, InnerBundleInfo> &infos, bool &isDownGrade)
{
    if (infos.empty()) {
        APP_LOGI("bundleName:%{public}s infos is empty", innerBundleInfo.GetBundleName().c_str());
        return false;
    }
    if (innerBundleInfo.GetVersionCode() > infos.begin()->second.GetVersionCode()) {
        APP_LOGI("bundleName:%{public}s version code is bigger than new pre-hap",
            innerBundleInfo.GetBundleName().c_str());
        isDownGrade = true;
        return false;
    }
    std::vector<std::string> moduleNameList;
    innerBundleInfo.GetModuleNames(moduleNameList);
    // Check the installed module.
    // If the corresponding module does not exist, it should be uninstalled.
    std::vector<std::string> moduleNeedUnsinstall;
    for (const auto &moduleName : moduleNameList) {
        bool isModuleExist = false;
        for (const auto &parserInfoIter : infos) {
            auto parserModuleNames = parserInfoIter.second.GetModuleNameVec();
            if (!parserModuleNames.empty() && moduleName == parserModuleNames[0]) {
                isModuleExist = true;
                break;
            }
        }

        if (!isModuleExist) {
            APP_LOGI("ProcessRebootBundleUninstall OTA app(%{public}s) uninstall module(%{public}s).",
                innerBundleInfo.GetBundleName().c_str(), moduleName.c_str());
            moduleNeedUnsinstall.emplace_back(moduleName);
        }
    }
    if (moduleNeedUnsinstall.empty()) {
        return true;
    }
    for (const std::string &moduleName : moduleNeedUnsinstall) {
        AppServiceFwkInstaller installer;
        if (installer.UnInstall(innerBundleInfo.GetBundleName(), moduleName) != ERR_OK) {
            APP_LOGW("uninstall failed");
        }
    }
    return true;
}

void BMSEventHandler::ProcessRebootSkillsUninstall()
{
    LOG_NOFUNC_I(BMS_TAG_INSTALLER, "Reboot scan and OTA uninstall for skills start");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_INSTALLER, "DataMgr is nullptr");
        return;
    }
    for (const auto &loadIter : loadExistData_) {
        if (loadIter.second.GetBundleType() != BundleType::SKILL) {
            continue;
        }
        std::string bundleName = loadIter.first;
        auto listIter = hapParseInfoMap_.find(bundleName);
        if (listIter == hapParseInfoMap_.end()) {
            LOG_I(BMS_TAG_DEFAULT, "ProcessRebootSkillsUninstall OTA uninstall skills %{public}s", bundleName.c_str());
            InnerBundleInfo info;
            if (!dataMgr->FetchInnerBundleInfo(bundleName, info)) {
                APP_LOGW("app(%{public}s) maybe has been uninstall.", bundleName.c_str());
                continue;
            }
            auto userIds = dataMgr->GetUserIds(bundleName);
            if (userIds.empty()) {
                LOG_W(BMS_TAG_INSTALLER, "skills %{public}s maybe has been uninstall, no user", bundleName.c_str());
                continue;
            }
            // need check whether kills already upgrade
            ErrCode ret = ERR_OK;
            for (const auto user : userIds) {
                InstallParam installParam;
                installParam.isPreInstallApp = true;
                installParam.isFirstBootInstall = false;
                installParam.needSavePreInstallInfo = false;
                installParam.SetKillProcess(false);
                installParam.userId = user;
                IndependentSkillsInstaller installer;
                ErrCode tempRet = installer.Uninstall(bundleName, installParam);
                if (tempRet != ERR_OK) {
                    LOG_E(BMS_TAG_INSTALLER, "skills -n %{public}s -u %{public}d uninstall failed",
                        bundleName.c_str(), user);
                    ret = tempRet;
                }
            }
            if (ret == ERR_OK) {
                LOG_I(BMS_TAG_DEFAULT, "OTA uninstall preInstall skills:%{public}s succeed", bundleName.c_str());
                std::string moduleName;
                DeletePreInfoInDb(bundleName, moduleName, true);
            }
        }
    }
    LOG_NOFUNC_I(BMS_TAG_INSTALLER, "Reboot scan and OTA uninstall for skills success");
}

void BMSEventHandler::ProcessEmptyOdid()
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "ProcessEmptyOdid DataMgr is nullptr");
        return;
    }
    dataMgr->ProcessEmptyOdid();
}

void BMSEventHandler::ProcessCheckAppExtensionAbility()
{
    bool checkExtensionAbility = false;
    CheckOtaFlag(OTAFlag::CHECK_EXTENSION_ABILITY, checkExtensionAbility);
    if (checkExtensionAbility) {
        LOG_I(BMS_TAG_DEFAULT, "Not need to check extension ability due to has checked");
        return;
    }
    LOG_I(BMS_TAG_DEFAULT, "Need to check extension ability");
    InnerProcessCheckAppExtensionAbility();
    UpdateOtaFlag(OTAFlag::CHECK_EXTENSION_ABILITY);
}

void BMSEventHandler::InnerProcessCheckAppExtensionAbility()
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "dataMgr is nullptr");
        return;
    }
    std::vector<ExtensionAbilityType> types = {
        ExtensionAbilityType::INPUTMETHOD,
        ExtensionAbilityType::SHARE,
        ExtensionAbilityType::ACTION
    };
    std::vector<std::string> bundleNames = dataMgr->GetAllExtensionBundleNames(types);
    if (bundleNames.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "bundleNames is empty");
        return;
    }

    int32_t userId = Constants::START_USERID;
    int32_t currentUserId = AccountHelper::GetCurrentActiveUserIdWithRetry(true);
    if (currentUserId != Constants::INVALID_USERID) {
        userId = currentUserId;
    }

    for (const auto &bundleName : bundleNames) {
        LOG_NOFUNC_I(BMS_TAG_DEFAULT, "-n %{public}s add resource when ota", bundleName.c_str());
        BundleResourceHelper::AddResourceInfoByBundleName(bundleName, userId, ADD_RESOURCE_TYPE::UPDATE_BUNDLE);
    }
}

void BMSEventHandler::ProcessRouterMap()
{
    bool checkRouterMap = false;
    CheckOtaFlag(OTAFlag::PROCESS_ROUTER_MAP, checkRouterMap);
    if (checkRouterMap) {
        LOG_I(BMS_TAG_DEFAULT, "Not need to process router map due to has checked");
        return;
    }
    LOG_I(BMS_TAG_DEFAULT, "Need to update router map");
    InnerProcessRouterMap();
}

void BMSEventHandler::InnerProcessRouterMap()
{
    auto task = []() {
        auto dataMgr = GetDataMgrFromService();
        if (dataMgr == nullptr) {
            LOG_E(BMS_TAG_DEFAULT, "dataMgr is nullptr");
            return;
        }
        LOG_I(BMS_TAG_DEFAULT, "addRouterMap start");
        auto bundleNames = dataMgr->GetAllBundleName();
        for (auto &bundleName : bundleNames) {
            dataMgr->UpdateRouterInfo(bundleName);
        }
        bool ret = dataMgr->UpdateRouterDB();
        if (!ret) {
            LOG_E(BMS_TAG_DEFAULT, "UpdateRouterDB failed");
        }
        LOG_I(BMS_TAG_DEFAULT, "addRouterMap end");
        UpdateOtaFlag(OTAFlag::PROCESS_ROUTER_MAP);
    };
    std::thread routerThread(task);
    routerThread.detach();
}

ErrCode BMSEventHandler::OTAInstallSystemHsp(const std::vector<std::string> &filePaths)
{
    InstallParam installParam;
    installParam.isPreInstallApp = true;
    installParam.removable = false;
    installParam.isOTA = true;
    installParam.copyHapToInstallPath = false;
    installParam.needSavePreInstallInfo = true;
    installParam.preinstallSourceFlag = ApplicationInfoFlag::FLAG_OTA_INSTALLED;
    AppServiceFwkInstaller installer;

    return installer.Install(filePaths, installParam);
}

ErrCode BMSEventHandler::OTAInstallSystemSkills(const std::vector<std::string> &filePaths,
    const std::set<int32_t> &userIds)
{
    if (filePaths.empty()) {
        LOG_E(BMS_TAG_INSTALLER, "File paths is empty");
        return ERR_APPEXECFWK_INSTALL_PARAM_ERROR;
    }

    if (userIds.empty()) {
        LOG_E(BMS_TAG_INSTALLER, "UserIds is empty");
        return ERR_APPEXECFWK_INSTALL_PARAM_ERROR;
    }

    InstallParam installParam;
    installParam.isPreInstallApp = true;
    installParam.removable = false;
    installParam.isOTA = true;
    installParam.copyHapToInstallPath = false;
    installParam.needSavePreInstallInfo = true;
    installParam.preinstallSourceFlag = ApplicationInfoFlag::FLAG_OTA_INSTALLED;
    ErrCode ret = ERR_OK;
    for (const auto userId : userIds) {
        if ((userId == Constants::DEFAULT_USERID) || (userId == Constants::U1)) {
            continue;
        }
        IndependentSkillsInstaller installer;
        installParam.userId = userId;
        ErrCode tempRet = installer.Install(filePaths, installParam);
        LOG_NOFUNC_I(BMS_TAG_INSTALLER, "Install skills for userId %{public}d, ret %{public}d", userId, tempRet);
        if (tempRet != ERR_OK) {
            ret = tempRet;
        }
    }
    return ret;
}

void BMSEventHandler::SaveSystemFingerprint()
{
    auto bmsPara = DelayedSingleton<BundleMgrService>::GetInstance()->GetBmsParam();
    if (bmsPara == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "bmsPara is nullptr");
        return;
    }

    std::string curSystemFingerprint = GetCurSystemFingerprint();
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "curSystemFingerprint(%{public}s)", curSystemFingerprint.c_str());
    if (curSystemFingerprint.empty()) {
        return;
    }

    bmsPara->SaveBmsParam(FINGERPRINT, curSystemFingerprint);
}

void BMSEventHandler::HandleOTACodeEncryption()
{
    std::string codeProtectFlag;
    auto bmsParam = DelayedSingleton<BundleMgrService>::GetInstance()->GetBmsParam();
    if (bmsParam != nullptr) {
        bmsParam->GetBmsParam(CODE_PROTECT_FLAG, codeProtectFlag);
        if (codeProtectFlag == std::string{ CODE_PROTECT_FLAG_CHECKED }) {
            LOG_I(BMS_TAG_DEFAULT, "checked");
            return;
        }
    }
    LOG_I(BMS_TAG_DEFAULT, "begin");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "dataMgr is null");
        return;
    }
    dataMgr->HandleOTACodeEncryption();
    BmsExtensionDataMgr bmsExtensionDataMgr;
    std::vector<CodeProtectBundleInfo> infos;
    auto res = bmsExtensionDataMgr.KeyOperation(infos, CodeOperation::OTA_CHECK_FINISHED);
    LOG_I(BMS_TAG_DEFAULT, "keyOperation result %{public}d", res);
    SaveCodeProtectFlag();
}

void BMSEventHandler::HandleDetermineCloneNumList()
{
    BmsExtensionDataMgr bmsExtensionDataMgr;
    std::vector<std::tuple<std::string, std::string, uint32_t>> determineCloneNumList;
    ErrCode result = bmsExtensionDataMgr.GetDetermineCloneNumList(determineCloneNumList);
    if (result != ERR_OK) {
        LOG_NOFUNC_W(BMS_TAG_DEFAULT, "GetDetermineCloneNumList result:%{public}d", result);
        return;
    }
    if (determineCloneNumList.empty()) {
        LOG_NOFUNC_W(BMS_TAG_DEFAULT, "GetDetermineCloneNumList empty");
        return;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_NOFUNC_E(BMS_TAG_DEFAULT, "dataMgr is null");
        return;
    }
    result = dataMgr->HandleDetermineCloneNumList(determineCloneNumList);
    if (result != ERR_OK) {
        LOG_NOFUNC_W(BMS_TAG_DEFAULT, "HandleDetermineCloneNumList result:%{public}d", result);
    }
}

void BMSEventHandler::SaveCodeProtectFlag()
{
    auto bmsPara = DelayedSingleton<BundleMgrService>::GetInstance()->GetBmsParam();
    if (bmsPara == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "bmsPara is nullptr");
        return;
    }
    if (!bmsPara->SaveBmsParam(CODE_PROTECT_FLAG, std::string{ CODE_PROTECT_FLAG_CHECKED })) {
        LOG_E(BMS_TAG_DEFAULT, "save failed");
    }
}

bool BMSEventHandler::IsModuleUpdate()
{
    std::string paramValue;
    if (!GetSystemParameter(MODULE_UPDATE_PARAM, paramValue) || paramValue.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "get system paramter failed");
        return false;
    }
    LOG_I(BMS_TAG_DEFAULT, "parameter %{public}s is %{public}s", MODULE_UPDATE_PARAM, paramValue.c_str());
    if (paramValue == MODULE_UPDATE_VALUE_UPDATE) {
        moduleUpdateStatus_ = ModuleUpdateStatus::UPDATE;
    } else if (paramValue == MODULE_UPDATE_VALUE_REVERT_BMS) {
        moduleUpdateStatus_ = ModuleUpdateStatus::REVERT;
    } else {
        moduleUpdateStatus_ = ModuleUpdateStatus::DEFAULT;
        return false;
    }
    return true;
}

void BMSEventHandler::HandleModuleUpdate()
{
    // 1. get hmp list and dir path
    // key: hmp name, value: appServiceFwk path of the hmp
    std::map<std::string, std::vector<std::string>> moduleUpdateAppServiceMap;
    // key: hmp name, value: normal app path of the hmp
    std::map<std::string, std::vector<std::string>> moduleUpdateNotAppServiceMap;
    if (!GetModuleUpdatePathList(moduleUpdateAppServiceMap, moduleUpdateNotAppServiceMap)) {
        LOG_E(BMS_TAG_DEFAULT, "get module update path map failed");
        return;
    }
    // 2. process rollback if needed
    ModuleUpdateRollBack();
    // 3. install all hmp, if install failed,
    HandleInstallHmp(moduleUpdateAppServiceMap, moduleUpdateNotAppServiceMap);
    // 4. update system parmeters
    ProcessModuleUpdateSystemParameters();
    // 5. uninstall redundant module
    HandleHmpUninstall();
}

bool BMSEventHandler::CheckIsModuleUpdate(const std::string &str)
{
    return str.find(MODULE_UPDATE_PATH) == 0 ||
        str.find(std::string(ServiceConstants::PATH_SEPARATOR) +
        MODULE_UPDATE_PATH) == 0;
}

bool BMSEventHandler::GetModuleUpdatePathList(
    std::map<std::string, std::vector<std::string>> &moduleUpdateAppServiceMap,
    std::map<std::string, std::vector<std::string>> &moduleUpdateNotAppServiceMap)
{
#ifdef USE_PRE_BUNDLE_PROFILE
    if (!LoadPreInstallProFile()) {
        LOG_W(BMS_TAG_DEFAULT, "LoadPreInstallProFile failed");
        return false;
    }
    std::vector<std::string> systemHspDirList;
    for (const auto &item : systemHspList_) {
        systemHspDirList.emplace_back(item.bundleDir);
    }
    FilterModuleUpdate(systemHspDirList, moduleUpdateAppServiceMap, true);
    std::vector<std::string> preInstallDirs;
    GetPreInstallDirFromLoadProFile(preInstallDirs);
    FilterModuleUpdate(preInstallDirs, moduleUpdateNotAppServiceMap, false);
    return true;
#endif
    LOG_W(BMS_TAG_DEFAULT, "USE_PRE_BUNDLE_PROFILE is not defined");
    return false;
}

bool BMSEventHandler::HandleInstallHmp(
    const std::map<std::string, std::vector<std::string>> &moduleUpdateAppServiceMap,
    const std::map<std::string, std::vector<std::string>> &moduleUpdateNotAppServiceMap)
{
    LOG_I(BMS_TAG_DEFAULT, "begin to HandleInstallHmp");
    for (const auto &item : moduleUpdateAppServiceMap) {
        LOG_I(BMS_TAG_DEFAULT, "begin to install hmp %{public}s", item.first.c_str());
        if (!HandleInstallModuleUpdateSystemHsp(item.second)) {
            LOG_E(BMS_TAG_DEFAULT, "hmp %{public}s install appServiceFwk failed", item.first.c_str());
            moduleUpdateInstallResults_[item.first] = false;
            continue;
        }
        LOG_I(BMS_TAG_DEFAULT, "hmp %{public}s install appService success", item.first.c_str());
        moduleUpdateInstallResults_[item.first] = true;
    }

    for (const auto &item : moduleUpdateNotAppServiceMap) {
        LOG_I(BMS_TAG_DEFAULT, "begin to install hmp %{public}s", item.first.c_str());
        if (!HandleInstallModuleUpdateNormalApp(item.second)) {
            LOG_E(BMS_TAG_DEFAULT, "hmp %{public}s install app failed", item.first.c_str());
            moduleUpdateInstallResults_[item.first] = false;
            continue;
        }
        auto iter = moduleUpdateInstallResults_.find(item.first);
        if (iter != moduleUpdateInstallResults_.end() && !(iter->second)) {
            LOG_I(BMS_TAG_DEFAULT, "hmp %{public}s install appService has been failed",
                item.first.c_str());
            continue;
        }
        LOG_I(BMS_TAG_DEFAULT, "hmp %{public}s install success", item.first.c_str());
        moduleUpdateInstallResults_[item.first] = true;
    }
    return true;
}

bool BMSEventHandler::HandleInstallModuleUpdateSystemHsp(const std::vector<std::string> &appDirList)
{
    bool result = true;
    for (const std::string &systemHspDir : appDirList) {
        if (!ProcessSystemHspInstall(systemHspDir)) {
            LOG_E(BMS_TAG_DEFAULT, "install %{public}s path failed", systemHspDir.c_str());
            result = false;
        }
    }

    return result;
}

bool BMSEventHandler::HandleInstallModuleUpdateNormalApp(const std::vector<std::string> &appDirList)
{
    bool result = true;
    for (const std::string &appDir : appDirList) {
        std::string normalizedAppDir = appDir;
        if (!appDir.empty() && appDir.back() == SEPARATOR) {
            normalizedAppDir = appDir.substr(0, appDir.size() - 1);
        }

        std::shared_ptr<HmpBundleInstaller> installer = std::make_shared<HmpBundleInstaller>();
        bool removable = GetRemovableInfo(appDir);
        auto res = installer->InstallNormalAppInHmp(normalizedAppDir, removable);
        LOG_I(BMS_TAG_DEFAULT, "install %{public}s %{public}d", appDir.c_str(), res);
        if (res == ERR_OK || (res == ERR_APPEXECFWK_INSTALL_VERSION_DOWNGRADE && CheckAppIsUpdatedByUser(appDir))) {
            continue;
        }
        LOG_E(BMS_TAG_DEFAULT, "install %{public}s path failed", appDir.c_str());
        result = false;
    }
    return result;
}

bool BMSEventHandler::CheckAppIsUpdatedByUser(const std::string& appDir)
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "dataMgr is null");
        return false;
    }
    std::string bundleName = GetBundleNameByPreInstallPath(appDir);
    if (bundleName.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "get bundleName failed, %{public}s", appDir.c_str());
        return false;
    }
    BundleInfo bundleInfo;
    auto baseFlag = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) +
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE);
    ErrCode ret = dataMgr->GetBundleInfoV9(bundleName, baseFlag, bundleInfo, Constants::ANY_USERID);
    if (ret != ERR_OK) {
        LOG_I(BMS_TAG_DEFAULT, "%{public}s not found", bundleName.c_str());
        return false;
    }
    for (const auto &hapInfo : bundleInfo.hapModuleInfos) {
        if (hapInfo.hapPath.size() > std::string(HAP_PATH_DATA_AREA).size() &&
            hapInfo.hapPath.compare(0, std::string(HAP_PATH_DATA_AREA).size(), std::string(HAP_PATH_DATA_AREA)) == 0) {
            LOG_I(BMS_TAG_DEFAULT, "%{public}s has been updated by user", hapInfo.name.c_str());
            return true;
        }
    }
    LOG_I(BMS_TAG_DEFAULT, "%{public}s has not been updated by user", bundleName.c_str());
    return false;
}

bool BMSEventHandler::GetRemovableInfo(const std::string& bundleDir)
{
    auto it = std::find_if(installList_.begin(), installList_.end(), [&bundleDir](const PreScanInfo& info) {
        return info.bundleDir == bundleDir;
    });
    if (it != installList_.end()) {
        return it->removable;
    }
    LOG_W(BMS_TAG_DEFAULT, "%{public}s not found", bundleDir.c_str());
    return true;
}

void BMSEventHandler::FilterModuleUpdate(const std::vector<std::string> &preInstallDirs,
    std::map<std::string, std::vector<std::string>> &moduleUpdatePathMap, bool isAppService)
{
    for (const std::string &preInstallDir : preInstallDirs) {
        if (!CheckIsModuleUpdate(preInstallDir)) {
            continue;
        }
        std::string moduleUpdatePath = std::string(MODULE_UPDATE_PATH) + ServiceConstants::PATH_SEPARATOR;
        size_t start = preInstallDir.find(moduleUpdatePath);
        if (start == std::string::npos) {
            continue;
        }
        start += std::string(moduleUpdatePath).length();

        size_t end = preInstallDir.find(ServiceConstants::PATH_SEPARATOR, start);
        if (end == std::string::npos) {
            continue;
        }
        std::string hmpName = preInstallDir.substr(start, end - start);
        LOG_I(BMS_TAG_DEFAULT, "path %{public}s added to hmp %{public}s", preInstallDir.c_str(), hmpName.c_str());
        moduleUpdatePathMap[hmpName].emplace_back(preInstallDir);
        std::string bundleName = GetBundleNameByPreInstallPath(preInstallDir);
        if (isAppService) {
            LOG_I(BMS_TAG_DEFAULT, "appService %{public}s added to hmp %{public}s",
                bundleName.c_str(), hmpName.c_str());
            moduleUpdateAppService_[hmpName].insert(bundleName);
        } else {
            if (moduleUpdateAppService_[hmpName].find(bundleName) == moduleUpdateAppService_[hmpName].end()) {
                LOG_I(BMS_TAG_DEFAULT, "app %{public}s added to hmp %{public}s", bundleName.c_str(), hmpName.c_str());
                moduleUpdateNormalApp_[hmpName].insert(bundleName);
            }
        }
        SaveHmpBundlePathInfo(hmpName, bundleName, preInstallDir, isAppService);
    }
}

void BMSEventHandler::SaveHmpBundlePathInfo(const std::string &hmpName,
    const std::string &bundleName, const std::string bundlePath, bool isAppService)
{
    HmpBundlePathInfo info;
    info.bundleName = bundleName;
    info.hmpName = hmpName;
    auto it = hmpBundlePathInfos_.find(bundleName);
    if (it != hmpBundlePathInfos_.end()) {
        info = it->second;
    }
    if (isAppService) {
        info.hspDir = bundlePath;
    } else {
        info.bundleDir = bundlePath;
    }
    hmpBundlePathInfos_[bundleName] = info;
}

void BMSEventHandler::GetHmpList(std::vector<std::string> &hmpList,
    std::map<std::string, std::vector<std::string>> &moduleUpdateAppServiceMap,
    std::map<std::string, std::vector<std::string>> &moduleUpdateNotAppServiceMap)
{
    std::set<std::string> hmpSet;
    for (const auto &item : moduleUpdateAppServiceMap) {
        hmpSet.insert(item.first);
    }
    for (const auto &item : moduleUpdateNotAppServiceMap) {
        hmpSet.insert(item.first);
    }
    hmpList.assign(hmpSet.begin(), hmpSet.end());
}

std::string BMSEventHandler::GetBundleNameByPreInstallPath(const std::string& path)
{
    std::vector<std::string> parts;
    std::string part;
    std::stringstream ss(path);

    while (getline(ss, part, SEPARATOR)) {
        if (!part.empty()) {
            parts.push_back(part);
        }
    }

    if (!parts.empty()) {
        return parts.back();
    } else {
        return std::string{};
    }
}

void BMSEventHandler::ModuleUpdateRollBack()
{
    if (moduleUpdateStatus_ != ModuleUpdateStatus::REVERT) {
        return;
    }
    std::set<std::string> normalAppSet;
    std::set<std::string> appServiceSet;
    for (const auto &item : moduleUpdateNormalApp_) {
        normalAppSet.insert(item.second.begin(), item.second.end());
    }
    for (const auto &item : moduleUpdateAppService_) {
        appServiceSet.insert(item.second.begin(), item.second.end());
    }
    LOG_W(BMS_TAG_DEFAULT, "hmp need to rollback");
    // rollback hmp which install failed
    std::shared_ptr<HmpBundleInstaller> installer = std::make_shared<HmpBundleInstaller>();
    installer->RollbackHmpBundle(appServiceSet, normalAppSet);
}

void BMSEventHandler::ProcessModuleUpdateSystemParameters()
{
    if (moduleUpdateStatus_ == ModuleUpdateStatus::UPDATE) {
        bool hasFailed = false;
        for (const auto &item : moduleUpdateInstallResults_) {
            if (item.second) {
                LOG_I(BMS_TAG_DEFAULT, "hmp %{public}s install success", item.first.c_str());
                continue;
            }
            hasFailed = true;
            LOG_W(BMS_TAG_DEFAULT, "hmp %{public}s install failed", item.first.c_str());
            std::string parameter = MODULE_UPDATE_INSTALL_RESULT + item.first;
            system::SetParameter(parameter, MODULE_UPDATE_INSTALL_RESULT_FALSE);
        }
        if (hasFailed) {
            LOG_I(BMS_TAG_DEFAULT, "module update failed, parameter %{public}s modified to revert",
                MODULE_UPDATE_PARAM);
            system::SetParameter(MODULE_UPDATE_PARAM, MODULE_UPDATE_VALUE_REVERT);
        } else {
            LOG_I(BMS_TAG_DEFAULT, "module update success");
            system::SetParameter(MODULE_UPDATE_PARAM, MODULE_UPDATE_PARAM_EMPTY);
        }
    } else if (moduleUpdateStatus_ == ModuleUpdateStatus::REVERT) {
        LOG_I(BMS_TAG_DEFAULT, "revert end, all parameters modified to empty");
        system::SetParameter(MODULE_UPDATE_PARAM, MODULE_UPDATE_PARAM_EMPTY);
        for (const auto &item : moduleUpdateInstallResults_) {
            std::string parameter = MODULE_UPDATE_INSTALL_RESULT + item.first;
            system::SetParameter(parameter, MODULE_UPDATE_PARAM_EMPTY);
        }
    }
}

void BMSEventHandler::HandleHmpUninstall()
{
    for (const auto &item : hmpBundlePathInfos_) {
        std::string hmpName = item.second.hmpName;
        if (moduleUpdateStatus_ == ModuleUpdateStatus::UPDATE && !moduleUpdateInstallResults_[hmpName]) {
            LOG_I(BMS_TAG_DEFAULT, "hmp %{public}s update failed, it has been rollback", hmpName.c_str());
            continue;
        }
        std::shared_ptr<HmpBundleInstaller> installer = std::make_shared<HmpBundleInstaller>();
        installer->UpdateBundleInfo(item.second.bundleName, item.second.bundleDir, item.second.hspDir);
    }
}

bool BMSEventHandler::IsSystemUpgrade()
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr != nullptr && dataMgr->IsBopdModeEnabled()) {
        LOG_I(BMS_TAG_DEFAULT, "system should be upgraded due to bopd mode enabled");
        return true;
    }
    return IsTestSystemUpgrade() || IsSystemFingerprintChanged();
}

bool BMSEventHandler::IsTestSystemUpgrade()
{
    std::string paramValue;
    if (!GetSystemParameter(BMS_TEST_UPGRADE, paramValue) || paramValue.empty()) {
        return false;
    }

    LOG_I(BMS_TAG_DEFAULT, "TestSystemUpgrade value is %{public}s", paramValue.c_str());
    return paramValue == VALUE_TRUE;
}

bool BMSEventHandler::IsSystemFingerprintChanged()
{
    std::string oldSystemFingerprint = GetOldSystemFingerprint();
    if (oldSystemFingerprint.empty()) {
        LOG_D(BMS_TAG_DEFAULT, "System should be upgraded due to oldSystemFingerprint is empty");
        return true;
    }

    std::string curSystemFingerprint = GetCurSystemFingerprint();
    LOG_D(BMS_TAG_DEFAULT, "oldSystemFingerprint(%{public}s), curSystemFingerprint(%{public}s)",
        oldSystemFingerprint.c_str(), curSystemFingerprint.c_str());
    return curSystemFingerprint != oldSystemFingerprint;
}

std::string BMSEventHandler::GetCurSystemFingerprint()
{
    std::string curSystemFingerprint;
    for (const auto &item : FINGERPRINTS) {
        std::string itemFingerprint;
        if (!GetSystemParameter(item, itemFingerprint) || itemFingerprint.empty()) {
            continue;
        }

        if (!curSystemFingerprint.empty()) {
            curSystemFingerprint.append(ServiceConstants::PATH_SEPARATOR);
        }

        curSystemFingerprint.append(itemFingerprint);
    }

    return curSystemFingerprint;
}

bool BMSEventHandler::GetSystemParameter(const std::string &key, std::string &value)
{
    char firmware[VERSION_LEN] = {0};
    int32_t ret = GetParameter(key.c_str(), UNKNOWN, firmware, VERSION_LEN);
    if (ret <= 0) {
        LOG_E(BMS_TAG_DEFAULT, "GetParameter failed");
        return false;
    }

    value = firmware;
    return true;
}

std::string BMSEventHandler::GetOldSystemFingerprint()
{
    std::string oldSystemFingerprint;
    auto bmsPara = DelayedSingleton<BundleMgrService>::GetInstance()->GetBmsParam();
    if (bmsPara != nullptr) {
        bmsPara->GetBmsParam(FINGERPRINT, oldSystemFingerprint);
    }

    return oldSystemFingerprint;
}

void BMSEventHandler::AddParseInfosToMap(
    const std::string &bundleName, const std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    auto hapParseInfoMapIter = hapParseInfoMap_.find(bundleName);
    if (hapParseInfoMapIter == hapParseInfoMap_.end()) {
        hapParseInfoMap_.emplace(bundleName, infos);
        return;
    }

    auto iterMap = hapParseInfoMapIter->second;
    for (auto infoIter : infos) {
        iterMap.emplace(infoIter.first, infoIter.second);
    }

    hapParseInfoMap_.at(bundleName) = iterMap;
}

void BMSEventHandler::ProcessRebootBundleUninstall()
{
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "Reboot scan and OTA uninstall start");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }

    std::vector<std::string> preloadBundleNames;
    for (auto &loadIter : loadExistData_) {
        std::string bundleName = loadIter.first;
        BundleInfo hasInstalledInfo;
        auto hasBundleInstalled = dataMgr->GetBundleInfo(
            bundleName, static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE),
            hasInstalledInfo, Constants::ANY_USERID);
        auto listIter = hapParseInfoMap_.find(bundleName);
        if (listIter == hapParseInfoMap_.end()) {
            // no need to process skills, ProcessRebootSkillsUninstall
            if (loadIter.second.GetBundleType() == BundleType::SKILL) {
                continue;
            }
            auto bundlePaths = loadIter.second.GetBundlePaths();
            if (!bundlePaths.empty() && bundlePaths.front().find(ServiceConstants::DATA_PRELOAD_APP) == 0) {
                continue;
            }
            LOG_I(BMS_TAG_DEFAULT, "ProcessRebootBundleUninstall OTA uninstall app(%{public}s)", bundleName.c_str());
            if (InnerProcessUninstallForExistPreBundle(hasInstalledInfo)) {
                continue;
            }
            SystemBundleInstaller installer;
            if (!installer.UninstallSystemBundle(bundleName)) {
                LOG_E(BMS_TAG_DEFAULT, "OTA uninstall app(%{public}s) error", bundleName.c_str());
            } else {
                LOG_I(BMS_TAG_DEFAULT, "OTA uninstall preInstall bundleName:%{public}s succeed", bundleName.c_str());
                std::string moduleName;
                DeletePreInfoInDb(bundleName, moduleName, true);
                if (hasBundleInstalled) {
                    SavePreloadAppUninstallInfo(loadIter.second, preloadBundleNames);
                }
            }

            continue;
        }

        if (!hasBundleInstalled) {
            LOG_W(BMS_TAG_DEFAULT, "app(%{public}s) maybe has been uninstall", bundleName.c_str());
            continue;
        }
        // Check the installed module
        bool isDownGrade = false;
        if (InnerProcessUninstallModule(hasInstalledInfo, listIter->second, isDownGrade)) {
            LOG_I(BMS_TAG_DEFAULT, "bundleName:%{public}s need delete module", bundleName.c_str());
        }
        if (isDownGrade) {
            LOG_I(BMS_TAG_DEFAULT, "bundleName:%{public}s is being downgraded for ota", bundleName.c_str());
            continue;
        }
        // Check the preInstall path in Db.
        // If the corresponding Hap does not exist, it should be deleted.
        auto parserInfoMap = listIter->second;
        for (auto preBundlePath : loadIter.second.GetBundlePaths()) {
            auto parserInfoIter = parserInfoMap.find(preBundlePath);
            if (parserInfoIter != parserInfoMap.end()) {
                continue;
            }

            LOG_I(BMS_TAG_DEFAULT, "OTA app(%{public}s) delete path(%{public}s)",
                bundleName.c_str(), preBundlePath.c_str());
            DeletePreInfoInDb(bundleName, preBundlePath, false);
        }
    }
    SaveUninstalledPreloadAppToFile(preloadBundleNames);
    LOG_I(BMS_TAG_DEFAULT, "Reboot scan and OTA uninstall success");
}

void BMSEventHandler::SavePreloadAppUninstallInfo(const PreInstallBundleInfo &info,
    std::vector<std::string> &preloadBundleNames)
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }
    std::string bundleName = info.GetBundleName();
    std::vector<std::string> bundlePaths = info.GetBundlePaths();
    if (bundlePaths.empty()) {
        LOG_W(BMS_TAG_DEFAULT, "-n %{public}s bundle path is empty.", bundleName.c_str());
        return;
    }
    bool isPreloadApp = std::all_of(bundlePaths.begin(), bundlePaths.end(),
        [] (const std::string &path) {
            return path.find(ServiceConstants::PRELOAD_APP_DIR) == 0;
        });
    bool isBundleExist = dataMgr->IsBundleExist(bundleName);
    if (isPreloadApp && !isBundleExist) {
        preloadBundleNames.emplace_back(bundleName);
    }
}

void BMSEventHandler::SaveUninstalledPreloadAppToFile(const std::vector<std::string> &preloadBundleNames)
{
    if (preloadBundleNames.empty()) {
        return;
    }
    LOG_I(BMS_TAG_DEFAULT, "save preload app:%{public}s", GetJsonStrFromInfo(preloadBundleNames).c_str());
    CreateUninstalledPreloadDir();
    std::string filePath = std::string(ServiceConstants::BUNDLE_MANAGER_SERVICE_PATH) +
        ServiceConstants::UNINSTALLED_PRELOAD_PATH + ServiceConstants::UNINSTALLED_PRELOAD_FILE;
    nlohmann::json jsonData;
    jsonData[ServiceConstants::UNINSTALL_PRELOAD_LIST] = preloadBundleNames;

    FILE *out = fopen(filePath.c_str(), "w");
    if (out == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "fopen %{public}s failed", filePath.c_str());
        return;
    }
    int32_t outFd = fileno(out);
    if (outFd < 0) {
        LOG_E(BMS_TAG_DEFAULT, "open %{public}s failed", filePath.c_str());
        (void)fclose(out);
        return;
    }
    if (fputs(jsonData.dump().c_str(), out) == EOF) {
        LOG_E(BMS_TAG_DEFAULT, "fputs %{public}s failed", filePath.c_str());
        (void)fclose(out);
        return;
    }
    if (fsync(outFd) != 0) {
        LOG_E(BMS_TAG_DEFAULT, "fsync %{public}s failed", filePath.c_str());
    }
    (void)fclose(out);
}

bool BMSEventHandler::InnerProcessUninstallModule(const BundleInfo &bundleInfo,
    const std::unordered_map<std::string, InnerBundleInfo> &infos, bool &isDownGrade)
{
    if (infos.empty()) {
        LOG_I(BMS_TAG_DEFAULT, "bundleName:%{public}s infos is empty", bundleInfo.name.c_str());
        return false;
    }
    if (bundleInfo.versionCode > infos.begin()->second.GetVersionCode()) {
        LOG_I(BMS_TAG_DEFAULT, "%{public}s version code is bigger than new pre-hap", bundleInfo.name.c_str());
        isDownGrade = true;
        return false;
    }
    for (const auto &hapModuleInfo : bundleInfo.hapModuleInfos) {
        if (hapModuleInfo.hapPath.find(Constants::BUNDLE_CODE_DIR) == 0) {
            return false;
        }
    }
    if (bundleInfo.hapModuleNames.size() == 1) {
        LOG_NOFUNC_I(BMS_TAG_DEFAULT, "InnerProcessUninstallModule -n %{public}s only one module forbid uninstall",
            bundleInfo.name.c_str());
        return false;
    }
    bool needUninstallModule = false;
    // Check the installed module.
    // If the corresponding Hap does not exist, it should be uninstalled.
    for (auto moduleName : bundleInfo.hapModuleNames) {
        bool hasModuleHapExist = false;
        for (auto parserInfoIter : infos) {
            auto parserModuleNames = parserInfoIter.second.GetModuleNameVec();
            if (!parserModuleNames.empty() && moduleName == parserModuleNames[0]) {
                hasModuleHapExist = true;
                break;
            }
        }

        if (!hasModuleHapExist) {
            LOG_I(BMS_TAG_DEFAULT, "ProcessRebootBundleUninstall OTA app(%{public}s) uninstall module(%{public}s)",
                bundleInfo.name.c_str(), moduleName.c_str());
            needUninstallModule = true;
            SystemBundleInstaller installer;
            if (!installer.UninstallSystemBundle(bundleInfo.name, moduleName)) {
                LOG_E(BMS_TAG_DEFAULT, "OTA app(%{public}s) uninstall module(%{public}s) error",
                    bundleInfo.name.c_str(), moduleName.c_str());
            }
        }
    }
    return needUninstallModule;
}

void BMSEventHandler::DeletePreInfoInDb(
    const std::string &bundleName, const std::string &bundlePath, bool bundleLevel)
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }

    PreInstallBundleInfo preInstallBundleInfo;
    preInstallBundleInfo.SetBundleName(bundleName);
    if (bundleLevel) {
        LOG_NOFUNC_I(BMS_TAG_DEFAULT, "DeletePreInfoInDb bundle %{public}s bundleLevel", bundleName.c_str());
        dataMgr->DeletePreInstallBundleInfo(bundleName, preInstallBundleInfo);
        return;
    }

    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "DeletePreInfoInDb -n %{public}s bundleLevel=false path:%{public}s",
        bundleName.c_str(), bundlePath.c_str());
    dataMgr->GetPreInstallBundleInfo(bundleName, preInstallBundleInfo);
    preInstallBundleInfo.DeleteBundlePath(bundlePath);
    if (preInstallBundleInfo.GetBundlePaths().empty()) {
        dataMgr->DeletePreInstallBundleInfo(bundleName, preInstallBundleInfo);
    } else {
        dataMgr->SavePreInstallBundleInfo(bundleName, preInstallBundleInfo);
    }
}

bool BMSEventHandler::HasModuleSavedInPreInstalledDb(
    const std::string &bundleName, const std::string &bundlePath)
{
    auto preInstallIter = loadExistData_.find(bundleName);
    if (preInstallIter == loadExistData_.end()) {
        LOG_E(BMS_TAG_DEFAULT, "app(%{public}s) does not save in PreInstalledDb", bundleName.c_str());
        return false;
    }

    return preInstallIter->second.HasBundlePath(bundlePath);
}

void BMSEventHandler::SavePreInstallException(const std::string &bundleDir)
{
    auto preInstallExceptionMgr =
        DelayedSingleton<BundleMgrService>::GetInstance()->GetPreInstallExceptionMgr();
    if (preInstallExceptionMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "preInstallExceptionMgr is nullptr");
        return;
    }

    preInstallExceptionMgr->SavePreInstallExceptionPath(bundleDir);
}

void BMSEventHandler::SavePreInstallExceptionBundleName(const std::string &bundleName)
{
    auto preInstallExceptionMgr =
        DelayedSingleton<BundleMgrService>::GetInstance()->GetPreInstallExceptionMgr();
    if (preInstallExceptionMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "preInstallExceptionMgr is nullptr");
        return;
    }

    preInstallExceptionMgr->SavePreInstallExceptionBundleName(bundleName);
}

void BMSEventHandler::SavePreInstallExceptionAppService(const std::string &bundleDir)
{
    auto preInstallExceptionMgr =
        DelayedSingleton<BundleMgrService>::GetInstance()->GetPreInstallExceptionMgr();
    if (preInstallExceptionMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "preInstallExceptionMgr is nullptr");
        return;
    }

    preInstallExceptionMgr->SavePreInstallExceptionAppServicePath(bundleDir);
}

void BMSEventHandler::DeletePreInstallExceptionAppService(const std::string &bundleDir)
{
    auto preInstallExceptionMgr =
        DelayedSingleton<BundleMgrService>::GetInstance()->GetPreInstallExceptionMgr();
    if (preInstallExceptionMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "preInstallExceptionMgr is nullptr");
        return;
    }

    preInstallExceptionMgr->DeletePreInstallExceptionAppServicePath(bundleDir);
}

void BMSEventHandler::SavePreInstallExceptionShared(const std::string &bundleDir)
{
    auto preInstallExceptionMgr =
        DelayedSingleton<BundleMgrService>::GetInstance()->GetPreInstallExceptionMgr();
    if (preInstallExceptionMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "preInstallExceptionMgr is nullptr");
        return;
    }

    preInstallExceptionMgr->SavePreInstallExceptionSharedBundlePath(bundleDir);
}

void BMSEventHandler::DeletePreInstallExceptionShared(const std::string &bundleDir)
{
    auto preInstallExceptionMgr =
        DelayedSingleton<BundleMgrService>::GetInstance()->GetPreInstallExceptionMgr();
    if (preInstallExceptionMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "preInstallExceptionMgr is nullptr");
        return;
    }

    preInstallExceptionMgr->DeletePreInstallExceptionSharedBundlePath(bundleDir);
}

void BMSEventHandler::HandlePreInstallException(bool needDeleteRecord)
{
    auto preInstallExceptionMgr =
        DelayedSingleton<BundleMgrService>::GetInstance()->GetPreInstallExceptionMgr();
    if (preInstallExceptionMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "preInstallExceptionMgr is nullptr");
        return;
    }

    std::set<std::string> exceptionPaths;
    std::set<std::string> exceptionBundleNames;
    std::set<std::string> exceptionAppServicePaths;
    std::set<std::string> exceptionAppServiceBundleNames;
    std::set<std::string> exceptionSharedPaths;
    if (!preInstallExceptionMgr->GetAllPreInstallExceptionInfo(exceptionPaths, exceptionBundleNames,
        exceptionAppServicePaths, exceptionAppServiceBundleNames, exceptionSharedPaths)) {
        LOG_I(BMS_TAG_DEFAULT, "No pre-install exception information found");
        return;
    }

    std::vector<std::string> tmpPath;
    tmpPath.reserve(exceptionPaths.size() + exceptionBundleNames.size() + exceptionAppServicePaths.size() +
        exceptionAppServiceBundleNames.size() + exceptionSharedPaths.size());
    tmpPath.insert(tmpPath.end(), exceptionPaths.begin(), exceptionPaths.end());
    tmpPath.insert(tmpPath.end(), exceptionBundleNames.begin(), exceptionBundleNames.end());
    tmpPath.insert(tmpPath.end(), exceptionAppServicePaths.begin(), exceptionAppServicePaths.end());
    tmpPath.insert(tmpPath.end(), exceptionAppServiceBundleNames.begin(), exceptionAppServiceBundleNames.end());
    tmpPath.insert(tmpPath.end(), exceptionSharedPaths.begin(), exceptionSharedPaths.end());
    EventReport::SendTriggerFallbackEvent(HighRiskOperationType::PRE_INSTALL_EXCEPTION, Constants::EMPTY_STRING,
        Constants::UNSPECIFIED_USERID, tmpPath);

    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "handle exception %{public}zu %{public}zu %{public}zu %{public}zu %{public}zu",
        exceptionPaths.size(), exceptionBundleNames.size(), exceptionAppServicePaths.size(),
        exceptionAppServiceBundleNames.size(), exceptionSharedPaths.size());
    HandlePreInstallAppServicePathsException(preInstallExceptionMgr, exceptionAppServicePaths);
    HandlePreInstallSharedBundlePathsException(preInstallExceptionMgr, exceptionSharedPaths);
    HandlePreInstallAppPathsException(preInstallExceptionMgr, exceptionPaths, needDeleteRecord);
    if (!exceptionBundleNames.empty() || !exceptionAppServiceBundleNames.empty()) {
        LOG_NOFUNC_I(BMS_TAG_DEFAULT, "Loading all pre-install bundle infos");
        LoadAllPreInstallBundleInfos();
    }
    HandlePreInstallAppServiceBundleNamesException(
        preInstallExceptionMgr, exceptionAppServiceBundleNames, needDeleteRecord);
    HandlePreInstallBundleNamesException(preInstallExceptionMgr, exceptionBundleNames, needDeleteRecord);

    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "Pre-install exception information cleared successfully");
}

void BMSEventHandler::HandlePreInstallAppServicePathsException(
    std::shared_ptr<PreInstallExceptionMgr> preInstallExceptionMgr,
    const std::set<std::string> &exceptionAppServicePaths)
{
    if (preInstallExceptionMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "preInstallExceptionMgr is nullptr");
        return;
    }
    for (const auto &pathIter : exceptionAppServicePaths) {
        LOG_NOFUNC_I(BMS_TAG_DEFAULT, "fwk path:%{public}s", pathIter.c_str());
        std::vector<std::string> filePaths { pathIter };
        if (OTAInstallSystemHsp(filePaths) != ERR_OK) {
            LOG_NOFUNC_W(BMS_TAG_DEFAULT, "ota install fwk path(%{public}s) error", pathIter.c_str());
        } else {
            preInstallExceptionMgr->DeletePreInstallExceptionAppServicePath(pathIter);
        }
    }
}

void BMSEventHandler::HandlePreInstallAppPathsException(std::shared_ptr<PreInstallExceptionMgr> preInstallExceptionMgr,
    const std::set<std::string> &exceptionPaths, bool needDeleteRecord)
{
    if (preInstallExceptionMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "preInstallExceptionMgr is nullptr");
        return;
    }
    for (const auto &pathIter : exceptionPaths) {
        LOG_NOFUNC_I(BMS_TAG_DEFAULT, "HandlePreInstallException path:%{public}s", pathIter.c_str());
        std::vector<std::string> filePaths { pathIter };
        bool removable = IsPreInstallRemovable(pathIter);
        if (!OTAInstallSystemBundle(filePaths, Constants::AppType::SYSTEM_APP, removable)) {
            LOG_NOFUNC_W(BMS_TAG_DEFAULT, "HandlePreInstallException path(%{public}s) error", pathIter.c_str());
            // If the bundle cannot be removed and the path is not empty, need try again
            if (!removable && !OHOS::IsEmptyFolder(pathIter)) {
                LOG_NOFUNC_W(BMS_TAG_DEFAULT, "%{public}s removable is false and not empty", pathIter.c_str());
                continue;
            }
        }

        if (needDeleteRecord) {
            preInstallExceptionMgr->DeletePreInstallExceptionPath(pathIter);
        }
    }
}

void BMSEventHandler::HandlePreInstallSharedBundlePathsException(
    std::shared_ptr<PreInstallExceptionMgr> preInstallExceptionMgr,
    const std::set<std::string> &exceptionSharedPaths)
{
    if (preInstallExceptionMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "preInstallExceptionMgr is nullptr");
        return;
    }
    for (const auto &pathIter : exceptionSharedPaths) {
        LOG_NOFUNC_I(BMS_TAG_DEFAULT, "shared path:%{public}s", pathIter.c_str());
        if (!OTAInstallSystemSharedBundle(
            { pathIter }, Constants::AppType::SYSTEM_APP, IsPreInstallRemovable(pathIter))) {
            LOG_NOFUNC_W(BMS_TAG_DEFAULT, "ota install shared path(%{public}s) error", pathIter.c_str());
        } else {
            preInstallExceptionMgr->DeletePreInstallExceptionSharedBundlePath(pathIter);
        }
    }
}

void BMSEventHandler::HandlePreInstallAppServiceBundleNamesException(
    std::shared_ptr<PreInstallExceptionMgr> preInstallExceptionMgr,
    const std::set<std::string> &exceptionAppServiceBundleNames, bool needDeleteRecord)
{
    if (preInstallExceptionMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "preInstallExceptionMgr is nullptr");
        return;
    }
    for (const auto &bundleNameIter : exceptionAppServiceBundleNames) {
        LOG_NOFUNC_I(BMS_TAG_DEFAULT, "handle fwk exception -n: %{public}s", bundleNameIter.c_str());
        auto iter = loadExistData_.find(bundleNameIter);
        if (iter == loadExistData_.end()) {
            LOG_NOFUNC_W(BMS_TAG_DEFAULT, "there is no(%{public}s) in PreInstallDb",
                bundleNameIter.c_str());
            continue;
        }
        const auto &preInstallBundleInfo = iter->second;
        if (OTAInstallSystemHsp(preInstallBundleInfo.GetBundlePaths()) != ERR_OK) {
            LOG_NOFUNC_W(BMS_TAG_DEFAULT, "ota install fwk(%{public}s) error", bundleNameIter.c_str());
        }

        if (needDeleteRecord) {
            preInstallExceptionMgr->DeletePreInstallExceptionBundleName(bundleNameIter);
        }
    }
}

void BMSEventHandler::HandlePreInstallBundleNamesException(
    std::shared_ptr<PreInstallExceptionMgr> preInstallExceptionMgr,
    const std::set<std::string> &exceptionBundleNames, bool needDeleteRecord)
{
    if (preInstallExceptionMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "preInstallExceptionMgr is nullptr");
        return;
    }
    for (const auto &bundleNameIter : exceptionBundleNames) {
        LOG_NOFUNC_I(BMS_TAG_DEFAULT, "HandlePreInstallException bundleName: %{public}s", bundleNameIter.c_str());
        auto iter = loadExistData_.find(bundleNameIter);
        if (iter == loadExistData_.end()) {
            LOG_NOFUNC_W(BMS_TAG_DEFAULT, "HandlePreInstallException no bundleName(%{public}s) in PreInstallDb",
                bundleNameIter.c_str());
            continue;
        }

        const auto &preInstallBundleInfo = iter->second;
        bool forceClone = preInstallBundleInfo.IsDualModeCloneApp();
        auto distPolicy = preInstallBundleInfo.GetDeviceModeDistributionPolicy();
        bool ret = false;
        if (preInstallBundleInfo.GetBundlePaths().empty()) {
            LOG_NOFUNC_W(BMS_TAG_DEFAULT, "HandlePreInstallException bundlePaths is empty: %{public}s",
                bundleNameIter.c_str());
        } else if (!xmlMap_.empty()) {
            std::vector<int32_t> userIds;
            std::string bundleName = bundleNameIter;
            GetBundleNameAndUserIdFromPath(preInstallBundleInfo.GetBundlePaths().front(), userIds, bundleName);
            ret = OTAInstallSystemBundleTargetUser(preInstallBundleInfo.GetBundlePaths(), bundleNameIter,
                Constants::AppType::SYSTEM_APP, preInstallBundleInfo.IsRemovable(), userIds, false, forceClone,
                distPolicy);
        } else if (CheckDualModeCrossInstall(forceClone, distPolicy)) {
            CrossModeOtaTask task;
            task.removable = preInstallBundleInfo.IsRemovable();
            task.policy = distPolicy;
            task.forceCrossModeOTAInstall = true;
            ret = OTAInstallSystemBundleForDualApp(preInstallBundleInfo.GetBundlePaths(), task,
                Constants::AppType::SYSTEM_APP);
        } else {
            ret = OTAInstallSystemBundle(preInstallBundleInfo.GetBundlePaths(),
                Constants::AppType::SYSTEM_APP, preInstallBundleInfo.IsRemovable(), forceClone, distPolicy);
        }
        if (!ret) {
            LOG_NOFUNC_W(BMS_TAG_DEFAULT, "HandlePreInstallException bundleName(%{public}s) error",
                bundleNameIter.c_str());
            if (!preInstallBundleInfo.IsRemovable()) {
                continue;
            }
        }
        if (needDeleteRecord) {
            preInstallExceptionMgr->DeletePreInstallExceptionBundleName(bundleNameIter);
        }
    }
}

bool BMSEventHandler::OTAInstallSystemBundle(
    const std::vector<std::string> &filePaths,
    Constants::AppType appType,
    bool removable,
    bool forceDualModeCloneInstall,
    DeviceModeDistributionPolicy deviceModeDistributionPolicy)
{
    if (filePaths.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "File path is empty");
        return false;
    }
    InstallParam installParam;
    installParam.isPreInstallApp = true;
    installParam.SetKillProcess(false);
    installParam.needSendEvent = false;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.removable = removable;
    installParam.needSavePreInstallInfo = true;
    installParam.copyHapToInstallPath = false;
    installParam.isOTA = true;
    installParam.preinstallSourceFlag = ApplicationInfoFlag::FLAG_OTA_INSTALLED;
    installParam.forceDualModeCloneInstall = forceDualModeCloneInstall;
    installParam.deviceModeDistributionPolicy = deviceModeDistributionPolicy;
    SystemBundleInstaller installer;
    ErrCode ret = installer.OTAInstallSystemBundle(filePaths, installParam, appType);
    if (ret == ERR_APPEXECFWK_INSTALL_ZERO_USER_WITH_NO_SINGLETON) {
        ret = ERR_OK;
    }
    return ret == ERR_OK;
}

bool BMSEventHandler::OTAInstallSystemBundleNeedCheckUser(
    const std::vector<std::string> &filePaths,
    const std::string &bundleName,
    Constants::AppType appType,
    bool removable,
    DeviceModeDistributionPolicy deviceModeDistributionPolicy)
{
    if (filePaths.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "File path is empty");
        return false;
    }
    int32_t timerId = XCollieHelper::SetOTATimer(OTA_PREINSTALL_BUNDLE_TASK, OTA_TIMEOUT_SECONDS);
    ScopeGuard cancelTimerIdGuard([timerId] { XCollieHelper::CancelTimer(timerId); });
    InstallParam installParam;
    installParam.isPreInstallApp = true;
    installParam.SetKillProcess(false);
    installParam.needSendEvent = false;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.removable = removable;
    installParam.needSavePreInstallInfo = true;
    installParam.copyHapToInstallPath = false;
    installParam.isOTA = true;
    installParam.preinstallSourceFlag = ApplicationInfoFlag::FLAG_OTA_INSTALLED;
    installParam.deviceModeDistributionPolicy = deviceModeDistributionPolicy;
    SystemBundleInstaller installer;
    ErrCode ret = installer.OTAInstallSystemBundleNeedCheckUser(filePaths, installParam, bundleName, appType);
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "bundle %{public}s with return code: %{public}d", bundleName.c_str(), ret);
    if ((ret != ERR_OK) && (ret != ERR_APPEXECFWK_INSTALL_ZERO_USER_WITH_NO_SINGLETON)) {
        APP_LOGE("OTA bundle(%{public}s) failed, errCode:%{public}d", bundleName.c_str(), ret);
        if (!filePaths.empty()) {
            SavePreInstallException(filePaths[0]);
        }
        return false;
    }
    return true;
}

bool BMSEventHandler::OTAInstallSystemBundleTargetUser(const std::vector<std::string> &filePaths,
    const std::string &bundleName, Constants::AppType appType, bool removable, const std::vector<int32_t> &userIds,
    bool isPatchDowngrade, bool forceDualModeCloneInstall,
    DeviceModeDistributionPolicy deviceModeDistributionPolicy)
{
    if (filePaths.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "File path is empty");
        return false;
    }
    if (userIds.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "userIds is empty");
        return false;
    }
    InstallParam installParam;
    installParam.isPreInstallApp = true;
    installParam.SetKillProcess(false);
    installParam.needSendEvent = false;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.removable = removable;
    installParam.needSavePreInstallInfo = true;
    installParam.copyHapToInstallPath = false;
    installParam.isOTA = true;
    installParam.preinstallSourceFlag = ApplicationInfoFlag::FLAG_OTA_INSTALLED;
    installParam.forceDualModeCloneInstall = forceDualModeCloneInstall;
    installParam.deviceModeDistributionPolicy = deviceModeDistributionPolicy;
    // support patch app downgrade install
    if (isPatchDowngrade) {
        installParam.allowPatchDowngrade = true;
    }
    SystemBundleInstaller installer;
    ErrCode ret = installer.OTAInstallSystemBundleTargetUser(filePaths, installParam, bundleName, appType, userIds);
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "bundle %{public}s with return code: %{public}d", bundleName.c_str(), ret);
    if ((ret != ERR_OK) && (ret != ERR_APPEXECFWK_INSTALL_ZERO_USER_WITH_NO_SINGLETON)) {
        APP_LOGE("OTA bundle(%{public}s) failed, errCode:%{public}d", bundleName.c_str(), ret);
        if (!filePaths.empty()) {
            SavePreInstallException(filePaths[0]);
        }
        return false;
    }
    return true;
}

bool BMSEventHandler::OTAInstallSystemSharedBundle(
    const std::vector<std::string> &filePaths,
    Constants::AppType appType,
    bool removable)
{
    if (filePaths.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "File path is empty");
        return false;
    }

    InstallParam installParam;
    installParam.isPreInstallApp = true;
    installParam.needSendEvent = false;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.removable = removable;
    installParam.needSavePreInstallInfo = true;
    installParam.sharedBundleDirPaths = filePaths;
    installParam.isOTA = true;
    installParam.preinstallSourceFlag = ApplicationInfoFlag::FLAG_OTA_INSTALLED;
    SystemBundleInstaller installer;
    return installer.InstallSystemSharedBundle(installParam, true, appType);
}

bool BMSEventHandler::CheckAndParseHapFiles(
    const std::string &hapFilePath,
    bool isPreInstallApp,
    std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    std::vector<std::string> hapFilePathVec { hapFilePath };
    std::vector<std::string> realPaths;
    auto ret = BundleUtil::CheckFilePath(hapFilePathVec, realPaths);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "File path %{public}s invalid", hapFilePath.c_str());
        return false;
    }
    return CheckAndParseHapFiles(realPaths, isPreInstallApp, infos);
}

bool BMSEventHandler::CheckAndParseHapFiles(
    const std::vector<std::string> &realPaths,
    bool isPreInstallApp,
    std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    std::unique_ptr<BundleInstallChecker> bundleInstallChecker =
        std::make_unique<BundleInstallChecker>();

    ErrCode checkSysCapRes = bundleInstallChecker->CheckSysCap(realPaths);
    if (checkSysCapRes != ERR_OK) {
        LOG_D(BMS_TAG_DEFAULT, "hap syscap check failed");
    }

    std::vector<Security::Verify::HapVerifyResult> hapVerifyResults;
    auto ret = bundleInstallChecker->CheckMultipleHapsSignInfo(realPaths, hapVerifyResults, true);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "CheckMultipleHapsSignInfo failed");
        return false;
    }

    InstallCheckParam checkParam;
    checkParam.isPreInstallApp = isPreInstallApp;
    if (isPreInstallApp) {
        checkParam.appType = Constants::AppType::SYSTEM_APP;
    }

    if (!LoadPreInstallProFile()) {
        LOG_W(BMS_TAG_DEFAULT, "load json failed for restore");
    }
    ret = bundleInstallChecker->ParseHapFiles(
        realPaths, checkParam, hapVerifyResults, infos);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "parse haps file failed");
        return false;
    }

    if (checkSysCapRes != ERR_OK) {
        ret = bundleInstallChecker->CheckDeviceType(infos, checkSysCapRes);
        if (ret != ERR_OK) {
            LOG_E(BMS_TAG_INSTALLER, "CheckDeviceType failed due to errorCode : %{public}d", ret);
            return false;
        }
    }

    ret = bundleInstallChecker->CheckHspInstallCondition(hapVerifyResults);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "CheckHspInstallCondition failed %{public}d", ret);
        return false;
    }

    ret = bundleInstallChecker->CheckAppLabelInfo(infos);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "Check APP label failed %{public}d", ret);
        return false;
    }

    ret = bundleInstallChecker->CheckMultiNativeFile(infos);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "CheckMultiNativeFile failed %{public}d", ret);
        return false;
    }
    std::string developerId;
    if (!hapVerifyResults.empty()) {
        developerId = hapVerifyResults[0].GetProvisionInfo().bundleInfo.developerId;
        if (developerId.empty()) {
            developerId = hapVerifyResults[0].GetProvisionInfo().bundleInfo.bundleName;
        }
    }

    // set hapPath
    std::for_each(infos.begin(), infos.end(), [&developerId](auto &item) {
        item.second.SetModuleHapPath(item.first);
        item.second.UpdateDeveloperId(developerId);
    });

    return true;
}

bool BMSEventHandler::ParseHapFiles(
    const std::string &hapFilePath,
    std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    std::vector<std::string> hapFilePathVec { hapFilePath };
    std::vector<std::string> realPaths;
    auto ret = BundleUtil::CheckFilePath(hapFilePathVec, realPaths);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "File path %{public}s invalid", hapFilePath.c_str());
        return false;
    }

    BundleParser bundleParser;
    for (auto realPath : realPaths) {
        InnerBundleInfo innerBundleInfo;
        bool isAbcCompressed = false;
        ret = bundleParser.Parse(realPath, innerBundleInfo, isAbcCompressed);
        if (ret != ERR_OK) {
            LOG_E(BMS_TAG_DEFAULT, "Parse bundle info failed, error: %{public}d", ret);
            continue;
        }

        infos.emplace(realPath, innerBundleInfo);
    }

    if (infos.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "Parse hap(%{public}s) empty ", hapFilePath.c_str());
        return false;
    }

    return true;
}

bool BMSEventHandler::IsPreInstallRemovable(const std::string &path)
{
#ifdef USE_PRE_BUNDLE_PROFILE
    if (!HasPreInstallProfile()) {
        return false;
    }

    if (!hasLoadPreInstallProFile_) {
        LOG_E(BMS_TAG_DEFAULT, "Not load preInstall proFile or release");
        return false;
    }

    if (path.empty() || installList_.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "path or installList is empty");
        return false;
    }
    auto installInfo = std::find_if(installList_.begin(), installList_.end(),
        [path](const auto &installInfo) {
        return installInfo.bundleDir == path;
    });
    if (installInfo != installList_.end()) {
        return (*installInfo).removable;
    }
    return true;
#else
    return false;
#endif
}

bool BMSEventHandler::GetPreInstallCapability(PreBundleConfigInfo &preBundleConfigInfo)
{
    if (!hasLoadPreInstallProFile_) {
        LOG_E(BMS_TAG_DEFAULT, "Not load preInstall proFile or release");
        return false;
    }

    if (preBundleConfigInfo.bundleName.empty() || installListCapabilities_.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "BundleName or installListCapabilities is empty");
        return false;
    }

    auto iter = installListCapabilities_.find(preBundleConfigInfo);
    if (iter == installListCapabilities_.end()) {
        LOG_D(BMS_TAG_DEFAULT, "BundleName(%{public}s) no has preinstall capability",
            preBundleConfigInfo.bundleName.c_str());
        return false;
    }

    preBundleConfigInfo = *iter;
    return true;
}

bool BMSEventHandler::CheckExtensionTypeInConfig(const std::string &typeName)
{
    if (!hasLoadPreInstallProFile_) {
        LOG_E(BMS_TAG_DEFAULT, "Not load typeName proFile or release");
        return false;
    }

    if (typeName.empty() || extensiontype_.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "TypeName or typeName configuration file is empty");
        return false;
    }

    auto iter = extensiontype_.find(typeName);
    if (iter == extensiontype_.end()) {
        LOG_E(BMS_TAG_DEFAULT, "ExtensionTypeConfig does not have '(%{public}s)' type",
            typeName.c_str());
        return false;
    }

    return true;
}

#ifdef USE_PRE_BUNDLE_PROFILE
void BMSEventHandler::UpdateRemovable(const std::string &bundleName, bool removable)
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }

    dataMgr->UpdateRemovable(bundleName, removable);
}

void BMSEventHandler::UpdateAllPrivilegeCapability()
{
    for (const auto &preBundleConfigInfo : installListCapabilities_) {
        UpdatePrivilegeCapability(preBundleConfigInfo);
    }
}

void BMSEventHandler::UpdatePrivilegeCapability(
    const PreBundleConfigInfo &preBundleConfigInfo)
{
    auto &bundleName = preBundleConfigInfo.bundleName;
    InnerBundleInfo innerBundleInfo;
    if (!FetchInnerBundleInfo(bundleName, innerBundleInfo)) {
        LOG_NOFUNC_W(BMS_TAG_DEFAULT, "App(%{public}s) is not installed", bundleName.c_str());
        return;
    }
    // match both fingerprint and appId
    if (!MatchSignature(preBundleConfigInfo, innerBundleInfo.GetCertificateFingerprint()) &&
        !MatchSignature(preBundleConfigInfo, innerBundleInfo.GetAppId()) &&
        !MatchSignature(preBundleConfigInfo, innerBundleInfo.GetAppIdentifier()) &&
        !MatchOldSignatures(preBundleConfigInfo, innerBundleInfo.GetOldAppIds())) {
        LOG_E(BMS_TAG_DEFAULT, "bundleName: %{public}s no match pre bundle config info", bundleName.c_str());
        return;
    }

    UpdateTrustedPrivilegeCapability(preBundleConfigInfo);
}

bool BMSEventHandler::MatchSignature(
    const PreBundleConfigInfo &configInfo, const std::string &signature)
{
    if (configInfo.appSignature.empty() || signature.empty()) {
        LOG_W(BMS_TAG_DEFAULT, "appSignature or signature is empty");
        return false;
    }

    return std::find(configInfo.appSignature.begin(),
        configInfo.appSignature.end(), signature) != configInfo.appSignature.end();
}

bool BMSEventHandler::MatchOldSignatures(const PreBundleConfigInfo &configInfo,
    const std::vector<std::string> &oldSignatures)
{
    if (configInfo.appSignature.empty() || oldSignatures.empty()) {
        LOG_W(BMS_TAG_DEFAULT, "appSignature or oldSignatures is empty");
        return false;
    }
    for (const auto &signature : oldSignatures) {
        if (std::find(configInfo.appSignature.begin(), configInfo.appSignature.end(), signature) !=
            configInfo.appSignature.end()) {
            return true;
        }
    }

    return false;
}

void BMSEventHandler::UpdateTrustedPrivilegeCapability(
    const PreBundleConfigInfo &preBundleConfigInfo)
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }

    ApplicationInfo appInfo;
    appInfo.keepAlive = preBundleConfigInfo.keepAlive;
    appInfo.singleton = preBundleConfigInfo.singleton;
    appInfo.runningResourcesApply = preBundleConfigInfo.runningResourcesApply;
    appInfo.associatedWakeUp = preBundleConfigInfo.associatedWakeUp;
    appInfo.allowCommonEvent = preBundleConfigInfo.allowCommonEvent;
    appInfo.resourcesApply = preBundleConfigInfo.resourcesApply;
    // For system apps, default allowAppRunWhenDeviceFirstLocked to true;
    // only override if explicitly configured in JSON
    InnerBundleInfo innerBundleInfo;
    bool isSystemApp = dataMgr->FetchInnerBundleInfo(preBundleConfigInfo.bundleName, innerBundleInfo) &&
        innerBundleInfo.IsSystemApp();
    static const std::string ALLOW_APP_RUN_WHEN_DEVICE_FIRST_LOCKED = "allowAppRunWhenDeviceFirstLocked";
    auto it = std::find(preBundleConfigInfo.existInJsonFile.cbegin(),
        preBundleConfigInfo.existInJsonFile.cend(), ALLOW_APP_RUN_WHEN_DEVICE_FIRST_LOCKED);
    if (it != preBundleConfigInfo.existInJsonFile.cend()) {
        appInfo.allowAppRunWhenDeviceFirstLocked = preBundleConfigInfo.allowAppRunWhenDeviceFirstLocked;
    } else if (isSystemApp) {
        appInfo.allowAppRunWhenDeviceFirstLocked = true;
    }
    appInfo.allowEnableNotification = preBundleConfigInfo.allowEnableNotification;
    appInfo.hideDesktopIcon = preBundleConfigInfo.hideDesktopIcon;
    appInfo.allowMultiProcess = preBundleConfigInfo.allowMultiProcess;
    appInfo.userDataClearable = preBundleConfigInfo.userDataClearable;
    appInfo.formVisibleNotify = preBundleConfigInfo.formVisibleNotify;
    dataMgr->UpdatePrivilegeCapability(preBundleConfigInfo.bundleName, appInfo);
}
#endif

bool BMSEventHandler::FetchInnerBundleInfo(
    const std::string &bundleName, InnerBundleInfo &innerBundleInfo)
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return false;
    }

    return dataMgr->FetchInnerBundleInfo(bundleName, innerBundleInfo);
}

void BMSEventHandler::ListeningUserUnlocked() const
{
    LOG_I(BMS_TAG_DEFAULT, "BMSEventHandler listen the unlock of someone user start");
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscribeInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);

    auto subscriberPtr = std::make_shared<UserUnlockedEventSubscriber>(subscribeInfo);
    if (AccountHelper::IsOsAccountVerified(Constants::START_USERID)) {
        LOG_I(BMS_TAG_DEFAULT, "user 100 is unlocked");
        OHOS::AAFwk::Want want;
        want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED);
        EventFwk::CommonEventData data { want };
        data.SetCode(Constants::START_USERID);
        subscriberPtr->OnReceiveEvent(data);
    }
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(subscriberPtr)) {
        LOG_W(BMS_TAG_DEFAULT, "BMSEventHandler subscribe common event %{public}s failed",
            EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED.c_str());
    }
}

void BMSEventHandler::RegisterOobeAgreeTermsEvent() const
{
    LOG_I(BMS_TAG_DEFAULT, "register oobe agree terms event start");
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(OOBE_AGREE_TERMS_EVENT);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscribeInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);
    subscribeInfo.SetPermission(Constants::PERMISSION_ACCESS_STARTUPGUIDE);

    auto subscriberPtr = std::make_shared<UserUnlockedEventSubscriber>(subscribeInfo);
    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(subscriberPtr)) {
        LOG_W(BMS_TAG_DEFAULT, "subscribe oobe agree terms event failed");
    }
}

void BMSEventHandler::RegisterIdleConditionEvent()
{
    LOG_I(BMS_TAG_DEFAULT, "register idle condition event start");
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_LOCKED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_POWER_CONNECTED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_BATTERY_CHANGED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_THERMAL_LEVEL_CHANGED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_POWER_DISCONNECTED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_STOPPING);
    matchingSkills.AddEvent("usual.event.DUE_SA_CFG_UPDATED");
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    subscribeInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);

    auto subscriberPtr = std::make_shared<IdleConditionEventSubscriber>(subscribeInfo);
    int32_t userId = AccountHelper::GetCurrentActiveUserId();
    if (userId == Constants::INVALID_USERID) {
        userId = Constants::START_USERID;
    }
    if (AccountHelper::IsOsAccountVerified(userId)) {
        LOG_I(BMS_TAG_DEFAULT, "user %{public}d is unlocked", userId);
        OHOS::AAFwk::Want want;
        want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_USER_UNLOCKED);
        EventFwk::CommonEventData data { want };
        data.SetCode(userId);
        subscriberPtr->OnReceiveEvent(data);
    }

    if (!EventFwk::CommonEventManager::SubscribeCommonEvent(subscriberPtr)) {
        LOG_W(BMS_TAG_DEFAULT, "subscribe relabel event failed");
    }
}

void BMSEventHandler::RemoveUnreservedSandbox() const
{
#if defined (BUNDLE_FRAMEWORK_SANDBOX_APP) && defined (DLP_PERMISSION_ENABLE)
    LOG_I(BMS_TAG_DEFAULT, "Start to RemoveUnreservedSandbox");
    const int32_t WAIT_TIMES = 40;
    const int32_t EACH_TIME = 1000; // 1000ms
    auto execFunc = [](int32_t waitTimes, int32_t eachTime) {
        int32_t currentUserId = Constants::INVALID_USERID;
        while (waitTimes--) {
            std::this_thread::sleep_for(std::chrono::milliseconds(eachTime));
            LOG_D(BMS_TAG_DEFAULT, "wait for account started");
            if (currentUserId == Constants::INVALID_USERID) {
                currentUserId = AccountHelper::GetUserIdByCallerType();
                LOG_D(BMS_TAG_DEFAULT, "current active userId is %{public}d", currentUserId);
                if (currentUserId == Constants::INVALID_USERID) {
                    continue;
                }
            }
            LOG_I(BMS_TAG_DEFAULT, "RemoveUnreservedSandbox call ClearUnreservedSandbox");
            Security::DlpPermission::DlpPermissionKit::ClearUnreservedSandbox();
            break;
        }
    };
    std::thread removeThread(execFunc, WAIT_TIMES, EACH_TIME);
    removeThread.detach();
#endif
    LOG_I(BMS_TAG_DEFAULT, "RemoveUnreservedSandbox finish");
}

void BMSEventHandler::AddStockAppProvisionInfoByOTA(const std::string &bundleName, const std::string &filePath)
{
    LOG_D(BMS_TAG_DEFAULT, "AddStockAppProvisionInfoByOTA bundleName: %{public}s", bundleName.c_str());
    // parse profile info
    Security::Verify::HapVerifyResult hapVerifyResult;
    auto ret = BundleVerifyMgr::ParseHapProfile(filePath, hapVerifyResult, true);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "BundleVerifyMgr::HapVerify failed, bundleName: %{public}s, errCode: %{public}d",
            bundleName.c_str(), ret);
        return;
    }

    std::unique_ptr<BundleInstallChecker> bundleInstallChecker =
        std::make_unique<BundleInstallChecker>();
    AppProvisionInfo appProvisionInfo = bundleInstallChecker->ConvertToAppProvisionInfo(
        hapVerifyResult.GetProvisionInfo());
    if (!DelayedSingleton<AppProvisionInfoManager>::GetInstance()->AddAppProvisionInfo(bundleName, appProvisionInfo)) {
        LOG_E(BMS_TAG_DEFAULT, "AddAppProvisionInfo failed, bundleName:%{public}s", bundleName.c_str());
    }
}

void BMSEventHandler::UpdateAppDataSelinuxLabel(const std::string &bundleName, const std::string &apl,
    bool isPreInstall, bool debug)
{
    LOG_D(BMS_TAG_DEFAULT, "UpdateAppDataSelinuxLabel bundleName: %{public}s start", bundleName.c_str());
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }
    std::set<int32_t> userIds = dataMgr->GetAllUser();
    for (const auto &userId : userIds) {
        for (const auto &el : ServiceConstants::BUNDLE_EL) {
            std::string baseBundleDataDir = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR +
                                            el +
                                            ServiceConstants::PATH_SEPARATOR +
                                            std::to_string(userId);
            std::string baseDataDir = baseBundleDataDir + ServiceConstants::BASE + bundleName;
            bool isExist = true;
            ErrCode result = InstalldClient::GetInstance()->IsExistDir(baseDataDir, isExist);
            if (result != ERR_OK) {
                LOG_E(BMS_TAG_DEFAULT, "IsExistDir failed, error is %{public}d", result);
                continue;
            }
            if (!isExist) {
                // Update only accessible directories when OTA,
                // and other directories need to be set after the device is unlocked.
                // Can see UserUnlockedEventSubscriber::UpdateAppDataDirSelinuxLabel
                continue;
            }
            int32_t uid = dataMgr->GetUidByBundleName(bundleName, userId, 0);
            result = InstalldClient::GetInstance()->SetDirApl(baseDataDir, bundleName, apl, isPreInstall, debug, uid);
            if (result != ERR_OK) {
                LOG_W(BMS_TAG_DEFAULT, "bundleName: %{public}s, fail to SetDirApl baseDataDir dir, error is %{public}d",
                    bundleName.c_str(), result);
            }
            std::string databaseDataDir = baseBundleDataDir + ServiceConstants::DATABASE + bundleName;
            result = InstalldClient::GetInstance()->SetDirApl(
                databaseDataDir, bundleName, apl, isPreInstall, debug, uid);
            if (result != ERR_OK) {
                LOG_W(BMS_TAG_DEFAULT, "bundleName: %{public}s, fail to SetDirApl databaseDir dir, error is %{public}d",
                    bundleName.c_str(), result);
            }
        }
    }
    LOG_D(BMS_TAG_DEFAULT, "UpdateAppDataSelinuxLabel bundleName: %{public}s end", bundleName.c_str());
}

void BMSEventHandler::HandleSceneBoard() const
{
#ifdef WINDOW_ENABLE
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "dataMgr is null");
        return;
    }
    bool sceneBoardEnable = Rosen::SceneBoardJudgement::IsSceneBoardEnabled();
    LOG_I(BMS_TAG_DEFAULT, "HandleSceneBoard sceneBoardEnable : %{public}d", sceneBoardEnable);
    bool stateChanged = false;
    dataMgr->SetApplicationEnabled(ServiceConstants::SYSTEM_UI_BUNDLE_NAME, 0, !sceneBoardEnable,
        ServiceConstants::CALLER_NAME_BMS, Constants::DEFAULT_USERID, stateChanged);
    std::set<int32_t> userIds = dataMgr->GetAllUser();
    std::for_each(userIds.cbegin(), userIds.cend(), [dataMgr, sceneBoardEnable](const int32_t userId) {
        if (userId == 0) {
            return;
        }
        bool stateChanged = false;
        dataMgr->SetApplicationEnabled(Constants::SCENE_BOARD_BUNDLE_NAME, 0, sceneBoardEnable,
            ServiceConstants::CALLER_NAME_BMS, userId, stateChanged);
        dataMgr->SetApplicationEnabled(ServiceConstants::LAUNCHER_BUNDLE_NAME, 0, !sceneBoardEnable,
            ServiceConstants::CALLER_NAME_BMS, userId, stateChanged);
    });
#endif
}

void BMSEventHandler::InnerProcessStockBundleProvisionInfo()
{
    LOG_D(BMS_TAG_DEFAULT, "InnerProcessStockBundleProvisionInfo start");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }
    std::unordered_set<std::string> allBundleNames;
    if (!DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAllAppProvisionInfoBundleName(allBundleNames)) {
        LOG_W(BMS_TAG_DEFAULT, "GetAllAppProvisionInfoBundleName failed");
    }
    // get all installed bundleName
    std::vector<std::string> installedBundleNames = dataMgr->GetAllBundleName();
    //check diss missed
    for (const auto &bundleName : installedBundleNames) {
        if (allBundleNames.find(bundleName) == allBundleNames.end()) {
            InnerBundleInfo innerBundleInfo;
            if (!dataMgr->FetchInnerBundleInfo(bundleName, innerBundleInfo)) {
                LOG_W(BMS_TAG_DEFAULT, "fetch failed -n %{public}s", bundleName.c_str());
                continue;
            }
            auto moduleMap = innerBundleInfo.GetInnerModuleInfos();
            if (!moduleMap.empty()) {
                AddStockAppProvisionInfoByOTA(bundleName, moduleMap.begin()->second.hapPath);
            }
        }
    }
    LOG_D(BMS_TAG_DEFAULT, "InnerProcessStockBundleProvisionInfo end");
}

void BMSEventHandler::InnerProcessStockBundleRouterInfo()
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }
    std::set<std::string> bundleNames;
    dataMgr->GetAllBundleNames(bundleNames);
    std::vector<BundleInfo> bundleInfos;
    auto baseFlag = static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE) +
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE);
    if (dataMgr->GetBundleInfosV9(baseFlag, bundleInfos, Constants::ALL_USERID) != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "GetBundleInfos failed");
        return;
    }
    for (const auto &bundleInfo : bundleInfos) {
        bool hasRouter = false;
        for (const HapModuleInfo &hapModuleInfo : bundleInfo.hapModuleInfos) {
            if (!hapModuleInfo.routerMap.empty()) {
                hasRouter = true;
                break;
            }
        }
        if (hasRouter && (bundleNames.find(bundleInfo.name) == bundleNames.end())) {
            dataMgr->UpdateRouterInfo(bundleInfo.name);
        }
    }
}

void BMSEventHandler::ProcessRebootQuickFixBundleInstall(const std::string &path, bool isOta)
{
    LOG_I(BMS_TAG_DEFAULT, "start, isOta:%{public}d", isOta);
    std::string systemHspPath = path + ServiceConstants::PATH_SEPARATOR + MODULE_UPDATE_APP_SERVICE_DIR;
    std::string sharedBundlePath = path + SHARED_BUNDLE_PATH;
    std::string systemBundlePath = path + SYSTEM_BUNDLE_PATH;
    PatchSystemHspInstall(systemHspPath, isOta);
    PatchSharedHspInstall(sharedBundlePath);
    PatchSystemBundleInstall(systemBundlePath, isOta);
    LOG_I(BMS_TAG_DEFAULT, "end");
}

void BMSEventHandler::PatchSystemHspInstall(const std::string &path, bool isOta)
{
    LOG_I(BMS_TAG_DEFAULT, "start");
    std::list<std::string> bundleDirs;
    ProcessScanDir(path, bundleDirs);
    if (bundleDirs.empty()) {
        LOG_I(BMS_TAG_DEFAULT, "end, bundleDirs is empty");
        return;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }
    for (auto &scanPathIter : bundleDirs) {
        std::unordered_map<std::string, InnerBundleInfo> infos;
        if (!ParseHapFiles(scanPathIter, infos) || infos.empty()) {
            LOG_E(BMS_TAG_DEFAULT, "ParseHapFiles failed : %{public}s ", scanPathIter.c_str());
            continue;
        }
        auto bundleName = infos.begin()->second.GetBundleName();
        auto versionCode = infos.begin()->second.GetVersionCode();
        InnerBundleInfo hasInstalledInfo;
        auto hasBundleInstalled = dataMgr->FetchInnerBundleInfo(bundleName, hasInstalledInfo);
        if (!hasBundleInstalled) {
            LOG_W(BMS_TAG_DEFAULT, "bundleName %{public}s not exist", bundleName.c_str());
            continue;
        }
        if ((versionCode <= hasInstalledInfo.GetVersionCode()) && IsHspPathExist(hasInstalledInfo)) {
            LOG_W(BMS_TAG_DEFAULT, "bundleName: %{public}s downgrade",
                bundleName.c_str());
            continue;
        }
        InstallParam installParam;
        installParam.SetKillProcess(false);
        installParam.removable = false;
        installParam.needSendEvent = false;
        installParam.copyHapToInstallPath = true;
        installParam.needSavePreInstallInfo = false;
        installParam.isOTA = isOta;
        installParam.isPatch = true;
        AppServiceFwkInstaller installer;
        std::vector<std::string> filePaths { scanPathIter };
        if (installer.Install(filePaths, installParam) != ERR_OK) {
            LOG_W(BMS_TAG_DEFAULT, "bundleName: %{public}s: install failed", bundleName.c_str());
        }
    }
    LOG_I(BMS_TAG_DEFAULT, "end");
}

void BMSEventHandler::PatchSharedHspInstall(const std::string &path)
{
    LOG_I(BMS_TAG_DEFAULT, "start");
    std::list<std::string> bundleDirs;
    ProcessScanDir(path, bundleDirs);
    if (bundleDirs.empty()) {
        LOG_I(BMS_TAG_DEFAULT, "end, bundleDirs is empty");
        return;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }
    for (auto &scanPathIter : bundleDirs) {
        std::unordered_map<std::string, InnerBundleInfo> infos;
        if (!ParseHapFiles(scanPathIter, infos) || infos.empty()) {
            LOG_E(BMS_TAG_DEFAULT, "ParseHapFiles failed : %{public}s ", scanPathIter.c_str());
            continue;
        }
        auto bundleName = infos.begin()->second.GetBundleName();
        auto versionCode = infos.begin()->second.GetVersionCode();
        InnerBundleInfo hasInstalledInfo;
        auto hasBundleInstalled = dataMgr->FetchInnerBundleInfo(bundleName, hasInstalledInfo);
        if (!hasBundleInstalled) {
            LOG_W(BMS_TAG_DEFAULT, "bundleName %{public}s not exist", bundleName.c_str());
            continue;
        }
        if ((versionCode <= hasInstalledInfo.GetVersionCode()) && IsHspPathExist(hasInstalledInfo)) {
            LOG_W(BMS_TAG_DEFAULT, "bundleName: %{public}s downgrade",
                bundleName.c_str());
            continue;
        }
        InstallParam installParam;
        installParam.sharedBundleDirPaths = {scanPathIter};
        installParam.SetKillProcess(false);
        installParam.removable = false;
        installParam.needSendEvent = false;
        installParam.needSavePreInstallInfo = false;
        installParam.isPatch = true;
        SystemBundleInstaller installer;
        if (!installer.InstallSystemSharedBundle(installParam, true, Constants::AppType::SYSTEM_APP)) {
            LOG_W(BMS_TAG_DEFAULT, "patch shared bundle %{public}s failed", bundleName.c_str());
        }
    }
    LOG_I(BMS_TAG_DEFAULT, "end");
}

void BMSEventHandler::PatchSystemBundleInstall(const std::string &path, bool isOta)
{
    LOG_I(BMS_TAG_DEFAULT, "start");
    std::list<std::string> bundleDirs;
    ProcessScanDir(path, bundleDirs);
    if (bundleDirs.empty()) {
        LOG_I(BMS_TAG_DEFAULT, "end, bundleDirs is empty");
        return;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }
    std::unique_ptr<BundleInstallChecker> bundleInstallChecker =
        std::make_unique<BundleInstallChecker>();
    std::unordered_map<std::string, std::vector<std::string>> needInstallMap;
    std::unordered_map<std::string, std::vector<std::string>> needInstallOverlayMap;
    for (auto &scanPathIter : bundleDirs) {
        std::unordered_map<std::string, InnerBundleInfo> infos;
        if (!ParseHapFiles(scanPathIter, infos) || infos.empty()) {
            LOG_E(BMS_TAG_DEFAULT, "ParseHapFiles failed : %{public}s ", scanPathIter.c_str());
            continue;
        }
        auto bundleName = infos.begin()->second.GetBundleName();
        auto hapVersionCode = bundleInstallChecker->GetVersionCode(infos);
        BundleInfo hasInstalledInfo;
        auto hasBundleInstalled = dataMgr->GetBundleInfo(
            bundleName, static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE),
            hasInstalledInfo, Constants::ANY_USERID);
        if (!hasBundleInstalled) {
            LOG_W(BMS_TAG_DEFAULT, "obtain bundleInfo failed, bundleName :%{public}s not exist", bundleName.c_str());
            continue;
        }
        if ((hapVersionCode <= hasInstalledInfo.versionCode) && IsHapPathExist(hasInstalledInfo)) {
            LOG_W(BMS_TAG_DEFAULT, "bundleName: %{public}s: hapVersionCode is less than old hap versionCode",
                bundleName.c_str());
            continue;
        } else if (hapVersionCode <= hasInstalledInfo.versionCode) {
            EventReport::SendTriggerFallbackEvent(HighRiskOperationType::PATCH_INSTALL_MISSING_HAP, bundleName,
                Constants::ALL_USERID, std::vector<std::string>{});
        }
        if (infos.begin()->second.GetOverlayType() == OverlayType::OVERLAY_EXTERNAL_BUNDLE) {
            needInstallOverlayMap[bundleName].emplace_back(scanPathIter);
        } else {
            needInstallMap[bundleName].emplace_back(scanPathIter);
        }
    }
    if (!InnerMultiProcessBundleInstallForPatch(needInstallMap, isOta)) {
        LOG_E(BMS_TAG_DEFAULT, "multi patch needInstallMap install failed");
    }
    for (auto iter = needInstallOverlayMap.begin(); iter != needInstallOverlayMap.end(); ++iter) {
        (void)BMSEventHandler::InstallSystemBundleNeedCheckUserForPatch(
            BMSEventHandler::ObtainRealPath(iter->second), iter->first, isOta);
    }
    LOG_I(BMS_TAG_DEFAULT, "end");
}

bool BMSEventHandler::InstallSystemBundleNeedCheckUserForPatch(const std::vector<std::string> &filePaths,
    const std::string &bundleName, bool isOta)
{
    if (filePaths.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "File path is empty");
        return false;
    }
    int32_t timerId = -1;
    if (isOta) {
        timerId = XCollieHelper::SetOTATimer(OTA_PATCH_BUNDLE_TASK, OTA_TIMEOUT_SECONDS);
    }
    ScopeGuard cancelTimerIdGuard([timerId] {
        if (timerId != -1) {
            XCollieHelper::CancelTimer(timerId);
        }
    });
    InstallParam installParam;
    installParam.SetKillProcess(false);
    installParam.needSendEvent = false;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.copyHapToInstallPath = true;
    installParam.isOTA = isOta;
    installParam.withCopyHaps = true;
    installParam.isPatch = true;
    SystemBundleInstaller installer;
    if (installer.OTAInstallSystemBundleNeedCheckUser(
        filePaths, installParam, bundleName, Constants::AppType::SYSTEM_APP) != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "-n %{public}s patch bundle install failed", bundleName.c_str());
        return false;
    }
    return true;
}

bool BMSEventHandler::InnerMultiProcessBundleInstallForPatch(
    const std::unordered_map<std::string, std::vector<std::string>> &needInstallMap, bool isOta)
{
    if (needInstallMap.empty()) {
        LOG_I(BMS_TAG_DEFAULT, "no patch bundle need to update");
        return true;
    }
    auto bundleMgrService = DelayedSingleton<BundleMgrService>::GetInstance();
    if (bundleMgrService == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "bundleMgrService is nullptr");
        return false;
    }

    sptr<BundleInstallerHost> installerHost = bundleMgrService->GetBundleInstaller();
    if (installerHost == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "installerHost is nullptr");
        return false;
    }

    size_t taskTotalNum = needInstallMap.size();
    size_t threadsNum = static_cast<size_t>(installerHost->GetThreadsNum());
    LOG_I(BMS_TAG_DEFAULT, "multi patch bundle install start, totalNum: %{public}zu, num: %{public}zu",
        taskTotalNum, threadsNum);
    std::atomic_uint taskEndNum = 0;
    std::shared_ptr<BundlePromise> bundlePromise = std::make_shared<BundlePromise>();
    for (auto iter = needInstallMap.begin(); iter != needInstallMap.end(); ++iter) {
        std::string bundleName = iter->first;
        std::vector<std::string> filePaths = iter->second;
        std::vector<std::string> realHapPaths = BMSEventHandler::ObtainRealPath(iter->second);
        auto task = [bundleName, realHapPaths, taskTotalNum, &taskEndNum, &bundlePromise, isOta]() {
            (void)BMSEventHandler::InstallSystemBundleNeedCheckUserForPatch(realHapPaths, bundleName, isOta);
            taskEndNum++;
            if (bundlePromise && taskEndNum >= taskTotalNum) {
                bundlePromise->NotifyAllTasksExecuteFinished();
                LOG_I(BMS_TAG_DEFAULT, "All tasks has executed and notify promise when patch install");
            }
            g_taskCounter--;
        };

        installerHost->AddTask(task, "RebootStartPatchBundleInstall : " + bundleName);
    }

    if (taskEndNum < taskTotalNum) {
        bundlePromise->WaitForAllTasksExecute();
        LOG_I(BMS_TAG_DEFAULT, "Wait for all tasks execute when patch install");
    }
    LOG_I(BMS_TAG_DEFAULT, "multi patch bundle install end");
    return true;
}

bool BMSEventHandler::IsHapPathExist(const BundleInfo &bundleInfo)
{
    LOG_I(BMS_TAG_DEFAULT, "-n %{public}s need to check hap path exist", bundleInfo.name.c_str());
    if (bundleInfo.hapModuleInfos.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "-n %{public}s has no moduleInfo", bundleInfo.name.c_str());
        return false;
    }
    for (const auto &moduleInfo : bundleInfo.hapModuleInfos) {
        if ((moduleInfo.hapPath.find(Constants::BUNDLE_CODE_DIR) == 0) &&
            !BundleUtil::IsExistFile(moduleInfo.hapPath)) {
            LOG_E(BMS_TAG_DEFAULT, "-p %{public}s hap path not exist", moduleInfo.hapPath.c_str());
            return false;
        }
    }
    return true;
}

bool BMSEventHandler::IsHspPathExist(const InnerBundleInfo &innerBundleInfo)
{
    LOG_I(BMS_TAG_DEFAULT, "-n %{public}s need to check hsp path exist", innerBundleInfo.GetBundleName().c_str());
    if (innerBundleInfo.GetInnerModuleInfos().empty()) {
        LOG_E(BMS_TAG_DEFAULT, "-n %{public}s has no moduleInfo", innerBundleInfo.GetBundleName().c_str());
        return false;
    }
    for (const auto &moduleInfoIter : innerBundleInfo.GetInnerModuleInfos()) {
        if ((moduleInfoIter.second.hapPath.find(Constants::BUNDLE_CODE_DIR) == 0) &&
            !BundleUtil::IsExistFile(moduleInfoIter.second.hapPath)) {
            LOG_E(BMS_TAG_DEFAULT, "-p %{public}s hsp path not exist", moduleInfoIter.second.hapPath.c_str());
            return false;
        }
    }
    return true;
}

bool BMSEventHandler::IsPathExistInInstalledBundleInfo(
    const std::string &path, const BundleInfo &bundleInfo)
{
    for (const auto &hapModuleInfo : bundleInfo.hapModuleInfos) {
        if ((hapModuleInfo.hapPath == path) || (hapModuleInfo.hapPath.find(Constants::BUNDLE_CODE_DIR) == 0)) {
            return true;
        }
    }
    LOG_W(BMS_TAG_DEFAULT, "-n %{public}s path is not exist in bundleInfo, need reinstall", bundleInfo.name.c_str());
    return false;
}

void BMSEventHandler::CheckALLResourceInfo()
{
    LOG_I(BMS_TAG_DEFAULT, "start");
    BundleResourceHelper::ProcessBundleResourceChange();
    std::thread ProcessBundleResourceThread(ProcessBundleResourceInfo);
    ProcessBundleResourceThread.detach();
}

void BMSEventHandler::ProcessBundleResourceInfo()
{
    LOG_I(BMS_TAG_DEFAULT, "ProcessBundleResourceInfo start");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "dataMgr is nullptr");
        return;
    }
    if (dataMgr->IsBopdModeEnabled()) {
        LOG_I(BMS_TAG_DEFAULT, "not process bundle resource info due to bopd mode enabled");
        return;
    }
    std::vector<std::string> bundleNames = dataMgr->GetAllBundleName();
    if (bundleNames.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "bundleNames is empty");
        return;
    }
    std::vector<std::string> resourceNames;
    BundleResourceHelper::GetAllBundleResourceName(resourceNames);

    std::set<std::string> needAddResourceBundles;
    for (const auto &bundleName : bundleNames) {
        if (std::find(resourceNames.begin(), resourceNames.end(), bundleName) == resourceNames.end()) {
            needAddResourceBundles.insert(bundleName);
        }
    }
    if (needAddResourceBundles.empty()) {
        LOG_I(BMS_TAG_DEFAULT, "needAddResourceBundles is empty, no need to add resource");
        return;
    }

    for (const auto &bundleName : needAddResourceBundles) {
        LOG_NOFUNC_I(BMS_TAG_DEFAULT, "-n %{public}s add resource when reboot", bundleName.c_str());
        std::set<int32_t> userIds;
        if (!dataMgr->GetInnerBundleInfoUsers(bundleName, userIds) || userIds.empty()) {
            LOG_W(BMS_TAG_DEFAULT, "-n %{public}s has no installed user, skip", bundleName.c_str());
            continue;
        }
        for (const auto &userId : userIds) {
            BundleResourceHelper::AddResourceInfoByBundleName(bundleName, userId,
                ADD_RESOURCE_TYPE::INSTALL_BUNDLE);
            std::vector<int32_t> appIndexes = dataMgr->GetCloneAppIndexes(bundleName, userId);
            for (const auto &appIndex : appIndexes) {
                BundleResourceHelper::AddCloneBundleResourceInfo(bundleName, userId, appIndex, false);
            }
        }
    }
    LOG_I(BMS_TAG_DEFAULT, "ProcessBundleResourceInfo end");
}

void BMSEventHandler::ProcessAllBundleDataGroupInfo()
{
    LOG_I(BMS_TAG_DEFAULT, "start");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "dataMgr is nullptr");
        return;
    }
    dataMgr->ScanAllBundleGroupInfo();
    LOG_I(BMS_TAG_DEFAULT, "end");
}

void BMSEventHandler::SendBundleUpdateFailedEvent(const BundleInfo &bundleInfo)
{
    SendBundleUpdateFailedEvent(bundleInfo, ERR_APPEXECFWK_OTA_INSTALL_VERSION_DOWNGRADE);
}

void BMSEventHandler::SendBundleUpdateFailedEvent(const BundleInfo &bundleInfo, const int32_t errorCode)
{
    LOG_I(BMS_TAG_DEFAULT, "SendBundleUpdateFailedEvent start, bundleName:%{public}s", bundleInfo.name.c_str());
    EventInfo eventInfo;
    eventInfo.userId = Constants::ANY_USERID;
    eventInfo.bundleName = bundleInfo.name;
    eventInfo.versionCode = bundleInfo.versionCode;
    eventInfo.errCode = errorCode;
    eventInfo.isPreInstallApp = bundleInfo.isPreInstallApp;
    eventInfo.callingUid = IPCSkeleton::GetCallingUid();
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr != nullptr) {
        dataMgr->GetOdidByBundleName(bundleInfo.name, eventInfo.odid);
    }
    EventReport::SendBundleSystemEvent(BundleEventType::UPDATE, eventInfo);
}

void BMSEventHandler::UpdatePreinstallDB(
    const std::unordered_map<std::string, std::pair<std::vector<std::string>, bool>> &needInstallMap)
{
    for (const auto &existInfo : loadExistData_) {
        std::string bundleName = existInfo.first;
        auto it = needInstallMap.find(bundleName);
        if (it != needInstallMap.end()) {
            LOG_NOFUNC_I(BMS_TAG_COMMON, "%{public}s installed already update", bundleName.c_str());
            continue;
        }
        auto hapParseInfoMapIter = hapParseInfoMap_.find(bundleName);
        if (hapParseInfoMapIter == hapParseInfoMap_.end()) {
            LOG_NOFUNC_I(BMS_TAG_COMMON, "%{public}s not preinstalled", bundleName.c_str());
            continue;
        }
        UpdatePreinstallDBForNotUpdatedBundle(bundleName, hapParseInfoMapIter->second);
    }
}

void BMSEventHandler::UpdatePreinstallDBForNotUpdatedBundle(const std::string &bundleName,
    const std::unordered_map<std::string, InnerBundleInfo> &innerBundleInfos)
{
    if (innerBundleInfos.empty()) {
        LOG_W(BMS_TAG_DEFAULT, "innerBundleInfos is empty");
        return;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_W(BMS_TAG_DEFAULT, "dataMgr is nullptr");
        return;
    }
    PreInstallBundleInfo preInstallBundleInfo;
    if (!dataMgr->GetPreInstallBundleInfo(bundleName, preInstallBundleInfo)) {
        LOG_W(BMS_TAG_DEFAULT, "get preinstalled bundle info failed :%{public}s", bundleName.c_str());
        return;
    }
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "begin update preinstall DB for %{public}s", bundleName.c_str());
    preInstallBundleInfo.ClearBundlePath();
    bool findEntry = false;
    for (const auto &item : innerBundleInfos) {
        preInstallBundleInfo.AddBundlePath(item.first);
        if (!findEntry) {
            auto applicationInfo = item.second.GetBaseApplicationInfo();
            item.second.AdaptMainLauncherResourceInfo(applicationInfo, true);
            preInstallBundleInfo.SetLabelId(applicationInfo.labelResource.id);
            preInstallBundleInfo.SetIconId(applicationInfo.iconResource.id);
            preInstallBundleInfo.SetDescriptionId(applicationInfo.descriptionId);
            preInstallBundleInfo.SetModuleName(applicationInfo.labelResource.moduleName);
            preInstallBundleInfo.SetVersionCode(applicationInfo.versionCode);
        }
        auto innerModuleInfos = item.second.GetInnerModuleInfos();
        if (!innerModuleInfos.empty() &&
            innerModuleInfos.begin()->second.distro.moduleType == Profile::MODULE_TYPE_ENTRY) {
            findEntry = true;
        }
    }
    if (!dataMgr->SavePreInstallBundleInfo(bundleName, preInstallBundleInfo)) {
        LOG_NOFUNC_I(BMS_TAG_DEFAULT, "update preinstall DB fail -n %{public}s", bundleName.c_str());
    }
}

bool BMSEventHandler::IsQuickfixPatchApp(const std::string &bundleName, uint32_t versionCode)
{
    // 1. check whether a patch has been installed on the app
    InnerPatchInfo innerPatchInfo;
    if (!PatchDataMgr::GetInstance().GetInnerPatchInfo(bundleName, innerPatchInfo)) {
        LOG_D(BMS_TAG_DEFAULT, "app is not patch -n %{public}s", bundleName.c_str());
        return false;
    }
    // 2. check appType, current only Internal app types can be uninstall
    if (innerPatchInfo.GetAppPatchType() != AppPatchType::INTERNAL) {
        LOG_NOFUNC_W(BMS_TAG_DEFAULT, "-n %{public}s app patch type err", bundleName.c_str());
        return false;
    }
    // 3. check version
    if (innerPatchInfo.GetVersionCode() != versionCode) {
        LOG_NOFUNC_W(BMS_TAG_DEFAULT, "-n %{public}s is not patch app patchVersion %{public}u version %{public}u",
            bundleName.c_str(), innerPatchInfo.GetVersionCode(), versionCode);
        return false;
    }
    LOG_NOFUNC_W(BMS_TAG_DEFAULT, "-n %{public}s is patch app", bundleName.c_str());
    return true;
}

bool BMSEventHandler::GetValueFromJson(nlohmann::json &jsonObject)
{
    bundleNameList_.clear();
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::vector<std::string>>(jsonObject,
        jsonObjectEnd,
        RESTOR_BUNDLE_NAME_LIST,
        bundleNameList_,
        JsonType::ARRAY,
        false,
        parseResult,
        ArrayType::STRING);
    if (parseResult != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "read bundleNameList from json file error, error code : %{public}d", parseResult);
        return false;
    }
    return true;
}

void BMSEventHandler::ProcessRebootQuickFixUnInstallAndRecover(const std::string &path)
{
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "ProcessRebootQuickFixUnInstallAndRecover start");
    if (!BundleUtil::IsExistFile(QUICK_FIX_APP_RECOVER_FILE)) {
        LOG_E(BMS_TAG_DEFAULT, "end, reinstall json file is empty");
        return;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "dataMgr is nullptr");
        return;
    }
    sptr<InnerReceiverImpl> innerReceiverImpl(new (std::nothrow) InnerReceiverImpl());
    if (innerReceiverImpl == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "innerReceiverImpl is nullptr");
        return;
    }
    auto installer = std::make_shared<BundleInstaller>(GetMicroTickCount(), innerReceiverImpl);
    nlohmann::json jsonObject;
    if (!BundleParser::ReadFileIntoJson(QUICK_FIX_APP_RECOVER_FILE, jsonObject) || !jsonObject.is_object() ||
        !GetValueFromJson(jsonObject)) {
        LOG_E(BMS_TAG_DEFAULT, "get jsonObject from path failed or get value failed");
        return;
    }
    for (const std::string &bundleName : bundleNameList_) {
        BundleInfo hasInstalledInfo;
        auto hasBundleInstalled = dataMgr->GetBundleInfo(bundleName,
            static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE),
            hasInstalledInfo, Constants::ANY_USERID);
        if (!hasBundleInstalled) {
            LOG_W(BMS_TAG_DEFAULT, "obtain bundleInfo failed, bundleName :%{public}s not exist", bundleName.c_str());
            continue;
        }
        if (IsQuickfixPatchApp(hasInstalledInfo.name, hasInstalledInfo.versionCode)) {
            // If metadata name has quickfix flag, it should be uninstall and recover.
            InstallParam installParam;
            installParam.SetIsUninstallAndRecover(true);
            installParam.SetKillProcess(false);
            installParam.needSendEvent = false;
            installParam.isKeepData = true;
            installer->UninstallAndRecover(bundleName, installParam);
        }
    }
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "ProcessRebootQuickFixUnInstallAndRecover end");
}

void BMSEventHandler::InnerProcessRebootUninstallWrongBundle()
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "dataMgr is null");
        return;
    }
    for (const auto &bundleName : ServiceConstants::SINGLETON_WHITE_LIST) {
        InnerBundleInfo bundleInfo;
        if (!dataMgr->FetchInnerBundleInfo(bundleName, bundleInfo)) {
            LOG_W(BMS_TAG_DEFAULT, "-n %{public}s is not exist", bundleName.c_str());
            continue;
        }
        InnerCheckSingletonBundleUserInfo(bundleInfo);
    }
}

bool BMSEventHandler::InnerCheckSingletonBundleUserInfo(const InnerBundleInfo &bundleInfo)
{
    const auto bundleUserInfos = bundleInfo.GetInnerBundleUserInfos();
    if (bundleUserInfos.size() <= 1) {
        return true;
    }
    std::set<int32_t> userIds;
    for (const auto &item : bundleUserInfos) {
        userIds.insert(item.second.bundleUserInfo.userId);
    }
    if (userIds.find(Constants::DEFAULT_USERID) == userIds.end()) {
        return true;
    }
    const std::string bundleName = bundleInfo.GetBundleName();
    LOG_I(BMS_TAG_DEFAULT, "-n %{public}s is exist different user info", bundleName.c_str());
    InstallParam installParam;
    installParam.userId = Constants::DEFAULT_USERID;
    installParam.SetKillProcess(false);
    installParam.needSendEvent = false;
    if (!bundleInfo.IsSingleton()) {
        LOG_I(BMS_TAG_DEFAULT, "-n %{public}s delete 0 userInfo", bundleName.c_str());
        SystemBundleInstaller installer;
        if (!installer.UninstallSystemBundle(bundleName, installParam)) {
            LOG_W(BMS_TAG_DEFAULT, "OTA uninstall bundle %{public}s userId %{public}d error", bundleName.c_str(),
                installParam.userId);
            return false;
        }
        return true;
    }
    for (const auto &userId : userIds) {
        if (userId == Constants::DEFAULT_USERID) {
            continue;
        }
        LOG_I(BMS_TAG_DEFAULT, "-n %{public}s delete %{public}d userInfo", bundleName.c_str(), userId);
        installParam.userId = userId;
        SystemBundleInstaller installer;
        if (!installer.UninstallSystemBundle(bundleName, installParam)) {
            LOG_W(BMS_TAG_DEFAULT, "OTA uninstall bundle %{public}s userId %{public}d error", bundleName.c_str(),
                installParam.userId);
            return false;
        }
    }
    return true;
}

void BMSEventHandler::ProcessCheckAppEl1Dir()
{
    LOG_I(BMS_TAG_DEFAULT, "start");
    std::thread thread(ProcessCheckAppEl1DirTask);
    thread.detach();
}

void BMSEventHandler::ProcessCheckAppEl1DirTask()
{
    LOG_I(BMS_TAG_DEFAULT, "begin");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }

    std::set<int32_t> userIds = dataMgr->GetAllUser();
    for (const auto &userId : userIds) {
        std::vector<BundleInfo> bundleInfos;
        if (!dataMgr->GetBundleInfos(static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE),
            bundleInfos, userId)) {
            LOG_W(BMS_TAG_DEFAULT, "GetBundleInfos failed");
            continue;
        }

        UpdateAppDataMgr::ProcessUpdateAppDataDir(userId, bundleInfos, ServiceConstants::DIR_EL1);
    }
    LOG_I(BMS_TAG_DEFAULT, "end");
}

void BMSEventHandler::ProcessMigrateSkillDir()
{
    bool isMigrated = false;
    CheckOtaFlag(OTAFlag::MIGRATE_SKILL_DIR, isMigrated);
    if (isMigrated) {
        LOG_D(BMS_TAG_DEFAULT, "skill dir has been migrated");
        return;
    }
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "migrate skill dir begin");
    CheckAppSkillDir();
    ErrCode ret = InstalldClient::GetInstance()->RemoveDir(
        ServiceConstants::LEGACY_SKILL_BASE_DIR, BundleDirScene::REMOVE_LEGACY_SKILL_DIR);
    if (ret != ERR_OK) {
        LOG_NOFUNC_E(BMS_TAG_DEFAULT, "delete legacy skill dir failed %{public}d", ret);
    }
    UpdateOtaFlag(OTAFlag::MIGRATE_SKILL_DIR);
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "migrate skill dir end");
}

void BMSEventHandler::ExtractAppSkills(const std::shared_ptr<BundleDataMgr> dataMgr, const std::string &bundleName)
{
    InnerBundleInfo info;
    if (!dataMgr->FetchInnerBundleInfo(bundleName, info)) {
        return;
    }
    for (const auto &item : info.GetInnerModuleInfos()) {
        const InnerModuleInfo &moduleInfo = item.second;
        if (moduleInfo.skillProfiles.empty()) {
            continue;
        }
        std::vector<std::string> skillNames;
        for (const auto &profile : moduleInfo.skillProfiles) {
            skillNames.emplace_back(profile.name);
        }
        std::vector<SkillsPackageInfo> skillInfos;
        ErrCode ret = SkillsInstallerUtil::ExtractSkillsPackage(bundleName, moduleInfo.moduleName,
            moduleInfo.moduleName, moduleInfo.hapPath, skillNames, skillInfos);
        if (ret == ERR_OK && skillInfos.size() != skillNames.size()) {
            LOG_NOFUNC_W(BMS_TAG_DEFAULT, "-n %{public}s -m %{public}s extract %{public}zu of %{public}zu skills",
                bundleName.c_str(), moduleInfo.moduleName.c_str(), skillInfos.size(), skillNames.size());
        }
    }
}

void BMSEventHandler::ProcessCheckAppSkillDir()
{
    std::thread checkThread(CheckAppSkillDir);
    checkThread.detach();
}

void BMSEventHandler::CheckAppSkillDir()
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_NOFUNC_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }
    for (const auto &bundleName : dataMgr->GetAppSkillBundleNames()) {
        if (!BundleUtil::IsExistDirNoLog(
            std::string(Constants::BASE_SKILL_DIR) + ServiceConstants::PATH_SEPARATOR + bundleName)) {
            ExtractAppSkills(dataMgr, bundleName);
        }
    }
}

void BMSEventHandler::CheckAndCreateShareFilesSubDataDirs()
{
    LOG_D(BMS_TAG_DEFAULT, "begin");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_W(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }

    std::set<int32_t> userIds = dataMgr->GetAllUser();
    for (const auto &userId : userIds) {
        std::vector<BundleInfo> bundleInfos;
        if (dataMgr->GetBundleInfosV9(static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE),
            bundleInfos, userId) != ERR_OK) {
            LOG_W(BMS_TAG_DEFAULT, "failed to GetBundleInfos for: [%{public}d]",
                userId);
            continue;
        }
        std::string shareFilesDir = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR + ServiceConstants::BUNDLE_EL[1] +
            ServiceConstants::PATH_SEPARATOR + std::to_string(userId) + ServiceConstants::SHAREFILES;
        bool isExist = true;
        ErrCode result = InstalldClient::GetInstance()->IsExistDir(shareFilesDir, isExist);
        if (result != ERR_OK || !isExist) {
            LOG_W(BMS_TAG_DEFAULT, "sharefile dir no exist: %{public}s",
                shareFilesDir.c_str());
            continue;
        }
        UpdateAppDataMgr::CreateShareFilesSubDataDirs(bundleInfos, userId);
    }
    LOG_D(BMS_TAG_DEFAULT, "end");
}

bool BMSEventHandler::InnerProcessUninstallForExistPreBundle(const BundleInfo &installedInfo)
{
    if (installedInfo.hapModuleInfos.empty()) {
        LOG_W(BMS_TAG_DEFAULT, "app(%{public}s) moduleInfos empty", installedInfo.name.c_str());
        return false;
    }
    bool isUpdated = std::all_of(installedInfo.hapModuleInfos.begin(), installedInfo.hapModuleInfos.end(),
        [] (const HapModuleInfo &moduleInfo) {
            return moduleInfo.hapPath.find(Constants::BUNDLE_CODE_DIR) == 0;
        });
    if (isUpdated) {
        LOG_I(BMS_TAG_DEFAULT, "no need to uninstall app(%{public}s) due to update", installedInfo.name.c_str());
        std::string moduleName;
        DeletePreInfoInDb(installedInfo.name, moduleName, true);
        if (installedInfo.isPreInstallApp) {
            // need update isPreInstallApp false
            auto dataMgr = GetDataMgrFromService();
            if (dataMgr == nullptr) {
                LOG_W(BMS_TAG_DEFAULT, "DataMgr is nullptr, -n %{public}s need change isPreInstallApp",
                    installedInfo.name.c_str());
                return isUpdated;
            }
            dataMgr->UpdateIsPreInstallApp(installedInfo.name, false);
        }
    }
    return isUpdated;
}

void BMSEventHandler::ProcessAppTmpPath()
{
    if (BundleUtil::IsExistDirNoLog(ServiceConstants::BMS_APP_COPY_TEMP_PATH)) {
        if (!BundleUtil::DeleteDir(ServiceConstants::BMS_APP_COPY_TEMP_PATH)) {
            LOG_E(BMS_TAG_INSTALLER, "delete app_copy_temp failed %{public}d", errno);
        }
        return;
    }
    if (!BundleUtil::IsExistDirNoLog(ServiceConstants::BMS_APP_TEMP_PATH)) {
        return;
    }
    EventReport::SendTriggerFallbackEvent(HighRiskOperationType::PROCESS_APP_GALLERY_TMP_PATH, Constants::EMPTY_STRING,
        Constants::ALL_USERID, std::vector<std::string>{});
    LOG_I(BMS_TAG_DEFAULT, "process app_temp start");
    InstallParam installParam;
    installParam.SetKillProcess(false);
    installParam.needSendEvent = false;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.copyHapToInstallPath = true;
    installParam.isOTA = false;
    installParam.withCopyHaps = true;
    installParam.isPatch = false;
    SystemBundleInstaller installer;
    std::vector<std::string> filePaths { ServiceConstants::BMS_APP_TEMP_PATH };
    if (installer.OTAInstallSystemBundle(filePaths, installParam, Constants::AppType::SYSTEM_APP) != ERR_OK) {
        LOG_W(BMS_TAG_DEFAULT, "app_temp path install failed");
        return;
    }
    if (!BundleUtil::DeleteDir(ServiceConstants::BMS_APP_TEMP_PATH)) {
        LOG_E(BMS_TAG_INSTALLER, "delete app_temp failed %{public}d", errno);
    }
    LOG_I(BMS_TAG_DEFAULT, "process app_temp end");
}

void BMSEventHandler::CleanTempDir() const
{
    BundleUtil::RestoreAppInstallHaps();
    std::vector<std::string> dirs = {
        std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR +
            ServiceConstants::STREAM_INSTALL_PATH,
        std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR +
            ServiceConstants::SECURITY_STREAM_INSTALL_PATH,
        std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR +
            ServiceConstants::SIGNATURE_FILE_PATH,
        std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR +
            PGO_FILE_PATH,
    };

    for (const auto& dir : dirs) {
        if (OHOS::IsEmptyFolder(dir)) {
            continue;
        }
        LOG_I(BMS_TAG_DEFAULT, "clean %{public}s", dir.c_str());
        if (!OHOS::ForceRemoveDirectoryBMS(dir)) {
            LOG_E(BMS_TAG_DEFAULT, "remove failed: %{public}s", dir.c_str());
            continue;
        }
        if (!BundleUtil::CreateTempDir(dir).empty()) {
            LOG_E(BMS_TAG_DEFAULT, "create failed: %{public}s", dir.c_str());
        }
    }

    UpdateAppDataMgr::DeleteUninstallTmpDirs(std::set<int32_t>{Constants::DEFAULT_USERID, Constants::U1});
}

void BMSEventHandler::CheckBundleProvisionInfo()
{
    LOG_I(BMS_TAG_DEFAULT, "start");
    std::thread ProcessBundleProvisionInfoThread(InnerProcessStockBundleProvisionInfo);
    ProcessBundleProvisionInfoThread.detach();
}

bool BMSEventHandler::SaveBmsSystemTimeForShortcut()
{
    auto bmsPara = DelayedSingleton<BundleMgrService>::GetInstance()->GetBmsParam();
    if (bmsPara == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "bmsPara is nullptr");
        return false;
    }
    std::string val;
    if (bmsPara->GetBmsParam(ServiceConstants::BMS_SYSTEM_TIME_FOR_SHORTCUT, val)) {
        return true;
    }

    int64_t systemTime = BundleUtil::GetCurrentTimeMs();
    if (!bmsPara->SaveBmsParam(ServiceConstants::BMS_SYSTEM_TIME_FOR_SHORTCUT, std::to_string(systemTime))) {
        LOG_E(BMS_TAG_DEFAULT, "save BMS_SYSTEM_TIME_FOR_SHORTCUT failed");
        return false;
    }
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "save BMS_SYSTEM_TIME_FOR_SHORTCUT succeed");
    return true;
}

void BMSEventHandler::InnerProcessAllDynamicIconInfoWhenOta()
{
    bool checkDynamicIcon = false;
    CheckOtaFlag(OTAFlag::PROCESS_DYNAMIC_ICON, checkDynamicIcon);
    if (checkDynamicIcon) {
        LOG_I(BMS_TAG_DEFAULT, "Not need to process dynamic due to has checked");
        return;
    }
    LOG_I(BMS_TAG_DEFAULT, "Need to process dynamic");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }
    dataMgr->ProcessDynamicIconForOta();
    UpdateOtaFlag(OTAFlag::PROCESS_DYNAMIC_ICON);
}

void BMSEventHandler::InnerProcessAllThemeAndDynamicIconInfoWhenOta(
    const std::unordered_map<std::string, std::pair<std::vector<std::string>, bool>> &needInstallMap)
{
    // process dynamic info
    InnerProcessAllDynamicIconInfoWhenOta();
    // process theme and dynamic icon
    bool checkThemeDynamicIcon = false;
    CheckOtaFlag(OTAFlag::PROCESS_THEME_AND_DYNAMIC_ICON, checkThemeDynamicIcon);
    if (checkThemeDynamicIcon) {
        LOG_I(BMS_TAG_DEFAULT, "No need to process theme and dynamic due to has checked");
        return;
    }
    LOG_I(BMS_TAG_DEFAULT, "process theme and dynamic start");
    std::set<std::string> bundleNames;
    for (const auto &item : needInstallMap) {
        bundleNames.insert(item.first);
    }
    if (!BundleResourceHelper::ProcessThemeAndDynamicIconWhenOta(bundleNames)) {
        LOG_E(BMS_TAG_DEFAULT, "process theme and dynamic failed");
        return;
    }
    UpdateOtaFlag(OTAFlag::PROCESS_THEME_AND_DYNAMIC_ICON);
    LOG_I(BMS_TAG_DEFAULT, "process theme and dynamic end");
}

void BMSEventHandler::InnerProcessBootCheckOnDemandBundle()
{
    for (const auto &preScanInfo : onDemandInstallList_) {
        std::vector<Security::Verify::HapVerifyResult> hapVerifyResults;
        std::unordered_map<std::string, InnerBundleInfo> infos;
        if (!ParseOnDemandHapFiles(preScanInfo.bundleDir, hapVerifyResults, infos)) {
            continue;
        }
        if (preScanInfo.isDataPreloadHap) {
            if (preScanInfo.appIdentifier != hapVerifyResults[0].GetProvisionInfo().bundleInfo.appIdentifier) {
                LOG_W(BMS_TAG_DEFAULT, "appIdentifier is different");
                continue;
            }
        }
        PreInstallBundleInfo preInstallBundleInfo;
        ConvertToOnDemandInstallBundleInfo(infos, preInstallBundleInfo);
        bool result = OnDemandInstallDataMgr::GetInstance().SaveOnDemandInstallBundleInfo(
            infos.begin()->second.GetBundleName(), preInstallBundleInfo);
        if (!result) {
            LOG_W(BMS_TAG_DEFAULT, "save onDemand bundle fail -n %{public}s",
                infos.begin()->second.GetBundleName().c_str());
        }
    }
}

void BMSEventHandler::ProcessRebootCheckOnDemandBundle()
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }
    OnDemandInstallDataMgr::GetInstance().DeleteNoDataPreloadBundleInfos();
    for (const auto &preScanInfo : onDemandInstallList_) {
        std::vector<Security::Verify::HapVerifyResult> hapVerifyResults;
        std::unordered_map<std::string, InnerBundleInfo> infos;
        if (!ParseOnDemandHapFiles(preScanInfo.bundleDir, hapVerifyResults, infos)) {
            continue;
        }
        if (preScanInfo.isDataPreloadHap) {
            LOG_W(BMS_TAG_DEFAULT, "data preload app is not support OTA");
            continue;
        }
        PreInstallBundleInfo preInstallBundleInfo;
        auto hasPreInstalled = dataMgr->GetPreInstallBundleInfo(infos.begin()->second.GetBundleName(),
            preInstallBundleInfo);
        if (hasPreInstalled) {
            installList_.insert(preScanInfo);
            continue;
        }
        ConvertToOnDemandInstallBundleInfo(infos, preInstallBundleInfo);
        bool result = OnDemandInstallDataMgr::GetInstance().SaveOnDemandInstallBundleInfo(
            infos.begin()->second.GetBundleName(), preInstallBundleInfo);
        if (!result) {
            LOG_W(BMS_TAG_DEFAULT, "save onDemand bundle:%{public}s fail",
                infos.begin()->second.GetBundleName().c_str());
        }
    }
}

bool BMSEventHandler::ParseOnDemandHapFiles(const std::string &hapFilePath,
    std::vector<Security::Verify::HapVerifyResult> &hapVerifyResults,
    std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    std::unique_ptr<BundleInstallChecker> bundleInstallChecker =
        std::make_unique<BundleInstallChecker>();

    std::vector<std::string> hapFilePathVec { hapFilePath };
    std::vector<std::string> realPaths;
    auto ret = BundleUtil::CheckFilePath(hapFilePathVec, realPaths);
    if (ret != ERR_OK) {
        LOG_W(BMS_TAG_DEFAULT, "File path %{public}s invalid", hapFilePath.c_str());
        return false;
    }
    ret = bundleInstallChecker->CheckMultipleHapsSignInfo(realPaths, hapVerifyResults);
    if (ret != ERR_OK || hapVerifyResults.empty()) {
        LOG_W(BMS_TAG_DEFAULT, "check signInfo failed");
        return false;
    }
    InstallCheckParam checkParam;
    checkParam.isPreInstallApp = true;
    checkParam.appType = Constants::AppType::THIRD_PARTY_APP;
    ret = bundleInstallChecker->ParseHapFiles(
        realPaths, checkParam, hapVerifyResults, infos);
    if (ret != ERR_OK || infos.empty()) {
        LOG_W(BMS_TAG_DEFAULT, "parse haps file failed");
        return false;
    }
    if (bundleInstallChecker->CheckAppLabelInfo(infos) != ERR_OK) {
        LOG_W(BMS_TAG_DEFAULT, "check app label info failed");
        return false;
    }
    return true;
}

void BMSEventHandler::ConvertToOnDemandInstallBundleInfo(const std::unordered_map<std::string, InnerBundleInfo> &infos,
    PreInstallBundleInfo &preInstallBundleInfo)
{
    std::unique_ptr<BundleInstallChecker> bundleInstallChecker =
        std::make_unique<BundleInstallChecker>();
    const InnerBundleInfo &innerBundleInfo = infos.begin()->second;
    preInstallBundleInfo.SetBundleName(innerBundleInfo.GetBundleName());
    preInstallBundleInfo.SetAppType(innerBundleInfo.GetAppType());
    preInstallBundleInfo.SetVersionCode(bundleInstallChecker->GetVersionCode(infos));
    for (const auto &item : infos) {
        preInstallBundleInfo.AddBundlePath(item.first);
    }
    preInstallBundleInfo.SetRemovable(true);
    preInstallBundleInfo.SetIsUninstalled(false);
    FillPreInstallResourceInfo(infos, preInstallBundleInfo);
}

void BMSEventHandler::CreateUninstalledPreloadDir()
{
    std::string path = std::string(ServiceConstants::BUNDLE_MANAGER_SERVICE_PATH) +
        ServiceConstants::UNINSTALLED_PRELOAD_PATH;
    if (!BundleUtil::CreateDir(path)) {
        LOG_E(BMS_TAG_DEFAULT, "create uninstalled preload dir failed");
    }
}

void BMSEventHandler::RemoveUninstalledPreloadFile()
{
    std::string path = std::string(ServiceConstants::BUNDLE_MANAGER_SERVICE_PATH) +
        ServiceConstants::UNINSTALLED_PRELOAD_PATH + ServiceConstants::UNINSTALLED_PRELOAD_FILE;
    if (!BundleUtil::DeleteDir(path)) {
        LOG_E(BMS_TAG_DEFAULT, "remove uninstalled preload file %{public}d failed", errno);
    }
}

void BMSEventHandler::ProcessUpdatePermissions()
{
    LOG_I(BMS_TAG_DEFAULT, "update permissions begin");
    if (IsPermissionsUpdated()) {
        LOG_I(BMS_TAG_DEFAULT, "permissions already updated");
        return;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }
    bool updatePermissionsFlag = true;
    std::map<std::string, InnerBundleInfo> infos = dataMgr->GetAllInnerBundleInfos();
    for (auto &infoPair : infos) {
        auto &innerBundleInfo = infoPair.second;
        std::string bundleName = innerBundleInfo.GetBundleName();
        auto &userInfos = innerBundleInfo.GetInnerBundleUserInfos();
        if (userInfos.empty()) {
            continue;
        }
        AppProvisionInfo appProvisionInfo;
        if (dataMgr->GetAppProvisionInfo(bundleName, userInfos.begin()->second.bundleUserInfo.userId,
            appProvisionInfo) != ERR_OK) {
            LOG_W(BMS_TAG_DEFAULT, "GetAppProvisionInfo failed -n:%{public}s", bundleName.c_str());
        }
        for (auto &uerInfo : userInfos) {
            if (uerInfo.second.accessTokenId == 0) {
                continue;
            }
            int32_t userId = uerInfo.second.bundleUserInfo.userId;
            Security::AccessToken::AccessTokenIDEx accessTokenIdEx;
            accessTokenIdEx.tokenIDEx = uerInfo.second.accessTokenIdEx;
            Security::AccessToken::HapInfoCheckResult checkResult;
            if (BundlePermissionMgr::UpdateHapToken(accessTokenIdEx, innerBundleInfo, userId, checkResult,
                appProvisionInfo.appServiceCapabilities, true) != ERR_OK) {
                LOG_W(BMS_TAG_DEFAULT, "UpdateHapToken failed %{public}s", bundleName.c_str());
                updatePermissionsFlag = false;
            }
        }
    }
    if (updatePermissionsFlag) {
        (void)SaveUpdatePermissionsFlag();
    }
    LOG_I(BMS_TAG_DEFAULT, "update permissions end");
}

ErrCode BMSEventHandler::CheckSystemOptimizeBundleShaderCache(const std::string &bundleName,
    int32_t appIndex, int32_t userId, int32_t uid)
{
    std::string cloneBundleName = bundleName;
    if (appIndex != 0) {
        cloneBundleName = BundleCloneCommonHelper::GetCloneDataDir(bundleName,
            appIndex);
    }
    if (uid == Constants::INVALID_UID) {
        LOG_W(BMS_TAG_DEFAULT, "invalid uid for: %{public}s", cloneBundleName.c_str());
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    std::string systemOptimizeShaderCache = ServiceConstants::SYSTEM_OPTIMIZE_PATH;
    systemOptimizeShaderCache = systemOptimizeShaderCache.replace(systemOptimizeShaderCache.find("%"),
        1, std::to_string(userId));
    systemOptimizeShaderCache = systemOptimizeShaderCache +
        cloneBundleName + ServiceConstants::SHADER_CACHE_SUBDIR;
    CreateDirParam createDirParam;
    createDirParam.bundleName = bundleName;
    createDirParam.bundleDirScene = BundleDirScene::EL1_SYSTEM_OPTIMIZE_SHADER_CACHE_DIR;
    ErrCode ret = InstalldClient::GetInstance()->Mkdir(systemOptimizeShaderCache,
        ServiceConstants::NEW_SHADER_CACHE_MODE,
        uid, ServiceConstants::NEW_SHADER_CACHE_GID, createDirParam);
    if (ret != ERR_OK) {
        LOG_W(BMS_TAG_DEFAULT, "Mkdir %{public}s failed, error is %{public}d",
            systemOptimizeShaderCache.c_str(), errno);
        return ret;
    }
    return InstalldClient::GetInstance()->SetArkStartupCacheApl(cloneBundleName, systemOptimizeShaderCache);
}

ErrCode BMSEventHandler::CheckSystemOptimizeShaderCache()
{
    LOG_I(BMS_TAG_DEFAULT, "start");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    std::set<int32_t> userIds = dataMgr->GetAllUser();
    for (const auto &userId : userIds) {
        std::unordered_map<std::string, std::vector<std::pair<int32_t, int32_t>>> cloneInfos;
        dataMgr->GetAllCloneAppIndexesAndUidsByInnerBundleInfo(userId, cloneInfos);
        for (const auto& [bundleName, pairs] : cloneInfos) {
            for (const auto& [appIndex, uid] : pairs) {
                CheckSystemOptimizeBundleShaderCache(bundleName, appIndex, userId, uid);
            }
        }
    }
    return ERR_OK;
}

ErrCode BMSEventHandler::CleanSystemOptimizeBundleShaderCache(const std::string &bundleName,
    int32_t appIndex, int32_t userId)
{
    std::string cloneBundleName = bundleName;
    if (appIndex != 0) {
        cloneBundleName = BundleCloneCommonHelper::GetCloneDataDir(bundleName,
            appIndex);
    }
    std::string systemOptimizeShaderCache = ServiceConstants::SYSTEM_OPTIMIZE_PATH;
    systemOptimizeShaderCache = systemOptimizeShaderCache.replace(systemOptimizeShaderCache.find("%"),
        1, std::to_string(userId));
    systemOptimizeShaderCache = systemOptimizeShaderCache +
        cloneBundleName + ServiceConstants::SHADER_CACHE_SUBDIR;
    return InstalldClient::GetInstance()->CleanBundleDataDir(systemOptimizeShaderCache, bundleName, userId);
}

ErrCode BMSEventHandler::CleanSystemOptimizeShaderCache()
{
    LOG_I(BMS_TAG_DEFAULT, "start");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    std::set<int32_t> userIds = dataMgr->GetAllUser();
    for (const auto &userId : userIds) {
        std::unordered_map<std::string, std::vector<std::pair<int32_t, int32_t>>> cloneInfos;
        dataMgr->GetAllCloneAppIndexesAndUidsByInnerBundleInfo(userId, cloneInfos);
        for (const auto& [bundleName, pairs] : cloneInfos) {
            for (const auto& [appIndex, uid] : pairs) {
                CleanSystemOptimizeBundleShaderCache(bundleName, appIndex, userId);
            }
        }
    }
    return ERR_OK;
}

bool BMSEventHandler::IsPermissionsUpdated()
{
    auto bmsParam = DelayedSingleton<BundleMgrService>::GetInstance()->GetBmsParam();
    if (bmsParam == nullptr) {
        LOG_W(BMS_TAG_DEFAULT, "bmsParam is nullptr");
        return false;
    }
    std::string value;
    if (bmsParam->GetBmsParam(ServiceConstants::UPDATE_PERMISSIONS_FLAG, value)) {
        LOG_I(BMS_TAG_DEFAULT, "already update permissions");
        return true;
    }
    return false;
}

bool BMSEventHandler::SaveUpdatePermissionsFlag()
{
    auto bmsPara = DelayedSingleton<BundleMgrService>::GetInstance()->GetBmsParam();
    if (bmsPara == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "bmsPara is nullptr");
        return false;
    }
    if (!bmsPara->SaveBmsParam(ServiceConstants::UPDATE_PERMISSIONS_FLAG,
        std::string{ ServiceConstants::UPDATE_PERMISSIONS_FLAG_UPDATED })) {
        LOG_E(BMS_TAG_DEFAULT, "save updatePermissionsFlag failed");
        return false;
    }
    return true;
}

bool BMSEventHandler::ProcessCheckSystemOptimizeDir()
{
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "Need to check system optimize dir");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return false;
    }
    std::set<int32_t> userIds = dataMgr->GetAllUser();
    for (const auto &userId : userIds) {
        std::string el1ArkStartupCachePath = ServiceConstants::SYSTEM_OPTIMIZE_PATH;
        el1ArkStartupCachePath = el1ArkStartupCachePath.replace(el1ArkStartupCachePath.find("%"), 1,
            std::to_string(userId));
        LOG_I(BMS_TAG_DEFAULT, "create system optimize dir for -u: %{public}d", userId);
        CreateDirParam createDirParam;
        createDirParam.bundleDirScene = BundleDirScene::EL1_SYSTEM_OPTIMIZE_DIR;
        InstalldClient::GetInstance()->Mkdir(
            el1ArkStartupCachePath, ServiceConstants::SYSTEM_OPTIMIZE_MODE, 0, 0, createDirParam);
    }
    return true;
}

bool BMSEventHandler::CleanAllBundleEl1ArkStartupCacheLocal()
{
    LOG_I(BMS_TAG_DEFAULT, "start");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return false;
    }

    std::set<int32_t> userIds = dataMgr->GetAllUser();
    std::vector<std::string> bundleNames = dataMgr->GetAllBundleName();
    for (const auto &userId : userIds) {
        std::string el1ArkStartupCachePath = std::string(ServiceConstants::SYSTEM_OPTIMIZE_PATH);
        el1ArkStartupCachePath = el1ArkStartupCachePath.replace(el1ArkStartupCachePath.find("%"),
            1, std::to_string(userId));
        for (auto &bundleName : bundleNames) {
            std::string el1BundleArkStartupCachePath = el1ArkStartupCachePath +
                bundleName + ServiceConstants::ARK_STARTUP_CACHE_DIR;
            InstalldClient::GetInstance()->CleanBundleDataDir(el1BundleArkStartupCachePath, bundleName, userId);
        }
    }
    return true;
}

bool BMSEventHandler::IsRecoverListEmpty(const std::string &bundleName, std::vector<int32_t> &userIds)
{
    bool isEmpty = true;
    std::vector<int32_t> notInstallUserIds;
    for (const auto &[userId, installAndRecoverPair] : userInstallAndRecoverMap_) {
        const auto &recoverList = installAndRecoverPair.second;
        if (std::find(recoverList.begin(), recoverList.end(), bundleName) != recoverList.end()) {
            isEmpty = false;
        } else {
            notInstallUserIds.emplace_back(userId);
        }
    }
    if (!xmlMap_.empty()) {
        std::string path;
        std::vector<int32_t> needInstallUserIds;
        std::string validBundleName = bundleName;
        GetBundleNameAndUserIdFromPath(path, needInstallUserIds, validBundleName);

        std::sort(notInstallUserIds.begin(), notInstallUserIds.end());
        std::sort(needInstallUserIds.begin(), needInstallUserIds.end());

        std::set_intersection(
            notInstallUserIds.begin(), notInstallUserIds.end(),
            needInstallUserIds.begin(), needInstallUserIds.end(),
            std::back_inserter(userIds));
    } else {
        userIds = notInstallUserIds;
    }
    return isEmpty;
}

void BMSEventHandler::ProcessRecoverList(const std::string &bundleName, const std::string &filePath, bool removable,
    Constants::AppType appType, const std::vector<int32_t> userIds,
    const std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "ProcessRecoverList start -n %{public}s", bundleName.c_str());
    // 1. install the bundle for empty recoverList user
    std::vector<std::string> filePaths{filePath};
    int32_t timerId = XCollieHelper::SetOTATimer(OTA_PREINSTALL_BUNDLE_TASK, OTA_TIMEOUT_SECONDS);
    ScopeGuard cancelTimerIdGuard([timerId] { XCollieHelper::CancelTimer(timerId); });
    if (!OTAInstallSystemBundleTargetUser(filePaths, bundleName, appType, removable, userIds)) {
        LOG_E(BMS_TAG_DEFAULT, "OTA install new bundle(%{public}s) error", bundleName.c_str());
    }
    // 2. save pre-Install bundle info
    PreInstallBundleInfo preInstallBundleInfo;
    bool findEntry = false;
    for (const auto &item : infos) {
        preInstallBundleInfo.AddBundlePath(item.first);
        if (!findEntry) {
            auto applicationInfo = item.second.GetBaseApplicationInfo();
            item.second.AdaptMainLauncherResourceInfo(applicationInfo, true);
            preInstallBundleInfo.SetLabelId(applicationInfo.labelResource.id);
            preInstallBundleInfo.SetIconId(applicationInfo.iconResource.id);
            preInstallBundleInfo.SetDescriptionId(applicationInfo.descriptionId);
            preInstallBundleInfo.SetModuleName(applicationInfo.labelResource.moduleName);
            preInstallBundleInfo.SetVersionCode(applicationInfo.versionCode);
        }
        auto innerModuleInfos = item.second.GetInnerModuleInfos();
        if (!innerModuleInfos.empty() &&
            innerModuleInfos.begin()->second.distro.moduleType == Profile::MODULE_TYPE_ENTRY) {
            findEntry = true;
        }
    }
    preInstallBundleInfo.SetBundleName(bundleName);
    preInstallBundleInfo.SetAppType(appType);
    preInstallBundleInfo.SetRemovable(removable);
    preInstallBundleInfo.SetIsUninstalled(true);
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }
    if (!dataMgr->SavePreInstallBundleInfo(bundleName, preInstallBundleInfo)) {
        LOG_E(BMS_TAG_DEFAULT, "save preinstall info fail -n %{public}s", bundleName.c_str());
    }
}

void BMSEventHandler::GetInstallAndRecoverListForAllUser(std::unordered_map<int32_t,
    std::pair<std::vector<std::string>, std::vector<std::string>>> &installAndRecoverList)
{
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }
    BmsExtensionDataMgr bmsExtensionDataMgr;
    auto userIds = dataMgr->GetAllUser();
    for (const auto &userId : userIds) {
        if (userId == Constants::DEFAULT_USERID) {
            continue;
        }
        std::vector<std::string> bundleNames;
        if (!dataMgr->GetBundleList(bundleNames, userId,
            static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE))) {
            LOG_E(BMS_TAG_DEFAULT, "-u %{public}d GetBundleList failed", userId);
            continue;
        }
        std::vector<std::string> forceInstallList;
        std::vector<std::string> recoverList;
        if (!bmsExtensionDataMgr.GetInstallAndRecoverList(userId, bundleNames, forceInstallList, recoverList)) {
            LOG_E(BMS_TAG_DEFAULT, "-u %{public}d GetInstallAndRecoverList failed", userId);
            continue;
        }
        installAndRecoverList.emplace(userId, std::make_pair(forceInstallList, recoverList));
    }
}

bool BMSEventHandler::IsForceInstallListEmpty(const std::string &bundleName)
{
    bool isEmpty = true;
    for (const auto &[userId, installAndRecoverPair] : userInstallAndRecoverMap_) {
        const auto &forceInstallList = installAndRecoverPair.first;
        if (std::find(forceInstallList.begin(), forceInstallList.end(), bundleName) != forceInstallList.end()) {
            isEmpty = false;
        }
    }
    return isEmpty;
}

bool BMSEventHandler::ProcessNewInstallForBlackList(const std::string &bundleName,
    const std::set<int32_t> &allUsers, std::vector<int32_t> &userIds)
{
    BmsExtensionDataMgr bmsExtensionDataMgr;
    bool ret = false;
    for (auto userId : allUsers) {
        if (userId == Constants::U1 || userId == Constants::DEFAULT_USERID) {
            continue;
        }
        if (bmsExtensionDataMgr.CheckAppBlackList(bundleName, userId) != ERR_OK) {
            ret = true;
            continue;
        }
        userIds.emplace_back(userId);
    }
    return ret;
}


void BMSEventHandler::ProcessUpdateExtensionDirsApl()
{
    LOG_I(BMS_TAG_DEFAULT, "begin");
    bool updateFlag = false;
    CheckOtaFlag(OTAFlag::UPDATE_EXTENSION_DIRS_SELINUX_APL, updateFlag);
    if (updateFlag) {
        LOG_I(BMS_TAG_DEFAULT, "Not need to update extension dirs due to has updated");
        return;
    }
    LOG_I(BMS_TAG_DEFAULT, "Need to update extension dirs selinux apl");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }
    bool updateExtensionDirsSelinuxAplFlag = true;
    std::vector<CreateDirParam> allExtensionDirsToUpdateSelinuxApl = dataMgr->GetAllExtensionDirsToUpdateSelinuxApl();
    for (auto &extensionDirsToUpdate : allExtensionDirsToUpdateSelinuxApl) {
        std::string bundleName = extensionDirsToUpdate.bundleName;
        auto result = InstalldClient::GetInstance()->SetDirsApl(extensionDirsToUpdate, true);
        if (result != ERR_OK) {
            LOG_W(BMS_TAG_INSTALLER, "fail for bundle(%{public}s), error:%{public}d", bundleName.c_str(), result);
            updateExtensionDirsSelinuxAplFlag = false;
        }
    }
    
    if (updateExtensionDirsSelinuxAplFlag) {
        UpdateOtaFlag(OTAFlag::UPDATE_EXTENSION_DIRS_SELINUX_APL);
    }
    LOG_I(BMS_TAG_DEFAULT, "update selinux apl for extension dirs end");
}

bool BMSEventHandler::ProcessIdleInfo()
{
    LOG_I(BMS_TAG_DEFAULT, "begin");
    bool flag = false;
    CheckOtaFlag(OTAFlag::ADD_IDLE_INFO, flag);
    if (flag && !(OHOS::system::GetBoolParameter(ServiceConstants::RELABEL_PARAM, false))) {
        LOG_I(BMS_TAG_DEFAULT, "Not need to add idle info");
        return true;
    }
    LOG_I(BMS_TAG_DEFAULT, "Need to add idle info");
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return false;
    }
    if (!dataMgr->ProcessIdleInfo()) {
        LOG_E(BMS_TAG_DEFAULT, "process idle info failed");
        return false;
    }
    UpdateOtaFlag(OTAFlag::ADD_IDLE_INFO);
    return true;
}

void BMSEventHandler::ProcessDeleteResourceSlaveDb()
{
    LOG_I(BMS_TAG_DEFAULT, "begin");
    bool flag = false;
    CheckOtaFlag(OTAFlag::DELETE_RESOURCE_SLAVE_DB, flag);
    if (flag) {
        LOG_I(BMS_TAG_DEFAULT, "already processed, skip");
        return;
    }
    std::string slavePath = std::string(BundleResourceConstants::BUNDLE_RESOURCE_RDB_PATH)
        + BundleResourceConstants::BUNDLE_RESOURCE_BACKUP_RDB_NAME;
    std::vector<std::string> siblingFiles = {
        slavePath + "-dwr",
        slavePath + "-shm",
        slavePath + "-wal",
        std::string(BundleResourceConstants::BUNDLE_RESOURCE_RDB_PATH)
            + BundleResourceConstants::BMS_BACKUP_RDB_NAME,
    };

    // Update the OTA flag only when bundleResource_slave.db is removed.
    bool slaveDeleted = false;
    if (access(slavePath.c_str(), F_OK) == 0) {
        if (BundleUtil::DeleteDir(slavePath)) {
            slaveDeleted = true;
            LOG_I(BMS_TAG_DEFAULT, "deleted slave db: %{public}s", slavePath.c_str());
        } else {
            LOG_E(BMS_TAG_DEFAULT, "failed to delete slave db: %{public}s, errno: %{public}d",
                slavePath.c_str(), errno);
        }
    } else {
        slaveDeleted = true;
        LOG_I(BMS_TAG_DEFAULT, "slave db not exist, skip");
    }

    for (const auto &file : siblingFiles) {
        if (access(file.c_str(), F_OK) != 0) {
            continue;
        }
        if (BundleUtil::DeleteDir(file)) {
            LOG_I(BMS_TAG_DEFAULT, "deleted %{public}s", file.c_str());
        } else {
            LOG_W(BMS_TAG_DEFAULT, "failed to delete %{public}s, errno: %{public}d", file.c_str(), errno);
        }
    }

    if (slaveDeleted) {
        UpdateOtaFlag(OTAFlag::DELETE_RESOURCE_SLAVE_DB);
    }
    LOG_I(BMS_TAG_DEFAULT, "end");
}

void BMSEventHandler::ProcessMigrateUninstallBundleResource()
{
    LOG_I(BMS_TAG_DEFAULT, "begin migrate uninstall bundle resource");
    bool flag = false;
    CheckOtaFlag(OTAFlag::MIGRATE_UNINSTALL_BUNDLE_RESOURCE, flag);
    if (flag) {
        LOG_I(BMS_TAG_DEFAULT, "already migrated, skip");
        return;
    }

    auto bundleMgr = DelayedSingleton<BundleMgrService>::GetInstance();
    if (bundleMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "BundleMgrService is nullptr");
        return;
    }

    if (BundleResourceHelper::MigrateUninstallBundleResource()) {
        LOG_I(BMS_TAG_DEFAULT, "migrate success");
        UpdateOtaFlag(OTAFlag::MIGRATE_UNINSTALL_BUNDLE_RESOURCE);
    } else {
        LOG_E(BMS_TAG_DEFAULT, "migrate failed");
    }
}

DualModePackageInfo BMSEventHandler::ParseDualModePackageInfo(
    const std::string &bundleName,
    const std::string &scanPathIter,
    const std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    DualModePackageInfo pkgInfo;
    // Non-dual-mode device: return the default (policy=UNSPECIFIED); the caller keeps the original flow.
    if (!DualModeHelper::IsDualModeDevice()) {
        return pkgInfo;
    }
    std::string bundleDir = scanPathIter;

    int32_t policy = 0;
    std::map<std::string, std::vector<std::string>> modeHapMap;
    if (!DualModeHelper::GetDeviceModelDistributionPolicy(bundleName, scanPathIter,
        Constants::APP_DISTRIBUTION_TYPE_OS_INTEGRATION, policy, modeHapMap)) {
        LOG_W(BMS_TAG_DEFAULT, "ERMS query failed for %{public}s, fallback to original flow", bundleName.c_str());
        return pkgInfo;
    }
    pkgInfo.policy = static_cast<DeviceModeDistributionPolicy>(policy);
    // Different-package policies are 4/6/8 (UNIVERSAL/PARTIAL_COMPATIBLE/FULL_COMPATIBLE_DIFFERENT_PACKAGE)
    pkgInfo.isDiffPackage = DualModeHelper::IsDiffPackageCategory(pkgInfo.policy);
    LOG_I(BMS_TAG_DEFAULT, "dual-mode parse: bundle=%{public}s policy=%{public}d isDiffPackage=%{public}d",
        bundleName.c_str(), static_cast<int>(pkgInfo.policy), pkgInfo.isDiffPackage);

    if (!pkgInfo.isDiffPackage || modeHapMap.empty()) {
        // Same-name-same-package app: the hap path is scanPathIter itself, both lists stay empty and
        // the original flow applies.
        return pkgInfo;
    }

    // Same-name-different-package: modeHapMap holds hap file names relative to the preinstall
    // directory. Split the two sides by mainmode (not the current mode) to stay consistent with
    // ResolveDualModePolicy's classification.
    auto joinPath = [](const std::string &dir, const std::string &name) -> std::string {
        if (dir.empty() || dir.back() == '/') {
            return dir + name;
        }
        return dir + "/" + name;
    };
    int32_t mainmode = DualModeHelper::GetMainmode();
    for (const auto &entry : modeHapMap) {
        bool isMainSide = (DualModeHelper::MapDeviceTypeToMode(entry.first) == mainmode);
        for (const auto &name : entry.second) {
            if (isMainSide) {
                pkgInfo.mainModeHaps.push_back(joinPath(scanPathIter, name));
            } else {
                pkgInfo.subModeHaps.push_back(joinPath(scanPathIter, name));
            }
        }
    }
    LOG_I(BMS_TAG_DEFAULT, "dual-mode split: bundle=%{public}s mainHaps=%{public}zu subHaps=%{public}zu",
        bundleName.c_str(), pkgInfo.mainModeHaps.size(), pkgInfo.subModeHaps.size());
    return pkgInfo;
}

void BMSEventHandler::HandleDualModeNewInstall(
    const DualModePackageInfo &pkgInfo,
    const std::string &bundleName,
    const std::string &scanPathIter,
    bool removable,
    std::unordered_map<std::string, std::pair<std::vector<std::string>, bool>> &needInstallSysMap,
    std::unordered_map<std::string, DeviceModeDistributionPolicy> &dualModePolicyForNewMap,
    std::unordered_map<std::string, CrossModeOtaTask> &crossModeOtaTasks)
{
    bool isCurrentSecondary = DualModeHelper::IsSecondaryMode();
    if (!pkgInfo.isDiffPackage) {
        if (pkgInfo.policy == DeviceModeDistributionPolicy::MAIN_ONLY ||
            pkgInfo.policy == DeviceModeDistributionPolicy::SUB_ONLY) {
            // MAIN_ONLY/SUB_ONLY package: matching the current mode installs directly; otherwise cross-mode.
            bool matchCurrentMode =
                (pkgInfo.policy == DeviceModeDistributionPolicy::MAIN_ONLY && !isCurrentSecondary) ||
                (pkgInfo.policy == DeviceModeDistributionPolicy::SUB_ONLY && isCurrentSecondary);
            if (matchCurrentMode) {
                dualModePolicyForNewMap[bundleName] = pkgInfo.policy;
                needInstallSysMap[bundleName] = std::make_pair(std::vector<std::string>{scanPathIter}, removable);
                LOG_I(BMS_TAG_DEFAULT, "dual-mode new install (single-mode, current mode): %{public}s",
                    bundleName.c_str());
            } else {
                CrossModeOtaTask task;
                task.filePaths = {scanPathIter};
                task.removable = removable;
                task.policy = pkgInfo.policy;
                task.forceCrossModeOTAInstall = true;
                crossModeOtaTasks[bundleName] = task;
                LOG_I(BMS_TAG_DEFAULT, "dual-mode new install (single-mode, cross mode): %{public}s",
                    bundleName.c_str());
            }
        } else {
            // Same-name-same-package (UNIVERSAL/PARTIAL/FULL_COMPATIBLE_IDENTICAL_PACKAGE, policies 3/5/7):
            // one package serves both modes, no separate counterpart exists, so install through the
            // current-mode normal flow without cross-mode handling.
            dualModePolicyForNewMap[bundleName] = pkgInfo.policy;
            needInstallSysMap[bundleName] = std::make_pair(std::vector<std::string>{scanPathIter}, removable);
            LOG_I(BMS_TAG_DEFAULT, "dual-mode new install (identical package): %{public}s", bundleName.c_str());
        }
        return;
    }

    // Same-name-different-package (policies 4/6/8): the current-mode side goes into needInstallSysMap,
    // the other side into the cross-mode task map. Task keys are always the original name
    // (tempBundleInfos_ is keyed the same way); the prefix is decided by install-time flags.
    const auto &currentHaps = isCurrentSecondary ? pkgInfo.subModeHaps : pkgInfo.mainModeHaps;
    if (!currentHaps.empty()) {
        dualModePolicyForNewMap[bundleName] = pkgInfo.policy;
        needInstallSysMap[bundleName] = std::make_pair(currentHaps, removable);
        LOG_I(BMS_TAG_DEFAULT, "dual-mode new install (diff package, current side): %{public}s haps=%{public}zu",
            bundleName.c_str(), currentHaps.size());
    } else {
        LOG_W(BMS_TAG_DEFAULT, "no haps for current mode: %{public}s, skip normal install", bundleName.c_str());
    }

    const auto &otherHaps = isCurrentSecondary ? pkgInfo.mainModeHaps : pkgInfo.subModeHaps;
    if (!otherHaps.empty()) {
        CrossModeOtaTask task;
        task.filePaths = otherHaps;
        task.removable = removable;
        task.policy = pkgInfo.policy;
        task.forceCrossModeOTAInstall = true;
        crossModeOtaTasks[bundleName] = task;
        LOG_I(BMS_TAG_DEFAULT, "dual-mode new install (diff package, cross side): key=%{public}s haps=%{public}zu",
            bundleName.c_str(), otherHaps.size());
    }
}

void BMSEventHandler::ProcessDualModeCrossUpdateIfNeeded(
    const DualModePackageInfo &pkgInfo,
    const std::unordered_map<std::string, InnerBundleInfo> &infos,
    const std::string &bundleName,
    bool removable,
    uint32_t hapVersionCode,
    std::unordered_map<std::string, CrossModeOtaTask> &crossModeOtaTasks)
{
    if (!DualModeHelper::IsDualModeDevice() ||
        pkgInfo.policy == DeviceModeDistributionPolicy::UNSPECIFIED) {
        return;
    }
    bool isCurrentSecondary = DualModeHelper::IsSecondaryMode();

    // Cross-mode scenarios covered:
    // a) same-name-different-package (policies 4/6/8): the other mode's package needs an update with the
    //    opposite-side haps; when that side is not installed (legacy devices upgraded from a build without
    //    the dual-mode mechanism), re-install it unless the user uninstalled it;
    // b) MAIN_ONLY/SUB_ONLY apps of the same-name-same-package kind: when the policy does not match the
    //    current mode, the hidden side also needs a cross-mode update;
    // c) IDENTICAL same-name-same-package (3/5/7): one package serves both modes, no counterpart exists,
    //    the current-mode flow handles it; skipped here.
    const bool isDiffPackage = pkgInfo.isDiffPackage;
    const bool isSingleMode =
        pkgInfo.policy == DeviceModeDistributionPolicy::MAIN_ONLY ||
        pkgInfo.policy == DeviceModeDistributionPolicy::SUB_ONLY;
    if (!isDiffPackage && !isSingleMode) {
        return;
    }
    const bool singleModeMismatch =
        isSingleMode &&
        ((pkgInfo.policy == DeviceModeDistributionPolicy::MAIN_ONLY && isCurrentSecondary) ||
         (pkgInfo.policy == DeviceModeDistributionPolicy::SUB_ONLY && !isCurrentSecondary));
    if (isSingleMode && !singleModeMismatch) {
        // MAIN_ONLY/SUB_ONLY matching the current mode: normal current-mode update, no cross task.
        return;
    }
    // Cross-mode task haps: the opposite-side list for different-package; for a mismatched single-mode
    // app the whole parsed package is the cross-mode hap (keys of the parsed infos).
    std::vector<std::string> otherHaps;
    if (isDiffPackage) {
        otherHaps = isCurrentSecondary ? pkgInfo.mainModeHaps : pkgInfo.subModeHaps;
    } else {
        for (const auto &item : infos) {
            otherHaps.push_back(item.first);
        }
    }
    if (otherHaps.empty()) {
        return;
    }

    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        return;
    }
    // Cross-mode package info is queried through FetchTempBundleInfo: tempBundleInfos_ stores the
    // non-current-mode variants (the different-package counterpart and hidden MAIN_ONLY/SUB_ONLY apps)
    // keyed by the original bundleName; never query the RDB with a prefixed name here.
    InnerBundleInfo crossInnerInfo;
    if (!dataMgr->FetchTempBundleInfo(bundleName, crossInnerInfo)) {
        if (!isDiffPackage) {
            // Mismatched MAIN_ONLY/SUB_ONLY with no hidden side: the app was never installed in the
            // other mode; its install is handled by the current-mode flow (IsCrossModeInstall decides
            // cross-mode storage by policy), so nothing to do here.
            LOG_D(BMS_TAG_DEFAULT, "single-mode app has no hidden side, no cross task: %{public}s",
                bundleName.c_str());
            return;
        }
        // Different-package with the other side missing. Re-install on legacy upgrades (the other mode
        // never had it); respect a user uninstall and skip. Judge the uninstall state from the
        // preinstall bundle info: the primary side is keyed by bundleName, the secondary side by the
        // +clone-10000+ prefixed name.
        const std::string effectiveBundleName = isCurrentSecondary ?
            bundleName : DualModeHelper::GetDualModeBundleName(bundleName);
        PreInstallBundleInfo preInstallBundleInfo;
        if (dataMgr->GetPreInstallBundleInfo(effectiveBundleName, preInstallBundleInfo)) {
            LOG_I(BMS_TAG_DEFAULT, "cross-side missing, no preinstall info or uninstalled, skip: %{public}s",
                bundleName.c_str());
            return;
        }
        CrossModeOtaTask task;
        task.filePaths = otherHaps;
        task.removable = removable;
        task.policy = pkgInfo.policy;
        // Same convention as HandleDualModeNewInstall: in secondary mode the target is the primary
        // side (keep the original name); in primary mode installing the secondary side uses the clone key.
        task.forceCrossModeOTAInstall = true;
        crossModeOtaTasks[bundleName] = task;
        LOG_I(BMS_TAG_DEFAULT, "legacy upgrade: cross-side install needed: %{public}s haps=%{public}zu",
            bundleName.c_str(), otherHaps.size());
        return;
    }

    // Version comparison mirrors the current-mode OTA flow, evaluated against the other side, via
    // GetBaseBundleInfo's BundleInfo view reusing IsPathExistInInstalledBundleInfo / UpdateModuleByHash
    // / hapModuleNames / applicationInfo.accessTokenIdEx.
    BundleInfo crossInstalledInfo;
    crossInnerInfo.GetBundleInfo(static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE),
        crossInstalledInfo, Constants::ALL_USERID);
    uint32_t crossVersionCode = crossInnerInfo.GetVersionCode();
    bool updateCrossBundle = false;
    bool hasEntry = false;
    for (const auto &item : infos) {
        if (item.second.HasEntry()) {
            hasEntry = true;
            break;
        }
    }
    for (const auto &item : infos) {
        auto parserModuleNames = item.second.GetModuleNameVec();
        if (parserModuleNames.empty()) {
            continue;
        }
        // Installed versionCode lower than the hap version: upgrade directly.
        if (crossVersionCode < hapVersionCode) {
            LOG_I(BMS_TAG_DEFAULT, "OTA cross update module(%{public}s) for(%{public}s)",
                parserModuleNames[0].c_str(), bundleName.c_str());
            updateCrossBundle = true;
            break;
        }
        // Legacy app with accessTokenIdEx == 0 needs an update.
        if (crossInstalledInfo.applicationInfo.accessTokenIdEx == 0) {
            LOG_I(BMS_TAG_DEFAULT, "OTA cross update module(%{public}s) accessTokenIdEx=0 for(%{public}s)",
                parserModuleNames[0].c_str(), bundleName.c_str());
            updateCrossBundle = true;
            break;
        }
        // Equal versionCode: update only for a new module or a changed build hash.
        if (crossVersionCode == hapVersionCode) {
            if (crossInnerInfo.GetInstallMark().status != InstallExceptionStatus::INSTALL_FINISH) {
                LOG_I(BMS_TAG_DEFAULT, "OTA cross status error: %{public}s %{public}d",
                    bundleName.c_str(), crossInnerInfo.GetInstallMark().status);
                updateCrossBundle = true;
                break;
            }
            if (!IsPathExistInInstalledBundleInfo(item.first, crossInstalledInfo)) {
                LOG_I(BMS_TAG_DEFAULT, "OTA cross install new module(%{public}s) for(%{public}s)",
                    parserModuleNames[0].c_str(), bundleName.c_str());
                updateCrossBundle = true;
                break;
            }
            bool hasModuleInstalled = std::find(
                crossInstalledInfo.hapModuleNames.begin(), crossInstalledInfo.hapModuleNames.end(),
                parserModuleNames[0]) != crossInstalledInfo.hapModuleNames.end();
            if (hasModuleInstalled) {
                if (UpdateModuleByHash(crossInstalledInfo, item.second) || (!hasEntry && item.second.IsHsp())) {
                    updateCrossBundle = true;
                    break;
                }
                continue;
            }
            updateCrossBundle = true;
            break;
        }
        // Installed versionCode higher than the hap version: downgrade, do not update.
        if (crossVersionCode > hapVersionCode) {
            LOG_E(BMS_TAG_DEFAULT, "-n %{public}s cross update failed version:%{public}d lower than "
                "current:%{public}d", bundleName.c_str(), hapVersionCode, crossVersionCode);
            updateCrossBundle = false;
            break;
        }
    }

    if (!updateCrossBundle) {
        return;
    }
    CrossModeOtaTask task;
    task.filePaths = otherHaps;
    task.removable = removable;
    task.policy = pkgInfo.policy;
    // Same convention as HandleDualModeNewInstall: cross-installing the secondary side forces the
    // clone key; in secondary mode the target is the primary side and keeps the original name
    // (different-package suppresses the NeedDualModeHandle fallback; MAIN_ONLY/SUB_ONLY are stored
    // under the original name anyway).
    task.forceCrossModeOTAInstall = true;
    crossModeOtaTasks[bundleName] = task;
    LOG_I(BMS_TAG_DEFAULT, "OTA cross-mode update needed: %{public}s haps=%{public}zu policy=%{public}d",
        bundleName.c_str(), otherHaps.size(), static_cast<int>(task.policy));
}

bool BMSEventHandler::IsSkipNormalOtaFlow(const DualModePackageInfo &pkgInfo)
{
    if (!DualModeHelper::IsDualModeDevice()) {
        return false;
    }
    bool isCurrentSecondary = DualModeHelper::IsSecondaryMode();
    // MAIN_ONLY in secondary mode / SUB_ONLY in primary mode: the current-mode flow does nothing
    // (their cross-mode install/update is decided separately in HandleDualModeNewInstall /
    // ProcessDualModeCrossUpdateIfNeeded).
    if ((pkgInfo.policy == DeviceModeDistributionPolicy::MAIN_ONLY && isCurrentSecondary) ||
        (pkgInfo.policy == DeviceModeDistributionPolicy::SUB_ONLY && !isCurrentSecondary)) {
        LOG_D(BMS_TAG_DEFAULT, "skip normal ota flow, single-mode app not for current mode");
        return true;
    }
    return false;
}

bool BMSEventHandler::OTAInstallSystemBundleForDualApp(
    const std::vector<std::string> &filePaths,
    const CrossModeOtaTask &task,
    Constants::AppType appType)
{
    if (filePaths.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "File path is empty");
        return false;
    }
    InstallParam installParam;
    installParam.isPreInstallApp = true;
    installParam.SetKillProcess(false);
    installParam.needSendEvent = false;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.removable = task.removable;
    installParam.needSavePreInstallInfo = true;
    installParam.copyHapToInstallPath = false;
    installParam.isOTA = true;
    installParam.preinstallSourceFlag = ApplicationInfoFlag::FLAG_OTA_INSTALLED;
    // Dual-mode key parameters: the policy is passed through so ResolveDualModePolicy skips the ERMS
    // query; the cross-mode flag drives the target-side storage key (+clone-10000+ for the secondary
    // side, the original name for the primary side).
    installParam.deviceModeDistributionPolicy = task.policy;
    installParam.forceCrossModeOTAInstall = task.forceCrossModeOTAInstall;
    SystemBundleInstaller installer;
    ErrCode ret = installer.OTAInstallSystemBundle(filePaths, installParam, appType);
    if (ret == ERR_APPEXECFWK_INSTALL_ZERO_USER_WITH_NO_SINGLETON) {
        ret = ERR_OK;
    }
    LOG_I(BMS_TAG_DEFAULT, "dual-app ota install ret=%{public}d forceClone=%{public}d policy=%{public}d",
        ret, task.forceCrossModeOTAInstall, static_cast<int>(task.policy));
    return ret == ERR_OK;
}

void BMSEventHandler::ProcessUpdateDualPolicy(const DualModePackageInfo &pkgInfo, const std::string &bundleName)
{
    if (!DualModeHelper::IsDualModeDevice() || !pkgInfo.isDiffPackage) {
        return;
    }
    auto dataMgr = GetDataMgrFromService();
    if (dataMgr == nullptr) {
        return;
    }
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "%{public}s update policy", bundleName.c_str());
    AppSandboxPolicy appSandboxPolicy =
        pkgInfo.isDiffPackage ? AppSandboxPolicy::ISOLATED_SANDBOX : AppSandboxPolicy::SHARED_SANDBOX;
    dataMgr->UpdateBundleInfoPolicy(bundleName, pkgInfo.policy, appSandboxPolicy);
    InnerBundleInfo crossInnerInfo;
    PreInstallBundleInfo preInstallBundleInfo;
    const std::string effectiveBundleName = DualModeHelper::GetDualModeBundleName(bundleName);
    //same package change to diff packages during ota, need update policy firstly
    if (dataMgr->FetchTempBundleInfo(bundleName, crossInnerInfo) ||
        dataMgr->GetPreInstallBundleInfo(effectiveBundleName, preInstallBundleInfo)) {
        return;
    }
    if (DualModeHelper::IsSecondaryMode()) {
        dataMgr->MoveBundleInfoToTemp(bundleName);
        LOG_NOFUNC_I(BMS_TAG_DEFAULT, "%{public}s move to tempBundleInfos", bundleName.c_str());
    }
}

bool BMSEventHandler::CheckDualModeCrossInstall(bool isDualCloneApp, DeviceModeDistributionPolicy policy)
{
    if (!DualModeHelper::IsDualModeDevice() || !DualModeHelper::IsDiffPackageCategory(policy)) {
        return false;
    }
    return DualModeHelper::IsSecondaryMode() ? !isDualCloneApp : isDualCloneApp;
}

static constexpr size_t MIGRATION_BATCH_SIZE = 50;
static constexpr int32_t MAX_RETRY = 5;
static constexpr int64_t BACKOFF_INTERVALS_MS[] = {500, 1000, 1000, 2000, 2000};

void BMSEventHandler::ProcessAccessTokenMigration()
{
    LOG_I(BMS_TAG_DEFAULT, "AccessTokenMigration: start");
    if (!BundleSpmManager::IsEnabled()) {
        LOG_I(BMS_TAG_DEFAULT, "AccessTokenMigration: SPM not enabled, skip");
        return;
    }
    bool migrationDone = false;
    CheckOtaFlag(OTAFlag::MIGRATE_UID_TO_ATM, migrationDone);
    if (migrationDone) {
        LOG_I(BMS_TAG_DEFAULT, "AccessTokenMigration: already migrated, check unmigrated bundles");
        FinishAccessTokenMigration();
        CheckAndFallbackUnmigratedBundles();
        return;
    }
    if (!InnerProcessAccessTokenMigration()) {
        LOG_E(BMS_TAG_DEFAULT, "AccessTokenMigration: failed");
        return;
    }
    LOG_I(BMS_TAG_DEFAULT, "AccessTokenMigration: completed and flag set");
}

bool BMSEventHandler::InnerProcessAccessTokenMigration()
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return false;
    }

    CleanDirtyUninstallData();

    std::vector<Security::AccessToken::MigratedInfo> migratedList;

    std::set<int32_t> allUidSet;

    std::unordered_map<int32_t, Security::AccessToken::HapBaseInfo> allUidToHapInfo;
    BuildMigrationData(dataMgr, migratedList, allUidSet, allUidToHapInfo);
    LOG_I(BMS_TAG_DEFAULT, "Migration: built data for %{public}zu bundles, %{public}zu uid entries",
        migratedList.size(), allUidSet.size());

    std::vector<bool> successFlags(migratedList.size(), false);

    std::vector<Security::AccessToken::HapBaseInfo> failedHapList;
    std::vector<int32_t> failedUidList;
    std::vector<int32_t> failedErrCodeList;
    bool noIpcFailure = ExecuteMigrationWithRetry(dataMgr, migratedList, successFlags,
        allUidSet, allUidToHapInfo, failedHapList, failedUidList, failedErrCodeList);
    if (!noIpcFailure) {
        LOG_E(BMS_TAG_DEFAULT, "Migration: aborted, ATM service unavailable, %{public}zu entries unresolved",
            failedHapList.size());
        return false;
    }

    size_t successCount = 0;
    for (auto f : successFlags) {
        if (f) {
            ++successCount;
        }
    }
    LOG_I(BMS_TAG_DEFAULT, "Migration: %{public}zu bundles succeeded, %{public}zu failed",
        successCount, successFlags.size() - successCount);

    MarkMigratedBundles(dataMgr, migratedList, successFlags);
    LOG_I(BMS_TAG_DEFAULT, "Migration: marked %{public}zu bundles as checkBySpm", successCount);

    FinishAccessTokenMigration();

    UpdateOtaFlag(OTAFlag::MIGRATE_UID_TO_ATM);

    if (!failedHapList.empty()) {
        LOG_I(BMS_TAG_DEFAULT, "Migration: start SPM fallback for %{public}zu failed entries",
            failedHapList.size());
        FallbackWithSpmSession(dataMgr, failedHapList, failedUidList, failedErrCodeList,
            successFlags, migratedList);
    }

    LOG_I(BMS_TAG_DEFAULT, "Migration: completed");
    return true;
}

void BMSEventHandler::CleanDirtyUninstallData()
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        return;
    }
    std::map<std::string, UninstallBundleInfo> uninstallBundleInfos;
    dataMgr->GetAllUninstallBundleInfo(uninstallBundleInfos);
    int32_t cleanCount = 0;
    for (const auto &[bundleName, info] : uninstallBundleInfos) {
        InnerBundleInfo innerBundleInfo;
        if (!dataMgr->FetchInnerBundleInfo(bundleName, innerBundleInfo)) {
            continue;
        }
        LOG_I(BMS_TAG_DEFAULT, "Clean dirty uninstall data for installed bundle: %{public}s",
            bundleName.c_str());
        for (const auto &[userIdStr, dui] : info.userInfos) {
            int32_t userId = 0;
            int32_t appIndex = 0;
            auto underscorePos = userIdStr.find(Constants::FILE_UNDERLINE);
            if (underscorePos != std::string::npos) {
                if (!OHOS::StrToInt(userIdStr.substr(0, underscorePos), userId)) {
                    continue;
                }
                OHOS::StrToInt(userIdStr.substr(underscorePos + 1), appIndex);
            } else {
                if (!OHOS::StrToInt(userIdStr, userId)) {
                    continue;
                }
            }
            if (appIndex == 0) {
                dataMgr->DeleteUninstallBundleInfo(bundleName, userId);
            } else {
                dataMgr->DeleteUninstallCloneBundleInfo(bundleName, userId, appIndex);
            }
            BundleResourceHelper::DeleteUninstallBundleResource(bundleName, userId, appIndex);
        }
        ++cleanCount;
    }
    if (cleanCount > 0) {
        LOG_I(BMS_TAG_DEFAULT, "CleanDirtyUninstallData cleaned %{public}d dirty records", cleanCount);
    }
}

void BMSEventHandler::BuildMigrationData(
    const std::shared_ptr<BundleDataMgr> &dataMgr,
    std::vector<Security::AccessToken::MigratedInfo> &migratedList,
    std::set<int32_t> &allUidSet,
    std::unordered_map<int32_t, Security::AccessToken::HapBaseInfo> &allUidToHapInfo)
{
    auto bundleNames = dataMgr->GetAllBundleName();
    std::map<std::string, UninstallBundleInfo> uninstallBundleInfos;
    dataMgr->GetAllUninstallBundleInfo(uninstallBundleInfos);

    std::map<std::string, Security::AccessToken::MigratedInfo> migratedMap;

    BuildFromInstalledBundles(bundleNames, dataMgr, migratedMap);
    LOG_I(BMS_TAG_DEFAULT, "Migration: built from %{public}zu installed bundles", bundleNames.size());
    BuildFromSandbox(dataMgr, migratedMap);
    BuildFromUninstallData(uninstallBundleInfos, migratedMap);
    LOG_I(BMS_TAG_DEFAULT, "Migration: built from %{public}zu uninstall-retained bundles",
        uninstallBundleInfos.size());
    BuildAllUidSet(migratedMap, allUidSet, allUidToHapInfo);

    for (auto &[bn, m] : migratedMap) {
        if (m.uidList.empty()) {
            continue;
        }
        migratedList.emplace_back(std::move(m));
    }
}

void BMSEventHandler::BuildFromInstalledBundles(const std::vector<std::string> &bundleNames,
    const std::shared_ptr<BundleDataMgr> &dataMgr,
    std::map<std::string, Security::AccessToken::MigratedInfo> &migratedMap)
{
    for (const auto &bundleName : bundleNames) {
        InnerBundleInfo info;
        if (!dataMgr->FetchInnerBundleInfo(bundleName, info)) {
            continue;
        }
        std::string bn = bundleName;
        Security::AccessToken::MigratedInfo m;
        m.bundleName = bn;
        m.pathList.hapPaths = info.GetAllHapPaths();
        m.pathList.isPreInstalled = info.IsPreInstallApp();
        m.pathList.userIdForEnterpriseSign = info.GetUserId();
        m.mode = info.IsDualModeCloneApp()
            ? Security::AccessToken::MultipleMode::SUB_MODE
            : Security::AccessToken::MultipleMode::DEFAULT_OR_MAIN_MODE;
        auto userInfos = info.GetInnerBundleUserInfos();
        for (const auto &[userIdStr, userInfo] : userInfos) {
            int32_t userId = userInfo.bundleUserInfo.userId;
            Security::AccessToken::HapBaseInfo hapBaseInfo{userId, bn, 0};
            m.uidList.emplace_back(userInfo.uid);
            m.hapBaseInfoList.emplace_back(hapBaseInfo);
            m.reservedTypeList.emplace_back(Security::AccessToken::ReservedType::NONE);
            for (const auto &[appIndexStr, cloneInfo] : userInfo.cloneInfos) {
                int32_t appIndex = 0;
                if (!OHOS::StrToInt(appIndexStr, appIndex) || appIndex <= 0) {
                    continue;
                }
                int32_t cloneUserId = cloneInfo.userId;
                Security::AccessToken::HapBaseInfo cloneHapBaseInfo{cloneUserId, bn, appIndex};
                m.uidList.emplace_back(cloneInfo.uid);
                m.hapBaseInfoList.emplace_back(cloneHapBaseInfo);
                m.reservedTypeList.emplace_back(Security::AccessToken::ReservedType::NONE);
            }
        }
        LOG_D(BMS_TAG_DEFAULT, "Migration: built from installed bundle=%{public}s, %{public}zu uid entries",
            bn.c_str(), m.uidList.size());
        migratedMap[bn] = std::move(m);
    }
}

void BMSEventHandler::BuildFromSandbox(const std::shared_ptr<BundleDataMgr> &dataMgr,
    std::map<std::string, Security::AccessToken::MigratedInfo> &migratedMap)
{
    auto sandboxHelper = dataMgr->GetSandboxAppHelper();
    if (sandboxHelper == nullptr) {
        LOG_D(BMS_TAG_DEFAULT, "Migration: sandbox helper null, skip sandbox");
        return;
    }
    auto sandboxMap = sandboxHelper->GetSandboxAppInfoMap();
    size_t addedCount = 0;
    for (const auto &[key, sandboxInfo] : sandboxMap) {
        std::string bn = sandboxInfo.GetBundleName();
        int32_t sandboxAppIndex = 0;
        auto pos = key.find(Constants::FILE_UNDERLINE);
        if (pos != std::string::npos) {
            OHOS::StrToInt(key.substr(0, pos), sandboxAppIndex);
        }
        auto it = migratedMap.find(bn);
        if (it == migratedMap.end()) {
            continue;
        }
        auto &m = it->second;
        size_t before = m.uidList.size();
        for (const auto &[uk, ui] : sandboxInfo.GetInnerBundleUserInfos()) {
            int32_t userId = ui.bundleUserInfo.userId;
            m.uidList.emplace_back(ui.uid);
            m.hapBaseInfoList.emplace_back(
                Security::AccessToken::HapBaseInfo{userId, bn, sandboxAppIndex});
            m.reservedTypeList.emplace_back(Security::AccessToken::ReservedType::NONE);
        }
        addedCount += m.uidList.size() - before;
    }
    LOG_D(BMS_TAG_DEFAULT, "Migration: built from sandbox, added %{public}zu uid entries", addedCount);
}

void BMSEventHandler::BuildFromUninstallData(
    const std::map<std::string, UninstallBundleInfo> &uninstallBundleInfos,
    std::map<std::string, Security::AccessToken::MigratedInfo> &migratedMap)
{
    for (const auto &[bundleName, uninstInfo] : uninstallBundleInfos) {
        std::string bn = bundleName;
        auto it = migratedMap.find(bn);
        Security::AccessToken::MigratedInfo m;
        if (it != migratedMap.end()) {
            m = it->second;
        } else {
            m.bundleName = bn;
        }
        for (const auto &[userIdStr, dui] : uninstInfo.userInfos) {
            int32_t userId = 0;
            int32_t appIndex = 0;
            auto underscorePos = userIdStr.find(Constants::FILE_UNDERLINE);
            if (underscorePos != std::string::npos) {
                if (!OHOS::StrToInt(userIdStr.substr(0, underscorePos), userId)) {
                    continue;
                }
                OHOS::StrToInt(userIdStr.substr(underscorePos + 1), appIndex);
            } else {
                if (!OHOS::StrToInt(userIdStr, userId) || userId == Constants::UNSPECIFIED_USERID) {
                    continue;
                }
            }
            if (std::any_of(m.hapBaseInfoList.begin(), m.hapBaseInfoList.end(),
                [&bn, userId, appIndex](const auto &hapInfo) {
                    return hapInfo.bundleName == bn && hapInfo.userID == userId && hapInfo.instIndex == appIndex;
                })) {
                continue;
            }
            m.uidList.emplace_back(dui.uid);
            m.hapBaseInfoList.emplace_back(
                Security::AccessToken::HapBaseInfo{userId, bn, appIndex});
            m.reservedTypeList.emplace_back(Security::AccessToken::ReservedType::RESERVED_DATA);
        }
        LOG_D(BMS_TAG_DEFAULT, "Migration: built from uninstall-retained bundle=%{public}s, %{public}zu uid entries",
            bn.c_str(), m.uidList.size());
        migratedMap[bn] = std::move(m);
    }
}

void BMSEventHandler::BuildAllUidSet(
    const std::map<std::string, Security::AccessToken::MigratedInfo> &migratedMap,
    std::set<int32_t> &allUidSet,
    std::unordered_map<int32_t, Security::AccessToken::HapBaseInfo> &allUidToHapInfo)
{
    for (const auto &[bn, m] : migratedMap) {
        for (size_t k = 0; k < m.hapBaseInfoList.size() && k < m.uidList.size(); ++k) {
            allUidSet.emplace(m.uidList[k]);
            allUidToHapInfo.try_emplace(m.uidList[k], m.hapBaseInfoList[k]);
        }
    }
}

void BMSEventHandler::ReportMigrationEvent(
    const std::vector<Security::AccessToken::HapBaseInfo> &hapList,
    const std::vector<int32_t> &uidList,
    const std::vector<int32_t> &errorCodeList,
    int32_t errCode)
{
    if (hapList.empty()) {
        return;
    }
    EventInfo eventInfo;
    for (const auto &hap : hapList) {
        eventInfo.bundleNameList.emplace_back(hap.bundleName);
        eventInfo.userIdList.emplace_back(hap.userID);
        eventInfo.appIndexList.emplace_back(hap.instIndex);
    }
    eventInfo.uidList = uidList;
    eventInfo.errorCodeList = errorCodeList;
    eventInfo.errCode = errCode;
    LOG_W(BMS_TAG_DEFAULT,
        "ReportMigrationEvent errCode=%{public}d hapCount=%{public}zu uidCount=%{public}zu",
        errCode, hapList.size(), uidList.size());
    EventReport::SendSystemEvent(BMSEventType::QUERY_BUNDLE_INFO, eventInfo);
}

void BMSEventHandler::FinishAccessTokenMigration()
{
    constexpr int32_t MAX_RETRY = 2;
    for (int32_t i = 0; i < MAX_RETRY; ++i) {
        int32_t ret = Security::AccessToken::AccessTokenKit::FinishMigration();
        if (ret == 0 || ret == Security::AccessToken::AccessTokenError::ERR_MIGRATION_COMPLETED) {
            LOG_I(BMS_TAG_DEFAULT, "FinishMigration succeeded, ret=%{public}d", ret);
            return;
        }
        LOG_W(BMS_TAG_DEFAULT, "FinishMigration failed, retrying (%{public}d/%{public}d)", i + 1, MAX_RETRY);
    }
    LOG_E(BMS_TAG_DEFAULT, "FinishMigration all retries failed");
}

bool BMSEventHandler::IsSystemAppMigration(const Security::AccessToken::MigratedInfo &migratedInfo,
    const std::shared_ptr<BundleDataMgr> &dataMgr)
{
    InnerBundleInfo info;
    if (!dataMgr->FetchInnerBundleInfo(migratedInfo.bundleName, info)) {
        return false;
    }
    return info.IsSystemApp();
}

bool BMSEventHandler::IsBundleAllResolved(
    const Security::AccessToken::MigratedInfo &m,
    const std::vector<Security::AccessToken::HapBaseInfo> &failedHapList,
    const std::vector<bool> &resolved)
{
    for (size_t k = 0; k < m.hapBaseInfoList.size() && k < m.uidList.size(); ++k) {
        const auto &hap = m.hapBaseInfoList[k];
        for (size_t j = 0; j < failedHapList.size(); ++j) {
            if (failedHapList[j].bundleName == hap.bundleName &&
                failedHapList[j].userID == hap.userID &&
                failedHapList[j].instIndex == hap.instIndex) {
                if (!resolved[j]) {
                    return false;
                }
                break;
            }
        }
    }
    return true;
}

bool BMSEventHandler::HasFailedEntry(
    const Security::AccessToken::MigratedInfo &m,
    const std::vector<Security::AccessToken::HapBaseInfo> &failedHapList)
{
    for (size_t k = 0; k < m.hapBaseInfoList.size(); ++k) {
        const auto &hap = m.hapBaseInfoList[k];
        for (const auto &failed : failedHapList) {
            if (failed.bundleName == hap.bundleName &&
                failed.userID == hap.userID &&
                failed.instIndex == hap.instIndex) {
                return true;
            }
        }
    }
    return false;
}

void BMSEventHandler::CompactFailedList(
    std::vector<Security::AccessToken::HapBaseInfo> &failedHapList,
    std::vector<int32_t> &failedUidList,
    std::vector<int32_t> &failedErrCodeList,
    const std::vector<bool> &resolved)
{
    size_t writeIdx = 0;
    for (size_t i = 0; i < failedHapList.size(); ++i) {
        if (!resolved[i]) {
            if (writeIdx != i) {
                failedHapList[writeIdx] = std::move(failedHapList[i]);
                failedUidList[writeIdx] = failedUidList[i];
                failedErrCodeList[writeIdx] = failedErrCodeList[i];
            }
            ++writeIdx;
        }
    }
    failedHapList.resize(writeIdx);
    failedUidList.resize(writeIdx);
    failedErrCodeList.resize(writeIdx);
}

void BMSEventHandler::MarkMigratedBundles(
    const std::shared_ptr<BundleDataMgr> &dataMgr,
    const std::vector<Security::AccessToken::MigratedInfo> &migratedList,
    const std::vector<bool> &successFlags)
{
    for (size_t i = 0; i < migratedList.size(); ++i) {
        if (!successFlags[i]) {
            continue;
        }
        const auto &bundleName = migratedList[i].bundleName;
        dataMgr->UpdateUninstallBundleCheckBySpm(bundleName, true);
        InnerBundleInfo info;
        if (dataMgr->FetchInnerBundleInfo(bundleName, info)) {
            info.SetBundleCheckBySpm(true);
            dataMgr->UpdateInnerBundleInfo(info);
            LOG_D(BMS_TAG_DEFAULT, "Migration: marked bundle=%{public}s as checkBySpm", bundleName.c_str());
        }
    }
}

void BMSEventHandler::UpdateTokenIdIfChanged(const std::shared_ptr<BundleDataMgr> &dataMgr,
    const Security::AccessToken::MigratedInfo &migratedInfo,
    const Security::AccessToken::BundleMigrateResult &result)
{
    for (size_t k = 0; k < result.tokenIdList.size() &&
        k < migratedInfo.hapBaseInfoList.size(); ++k) {
        const auto &hapBaseInfo = migratedInfo.hapBaseInfoList[k];
        uint64_t newTokenIdEx = result.tokenIdList[k].tokenIDEx;
        uint32_t newTokenId = result.tokenIdList[k].tokenIdExStruct.tokenID;

        InnerBundleInfo info;
        if (!dataMgr->FetchInnerBundleInfo(hapBaseInfo.bundleName, info)) {
            continue;
        }
        InnerBundleUserInfo userInfo;
        if (!info.GetInnerBundleUserInfo(hapBaseInfo.userID, userInfo)) {
            continue;
        }
        uint64_t oldTokenIdEx = 0;
        uint32_t oldTokenId = 0;
        if (hapBaseInfo.instIndex == 0) {
            oldTokenIdEx = userInfo.accessTokenIdEx;
            oldTokenId = userInfo.accessTokenId;
        } else {
            auto it = userInfo.cloneInfos.find(std::to_string(hapBaseInfo.instIndex));
            if (it != userInfo.cloneInfos.end()) {
                oldTokenIdEx = it->second.accessTokenIdEx;
                oldTokenId = it->second.accessTokenId;
            }
        }
        if (oldTokenId != 0 && oldTokenId != newTokenId) {
            if (hapBaseInfo.instIndex == 0) {
                userInfo.accessTokenId = newTokenId;
                userInfo.accessTokenIdEx = newTokenIdEx;
            } else {
                auto it = userInfo.cloneInfos.find(std::to_string(hapBaseInfo.instIndex));
                if (it != userInfo.cloneInfos.end()) {
                    it->second.accessTokenId = newTokenId;
                    it->second.accessTokenIdEx = newTokenIdEx;
                }
            }
            info.AddInnerBundleUserInfo(userInfo);
            dataMgr->UpdateInnerBundleInfo(info);
            LOG_I(BMS_TAG_DEFAULT,
                "Updated token: bundle=%{public}s userId=%{public}d appIndex=%{public}d",
                hapBaseInfo.bundleName.c_str(), hapBaseInfo.userID, hapBaseInfo.instIndex);
        }
    }
}

void BMSEventHandler::BuildRetryList(
    const std::vector<Security::AccessToken::HapBaseInfo> &failedHapList,
    const std::vector<int32_t> &failedUidList,
    const std::vector<Security::AccessToken::MigratedInfo> &migratedList,
    std::vector<Security::AccessToken::MigratedInfo> &retryList)
{
    std::map<std::string, const Security::AccessToken::MigratedInfo*> originalMap;
    for (const auto &m : migratedList) {
        originalMap[m.bundleName] = &m;
    }
    auto findReservedType = [&](const std::string &bn, int32_t userId, int32_t appIndex)
        -> Security::AccessToken::ReservedType {
        auto it = originalMap.find(bn);
        if (it == originalMap.end()) {
            return Security::AccessToken::ReservedType::NONE;
        }
        const auto &orig = *it->second;
        for (size_t k = 0; k < orig.hapBaseInfoList.size() && k < orig.reservedTypeList.size(); ++k) {
            if (orig.hapBaseInfoList[k].userID == userId && orig.hapBaseInfoList[k].instIndex == appIndex) {
                return orig.reservedTypeList[k];
            }
        }
        return Security::AccessToken::ReservedType::NONE;
    };

    std::map<std::string, Security::AccessToken::MigratedInfo> retryMap;
    for (size_t i = 0; i < failedHapList.size(); ++i) {
        const auto &hapInfo = failedHapList[i];
        int32_t uid = failedUidList[i];
        auto origIt = originalMap.find(hapInfo.bundleName);
        auto it = retryMap.find(hapInfo.bundleName);
        if (it == retryMap.end()) {
            Security::AccessToken::MigratedInfo m;
            m.bundleName = hapInfo.bundleName;
            if (origIt != originalMap.end()) {
                m.pathList = origIt->second->pathList;
            }
            m.uidList.emplace_back(uid);
            m.hapBaseInfoList.emplace_back(hapInfo);
            m.reservedTypeList.emplace_back(findReservedType(hapInfo.bundleName, hapInfo.userID, hapInfo.instIndex));
            retryMap[hapInfo.bundleName] = std::move(m);
        } else {
            auto &m = it->second;
            m.uidList.emplace_back(uid);
            m.hapBaseInfoList.emplace_back(hapInfo);
            m.reservedTypeList.emplace_back(findReservedType(hapInfo.bundleName, hapInfo.userID, hapInfo.instIndex));
        }
    }
    for (auto &[bn, m] : retryMap) {
        retryList.emplace_back(std::move(m));
    }
    LOG_I(BMS_TAG_DEFAULT, "MigrationRetry: %{public}zu bundles, %{public}zu entries to retry",
        retryList.size(), failedHapList.size());
}

bool BMSEventHandler::ProcessRetryBatches(const std::shared_ptr<BundleDataMgr> &dataMgr,
    const std::vector<Security::AccessToken::MigratedInfo> &retryList,
    const std::vector<Security::AccessToken::HapBaseInfo> &failedHapList,
    std::vector<bool> &retryResolved)
{
    bool hasIpcFailure = false;
    size_t totalBatches = (retryList.size() + MIGRATION_BATCH_SIZE - 1) / MIGRATION_BATCH_SIZE;
    for (size_t batchStart = 0; batchStart < retryList.size(); batchStart += MIGRATION_BATCH_SIZE) {
        size_t batchEnd = std::min(batchStart + MIGRATION_BATCH_SIZE, retryList.size());
        size_t batchNum = batchStart / MIGRATION_BATCH_SIZE + 1;
        std::vector<Security::AccessToken::MigratedInfo> batch(
            retryList.begin() + static_cast<ptrdiff_t>(batchStart),
            retryList.begin() + static_cast<ptrdiff_t>(batchEnd));
        std::vector<Security::AccessToken::BundleMigrateResult> results;
        int32_t ret = Security::AccessToken::AccessTokenKit::MigrateInstalledBundles(batch, results);
        if (ret != 0) {
            LOG_W(BMS_TAG_DEFAULT, "MigrationRetry: IPC failed ret=%{public}d, aborting retry", ret);
            hasIpcFailure = true;
            break;
        }
        size_t batchSuccess = 0;
        for (size_t j = 0; j < batch.size() && j < results.size(); ++j) {
            if (results[j].errcode != 0) {
                LOG_D(BMS_TAG_DEFAULT, "MigrationRetry: bundle=%{public}s failed errCode=%{public}d",
                    batch[j].bundleName.c_str(), results[j].errcode);
                continue;
            }
            ++batchSuccess;
            const auto &m = batch[j];
            for (size_t k = 0; k < m.hapBaseInfoList.size() && k < m.uidList.size(); ++k) {
                for (size_t i = 0; i < failedHapList.size(); ++i) {
                    if (failedHapList[i].bundleName == m.hapBaseInfoList[k].bundleName &&
                        failedHapList[i].userID == m.hapBaseInfoList[k].userID &&
                        failedHapList[i].instIndex == m.hapBaseInfoList[k].instIndex) {
                        retryResolved[i] = true;
                        break;
                    }
                }
            }
            UpdateTokenIdIfChanged(dataMgr, m, results[j]);
        }
        LOG_I(BMS_TAG_DEFAULT, "MigrationRetry: batch %{public}zu/%{public}zu done, %{public}zu/%{public}zu succeeded",
            batchNum, totalBatches, batchSuccess, batch.size());
    }
    return hasIpcFailure;
}

void BMSEventHandler::UpdateRetrySuccessFlags(
    const std::vector<Security::AccessToken::MigratedInfo> &migratedList,
    std::vector<bool> &successFlags,
    const std::vector<Security::AccessToken::HapBaseInfo> &failedHapList,
    const std::vector<bool> &retryResolved)
{
    for (size_t i = 0; i < migratedList.size(); ++i) {
        if (successFlags[i]) {
            continue;
        }
        if (IsBundleAllResolved(migratedList[i], failedHapList, retryResolved)) {
            successFlags[i] = true;
        }
    }
}

bool BMSEventHandler::RetryMigrationForFailedEntries(
    const std::shared_ptr<BundleDataMgr> &dataMgr,
    std::vector<Security::AccessToken::HapBaseInfo> &failedHapList,
    std::vector<int32_t> &failedUidList,
    std::vector<int32_t> &failedErrCodeList,
    std::vector<bool> &successFlags,
    const std::vector<Security::AccessToken::MigratedInfo> &migratedList)
{
    if (failedHapList.empty()) {
        return false;
    }
    std::vector<Security::AccessToken::MigratedInfo> retryList;
    BuildRetryList(failedHapList, failedUidList, migratedList, retryList);

    std::vector<bool> retryResolved(failedHapList.size(), false);
    bool hasIpcFailure = ProcessRetryBatches(dataMgr, retryList, failedHapList, retryResolved);

    UpdateRetrySuccessFlags(migratedList, successFlags, failedHapList, retryResolved);
    CompactFailedList(failedHapList, failedUidList, failedErrCodeList, retryResolved);

    size_t remaining = failedHapList.size();
    if (remaining > 0) {
        LOG_I(BMS_TAG_DEFAULT, "MigrationRetry: %{public}zu entries still failed after retry", remaining);
    } else {
        LOG_I(BMS_TAG_DEFAULT, "MigrationRetry: all entries resolved");
    }
    return hasIpcFailure;
}

void BMSEventHandler::SplitSystemAndNonSystem(
    const std::vector<Security::AccessToken::MigratedInfo> &migratedList,
    const std::shared_ptr<BundleDataMgr> &dataMgr,
    std::vector<Security::AccessToken::MigratedInfo> &systemApps,
    std::vector<Security::AccessToken::MigratedInfo> &nonSystemApps,
    std::vector<size_t> &systemIndices,
    std::vector<size_t> &nonSystemIndices)
{
    for (size_t i = 0; i < migratedList.size(); ++i) {
        if (IsSystemAppMigration(migratedList[i], dataMgr)) {
            systemApps.emplace_back(migratedList[i]);
            systemIndices.emplace_back(i);
        } else {
            nonSystemApps.emplace_back(migratedList[i]);
            nonSystemIndices.emplace_back(i);
        }
    }
}

namespace {
int32_t MigrateBatchWithRetry(const std::vector<Security::AccessToken::MigratedInfo> &batch,
    std::vector<Security::AccessToken::BundleMigrateResult> &results)
{
    int32_t retry = 0;
    int32_t ret = -1;
    while (retry < MAX_RETRY) {
        results.clear();
        ret = Security::AccessToken::AccessTokenKit::MigrateInstalledBundles(batch, results);
        if (ret == 0 || ret == Security::AccessToken::AccessTokenError::ERR_MIGRATION_COMPLETED) {
            break;
        }
        LOG_W(BMS_TAG_DEFAULT,
            "Migration batch IPC failed (retry %{public}d/%{public}d) ret=%{public}d",
            retry + 1, MAX_RETRY, ret);
        if (retry < MAX_RETRY - 1) {
            int64_t sleepMs = BACKOFF_INTERVALS_MS[retry];
            std::this_thread::sleep_for(std::chrono::milliseconds(sleepMs));
        }
        ++retry;
    }
    return ret;
}
} // anonymous namespace

void BMSEventHandler::ProcessMigrationBatch(
    const std::shared_ptr<BundleDataMgr> &dataMgr,
    std::vector<Security::AccessToken::MigratedInfo> &apps,
    const std::vector<size_t> &indices,
    std::vector<bool> &successFlags,
    std::vector<int32_t> &migratedErrCodes)
{
    size_t totalBatches = (apps.size() + MIGRATION_BATCH_SIZE - 1) / MIGRATION_BATCH_SIZE;
    LOG_I(BMS_TAG_DEFAULT, "MigrationBatch: start %{public}zu bundles in %{public}zu batches",
        apps.size(), totalBatches);
    for (size_t batchStart = 0; batchStart < apps.size(); batchStart += MIGRATION_BATCH_SIZE) {
        size_t batchEnd = std::min(batchStart + MIGRATION_BATCH_SIZE, apps.size());
        std::vector<Security::AccessToken::MigratedInfo> batch(
            apps.begin() + static_cast<ptrdiff_t>(batchStart),
            apps.begin() + static_cast<ptrdiff_t>(batchEnd));
        std::string batchBundleNames;
        for (const auto &m : batch) {
            if (!batchBundleNames.empty()) { batchBundleNames += ","; }
            batchBundleNames += m.bundleName;
        }
        size_t batchNum = batchStart / MIGRATION_BATCH_SIZE + 1;
        LOG_D(BMS_TAG_DEFAULT, "MigrationBatch: batch %{public}zu/%{public}zu bundles: %{public}s",
            batchNum, totalBatches, batchBundleNames.c_str());
        std::vector<Security::AccessToken::BundleMigrateResult> results;
        int32_t ret = MigrateBatchWithRetry(batch, results);
        if (ret != 0) {
            LOG_W(BMS_TAG_DEFAULT, "MigrationBatch: IPC failed after %{public}d retries, skip this batch",
                MAX_RETRY);
            continue;
        }
        size_t batchSuccess = 0;
        for (size_t j = 0; j < batch.size() && j < results.size() && j < indices.size(); ++j) {
            size_t origIdx = indices[batchStart + j];
            successFlags[origIdx] = (results[j].errcode == 0);
            migratedErrCodes[origIdx] = results[j].errcode;
            if (successFlags[origIdx]) {
                ++batchSuccess;
                UpdateTokenIdIfChanged(dataMgr, batch[j], results[j]);
                LOG_D(BMS_TAG_DEFAULT, "MigrationBatch: bundle=%{public}s succeeded",
                    batch[j].bundleName.c_str());
            } else {
                LOG_W(BMS_TAG_DEFAULT, "MigrationBatch: bundle=%{public}s failed errCode=%{public}d",
                    batch[j].bundleName.c_str(), results[j].errcode);
            }
        }
        LOG_I(BMS_TAG_DEFAULT, "MigrationBatch: batch %{public}zu done, %{public}zu/%{public}zu succeeded",
            batchNum, batchSuccess, batch.size());
    }
}

void BMSEventHandler::CollectFailedFromHandshake(
    const std::set<int32_t> &allUidSet,
    const std::unordered_map<int32_t, Security::AccessToken::HapBaseInfo> &allUidToHapInfo,
    std::vector<Security::AccessToken::HapBaseInfo> &failedHapList,
    std::vector<int32_t> &failedUidList,
    std::vector<int32_t> &failedErrCodeList)
{
    std::set<int32_t> unreceivedUids;
    if (!allUidSet.empty()) {
        int32_t checkRet = Security::AccessToken::AccessTokenKit::CheckMigratedUidSet(
            allUidSet, unreceivedUids);
        LOG_I(BMS_TAG_DEFAULT,
            "CheckMigratedUidSet total=%{public}zu unreceived=%{public}zu ret=%{public}d",
            allUidSet.size(), unreceivedUids.size(), checkRet);
    }
    for (int32_t uid : unreceivedUids) {
        auto it = allUidToHapInfo.find(uid);
        if (it == allUidToHapInfo.end()) {
            LOG_W(BMS_TAG_DEFAULT, "Migration: unreceived entry not found in migration data");
            continue;
        }
        failedHapList.emplace_back(it->second);
        failedUidList.emplace_back(uid);
        failedErrCodeList.emplace_back(Security::AccessToken::ERR_MIGRATION_UID_EXISTED);
        LOG_W(BMS_TAG_DEFAULT, "Migration: unreceived entry bundle=%{public}s userId=%{public}d appIndex=%{public}d",
            it->second.bundleName.c_str(), it->second.userID, it->second.instIndex);
    }
}

void BMSEventHandler::CollectFailedFromBatches(
    const std::vector<Security::AccessToken::MigratedInfo> &migratedList,
    const std::vector<bool> &successFlags,
    const std::vector<int32_t> &migratedErrCodes,
    std::vector<Security::AccessToken::HapBaseInfo> &failedHapList,
    std::vector<int32_t> &failedUidList,
    std::vector<int32_t> &failedErrCodeList)
{
    for (size_t i = 0; i < migratedList.size(); ++i) {
        if (successFlags[i]) {
            continue;
        }
        for (size_t k = 0; k < migratedList[i].hapBaseInfoList.size() &&
            k < migratedList[i].uidList.size(); ++k) {
            const auto &hap = migratedList[i].hapBaseInfoList[k];
            int32_t uid = migratedList[i].uidList[k];
            bool alreadyInFailed = false;
            for (const auto &failed : failedHapList) {
                if (failed.bundleName == hap.bundleName &&
                    failed.userID == hap.userID &&
                    failed.instIndex == hap.instIndex) {
                    alreadyInFailed = true;
                    break;
                }
            }
            if (alreadyInFailed) {
                continue;
            }
            failedHapList.emplace_back(hap);
            failedUidList.emplace_back(uid);
            int32_t errCode = migratedErrCodes[i] != 0 ?
                migratedErrCodes[i] : ERR_APPEXECFWK_ACCESS_TOKEN_MIGRATION_FAILED;
            failedErrCodeList.emplace_back(errCode);
            LOG_W(BMS_TAG_DEFAULT,
                "Migration: batch failed bundle=%{public}s userId=%{public}d "
                "appIndex=%{public}d errCode=%{public}d",
                hap.bundleName.c_str(), hap.userID, hap.instIndex, errCode);
        }
    }
}

void BMSEventHandler::RecheckSuccessFlags(
    const std::vector<Security::AccessToken::MigratedInfo> &migratedList,
    std::vector<bool> &successFlags,
    const std::vector<Security::AccessToken::HapBaseInfo> &failedHapList)
{
    size_t successCount = 0;
    for (size_t i = 0; i < migratedList.size(); ++i) {
        successFlags[i] = !HasFailedEntry(migratedList[i], failedHapList);
        if (successFlags[i]) {
            ++successCount;
        }
    }
    LOG_I(BMS_TAG_DEFAULT, "Migration: recheck done, %{public}zu/%{public}zu bundles succeeded",
        successCount, migratedList.size());
}

bool BMSEventHandler::ExecuteMigrationWithRetry(
    const std::shared_ptr<BundleDataMgr> &dataMgr,
    std::vector<Security::AccessToken::MigratedInfo> &migratedList,
    std::vector<bool> &successFlags,
    const std::set<int32_t> &allUidSet,
    const std::unordered_map<int32_t, Security::AccessToken::HapBaseInfo> &allUidToHapInfo,
    std::vector<Security::AccessToken::HapBaseInfo> &failedHapList,
    std::vector<int32_t> &failedUidList,
    std::vector<int32_t> &failedErrCodeList)
{
    successFlags.assign(migratedList.size(), false);
    std::vector<int32_t> migratedErrCodes(migratedList.size(), 0);

    std::vector<Security::AccessToken::MigratedInfo> systemApps;
    std::vector<Security::AccessToken::MigratedInfo> nonSystemApps;
    std::vector<size_t> systemIndices;
    std::vector<size_t> nonSystemIndices;
    SplitSystemAndNonSystem(migratedList, dataMgr,
        systemApps, nonSystemApps, systemIndices, nonSystemIndices);
    LOG_I(BMS_TAG_DEFAULT, "Migration: split %{public}zu system + %{public}zu non-system apps",
        systemApps.size(), nonSystemApps.size());

    LOG_I(BMS_TAG_DEFAULT, "Migration: start system app batches");
    ProcessMigrationBatch(dataMgr, systemApps, systemIndices, successFlags, migratedErrCodes);
    LOG_I(BMS_TAG_DEFAULT, "Migration: start non-system app batches");
    ProcessMigrationBatch(dataMgr, nonSystemApps, nonSystemIndices, successFlags, migratedErrCodes);

    CollectFailedFromHandshake(allUidSet, allUidToHapInfo, failedHapList, failedUidList, failedErrCodeList);
    CollectFailedFromBatches(migratedList, successFlags, migratedErrCodes, failedHapList, failedUidList,
        failedErrCodeList);

    LOG_I(BMS_TAG_DEFAULT, "Migration: failed entries after batch+handshake: %{public}zu",
        failedHapList.size());

    RecheckSuccessFlags(migratedList, successFlags, failedHapList);

    bool hasIpcFailure = RetryMigrationForFailedEntries(dataMgr, failedHapList, failedUidList,
        failedErrCodeList, successFlags, migratedList);
    if (hasIpcFailure) {
        LOG_E(BMS_TAG_DEFAULT, "Migration: aborted after retry, %{public}zu entries unresolved",
            failedHapList.size());
        ReportMigrationEvent(failedHapList, failedUidList, failedErrCodeList,
            ERR_APPEXECFWK_ACCESS_TOKEN_MIGRATION_FAILED);
        return false;
    }
    LOG_I(BMS_TAG_DEFAULT, "Migration: retry complete, %{public}zu entries still failed",
        failedHapList.size());

    ReportMigrationEvent(failedHapList, failedUidList, failedErrCodeList,
        ERR_APPEXECFWK_ACCESS_TOKEN_MIGRATION_FAILED);
    return true;
}

namespace {
struct FailedEntryCollector {
    std::vector<Security::AccessToken::HapBaseInfo> &hapList;
    std::vector<int32_t> &uidList;
    std::vector<int32_t> &errCodeList;
};

struct UpdatePayload {
    int32_t resolvedUid;
    uint32_t existingTokenId;
    uint64_t existingTokenIdEx;
    bool uidChanged;
};

void CollectBundleUserInfosForFallback(const std::string &bundleName,
    const InnerBundleUserInfo &userInfo,
    Security::AccessToken::MigratedInfo &m,
    FailedEntryCollector &failed)
{
    int32_t userId = userInfo.bundleUserInfo.userId;
    m.uidList.emplace_back(userInfo.uid);
    m.hapBaseInfoList.emplace_back(Security::AccessToken::HapBaseInfo{userId, bundleName, 0});
    m.reservedTypeList.emplace_back(Security::AccessToken::ReservedType::NONE);
    failed.hapList.emplace_back(Security::AccessToken::HapBaseInfo{userId, bundleName, 0});
    failed.uidList.emplace_back(userInfo.uid);
    failed.errCodeList.emplace_back(ERR_APPEXECFWK_ACCESS_TOKEN_MIGRATION_FAILED);
    for (const auto &[appIndexStr, cloneInfo] : userInfo.cloneInfos) {
        int32_t appIndex = 0;
        if (!OHOS::StrToInt(appIndexStr, appIndex) || appIndex <= 0) {
            continue;
        }
        m.uidList.emplace_back(cloneInfo.uid);
        m.hapBaseInfoList.emplace_back(
            Security::AccessToken::HapBaseInfo{cloneInfo.userId, bundleName, appIndex});
        m.reservedTypeList.emplace_back(Security::AccessToken::ReservedType::NONE);
        failed.hapList.emplace_back(
            Security::AccessToken::HapBaseInfo{cloneInfo.userId, bundleName, appIndex});
        failed.uidList.emplace_back(cloneInfo.uid);
        failed.errCodeList.emplace_back(ERR_APPEXECFWK_ACCESS_TOKEN_MIGRATION_FAILED);
    }
}

void CollectSandboxUserInfosForFallback(int32_t sandboxAppIndex,
    const InnerBundleInfo &sandboxInfo,
    Security::AccessToken::MigratedInfo &m,
    FailedEntryCollector &failed)
{
    std::string bn = sandboxInfo.GetBundleName();
    for (const auto &[uk, sui] : sandboxInfo.GetInnerBundleUserInfos()) {
        int32_t userId = sui.bundleUserInfo.userId;
        m.uidList.emplace_back(sui.uid);
        m.hapBaseInfoList.emplace_back(
            Security::AccessToken::HapBaseInfo{userId, bn, sandboxAppIndex});
        m.reservedTypeList.emplace_back(Security::AccessToken::ReservedType::NONE);
        failed.hapList.emplace_back(
            Security::AccessToken::HapBaseInfo{userId, bn, sandboxAppIndex});
        failed.uidList.emplace_back(sui.uid);
        failed.errCodeList.emplace_back(ERR_APPEXECFWK_ACCESS_TOKEN_MIGRATION_FAILED);
    }
}

void GetTokenIdFromUserInfo(const Security::AccessToken::HapBaseInfo &hapInfo,
    const InnerBundleUserInfo &userInfo,
    uint32_t &existingTokenId, uint64_t &existingTokenIdEx)
{
    if (hapInfo.instIndex == 0) {
        existingTokenId = userInfo.accessTokenId;
        existingTokenIdEx = userInfo.accessTokenIdEx;
        return;
    }
    auto cloneIt = userInfo.cloneInfos.find(std::to_string(hapInfo.instIndex));
    if (cloneIt != userInfo.cloneInfos.end()) {
        existingTokenId = cloneIt->second.accessTokenId;
        existingTokenIdEx = cloneIt->second.accessTokenIdEx;
    }
}

void FindTokenInSandboxUserInfos(const InnerBundleInfo &sandboxInfo,
    const Security::AccessToken::HapBaseInfo &hapInfo,
    uint32_t &existingTokenId, uint64_t &existingTokenIdEx)
{
    for (const auto &[uk, sui] : sandboxInfo.GetInnerBundleUserInfos()) {
        if (sui.bundleUserInfo.userId == hapInfo.userID) {
            existingTokenId = sui.accessTokenId;
            existingTokenIdEx = sui.accessTokenIdEx;
            break;
        }
    }
}

void SearchSandboxForTokenId(const std::shared_ptr<BundleDataMgr> &dataMgr,
    const Security::AccessToken::HapBaseInfo &hapInfo,
    uint32_t &existingTokenId, uint64_t &existingTokenIdEx)
{
    auto sandboxHelper = dataMgr->GetSandboxAppHelper();
    if (sandboxHelper == nullptr) {
        return;
    }
    auto sandboxMap = sandboxHelper->GetSandboxAppInfoMap();
    for (const auto &[key, sandboxInfo] : sandboxMap) {
        if (sandboxInfo.GetBundleName() != hapInfo.bundleName) {
            continue;
        }
        int32_t sandboxAppIndex = 0;
        auto pos = key.find(Constants::FILE_UNDERLINE);
        if (pos != std::string::npos) {
            OHOS::StrToInt(key.substr(0, pos), sandboxAppIndex);
        }
        if (sandboxAppIndex != hapInfo.instIndex) {
            continue;
        }
        FindTokenInSandboxUserInfos(sandboxInfo, hapInfo, existingTokenId, existingTokenIdEx);
        break;
    }
}

void UpdateMainUserInfo(InnerBundleUserInfo &userInfo, const UpdatePayload &payload)
{
    if (payload.uidChanged) {
        auto oldUid = userInfo.uid;
        userInfo.uid = payload.resolvedUid;
        auto gidIt = std::find(userInfo.gids.begin(), userInfo.gids.end(), oldUid);
        if (gidIt != userInfo.gids.end()) {
            *gidIt = payload.resolvedUid;
        } else {
            userInfo.gids.emplace_back(payload.resolvedUid);
        }
    }
    userInfo.accessTokenId = payload.existingTokenId;
    userInfo.accessTokenIdEx = payload.existingTokenIdEx;
}

void UpdateCloneUserInfo(int32_t instIndex,
    InnerBundleUserInfo &userInfo, const UpdatePayload &payload)
{
    auto cloneIt = userInfo.cloneInfos.find(std::to_string(instIndex));
    if (cloneIt == userInfo.cloneInfos.end()) {
        return;
    }
    if (payload.uidChanged) {
        auto oldUid = cloneIt->second.uid;
        cloneIt->second.uid = payload.resolvedUid;
        auto gidIt = std::find(cloneIt->second.gids.begin(), cloneIt->second.gids.end(), oldUid);
        if (gidIt != cloneIt->second.gids.end()) {
            *gidIt = payload.resolvedUid;
        } else {
            cloneIt->second.gids.emplace_back(payload.resolvedUid);
        }
    }
    cloneIt->second.accessTokenId = payload.existingTokenId;
    cloneIt->second.accessTokenIdEx = payload.existingTokenIdEx;
}

void UpdateSandboxUserInfo(InnerBundleUserInfo &sandboxUserInfo, const UpdatePayload &payload)
{
    if (payload.uidChanged) {
        auto oldUid = sandboxUserInfo.uid;
        sandboxUserInfo.uid = payload.resolvedUid;
        auto gidIt = std::find(sandboxUserInfo.gids.begin(), sandboxUserInfo.gids.end(), oldUid);
        if (gidIt != sandboxUserInfo.gids.end()) {
            *gidIt = payload.resolvedUid;
        } else {
            sandboxUserInfo.gids.emplace_back(payload.resolvedUid);
        }
    }
    sandboxUserInfo.accessTokenId = payload.existingTokenId;
    sandboxUserInfo.accessTokenIdEx = payload.existingTokenIdEx;
}

void TryUpdateSandboxUserInfo(const std::shared_ptr<BundleDataMgr> &dataMgr,
    const Security::AccessToken::HapBaseInfo &hapInfo, const UpdatePayload &payload)
{
    auto sandboxHelper = dataMgr->GetSandboxAppHelper();
    if (sandboxHelper == nullptr) {
        return;
    }
    InnerBundleInfo sandboxInfo;
    int32_t sandboxUserId = hapInfo.userID;
    if (sandboxHelper->GetSandboxAppInfo(
        hapInfo.bundleName, hapInfo.instIndex, sandboxUserId, sandboxInfo) != ERR_OK) {
        return;
    }
    InnerBundleUserInfo sandboxUserInfo;
    if (!sandboxInfo.GetInnerBundleUserInfo(hapInfo.userID, sandboxUserInfo)) {
        return;
    }
    UpdateSandboxUserInfo(sandboxUserInfo, payload);
    sandboxInfo.AddInnerBundleUserInfo(sandboxUserInfo);
    sandboxHelper->SaveSandboxAppInfo(sandboxInfo, hapInfo.instIndex);
}

const Security::AccessToken::MigratedInfo* FindMigratedInfo(
    const std::vector<Security::AccessToken::MigratedInfo> &migratedList,
    const std::string &bundleName)
{
    for (const auto &m : migratedList) {
        if (m.bundleName == bundleName) {
            return &m;
        }
    }
    return nullptr;
}

bool PrepareSpmFallbackSession(const InnerBundleInfo &info,
    const Security::AccessToken::MigratedInfo *migratedInfo, int32_t &sessionId)
{
    Security::AccessToken::BundleHapList hapList;
    hapList.hapPaths = migratedInfo ? migratedInfo->pathList.hapPaths : info.GetAllHapPaths();
    hapList.isPreInstalled = info.IsPreInstallApp();
    hapList.userIdForEnterpriseSign = info.GetUserId();
    std::vector<Security::AccessToken::TrustedBundleInfo> trustedBundleInfos;
    Security::AccessToken::HapVerifyResultInfo resultInfo;
    int32_t signRet = Security::AccessToken::AccessTokenKit::CheckHapSignInfo(
        hapList, Security::AccessToken::QUERY_PROFILE,
        sessionId, trustedBundleInfos, resultInfo);
    if (signRet != 0) {
        LOG_E(BMS_TAG_DEFAULT, "Fallback: CheckHapSignInfo failed ret=%{public}d", signRet);
        if (sessionId != 0) {
            Security::AccessToken::AccessTokenKit::FinishInstall(sessionId, false, {});
        }
        return false;
    }
    // Identity mode of the re-sign session: the migration entry carries it
    // (moved from pathList.mode); a bundle without one falls back to the same
    // per-variant rule the migration builders use.
    Security::AccessToken::MultipleMode mode = migratedInfo != nullptr
        ? migratedInfo->mode
        : (info.IsDualModeCloneApp()
            ? Security::AccessToken::MultipleMode::SUB_MODE
            : Security::AccessToken::MultipleMode::DEFAULT_OR_MAIN_MODE);
    Security::AccessToken::HapInfoCheckResult permResult;
    int32_t permRet = Security::AccessToken::AccessTokenKit::CheckHapPermissionInfo(
        sessionId, Security::AccessToken::InstallTypeEnum::TYPE_REPLACE, mode, permResult);
    if (permRet != 0) {
        LOG_E(BMS_TAG_DEFAULT, "Fallback: CheckHapPermissionInfo failed sessionId=%{public}d ret=%{public}d",
            sessionId, permRet);
        Security::AccessToken::AccessTokenKit::FinishInstall(sessionId, false, {});
        return false;
    }
    return true;
}

void BuildModulePathMap(const Security::AccessToken::MigratedInfo *migratedInfo,
    std::map<std::string, std::string> &modulePathMap)
{
    if (migratedInfo == nullptr) {
        return;
    }
    for (size_t k = 0; k < migratedInfo->pathList.hapPaths.size(); ++k) {
        modulePathMap[migratedInfo->pathList.hapPaths[k]] = "";
    }
}

void MarkBundleCheckBySpm(const std::shared_ptr<BundleDataMgr> &dataMgr,
    const std::string &bundleName)
{
    dataMgr->UpdateUninstallBundleCheckBySpm(bundleName, true);
    InnerBundleInfo updateInfo;
    if (dataMgr->FetchInnerBundleInfo(bundleName, updateInfo)) {
        updateInfo.SetBundleCheckBySpm(true);
        dataMgr->UpdateInnerBundleInfo(updateInfo);
        LOG_D(BMS_TAG_DEFAULT, "Fallback: bundle=%{public}s marked checkBySpm=true",
            bundleName.c_str());
    }
}

void GroupFailedByBundle(const std::shared_ptr<BundleDataMgr> &dataMgr,
    const std::vector<Security::AccessToken::HapBaseInfo> &failedHapList,
    std::map<std::string, std::vector<size_t>> &bundleToIndices)
{
    size_t uninstalledCount = 0;
    for (size_t i = 0; i < failedHapList.size(); ++i) {
        InnerBundleInfo info;
        if (!dataMgr->FetchInnerBundleInfo(failedHapList[i].bundleName, info)) {
            LOG_W(BMS_TAG_DEFAULT, "Fallback: bundle=%{public}s uninstalled, mark checkBySpm=false",
                failedHapList[i].bundleName.c_str());
            dataMgr->UpdateUninstallBundleCheckBySpm(failedHapList[i].bundleName, false);
            ++uninstalledCount;
            continue;
        }
        bundleToIndices[failedHapList[i].bundleName].emplace_back(i);
    }
    LOG_I(BMS_TAG_DEFAULT,
        "Fallback: grouped %{public}zu entries into %{public}zu bundles, %{public}zu uninstalled",
        failedHapList.size(), bundleToIndices.size(), uninstalledCount);
}
} // anonymous namespace

void BMSEventHandler::CollectUnmigratedMainAndClone(
    const std::shared_ptr<BundleDataMgr> &dataMgr,
    std::vector<Security::AccessToken::HapBaseInfo> &failedHapList,
    std::vector<int32_t> &failedUidList,
    std::vector<int32_t> &failedErrCodeList,
    std::map<std::string, Security::AccessToken::MigratedInfo> &failedMigratedMap)
{
    auto bundleNames = dataMgr->GetAllBundleName();
    size_t entryBefore = failedHapList.size();
    size_t skippedCount = 0;
    FailedEntryCollector failed{failedHapList, failedUidList, failedErrCodeList};
    LOG_I(BMS_TAG_DEFAULT, "FallbackCheck: collecting main+clone from %{public}zu bundles",
        bundleNames.size());
    for (const auto &bundleName : bundleNames) {
        InnerBundleInfo info;
        if (!dataMgr->FetchInnerBundleInfo(bundleName, info)) {
            continue;
        }
        if (info.IsBundleCheckBySpm()) {
            ++skippedCount;
            continue;
        }
        auto &m = failedMigratedMap[bundleName];
        m.bundleName = bundleName;
        m.pathList.hapPaths = info.GetAllHapPaths();
        m.pathList.isPreInstalled = info.IsPreInstallApp();
        m.pathList.userIdForEnterpriseSign = info.GetUserId();
        m.mode = info.IsDualModeCloneApp()
            ? Security::AccessToken::MultipleMode::SUB_MODE
            : Security::AccessToken::MultipleMode::DEFAULT_OR_MAIN_MODE;
        for (const auto &[userIdStr, userInfo] : info.GetInnerBundleUserInfos()) {
            CollectBundleUserInfosForFallback(bundleName, userInfo, m, failed);
        }
    }
    LOG_I(BMS_TAG_DEFAULT,
        "FallbackCheck: main+clone done, %{public}zu entries in %{public}zu bundles, %{public}zu already migrated",
        failedHapList.size() - entryBefore, failedMigratedMap.size(), skippedCount);
}

void BMSEventHandler::CollectUnmigratedSandbox(
    const std::shared_ptr<BundleDataMgr> &dataMgr,
    std::vector<Security::AccessToken::HapBaseInfo> &failedHapList,
    std::vector<int32_t> &failedUidList,
    std::vector<int32_t> &failedErrCodeList,
    std::map<std::string, Security::AccessToken::MigratedInfo> &failedMigratedMap)
{
    auto sandboxHelper = dataMgr->GetSandboxAppHelper();
    if (sandboxHelper == nullptr) {
        LOG_D(BMS_TAG_DEFAULT, "FallbackCheck: sandbox helper null, skip sandbox collection");
        return;
    }
    auto sandboxMap = sandboxHelper->GetSandboxAppInfoMap();
    size_t entryBefore = failedHapList.size();
    FailedEntryCollector failed{failedHapList, failedUidList, failedErrCodeList};
    LOG_I(BMS_TAG_DEFAULT, "FallbackCheck: collecting sandbox from %{public}zu sandbox apps",
        sandboxMap.size());
    for (const auto &[key, sandboxInfo] : sandboxMap) {
        std::string bn = sandboxInfo.GetBundleName();
        auto mapIt = failedMigratedMap.find(bn);
        if (mapIt == failedMigratedMap.end()) {
            continue;
        }
        int32_t sandboxAppIndex = 0;
        auto pos = key.find(Constants::FILE_UNDERLINE);
        if (pos != std::string::npos) {
            OHOS::StrToInt(key.substr(0, pos), sandboxAppIndex);
        }
        CollectSandboxUserInfosForFallback(sandboxAppIndex, sandboxInfo,
            mapIt->second, failed);
    }
    LOG_I(BMS_TAG_DEFAULT, "FallbackCheck: sandbox done, added %{public}zu entries",
        failedHapList.size() - entryBefore);
}

void BMSEventHandler::CheckAndFallbackUnmigratedBundles()
{
    LOG_I(BMS_TAG_DEFAULT, "FallbackCheck: start checking unmigrated bundles");
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "FallbackCheck: DataMgr is nullptr");
        return;
    }
    std::vector<Security::AccessToken::HapBaseInfo> failedHapList;
    std::vector<int32_t> failedUidList;
    std::vector<int32_t> failedErrCodeList;
    std::map<std::string, Security::AccessToken::MigratedInfo> failedMigratedMap;

    CollectUnmigratedMainAndClone(dataMgr, failedHapList, failedUidList, failedErrCodeList, failedMigratedMap);
    CollectUnmigratedSandbox(dataMgr, failedHapList, failedUidList, failedErrCodeList, failedMigratedMap);

    if (failedHapList.empty()) {
        LOG_I(BMS_TAG_DEFAULT, "CheckAndFallbackUnmigratedBundles: all bundles migrated");
        return;
    }
    LOG_I(BMS_TAG_DEFAULT, "CheckAndFallbackUnmigratedBundles: %{public}zu unmigrated entries",
        failedHapList.size());
    std::vector<Security::AccessToken::MigratedInfo> failedMigratedList;
    for (auto &[bn, m] : failedMigratedMap) {
        failedMigratedList.emplace_back(std::move(m));
    }
    std::vector<bool> successFlags(failedMigratedList.size(), false);
    FallbackWithSpmSession(dataMgr, failedHapList, failedUidList, failedErrCodeList,
        successFlags, failedMigratedList);
    LOG_I(BMS_TAG_DEFAULT, "FallbackCheck: done");
}

// ── SPM fallback ──

bool BMSEventHandler::GetExistingTokenId(const std::shared_ptr<BundleDataMgr> &dataMgr,
    const InnerBundleInfo &info,
    const Security::AccessToken::HapBaseInfo &hapInfo,
    const InnerBundleUserInfo &userInfo,
    uint32_t &existingTokenId,
    uint64_t &existingTokenIdEx,
    int32_t &dlpType)
{
    dlpType = 0;
    GetTokenIdFromUserInfo(hapInfo, userInfo, existingTokenId, existingTokenIdEx);
    if (existingTokenId == 0) {
        SearchSandboxForTokenId(dataMgr, hapInfo, existingTokenId, existingTokenIdEx);
    }
    if (existingTokenId == 0) {
        return false;
    }
    Security::AccessToken::HapTokenInfo tokenInfo;
    int32_t ret = Security::AccessToken::AccessTokenKit::GetHapTokenInfo(existingTokenId, tokenInfo);
    if (ret == 0) {
        dlpType = tokenInfo.dlpType;
    }
    return true;
}

void BMSEventHandler::UpdateBundleInfoAfterFallback(
    const std::shared_ptr<BundleDataMgr> &dataMgr,
    const std::string &bundleName,
    const Security::AccessToken::HapBaseInfo &hapInfo,
    int32_t resolvedUid,
    uint32_t existingTokenId,
    uint64_t existingTokenIdEx,
    bool uidChanged)
{
    InnerBundleInfo info;
    if (!dataMgr->FetchInnerBundleInfo(bundleName, info)) {
        LOG_W(BMS_TAG_DEFAULT, "Fallback: bundle=%{public}s update info failed, bundle not found",
            bundleName.c_str());
        return;
    }
    InnerBundleUserInfo userInfo;
    if (!info.GetInnerBundleUserInfo(hapInfo.userID, userInfo)) {
        LOG_W(BMS_TAG_DEFAULT, "Fallback: bundle=%{public}s userId=%{public}d userInfo not found",
            bundleName.c_str(), hapInfo.userID);
        return;
    }
    UpdatePayload payload{resolvedUid, existingTokenId, existingTokenIdEx, uidChanged};
    if (hapInfo.instIndex == 0) {
        UpdateMainUserInfo(userInfo, payload);
    } else {
        UpdateCloneUserInfo(hapInfo.instIndex, userInfo, payload);
    }
    info.AddInnerBundleUserInfo(userInfo);
    dataMgr->UpdateInnerBundleInfo(info);
    if (hapInfo.instIndex > 0) {
        TryUpdateSandboxUserInfo(dataMgr, hapInfo, payload);
    }
}

void BMSEventHandler::CollectFallbackPendingResults(
    const std::shared_ptr<BundleDataMgr> &dataMgr,
    const InnerBundleInfo &info,
    const std::vector<size_t> &indices,
    std::vector<Security::AccessToken::HapBaseInfo> &failedHapList,
    std::vector<int32_t> &failedUidList,
    int32_t sessionId,
    std::vector<FallbackResult> &pendingResults)
{
    for (size_t idx : indices) {
        const auto &hapInfo = failedHapList[idx];
        int32_t oldUid = failedUidList[idx];
        InnerBundleUserInfo userInfo;
        if (!info.GetInnerBundleUserInfo(hapInfo.userID, userInfo)) {
            LOG_W(BMS_TAG_DEFAULT, "Fallback: bundle=%{public}s userId=%{public}d not found in InnerBundleUserInfo",
                info.GetBundleName().c_str(), hapInfo.userID);
            continue;
        }
        uint32_t existingTokenId = 0;
        uint64_t existingTokenIdEx = 0;
        int32_t dlpType = 0;
        if (!GetExistingTokenId(dataMgr, info, hapInfo, userInfo, existingTokenId, existingTokenIdEx, dlpType)) {
            LOG_W(BMS_TAG_DEFAULT, "Fallback: bundle=%{public}s appIndex=%{public}d no tokenId found, skip",
                info.GetBundleName().c_str(), hapInfo.instIndex);
            continue;
        }
        Security::AccessToken::BundlePolicy policy = BundleSpmManager::CreateBundlePolicy(
            info, dlpType,
            info.GetBaseApplicationInfo().appProvisionType == Constants::APP_PROVISION_TYPE_DEBUG);
        int32_t resolvedUid = oldUid;
        // UpdateHapPolicy takes AccessTokenIDEx as an in/out parameter (AT PR
        // #5133): the low 32 bits locate the token and the high 32 bits come
        // back refreshed (same source as the FinishInstall commit value), so the
        // AT-refreshed tokenAttr is what gets persisted below.
        Security::AccessToken::AccessTokenIDEx tokenIdEx;
        tokenIdEx.tokenIDEx = existingTokenIdEx;
        int32_t policyRet = Security::AccessToken::AccessTokenKit::UpdateHapPolicy(
            sessionId, tokenIdEx, policy, resolvedUid);
        if (policyRet != 0) {
            LOG_E(BMS_TAG_DEFAULT,
                "Fallback: bundle=%{public}s userId=%{public}d appIndex=%{public}d "
                "UpdateHapPolicy failed ret=%{public}d",
                info.GetBundleName().c_str(), hapInfo.userID, hapInfo.instIndex, policyRet);
            continue;
        }
        bool uidChanged = (resolvedUid != 0 && resolvedUid != oldUid);
        pendingResults.push_back({idx, hapInfo, resolvedUid, existingTokenId,
            tokenIdEx.tokenIDEx, uidChanged});
    }
}

void BMSEventHandler::ApplySingleFallbackResult(
    const std::shared_ptr<BundleDataMgr> &dataMgr,
    const std::string &bundleName,
    InnerBundleInfo &info,
    const FallbackResult &r,
    std::vector<int32_t> &failedUidList,
    std::vector<bool> &resolved)
{
    resolved[r.idx] = true;
    if (r.uidChanged) {
        bool isSandbox = false;
        auto sandboxHelper = dataMgr->GetSandboxAppHelper();
        if (sandboxHelper != nullptr && r.hapInfo.instIndex > 0) {
            InnerBundleInfo sandboxInfo;
            int32_t sandboxUserId = r.hapInfo.userID;
            isSandbox = (sandboxHelper->GetSandboxAppInfo(bundleName, r.hapInfo.instIndex,
                sandboxUserId, sandboxInfo) == ERR_OK);
        }
        if (isSandbox) {
            dataMgr->UpdateSandboxBundleUid(bundleName, r.hapInfo.userID,
                r.hapInfo.instIndex, failedUidList[r.idx], r.resolvedUid);
        } else {
            dataMgr->UpdateBundleUid(bundleName, r.hapInfo.userID,
                r.hapInfo.instIndex, failedUidList[r.idx], r.resolvedUid, info.IsDualModeCloneApp());
        }
    }
    UpdateBundleInfoAfterFallback(dataMgr, bundleName, r.hapInfo,
        r.resolvedUid, r.existingTokenId, r.existingTokenIdEx, r.uidChanged);
    LOG_I(BMS_TAG_DEFAULT,
        "Fallback: bundle=%{public}s userId=%{public}d appIndex=%{public}d "
        "succeeded, uid %{public}s",
        bundleName.c_str(), r.hapInfo.userID, r.hapInfo.instIndex,
        r.uidChanged ? "changed" : "unchanged");
}

void BMSEventHandler::CommitFallbackResults(
    const std::shared_ptr<BundleDataMgr> &dataMgr,
    const std::string &bundleName,
    InnerBundleInfo &info,
    const Security::AccessToken::MigratedInfo *migratedInfo,
    int32_t sessionId,
    std::vector<FallbackResult> &pendingResults,
    std::vector<int32_t> &failedUidList,
    std::vector<bool> &resolved)
{
    std::map<std::string, std::string> modulePathMap;
    BuildModulePathMap(migratedInfo, modulePathMap);
    int32_t finishRet = Security::AccessToken::AccessTokenKit::FinishInstall(
        sessionId, true, modulePathMap);
    if (finishRet != 0) {
        LOG_E(BMS_TAG_DEFAULT, "Fallback: bundle=%{public}s FinishInstall failed ret=%{public}d, rollback session",
            bundleName.c_str(), finishRet);
        Security::AccessToken::AccessTokenKit::FinishInstall(sessionId, false, {});
        return;
    }
    LOG_I(BMS_TAG_DEFAULT, "Fallback: bundle=%{public}s FinishInstall succeeded, applying %{public}zu results",
        bundleName.c_str(), pendingResults.size());
    for (const auto &r : pendingResults) {
        ApplySingleFallbackResult(dataMgr, bundleName, info, r, failedUidList, resolved);
    }
}

void BMSEventHandler::ProcessBundleFallback(
    const std::shared_ptr<BundleDataMgr> &dataMgr,
    const std::string &bundleName,
    const std::vector<size_t> &indices,
    std::vector<Security::AccessToken::HapBaseInfo> &failedHapList,
    std::vector<int32_t> &failedUidList,
    std::vector<bool> &resolved,
    const std::vector<Security::AccessToken::MigratedInfo> &migratedList)
{
    LOG_I(BMS_TAG_DEFAULT, "Fallback: start bundle=%{public}s entries=%{public}zu",
        bundleName.c_str(), indices.size());
    InnerBundleInfo info;
    if (!dataMgr->FetchInnerBundleInfo(bundleName, info)) {
        LOG_W(BMS_TAG_DEFAULT, "Fallback: bundle=%{public}s not found, skip", bundleName.c_str());
        return;
    }
    const Security::AccessToken::MigratedInfo *migratedInfo = FindMigratedInfo(migratedList, bundleName);
    int32_t sessionId = 0;
    if (!PrepareSpmFallbackSession(info, migratedInfo, sessionId)) {
        LOG_E(BMS_TAG_DEFAULT, "Fallback: bundle=%{public}s SPM session failed", bundleName.c_str());
        return;
    }
    LOG_I(BMS_TAG_DEFAULT, "Fallback: bundle=%{public}s sessionId=%{public}d", bundleName.c_str(), sessionId);
    std::vector<FallbackResult> pendingResults;
    CollectFallbackPendingResults(dataMgr, info, indices,
        failedHapList, failedUidList, sessionId, pendingResults);
    LOG_I(BMS_TAG_DEFAULT, "Fallback: bundle=%{public}s collected %{public}zu pending results",
        bundleName.c_str(), pendingResults.size());
    CommitFallbackResults(dataMgr, bundleName, info, migratedInfo,
        sessionId, pendingResults, failedUidList, resolved);
}

void BMSEventHandler::UpdateSuccessFlagsAndCheckBySpm(
    const std::shared_ptr<BundleDataMgr> &dataMgr,
    const std::vector<Security::AccessToken::MigratedInfo> &migratedList,
    std::vector<bool> &successFlags,
    const std::vector<Security::AccessToken::HapBaseInfo> &failedHapList,
    const std::vector<bool> &resolved)
{
    size_t markedCount = 0;
    for (size_t i = 0; i < migratedList.size(); ++i) {
        if (successFlags[i]) {
            continue;
        }
        if (!IsBundleAllResolved(migratedList[i], failedHapList, resolved)) {
            continue;
        }
        successFlags[i] = true;
        MarkBundleCheckBySpm(dataMgr, migratedList[i].bundleName);
        ++markedCount;
    }
    LOG_I(BMS_TAG_DEFAULT, "Fallback: marked %{public}zu bundles as checkBySpm", markedCount);
}

void BMSEventHandler::FallbackWithSpmSession(
    const std::shared_ptr<BundleDataMgr> &dataMgr,
    std::vector<Security::AccessToken::HapBaseInfo> &failedHapList,
    std::vector<int32_t> &failedUidList,
    std::vector<int32_t> &failedErrCodeList,
    std::vector<bool> &successFlags,
    const std::vector<Security::AccessToken::MigratedInfo> &migratedList)
{
    if (failedHapList.empty()) {
        return;
    }
    LOG_I(BMS_TAG_DEFAULT, "Fallback: start, %{public}zu failed entries", failedHapList.size());
    std::vector<bool> resolved(failedHapList.size(), false);
    std::map<std::string, std::vector<size_t>> bundleToIndices;
    GroupFailedByBundle(dataMgr, failedHapList, bundleToIndices);
    LOG_I(BMS_TAG_DEFAULT, "Fallback: grouped into %{public}zu bundles", bundleToIndices.size());
    for (const auto &[bundleName, indices] : bundleToIndices) {
        ProcessBundleFallback(dataMgr, bundleName, indices,
            failedHapList, failedUidList, resolved, migratedList);
    }
    UpdateSuccessFlagsAndCheckBySpm(dataMgr, migratedList, successFlags, failedHapList, resolved);
    CompactFailedList(failedHapList, failedUidList, failedErrCodeList, resolved);
    size_t stillFailed = failedHapList.size();
    LOG_I(BMS_TAG_DEFAULT, "Fallback: done, %{public}zu resolved, %{public}zu still failed",
        resolved.size() - stillFailed, stillFailed);
}
}  // namespace AppExecFwk
}  // namespace OHOS
