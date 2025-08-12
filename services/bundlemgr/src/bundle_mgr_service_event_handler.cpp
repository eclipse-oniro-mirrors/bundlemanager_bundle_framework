/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include <sstream>
#include <sys/stat.h>

#include "account_helper.h"
#include "aot/aot_handler.h"
#include "app_log_tag_wrapper.h"
#include "app_provision_info_manager.h"
#include "app_service_fwk_installer.h"
#include "bms_extension_data_mgr.h"
#include "bms_key_event_mgr.h"
#include "bundle_installer.h"
#include "bundle_parser.h"
#include "bundle_permission_mgr.h"
#include "bundle_resource_helper.h"
#include "bundle_scanner.h"
#include "on_demand_install_data_mgr.h"
#ifdef CONFIG_POLOCY_ENABLE
#include "config_policy_utils.h"
#endif
#include "datetime_ex.h"
#include "directory_ex.h"
#if defined (BUNDLE_FRAMEWORK_SANDBOX_APP) && defined (DLP_PERMISSION_ENABLE)
#include "dlp_permission_kit.h"
#endif
#include "hmp_bundle_installer.h"
#include "inner_patch_info.h"
#include "installd_client.h"
#include "install_exception_mgr.h"
#include "parameter.h"
#include "parameters.h"
#include "patch_data_mgr.h"
#include "perf_profile.h"
#ifdef WINDOW_ENABLE
#include "scene_board_judgement.h"
#endif
#include "status_receiver_host.h"
#include "system_bundle_installer.h"
#ifdef BUNDLE_FRAMEWORK_QUICK_FIX
#include "quick_fix_boot_scanner.h"
#endif
#include "user_unlocked_event_subscriber.h"
#ifdef STORAGE_SERVICE_ENABLE
#include "storage_manager_proxy.h"
#include "iservice_registry.h"
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
constexpr const char* HAP_PATH_DATA_AREA = "/data/app/el1/bundle/public";
constexpr const char* MODULE_UPDATE_INSTALL_RESULT_FALSE = "false";
constexpr const char* MODULE_UPDATE_PARAM_EMPTY = "";
constexpr const char* FINGERPRINT = "fingerprint";
constexpr const char* UNKNOWN = "";
constexpr const char* VALUE_TRUE = "true";
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
constexpr const char* HSP_VERSION_PREFIX = "v";
constexpr const char* OTA_FLAG = "otaFlag";
// pre bundle profile
constexpr const char* DEFAULT_PRE_BUNDLE_ROOT_DIR = "/system";
constexpr const char* MODULE_UPDATE_PRODUCT_SUFFIX = "/etc/app/module_update";
constexpr const char* INSTALL_LIST_CONFIG = "/install_list.json";
constexpr const char* APP_SERVICE_FWK_INSTALL_LIST_CONFIG = "/app_service_fwk_install_list.json";
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
constexpr const char* INNER_UNDER_LINE = "_";
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
constexpr const char* KEY_STORAGE_SIZE = "storageSize";
constexpr int64_t TEN_MB = 1024 * 1024 * 10; //10MB

std::set<PreScanInfo> installList_;
std::set<PreScanInfo> onDemandInstallList_;
std::set<PreScanInfo> systemHspList_;
std::set<std::string> uninstallList_;
std::set<PreBundleConfigInfo> installListCapabilities_;
std::set<std::string> extensiontype_;
bool hasLoadPreInstallProFile_ = false;
std::vector<std::string> bundleNameList_;

#ifdef STORAGE_SERVICE_ENABLE
#ifdef QUOTA_PARAM_SET_ENABLE
const std::string SYSTEM_PARAM_ATOMICSERVICE_DATASIZE_THRESHOLD =
    "persist.sys.bms.aging.policy.atomicservice.datasize.threshold";
const int32_t THRESHOLD_VAL_LEN = 20;
#endif // QUOTA_PARAM_SET_ENABLE
const int32_t STORAGE_MANAGER_MANAGER_ID = 5003;
#endif // STORAGE_SERVICE_ENABLE
const int32_t ATOMIC_SERVICE_DATASIZE_THRESHOLD_MB_PRESET = 200;

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
        if (InstalldClient::GetInstance()->MoveFile(path, toPath) != ERR_OK) {
            LOG_W(BMS_TAG_DEFAULT, "move from %{public}s to %{public}s failed", path.c_str(), toPath.c_str());
            continue;
        }

        toPaths.emplace_back(toPath);
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

    if (!BundleUtil::CheckSystemFreeSize(ServiceConstants::BUNDLE_MANAGER_SERVICE_PATH, TEN_MB)) {
        LOG_NOFUNC_E(BMS_TAG_DEFAULT, "OnBmsStarting no space");
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
            }

            break;
        }
        case ResultCode::REINSTALL_OK: {
            LOG_NOFUNC_I(BMS_TAG_DEFAULT, "OnBmsStarting ReInstall all haps");
            needNotifyBundleScanStatus_ = true;
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
#ifdef BUNDLE_FRAMEWORK_QUICK_FIX
    if (OHOS::system::GetBoolParameter(ServiceConstants::DEVELOPERMODE_STATE, false)) {
        DelayedSingleton<QuickFixBootScanner>::GetInstance()->ProcessQuickFixBootUp();
    }
#endif
    DelayedSingleton<BundleMgrService>::GetInstance()->CheckAllUser();
    // process is online theme
    BundleResourceHelper::SetIsOnlineThemeWhenBoot();
    CreateAppInstallDir();
    SetAllInstallFlag();
    HandleSceneBoard();
    CleanTempDir();
    DelayedSingleton<BundleMgrService>::GetInstance()->RegisterService();
    BundleResourceHelper::RegisterCommonEventSubscriber();
    BundleResourceHelper::RegisterConfigurationObserver();
    EventReport::SendScanSysEvent(BMSEventType::BOOT_SCAN_END);
    if (SetParameter(BUNDLE_SCAN_PARAM, BUNDLE_SCAN_FINISH) != 0) {
        LOG_E(BMS_TAG_DEFAULT, "set bms.scanning_apps.status 1 failed");
    }
    ClearCache();
    if (needNotifyBundleScanStatus_) {
        DelayedSingleton<BundleMgrService>::GetInstance()->NotifyBundleScanStatus();
    }
    BmsExtensionDataMgr bmsExtensionDataMgr;
    bmsExtensionDataMgr.RegisterPreInstallWithCard();
    ListeningUserUnlocked();
    RemoveUnreservedSandbox();
    ProcessCheckAppEl1Dir();
    ProcessCheckSystemOptimizeDir();
    LOG_I(BMS_TAG_DEFAULT, "BMSEventHandler AfterBmsStart end");
}

void BMSEventHandler::ClearCache()
{
    hapParseInfoMap_.clear();
    loadExistData_.clear();
    hasLoadAllPreInstallBundleInfosFromDb_ = false;
}

bool BMSEventHandler::LoadInstallInfosFromDb()
{
    LOG_I(BMS_TAG_DEFAULT, "Load install infos from db");
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return false;
    }

    return dataMgr->LoadDataFromPersistentStorage();
}

void BMSEventHandler::BundleBootStartEvent()
{
    EventReport::SendCpuSceneEvent(FOUNDATION_PROCESS_NAME, SCENE_ID_OTA_INSTALL);
    OnBundleBootStart(Constants::DEFAULT_USERID);
#ifdef CHECK_ELDIR_ENABLED
    UpdateOtaFlag(OTAFlag::CHECK_ELDIR);
#endif
    UpdateOtaFlag(OTAFlag::CHECK_LOG_DIR);
    UpdateOtaFlag(OTAFlag::CHECK_FILE_MANAGER_DIR);
    UpdateOtaFlag(OTAFlag::CHECK_PREINSTALL_DATA);
    UpdateOtaFlag(OTAFlag::CHECK_SHADER_CAHCE_DIR);
    UpdateOtaFlag(OTAFlag::CHECK_CLOUD_SHADER_DIR);
    UpdateOtaFlag(OTAFlag::CHECK_BACK_UP_DIR);
    UpdateOtaFlag(OTAFlag::CHECK_RECOVERABLE_APPLICATION_INFO);
    UpdateOtaFlag(OTAFlag::CHECK_INSTALL_SOURCE);
    UpdateOtaFlag(OTAFlag::DELETE_DEPRECATED_ARK_PATHS);
    UpdateOtaFlag(OTAFlag::PROCESS_DYNAMIC_ICON);
    UpdateOtaFlag(OTAFlag::PROCESS_THEME_AND_DYNAMIC_ICON);
    (void)SaveBmsSystemTimeForShortcut();
    UpdateOtaFlag(OTAFlag::CHECK_EXTENSION_ABILITY);
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
        OnBundleRebootStart();
        HandleOTACodeEncryption();
        SaveSystemFingerprint();
        (void)SaveBmsSystemTimeForShortcut();
        AOTHandler::GetInstance().HandleOTA();
    } else {
        HandlePreInstallException();
        ProcessRebootQuickFixBundleInstall(QUICK_FIX_APP_PATH, false);
        ProcessRebootQuickFixUnInstallAndRecover(QUICK_FIX_APP_RECOVER_FILE);
        CheckBundleProvisionInfo();
        CheckALLResourceInfo();
        RemoveUninstalledPreloadFile();
    }
    // need process main bundle status
    BmsKeyEventMgr::ProcessMainBundleStatusFinally();

    if (IsModuleUpdate()) {
        HandleModuleUpdate();
    }

    // need check /data/service/el1/public/bms/bundle_manager_service/app_temp
    ProcessAppTmpPath();

    needNotifyBundleScanStatus_ = true;
}

ResultCode BMSEventHandler::GuardAgainstInstallInfosLossedStrategy()
{
    LOG_I(BMS_TAG_DEFAULT, "GuardAgainstInstallInfosLossedStrategy start");
    // Check user path, and parse userData to InnerBundleUserInfo
    std::map<std::string, std::vector<InnerBundleUserInfo>> innerBundleUserInfoMaps;
    ScanResultCode scanResultCode = ScanAndAnalyzeUserDatas(innerBundleUserInfoMaps);
    if (scanResultCode == ScanResultCode::SCAN_NO_DATA) {
        LOG_E(BMS_TAG_DEFAULT, "Scan the user data directory failed");
        return ResultCode::NO_INSTALLED_DATA;
    }

    // When data exist, but parse all userinfo fails, reinstall all app.
    // For example: the AT database is lost or others.
    if (scanResultCode == ScanResultCode::SCAN_HAS_DATA_PARSE_FAILED) {
        // Reinstall all app from install dir
        return ReInstallAllInstallDirApps();
    }

    // When data exist and parse all userinfo success,
    // it can be judged that some bundles has installed.
    // Check install dir, and parse the hap in install dir to InnerBundleInfo
    std::map<std::string, std::vector<InnerBundleInfo>> installInfos;
    ScanAndAnalyzeInstallInfos(installInfos);
    if (installInfos.empty()) {
        LOG_E(BMS_TAG_DEFAULT, "check bundle path failed due to hap lossd or parse failed");
        return ResultCode::SYSTEM_ERROR;
    }

    // Combine InnerBundleInfo and InnerBundleUserInfo
    if (!CombineBundleInfoAndUserInfo(installInfos, innerBundleUserInfoMaps)) {
        LOG_E(BMS_TAG_DEFAULT, "System internal error");
        return ResultCode::SYSTEM_ERROR;
    }

    return ResultCode::RECOVER_OK;
}

ScanResultCode BMSEventHandler::ScanAndAnalyzeUserDatas(
    std::map<std::string, std::vector<InnerBundleUserInfo>> &userMaps)
{
    ScanResultCode scanResultCode = ScanResultCode::SCAN_NO_DATA;
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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
            LOG_E(BMS_TAG_DEFAULT, "UserId(%{public}s) strToInt failed", userId.c_str());
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

    std::string userDataBundlePath = userDataDir + userDataBundleName;
    LOG_D(BMS_TAG_DEFAULT, "Analyze user data path(%{public}s)", userDataBundlePath.c_str());
    FileStat fileStat;
    if (InstalldClient::GetInstance()->GetFileStat(userDataBundlePath, fileStat) != ERR_OK) {
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
        std::vector<InnerBundleUserInfo> innerBundleUserInfos = { innerBundleUserInfo };
        userMaps.emplace(userDataBundleName, innerBundleUserInfos);
        return true;
    }

    userMaps.at(userDataBundleName).emplace_back(innerBundleUserInfo);
    return true;
}

ResultCode BMSEventHandler::ReInstallAllInstallDirApps()
{
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
    std::map<std::string, std::vector<InnerBundleInfo>> &installInfos)
{
    // Scan the installed directory
    std::map<std::string, std::vector<std::string>> hapPathsMap;
    ScanInstallDir(hapPathsMap);
    AnalyzeHaps(false, hapPathsMap, installInfos);

    // Scan preBundle directory
    std::vector<std::string> preInstallDirs;
    GetPreInstallDir(preInstallDirs);
    AnalyzeHaps(true, preInstallDirs, installInfos);
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
    std::map<std::string, std::vector<InnerBundleInfo>> &installInfos)
{
    for (const auto &bundleDir : bundleDirs) {
        std::unordered_map<std::string, InnerBundleInfo> hapInfos;
        if (!CheckAndParseHapFiles(bundleDir, isPreInstallApp, hapInfos) || hapInfos.empty()) {
            LOG_E(BMS_TAG_DEFAULT, "Parse bundleDir(%{public}s) failed", bundleDir.c_str());
            continue;
        }

        CollectInstallInfos(hapInfos, installInfos);
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
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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
        if (userIter == userInfoMaps.end()) {
            LOG_E(BMS_TAG_DEFAULT, "User data directory missing with bundle %{public}s ", bundleName.c_str());
            needRebootOta_ = true;
            continue;
        }

        for (auto &info : hasInstallInfo.second) {
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
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "dataMgr is null");
        return;
    }

    auto bundleName = info.GetBundleName();
    auto appCodePath = std::string(Constants::BUNDLE_CODE_DIR) + ServiceConstants::PATH_SEPARATOR + bundleName;
    info.SetAppCodePath(appCodePath);

    std::string dataBaseDir = ServiceConstants::BUNDLE_APP_DATA_BASE_DIR + ServiceConstants::BUNDLE_EL[1]
        + ServiceConstants::DATABASE + bundleName;
    info.SetAppDataBaseDir(dataBaseDir);

    auto moduleDir = info.GetAppCodePath() + ServiceConstants::PATH_SEPARATOR + info.GetCurrentModulePackage();
    info.AddModuleSrcDir(moduleDir);
    info.AddModuleResPath(moduleDir);

    bool bundleExist = false;
    InnerBundleInfo dbInfo;
    {
        auto &mtx = dataMgr->GetBundleMutex(bundleName);
        std::lock_guard lock { mtx };
        bundleExist = dataMgr->FetchInnerBundleInfo(bundleName, dbInfo);
    }

    if (!bundleExist) {
        dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_START);
        if (!dataMgr->AddInnerBundleInfo(bundleName, info)) {
            LOG_E(BMS_TAG_DEFAULT, "add bundle %{public}s failed", bundleName.c_str());
            dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_FAIL);
            return;
        }
        dataMgr->UpdateBundleInstallState(bundleName, InstallState::INSTALL_SUCCESS);
        return;
    }

    auto& hapModuleName = info.GetCurModuleName();
    std::vector<std::string> dbModuleNames;
    dbInfo.GetModuleNames(dbModuleNames);
    auto iter = std::find(dbModuleNames.begin(), dbModuleNames.end(), hapModuleName);
    if (iter != dbModuleNames.end()) {
        LOG_E(BMS_TAG_DEFAULT, "module(%{public}s) has install", hapModuleName.c_str());
        return;
    }

    dataMgr->UpdateBundleInstallState(bundleName, InstallState::UPDATING_START);
    dataMgr->UpdateBundleInstallState(bundleName, InstallState::UPDATING_SUCCESS);
    dataMgr->AddNewModuleInfo(bundleName, info, dbInfo);
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
    for (auto item : bundleList) {
        auto iter = std::find(bundleDirs.begin(), bundleDirs.end(), item);
        if (iter == bundleDirs.end()) {
            bundleDirs.push_back(item);
        }
    }
}

void BMSEventHandler::InnerProcessBootSystemHspInstall()
{
    for (const auto &systemHspPath : systemHspList_) {
        ProcessSystemHspInstall(systemHspPath);
    }
}

void BMSEventHandler::ProcessSystemHspInstall(const PreScanInfo &preScanInfo)
{
    InstallParam installParam;
    installParam.isPreInstallApp = true;
    installParam.removable = false;
    installParam.copyHapToInstallPath = false;
    installParam.needSavePreInstallInfo = true;
    installParam.preinstallSourceFlag = ApplicationInfoFlag::FLAG_BOOT_INSTALLED;
    AppServiceFwkInstaller installer;
    SavePreInstallExceptionAppService(preScanInfo.bundleDir);
    ErrCode ret = installer.Install({preScanInfo.bundleDir}, installParam);
    LOG_I(BMS_TAG_DEFAULT, "Install systemHsp %{public}s result %{public}d", preScanInfo.bundleDir.c_str(), ret);
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
    LOG_I(BMS_TAG_DEFAULT, "Process system shared bundle by sharedBundlePath(%{public}s)", sharedBundlePath.c_str());
    InstallParam installParam;
    installParam.isPreInstallApp = true;
    installParam.SetKillProcess(false);
    installParam.needSendEvent = false;
    installParam.removable = false;
    installParam.needSavePreInstallInfo = true;
    installParam.sharedBundleDirPaths = {sharedBundlePath};
    installParam.preinstallSourceFlag = ApplicationInfoFlag::FLAG_BOOT_INSTALLED;
    SystemBundleInstaller installer;
    if (!installer.InstallSystemSharedBundle(installParam, false, appType)) {
        LOG_W(BMS_TAG_DEFAULT, "install system shared bundle: %{public}s error", sharedBundlePath.c_str());
    }
}

void BMSEventHandler::CreateAppInstallDir() const
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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
    ProcessRebootBundle();
}

void BMSEventHandler::ProcessRebootBundle()
{
    LOG_I(BMS_TAG_DEFAULT, "BMSEventHandler Process reboot bundle start");
    LoadAllPreInstallBundleInfos();
    BundleResourceHelper::DeleteNotExistResourceInfo();
    InnerProcessRebootUninstallWrongBundle();
    ProcessRebootCheckOnDemandBundle();
    ProcessRebootBundleInstall();
    ProcessRebootBundleUninstall();
    ProcessRebootAppServiceUninstall();
    //refresh application permissions
    ProcessUpdatePermissions();
    ProcessRebootQuickFixBundleInstall(QUICK_FIX_APP_PATH, true);
    ProcessRebootQuickFixUnInstallAndRecover(QUICK_FIX_APP_RECOVER_FILE);
    ProcessBundleResourceInfo();
    ProcessAllBundleDataGroupInfo();
#ifdef CHECK_ELDIR_ENABLED
    ProcessCheckAppDataDir();
#endif
    ProcessCheckAppLogDir();
    ProcessCheckAppFileManagerDir();
    ProcessCheckPreinstallData();
    ProcessCheckShaderCacheDir();
    ProcessCheckCloudShaderDir();
    ProcessNewBackupDir();
    CheckAndCreateShareFilesSubDataDirs();
    RefreshQuotaForAllUid();
    ProcessCheckRecoverableApplicationInfo();
    ProcessCheckInstallSource();
    ProcessCheckAppExtensionAbility();
    // Driver update may cause shader cache invalidity and need to be cleared
    CleanAllBundleShaderCache();
    CleanAllBundleEl1ShaderCacheLocal();
    CleanSystemOptimizeShaderCache();
    CleanAllBundleEl1ArkStartupCacheLocal();
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
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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
            preInstallBundleInfo.SetModuleName(resultBundleInfo.applicationInfo.labelResource.moduleName);
            if (!bundleInfo.hapModuleInfos.empty() &&
                resultBundleInfo.hapModuleInfos[0].moduleType == ModuleType::ENTRY) {
                break;
            }
        }
        dataMgr->SavePreInstallBundleInfo(resultBundleInfo.name, preInstallBundleInfo);
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
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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

void BMSEventHandler::ProcessCheckShaderCacheDir()
{
    bool checkShaderCache = false;
    CheckOtaFlag(OTAFlag::CHECK_SHADER_CAHCE_DIR, checkShaderCache);
    if (checkShaderCache) {
        LOG_I(BMS_TAG_DEFAULT, "Not need to check shader cache dir due to has checked");
        return;
    }
    LOG_I(BMS_TAG_DEFAULT, "Need to check shader cache dir");
    InnerProcessCheckShaderCacheDir();
    CheckAllBundleEl1ShaderCacheLocal();
    CheckSystemOptimizeShaderCache();
    UpdateOtaFlag(OTAFlag::CHECK_SHADER_CAHCE_DIR);
}

void BMSEventHandler::InnerProcessCheckShaderCacheDir()
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }
    std::vector<BundleInfo> bundleInfos;
    ErrCode res = dataMgr->GetBundleInfosV9(
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE), bundleInfos, Constants::ALL_USERID);
    if (res != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "GetAllBundleInfos failed");
        return;
    }
    for (const auto &bundleInfo : bundleInfos) {
        if (bundleInfo.name.empty()) {
            continue;
        }
        std::string shaderCachePath;
        shaderCachePath.append(ServiceConstants::SHADER_CACHE_PATH).append(bundleInfo.name);
        ErrCode res = InstalldClient::GetInstance()->Mkdir(shaderCachePath, S_IRWXU, bundleInfo.uid, bundleInfo.gid);
        if (res != ERR_OK) {
            LOG_W(BMS_TAG_DEFAULT, "create shader cache failed: %{public}s ", shaderCachePath.c_str());
        }
    }
}

void BMSEventHandler::CheckBundleCloneEl1ShaderCacheLocal(const std::string &bundleName,
    int32_t appIndex, int32_t userId, int32_t uid)
{
    std::string cloneBundleName = bundleName;
    if (appIndex != 0) {
        cloneBundleName = BundleCloneCommonHelper::GetCloneDataDir(bundleName,
            appIndex);
    }
    if (uid == Constants::INVALID_UID) {
        LOG_W(BMS_TAG_DEFAULT, "invalid uid for: %{public}s", cloneBundleName.c_str());
        return;
    }
    std::string el1ShaderCachePath = std::string(ServiceConstants::NEW_SHADER_CACHE_PATH);
    el1ShaderCachePath = el1ShaderCachePath.replace(el1ShaderCachePath.find("%"),
        1, std::to_string(userId));
    el1ShaderCachePath = el1ShaderCachePath + cloneBundleName;
    bool isExist = true;
    ErrCode result = InstalldClient::GetInstance()->IsExistDir(el1ShaderCachePath, isExist);
    if (result == ERR_OK && isExist) {
        return;
    }
    result = InstalldClient::GetInstance()->Mkdir(el1ShaderCachePath,
        ServiceConstants::NEW_SHADRE_CACHE_MODE,
        uid, ServiceConstants::NEW_SHADRE_CACHE_GID);
    if (result != ERR_OK) {
        LOG_W(BMS_TAG_DEFAULT, "create new shadercache failed: %{public}s ", el1ShaderCachePath.c_str());
    }
}

void BMSEventHandler::CheckAllBundleEl1ShaderCacheLocal()
{
    LOG_I(BMS_TAG_DEFAULT, "start");
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }
    std::set<int32_t> userIds = dataMgr->GetAllUser();
    for (const auto &userId : userIds) {
        std::string el1ShaderCachePath = std::string(ServiceConstants::NEW_SHADER_CACHE_PATH);
        el1ShaderCachePath = el1ShaderCachePath.replace(el1ShaderCachePath.find("%"),
            1, std::to_string(userId));
        bool isExist = true;
        ErrCode result = InstalldClient::GetInstance()->IsExistDir(el1ShaderCachePath, isExist);
        if (result != ERR_OK || !isExist) {
            LOG_W(BMS_TAG_DEFAULT, "shadercache not exist: %{public}s ", el1ShaderCachePath.c_str());
            continue;
        }
        std::map<std::string, InnerBundleInfo> infos = dataMgr->GetAllInnerBundleInfos();
        for (auto &infoPair : infos) {
            auto &info = infoPair.second;
            std::string bundleName = info.GetBundleName();
            BundleType type = info.GetApplicationBundleType();
            std::vector<int32_t> allAppIndexes = {0};
            std::vector<int32_t> cloneAppIndexes = dataMgr->GetCloneAppIndexesByInnerBundleInfo(info, userId);
            allAppIndexes.insert(allAppIndexes.end(), cloneAppIndexes.begin(), cloneAppIndexes.end());
            for (int32_t appIndex: allAppIndexes) {
                int32_t uid = info.GetUid(userId, appIndex);
                CheckBundleCloneEl1ShaderCacheLocal(bundleName, appIndex, userId, uid);
            }
        }
    }
}

void BMSEventHandler::CleanBundleCloneEl1ShaderCacheLocal(const std::string &bundleName,
    int32_t appIndex, int32_t userId)
{
    std::string cloneBundleName = bundleName;
    if (appIndex != 0) {
        cloneBundleName = BundleCloneCommonHelper::GetCloneDataDir(bundleName,
            appIndex);
    }
    std::string el1ShaderCachePath = std::string(ServiceConstants::NEW_SHADER_CACHE_PATH);
    el1ShaderCachePath = el1ShaderCachePath.replace(el1ShaderCachePath.find("%"),
        1, std::to_string(userId));
    el1ShaderCachePath = el1ShaderCachePath + cloneBundleName;
    ErrCode res = InstalldClient::GetInstance()->CleanBundleDataDir(el1ShaderCachePath);
    if (res != ERR_OK) {
        LOG_NOFUNC_W(BMS_TAG_DEFAULT, "%{public}s clean shader cache fail %{public}d",
            bundleName.c_str(), res);
    }
}

void BMSEventHandler::CleanAllBundleEl1ShaderCacheLocal()
{
    LOG_I(BMS_TAG_DEFAULT, "start");
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }
    std::set<int32_t> userIds = dataMgr->GetAllUser();
    for (const auto &userId : userIds) {
        std::string el1ShaderCachePath = std::string(ServiceConstants::NEW_SHADER_CACHE_PATH);
        el1ShaderCachePath = el1ShaderCachePath.replace(el1ShaderCachePath.find("%"),
            1, std::to_string(userId));
        bool isExist = true;
        ErrCode result = InstalldClient::GetInstance()->IsExistDir(el1ShaderCachePath, isExist);
        if (result != ERR_OK || !isExist) {
            LOG_W(BMS_TAG_DEFAULT, "shadercache not exist: %{public}s ", el1ShaderCachePath.c_str());
            continue;
        }
        std::map<std::string, InnerBundleInfo> infos = dataMgr->GetAllInnerBundleInfos();
        for (auto &infoPair : infos) {
            auto &info = infoPair.second;
            std::string bundleName = info.GetBundleName();
            BundleType type = info.GetApplicationBundleType();
            std::vector<int32_t> allAppIndexes = {0};
            std::vector<int32_t> cloneAppIndexes = dataMgr->GetCloneAppIndexesByInnerBundleInfo(info, userId);
            allAppIndexes.insert(allAppIndexes.end(), cloneAppIndexes.begin(), cloneAppIndexes.end());
            for (int32_t appIndex: allAppIndexes) {
                CleanBundleCloneEl1ShaderCacheLocal(bundleName, appIndex, userId);
            }
        }
    }
}

void BMSEventHandler::ProcessCheckCloudShaderDir()
{
    bool checkCloudShader = false;
    CheckOtaFlag(OTAFlag::CHECK_CLOUD_SHADER_DIR, checkCloudShader);
    if (checkCloudShader) {
        LOG_D(BMS_TAG_DEFAULT, "Not need to check cloud shader cache dir due to has checked");
        return;
    }
    LOG_D(BMS_TAG_DEFAULT, "Need to check cloud shader cache dir");
    InnerProcessCheckCloudShaderDir();
    UpdateOtaFlag(OTAFlag::CHECK_CLOUD_SHADER_DIR);
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
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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

void BMSEventHandler::InnerProcessCheckCloudShaderDir()
{
    bool cloudExist = true;
    bool commonExist = true;
    ErrCode result = InstalldClient::GetInstance()->IsExistDir(ServiceConstants::CLOUD_SHADER_PATH, cloudExist);
    if (result != ERR_OK) {
        LOG_W(BMS_TAG_DEFAULT, "IsExistDir failed, error is %{public}d", result);
        return;
    }
    result = InstalldClient::GetInstance()->IsExistDir(ServiceConstants::CLOUD_SHADER_COMMON_PATH, commonExist);
    if (result != ERR_OK) {
        LOG_W(BMS_TAG_DEFAULT, "IsExistDir failed, error is %{public}d", result);
        commonExist = false;
    }
    if (cloudExist && commonExist) {
        LOG_D(BMS_TAG_DEFAULT, "CLOUD_SHADER_PATH and CLOUD_SHADER_COMMON_PATH existed");
        return;
    }
    const std::string bundleName = OHOS::system::GetParameter(ServiceConstants::CLOUD_SHADER_OWNER, "");
    if (bundleName.empty()) {
        return;
    }

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_W(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }

    BundleInfo info;
    auto hasBundleInstalled = dataMgr->GetBundleInfo(
        bundleName, static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE),
        info, Constants::ANY_USERID);
    if (!hasBundleInstalled) {
        LOG_D(BMS_TAG_DEFAULT, "Obtain bundleInfo failed, bundleName: %{public}s not exist", bundleName.c_str());
        return;
    }
    if (!cloudExist) {
        constexpr int32_t mode = (S_IRWXU | S_IXGRP | S_IXOTH);
        result = InstalldClient::GetInstance()->Mkdir(ServiceConstants::CLOUD_SHADER_PATH, mode, info.uid, info.gid);
        if (result != ERR_OK) {
            LOG_W(BMS_TAG_DEFAULT, "Mkdir CLOUD_SHADER_PATH failed, error is %{public}d", result);
            return;
        }
    }
    if (!commonExist) {
        InnerProcessCheckCloudShaderCommonDir(info.uid, info.gid);
    }
    LOG_I(BMS_TAG_DEFAULT, "Create cloud shader cache result: %{public}d", result);
}

void BMSEventHandler::InnerProcessCheckCloudShaderCommonDir(const int32_t uid, const int32_t gid)
{
    constexpr int32_t commonMode = (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    ErrCode result = InstalldClient::GetInstance()->Mkdir(ServiceConstants::CLOUD_SHADER_COMMON_PATH,
        commonMode, uid, gid);
    if (result != ERR_OK) {
        LOG_W(BMS_TAG_DEFAULT, "Mkdir CLOUD_SHADER_COMMON_PATH failed, error is %{public}d", result);
        return;
    }
    LOG_I(BMS_TAG_DEFAULT, "Create cloud shader cache result: %{public}d", result);
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
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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
    ParseSizeFromProvision(bundleName, atomicserviceDatasizeThreshold);
    SendToStorageQuota(bundleName, uid, bundleDataDirPath, atomicserviceDatasizeThreshold);
}

void BMSEventHandler::ParseSizeFromProvision(const std::string &bundleName, int32_t &sizeMb) const
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
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return false;
    }

    std::vector<PreInstallBundleInfo> preInstallBundleInfos = dataMgr->GetAllPreInstallBundleInfos();
    for (auto &iter : preInstallBundleInfos) {
        LOG_D(BMS_TAG_DEFAULT, "load preInstallBundleInfos: %{public}s ", iter.GetBundleName().c_str());
        loadExistData_.emplace(iter.GetBundleName(), iter);
    }

    hasLoadAllPreInstallBundleInfosFromDb_ = true;
    return !preInstallBundleInfos.empty();
}

void BMSEventHandler::ProcessRebootBundleInstall()
{
    LOG_I(BMS_TAG_DEFAULT, "BMSEventHandler Process reboot bundle install start");
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

    InnerProcessRebootSystemHspInstall(systemHspDirs);
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

void BMSEventHandler::InnerProcessRebootBundleInstall(
    const std::list<std::string> &scanPathList, Constants::AppType appType)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }

    std::unordered_map<std::string, std::pair<std::string, bool>> needInstallMap;
    for (auto &scanPathIter : scanPathList) {
        LOG_NOFUNC_I(BMS_TAG_DEFAULT, "reboot scan bundle path: %{public}s ", scanPathIter.c_str());
        bool removable = IsPreInstallRemovable(scanPathIter);
        std::unordered_map<std::string, InnerBundleInfo> infos;
        if (!ParseHapFiles(scanPathIter, infos) || infos.empty()) {
            LOG_E(BMS_TAG_DEFAULT, "obtain bundleinfo failed : %{public}s ", scanPathIter.c_str());
            BmsKeyEventMgr::ProcessMainBundleInstallFailed(scanPathIter, ERR_APPEXECFWK_PARSE_UNEXPECTED);
            SavePreInstallException(scanPathIter);
            continue;
        }

        auto bundleName = infos.begin()->second.GetBundleName();
        auto hapVersionCode = infos.begin()->second.GetVersionCode();
        AddParseInfosToMap(bundleName, infos);
        auto mapIter = loadExistData_.find(bundleName);
        if (mapIter == loadExistData_.end()) {
            LOG_NOFUNC_I(BMS_TAG_DEFAULT, "OTA Install new -n %{public}s by path:%{public}s",
                bundleName.c_str(), scanPathIter.c_str());
            std::vector<std::string> filePaths { scanPathIter };
            if (!OTAInstallSystemBundle(filePaths, appType, removable)) {
                LOG_E(BMS_TAG_DEFAULT, "OTA Install new bundle(%{public}s) error", bundleName.c_str());
                SavePreInstallException(scanPathIter);
            }
            continue;
        }

        LOG_NOFUNC_I(BMS_TAG_DEFAULT, "OTA process -n %{public}s path:%{public}s",
            bundleName.c_str(), scanPathIter.c_str());
        BundleInfo hasInstalledInfo;
        auto hasBundleInstalled = dataMgr->GetBundleInfo(
            bundleName, static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE),
            hasInstalledInfo, Constants::ANY_USERID);
        if (!hasBundleInstalled && mapIter->second.IsUninstalled()) {
            LOG_W(BMS_TAG_DEFAULT, "app(%{public}s) has been uninstalled and do not OTA install",
                bundleName.c_str());
            continue;
        }
        std::vector<int32_t> currentBundleUserIds;
        if (HotPatchAppProcessing(bundleName, hasInstalledInfo.versionCode, hapVersionCode, currentBundleUserIds)) {
            LOG_I(BMS_TAG_DEFAULT, "OTA Install prefab bundle(%{public}s) by path(%{public}s) for hotPatch upgrade",
                bundleName.c_str(), scanPathIter.c_str());
            // After the patch app is uninstalled, install the preconfigured app of the ota version.
            std::vector<std::string> filePaths{scanPathIter};
            if (!OTAInstallSystemBundleTargetUser(filePaths, bundleName, appType, removable, currentBundleUserIds)) {
                LOG_E(BMS_TAG_DEFAULT, "OTA install prefab bundle(%{public}s) error", bundleName.c_str());
                SavePreInstallException(scanPathIter);
            }
            continue;
        }
        std::vector<std::string> filePaths;
        bool updateSelinuxLabel = false;
        bool updateBundle = false;
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
                    if (UpdateModuleByHash(hasInstalledInfo, item.second)) {
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
                if (CheckIsBundleUpdatedByHapPath(hasInstalledInfo)) {
                    break;
                }
                LOG_NOFUNC_E(BMS_TAG_DEFAULT, "-n %{public}s update failed versionCode:%{public}d lower than "
                    "current:%{public}d", bundleName.c_str(), hapVersionCode, hasInstalledInfo.versionCode);
                SendBundleUpdateFailedEvent(hasInstalledInfo);
                break;
            }
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
        needInstallMap[bundleName] = std::make_pair(scanPathIter, removable);
    }
    if (!InnerMultiProcessBundleInstall(needInstallMap, appType)) {
        LOG_E(BMS_TAG_DEFAULT, "multi install failed");
    }
    UpdatePreinstallDB(needInstallMap);
    // process bundle theme and dynamic resource
    InnerProcessAllThemeAndDynamicIconInfoWhenOta(needInstallMap);
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
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return false;
    }
    userIds = dataMgr->GetUserIds(bundleName);

    if (IsQuickfixPatchApp(bundleName, hasInstallVersionCode)) {
        LOG_I(BMS_TAG_DEFAULT, "hasInstallVersionCode: %{public}u, hapVersionCode: %{public}u",
            hasInstallVersionCode, hapVersionCode);
        // installed patch application version greater than or equal to OTA Preconfigured APP Version
        if (hasInstallVersionCode >= hapVersionCode) {
            BundleInfo bundleInfo;
            bundleInfo.name = bundleName;
            bundleInfo.versionCode = hapVersionCode;
            SendBundleUpdateFailedEvent(bundleInfo, ERR_APPEXECFWK_UNINSTALL_AND_INSTALL);
            LOG_I(BMS_TAG_DEFAULT, "get patch success, bundleName: %{public}s", bundleName.c_str());
            // uninstall the patch app
            SystemBundleInstaller installer;
            if (!installer.UninstallSystemBundle(bundleName, true)) {
                LOG_E(BMS_TAG_DEFAULT, "keep data to uninstall app failed, bundleName: %{public}s", bundleName.c_str());
                return false;
            }
        }
        // delete patch data
        if (!PatchDataMgr::GetInstance().DeleteInnerPatchInfo(bundleName)) {
            LOG_W(BMS_TAG_DEFAULT, "DeleteInnerPatchInfo failed, bundleName: %{public}s", bundleName.c_str());
        }
        return true;
    }
    return false;
}

bool BMSEventHandler::InnerMultiProcessBundleInstall(
    const std::unordered_map<std::string, std::pair<std::string, bool>> &needInstallMap,
    Constants::AppType appType)
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
        auto task = [bundleName, pair, taskTotalNum, appType, &taskEndNum, &bundlePromise]() {
            std::vector<std::string> filePaths = {pair.first};
            (void)BMSEventHandler::OTAInstallSystemBundleNeedCheckUser(filePaths, bundleName, appType, pair.second);
            taskEndNum++;
            if (bundlePromise && taskEndNum >= taskTotalNum) {
                bundlePromise->NotifyAllTasksExecuteFinished();
                LOG_I(BMS_TAG_DEFAULT, "All tasks has executed and notify promise when ota");
            }
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
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }
    for (const auto &scanPath : scanPathList) {
        bool removable = IsPreInstallRemovable(scanPath);
        std::unordered_map<std::string, InnerBundleInfo> infos;
        if (!ParseHapFiles(scanPath, infos) || infos.empty()) {
            LOG_E(BMS_TAG_DEFAULT, "obtain bundleinfo failed : %{public}s ", scanPath.c_str());
            continue;
        }

        auto bundleName = infos.begin()->second.GetBundleName();
        auto versionCode = infos.begin()->second.GetVersionCode();
        AddParseInfosToMap(bundleName, infos);
        auto mapIter = loadExistData_.find(bundleName);
        if (mapIter == loadExistData_.end()) {
            LOG_I(BMS_TAG_DEFAULT, "OTA Install new shared bundle(%{public}s) by path(%{public}s)",
                bundleName.c_str(), scanPath.c_str());
            if (!OTAInstallSystemSharedBundle({scanPath}, appType, removable)) {
                LOG_E(BMS_TAG_DEFAULT, "OTA Install new shared bundle(%{public}s) error", bundleName.c_str());
            }
            continue;
        }

        InnerBundleInfo oldBundleInfo;
        bool hasInstalled = dataMgr->FetchInnerBundleInfo(bundleName, oldBundleInfo);
        if (!hasInstalled) {
            LOG_W(BMS_TAG_DEFAULT, "app(%{public}s) has been uninstalled and do not OTA install", bundleName.c_str());
            continue;
        }

        if (oldBundleInfo.GetVersionCode() > versionCode) {
            LOG_D(BMS_TAG_DEFAULT, "the installed version is up-to-date");
            continue;
        }

        if (!OTAInstallSystemSharedBundle({scanPath}, appType, removable)) {
            LOG_E(BMS_TAG_DEFAULT, "OTA update shared bundle(%{public}s) error", bundleName.c_str());
        }
    }
}

void BMSEventHandler::InnerProcessRebootSystemHspInstall(const std::list<std::string> &scanPathList)
{
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "InnerProcessRebootSystemHspInstall");
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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
            LOG_I(BMS_TAG_DEFAULT, "OTA Install new system hsp(%{public}s) by path(%{public}s) ret %{public}d",
                bundleName.c_str(), scanPath.c_str(), ret);
            if (ret == ERR_OK) {
                DeletePreInstallExceptionAppService(scanPath);
            }
            continue;
        }
        InnerBundleInfo oldBundleInfo;
        bool hasInstalled = dataMgr->FetchInnerBundleInfo(bundleName, oldBundleInfo);
        if (!hasInstalled) {
            LOG_W(BMS_TAG_DEFAULT, "app(%{public}s) has been uninstalled and do not OTA install", bundleName.c_str());
            continue;
        }
        if (oldBundleInfo.GetVersionCode() > versionCode) {
            LOG_D(BMS_TAG_DEFAULT, "the installed version is up-to-date");
            continue;
        }
        SavePreInstallExceptionAppService(scanPath);
        auto ret = OTAInstallSystemHsp({scanPath});
        LOG_I(BMS_TAG_DEFAULT, "OTA Install system hsp(%{public}s) by path(%{public}s) ret %{public}d",
            bundleName.c_str(), scanPath.c_str(), ret);
        if (ret == ERR_OK) {
            DeletePreInstallExceptionAppService(scanPath);
        }
    }
}

void BMSEventHandler::ProcessRebootAppServiceUninstall()
{
    APP_LOGI("Reboot scan and OTA uninstall for appServiceFwk start");
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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

void BMSEventHandler::UpdateExtensionType()
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "dataMgr is null");
        return;
    }
    std::map<std::string, InnerBundleInfo> infos = dataMgr->GetAllInnerBundleInfos();
    for (auto &[bundleName, innerBundleInfo] : infos) {
        bool needUpdate = false;
        for (auto &[key, innerExtensionInfo] : innerBundleInfo.FetchInnerExtensionInfos()) {
            if (innerExtensionInfo.type == ExtensionAbilityType::UNSPECIFIED) {
                LOG_I(BMS_TAG_DEFAULT, "update extension type, -b : %{public}s, -e : %{public}s",
                    bundleName.c_str(), innerExtensionInfo.name.c_str());
                needUpdate = true;
                innerExtensionInfo.type = ConvertToExtensionAbilityType(innerExtensionInfo.extensionTypeName);
            }
        }
        if (needUpdate) {
            dataMgr->UpdateInnerBundleInfo(innerBundleInfo, true);
        }
    }
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
    UpdateExtensionType();
    InnerProcessCheckAppExtensionAbility();
    UpdateOtaFlag(OTAFlag::CHECK_EXTENSION_ABILITY);
}

void BMSEventHandler::InnerProcessCheckAppExtensionAbility()
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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

void BMSEventHandler::SaveSystemFingerprint()
{
    auto bmsPara = DelayedSingleton<BundleMgrService>::GetInstance()->GetBmsParam();
    if (bmsPara == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "bmsPara is nullptr");
        return;
    }

    std::string curSystemFingerprint = GetCurSystemFingerprint();
    LOG_I(BMS_TAG_DEFAULT, "curSystemFingerprint(%{public}s)", curSystemFingerprint.c_str());
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
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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

void BMSEventHandler::HandlePreInstallException()
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
    if (!preInstallExceptionMgr->GetAllPreInstallExceptionInfo(
        exceptionPaths, exceptionBundleNames, exceptionAppServicePaths, exceptionAppServiceBundleNames)) {
        LOG_I(BMS_TAG_DEFAULT, "No pre-install exception information found");
        return;
    }

    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "handle exception %{public}zu %{public}zu %{public}zu %{public}zu",
        exceptionPaths.size(), exceptionBundleNames.size(),
        exceptionAppServicePaths.size(), exceptionAppServiceBundleNames.size());
    HandlePreInstallAppServicePathsException(preInstallExceptionMgr, exceptionAppServicePaths);
    HandlePreInstallAppPathsException(preInstallExceptionMgr, exceptionPaths);
    if (!exceptionBundleNames.empty() || !exceptionAppServiceBundleNames.empty()) {
        LOG_NOFUNC_I(BMS_TAG_DEFAULT, "Loading all pre-install bundle infos");
        LoadAllPreInstallBundleInfos();
    }
    HandlePreInstallAppServiceBundleNamesException(preInstallExceptionMgr, exceptionAppServiceBundleNames);
    HandlePreInstallBundleNamesException(preInstallExceptionMgr, exceptionBundleNames);

    preInstallExceptionMgr->ClearAll();
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
        }

        preInstallExceptionMgr->DeletePreInstallExceptionPath(pathIter);
    }
}

void BMSEventHandler::HandlePreInstallAppPathsException(
    std::shared_ptr<PreInstallExceptionMgr> preInstallExceptionMgr, const std::set<std::string> &exceptionPaths)
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
        }

        preInstallExceptionMgr->DeletePreInstallExceptionPath(pathIter);
    }
}

void BMSEventHandler::HandlePreInstallAppServiceBundleNamesException(
    std::shared_ptr<PreInstallExceptionMgr> preInstallExceptionMgr,
    const std::set<std::string> &exceptionAppServiceBundleNames)
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

        preInstallExceptionMgr->DeletePreInstallExceptionBundleName(bundleNameIter);
    }
}

void BMSEventHandler::HandlePreInstallBundleNamesException(
    std::shared_ptr<PreInstallExceptionMgr> preInstallExceptionMgr, const std::set<std::string> &exceptionBundleNames)
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
        if (!OTAInstallSystemBundle(preInstallBundleInfo.GetBundlePaths(),
            Constants::AppType::SYSTEM_APP, preInstallBundleInfo.IsRemovable())) {
            LOG_NOFUNC_W(BMS_TAG_DEFAULT, "HandlePreInstallException bundleName(%{public}s) error",
                bundleNameIter.c_str());
        }

        preInstallExceptionMgr->DeletePreInstallExceptionBundleName(bundleNameIter);
    }
}

bool BMSEventHandler::OTAInstallSystemBundle(
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
    installParam.SetKillProcess(false);
    installParam.needSendEvent = false;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.removable = removable;
    installParam.needSavePreInstallInfo = true;
    installParam.copyHapToInstallPath = false;
    installParam.isOTA = true;
    installParam.preinstallSourceFlag = ApplicationInfoFlag::FLAG_OTA_INSTALLED;
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
    bool removable)
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
    const std::string &bundleName, Constants::AppType appType, bool removable, const std::vector<int32_t> &userIds)
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

    auto ret = bundleInstallChecker->CheckSysCap(realPaths);
    if (ret != ERR_OK) {
        LOG_I(BMS_TAG_DEFAULT, "hap syscap check failed");
    }
    bool isSysCapValid = (ret == ERR_OK);

    std::vector<Security::Verify::HapVerifyResult> hapVerifyResults;
    ret = bundleInstallChecker->CheckMultipleHapsSignInfo(realPaths, hapVerifyResults, true);
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

    if (!isSysCapValid) {
        ret = bundleInstallChecker->CheckDeviceType(infos);
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

    // set hapPath
    std::for_each(infos.begin(), infos.end(), [](auto &item) {
        item.second.SetModuleHapPath(item.first);
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
        ret = bundleParser.Parse(realPath, innerBundleInfo);
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
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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
    appInfo.allowAppRunWhenDeviceFirstLocked = preBundleConfigInfo.allowAppRunWhenDeviceFirstLocked;
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
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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
                currentUserId = AccountHelper::GetCurrentActiveUserId();
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
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "dataMgr is null");
        return;
    }
    bool sceneBoardEnable = Rosen::SceneBoardJudgement::IsSceneBoardEnabled();
    LOG_I(BMS_TAG_DEFAULT, "HandleSceneBoard sceneBoardEnable : %{public}d", sceneBoardEnable);
    dataMgr->SetApplicationEnabled(ServiceConstants::SYSTEM_UI_BUNDLE_NAME, 0, !sceneBoardEnable,
        ServiceConstants::CALLER_NAME_BMS, Constants::DEFAULT_USERID);
    std::set<int32_t> userIds = dataMgr->GetAllUser();
    std::for_each(userIds.cbegin(), userIds.cend(), [dataMgr, sceneBoardEnable](const int32_t userId) {
        if (userId == 0) {
            return;
        }
        dataMgr->SetApplicationEnabled(Constants::SCENE_BOARD_BUNDLE_NAME, 0, sceneBoardEnable,
            ServiceConstants::CALLER_NAME_BMS, userId);
        dataMgr->SetApplicationEnabled(ServiceConstants::LAUNCHER_BUNDLE_NAME, 0, !sceneBoardEnable,
            ServiceConstants::CALLER_NAME_BMS, userId);
    });
#endif
}

void BMSEventHandler::InnerProcessStockBundleProvisionInfo()
{
    LOG_D(BMS_TAG_DEFAULT, "InnerProcessStockBundleProvisionInfo start");
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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
        auto hapVersionCode = infos.begin()->second.GetVersionCode();
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
        }
        InstallParam installParam;
        installParam.SetKillProcess(false);
        installParam.needSendEvent = false;
        installParam.installFlag = InstallFlag::REPLACE_EXISTING;
        installParam.copyHapToInstallPath = true;
        installParam.isOTA = isOta;
        installParam.withCopyHaps = true;
        installParam.isPatch = true;
        SystemBundleInstaller installer;
        std::vector<std::string> filePaths { scanPathIter };
        if (installer.OTAInstallSystemBundleNeedCheckUser(
            filePaths, installParam, bundleName, Constants::AppType::SYSTEM_APP) != ERR_OK) {
            LOG_W(BMS_TAG_DEFAULT, "bundleName: %{public}s: install failed", bundleName.c_str());
        }
    }
    LOG_I(BMS_TAG_DEFAULT, "end");
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
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "dataMgr is nullptr");
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
        BundleResourceHelper::AddResourceInfoByBundleName(bundleName, Constants::START_USERID,
            ADD_RESOURCE_TYPE::INSTALL_BUNDLE);
    }
    LOG_I(BMS_TAG_DEFAULT, "ProcessBundleResourceInfo end");
}

void BMSEventHandler::ProcessAllBundleDataGroupInfo()
{
    LOG_I(BMS_TAG_DEFAULT, "start");
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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
    EventReport::SendBundleSystemEvent(BundleEventType::UPDATE, eventInfo);
}

void BMSEventHandler::UpdatePreinstallDB(
    const std::unordered_map<std::string, std::pair<std::string, bool>> &needInstallMap)
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
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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
            item.second.AdaptMainLauncherResourceInfo(applicationInfo);
            preInstallBundleInfo.SetLabelId(applicationInfo.labelResource.id);
            preInstallBundleInfo.SetIconId(applicationInfo.iconResource.id);
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
        LOG_W(BMS_TAG_DEFAULT, "the app is not patch, bundleName: %{public}s", bundleName.c_str());
        return false;
    }
    // 2. check appType, current only Internal app types can be uninstall
    if (innerPatchInfo.GetAppPatchType() != AppPatchType::INTERNAL) {
        LOG_W(BMS_TAG_DEFAULT, "bundleName: %{public}s, app patch type err", bundleName.c_str());
        return false;
    }
    // 3. check version
    if (innerPatchInfo.GetVersionCode() != versionCode) {
        LOG_W(BMS_TAG_DEFAULT,
            "bundleName: %{public}s is not patch app, patchVersionCode: %{public}u, versionCode: %{public}u",
            bundleName.c_str(), innerPatchInfo.GetVersionCode(), versionCode);
        return false;
    }
    LOG_I(BMS_TAG_DEFAULT, "bundleName: %{public}s is patch app", bundleName.c_str());
    return true;
}

bool BMSEventHandler::GetValueFromJson(nlohmann::json &jsonObject)
{
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
    LOG_I(BMS_TAG_DEFAULT, "ProcessRebootQuickFixUnInstallAndRecover start");
    if (!BundleUtil::IsExistFile(QUICK_FIX_APP_RECOVER_FILE)) {
        LOG_E(BMS_TAG_DEFAULT, "end, reinstall json file is empty");
        return;
    }
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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
    LOG_I(BMS_TAG_DEFAULT, "ProcessRebootQuickFixUnInstallAndRecover end");
}

void BMSEventHandler::InnerProcessRebootUninstallWrongBundle()
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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

void BMSEventHandler::CheckAndCreateShareFilesSubDataDirs()
{
    LOG_D(BMS_TAG_DEFAULT, "begin");
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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
        UpdateAppDataMgr::CreateSharefilesSubDataDirs(bundleInfos, userId);
    }
    LOG_D(BMS_TAG_DEFAULT, "end");
}

void BMSEventHandler::CleanAllBundleShaderCache() const
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }
    std::vector<BundleInfo> bundleInfos;
    ErrCode res = dataMgr->GetBundleInfosV9(
        static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_DISABLE), bundleInfos, Constants::ALL_USERID);
    if (res != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "GetAllBundleInfos failed");
        return;
    }
    for (const auto &bundleInfo : bundleInfos) {
        if (bundleInfo.name.empty()) {
            continue;
        }
        std::string shaderCachePath;
        shaderCachePath.append(ServiceConstants::SHADER_CACHE_PATH).append(bundleInfo.name);
        ErrCode res = InstalldClient::GetInstance()->CleanBundleDataDir(shaderCachePath);
        if (res != ERR_OK) {
            LOG_NOFUNC_I(BMS_TAG_DEFAULT, "%{public}s clean shader fail %{public}d", bundleInfo.name.c_str(), res);
        }
    }
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
            auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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
    LOG_I(BMS_TAG_DEFAULT, "save BMS_SYSTEM_TIME_FOR_SHORTCUT succeed");
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
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }
    dataMgr->ProcessDynamicIconForOta();
    UpdateOtaFlag(OTAFlag::PROCESS_DYNAMIC_ICON);
}

void BMSEventHandler::InnerProcessAllThemeAndDynamicIconInfoWhenOta(
    const std::unordered_map<std::string, std::pair<std::string, bool>> &needInstallMap)
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
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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
    const InnerBundleInfo &innerBundleInfo = infos.begin()->second;
    preInstallBundleInfo.SetBundleName(innerBundleInfo.GetBundleName());
    preInstallBundleInfo.SetAppType(innerBundleInfo.GetAppType());
    preInstallBundleInfo.SetVersionCode(innerBundleInfo.GetVersionCode());
    for (const auto &item : infos) {
        preInstallBundleInfo.AddBundlePath(item.first);
    }
    preInstallBundleInfo.SetRemovable(true);
    preInstallBundleInfo.SetIsUninstalled(false);
    for (const auto &innerBundleInfo : infos) {
        auto applicationInfo = innerBundleInfo.second.GetBaseApplicationInfo();
        innerBundleInfo.second.AdaptMainLauncherResourceInfo(applicationInfo);
        preInstallBundleInfo.SetLabelId(applicationInfo.labelResource.id);
        preInstallBundleInfo.SetIconId(applicationInfo.iconResource.id);
        preInstallBundleInfo.SetModuleName(applicationInfo.labelResource.moduleName);
        preInstallBundleInfo.SetSystemApp(applicationInfo.isSystemApp);
        auto moduleMap = innerBundleInfo.second.GetInnerModuleInfos();
        if (innerBundleInfo.second.GetIsNewVersion()) {
            preInstallBundleInfo.SetBundleType(innerBundleInfo.second.GetApplicationBundleType());
        } else if (!moduleMap.empty() && moduleMap.begin()->second.distro.installationFree) {
            preInstallBundleInfo.SetBundleType(BundleType::ATOMIC_SERVICE);
        }
        if (!moduleMap.empty() && moduleMap.begin()->second.distro.moduleType == Profile::MODULE_TYPE_ENTRY) {
            break;
        }
    }
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
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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
    LOG_I(BMS_TAG_DEFAULT, "Need to check system optimize dir");
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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
        InstalldClient::GetInstance()->Mkdir(el1ArkStartupCachePath, ServiceConstants::SYSTEM_OPTIMIZE_MODE, 0, 0);
    }
    return true;
}

bool BMSEventHandler::CleanAllBundleEl1ArkStartupCacheLocal()
{
    LOG_I(BMS_TAG_DEFAULT, "start");
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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
            InstalldClient::GetInstance()->CleanBundleDataDir(el1BundleArkStartupCachePath);
        }
    }
    return true;
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
    std::string systemOptimizeShaderCache = ServiceConstants::SYSTEM_OPTIMIZE_SHADER_CACHE_PATH;
    systemOptimizeShaderCache = systemOptimizeShaderCache.replace(systemOptimizeShaderCache.find("%"),
        1, std::to_string(userId));
    systemOptimizeShaderCache = systemOptimizeShaderCache +
        cloneBundleName + ServiceConstants::SHADER_CACHE_SUBDIR;
    ErrCode ret = InstalldClient::GetInstance()->Mkdir(systemOptimizeShaderCache,
        ServiceConstants::NEW_SHADRE_CACHE_MODE,
        uid, ServiceConstants::NEW_SHADRE_CACHE_GID);
    if (ret != ERR_OK) {
        LOG_W(BMS_TAG_DEFAULT, "Mkdir %{public}s failed, error is %{public}d",
            systemOptimizeShaderCache.c_str(), errno);
        return ret;
    }
    return InstalldClient::GetInstance()->SetArkStartupCacheApl(systemOptimizeShaderCache);
}

ErrCode BMSEventHandler::CheckSystemOptimizeShaderCache()
{
    LOG_I(BMS_TAG_DEFAULT, "start");
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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
    std::string systemOptimizeShaderCache = ServiceConstants::SYSTEM_OPTIMIZE_SHADER_CACHE_PATH;
    systemOptimizeShaderCache = systemOptimizeShaderCache.replace(systemOptimizeShaderCache.find("%"),
        1, std::to_string(userId));
    systemOptimizeShaderCache = systemOptimizeShaderCache +
        cloneBundleName + ServiceConstants::SHADER_CACHE_SUBDIR;
    return InstalldClient::GetInstance()->CleanBundleDataDir(systemOptimizeShaderCache);
}

ErrCode BMSEventHandler::CleanSystemOptimizeShaderCache()
{
    LOG_I(BMS_TAG_DEFAULT, "start");
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
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
}  // namespace AppExecFwk
}  // namespace OHOS
