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

#include "bundle_mgr_service_event_handler.h"

#include <sstream>
#include <sys/stat.h>

#include "account_helper.h"
#include "aot/aot_handler.h"
#include "app_log_tag_wrapper.h"
#include "app_provision_info_manager.h"
#include "app_service_fwk_installer.h"
#include "bms_key_event_mgr.h"
#include "bundle_parser.h"
#include "bundle_permission_mgr.h"
#include "bundle_resource_helper.h"
#include "bundle_scanner.h"
#ifdef CONFIG_POLOCY_ENABLE
#include "config_policy_utils.h"
#endif
#if defined (BUNDLE_FRAMEWORK_SANDBOX_APP) && defined (DLP_PERMISSION_ENABLE)
#include "dlp_permission_kit.h"
#endif
#include "hmp_bundle_installer.h"
#include "installd_client.h"
#include "parameter.h"
#include "parameters.h"
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
const char* APP_SUFFIX = "/app";
const char* TEMP_PREFIX = "temp_";
const char* MODULE_PREFIX = "module_";
const char* PRE_INSTALL_HSP_PATH = "/shared_bundles/";
const char* BMS_TEST_UPGRADE = "persist.bms.test-upgrade";
const char* MODULE_UPDATE_PATH = "module_update";
const char* MODULE_UPDATE_PARAM = "persist.moduleupdate.bms.scan";
const char* MODULE_UPDATE_VALUE_UPDATE = "update";
const char* MODULE_UPDATE_VALUE_REVERT_BMS = "revert_bms";
const char* MODULE_UPDATE_VALUE_REVERT = "revert";
const char* MODULE_UPDATE_APP_SERVICE_DIR = "appServiceFwk";
const char* MODULE_UPDATE_INSTALL_RESULT = "persist.moduleupdate.bms.install.";
const char* MODULE_UPDATE_INSTALL_RESULT_FALSE = "false";
const char* MODULE_UPDATE_PARAM_EMPTY = "";
const char* FINGERPRINT = "fingerprint";
const char* UNKNOWN = "";
const char* VALUE_TRUE = "true";
const int8_t VERSION_LEN = 64;
const std::vector<std::string> FINGERPRINTS = {
    "const.product.software.version",
    "const.product.build.type",
    "const.product.brand",
    "const.product.name",
    "const.product.devicetype",
    "const.product.incremental.version",
    "const.comp.hl.product_base_version.real"
};
const char* HSP_VERSION_PREFIX = "v";
const char* OTA_FLAG = "otaFlag";
// pre bundle profile
constexpr const char* DEFAULT_PRE_BUNDLE_ROOT_DIR = "/system";
constexpr const char* PRODUCT_SUFFIX = "/etc/app";
constexpr const char* MODULE_UPDATE_PRODUCT_SUFFIX = "/etc/app/module_update";
constexpr const char* INSTALL_LIST_CONFIG = "/install_list.json";
constexpr const char* APP_SERVICE_FWK_INSTALL_LIST_CONFIG = "/app_service_fwk_install_list.json";
constexpr const char* UNINSTALL_LIST_CONFIG = "/uninstall_list.json";
constexpr const char* INSTALL_LIST_CAPABILITY_CONFIG = "/install_list_capability.json";
constexpr const char* EXTENSION_TYPE_LIST_CONFIG = "/extension_type_config.json";
constexpr const char* SHARED_BUNDLES_INSTALL_LIST_CONFIG = "/shared_bundles_install_list.json";
constexpr const char* SYSTEM_RESOURCES_APP_PATH = "/system/app/ohos.global.systemres";
constexpr const char* QUICK_FIX_APP_PATH = "/data/update/quickfix/app/temp/keepalive";
constexpr const char* RESTOR_BUNDLE_NAME_LIST = "list";
constexpr const char* QUICK_FIX_APP_RECOVER_FILE = "/data/update/quickfix/app/temp/quickfix_app_recover.json";

constexpr const char* INNER_UNDER_LINE = "_";
constexpr char SEPARATOR = '/';

std::set<PreScanInfo> installList_;
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
    LOG_I(BMS_TAG_DEFAULT, "BMSEventHandler BmsStartEvent start");
    BeforeBmsStart();
    OnBmsStarting();
    AfterBmsStart();
    LOG_I(BMS_TAG_DEFAULT, "BMSEventHandler BmsStartEvent end");
}

void BMSEventHandler::BeforeBmsStart()
{
    needNotifyBundleScanStatus_ = false;
    if (!BundlePermissionMgr::Init()) {
        LOG_W(BMS_TAG_DEFAULT, "BundlePermissionMgr::Init failed");
    }

    EventReport::SendScanSysEvent(BMSEventType::BOOT_SCAN_START);
}

void BMSEventHandler::OnBmsStarting()
{
    LOG_I(BMS_TAG_DEFAULT, "BMSEventHandler OnBmsStarting start");
    // Judge whether there is install info in the persistent Db
    if (LoadInstallInfosFromDb()) {
        LOG_I(BMS_TAG_DEFAULT, "OnBmsStarting Load install info from db success");
        BundleRebootStartEvent();
        return;
    }

    // If the preInstall infos does not exist in preInstall db,
    // all preInstall directory applications will be reinstalled.
    if (!LoadAllPreInstallBundleInfos()) {
        LOG_E(BMS_TAG_DEFAULT, "OnBmsStarting Load all preInstall bundleInfos failed");
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
            LOG_I(BMS_TAG_DEFAULT, "OnBmsStarting Guard against install infos lossed strategy take effect");
            if (needRebootOta_) {
                BundleRebootStartEvent();
            } else {
                needNotifyBundleScanStatus_ = true;
            }

            break;
        }
        case ResultCode::REINSTALL_OK: {
            LOG_I(BMS_TAG_DEFAULT, "OnBmsStarting ReInstall all haps");
            needNotifyBundleScanStatus_ = true;
            break;
        }
        case ResultCode::NO_INSTALLED_DATA: {
            // First boot
            LOG_I(BMS_TAG_DEFAULT, "OnBmsStarting first boot");
            BundleBootStartEvent();
            break;
        }
        default:
            LOG_E(BMS_TAG_DEFAULT, "System internal error, install informations missing");
            break;
    }

    SaveSystemFingerprint();
    LOG_I(BMS_TAG_DEFAULT, "BMSEventHandler OnBmsStarting end");
}

void BMSEventHandler::AfterBmsStart()
{
    LOG_I(BMS_TAG_DEFAULT, "BMSEventHandler AfterBmsStart start");
#ifdef BUNDLE_FRAMEWORK_QUICK_FIX
    DelayedSingleton<QuickFixBootScanner>::GetInstance()->ProcessQuickFixBootUp();
#endif
    DelayedSingleton<BundleMgrService>::GetInstance()->CheckAllUser();
    SetAllInstallFlag();
    HandleSceneBoard();
    DelayedSingleton<BundleMgrService>::GetInstance()->RegisterService();
    EventReport::SendScanSysEvent(BMSEventType::BOOT_SCAN_END);
    ClearCache();
    if (needNotifyBundleScanStatus_) {
        DelayedSingleton<BundleMgrService>::GetInstance()->NotifyBundleScanStatus();
    }
    ListeningUserUnlocked();
    RemoveUnreservedSandbox();
    DelayedSingleton<BundleMgrService>::GetInstance()->RegisterChargeIdleListener();
    BundleResourceHelper::RegisterCommonEventSubscriber();
    BundleResourceHelper::RegisterConfigurationObserver();
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
        OnBundleRebootStart();
        SaveSystemFingerprint();
        AOTHandler::GetInstance().HandleOTA();
    } else {
        HandlePreInstallException();
        ProcessRebootQuickFixBundleInstall(QUICK_FIX_APP_PATH, false);
        ProcessRebootQuickFixUnInstallAndRecover(QUICK_FIX_APP_RECOVER_FILE);
        CheckALLResourceInfo();
    }
    // need process main bundle status
    BmsKeyEventMgr::ProcessMainBundleStatusFinally();

    if (IsModuleUpdate()) {
        HandleModuleUpdate();
    }

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
        if (!BundleUtil::CheckFileType(hapPath, ServiceConstants::INSTALL_FILE_SUFFIX)) {
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
    auto cfgDirList = GetCfgDirList();
    if (cfgDirList != nullptr) {
        for (const auto &cfgDir : cfgDirList->paths) {
            if (cfgDir == nullptr) {
                continue;
            }

            LOG_NOFUNC_I(BMS_TAG_DEFAULT, "GetPreInstallRootDirList cfgDir: %{public}s", cfgDir);
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
        ParsePreBundleProFile(rootDir + PRODUCT_SUFFIX);
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
        AnalyzeHaps(isPreInstallApp, hapPaths.second, installInfos);
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
        }

        installInfos.at(bundleName).emplace_back(hapInfoIter.second);
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
        bundleExist = dataMgr->GetInnerBundleInfo(bundleName, dbInfo);
        if (bundleExist) {
            dataMgr->EnableBundle(bundleName);
        }
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
    LOG_I(BMS_TAG_DEFAULT, "Install systemHsp by bundleDir(%{public}s)", preScanInfo.bundleDir.c_str());
    InstallParam installParam;
    installParam.isPreInstallApp = true;
    installParam.removable = false;
    AppServiceFwkInstaller installer;
    ErrCode ret = installer.Install({preScanInfo.bundleDir}, installParam);
    if (ret != ERR_OK) {
        LOG_W(BMS_TAG_DEFAULT, "Install systemHsp %{public}s error", preScanInfo.bundleDir.c_str());
    }
}

bool BMSEventHandler::ProcessSystemHspInstall(const std::string &systemHspDir)
{
    LOG_I(BMS_TAG_DEFAULT, "Install systemHsp by bundleDir(%{public}s)", systemHspDir.c_str());
    InstallParam installParam;
    installParam.isPreInstallApp = true;
    installParam.removable = false;
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
    installParam.noSkipsKill = false;
    installParam.needSendEvent = false;
    installParam.removable = preScanInfo.removable;
    installParam.needSavePreInstallInfo = true;
    installParam.copyHapToInstallPath = false;
    SystemBundleInstaller installer;
    ErrCode ret = installer.InstallSystemBundle(preScanInfo.bundleDir, installParam, appType);
    if (ret != ERR_OK && ret != ERR_APPEXECFWK_INSTALL_ZERO_USER_WITH_NO_SINGLETON) {
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
    installParam.noSkipsKill = false;
    installParam.needSendEvent = false;
    installParam.removable = false;
    installParam.needSavePreInstallInfo = true;
    installParam.copyHapToInstallPath = false;
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
    installParam.noSkipsKill = false;
    installParam.needSendEvent = false;
    installParam.removable = false;
    installParam.needSavePreInstallInfo = true;
    installParam.sharedBundleDirPaths = {sharedBundlePath};
    SystemBundleInstaller installer;
    if (!installer.InstallSystemSharedBundle(installParam, false, appType)) {
        LOG_W(BMS_TAG_DEFAULT, "install system shared bundle: %{public}s error", sharedBundlePath.c_str());
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
    ProcessRebootBundleInstall();
    ProcessRebootBundleUninstall();
    ProcessRebootQuickFixBundleInstall(QUICK_FIX_APP_PATH, true);
    ProcessRebootQuickFixUnInstallAndRecover(QUICK_FIX_APP_RECOVER_FILE);
    ProcessBundleResourceInfo();
#ifdef CHECK_ELDIR_ENABLED
    ProcessCheckAppDataDir();
#endif
    ProcessCheckAppLogDir();
    ProcessCheckAppFileManagerDir();
    ProcessCheckPreinstallData();
    ProcessCheckShaderCacheDir();
    ProcessCheckCloudShaderDir();
    ProcessNewBackupDir();
    RefreshQuotaForAllUid();
    ProcessCheckRecoverableApplicationInfo();
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
        if (!dataMgr->GetBundleInfos(BundleFlag::GET_BUNDLE_DEFAULT, bundleInfos, userId)) {
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
            BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, Constants::ALL_USERID)) {
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
    if (!dataMgr->GetBundleInfos(BundleFlag::GET_BUNDLE_DEFAULT, bundleInfos, Constants::DEFAULT_USERID)) {
        LOG_E(BMS_TAG_DEFAULT, "GetAllBundleInfos failed");
        return;
    }
    UpdateAppDataMgr::ProcessUpdateAppLogDir(bundleInfos, Constants::DEFAULT_USERID);
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
    if (!dataMgr->GetBundleInfos(BundleFlag::GET_BUNDLE_DEFAULT, bundleInfos, Constants::DEFAULT_USERID)) {
        LOG_E(BMS_TAG_DEFAULT, "GetAllBundleInfos failed");
        return;
    }
    UpdateAppDataMgr::ProcessFileManagerDir(bundleInfos, Constants::DEFAULT_USERID);
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
    if (!dataMgr->GetBundleInfos(BundleFlag::GET_BUNDLE_DEFAULT, bundleInfos, Constants::ALL_USERID)) {
        LOG_E(BMS_TAG_DEFAULT, "GetAllBundleInfos failed");
        return;
    }
    for (const auto &bundleInfo : bundleInfos) {
        std::string shaderCachePath;
        shaderCachePath.append(ServiceConstants::SHADER_CACHE_PATH).append(bundleInfo.name);
        ErrCode res = InstalldClient::GetInstance()->Mkdir(shaderCachePath, S_IRWXU, bundleInfo.uid, bundleInfo.gid);
        if (res != ERR_OK) {
            LOG_I(BMS_TAG_DEFAULT, "create shader cache failed: %{public}s ", shaderCachePath.c_str());
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
        if (userId == Constants::DEFAULT_USERID) {
            continue;
        }
        std::vector<BundleInfo> bundleInfos;
        if (!dataMgr->GetBundleInfos(BundleFlag::GET_BUNDLE_DEFAULT, bundleInfos, userId)) {
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
    ErrCode result = InstalldClient::GetInstance()->IsExistDir(ServiceConstants::CLOUD_SHADER_PATH, cloudExist);
    if (result != ERR_OK) {
        LOG_W(BMS_TAG_DEFAULT, "IsExistDir failed, error is %{public}d", result);
        return;
    }
    if (cloudExist) {
        LOG_D(BMS_TAG_DEFAULT, "CLOUD_SHADER_PATH is exist");
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
        bundleName, BundleFlag::GET_BUNDLE_DEFAULT, info, Constants::ANY_USERID);
    if (!hasBundleInstalled) {
        LOG_D(BMS_TAG_DEFAULT, "Obtain bundleInfo failed, bundleName: %{public}s not exist", bundleName.c_str());
        return;
    }

    constexpr int32_t mode = (S_IRWXU | S_IXGRP | S_IXOTH);
    result = InstalldClient::GetInstance()->Mkdir(ServiceConstants::CLOUD_SHADER_PATH, mode, info.uid, info.gid);
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
            BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, Constants::ALL_USERID)) {
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
    SendToStorageQuota(bundleName, uid, bundleDataDirPath, atomicserviceDatasizeThreshold);
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
        LOG_I(BMS_TAG_DEFAULT, "Process reboot preBundle proFile install %{public}s", installInfo.ToString().c_str());
        if (uninstallList_.find(installInfo.bundleDir) != uninstallList_.end()) {
            LOG_W(BMS_TAG_DEFAULT, "(%{public}s) not allowed installed when reboot", installInfo.bundleDir.c_str());
            continue;
        }

        if (installInfo.bundleDir.find(PRE_INSTALL_HSP_PATH) != std::string::npos) {
            LOG_I(BMS_TAG_DEFAULT, "found shared bundle path: %{public}s", installInfo.bundleDir.c_str());
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
}

void BMSEventHandler::ProcessRebootBundleInstallFromScan()
{
    LOG_D(BMS_TAG_DEFAULT, "Process reboot bundle install from scan");
    std::list<std::string> bundleDirs;
    GetBundleDirFromScan(bundleDirs);
    InnerProcessRebootBundleInstall(bundleDirs, Constants::AppType::SYSTEM_APP);
    InnerProcessStockBundleProvisionInfo();
}

void BMSEventHandler::InnerProcessRebootBundleInstall(
    const std::list<std::string> &scanPathList, Constants::AppType appType)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }

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
            LOG_I(BMS_TAG_DEFAULT, "OTA Install new bundle(%{public}s) by path(%{public}s)",
                bundleName.c_str(), scanPathIter.c_str());
            std::vector<std::string> filePaths { scanPathIter };
            if (!OTAInstallSystemBundle(filePaths, appType, removable)) {
                LOG_E(BMS_TAG_DEFAULT, "OTA Install new bundle(%{public}s) error", bundleName.c_str());
                SavePreInstallException(scanPathIter);
            }

            continue;
        }

        LOG_NOFUNC_I(BMS_TAG_DEFAULT, "OTA process bundle(%{public}s) by path(%{public}s)",
            bundleName.c_str(), scanPathIter.c_str());
        BundleInfo hasInstalledInfo;
        auto hasBundleInstalled = dataMgr->GetBundleInfo(
            bundleName, BundleFlag::GET_BUNDLE_DEFAULT, hasInstalledInfo, Constants::ANY_USERID);
        if (!hasBundleInstalled && mapIter->second.IsUninstalled()) {
            LOG_W(BMS_TAG_DEFAULT, "app(%{public}s) has been uninstalled and do not OTA install",
                bundleName.c_str());
            if (!removable) {
                std::vector<std::string> filePaths { scanPathIter };
                if (!OTAInstallSystemBundle(filePaths, appType, removable)) {
                    LOG_E(BMS_TAG_DEFAULT, "OTA Install prefab bundle(%{public}s) error", bundleName.c_str());
                    SavePreInstallException(scanPathIter);
                }
            } else {
                UpdatePreinstallDBForUninstalledBundle(bundleName, infos);
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
                LOG_E(BMS_TAG_DEFAULT, "bundleName: %{public}s update failed, versionCode(%{public}d) is lower than "
                    "installed bundle(%{public}d)", bundleName.c_str(), hapVersionCode, hasInstalledInfo.versionCode);
                SendBundleUpdateFailedEvent(hasInstalledInfo);
                break;
            }
        }

        if (updateBundle) {
            filePaths.clear();
            filePaths.emplace_back(scanPathIter);
        }

        if (filePaths.empty()) {
#ifdef USE_PRE_BUNDLE_PROFILE
            UpdateRemovable(bundleName, removable);
#endif
            continue;
        }

        if (!OTAInstallSystemBundleNeedCheckUser(filePaths, bundleName, appType, removable)) {
            LOG_E(BMS_TAG_DEFAULT, "OTA bundle(%{public}s) failed", bundleName.c_str());
            SavePreInstallException(scanPathIter);
#ifdef USE_PRE_BUNDLE_PROFILE
            UpdateRemovable(bundleName, removable);
#endif
        }
    }
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
        if (oldBundleInfo.GetVersionCode() == versionCode) {
            if (!IsNeedToUpdateSharedAppByHash(oldBundleInfo, infos.begin()->second)) {
                LOG_D(BMS_TAG_DEFAULT, "the installed version is up-to-date");
                continue;
            }
        }

        if (!OTAInstallSystemSharedBundle({scanPath}, appType, removable)) {
            LOG_E(BMS_TAG_DEFAULT, "OTA update shared bundle(%{public}s) error", bundleName.c_str());
        }
    }
}

void BMSEventHandler::InnerProcessRebootSystemHspInstall(const std::list<std::string> &scanPathList)
{
    LOG_I(BMS_TAG_DEFAULT, "InnerProcessRebootSystemHspInstall");
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }
    for (const auto &scanPath : scanPathList) {
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
            LOG_I(BMS_TAG_DEFAULT, "OTA Install new system hsp(%{public}s) by path(%{public}s)",
                bundleName.c_str(), scanPath.c_str());
            if (OTAInstallSystemHsp({scanPath}) != ERR_OK) {
                LOG_E(BMS_TAG_DEFAULT, "OTA Install new system hsp(%{public}s) error", bundleName.c_str());
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
        if (oldBundleInfo.GetVersionCode() == versionCode) {
            for (const auto &item : infos) {
                if (!IsNeedToUpdateSharedHspByHash(oldBundleInfo, item.second)) {
                    LOG_D(BMS_TAG_DEFAULT, "the installed version is up-to-date");
                    continue;
                }
            }
        }
        if (OTAInstallSystemHsp({scanPath}) != ERR_OK) {
            LOG_E(BMS_TAG_DEFAULT, "OTA update shared bundle(%{public}s) error", bundleName.c_str());
        }
    }
}

ErrCode BMSEventHandler::OTAInstallSystemHsp(const std::vector<std::string> &filePaths)
{
    InstallParam installParam;
    installParam.isPreInstallApp = true;
    installParam.removable = false;
    AppServiceFwkInstaller installer;

    return installer.Install(filePaths, installParam);
}

bool BMSEventHandler::IsNeedToUpdateSharedHspByHash(
    const InnerBundleInfo &oldInfo, const InnerBundleInfo &newInfo) const
{
    std::string moduleName = newInfo.GetCurrentModulePackage();
    std::string newModuleBuildHash;
    if (!newInfo.GetModuleBuildHash(moduleName, newModuleBuildHash)) {
        LOG_E(BMS_TAG_DEFAULT, "internal error, can not find module %{public}s", moduleName.c_str());
        return false;
    }

    std::string oldModuleBuildHash;
    if (!oldInfo.GetModuleBuildHash(moduleName, oldModuleBuildHash) ||
        newModuleBuildHash != oldModuleBuildHash) {
        LOG_D(BMS_TAG_DEFAULT, "module %{public}s need to be updated", moduleName.c_str());
        return true;
    }
    return false;
}

bool BMSEventHandler::IsNeedToUpdateSharedAppByHash(
    const InnerBundleInfo &oldInfo, const InnerBundleInfo &newInfo) const
{
    auto oldSharedModuleMap = oldInfo.GetInnerSharedModuleInfos();
    auto newSharedModuleMap = newInfo.GetInnerSharedModuleInfos();
    for (const auto &item : newSharedModuleMap) {
        auto newModuleName = item.first;
        auto oldModuleInfos = oldSharedModuleMap[newModuleName];
        auto newModuleInfos = item.second;
        if (!oldModuleInfos.empty() && !newModuleInfos.empty()) {
            auto oldBuildHash = oldModuleInfos[0].buildHash;
            auto newBuildHash = newModuleInfos[0].buildHash;
            return oldBuildHash != newBuildHash;
        } else {
            return true;
        }
    }
    return false;
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
    ProcessRevertAppPath(moduleUpdateAppServiceMap, moduleUpdateNotAppServiceMap);
    // 2. install all hmp, if install failed,
    HandleInstallHmp(moduleUpdateAppServiceMap, moduleUpdateNotAppServiceMap);
    // 3. handle install result
    HandleInstallHmpResult();
    // 4. handle module update uninstall
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

void BMSEventHandler::ProcessRevertAppPath(
    std::map<std::string, std::vector<std::string>> &moduleUpdateAppServiceMap,
    std::map<std::string, std::vector<std::string>> &moduleUpdateNotAppServiceMap)
{
    if (moduleUpdateStatus_ != ModuleUpdateStatus::REVERT) {
        return;
    }
    std::vector<std::string> hmpList;
    if (!GetRevertHmpList(hmpList, moduleUpdateAppServiceMap, moduleUpdateNotAppServiceMap)) {
        LOG_E(BMS_TAG_DEFAULT, "get hmp path failed");
        return;
    }
    LOG_I(BMS_TAG_DEFAULT, "revert hmp list: %{public}s", BundleUtil::ToString(hmpList).c_str());
    for (auto it = moduleUpdateAppServiceMap.begin(); it != moduleUpdateAppServiceMap.end();) {
        if (std::find(hmpList.begin(), hmpList.end(), it->first) == hmpList.end()) {
            it = moduleUpdateAppServiceMap.erase(it);
        } else {
            ++it;
        }
    }

    for (auto it = moduleUpdateNotAppServiceMap.begin(); it != moduleUpdateNotAppServiceMap.end();) {
        if (std::find(hmpList.begin(), hmpList.end(), it->first) == hmpList.end()) {
            it = moduleUpdateNotAppServiceMap.erase(it);
        } else {
            ++it;
        }
    }
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
        if (res != ERR_OK) {
            LOG_E(BMS_TAG_DEFAULT, "install %{public}s path failed", appDir.c_str());
            result = false;
        }
    }

    return result;
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

bool BMSEventHandler::GetRevertHmpList(std::vector<std::string> &revertHmpList,
    std::map<std::string, std::vector<std::string>> &moduleUpdateAppServiceMap,
    std::map<std::string, std::vector<std::string>> &moduleUpdateNotAppServiceMap)
{
    std::vector<std::string> hmpList;
    GetHmpList(hmpList, moduleUpdateAppServiceMap, moduleUpdateNotAppServiceMap);
    for (const std::string &hmp : hmpList) {
        std::string hmpInstallPara = MODULE_UPDATE_INSTALL_RESULT + hmp;
        std::string paramValue;
        if (!GetSystemParameter(hmpInstallPara, paramValue) || paramValue != MODULE_UPDATE_INSTALL_RESULT_FALSE) {
            continue;
        }

        LOG_I(BMS_TAG_DEFAULT, "hmp %{public}s need to revert", hmp.c_str());
        revertHmpList.emplace_back(hmp);
    }
    return true;
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

void BMSEventHandler::HandleInstallHmpResult()
{
    ModuleUpdateRollBack();
    ProcessModuleUpdateSystemParameters();
}

void BMSEventHandler::ModuleUpdateRollBack()
{
    if (moduleUpdateStatus_ != ModuleUpdateStatus::UPDATE) {
        return;
    }
    for (const auto &item : moduleUpdateInstallResults_) {
        LOG_I(BMS_TAG_DEFAULT, "hmp %{public}s install result %{public}d", item.first.c_str(), item.second);
        if (item.second) {
            continue;
        }
        LOG_W(BMS_TAG_DEFAULT, "hmp %{public}s need to rollback", item.first.c_str());
        // rollback hmp which install failed
        std::shared_ptr<HmpBundleInstaller> installer = std::make_shared<HmpBundleInstaller>();
        installer->RollbackHmpBundle(moduleUpdateAppService_[item.first], moduleUpdateNormalApp_[item.first]);
    }
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
    LOG_I(BMS_TAG_DEFAULT, "Reboot scan and OTA uninstall start");
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }

    for (auto &loadIter : loadExistData_) {
        std::string bundleName = loadIter.first;
        auto listIter = hapParseInfoMap_.find(bundleName);
        if (listIter == hapParseInfoMap_.end()) {
            LOG_I(BMS_TAG_DEFAULT, "ProcessRebootBundleUninstall OTA uninstall app(%{public}s)", bundleName.c_str());
            SystemBundleInstaller installer;
            if (!installer.UninstallSystemBundle(bundleName)) {
                LOG_E(BMS_TAG_DEFAULT, "OTA uninstall app(%{public}s) error", bundleName.c_str());
            } else {
                LOG_I(BMS_TAG_DEFAULT, "OTA uninstall preInstall bundleName:%{public}s succeed", bundleName.c_str());
                std::string moduleName;
                DeletePreInfoInDb(bundleName, moduleName, true);
            }

            continue;
        }

        BundleInfo hasInstalledInfo;
        auto hasBundleInstalled = dataMgr->GetBundleInfo(
            bundleName, BundleFlag::GET_BUNDLE_DEFAULT, hasInstalledInfo, Constants::ANY_USERID);
        if (!hasBundleInstalled) {
            LOG_W(BMS_TAG_DEFAULT, "app(%{public}s) maybe has been uninstall", bundleName.c_str());
            continue;
        }
        // Check the installed module
        if (InnerProcessUninstallModule(hasInstalledInfo, listIter->second)) {
            LOG_I(BMS_TAG_DEFAULT, "bundleName:%{public}s need delete module", bundleName.c_str());
        }
        // Check the preInstall path in Db.
        // If the corresponding Hap does not exist, it should be deleted.
        auto parserInfoMap = listIter->second;
        for (auto preBundlePath : loadIter.second.GetBundlePaths()) {
            auto parserInfoIter = parserInfoMap.find(preBundlePath);
            if (parserInfoIter != parserInfoMap.end()) {
                LOG_I(BMS_TAG_DEFAULT, "OTA uninstall app(%{public}s) module path(%{public}s) exits",
                    bundleName.c_str(), preBundlePath.c_str());
                continue;
            }

            LOG_I(BMS_TAG_DEFAULT, "OTA app(%{public}s) delete path(%{public}s)",
                bundleName.c_str(), preBundlePath.c_str());
            DeletePreInfoInDb(bundleName, preBundlePath, false);
        }
    }

    LOG_I(BMS_TAG_DEFAULT, "Reboot scan and OTA uninstall success");
}

bool BMSEventHandler::InnerProcessUninstallModule(const BundleInfo &bundleInfo,
    const std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    if (infos.empty()) {
        LOG_I(BMS_TAG_DEFAULT, "bundleName:%{public}s infos is empty", bundleInfo.name.c_str());
        return false;
    }
    if (bundleInfo.versionCode > infos.begin()->second.GetVersionCode()) {
        LOG_I(BMS_TAG_DEFAULT, "%{public}s version code is bigger than new pre-hap", bundleInfo.name.c_str());
        return false;
    }
    for (const auto &hapModuleInfo : bundleInfo.hapModuleInfos) {
        if (hapModuleInfo.hapPath.find(Constants::BUNDLE_CODE_DIR) == 0) {
            return false;
        }
    }
    if (bundleInfo.hapModuleNames.size() == 1) {
        LOG_I(BMS_TAG_DEFAULT, "bundleName:%{public}s only has one module, can not be uninstalled",
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
        LOG_I(BMS_TAG_DEFAULT, "DeletePreInfoInDb bundle %{public}s bundleLevel", bundleName.c_str());
        dataMgr->DeletePreInstallBundleInfo(bundleName, preInstallBundleInfo);
        return;
    }

    LOG_I(BMS_TAG_DEFAULT, "DeletePreInfoInDb bundle %{public}s not bundleLevel with path(%{public}s)",
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

    LOG_I(BMS_TAG_DEFAULT, "Starting to save pre-install exception for bundle: %{public}s", bundleDir.c_str());
    preInstallExceptionMgr->SavePreInstallExceptionPath(bundleDir);
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
    if (!preInstallExceptionMgr->GetAllPreInstallExceptionInfo(
        exceptionPaths, exceptionBundleNames)) {
        LOG_I(BMS_TAG_DEFAULT, "No pre-install exception information found");
        return;
    }

    LOG_I(BMS_TAG_DEFAULT, "HandlePreInstallExceptions pathSize: %{public}zu, bundleNameSize: %{public}zu",
        exceptionPaths.size(), exceptionBundleNames.size());
    for (const auto &pathIter : exceptionPaths) {
        LOG_I(BMS_TAG_DEFAULT, "HandlePreInstallException path: %{public}s", pathIter.c_str());
        std::vector<std::string> filePaths { pathIter };
        bool removable = IsPreInstallRemovable(pathIter);
        if (!OTAInstallSystemBundle(filePaths, Constants::AppType::SYSTEM_APP, removable)) {
            LOG_W(BMS_TAG_DEFAULT, "HandlePreInstallException path(%{public}s) error", pathIter.c_str());
        }

        preInstallExceptionMgr->DeletePreInstallExceptionPath(pathIter);
        LOG_I(BMS_TAG_DEFAULT, "Deleted pre-install exception path: %{public}s", pathIter.c_str());
    }

    if (exceptionBundleNames.size() > 0) {
        LOG_I(BMS_TAG_DEFAULT, "Loading all pre-install bundle infos");
        LoadAllPreInstallBundleInfos();
    }

    for (const auto &bundleNameIter : exceptionBundleNames) {
        LOG_I(BMS_TAG_DEFAULT, "HandlePreInstallException bundleName: %{public}s", bundleNameIter.c_str());
        auto iter = loadExistData_.find(bundleNameIter);
        if (iter == loadExistData_.end()) {
            LOG_W(BMS_TAG_DEFAULT, "HandlePreInstallException no bundleName(%{public}s) in PreInstallDb",
                bundleNameIter.c_str());
            continue;
        }

        const auto &preInstallBundleInfo = iter->second;
        if (!OTAInstallSystemBundle(preInstallBundleInfo.GetBundlePaths(),
            Constants::AppType::SYSTEM_APP, preInstallBundleInfo.IsRemovable())) {
            LOG_W(BMS_TAG_DEFAULT, "HandlePreInstallException bundleName(%{public}s) error", bundleNameIter.c_str());
        }

        LOG_I(BMS_TAG_DEFAULT, "Deleting %{public}s from pre-install exception list", bundleNameIter.c_str());
        preInstallExceptionMgr->DeletePreInstallExceptionBundleName(bundleNameIter);
    }

    preInstallExceptionMgr->ClearAll();
    LOG_I(BMS_TAG_DEFAULT, "Pre-install exception information cleared successfully");
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
    installParam.noSkipsKill = false;
    installParam.needSendEvent = false;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.removable = removable;
    installParam.needSavePreInstallInfo = true;
    installParam.copyHapToInstallPath = false;
    installParam.isOTA = true;
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
    installParam.noSkipsKill = false;
    installParam.needSendEvent = false;
    installParam.installFlag = InstallFlag::REPLACE_EXISTING;
    installParam.removable = removable;
    installParam.needSavePreInstallInfo = true;
    installParam.copyHapToInstallPath = false;
    installParam.isOTA = true;
    SystemBundleInstaller installer;
    ErrCode ret = installer.OTAInstallSystemBundleNeedCheckUser(filePaths, installParam, bundleName, appType);
    LOG_NOFUNC_I(BMS_TAG_DEFAULT, "bundle %{public}s with return code: %{public}d", bundleName.c_str(), ret);
    if (ret == ERR_APPEXECFWK_INSTALL_ZERO_USER_WITH_NO_SINGLETON) {
        ret = ERR_OK;
    }
    if (ret != ERR_OK) {
        APP_LOGE("OTA bundle(%{public}s) failed, errCode:%{public}d", bundleName.c_str(), ret);
    }
    return ret == ERR_OK;
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
    SystemBundleInstaller installer;
    return installer.InstallSystemSharedBundle(installParam, true, appType);
}

bool BMSEventHandler::CheckAndParseHapFiles(
    const std::string &hapFilePath,
    bool isPreInstallApp,
    std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    std::unique_ptr<BundleInstallChecker> bundleInstallChecker =
        std::make_unique<BundleInstallChecker>();
    std::vector<std::string> hapFilePathVec { hapFilePath };
    std::vector<std::string> realPaths;
    auto ret = BundleUtil::CheckFilePath(hapFilePathVec, realPaths);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "File path %{public}s invalid", hapFilePath.c_str());
        return false;
    }

    ret = bundleInstallChecker->CheckSysCap(realPaths);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "hap(%{public}s) syscap check failed", hapFilePath.c_str());
        return false;
    }

    std::vector<Security::Verify::HapVerifyResult> hapVerifyResults;
    ret = bundleInstallChecker->CheckMultipleHapsSignInfo(realPaths, hapVerifyResults);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "CheckMultipleHapsSignInfo %{public}s failed", hapFilePath.c_str());
        return false;
    }

    InstallCheckParam checkParam;
    checkParam.isPreInstallApp = isPreInstallApp;
    if (isPreInstallApp) {
        checkParam.appType = Constants::AppType::SYSTEM_APP;
    }

    ret = bundleInstallChecker->ParseHapFiles(
        realPaths, checkParam, hapVerifyResults, infos);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "parse haps file(%{public}s) failed", hapFilePath.c_str());
        return false;
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
    auto ret = BundleVerifyMgr::ParseHapProfile(filePath, hapVerifyResult);
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
            result = InstalldClient::GetInstance()->SetDirApl(baseDataDir, bundleName, apl, isPreInstall, debug);
            if (result != ERR_OK) {
                LOG_W(BMS_TAG_DEFAULT, "bundleName: %{public}s, fail to SetDirApl baseDataDir dir, error is %{public}d",
                    bundleName.c_str(), result);
            }
            std::string databaseDataDir = baseBundleDataDir + ServiceConstants::DATABASE + bundleName;
            result = InstalldClient::GetInstance()->SetDirApl(databaseDataDir, bundleName, apl, isPreInstall, debug);
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
    dataMgr->SetApplicationEnabled(ServiceConstants::SYSTEM_UI_BUNDLE_NAME, !sceneBoardEnable,
        Constants::DEFAULT_USERID);
    std::set<int32_t> userIds = dataMgr->GetAllUser();
    std::for_each(userIds.cbegin(), userIds.cend(), [dataMgr, sceneBoardEnable](const int32_t userId) {
        if (userId == 0) {
            return;
        }
        dataMgr->SetApplicationEnabled(Constants::SCENE_BOARD_BUNDLE_NAME, sceneBoardEnable, userId);
        dataMgr->SetApplicationEnabled(ServiceConstants::LAUNCHER_BUNDLE_NAME, !sceneBoardEnable, userId);
    });
#endif
}

void BMSEventHandler::InnerProcessStockBundleProvisionInfo()
{
    LOG_D(BMS_TAG_DEFAULT, "InnerProcessStockBundleProvisionInfo start");
    std::unordered_set<std::string> allBundleNames;
    if (!DelayedSingleton<AppProvisionInfoManager>::GetInstance()->GetAllAppProvisionInfoBundleName(allBundleNames)) {
        LOG_E(BMS_TAG_DEFAULT, "GetAllAppProvisionInfoBundleName failed");
        return;
    }
    // process normal bundle
    ProcessBundleProvisionInfo(allBundleNames);
    // process shared bundle
    ProcessSharedBundleProvisionInfo(allBundleNames);
    LOG_D(BMS_TAG_DEFAULT, "InnerProcessStockBundleProvisionInfo end");
}

void BMSEventHandler::ProcessBundleProvisionInfo(const std::unordered_set<std::string> &allBundleNames)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }
    std::vector<BundleInfo> bundleInfos;
    if (dataMgr->GetBundleInfosV9(static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE),
        bundleInfos, Constants::ALL_USERID) != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "GetBundleInfos failed");
        return;
    }
    for (const auto &bundleInfo : bundleInfos) {
        // not exist in appProvisionInfo table, then parse profile info and save it
        if ((allBundleNames.find(bundleInfo.name) == allBundleNames.end()) &&
            !bundleInfo.hapModuleInfos.empty()) {
            AddStockAppProvisionInfoByOTA(bundleInfo.name, bundleInfo.hapModuleInfos[0].hapPath);
        }
    }
}

void BMSEventHandler::ProcessSharedBundleProvisionInfo(const std::unordered_set<std::string> &allBundleNames)
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "DataMgr is nullptr");
        return;
    }
    std::vector<SharedBundleInfo> shareBundleInfos;
    if (dataMgr->GetAllSharedBundleInfo(shareBundleInfos) != ERR_OK) {
        LOG_E(BMS_TAG_DEFAULT, "GetAllSharedBundleInfo failed");
        return;
    }
    for (const auto &sharedBundleInfo : shareBundleInfos) {
        // not exist in appProvisionInfo table, then parse profile info and save it
        if ((allBundleNames.find(sharedBundleInfo.name) == allBundleNames.end()) &&
            !sharedBundleInfo.sharedModuleInfos.empty()) {
            std::string hspPath = std::string(Constants::BUNDLE_CODE_DIR)
                + ServiceConstants::PATH_SEPARATOR + sharedBundleInfo.name
                + ServiceConstants::PATH_SEPARATOR + HSP_VERSION_PREFIX
                + std::to_string(sharedBundleInfo.sharedModuleInfos[0].versionCode) + ServiceConstants::PATH_SEPARATOR
                + sharedBundleInfo.sharedModuleInfos[0].name + ServiceConstants::PATH_SEPARATOR
                + sharedBundleInfo.sharedModuleInfos[0].name + ServiceConstants::HSP_FILE_SUFFIX;
            AddStockAppProvisionInfoByOTA(sharedBundleInfo.name, hspPath);
        }
    }
}

void BMSEventHandler::ProcessRebootQuickFixBundleInstall(const std::string &path, bool isOta)
{
    LOG_I(BMS_TAG_DEFAULT, "ProcessRebootQuickFixBundleInstall start, isOta:%{public}d", isOta);
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
            bundleName, BundleFlag::GET_BUNDLE_DEFAULT, hasInstalledInfo, Constants::ANY_USERID);
        if (!hasBundleInstalled) {
            LOG_W(BMS_TAG_DEFAULT, "obtain bundleInfo failed, bundleName :%{public}s not exist", bundleName.c_str());
            continue;
        }
        if (hapVersionCode <= hasInstalledInfo.versionCode) {
            LOG_W(BMS_TAG_DEFAULT, "bundleName: %{public}s: hapVersionCode is less than old hap versionCode",
                bundleName.c_str());
            continue;
        }
        if (!hasInstalledInfo.isKeepAlive) {
            LOG_W(BMS_TAG_DEFAULT, "bundleName: %{public}s: is not keep alive bundle", bundleName.c_str());
            continue;
        }
        InstallParam installParam;
        installParam.noSkipsKill = false;
        installParam.needSendEvent = false;
        installParam.installFlag = InstallFlag::REPLACE_EXISTING;
        installParam.copyHapToInstallPath = true;
        installParam.isOTA = isOta;
        SystemBundleInstaller installer;
        std::vector<std::string> filePaths { scanPathIter };
        if (!installer.OTAInstallSystemBundle(filePaths, installParam, Constants::AppType::SYSTEM_APP)) {
            LOG_W(BMS_TAG_DEFAULT, "bundleName: %{public}s: install failed", bundleName.c_str());
        }
    }
    LOG_I(BMS_TAG_DEFAULT, "ProcessRebootQuickFixBundleInstall end");
}

void BMSEventHandler::CheckALLResourceInfo()
{
    LOG_I(BMS_TAG_DEFAULT, "start");
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
        BundleResourceHelper::AddResourceInfoByBundleName(bundleName, Constants::START_USERID);
    }
    LOG_I(BMS_TAG_DEFAULT, "ProcessBundleResourceInfo end");
}

void BMSEventHandler::SendBundleUpdateFailedEvent(const BundleInfo &bundleInfo)
{
    LOG_I(BMS_TAG_DEFAULT, "SendBundleUpdateFailedEvent start, bundleName:%{public}s", bundleInfo.name.c_str());
    EventInfo eventInfo;
    eventInfo.userId = Constants::ANY_USERID;
    eventInfo.bundleName = bundleInfo.name;
    eventInfo.versionCode = bundleInfo.versionCode;
    eventInfo.errCode = ERR_APPEXECFWK_INSTALL_VERSION_DOWNGRADE;
    eventInfo.isPreInstallApp = bundleInfo.isPreInstallApp;
    EventReport::SendBundleSystemEvent(BundleEventType::UPDATE, eventInfo);
}

void BMSEventHandler::UpdatePreinstallDBForUninstalledBundle(const std::string &bundleName,
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
    if (innerBundleInfos.begin()->second.GetBaseBundleInfo().versionCode <= preInstallBundleInfo.GetVersionCode()) {
        LOG_I(BMS_TAG_DEFAULT, "bundle no change");
        return;
    }
    LOG_I(BMS_TAG_DEFAULT, "begin update preinstall DB for %{public}s", bundleName.c_str());
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
        }
        auto bundleInfo = item.second.GetBaseBundleInfo();
        if (!bundleInfo.hapModuleInfos.empty() &&
            bundleInfo.hapModuleInfos[0].moduleType == ModuleType::ENTRY) {
            findEntry = true;
        }
    }
    dataMgr->SavePreInstallBundleInfo(bundleName, preInstallBundleInfo);
}

bool BMSEventHandler::IsQuickfixFlagExsit(const BundleInfo &bundleInfo)
{
    // check the quickfix flag.
    for (auto const & hapModuleInfo : bundleInfo.hapModuleInfos) {
        for (auto const & metadata : hapModuleInfo.metadata) {
            if (metadata.name.compare("ohos.app.quickfix") == 0) {
                return true;
            }
        }
    }
    return false;
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
    auto installer = DelayedSingleton<BundleMgrService>::GetInstance()->GetBundleInstaller();
    if (installer == nullptr) {
        LOG_E(BMS_TAG_DEFAULT, "installer is nullptr");
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
    nlohmann::json jsonObject;
    if (!BundleParser::ReadFileIntoJson(QUICK_FIX_APP_RECOVER_FILE, jsonObject) || !jsonObject.is_object() ||
        !GetValueFromJson(jsonObject)) {
        LOG_E(BMS_TAG_DEFAULT, "get jsonObject from path failed or get value failed");
        return;
    }
    for (const std::string &bundleName : bundleNameList_) {
        BundleInfo hasInstalledInfo;
        auto hasBundleInstalled =
            dataMgr->GetBundleInfo(bundleName, BundleFlag::GET_BUNDLE_DEFAULT, hasInstalledInfo, Constants::ANY_USERID);
        if (!hasBundleInstalled) {
            LOG_W(BMS_TAG_DEFAULT, "obtain bundleInfo failed, bundleName :%{public}s not exist", bundleName.c_str());
            continue;
        }
        if (IsQuickfixFlagExsit(hasInstalledInfo)) {
            // If metadata name has quickfix flag, it should be uninstall and recover.
            InstallParam installParam;
            installParam.isUninstallAndRecover = true;
            installParam.noSkipsKill = false;
            installParam.needSendEvent = false;
            installer->UninstallAndRecover(bundleName, installParam, innerReceiverImpl);
        }
    }
    LOG_I(BMS_TAG_DEFAULT, "ProcessRebootQuickFixUnInstallAndRecover end");
}

void BMSEventHandler::InnerProcessRebootUninstallWrongBundle()
{
    InstallParam installParam;
    installParam.userId = Constants::DEFAULT_USERID;
    installParam.noSkipsKill = false;
    installParam.needSendEvent = false;
    std::vector<std::string> wrongBundleNameList;
    wrongBundleNameList.emplace_back(Constants::SCENE_BOARD_BUNDLE_NAME);

    for (const auto &bundle : wrongBundleNameList) {
        SystemBundleInstaller installer;
        if (!installer.UninstallSystemBundle(bundle, installParam)) {
            LOG_W(BMS_TAG_DEFAULT, "OTA uninstall bundle %{public}s userId %{public}d error", bundle.c_str(),
                installParam.userId);
        }
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
