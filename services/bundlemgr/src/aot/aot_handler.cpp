/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "aot/aot_handler.h"

#include <dlfcn.h>
#include <sys/stat.h>
#include <thread>
#include <vector>

#include "account_helper.h"
#ifdef CODE_SIGNATURE_ENABLE
#include "aot/aot_sign_data_cache_mgr.h"
#endif
#include "appexecfwk_errors.h"
#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_util.h"
#include "scope_guard.h"
#include "installd_client.h"
#include "parameter.h"
#include "parameters.h"
#include "string_ex.h"
#ifdef BUNDLE_FRAMEWORK_POWER_MGR_ENABLE
#include "display_power_mgr_client.h"
#endif

namespace OHOS {
namespace AppExecFwk {
namespace {
using UserStatusFunc = ErrCode (*)(int32_t, std::vector<std::string>&, std::vector<std::string>&);
// ark compile option parameter key
constexpr const char* INSTALL_COMPILE_MODE = "persist.bm.install.arkopt";
constexpr const char* IDLE_COMPILE_MODE = "persist.bm.idle.arkopt";
constexpr const char* OTA_COMPILE_MODE = "persist.bm.ota.arkopt";

constexpr const char* COMPILE_OPTCODE_RANGE_KEY = "ark.optcode.range";
const std::string DEBUG_APP_IDENTIFIER = "DEBUG_LIB_ID";

constexpr const char* UPDATE_TYPE = "persist.dupdate_engine.update_type";
const std::string UPDATE_TYPE_MANUAL = "manual";
const std::string UPDATE_TYPE_NIGHT = "night";

constexpr const char* OTA_COMPILE_SWITCH = "const.bms.optimizing_apps.switch";
constexpr const char* OTA_COMPILE_SWITCH_DEFAULT = "off";
const std::string OTA_COMPILE_SWITCH_ON = "on";

constexpr const char* OTA_COMPILE_TIME = "persist.bms.optimizing_apps.timing";
constexpr int32_t OTA_COMPILE_TIME_DEFAULT = 4 * 60; // 4min
constexpr int32_t GAP_SECONDS = 10;

constexpr const char* OTA_COMPILE_COUNT_MANUAL = "persist.bms.optimizing_apps.counts.manual";
constexpr int32_t OTA_COMPILE_COUNT_MANUAL_DEFAULT = 20;
constexpr const char* OTA_COMPILE_COUNT_NIGHT = "persist.bms.optimizing_apps.counts.night";
constexpr int32_t OTA_COMPILE_COUNT_NIGHT_DEFAULT = 30;

constexpr const char* OTA_COMPILE_STATUS = "bms.optimizing_apps.status";
constexpr const char* OTA_COMPILE_STATUS_BEGIN = "0";
constexpr const char* OTA_COMPILE_STATUS_END = "1";

const std::string QUEUE_NAME = "OTAQueue";
const std::string TASK_NAME = "OTACompileTimer";

constexpr uint32_t CONVERSION_FACTOR = 1000; // s to ms

const std::string FAILURE_REASON_TIME_OUT = "timeout";
const std::string FAILURE_REASON_BUNDLE_NOT_EXIST = "bundle not exist";
const std::string FAILURE_REASON_NOT_STAGE_MODEL = "not stage model";
const std::string FAILURE_REASON_COMPILE_FAILED = "compile failed";

constexpr const char* PGO_MERGED_AP_PREFIX = "merged_";
constexpr const char* PGO_RT_AP_PREFIX = "rt_";
constexpr const char* COPY_AP_DEST_PATH  = "/data/local/pgo/";
constexpr const char* COMPILE_NONE = "none";

constexpr const char* USER_STATUS_SO_NAME = "libuser_status_client.z.so";
constexpr const char* USER_STATUS_FUNC_NAME = "GetUserPreferenceApp";
}

AOTHandler::AOTHandler()
{
    serialQueue_ = std::make_shared<SerialQueue>(QUEUE_NAME);
}

AOTHandler& AOTHandler::GetInstance()
{
    static AOTHandler handler;
    return handler;
}

bool AOTHandler::IsSupportARM64() const
{
    std::string abis = GetAbiList();
    APP_LOGD("abi list : %{public}s", abis.c_str());
    std::vector<std::string> abiList;
    SplitStr(abis, ServiceConstants::ABI_SEPARATOR, abiList, false, false);
    if (abiList.empty()) {
        APP_LOGD("abiList empty");
        return false;
    }
    return std::find(abiList.begin(), abiList.end(), ServiceConstants::ARM64_V8A) != abiList.end();
}

std::string AOTHandler::GetArkProfilePath(const std::string &bundleName, const std::string &moduleName) const
{
    APP_LOGD("GetArkProfilePath begin");
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (!dataMgr) {
        APP_LOGE("dataMgr is null");
        return Constants::EMPTY_STRING;
    }
    int32_t userId = AccountHelper::GetCurrentActiveUserId();
    if (userId <= 0) {
        userId = Constants::START_USERID;
    }
    std::string path;
    path.append(ServiceConstants::ARK_PROFILE_PATH).append(std::to_string(userId))
        .append(ServiceConstants::PATH_SEPARATOR).append(bundleName)
        .append(ServiceConstants::PATH_SEPARATOR).append(moduleName).append(ServiceConstants::AP_SUFFIX);
    APP_LOGD("path : %{public}s", path.c_str());
    bool isExistFile = false;
    (void)InstalldClient::GetInstance()->IsExistApFile(path, isExistFile);
    if (isExistFile) {
        return path;
    }
    APP_LOGD("GetArkProfilePath failed");
    return Constants::EMPTY_STRING;
}

std::optional<AOTArgs> AOTHandler::BuildAOTArgs(const InnerBundleInfo &info, const std::string &moduleName,
    const std::string &compileMode, bool isEnanleBaselinePgo) const
{
    AOTArgs aotArgs;
    aotArgs.bundleName = info.GetBundleName();
    aotArgs.moduleName = moduleName;
    if (compileMode == ServiceConstants::COMPILE_PARTIAL) {
        aotArgs.arkProfilePath = GetArkProfilePath(aotArgs.bundleName, aotArgs.moduleName);
        if (aotArgs.arkProfilePath.empty()) {
            APP_LOGD("compile mode is partial, but ap not exist, no need to AOT");
            return std::nullopt;
        }
    }
    aotArgs.compileMode = compileMode;
    aotArgs.hapPath = info.GetModuleHapPath(aotArgs.moduleName);
    aotArgs.coreLibPath = Constants::EMPTY_STRING;
    aotArgs.outputPath = ServiceConstants::ARK_CACHE_PATH + aotArgs.bundleName + ServiceConstants::PATH_SEPARATOR
        + ServiceConstants::ARM64;
    // handle internal hsp
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (!dataMgr) {
        APP_LOGE("dataMgr is null");
        return std::nullopt;
    }
    InnerBundleInfo installedInfo;
    if (!dataMgr->QueryInnerBundleInfo(info.GetBundleName(), installedInfo)) {
        APP_LOGE("QueryInnerBundleInfo failed");
        return std::nullopt;
    }
    installedInfo.GetInternalDependentHspInfo(moduleName, aotArgs.hspVector);

    InnerBundleUserInfo newInnerBundleUserInfo;
    int32_t curActiveUserId = AccountHelper::GetCurrentActiveUserId();
    int32_t activeUserId = curActiveUserId <= 0 ? Constants::START_USERID : curActiveUserId;
    if (!installedInfo.GetInnerBundleUserInfo(activeUserId, newInnerBundleUserInfo)) {
        APP_LOGE("bundle(%{public}s) get user (%{public}d) failed",
            installedInfo.GetBundleName().c_str(), activeUserId);
        return std::nullopt;
    }
    aotArgs.bundleUid = newInnerBundleUserInfo.uid;
    aotArgs.bundleGid = installedInfo.GetGid(activeUserId);
    aotArgs.isEncryptedBundle = installedInfo.IsEncryptedMoudle(moduleName) ? 1 : 0;
    aotArgs.appIdentifier = (info.GetAppProvisionType() == Constants::APP_PROVISION_TYPE_DEBUG) ?
        DEBUG_APP_IDENTIFIER : info.GetAppIdentifier();
    aotArgs.anFileName = aotArgs.outputPath + ServiceConstants::PATH_SEPARATOR + aotArgs.moduleName
        + ServiceConstants::AN_SUFFIX;

    std::string optBCRange = system::GetParameter(COMPILE_OPTCODE_RANGE_KEY, "");
    aotArgs.optBCRangeList = optBCRange;

    bool deviceIsScreenOff = CheckDeviceState();
    aotArgs.isScreenOff = static_cast<uint32_t>(deviceIsScreenOff);

    aotArgs.isEnanleBaselinePgo = static_cast<uint32_t>(isEnanleBaselinePgo);
    APP_LOGD("args : %{public}s", aotArgs.ToString().c_str());
    return aotArgs;
}

ErrCode AOTHandler::AOTInternal(const std::optional<AOTArgs> &aotArgs, uint32_t versionCode) const
{
    if (!aotArgs) {
        APP_LOGD("aotArgs empty");
        return ERR_APPEXECFWK_AOT_ARGS_EMPTY;
    }
    ErrCode ret = ERR_OK;
    std::vector<uint8_t> pendSignData;
    {
        std::lock_guard<std::mutex> lock(executeMutex_);
        ret = InstalldClient::GetInstance()->ExecuteAOT(*aotArgs, pendSignData);
    }
    APP_LOGI("ExecuteAOT ret : %{public}d", ret);
#ifdef CODE_SIGNATURE_ENABLE
    AOTSignDataCacheMgr::GetInstance().AddPendSignData(*aotArgs, versionCode, pendSignData, ret);
#endif
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (!dataMgr) {
        APP_LOGE("dataMgr is null");
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    AOTCompileStatus status = ret == ERR_OK ? AOTCompileStatus::COMPILE_SUCCESS : AOTCompileStatus::COMPILE_FAILED;
    dataMgr->SetAOTCompileStatus(aotArgs->bundleName, aotArgs->moduleName, status, versionCode);
    return ret;
}

void AOTHandler::HandleInstallWithSingleHap(const InnerBundleInfo &info, const std::string &compileMode) const
{
    std::optional<AOTArgs> aotArgs = BuildAOTArgs(info, info.GetCurrentModulePackage(), compileMode, true);
    (void)AOTInternal(aotArgs, info.GetVersionCode());
}

void AOTHandler::HandleInstall(const std::unordered_map<std::string, InnerBundleInfo> &infos) const
{
    auto task = [this, infos]() {
        APP_LOGD("HandleInstall begin");
        if (infos.empty() || !(infos.cbegin()->second.GetIsNewVersion())) {
            APP_LOGD("not stage model, no need to AOT");
            return;
        }
        if (!IsSupportARM64()) {
            APP_LOGD("current device doesn't support arm64, no need to AOT");
            return;
        }
        std::string compileMode = system::GetParameter(INSTALL_COMPILE_MODE, COMPILE_NONE);
        APP_LOGD("%{public}s = %{public}s", INSTALL_COMPILE_MODE, compileMode.c_str());
        if (compileMode == COMPILE_NONE) {
            APP_LOGD("%{public}s = none, no need to AOT", INSTALL_COMPILE_MODE);
            return;
        }
        std::for_each(infos.cbegin(), infos.cend(), [this, compileMode](const auto &item) {
            HandleInstallWithSingleHap(item.second, compileMode);
        });
        APP_LOGD("HandleInstall end");
    };
    std::thread t(task);
    t.detach();
}

void AOTHandler::ClearArkCacheDir() const
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (!dataMgr) {
        APP_LOGE("dataMgr is null");
        return;
    }
    std::vector<std::string> bundleNames = dataMgr->GetAllBundleName();
    std::for_each(bundleNames.cbegin(), bundleNames.cend(), [dataMgr](const auto &bundleName) {
        std::string removeDir = ServiceConstants::ARK_CACHE_PATH + bundleName;
        ErrCode ret = InstalldClient::GetInstance()->RemoveDir(removeDir);
        APP_LOGD("removeDir %{public}s, ret : %{public}d", removeDir.c_str(), ret);
    });
}

void AOTHandler::HandleResetAOT(const std::string &bundleName, bool isAllBundle) const
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (!dataMgr) {
        APP_LOGE("dataMgr is null");
        return;
    }
    std::vector<std::string> bundleNames;
    if (isAllBundle) {
        bundleNames = dataMgr->GetAllBundleName();
    } else {
        bundleNames = {bundleName};
    }
    std::for_each(bundleNames.cbegin(), bundleNames.cend(), [dataMgr](const auto &bundleToReset) {
        std::string removeDir = ServiceConstants::ARK_CACHE_PATH + bundleToReset;
        ErrCode ret = InstalldClient::GetInstance()->RemoveDir(removeDir);
        APP_LOGD("removeDir %{public}s, ret : %{public}d", removeDir.c_str(), ret);
        dataMgr->ResetAOTFlagsCommand(bundleToReset);
    });
}

ErrCode AOTHandler::MkApDestDirIfNotExist() const
{
    ErrCode errCode;
    bool isDirExist = false;
    errCode = InstalldClient::GetInstance()->IsExistDir(COPY_AP_DEST_PATH, isDirExist);
    if (errCode != ERR_OK) {
        APP_LOGE("check if dir exist failed, err %{public}d", errCode);
    }
    if (isDirExist) {
        APP_LOGI("Copy ap path is exist");
        return ERR_OK;
    }
    mode_t mode = S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP;
    errCode = InstalldClient::GetInstance()->Mkdir(
        COPY_AP_DEST_PATH, mode, Constants::FOUNDATION_UID, ServiceConstants::SHELL_UID);
    if (errCode != ERR_OK) {
        APP_LOGE("fail create dir err %{public}d", errCode);
        return errCode;
    }
    APP_LOGI("MkApDestDir path success");
    return ERR_OK;
}

ErrCode AOTHandler::HandleCopyAp(const std::string &bundleName, bool isAllBundle,
    std::vector<std::string> &results) const
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (!dataMgr) {
        APP_LOGE("dataMgr is null");
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    std::vector<std::string> bundleNames;
    if (isAllBundle) {
        bundleNames = dataMgr->GetAllBundleName();
    } else {
        bundleNames = {bundleName};
    }
    ErrCode errCode = MkApDestDirIfNotExist();
    if (errCode != ERR_OK) {
        return errCode;
    }
    int32_t userId = AccountHelper::GetCurrentActiveUserId();
    if (userId <= 0) {
        userId = Constants::START_USERID;
    }
    for (const auto &bundleName : bundleNames) {
        BundleInfo bundleInfo;
        if (!dataMgr->GetBundleInfo(bundleName, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo, userId)) {
            std::string errInfo = bundleName + " GetBundleInfo failed";
            APP_LOGW("%{public}s", errInfo.c_str());
            results.emplace_back(errInfo);
            continue;
        }
        CopyApWithBundle(bundleName, bundleInfo, userId, results);
    };
    return ERR_OK;
}

std::string AOTHandler::GetSouceAp(const std::string &mergedAp, const std::string &rtAp) const
{
    ErrCode errCode;
    bool isMergedApExist = false;
    bool isRtApExist = false;
    errCode = InstalldClient::GetInstance()->IsExistFile(mergedAp, isMergedApExist);
    if (errCode != ERR_OK) {
        APP_LOGE("CopyAp mergedAp %{public}s failed due to call IsExistFile failed %{public}d",
            mergedAp.c_str(), errCode);
        return Constants::EMPTY_STRING;
    }
    if (isMergedApExist) {
        return mergedAp;
    }
    errCode = InstalldClient::GetInstance()->IsExistFile(rtAp, isRtApExist);
    if (errCode != ERR_OK) {
        APP_LOGE("CopyAp rtAp %{public}s failed due to call IsExistFile failed %{public}d",
            rtAp.c_str(), errCode);
        return Constants::EMPTY_STRING;
    }
    if (isRtApExist) {
        return rtAp;
    }
    APP_LOGE("Source ap is not exist");
    return Constants::EMPTY_STRING;
}

void AOTHandler::CopyApWithBundle(const std::string &bundleName, const BundleInfo &bundleInfo,
    const int32_t userId, std::vector<std::string> &results) const
{
    std::string arkProfilePath;
    arkProfilePath.append(ServiceConstants::ARK_PROFILE_PATH).append(std::to_string(userId))
        .append(ServiceConstants::PATH_SEPARATOR).append(bundleName).append(ServiceConstants::PATH_SEPARATOR);
    ErrCode errCode;
    for (const auto &moduleName : bundleInfo.moduleNames) {
        std::string mergedAp = arkProfilePath + PGO_MERGED_AP_PREFIX + moduleName + ServiceConstants::AP_SUFFIX;
        std::string rtAp = arkProfilePath + PGO_RT_AP_PREFIX + moduleName + ServiceConstants::AP_SUFFIX;
        std::string sourceAp = GetSouceAp(mergedAp, rtAp);
        std::string result;
        if (sourceAp.empty()) {
            result.append(bundleName).append(" ").append(moduleName).append(" get source ap failed!");
            results.emplace_back(result);
            continue;
        }
        if (sourceAp.find(ServiceConstants::RELATIVE_PATH) != std::string::npos) {
            return;
        }
        std::string destAp = COPY_AP_DEST_PATH  + bundleName + "_" + moduleName + ServiceConstants::AP_SUFFIX;
        if (sourceAp.find(destAp) == std::string::npos) {
            return;
        }
        result.append(sourceAp);
        errCode = InstalldClient::GetInstance()->CopyFile(sourceAp, destAp);
        if (errCode != ERR_OK) {
            APP_LOGE("Copy ap dir %{public}s failed err %{public}d", sourceAp.c_str(), errCode);
            result.append(" copy ap failed!");
            continue;
        }
        result.append(" copy ap success!");
        results.emplace_back(result);
    }
}

void AOTHandler::ResetAOTFlags() const
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (!dataMgr) {
        APP_LOGE("dataMgr is null");
        return;
    }
    dataMgr->ResetAOTFlags();
}

void AOTHandler::HandleOTA()
{
    APP_LOGI("HandleOTA begin");
    ClearArkCacheDir();
    ResetAOTFlags();
    HandleOTACompile();
}

void AOTHandler::HandleOTACompile()
{
    if (!IsOTACompileSwitchOn()) {
        APP_LOGI("OTACompileSwitch off, no need to compile");
        return;
    }
    BeforeOTACompile();
    OTACompile();
}

bool AOTHandler::IsOTACompileSwitchOn() const
{
    std::string OTACompileSwitch = system::GetParameter(OTA_COMPILE_SWITCH, OTA_COMPILE_SWITCH_DEFAULT);
    APP_LOGI("OTACompileSwitch %{public}s", OTACompileSwitch.c_str());
    return OTACompileSwitch == OTA_COMPILE_SWITCH_ON;
}

void AOTHandler::BeforeOTACompile()
{
    OTACompileDeadline_ = false;
    int32_t limitSeconds = system::GetIntParameter<int32_t>(OTA_COMPILE_TIME, OTA_COMPILE_TIME_DEFAULT);
    APP_LOGI("OTA compile time limit seconds %{public}d", limitSeconds);
    auto task = [this]() {
        APP_LOGI("compile timer end");
        OTACompileDeadline_ = true;
        ErrCode ret = InstalldClient::GetInstance()->StopAOT();
        APP_LOGI("StopAOT ret %{public}d", ret);
    };
    int32_t delayTimeSeconds = limitSeconds - GAP_SECONDS;
    if (delayTimeSeconds < 0) {
        delayTimeSeconds = 0;
    }
    serialQueue_->ScheduleDelayTask(TASK_NAME, delayTimeSeconds * CONVERSION_FACTOR, task);
}

void AOTHandler::OTACompile() const
{
    auto OTACompileTask = [this]() {
        OTACompileInternal();
    };
    std::thread(OTACompileTask).detach();
}

void AOTHandler::OTACompileInternal() const
{
    APP_LOGI("OTACompileInternal begin");
    system::SetParameter(OTA_COMPILE_STATUS, OTA_COMPILE_STATUS_BEGIN);
    ScopeGuard guard([this] {
        APP_LOGI("set OTA compile status to end");
        system::SetParameter(OTA_COMPILE_STATUS, OTA_COMPILE_STATUS_END);
        serialQueue_->CancelDelayTask(TASK_NAME);
    });

    if (!IsSupportARM64()) {
        APP_LOGI("current device doesn't support arm64, no need to AOT");
        return;
    }

    std::string compileMode = system::GetParameter(OTA_COMPILE_MODE, COMPILE_NONE);
    APP_LOGI("%{public}s = %{public}s", OTA_COMPILE_MODE, compileMode.c_str());
    if (compileMode == COMPILE_NONE) {
        APP_LOGI("%{public}s none, no need to AOT", OTA_COMPILE_MODE);
        return;
    }

    std::vector<std::string> bundleNames;
    if (!GetOTACompileList(bundleNames)) {
        APP_LOGE("get OTA compile list failed");
        return;
    }

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (!dataMgr) {
        APP_LOGE("dataMgr is null");
        return;
    }

    std::map<std::string, EventInfo> sysEventMap;
    for (const std::string &bundleName : bundleNames) {
        EventInfo eventInfo = HandleCompileWithBundle(bundleName, compileMode, dataMgr);
        sysEventMap.emplace(bundleName, eventInfo);
    }
    ReportSysEvent(sysEventMap);
    APP_LOGI("OTACompileInternal end");
}

bool AOTHandler::GetOTACompileList(std::vector<std::string> &bundleNames) const
{
    std::string updateType = system::GetParameter(UPDATE_TYPE, "");
    APP_LOGI("updateType %{public}s", updateType.c_str());
    int32_t size = 0;
    if (updateType == UPDATE_TYPE_MANUAL) {
        size = system::GetIntParameter<int32_t>(OTA_COMPILE_COUNT_MANUAL, OTA_COMPILE_COUNT_MANUAL_DEFAULT);
    } else if (updateType == UPDATE_TYPE_NIGHT) {
        size = system::GetIntParameter<int32_t>(OTA_COMPILE_COUNT_NIGHT, OTA_COMPILE_COUNT_NIGHT_DEFAULT);
    } else {
        APP_LOGE("invalid updateType");
        return false;
    }
    return GetUserBehaviourAppList(bundleNames, size);
}

bool AOTHandler::GetUserBehaviourAppList(std::vector<std::string> &bundleNames, int32_t size) const
{
    APP_LOGI("GetUserBehaviourAppList begin, size %{public}d", size);
    void* handle = dlopen(USER_STATUS_SO_NAME, RTLD_NOW);
    if (handle == nullptr) {
        APP_LOGE("user status dlopen failed : %{public}s", dlerror());
        return false;
    }
    UserStatusFunc userStatusFunc = reinterpret_cast<UserStatusFunc>(dlsym(handle, USER_STATUS_FUNC_NAME));
    if (userStatusFunc == nullptr) {
        APP_LOGE("user status dlsym failed : %{public}s", dlerror());
        dlclose(handle);
        return false;
    }
    std::vector<std::string> interestedApps;
    ErrCode ret = userStatusFunc(size, interestedApps, bundleNames);
    APP_LOGI("GetUserPreferenceApp ret : %{public}d, bundleNames size : %{public}zu", ret, bundleNames.size());
    dlclose(handle);
    return ret == ERR_OK;
}

EventInfo AOTHandler::HandleCompileWithBundle(const std::string &bundleName, const std::string &compileMode,
    std::shared_ptr<BundleDataMgr> dataMgr) const
{
    APP_LOGI("handle compile bundle %{public}s", bundleName.c_str());
    EventInfo eventInfo;
    eventInfo.timeStamp = BundleUtil::GetCurrentTime();
    eventInfo.bundleName = bundleName;
    eventInfo.compileMode = compileMode;
    eventInfo.compileResult = false;

    if (OTACompileDeadline_) {
        APP_LOGI("reach OTA deadline, stop compile bundle");
        eventInfo.failureReason = FAILURE_REASON_TIME_OUT;
        return eventInfo;
    }

    InnerBundleInfo info;
    if (!dataMgr->QueryInnerBundleInfo(bundleName, info)) {
        APP_LOGE("QueryInnerBundleInfo failed");
        eventInfo.failureReason = FAILURE_REASON_BUNDLE_NOT_EXIST;
        return eventInfo;
    }
    if (!info.GetIsNewVersion()) {
        APP_LOGI("not stage model, no need to AOT");
        eventInfo.failureReason = FAILURE_REASON_NOT_STAGE_MODEL;
        return eventInfo;
    }

    int64_t beginTimeSeconds = BundleUtil::GetCurrentTime();
    bool compileRet = true;

    std::vector<std::string> moduleNames;
    info.GetModuleNames(moduleNames);
    for (const std::string &moduleName : moduleNames) {
        if (OTACompileDeadline_) {
            APP_LOGI("reach OTA deadline, stop compile module");
            eventInfo.failureReason = FAILURE_REASON_TIME_OUT;
            eventInfo.costTimeSeconds = BundleUtil::GetCurrentTime() - beginTimeSeconds;
            return eventInfo;
        }
        ErrCode ret = HandleCompileWithSingleHap(info, moduleName, compileMode, true);
        APP_LOGI("moduleName : %{public}s, ret : %{public}d", moduleName.c_str(), ret);
        if (ret != ERR_OK) {
            compileRet = false;
        }
    }

    if (compileRet) {
        eventInfo.compileResult = true;
        eventInfo.failureReason.clear();
    } else {
        eventInfo.compileResult = false;
        eventInfo.failureReason = FAILURE_REASON_COMPILE_FAILED;
    }
    eventInfo.costTimeSeconds = BundleUtil::GetCurrentTime() - beginTimeSeconds;
    return eventInfo;
}

void AOTHandler::ReportSysEvent(const std::map<std::string, EventInfo> &sysEventMap) const
{
    auto task = [sysEventMap]() {
        APP_LOGI("begin to report AOT sysEvent");
        EventInfo summaryInfo;
        summaryInfo.timeStamp = BundleUtil::GetCurrentTime();
        for (const auto &item : sysEventMap) {
            summaryInfo.totalBundleNames.emplace_back(item.first);
            if (item.second.compileResult) {
                summaryInfo.successCnt++;
            }
            summaryInfo.costTimeSeconds += item.second.costTimeSeconds;
            EventReport::SendSystemEvent(BMSEventType::AOT_COMPILE_RECORD, item.second);
        }
        EventReport::SendSystemEvent(BMSEventType::AOT_COMPILE_SUMMARY, summaryInfo);
        APP_LOGI("report AOT sysEvent done");
    };
    std::thread(task).detach();
}

void AOTHandler::HandleIdleWithSingleHap(
    const InnerBundleInfo &info, const std::string &moduleName, const std::string &compileMode) const
{
    APP_LOGD("HandleIdleWithSingleHap, moduleName : %{public}s", moduleName.c_str());
    if (info.GetAOTCompileStatus(moduleName) == AOTCompileStatus::COMPILE_SUCCESS) {
        APP_LOGD("AOT history success, no need to AOT");
        return;
    }
    std::optional<AOTArgs> aotArgs = BuildAOTArgs(info, moduleName, compileMode);
    (void)AOTInternal(aotArgs, info.GetVersionCode());
}

ErrCode AOTHandler::HandleCompileWithSingleHap(const InnerBundleInfo &info, const std::string &moduleName,
    const std::string &compileMode, bool isEnanleBaselinePgo) const
{
    APP_LOGI("HandleCompileWithSingleHap, moduleName : %{public}s", moduleName.c_str());
    std::optional<AOTArgs> aotArgs = BuildAOTArgs(info, moduleName, compileMode, isEnanleBaselinePgo);
    return AOTInternal(aotArgs, info.GetVersionCode());
}

bool AOTHandler::CheckDeviceState() const
{
#ifdef BUNDLE_FRAMEWORK_POWER_MGR_ENABLE
    DisplayPowerMgr::DisplayState displayState =
        DisplayPowerMgr::DisplayPowerMgrClient::GetInstance().GetDisplayState();
    if (displayState != DisplayPowerMgr::DisplayState::DISPLAY_OFF) {
        APP_LOGI("displayState is not DISPLAY_OFF");
        return false;
    }
    return true;
#else
    APP_LOGI("device not support power system");
    return false;
#endif
}

void AOTHandler::HandleIdle() const
{
    APP_LOGI("HandleIdle begin");
    std::unique_lock<std::mutex> lock(idleMutex_, std::defer_lock);
    if (!lock.try_lock()) {
        APP_LOGI("idle task is running, skip");
        return;
    }
    if (!IsSupportARM64()) {
        APP_LOGI("current device doesn't support arm64, no need to AOT");
        return;
    }
    std::string compileMode = system::GetParameter(IDLE_COMPILE_MODE, ServiceConstants::COMPILE_PARTIAL);
    APP_LOGI("%{public}s = %{public}s", IDLE_COMPILE_MODE, compileMode.c_str());
    if (compileMode == COMPILE_NONE) {
        APP_LOGI("%{public}s none, no need to AOT", IDLE_COMPILE_MODE);
        return;
    }
    if (!CheckDeviceState()) {
        APP_LOGI("device state is not suitable");
        return;
    }
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (!dataMgr) {
        APP_LOGE("dataMgr is null");
        return;
    }
    std::vector<std::string> bundleNames = dataMgr->GetAllBundleName();
    std::for_each(bundleNames.cbegin(), bundleNames.cend(), [this, dataMgr, &compileMode](const auto &bundleName) {
        APP_LOGD("HandleIdle bundleName : %{public}s", bundleName.c_str());
        InnerBundleInfo info;
        if (!dataMgr->QueryInnerBundleInfo(bundleName, info)) {
            APP_LOGE("QueryInnerBundleInfo failed");
            return;
        }
        if (!info.GetIsNewVersion()) {
            APP_LOGD("not stage model, no need to AOT");
            return;
        }
        std::vector<std::string> moduleNames;
        info.GetModuleNames(moduleNames);
        std::for_each(moduleNames.cbegin(), moduleNames.cend(), [this, &info, &compileMode](const auto &moduleName) {
            HandleIdleWithSingleHap(info, moduleName, compileMode);
        });
    });
    APP_LOGI("HandleIdle end");
}

ErrCode AOTHandler::HandleCompile(const std::string &bundleName, const std::string &compileMode, bool isAllBundle,
    std::vector<std::string> &compileResults) const
{
    APP_LOGI("HandleCompile begin");
    std::unique_lock<std::mutex> lock(compileMutex_, std::defer_lock);
    if (!lock.try_lock()) {
        APP_LOGI("compile task running, skip %{public}s", bundleName.c_str());
        std::string compileResult = "info: compile task is running, skip.";
        compileResults.emplace_back(compileResult);
        return ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED;
    }
    if (!IsSupportARM64()) {
        APP_LOGI("current device doesn't support arm64, no need to AOT");
        std::string compileResult = "info: current device doesn't support arm64, no need to AOT.";
        compileResults.emplace_back(compileResult);
        return ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED;
    }
    if (compileMode == COMPILE_NONE) {
        APP_LOGI("%{public}s none, no need to AOT", IDLE_COMPILE_MODE);
        std::string compileResult = "info: persist.bm.idle.arkopt = none, no need to AOT.";
        compileResults.emplace_back(compileResult);
        return ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED;
    }
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (!dataMgr) {
        APP_LOGE("dataMgr is null");
        std::string compileResult = "error: dataMgr is null, compile fail.";
        compileResults.emplace_back(compileResult);
        return ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED;
    }
    std::vector<std::string> bundleNames;
    if (isAllBundle) {
        bundleNames = dataMgr->GetAllBundleName();
    } else {
        bundleNames = {bundleName};
    }
    ErrCode ret = HandleCompileBundles(bundleNames, compileMode, dataMgr, compileResults);
    if (ret == ERR_OK) {
        compileResults.clear();
    }
    APP_LOGI("HandleCompile end");
    return ret;
}

ErrCode AOTHandler::HandleCompileBundles(const std::vector<std::string> &bundleNames, const std::string &compileMode,
    std::shared_ptr<BundleDataMgr> &dataMgr, std::vector<std::string> &compileResults) const
{
    ErrCode ret = ERR_OK;
    std::for_each(bundleNames.cbegin(), bundleNames.cend(),
        [this, dataMgr, &compileMode, &ret, &compileResults](const auto &bundleToCompile) {
        APP_LOGD("HandleCompile bundleToCompile : %{public}s", bundleToCompile.c_str());
        InnerBundleInfo info;
        if (!dataMgr->QueryInnerBundleInfo(bundleToCompile, info)) {
            APP_LOGE("QueryInnerBundleInfo failed. bundleToCompile %{public}s", bundleToCompile.c_str());
            std::string compileResult = bundleToCompile + ": QueryInnerBundleInfo failed.";
            compileResults.emplace_back(compileResult);
            ret = ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED;
            return;
        }
        if (!info.GetIsNewVersion()) {
            APP_LOGD("not stage model, no need to AOT");
            std::string compileResult = bundleToCompile + ": not stage model, no need to AOT.";
            compileResults.emplace_back(compileResult);
            ret = ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED;
            return;
        }
        std::vector<std::string> moduleNames;
        info.GetModuleNames(moduleNames);
        std::string compileResult = "";
        if (HandleCompileModules(moduleNames, compileMode, info, compileResult) == ERR_OK) {
            compileResult = bundleToCompile + ": compile success.";
        } else {
            compileResult = bundleToCompile + ":" + compileResult;
            ret = ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED;
        }
        compileResults.emplace_back(compileResult);
    });
    return ret;
}

ErrCode AOTHandler::HandleCompileModules(const std::vector<std::string> &moduleNames, const std::string &compileMode,
    InnerBundleInfo &info, std::string &compileResult) const
{
    ErrCode ret = ERR_OK;
    std::for_each(moduleNames.cbegin(), moduleNames.cend(),
        [this, &info, &compileMode, &ret, &compileResult](const auto &moduleName) {
        ErrCode errCode = HandleCompileWithSingleHap(info, moduleName, compileMode);
        switch (errCode) {
            case ERR_OK:
                break;
            case ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED:
                compileResult += "  " + moduleName + ":compile-fail";
                break;
            case ERR_APPEXECFWK_INSTALLD_SIGN_AOT_FAILED:
                compileResult += "  " + moduleName + ":signature-fail";
                break;
            case ERR_APPEXECFWK_INSTALLD_SIGN_AOT_DISABLE:
                compileResult += "  " + moduleName + ":signature-disable";
                break;
            case ERR_APPEXECFWK_AOT_ARGS_EMPTY:
                compileResult += "  " + moduleName + ":args-empty";
                break;
            default:
                compileResult += "  " + moduleName + ":other-fail";
                break;
        }
        if (errCode != ERR_OK) {
            ret = ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED;
        }
    });
    return ret;
}
}  // namespace AppExecFwk
}  // namespace OHOS
