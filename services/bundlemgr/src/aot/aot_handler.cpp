/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <thread>
#include <vector>

#include "appexecfwk_errors.h"
#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_mgr_service.h"
#include "bundle_util.h"
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
// ark compile option parameter key
constexpr const char* COMPILE_INSTALL_PARAM_KEY = "persist.bm.install.arkopt";
constexpr const char* COMPILE_IDLE_PARA_KEY = "persist.bm.idle.arkopt";
constexpr const char* COMPILE_OPTCODE_RANGE_KEY = "ark.optcode.range";
const std::string DEBUG_APP_IDENTIFIER = "DEBUG_LIB_ID";
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
    SplitStr(abis, Constants::ABI_SEPARATOR, abiList, false, false);
    if (abiList.empty()) {
        APP_LOGD("abiList empty");
        return false;
    }
    return std::find(abiList.begin(), abiList.end(), Constants::ARM64_V8A) != abiList.end();
}

std::string AOTHandler::GetArkProfilePath(const std::string &bundleName, const std::string &moduleName) const
{
    APP_LOGD("GetArkProfilePath begin");
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (!dataMgr) {
        APP_LOGE("dataMgr is null");
        return Constants::EMPTY_STRING;
    }
    std::vector<int32_t> userIds = dataMgr->GetUserIds(bundleName);
    for (int32_t userId : userIds) {
        std::string path;
        path.append(Constants::ARK_PROFILE_PATH).append(std::to_string(userId))
            .append(Constants::PATH_SEPARATOR).append(bundleName)
            .append(Constants::PATH_SEPARATOR).append(moduleName).append(Constants::AP_SUFFIX);
        APP_LOGD("path : %{public}s", path.c_str());
        bool isExistFile = false;
        (void)InstalldClient::GetInstance()->IsExistApFile(path, isExistFile);
        if (isExistFile) {
            return path;
        }
    }
    APP_LOGD("GetArkProfilePath failed");
    return Constants::EMPTY_STRING;
}

std::optional<AOTArgs> AOTHandler::BuildAOTArgs(
    const InnerBundleInfo &info, const std::string &moduleName, const std::string &compileMode) const
{
    AOTArgs aotArgs;
    aotArgs.bundleName = info.GetBundleName();
    aotArgs.moduleName = moduleName;
    if (compileMode == Constants::COMPILE_PARTIAL) {
        aotArgs.arkProfilePath = GetArkProfilePath(aotArgs.bundleName, aotArgs.moduleName);
        if (aotArgs.arkProfilePath.empty()) {
            APP_LOGI("compile mode is partial, but ap not exist, no need to AOT");
            return std::nullopt;
        }
    }
    aotArgs.compileMode = compileMode;
    aotArgs.hapPath = info.GetModuleHapPath(aotArgs.moduleName);
    aotArgs.coreLibPath = Constants::EMPTY_STRING;
    aotArgs.outputPath = Constants::ARK_CACHE_PATH + aotArgs.bundleName + Constants::PATH_SEPARATOR + Constants::ARM64;
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
    if (!installedInfo.GetInnerBundleUserInfo(Constants::ALL_USERID, newInnerBundleUserInfo)) {
        APP_LOGE("bundle(%{public}s) get user (%{public}d) failed.",
            installedInfo.GetBundleName().c_str(), Constants::ALL_USERID);
        return std::nullopt;
    }
    aotArgs.bundleUid = static_cast<uint32_t>(newInnerBundleUserInfo.uid);
    aotArgs.isEncryptedBundle = installedInfo.IsEncryptedMoudle(moduleName) ? 1 : 0;
    aotArgs.appIdentifier = (info.GetAppProvisionType() == Constants::APP_PROVISION_TYPE_DEBUG) ?
        DEBUG_APP_IDENTIFIER : info.GetAppIdentifier();

    // key rule is start:end,start:end......
    std::string optBCRange = system::GetParameter(COMPILE_OPTCODE_RANGE_KEY, "");
    aotArgs.optBCRangeList = optBCRange;

    bool deviceIsScreenOff = CheckDeviceState();
    aotArgs.isScreenOff = static_cast<uint32_t>(deviceIsScreenOff);

    APP_LOGD("args : %{public}s", aotArgs.ToString().c_str());
    return aotArgs;
}

void AOTHandler::AOTInternal(std::optional<AOTArgs> aotArgs, uint32_t versionCode) const
{
    if (!aotArgs) {
        APP_LOGI("aotArgs empty");
        return;
    }
    ErrCode ret = ERR_OK;
    {
        std::lock_guard<std::mutex> lock(executeMutex_);
        ret = InstalldClient::GetInstance()->ExecuteAOT(*aotArgs);
    }
    APP_LOGI("ExecuteAOT ret : %{public}d", ret);

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (!dataMgr) {
        APP_LOGE("dataMgr is null");
        return;
    }
    AOTCompileStatus status = ret == ERR_OK ? AOTCompileStatus::COMPILE_SUCCESS : AOTCompileStatus::COMPILE_FAILED;
    dataMgr->SetAOTCompileStatus(aotArgs->bundleName, aotArgs->moduleName, status, versionCode);
}

void AOTHandler::HandleInstallWithSingleHap(const InnerBundleInfo &info, const std::string &compileMode) const
{
    std::optional<AOTArgs> aotArgs = BuildAOTArgs(info, info.GetCurrentModulePackage(), compileMode);
    AOTInternal(aotArgs, info.GetVersionCode());
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
        std::string compileMode = system::GetParameter(COMPILE_INSTALL_PARAM_KEY, Constants::COMPILE_NONE);
        APP_LOGD("%{public}s = %{public}s", COMPILE_INSTALL_PARAM_KEY, compileMode.c_str());
        if (compileMode == Constants::COMPILE_NONE) {
            APP_LOGD("%{public}s = none, no need to AOT", COMPILE_INSTALL_PARAM_KEY);
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
        std::string removeDir = Constants::ARK_CACHE_PATH + bundleName;
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
        std::string removeDir = Constants::ARK_CACHE_PATH + bundleToReset;
        ErrCode ret = InstalldClient::GetInstance()->RemoveDir(removeDir);
        APP_LOGD("removeDir %{public}s, ret : %{public}d", removeDir.c_str(), ret);
        dataMgr->ResetAOTFlagsCommand(bundleToReset);
    });
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

void AOTHandler::HandleOTA() const
{
    APP_LOGI("HandleOTA begin");
    ClearArkCacheDir();
    ResetAOTFlags();
    APP_LOGI("HandleOTA end");
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
    AOTInternal(aotArgs, info.GetVersionCode());
}

void AOTHandler::HandleCompileWithSingleHap(
    const InnerBundleInfo &info, const std::string &moduleName, const std::string &compileMode) const
{
    APP_LOGD("HandleCompileWithSingleHap, moduleName : %{public}s", moduleName.c_str());
    std::optional<AOTArgs> aotArgs = BuildAOTArgs(info, moduleName, compileMode);
    AOTInternal(aotArgs, info.GetVersionCode());
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
    std::string compileMode = system::GetParameter(COMPILE_IDLE_PARA_KEY, Constants::COMPILE_PARTIAL);
    APP_LOGI("%{public}s = %{public}s", COMPILE_IDLE_PARA_KEY, compileMode.c_str());
    if (compileMode == Constants::COMPILE_NONE) {
        APP_LOGI("%{public}s = none, no need to AOT", COMPILE_IDLE_PARA_KEY);
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

void AOTHandler::HandleCompile(const std::string &bundleName, const std::string &compileMode, bool isAllBundle) const
{
    APP_LOGI("HandleCompile begin");
    std::unique_lock<std::mutex> lock(compileMutex_, std::defer_lock);
    if (!lock.try_lock()) {
        APP_LOGI("compile task is running, skip %{public}s", bundleName.c_str());
        return;
    }
    if (!IsSupportARM64()) {
        APP_LOGI("current device doesn't support arm64, no need to AOT");
        return;
    }
    if (compileMode == Constants::COMPILE_NONE) {
        APP_LOGI("%{public}s = none, no need to AOT", COMPILE_IDLE_PARA_KEY);
        return;
    }
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
    std::for_each(bundleNames.cbegin(), bundleNames.cend(), [this, dataMgr, &compileMode](const auto &bundleToCompile) {
        APP_LOGD("HandleCompile bundleToCompile : %{public}s", bundleToCompile.c_str());
        InnerBundleInfo info;
        if (!dataMgr->QueryInnerBundleInfo(bundleToCompile, info)) {
            APP_LOGE("QueryInnerBundleInfo failed. bundleToCompile: %{public}s", bundleToCompile.c_str());
            return;
        }
        if (!info.GetIsNewVersion()) {
            APP_LOGD("not stage model, no need to AOT");
            return;
        }
        std::vector<std::string> moduleNames;
        info.GetModuleNames(moduleNames);
        std::for_each(moduleNames.cbegin(), moduleNames.cend(),
            [this, &info, &compileMode](const auto &moduleName) {
            HandleCompileWithSingleHap(info, moduleName, compileMode);
        });
    });
    APP_LOGI("HandleCompile end");
}
}  // namespace AppExecFwk
}  // namespace OHOS
