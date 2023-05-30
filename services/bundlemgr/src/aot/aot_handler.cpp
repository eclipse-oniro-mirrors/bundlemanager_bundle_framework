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

#include <sys/stat.h>
#include <thread>
#include <vector>

#include "appexecfwk_errors.h"
#include "app_log_wrapper.h"
#include "battery_srv_client.h"
#include "bundle_constants.h"
#include "bundle_mgr_service.h"
#include "bundle_util.h"
#include "display_power_mgr_client.h"
#include "installd_client.h"
#include "parameter.h"
#include "parameters.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
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
        (void)InstalldClient::GetInstance()->IsExistFile(path, isExistFile);
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
    APP_LOGD("args : %{public}s", aotArgs.ToString().c_str());
    return aotArgs;
}

void AOTHandler::AOTInternal(std::optional<AOTArgs> aotArgs) const
{
    if (!aotArgs) {
        APP_LOGI("aotArgs empty");
        return;
    }
    ErrCode ret = ERR_OK;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ret = InstalldClient::GetInstance()->ExecuteAOT(*aotArgs);
    }
    APP_LOGI("ExecuteAOT ret : %{public}d", ret);

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (!dataMgr) {
        APP_LOGE("dataMgr is null");
        return;
    }
    AOTCompileStatus status = ret == ERR_OK ? AOTCompileStatus::COMPILE_SUCCESS : AOTCompileStatus::COMPILE_FAILED;
    dataMgr->SetAOTCompileStatus(aotArgs->bundleName, aotArgs->moduleName, status);
}

void AOTHandler::HandleInstallWithSingleHap(const InnerBundleInfo &info, const std::string &compileMode) const
{
    std::optional<AOTArgs> aotArgs = BuildAOTArgs(info, info.GetCurrentModulePackage(), compileMode);
    AOTInternal(aotArgs);
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
        std::string compileMode = system::GetParameter(Constants::COMPILE_INSTALL_PARAM_KEY, Constants::COMPILE_NONE);
        APP_LOGD("%{public}s = %{public}s", Constants::COMPILE_INSTALL_PARAM_KEY, compileMode.c_str());
        if (compileMode == Constants::COMPILE_NONE) {
            APP_LOGD("%{public}s = none, no need to AOT", Constants::COMPILE_INSTALL_PARAM_KEY);
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
    ErrCode ret = InstalldClient::GetInstance()->RemoveDir(Constants::ARK_CACHE_PATH);
    if (ret != ERR_OK) {
        ret = InstalldClient::GetInstance()->RemoveDir(Constants::ARK_CACHE_PATH);
    }
    APP_LOGI("RemoveDir ret : %{public}d", ret);
    mode_t mode = S_IRWXU | S_IXGRP | S_IXOTH;
    ret = InstalldClient::GetInstance()->Mkdir(Constants::ARK_CACHE_PATH, mode, 0, 0);
    if (ret != ERR_OK) {
        ret = InstalldClient::GetInstance()->Mkdir(Constants::ARK_CACHE_PATH, mode, 0, 0);
    }
    APP_LOGI("Mkdir ret : %{public}d", ret);
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
    AOTInternal(aotArgs);
}

bool AOTHandler::CheckDeviceState() const
{
    DisplayPowerMgr::DisplayState displayState =
        DisplayPowerMgr::DisplayPowerMgrClient::GetInstance().GetDisplayState();
    if (displayState != DisplayPowerMgr::DisplayState::DISPLAY_OFF) {
        APP_LOGI("displayState is not DISPLAY_OFF");
        return false;
    }
    PowerMgr::BatteryChargeState batteryChargeState =
        OHOS::PowerMgr::BatterySrvClient::GetInstance().GetChargingStatus();
    if (batteryChargeState == PowerMgr::BatteryChargeState::CHARGE_STATE_ENABLE
        || batteryChargeState == PowerMgr::BatteryChargeState::CHARGE_STATE_FULL) {
        APP_LOGI("device is in charging state");
        return true;
    }
    APP_LOGI("device is not in charging state");
    return false;
}

void AOTHandler::HandleIdle() const
{
    APP_LOGI("HandleIdle begin");
    if (!IsSupportARM64()) {
        APP_LOGI("current device doesn't support arm64, no need to AOT");
        return;
    }
    std::string compileMode = system::GetParameter(Constants::COMPILE_IDLE_PARA_KEY, Constants::COMPILE_NONE);
    APP_LOGI("%{public}s = %{public}s", Constants::COMPILE_IDLE_PARA_KEY, compileMode.c_str());
    if (compileMode == Constants::COMPILE_NONE) {
        APP_LOGI("%{public}s = none, no need to AOT", Constants::COMPILE_IDLE_PARA_KEY);
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
}  // namespace AppExecFwk
}  // namespace OHOS
