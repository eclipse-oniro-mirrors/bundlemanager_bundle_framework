/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "module_json_updater.h"

#include <sstream>
#include <thread>

#include "app_log_wrapper.h"
#include "bundle_extractor.h"
#include "bundle_install_checker.h"
#include "bundle_mgr_service.h"
#include "bundle_mgr_service_event_handler.h"
#include "inner_bundle_info.h"
#include "module_profile.h"
#include "privilege_extension_ability_type.h"

namespace OHOS {
namespace AppExecFwk {
std::set<std::string> ModuleJsonUpdater::ignoreBundleNames_;
std::mutex ModuleJsonUpdater::mutex_;

void ModuleJsonUpdater::UpdateModuleJsonAsync()
{
    bool isHandled = false;
    (void)BMSEventHandler::CheckOtaFlag(OTAFlag::UPDATE_MODULE_JSON, isHandled);
    if (isHandled) {
        ClearIgnoreBundleNames();
        return;
    }
    std::thread([]() {
        UpdateModuleJson();
        (void)BMSEventHandler::UpdateOtaFlag(OTAFlag::UPDATE_MODULE_JSON);
    }).detach();
}

void ModuleJsonUpdater::UpdateModuleJson()
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE_NOFUNC("dataMgr is null");
        return;
    }
    APP_LOGI_NOFUNC("UpdateModuleJson begin");
    std::set<std::string> ignoreBundleNames = GetIgnoreBundleNames();
    std::map<std::string, InnerBundleInfo> infos = dataMgr->GetAllInnerBundleInfos();
    for (const auto &[bundleName, curInfo] : infos) {
        if (ignoreBundleNames.find(bundleName) != ignoreBundleNames.end()) {
            continue;
        }
        std::map<std::string, InnerBundleInfo> moduleJsonMap;
        if (!ParseBundleModuleJson(curInfo, moduleJsonMap)) {
            APP_LOGE_NOFUNC("ParseBundleModuleJson failed, -b:%{public}s", bundleName.c_str());
            continue;
        }
        InnerBundleInfo mergedInfo;
        if (!MergeInnerBundleInfo(moduleJsonMap, mergedInfo)) {
            APP_LOGE_NOFUNC("MergeInnerBundleInfo failed, -b:%{public}s", bundleName.c_str());
            continue;
        }
        UpdateExtensionType(curInfo, mergedInfo);
        bool ret = dataMgr->UpdatePartialInnerBundleInfo(mergedInfo);
        if (!ret) {
            APP_LOGE_NOFUNC("UpdatePartialInnerBundleInfo failed, -b:%{public}s", bundleName.c_str());
        }
    }
    ClearIgnoreBundleNames();
    APP_LOGI_NOFUNC("UpdateModuleJson end");
}

bool ModuleJsonUpdater::ParseBundleModuleJson(
    const InnerBundleInfo &curInfo, std::map<std::string, InnerBundleInfo> &moduleJsonMap)
{
    for (const auto &[moduleName, innerModuleInfo] : curInfo.GetInnerModuleInfos()) {
        InnerBundleInfo jsonInfo;
        bool ret = ParseHapModuleJson(innerModuleInfo.hapPath, jsonInfo);
        if (!ret) {
            APP_LOGE_NOFUNC("ParseHapModuleJson failed, -b:%{public}s, -m:%{public}s",
                curInfo.GetBundleName().c_str(), moduleName.c_str());
            continue;
        }
        moduleJsonMap.try_emplace(moduleName, jsonInfo);
    }
    return !moduleJsonMap.empty();
}

bool ModuleJsonUpdater::ParseHapModuleJson(const std::string &hapPath, InnerBundleInfo &jsonInfo)
{
    BundleExtractor bundleExtractor(hapPath);
    if (!bundleExtractor.Init()) {
        APP_LOGE_NOFUNC("bundle extractor init failed");
        return false;
    }
    std::ostringstream outStream;
    if (!bundleExtractor.ExtractProfile(outStream)) {
        APP_LOGE_NOFUNC("extract profile failed");
        return false;
    }
    if (!bundleExtractor.IsNewVersion()) {
        APP_LOGI_NOFUNC("not support FA");
        return false;
    }
    jsonInfo.SetIsNewVersion(true);
    ModuleProfile moduleProfile;
    ErrCode ret = moduleProfile.TransformTo(outStream, bundleExtractor, jsonInfo);
    if (ret != ERR_OK) {
        APP_LOGE_NOFUNC("TransformTo failed, err:%{public}d", ret);
        return false;
    }
    return true;
}

bool ModuleJsonUpdater::MergeInnerBundleInfo(
    const std::map<std::string, InnerBundleInfo> &moduleJsonMap, InnerBundleInfo &mergedInfo)
{
    if (moduleJsonMap.empty()) {
        APP_LOGE_NOFUNC("moduleJsonMap empty");
        return false;
    }
    mergedInfo.SetBaseApplicationInfo(moduleJsonMap.begin()->second.GetBaseApplicationInfo());
    for (const auto &[moduleName, innerBundleInfo] : moduleJsonMap) {
        if (innerBundleInfo.IsEntryModule(moduleName)) {
            mergedInfo.SetBaseApplicationInfo(innerBundleInfo.GetBaseApplicationInfo());
        }
        mergedInfo.AddInnerModuleInfo(innerBundleInfo.GetInnerModuleInfos());
        mergedInfo.AddModuleAbilityInfo(innerBundleInfo.GetInnerAbilityInfos());
        mergedInfo.AddModuleExtensionInfos(innerBundleInfo.GetInnerExtensionInfos());
    }
    return true;
}

void ModuleJsonUpdater::UpdateExtensionType(const InnerBundleInfo &curInfo, InnerBundleInfo &mergedInfo)
{
    std::map<std::string, bool> privilegeMap;
    for (const auto &[key, innerExtensionInfo] : curInfo.GetInnerExtensionInfos()) {
        if (innerExtensionInfo.type != ExtensionAbilityType::UNSPECIFIED) {
            continue;
        }
        auto &moduleJsonExtensionInfos = mergedInfo.FetchInnerExtensionInfos();
        auto item = moduleJsonExtensionInfos.find(key);
        if (item == moduleJsonExtensionInfos.end() ||
            innerExtensionInfo.moduleName != item->second.moduleName ||
            innerExtensionInfo.name != item->second.name) {
            continue;
        }
        bool isPrivilegeType =
            PRIVILEGE_EXTENSION_ABILITY_TYPE.find(item->second.type) != PRIVILEGE_EXTENSION_ABILITY_TYPE.end();
        if (!isPrivilegeType) {
            continue;
        }
        if (privilegeMap.find(innerExtensionInfo.hapPath) == privilegeMap.end()) {
            privilegeMap[innerExtensionInfo.hapPath] =
                CanUsePrivilegeExtension(innerExtensionInfo.hapPath, innerExtensionInfo.bundleName);
        }
        if (!privilegeMap[innerExtensionInfo.hapPath]) {
            APP_LOGE_NOFUNC("UpdateExtensionType failed, bundleName:%{public}s, extensionName:%{public}s, type:%{public}d",
                innerExtensionInfo.bundleName.c_str(), innerExtensionInfo.name.c_str(),
                static_cast<int>(item->second.type));
            item->second.type = ExtensionAbilityType::UNSPECIFIED;
        }
    }
}

bool ModuleJsonUpdater::CanUsePrivilegeExtension(const std::string &hapPath, const std::string &bundleName)
{
    BundleInstallChecker bundleInstallChecker;
    std::vector<Security::Verify::HapVerifyResult> hapVerifyRes;
    ErrCode ret = bundleInstallChecker.CheckMultipleHapsSignInfo({hapPath}, hapVerifyRes, true);
    if (ret != ERR_OK || hapVerifyRes.empty()) {
        APP_LOGE_NOFUNC("sign check failed, err:%{public}d, hapPath:%{public}s", ret, hapPath.c_str());
        return false;
    }
    const auto &provisionInfo = hapVerifyRes[0].GetProvisionInfo();

    AppPrivilegeCapability appPrivilegeCapability;
    bundleInstallChecker.ParseAppPrivilegeCapability(provisionInfo, appPrivilegeCapability);

    std::vector<std::string> appSignatures;
    appSignatures.emplace_back(provisionInfo.bundleInfo.appIdentifier);
    appSignatures.emplace_back(bundleName + Constants::FILE_UNDERLINE + provisionInfo.appId);
    appSignatures.emplace_back(provisionInfo.fingerprint);
    bundleInstallChecker.FetchPrivilegeCapabilityFromPreConfig(bundleName, appSignatures, appPrivilegeCapability);

    return appPrivilegeCapability.allowUsePrivilegeExtension;
}

void ModuleJsonUpdater::SetIgnoreBundleNames(const std::set<std::string> &bundles)
{
    std::lock_guard<std::mutex> lock(mutex_);
    ignoreBundleNames_ = bundles;
}

std::set<std::string> ModuleJsonUpdater::GetIgnoreBundleNames()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return ignoreBundleNames_;
}

void ModuleJsonUpdater::ClearIgnoreBundleNames()
{
    std::lock_guard<std::mutex> lock(mutex_);
    ignoreBundleNames_.clear();
}
}  // namespace AppExecFwk
}  // namespace OHOS
