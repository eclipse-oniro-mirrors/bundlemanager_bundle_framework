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

#include "shared_bundle_installer.h"

#include "app_log_wrapper.h"
#include "bundle_mgr_service.h"
#include "scope_guard.h"

namespace OHOS {
namespace AppExecFwk {
SharedBundleInstaller::SharedBundleInstaller(const InstallParam &installParam, const Constants::AppType appType)
    : installParam_(installParam), appType_(appType)
{
    APP_LOGD("shared bundle installer instance is created");
}

SharedBundleInstaller::~SharedBundleInstaller()
{
    APP_LOGD("shared bundle installer instance is destroyed");
}

ErrCode SharedBundleInstaller::ParseFiles()
{
    ErrCode result = ERR_OK;
    if (installParam_.sharedBundleDirPaths.empty()) {
        APP_LOGI("sharedBundleDirPaths is empty");
        return result;
    }

    InstallCheckParam checkParam;
    checkParam.isPreInstallApp = installParam_.isPreInstallApp;
    checkParam.crowdtestDeadline = installParam_.crowdtestDeadline;
    checkParam.appType = appType_;
    checkParam.removable = installParam_.removable;
    checkParam.installBundlePermissionStatus = installParam_.installBundlePermissionStatus;
    checkParam.installEnterpriseBundlePermissionStatus = installParam_.installEnterpriseBundlePermissionStatus;
    checkParam.installEtpNormalBundlePermissionStatus = installParam_.installEtpNormalBundlePermissionStatus;
    checkParam.installEtpMdmBundlePermissionStatus = installParam_.installEtpMdmBundlePermissionStatus;
    checkParam.isCallByShell = installParam_.isCallByShell;

    for (const auto &path : installParam_.sharedBundleDirPaths) {
        auto installer = std::make_shared<InnerSharedBundleInstaller>(path);
        result = installer->ParseFiles(checkParam);
        CHECK_RESULT(result, "parse file failed %{public}d");
        if (innerInstallers_.find(installer->GetBundleName()) != innerInstallers_.end()) {
            APP_LOGW("sharedBundleDirPaths does not support that different paths contain hsp of same bundleName");
            continue;
        }
        innerInstallers_.emplace(installer->GetBundleName(), installer);
    }

    APP_LOGI("parse shared bundles successfully");
    return result;
}

bool SharedBundleInstaller::CheckDependency(const InnerBundleInfo &innerBundleInfo) const
{
    if (innerBundleInfo.GetDependencies().empty()) {
        APP_LOGD("dependencies of %{public}s is empty", innerBundleInfo.GetBundleName().c_str());
        return true;
    }

    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return false;
    }

    for (const auto &dependency : innerBundleInfo.GetDependencies()) {
        if (dependency.bundleName.empty() || dependency.bundleName == innerBundleInfo.GetBundleName()) {
            APP_LOGD("inner-app dependency: %{public}s", GetJsonStrFromInfo(dependency).c_str());
            continue;
        }

        auto iter = innerInstallers_.find(dependency.bundleName);
        if (iter != innerInstallers_.end() && iter->second->CheckDependency(dependency)) {
            APP_LOGD("dependency found in installing shared bundles: %{public}s",
                GetJsonStrFromInfo(dependency).c_str());
            continue;
        }

        if (FindDependencyInInstalledBundles(dependency)) {
            APP_LOGD("dependency found in installed shared bundles: %{public}s",
                GetJsonStrFromInfo(dependency).c_str());
            continue;
        }

        APP_LOGE("dependency not found: %{public}s", GetJsonStrFromInfo(dependency).c_str());
        if (iter != innerInstallers_.end()) {
            std::string checkResultMsg = "the dependent module: " + dependency.moduleName + " does not exist.";
            iter->second->SetCheckResultMsg(checkResultMsg);
        }
        return false;
    }

    APP_LOGD("dependencies are satisfied");
    return true;
}

ErrCode SharedBundleInstaller::Install(const EventInfo &eventTemplate)
{
    if (!NeedToInstall()) {
        APP_LOGI("do not need to install");
        return ERR_OK;
    }

    std::vector<std::string> processedBundles;
    ScopeGuard installGuard([this, &processedBundles] {
        APP_LOGE("install shared bundles failed, rollbacking:%{public}s", GetJsonStrFromInfo(processedBundles).c_str());
        for (auto iter = processedBundles.crbegin(); iter != processedBundles.crend(); ++iter) {
            auto installer = innerInstallers_.find(*iter);
            if (installer != innerInstallers_.end()) {
                installer->second->RollBack();
            } else {
                APP_LOGE("rollback failed : %{public}s", iter->c_str());
            }
        }
    });

    ErrCode result = ERR_OK;
    for (auto installer : innerInstallers_) {
        result = installer.second->Install(installParam_);
        processedBundles.emplace_back(installer.first);
        if (result != ERR_OK) {
            APP_LOGE("install shared bundle failed %{public}d", result);
            SendBundleSystemEvent(eventTemplate, result);
            return result;
        }
    }

    installGuard.Dismiss();
    SendBundleSystemEvent(eventTemplate, result);
    APP_LOGD("install shared bundles success");
    return result;
}

bool SharedBundleInstaller::FindDependencyInInstalledBundles(const Dependency &dependency) const
{
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return false;
    }

    InnerBundleInfo bundleInfo;
    bool isBundleExist = dataMgr->FetchInnerBundleInfo(dependency.bundleName, bundleInfo);
    if (!isBundleExist || bundleInfo.GetApplicationBundleType() != BundleType::SHARED) {
        APP_LOGE("the shared bundle (%{public}s) is not installed", dependency.bundleName.c_str());
        return false;
    }

    BaseSharedBundleInfo sharedBundle;
    bool isModuleExist = bundleInfo.GetMaxVerBaseSharedBundleInfo(dependency.moduleName, sharedBundle);
    if (isModuleExist && dependency.versionCode <= sharedBundle.versionCode) {
        return true;
    }

    APP_LOGE("the module or version not satisfied : %{public}s", GetJsonStrFromInfo(dependency).c_str());
    return false;
}

void SharedBundleInstaller::SendBundleSystemEvent(const EventInfo &eventTemplate, ErrCode errCode)
{
    EventInfo commonEventInfo = eventTemplate;
    commonEventInfo.isPreInstallApp = installParam_.isPreInstallApp;
    commonEventInfo.errCode = errCode;
    commonEventInfo.isFreeInstallMode = (installParam_.installFlag == InstallFlag::FREE_INSTALL);
    GetCallingEventInfo(commonEventInfo);

    for (auto installer : innerInstallers_) {
        installer.second->SendBundleSystemEvent(commonEventInfo);
    }
}

void SharedBundleInstaller::GetCallingEventInfo(EventInfo &eventInfo)
{
    APP_LOGD("GetCallingEventInfo start, bundleName:%{public}s", eventInfo.callingBundleName.c_str());
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("Get dataMgr shared_ptr nullptr");
        return;
    }
    if (!dataMgr->GetBundleNameForUid(eventInfo.callingUid, eventInfo.callingBundleName)) {
        APP_LOGW("CallingUid %{public}d is not hap, no bundleName", eventInfo.callingUid);
        eventInfo.callingBundleName = Constants::EMPTY_STRING;
        return;
    }

    BundleInfo bundleInfo;
    if (!dataMgr->GetBundleInfo(eventInfo.callingBundleName, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo,
        eventInfo.callingUid / Constants::BASE_USER_RANGE)) {
        APP_LOGE("GetBundleInfo failed, bundleName: %{public}s", eventInfo.callingBundleName.c_str());
        return;
    }
    eventInfo.callingAppId = bundleInfo.appId;
}
}  // namespace AppExecFwk
}  // namespace OHOS
