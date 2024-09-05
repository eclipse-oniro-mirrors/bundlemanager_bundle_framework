/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "bundle_sandbox_app_helper.h"

#include "app_log_wrapper.h"

#ifdef BUNDLE_FRAMEWORK_SANDBOX_APP
#include "bundle_sandbox_installer.h"
#endif

namespace OHOS {
namespace AppExecFwk {
void BundleSandboxAppHelper::SaveSandboxAppInfo(const InnerBundleInfo &info, const int32_t &appIndex)
{
#ifdef BUNDLE_FRAMEWORK_SANDBOX_APP
    APP_LOGD("enter SaveSandboxAppInfo");
    if (sandboxDataMgr_ == nullptr) {
        APP_LOGE("sandboxDataMgr_ is nullptr");
        return;
    }
    sandboxDataMgr_->SaveSandboxAppInfo(info, appIndex);
#else
    APP_LOGD("sandbox app not supported");
#endif
}

void BundleSandboxAppHelper::DeleteSandboxAppInfo(const std::string &bundleName, const int32_t &appIndex)
{
#ifdef BUNDLE_FRAMEWORK_SANDBOX_APP
    APP_LOGD("enter DeleteSandboxAppInfo");
    if (sandboxDataMgr_ == nullptr) {
        APP_LOGE("sandboxDataMgr_ is nullptr");
        return;
    }
    sandboxDataMgr_->DeleteSandboxAppInfo(bundleName, appIndex);
#else
    APP_LOGD("sandbox app not supported");
#endif
}

ErrCode BundleSandboxAppHelper::GetSandboxAppBundleInfo(
    const std::string &bundleName, const int32_t &appIndex, const int32_t &userId, BundleInfo &info) const
{
#ifdef BUNDLE_FRAMEWORK_SANDBOX_APP
    APP_LOGD("enter GetSandboxAppBundleInfo");
    if (sandboxDataMgr_ == nullptr) {
        APP_LOGE("sandboxDataMgr_ is nullptr");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_INTERNAL_ERROR;
    }
    return sandboxDataMgr_->GetSandboxAppBundleInfo(bundleName, appIndex, userId, info);
#else
    APP_LOGD("sandbox app not supported");
    return ERR_APPEXECFWK_SANDBOX_APP_NOT_SUPPORTED;
#endif
}

int32_t BundleSandboxAppHelper::GenerateSandboxAppIndex(const std::string &bundleName)
{
#ifdef BUNDLE_FRAMEWORK_SANDBOX_APP
    APP_LOGD("enter GenerateSandboxAppIndex");
    if (sandboxDataMgr_ == nullptr) {
        APP_LOGE("sandboxDataMgr_ is nullptr");
        return Constants::INITIAL_SANDBOX_APP_INDEX;
    }
    return sandboxDataMgr_->GenerateSandboxAppIndex(bundleName);
#else
    APP_LOGD("sandbox app not supported");
    return Constants::INITIAL_SANDBOX_APP_INDEX;
#endif
}

bool BundleSandboxAppHelper::DeleteSandboxAppIndex(const std::string &bundleName, int32_t appIndex)
{
#ifdef BUNDLE_FRAMEWORK_SANDBOX_APP
    APP_LOGD("enter DeleteSandboxAppIndex");
    if (sandboxDataMgr_ == nullptr) {
        APP_LOGE("sandboxDataMgr_ is nullptr");
        return false;
    }
    return sandboxDataMgr_->DeleteSandboxAppIndex(bundleName, appIndex);
#else
    APP_LOGD("sandbox app not supported");
    return false;
#endif
}

std::unordered_map<std::string, InnerBundleInfo> BundleSandboxAppHelper::GetSandboxAppInfoMap() const
{
#ifdef BUNDLE_FRAMEWORK_SANDBOX_APP
    APP_LOGD("enter GetSandboxAppInfoMap");
    if (sandboxDataMgr_ == nullptr) {
        APP_LOGE("sandboxDataMgr_ is nullptr");
        std::unordered_map<std::string, InnerBundleInfo> innerBundleInfoMap;
        return innerBundleInfoMap;
    }
    return sandboxDataMgr_->GetSandboxAppInfoMap();
#else
    APP_LOGD("sandbox app not supported");
    std::unordered_map<std::string, InnerBundleInfo> innerBundleInfoMap;
    return innerBundleInfoMap;
#endif
}

ErrCode BundleSandboxAppHelper::GetSandboxAppInfo(
    const std::string &bundleName, const int32_t &appIndex, int32_t &userId, InnerBundleInfo &info) const
{
#ifdef BUNDLE_FRAMEWORK_SANDBOX_APP
    APP_LOGD("enter GetSandboxAppInfo");
    if (sandboxDataMgr_ == nullptr) {
        APP_LOGE("sandboxDataMgr_ is nullptr");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_INTERNAL_ERROR;
    }
    return sandboxDataMgr_->GetSandboxAppInfo(bundleName, appIndex, userId, info);
#else
    APP_LOGD("sandbox app not supported");
    return ERR_APPEXECFWK_SANDBOX_APP_NOT_SUPPORTED;
#endif
}

ErrCode BundleSandboxAppHelper::GetSandboxHapModuleInfo(
    const AbilityInfo &abilityInfo, int32_t appIndex, int32_t userId, HapModuleInfo &hapModuleInfo) const
{
#ifdef BUNDLE_FRAMEWORK_SANDBOX_APP
    APP_LOGD("enter GetSandboxHapModuleInfo");
    if (sandboxDataMgr_ == nullptr) {
        APP_LOGE("sandboxDataMgr_ is nullptr");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_INTERNAL_ERROR;
    }
    return sandboxDataMgr_->GetSandboxHapModuleInfo(abilityInfo, appIndex, userId, hapModuleInfo);
#else
    APP_LOGD("sandbox app not supported");
    return ERR_APPEXECFWK_SANDBOX_APP_NOT_SUPPORTED;
#endif
}

ErrCode BundleSandboxAppHelper::GetInnerBundleInfoByUid(const int32_t &uid, InnerBundleInfo &innerBundleInfo) const
{
#ifdef BUNDLE_FRAMEWORK_SANDBOX_APP
    APP_LOGD("enter GetInnerBundleInfoByUid");
    if (sandboxDataMgr_ == nullptr) {
        APP_LOGE("sandboxDataMgr_ is nullptr");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_INTERNAL_ERROR;
    }
    return sandboxDataMgr_->GetInnerBundleInfoByUid(uid, innerBundleInfo);
#else
    APP_LOGD("sandbox app not supported");
    return ERR_APPEXECFWK_SANDBOX_APP_NOT_SUPPORTED;
#endif
}

ErrCode BundleSandboxAppHelper::InstallSandboxApp(const std::string &bundleName, const int32_t &dlpType,
    const int32_t &userId, int32_t &appIndex)
{
#ifdef BUNDLE_FRAMEWORK_SANDBOX_APP
    APP_LOGD("enter InstallSandboxApp");
    std::shared_ptr<BundleSandboxInstaller> installer = std::make_shared<BundleSandboxInstaller>();
    return installer->InstallSandboxApp(bundleName, dlpType, userId, appIndex);
#else
    APP_LOGD("sandbox app not supported");
    return ERR_APPEXECFWK_SANDBOX_APP_NOT_SUPPORTED;
#endif
}

ErrCode BundleSandboxAppHelper::UninstallSandboxApp(
    const std::string &bundleName, const int32_t &appIndex, const int32_t &userId)
{
#ifdef BUNDLE_FRAMEWORK_SANDBOX_APP
    APP_LOGD("enter UninstallSandboxApp");
    std::shared_ptr<BundleSandboxInstaller> installer = std::make_shared<BundleSandboxInstaller>();
    return installer->UninstallSandboxApp(bundleName, appIndex, userId);
#else
    APP_LOGD("sandbox app not supported");
    return ERR_APPEXECFWK_SANDBOX_APP_NOT_SUPPORTED;
#endif
}

ErrCode BundleSandboxAppHelper::UninstallAllSandboxApps(const std::string &bundleName, int32_t userId)
{
#ifdef BUNDLE_FRAMEWORK_SANDBOX_APP
    APP_LOGD("enter UninstallAllSandboxApps");
    std::shared_ptr<BundleSandboxInstaller> installer = std::make_shared<BundleSandboxInstaller>();
    return installer->UninstallAllSandboxApps(bundleName, userId);
#else
    APP_LOGD("sandbox app not supported");
    return ERR_APPEXECFWK_SANDBOX_APP_NOT_SUPPORTED;
#endif
}

void BundleSandboxAppHelper::RestoreSandboxUidAndGid(std::map<int32_t, std::string> &bundleIdMap)
{
#ifdef BUNDLE_FRAMEWORK_SANDBOX_APP
    APP_LOGD("enter RestoreSandboxUidAndGid");
    if (sandboxDataMgr_ == nullptr) {
        APP_LOGE("sandboxDataMgr_ is nullptr");
        return;
    }
    sandboxDataMgr_->RestoreSandboxUidAndGid(bundleIdMap);
#else
    APP_LOGD("sandbox app not supported");
#endif
}
} // AppExecFwk
} // OHOS
