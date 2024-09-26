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
#include "bundle_mgr_client.h"

#include "ability_info.h"
#include "app_log_wrapper.h"
#include "app_log_tag_wrapper.h"
#include "bundle_mgr_client_impl.h"
#include "extension_ability_info.h"
#include "hap_module_info.h"

namespace OHOS {
namespace AppExecFwk {
std::shared_ptr<BundleMgrClientImpl> BundleMgrClient::impl_ = std::make_shared<BundleMgrClientImpl>();

BundleMgrClient::BundleMgrClient()
{
    APP_LOGD("create BundleMgrClient");
}

BundleMgrClient::~BundleMgrClient()
{
    APP_LOGD("destory BundleMgrClient");
}

ErrCode BundleMgrClient::GetNameForUid(const int uid, std::string &name)
{
    if (impl_ == nullptr) {
        APP_LOGE("Bundle mgr client impl is nullptr");
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    return impl_->GetNameForUid(uid, name);
}

bool BundleMgrClient::GetBundleInfo(const std::string &bundleName, const BundleFlag flag, BundleInfo &bundleInfo,
    int32_t userId)
{
    if (impl_ == nullptr) {
        LOG_E(BMS_TAG_QUERY, "Bundle mgr client impl is nullptr");
        return false;
    }
    return impl_->GetBundleInfo(bundleName, flag, bundleInfo, userId);
}

ErrCode BundleMgrClient::GetBundlePackInfo(
    const std::string &bundleName, const BundlePackFlag flag, BundlePackInfo &bundlePackInfo, int32_t userId)
{
    if (impl_ == nullptr) {
        APP_LOGE("Bundle mgr client impl is nullptr");
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    return impl_->GetBundlePackInfo(bundleName, flag, bundlePackInfo, userId);
}

ErrCode BundleMgrClient::CreateBundleDataDir(int32_t userId)
{
    if (impl_ == nullptr) {
        APP_LOGE("Bundle mgr client impl is nullptr");
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    return impl_->CreateBundleDataDir(userId);
}

bool BundleMgrClient::GetHapModuleInfo(const std::string &bundleName, const std::string &hapName,
    HapModuleInfo &hapModuleInfo)
{
    if (impl_ == nullptr) {
        APP_LOGE("Bundle mgr client impl is nullptr");
        return false;
    }
    return impl_->GetHapModuleInfo(bundleName, hapName, hapModuleInfo);
}

bool BundleMgrClient::GetResConfigFile(const HapModuleInfo &hapModuleInfo, const std::string &metadataName,
    std::vector<std::string> &profileInfos) const
{
    if (impl_ == nullptr) {
        APP_LOGE("Bundle mgr client impl is nullptr");
        return false;
    }
    return impl_->GetResConfigFile(hapModuleInfo, metadataName, profileInfos);
}

bool BundleMgrClient::GetResConfigFile(const ExtensionAbilityInfo &extensionInfo, const std::string &metadataName,
    std::vector<std::string> &profileInfos) const
{
    if (impl_ == nullptr) {
        APP_LOGE("Bundle mgr client impl is nullptr");
        return false;
    }
    return impl_->GetResConfigFile(extensionInfo, metadataName, profileInfos);
}

bool BundleMgrClient::GetResConfigFile(const AbilityInfo &abilityInfo, const std::string &metadataName,
    std::vector<std::string> &profileInfos) const
{
    if (impl_ == nullptr) {
        APP_LOGE("Bundle mgr client impl is nullptr");
        return false;
    }
    return impl_->GetResConfigFile(abilityInfo, metadataName, profileInfos);
}

bool BundleMgrClient::GetProfileFromExtension(const ExtensionAbilityInfo &extensionInfo,
    const std::string &metadataName, std::vector<std::string> &profileInfos) const
{
    if (impl_ == nullptr) {
        APP_LOGE("Bundle mgr client impl is nullptr");
        return false;
    }
    return impl_->GetProfileFromExtension(extensionInfo, metadataName, profileInfos);
}

bool BundleMgrClient::GetProfileFromAbility(const AbilityInfo &abilityInfo, const std::string &metadataName,
    std::vector<std::string> &profileInfos) const
{
    if (impl_ == nullptr) {
        APP_LOGE("Bundle mgr client impl is nullptr");
        return false;
    }
    return impl_->GetProfileFromAbility(abilityInfo, metadataName, profileInfos);
}

bool BundleMgrClient::GetProfileFromHap(const HapModuleInfo &hapModuleInfo, const std::string &metadataName,
    std::vector<std::string> &profileInfos) const
{
    if (impl_ == nullptr) {
        APP_LOGE("Bundle mgr client impl is nullptr");
        return false;
    }
    return impl_->GetProfileFromHap(hapModuleInfo, metadataName, profileInfos);
}

ErrCode BundleMgrClient::InstallSandboxApp(const std::string &bundleName, int32_t dlpType, int32_t userId,
    int32_t &appIndex)
{
    if (impl_ == nullptr) {
        APP_LOGE("Bundle mgr client impl is nullptr");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_INTERNAL_ERROR;
    }
    return impl_->InstallSandboxApp(bundleName, dlpType, userId, appIndex);
}

ErrCode BundleMgrClient::UninstallSandboxApp(const std::string &bundleName, int32_t appIndex, int32_t userId)
{
    if (impl_ == nullptr) {
        APP_LOGE("Bundle mgr client impl is nullptr");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_INTERNAL_ERROR;
    }
    return impl_->UninstallSandboxApp(bundleName, appIndex, userId);
}

ErrCode BundleMgrClient::GetSandboxBundleInfo(
    const std::string &bundleName, int32_t appIndex, int32_t userId, BundleInfo &info)
{
    if (impl_ == nullptr) {
        APP_LOGE("Bundle mgr client impl is nullptr");
        return ERR_APPEXECFWK_SANDBOX_QUERY_INTERNAL_ERROR;
    }
    return impl_->GetSandboxBundleInfo(bundleName, appIndex, userId, info);
}

ErrCode BundleMgrClient::GetSandboxAbilityInfo(const Want &want, int32_t appIndex, int32_t flags, int32_t userId,
    AbilityInfo &abilityInfo)
{
    if (impl_ == nullptr) {
        APP_LOGE("Bundle mgr client impl is nullptr");
        return ERR_APPEXECFWK_SANDBOX_QUERY_INTERNAL_ERROR;
    }
    return impl_->GetSandboxAbilityInfo(want, appIndex, flags, userId, abilityInfo);
}

ErrCode BundleMgrClient::GetSandboxExtAbilityInfos(const Want &want, int32_t appIndex, int32_t flags, int32_t userId,
    std::vector<ExtensionAbilityInfo> &extensionInfos)
{
    if (impl_ == nullptr) {
        APP_LOGE("Bundle mgr client impl is nullptr");
        return ERR_APPEXECFWK_SANDBOX_QUERY_INTERNAL_ERROR;
    }
    return impl_->GetSandboxExtAbilityInfos(want, appIndex, flags, userId, extensionInfos);
}

ErrCode BundleMgrClient::GetSandboxHapModuleInfo(const AbilityInfo &abilityInfo, int32_t appIndex, int32_t userId,
    HapModuleInfo &hapModuleInfo)
{
    if (impl_ == nullptr) {
        APP_LOGE("Bundle mgr client impl is nullptr");
        return ERR_APPEXECFWK_SANDBOX_QUERY_INTERNAL_ERROR;
    }
    return impl_->GetSandboxHapModuleInfo(abilityInfo, appIndex, userId, hapModuleInfo);
}

ErrCode BundleMgrClient::GetDirByBundleNameAndAppIndex(const std::string &bundleName, int32_t appIndex,
        std::string &dataDir)
{
    if (impl_ == nullptr) {
        APP_LOGE("Bundle mgr client impl is nullptr");
        return ERR_APPEXECFWK_SANDBOX_QUERY_INTERNAL_ERROR;
    }
    return impl_->GetDirByBundleNameAndAppIndex(bundleName, appIndex, dataDir);
}
}  // namespace AppExecFwk
}  // namespace OHOS
