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
#include "resource_helper.h"
#include "app_log_wrapper.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "bundle_errors.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "common_func.h"

namespace OHOS {
namespace AppExecFwk {

sptr<IBundleResource> ResourceHelper::bundleResourceMgr_ = nullptr;
std::mutex ResourceHelper::bundleResourceMutex_;
sptr<IRemoteObject::DeathRecipient> ResourceHelper::deathRecipient_(sptr<BundleResourceMgrDeathRecipient>::MakeSptr());

void ResourceHelper::BundleResourceMgrDeathRecipient::OnRemoteDied([[maybe_unused]] const wptr<IRemoteObject>& remote)
{
    APP_LOGI("BundleManagerService dead");
    std::lock_guard<std::mutex> lock(bundleResourceMutex_);
    bundleResourceMgr_ = nullptr;
};

sptr<IBundleResource> ResourceHelper::GetBundleResourceMgr()
{
    std::lock_guard<std::mutex> lock(bundleResourceMutex_);
    if (bundleResourceMgr_ == nullptr) {
        auto systemAbilityManager = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (systemAbilityManager == nullptr) {
            APP_LOGE("systemAbilityManager is null");
            return nullptr;
        }
        auto bundleMgrSa = systemAbilityManager->GetSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
        if (bundleMgrSa == nullptr) {
            APP_LOGE("bundleMgrSa is null");
            return nullptr;
        }
        auto bundleMgr = OHOS::iface_cast<IBundleMgr>(bundleMgrSa);
        if (bundleMgr == nullptr) {
            APP_LOGE("iface_cast failed");
            return nullptr;
        }
        bundleMgr->AsObject()->AddDeathRecipient(deathRecipient_);
        bundleResourceMgr_ = bundleMgr->GetBundleResourceProxy();
    }
    return bundleResourceMgr_;
}

ErrCode ResourceHelper::InnerGetBundleResourceInfo(
    const std::string &bundleName, uint32_t flags, int32_t appIndex, BundleResourceInfo &resourceInfo)
{
    APP_LOGD("start");
    auto bundleResourceProxy = ResourceHelper::GetBundleResourceMgr();
    if (bundleResourceProxy == nullptr) {
        APP_LOGE("bundleResourceProxy is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = bundleResourceProxy->GetBundleResourceInfo(bundleName, flags, resourceInfo, appIndex);
    if (ret != ERR_OK) {
        APP_LOGE("failed, bundleName is %{public}s, errCode: %{public}d", bundleName.c_str(), ret);
    }
    return CommonFunc::ConvertErrCode(ret);
}

ErrCode ResourceHelper::InnerGetLauncherAbilityResourceInfo(
    const std::string &bundleName, uint32_t flags, int32_t appIndex,
    std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfo)
{
    APP_LOGD("start");
    auto bundleResourceProxy = ResourceHelper::GetBundleResourceMgr();
    if (bundleResourceProxy == nullptr) {
        APP_LOGE("bundleResourceProxy is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = bundleResourceProxy->GetLauncherAbilityResourceInfo(bundleName,
        flags, launcherAbilityResourceInfo, appIndex);
    if (ret != ERR_OK) {
        APP_LOGE("failed, bundleName is %{public}s, errCode: %{public}d", bundleName.c_str(), ret);
    }
    return CommonFunc::ConvertErrCode(ret);
}

ErrCode ResourceHelper::InnerGetAllBundleResourceInfo(uint32_t flags,
    std::vector<BundleResourceInfo> &bundleResourceInfos)
{
    auto bundleResourceProxy = ResourceHelper::GetBundleResourceMgr();
    if (bundleResourceProxy == nullptr) {
        APP_LOGE("bundleResourceProxy is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = bundleResourceProxy->GetAllBundleResourceInfo(flags, bundleResourceInfos);
    if (ret != ERR_OK) {
        APP_LOGE("failed, errCode: %{public}d", ret);
    }
    return CommonFunc::ConvertErrCode(ret);
}

ErrCode ResourceHelper::InnerGetAllLauncherAbilityResourceInfo(uint32_t flags,
    std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfos)
{
    auto bundleResourceProxy = ResourceHelper::GetBundleResourceMgr();
    if (bundleResourceProxy == nullptr) {
        APP_LOGE("bundleResourceProxy is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = bundleResourceProxy->GetAllLauncherAbilityResourceInfo(flags, launcherAbilityResourceInfos);
    if (ret != ERR_OK) {
        APP_LOGE("failed, errCode: %{public}d", ret);
    }
    return CommonFunc::ConvertErrCode(ret);
}
} // AppExecFwk
} // OHOS