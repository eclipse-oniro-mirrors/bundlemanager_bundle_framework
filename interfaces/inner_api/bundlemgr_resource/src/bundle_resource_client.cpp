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

#include "bundle_resource_client.h"

#include "app_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
BundleResourceClient::BundleResourceClient()
{
    dataProcess_ = std::make_shared<BundleResourceDataProcess>();
}

BundleResourceClient::~BundleResourceClient()
{
}

ErrCode BundleResourceClient::GetBundleResourceInfo(
    const std::string &bundleName,
    const uint32_t flags,
    BundleResourceInfo &bundleResourceInfo)
{
    if (dataProcess_ == nullptr) {
        APP_LOGE("dataProcess_ is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    return dataProcess_->GetBundleResourceInfo(bundleName, flags, bundleResourceInfo);
}

ErrCode BundleResourceClient::GetLauncherAbilityResourceInfo(
    const std::string &bundleName,
    const uint32_t flags,
    std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfo)
{
    if (dataProcess_ == nullptr) {
        APP_LOGE("dataProcess_ is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    return dataProcess_->GetLauncherAbilityResourceInfo(bundleName, flags, launcherAbilityResourceInfo);
}

ErrCode BundleResourceClient::GetAllBundleResourceInfo(const uint32_t flags,
    std::vector<BundleResourceInfo> &bundleResourceInfos)
{
    if (dataProcess_ == nullptr) {
        APP_LOGE("dataProcess_ is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataProcess_->GetAllBundleResourceInfo(flags, bundleResourceInfos);
}

ErrCode BundleResourceClient::GetAllLauncherAbilityResourceInfo(const uint32_t flags,
    std::vector<LauncherAbilityResourceInfo> &launcherAbilityResourceInfos)
{
    if (dataProcess_ == nullptr) {
        APP_LOGE("dataProcess_ is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return dataProcess_->GetAllLauncherAbilityResourceInfo(flags, launcherAbilityResourceInfos);
}
} // namespace AppExecFwk
} // namespace OHOS
