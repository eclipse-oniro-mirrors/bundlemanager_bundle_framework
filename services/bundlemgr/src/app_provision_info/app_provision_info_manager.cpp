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

#include "app_provision_info_manager.h"
#include "app_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
AppProvisionInfoManager::AppProvisionInfoManager()
{
    AppProvisionInfoManagerDb_ = std::make_shared<AppProvisionInfoManagerRdb>();
}

AppProvisionInfoManager::~AppProvisionInfoManager()
{}


bool AppProvisionInfoManager::AddAppProvisionInfo(const std::string &bundleName,
    const AppProvisionInfo &appProvisionInfo)
{
    APP_LOGD("AppProvisionInfoManager::AddAppProvisionInfo bundleName: %{public}s", bundleName.c_str());
    return AppProvisionInfoManagerDb_->AddAppProvisionInfo(bundleName, appProvisionInfo);
}

bool AppProvisionInfoManager::DeleteAppProvisionInfo(const std::string &bundleName)
{
    APP_LOGD("AppProvisionInfoManager::DeleteAppProvisionInfo bundleName: %{public}s", bundleName.c_str());
    return AppProvisionInfoManagerDb_->DeleteAppProvisionInfo(bundleName);
}

bool AppProvisionInfoManager::GetAppProvisionInfo(const std::string &bundleName,
    AppProvisionInfo &appProvisionInfo)
{
    APP_LOGD("AppProvisionInfoManager::GetAppProvisionInfo bundleName: %{public}s", bundleName.c_str());
    return AppProvisionInfoManagerDb_->GetAppProvisionInfo(bundleName, appProvisionInfo);
}

bool AppProvisionInfoManager::GetAllAppProvisionInfoBundleName(std::unordered_set<std::string> &bundleNames)
{
    APP_LOGD("AppProvisionInfoManager::GetAllAppProvisionInfoBundleName");
    return AppProvisionInfoManagerDb_->GetAllAppProvisionInfoBundleName(bundleNames);
}

bool AppProvisionInfoManager::SetSpecifiedDistributionType(
    const std::string &bundleName, const std::string &specifiedDistributionType)
{
    return AppProvisionInfoManagerDb_->SetSpecifiedDistributionType(bundleName, specifiedDistributionType);
}

bool AppProvisionInfoManager::GetSpecifiedDistributionType(
    const std::string &bundleName, std::string &specifiedDistributionType)
{
    return AppProvisionInfoManagerDb_->GetSpecifiedDistributionType(bundleName, specifiedDistributionType);
}

bool AppProvisionInfoManager::SetAdditionalInfo(
    const std::string &bundleName, const std::string &additionalInfo)
{
    return AppProvisionInfoManagerDb_->SetAdditionalInfo(bundleName, additionalInfo);
}

bool AppProvisionInfoManager::GetAdditionalInfo(
    const std::string &bundleName, std::string &additionalInfo)
{
    return AppProvisionInfoManagerDb_->GetAdditionalInfo(bundleName, additionalInfo);
}
} // AppExecFwk
} // OHOS
