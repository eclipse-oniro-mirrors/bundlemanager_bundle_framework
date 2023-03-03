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

#include "app_log_wrapper.h"
#include "bundle_info_resolve_util.h"
#include "iservice_registry.h"
#include "service_router_data_mgr.h"
#include "sr_constants.h"
#include "sr_samgr_helper.h"
#include "system_ability_definition.h"
#include "uri.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
    const std::string SCHEME_SEPARATOR = "://";
    const std::string SCHEME_SERVICE_ROUTER = "servicerouter";
}

bool ServiceRouterDataMgr::LoadAllBundleInfos()
{
    APP_LOGD("SRDM LoadAllBundleInfos");
    auto bms = SrSamgrHelper::GetInstance().GetBundleMgr();
    if (bms == nullptr) {
        APP_LOGE("SRDM GetBundleMgr return null");
        return false;
    }
    auto flags = (BundleFlag::GET_BUNDLE_WITH_ABILITIES | BundleFlag::GET_BUNDLE_WITH_EXTENSION_INFO);
    std::vector<BundleInfo> bundleInfos;
    bool ret = bms->GetBundleInfos(flags, bundleInfos, SrSamgrHelper::GetCurrentActiveUserId());
    if (!ret) {
        APP_LOGE("SRDM bms->GetBundleInfos return false");
    }
    for (const auto &bundleInfo : bundleInfos) {
        UpdateBundleInfo(bundleInfo);
    }
    return ret;
}

bool ServiceRouterDataMgr::LoadBundleInfo(const std::string &bundleName)
{
    APP_LOGD("SRDM LoadBundleInfo");
    auto bms = SrSamgrHelper::GetInstance().GetBundleMgr();
    if (bms == nullptr) {
        APP_LOGI("SRDM GetBundleMgr return null");
        return false;
    }
    BundleInfo bundleInfo;
    auto flags = (BundleFlag::GET_BUNDLE_WITH_ABILITIES | BundleFlag::GET_BUNDLE_WITH_EXTENSION_INFO);
    bool ret = bms->GetBundleInfo(bundleName, flags, bundleInfo, SrSamgrHelper::GetCurrentActiveUserId());
    if (!ret) {
        APP_LOGE("SRDM bms->GetBundleInfos return false");
    }
    UpdateBundleInfo(bundleInfo);
    return ret;
}

void ServiceRouterDataMgr::UpdateBundleInfo(const BundleInfo &bundleInfo)
{
    APP_LOGD("SRDM UpdateBundleInfo");
    InnerServiceInfo innerServiceInfo;
    auto infoItem = innerServiceInfos_.find(bundleInfo.name);
    if (infoItem != innerServiceInfos_.end()) {
        innerServiceInfo = infoItem->second;
    }
    innerServiceInfo.UpdateAppInfo(bundleInfo.applicationInfo);

    std::vector<PurposeInfo> purposeInfos;
    std::vector<ServiceInfo> serviceInfos;
    if (BundleInfoResolveUtil::ResolveBundleInfo(bundleInfo, purposeInfos, serviceInfos,
        innerServiceInfo.GetAppInfo())) {
        std::lock_guard<std::mutex> lock(bundleInfoMutex_);
        innerServiceInfo.UpdateInnerServiceInfo(purposeInfos, serviceInfos);
        innerServiceInfos_.try_emplace(bundleInfo.name, innerServiceInfo);
    }
}

void ServiceRouterDataMgr::DeleteBundleInfo(const std::string &bundleName)
{
    APP_LOGD("SRDM DeleteBundleInfo");
    std::lock_guard<std::mutex> lock(bundleInfoMutex_);
    auto infoItem = innerServiceInfos_.find(bundleName);
    if (infoItem == innerServiceInfos_.end()) {
        APP_LOGE("SRDM inner service info not found by bundleName");
        return;
    }
    innerServiceInfos_.erase(bundleName);
}

int32_t ServiceRouterDataMgr::QueryServiceInfos(const Want &want, const ExtensionServiceType &serviceType,
    std::vector<ServiceInfo> &serviceInfos) const
{
    APP_LOGD("SRDM QueryServiceInfos");
    ExtensionServiceType validType = GetExtensionServiceType(want, serviceType);
    if (validType != ExtensionServiceType::SHARE) {
        APP_LOGE("SRDM QueryServiceInfos, serviceType is empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    ElementName element = want.GetElement();
    std::string bundleName = element.GetBundleName();
    if (bundleName.empty()) {
        for (const auto &item : innerServiceInfos_) {
            item.second.FindServiceInfos(validType, serviceInfos);
        }
    } else {
        auto infoItem = innerServiceInfos_.find(bundleName);
        if (infoItem == innerServiceInfos_.end()) {
            APP_LOGE("SRDM QueryServiceInfos, not found by bundleName.");
            return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
        }
        infoItem->second.FindServiceInfos(validType, serviceInfos);
    }
    return ERR_OK;
}

int32_t ServiceRouterDataMgr::QueryPurposeInfos(const Want &want, const std::string purposeName,
    std::vector<PurposeInfo> &purposeInfos) const
{
    APP_LOGD("SRDM QueryPurposeInfos");
    if (purposeName.empty()) {
        APP_LOGE("SRDM QueryPurposeInfos, purposeName is empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }

    ElementName element = want.GetElement();
    std::string bundleName = element.GetBundleName();
    if (bundleName.empty()) {
        for (const auto &item : innerServiceInfos_) {
            item.second.FindPurposeInfos(purposeName, purposeInfos);
        }
    } else {
        auto infoItem = innerServiceInfos_.find(bundleName);
        if (infoItem == innerServiceInfos_.end()) {
            APP_LOGE("SRDM QueryPurposeInfos, not found by bundleName.");
            return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
        }
        infoItem->second.FindPurposeInfos(purposeName, purposeInfos);
    }
    return ERR_OK;
}

ExtensionServiceType ServiceRouterDataMgr::GetExtensionServiceType(const Want &want,
    const ExtensionServiceType &serviceType) const
{
    if (serviceType == ExtensionServiceType::SHARE) {
        return serviceType;
    }
    Uri uri = want.GetUri();
    if (uri.GetScheme().empty() || uri.GetHost().empty() || uri.GetScheme() != SCHEME_SERVICE_ROUTER) {
        APP_LOGE("GetExtensionServiceType, invalid uri: %{public}s", want.GetUriString().c_str());
        return ExtensionServiceType::UNSPECIFIED;
    }
    return BundleInfoResolveUtil::findExtensionServiceType(uri.GetHost());
}
}  // namespace AppExecFwk
}  // namespace OHOS
