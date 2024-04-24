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

#include "app_log_tag_wrapper.h"
#include "bms_extension_client.h"
#include "bundle_mgr_service.h"

namespace OHOS {
namespace AppExecFwk {
BmsExtensionClient::BmsExtensionClient()
{
    APP_LOGD("create");
    bmsExtensionImpl_ = std::make_shared<BmsExtensionDataMgr>();
}

ErrCode BmsExtensionClient::QueryLauncherAbility(const Want &want, int32_t userId,
    std::vector<AbilityInfo> &abilityInfos) const
{
    LOG_D(BMS_TAG_QUERY_ABILITY, "start to query launcher abilities from bms extension");
    auto dataMgr = GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_W(BMS_TAG_QUERY_ABILITY, "dataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    if (userId != Constants::ALL_USERID) {
        int32_t requestUserId = dataMgr->GetUserId(userId);
        if (requestUserId == Constants::INVALID_USERID) {
            return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
        }
    }

    std::string bundleName = want.GetElement().GetBundleName();
    InnerBundleInfo info;
    if (!bundleName.empty() && dataMgr->QueryInnerBundleInfo(bundleName, info)) {
        LOG_D(BMS_TAG_QUERY_ABILITY, "bundle %{public}s has been existed and does not need to find in bms extension",
            bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    if (bmsExtensionImpl_ == nullptr) {
        LOG_W(BMS_TAG_QUERY_ABILITY, "bmsExtensionImpl_ is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    ErrCode res = bmsExtensionImpl_->QueryAbilityInfos(want, userId, abilityInfos);
    if (res != ERR_OK) {
        LOG_D(BMS_TAG_QUERY_ABILITY, "query ability infos failed due to error code %{public}d", res);
        return res;
    }
    for_each(abilityInfos.begin(), abilityInfos.end(), [this](auto &info) {
        // if labelId and label of abilityInfo is 0 or empty, replacing them by utilizing the corresponding
        // elements of applicationInfo
        ModifyLauncherAbilityInfo(info);
    });
    return ERR_OK;
}

ErrCode BmsExtensionClient::QueryAbilityInfos(const Want &want, int32_t flags, int32_t userId,
    std::vector<AbilityInfo> &abilityInfos, bool isNewVersion) const
{
    LOG_D(BMS_TAG_QUERY_ABILITY, "start to query abilityInfos from bms extension");
    auto dataMgr = GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_W(BMS_TAG_QUERY_ABILITY, "dataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    if (userId != Constants::ALL_USERID) {
        int32_t requestUserId = dataMgr->GetUserId(userId);
        if (requestUserId == Constants::INVALID_USERID) {
            return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
        }
    }

    std::string bundleName = want.GetElement().GetBundleName();
    InnerBundleInfo info;
    if (!bundleName.empty() && dataMgr->QueryInnerBundleInfo(bundleName, info)) {
        LOG_D(BMS_TAG_QUERY_ABILITY, "bundle %{public}s has been existed and does not need to find in bms extension",
            bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    if (bmsExtensionImpl_ == nullptr) {
        LOG_W(BMS_TAG_QUERY_ABILITY, "bmsExtensionImpl_ is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    ErrCode res = bmsExtensionImpl_->QueryAbilityInfosWithFlag(want, flags, userId, abilityInfos, isNewVersion);
    if (res != ERR_OK) {
        LOG_D(BMS_TAG_QUERY_ABILITY, "query ability infos failed due to error code %{public}d", res);
        return res;
    }
    if (abilityInfos.empty()) {
        LOG_D(BMS_TAG_QUERY_ABILITY, "no ability info can be found from bms extension");
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }
    return ERR_OK;
}

ErrCode BmsExtensionClient::BatchQueryAbilityInfos(const std::vector<Want> &wants, int32_t flags, int32_t userId,
    std::vector<AbilityInfo> &abilityInfos, bool isNewVersion) const
{
    APP_LOGD("start to query abilityInfos from bms extension");
    auto dataMgr = GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGW("dataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    if (userId != Constants::ALL_USERID) {
        int32_t requestUserId = dataMgr->GetUserId(userId);
        if (requestUserId == Constants::INVALID_USERID) {
            return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
        }
    }

    for (int i = 0; i < wants.size(); i++) {
        std::vector<AbilityInfo> tmpAbilityInfos;
        std::string bundleName = wants[i].GetElement().GetBundleName();
        InnerBundleInfo info;
        if (!bundleName.empty() && dataMgr->QueryInnerBundleInfo(bundleName, info)) {
            APP_LOGD("bundle %{public}s has been existed and does not need to find in bms extension",
                bundleName.c_str());
            return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
        }

        if (bmsExtensionImpl_ == nullptr) {
            APP_LOGW("bmsExtensionImpl_ is nullptr");
            return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
        }
        ErrCode res = bmsExtensionImpl_->QueryAbilityInfosWithFlag(wants[i], flags, userId, tmpAbilityInfos,
            isNewVersion);
        if (res != ERR_OK) {
            APP_LOGD("query ability infos failed due to error code %{public}d", res);
            return res;
        }
        abilityInfos.insert(abilityInfos.end(), tmpAbilityInfos.begin(), tmpAbilityInfos.end());
    }

    if (abilityInfos.empty()) {
        APP_LOGD("no ability info can be found from bms extension");
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }
    return ERR_OK;
}

ErrCode BmsExtensionClient::QueryAbilityInfo(const Want &want, int32_t flags, int32_t userId,
    AbilityInfo &abilityInfo, bool isNewVersion) const
{
    LOG_D(BMS_TAG_QUERY_ABILITY, "start to query abilityInfo from bms extension");
    std::vector<AbilityInfo> abilityInfos;
    ErrCode res = QueryAbilityInfos(want, flags, userId, abilityInfos, isNewVersion);
    if (res != ERR_OK) {
        LOG_D(BMS_TAG_QUERY_ABILITY, "query ability info failed due to error code %{public}d", res);
        return res;
    }
    if (abilityInfos.empty()) {
        LOG_D(BMS_TAG_QUERY_ABILITY, "no ability info can be found from bms extension");
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }

    abilityInfo = abilityInfos[0];
    return ERR_OK;
}

ErrCode BmsExtensionClient::GetBundleInfos(
    int32_t flags, std::vector<BundleInfo> &bundleInfos, int32_t userId, bool isNewVersion) const
{
    LOG_D(BMS_TAG_QUERY_BUNDLE, "start to query bundle infos from bms extension");
    if (userId != Constants::ALL_USERID) {
        auto dataMgr = GetDataMgr();
        if (dataMgr == nullptr) {
            LOG_W(BMS_TAG_QUERY_BUNDLE, "dataMgr is nullptr");
            return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
        }
        int32_t requestUserId = dataMgr->GetUserId(userId);
        if (requestUserId == Constants::INVALID_USERID) {
            return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
        }
    }
    if (bmsExtensionImpl_ == nullptr) {
        LOG_W(BMS_TAG_QUERY_BUNDLE, "bmsExtensionImpl_ is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    ErrCode res = bmsExtensionImpl_->GetBundleInfos(flags, bundleInfos, userId, isNewVersion);
    if (res != ERR_OK) {
        LOG_D(BMS_TAG_QUERY_BUNDLE, "query bundle infos failed due to error code %{public}d", res);
        return res;
    }

    return ERR_OK;
}

ErrCode BmsExtensionClient::GetBundleInfo(const std::string &bundleName, int32_t flags,
    BundleInfo &bundleInfo, int32_t userId, bool isNewVersion) const
{
    LOG_D(BMS_TAG_QUERY_BUNDLE, "start to query bundle info from bms extension");
    auto dataMgr = GetDataMgr();
    if (dataMgr == nullptr) {
        LOG_W(BMS_TAG_QUERY_BUNDLE, "dataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    if (userId != Constants::ALL_USERID) {
        int32_t requestUserId = dataMgr->GetUserId(userId);
        if (requestUserId == Constants::INVALID_USERID) {
            return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
        }
    }
    InnerBundleInfo info;
    if (dataMgr->QueryInnerBundleInfo(bundleName, info)) {
        LOG_D(BMS_TAG_QUERY_BUNDLE, "bundle %{public}s has been existed and does not need to find in bms extension",
            bundleName.c_str());
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    if (bmsExtensionImpl_ == nullptr) {
        LOG_W(BMS_TAG_QUERY_BUNDLE, "bmsExtensionImpl_ is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    ErrCode res = bmsExtensionImpl_->GetBundleInfo(bundleName, flags, userId, bundleInfo, isNewVersion);
    if (res != ERR_OK) {
        LOG_D(BMS_TAG_QUERY_BUNDLE, "query bundle info failed due to error code %{public}d", res);
        return res;
    }

    return ERR_OK;
}

ErrCode BmsExtensionClient::BatchGetBundleInfo(const std::vector<std::string> &bundleNames, int32_t flags,
    std::vector<BundleInfo> &bundleInfos, int32_t userId, bool isNewVersion) const
{
    APP_LOGD("start to batch query bundle info from bms extension");
    auto dataMgr = GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGW("dataMgr is nullptr");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    if (userId != Constants::ALL_USERID) {
        int32_t requestUserId = dataMgr->GetUserId(userId);
        if (requestUserId == Constants::INVALID_USERID) {
            return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
        }
    }
    for (size_t i = 0; i < bundleNames.size(); i++) {
        InnerBundleInfo innerBundleInfo;
        BundleInfo bundleInfo;
        if (dataMgr->QueryInnerBundleInfo(bundleNames[i], innerBundleInfo)) {
            APP_LOGD("bundle %{public}s has been existed and does not need to find in bms extension",
                bundleNames[i].c_str());
            return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
        }
        if (bmsExtensionImpl_ == nullptr) {
            APP_LOGW("bmsExtensionImpl_ is nullptr");
            return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
        }
        ErrCode res = bmsExtensionImpl_->GetBundleInfo(bundleNames[i], flags, userId, bundleInfo, isNewVersion);
        if (res != ERR_OK) {
            APP_LOGD("query bundle info failed due to error code %{public}d", res);
            return res;
        }
        bundleInfos.push_back(bundleInfo);
    }

    return ERR_OK;
}

ErrCode BmsExtensionClient::ImplicitQueryAbilityInfos(
    const Want &want, int32_t flags, int32_t userId, std::vector<AbilityInfo> &abilityInfos, bool isNewVersion) const
{
    LOG_D(BMS_TAG_QUERY_ABILITY, "start to implicitly query ability info from bms extension");
    if (userId != Constants::ALL_USERID) {
        auto dataMgr = GetDataMgr();
        if (dataMgr == nullptr) {
            LOG_W(BMS_TAG_QUERY_ABILITY, "dataMgr is nullptr");
            return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
        }
        int32_t requestUserId = dataMgr->GetUserId(userId);
        if (requestUserId == Constants::INVALID_USERID) {
            return ERR_BUNDLE_MANAGER_INVALID_USER_ID;
        }
    }

    ElementName element = want.GetElement();
    std::string bundleName = element.GetBundleName();
    std::string abilityName = element.GetAbilityName();
    // does not support explicit query
    if (!bundleName.empty() && !abilityName.empty()) {
        LOG_W(BMS_TAG_QUERY_ABILITY, "implicit query failed bundleName:%{public}s, abilityName:%{public}s not empty",
            bundleName.c_str(), abilityName.c_str());
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    ErrCode res = QueryAbilityInfos(want, flags, userId, abilityInfos, isNewVersion);
    if (res != ERR_OK) {
        LOG_E(BMS_TAG_QUERY_ABILITY, "query ability info failed error code %{public}d", res);
        return res;
    }
    if (abilityInfos.empty()) {
        LOG_E(BMS_TAG_QUERY_ABILITY, "no ability info can be found from bms extension");
        return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST;
    }

    return ERR_OK;
}

ErrCode BmsExtensionClient::GetBundleStats(
    const std::string &bundleName, int32_t userId, std::vector<int64_t> &bundleStats)
{
    if (bmsExtensionImpl_ == nullptr) {
        APP_LOGW("bmsExtensionImpl_ is null");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return bmsExtensionImpl_->GetBundleStats(bundleName, userId, bundleStats);
}
ErrCode BmsExtensionClient::ClearData(const std::string &bundleName, int32_t userId)
{
    if (bmsExtensionImpl_ == nullptr) {
        APP_LOGW("bmsExtensionImpl_ is null");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return bmsExtensionImpl_->ClearData(bundleName, userId);
}
ErrCode BmsExtensionClient::ClearCache(const std::string &bundleName, sptr<IRemoteObject> callback, int32_t userId)
{
    if (bmsExtensionImpl_ == nullptr) {
        APP_LOGW("bmsExtensionImpl_ is null");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return bmsExtensionImpl_->ClearCache(bundleName, callback, userId);
}
ErrCode BmsExtensionClient::GetUidByBundleName(const std::string &bundleName, int32_t userId, int32_t &uid)
{
    if (bmsExtensionImpl_ == nullptr) {
        APP_LOGW("bmsExtensionImpl_ is null");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return bmsExtensionImpl_->GetUidByBundleName(bundleName, userId, uid);
}
ErrCode BmsExtensionClient::GetBundleNameByUid(int32_t uid, std::string &bundleName)
{
    if (bmsExtensionImpl_ == nullptr) {
        APP_LOGW("bmsExtensionImpl_ is null");
        return ERR_BUNDLE_MANAGER_INTERNAL_ERROR;
    }
    return bmsExtensionImpl_->GetBundleNameByUid(uid, bundleName);
}

void BmsExtensionClient::ModifyLauncherAbilityInfo(AbilityInfo &abilityInfo) const
{
    if (abilityInfo.labelId == 0) {
        abilityInfo.labelId = abilityInfo.applicationInfo.labelId;
    }

    if (abilityInfo.label.empty()) {
        abilityInfo.label = abilityInfo.applicationInfo.label;
    }

    if (abilityInfo.iconId == 0) {
        abilityInfo.iconId = abilityInfo.applicationInfo.iconId;
    }
}

const std::shared_ptr<BundleDataMgr> BmsExtensionClient::GetDataMgr() const
{
    return DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
}
} // AppExecFwk
} // OHOS