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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BMS_EXTENSION_CLIENT_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BMS_EXTENSION_CLIENT_H

#include "bms_extension_data_mgr.h"
#include "bundle_data_mgr.h"

namespace OHOS {
namespace AppExecFwk {
class BmsExtensionClient {
public:
    using Want = OHOS::AAFwk::Want;

    BmsExtensionClient();
    virtual ~BmsExtensionClient() = default;

    ErrCode QueryLauncherAbility(const Want &want, int32_t userId,
        std::vector<AbilityInfo> &abilityInfos) const;

    ErrCode QueryAbilityInfos(const Want &want, int32_t flags, int32_t userId,
        std::vector<AbilityInfo> &abilityInfos, bool isNewVersion = false) const;

    ErrCode BatchQueryAbilityInfos(const std::vector<Want> &wants, int32_t flags, int32_t userId,
        std::vector<AbilityInfo> &abilityInfos, bool isNewVersion = false) const;

    ErrCode QueryAbilityInfo(const Want &want, int32_t flags, int32_t userId,
        AbilityInfo &abilityInfo, bool isNewVersion = false) const;

    ErrCode GetBundleInfos(
        int32_t flags, std::vector<BundleInfo> &bundleInfos, int32_t userId, bool isNewVersion = false) const;

    ErrCode GetBundleInfo(const std::string &bundleName, int32_t flags,
        BundleInfo &bundleInfo, int32_t userId, bool isNewVersion = false) const;

    ErrCode BatchGetBundleInfo(const std::vector<std::string> &bundleNames, int32_t flags,
        std::vector<BundleInfo> &bundleInfo, int32_t userId, bool isNewVersion = false) const;

    ErrCode ImplicitQueryAbilityInfos(
        const Want &want, int32_t flags, int32_t userId, std::vector<AbilityInfo> &abilityInfos,
        bool isNewVersion) const;
    ErrCode GetBundleStats(const std::string &bundleName, int32_t userId, std::vector<int64_t> &bundleStats);
    ErrCode ClearData(const std::string &bundleName, int32_t userId);
    ErrCode ClearCache(const std::string &bundleName, sptr<IRemoteObject> callback, int32_t userId);
    ErrCode GetUidByBundleName(const std::string &bundleName, int32_t userId, int32_t &uid);
    ErrCode GetBundleNameByUid(int32_t uid, std::string &bundleName);
    ErrCode AddResourceInfoByBundleName(const std::string &bundleName, const int32_t userId);
    ErrCode AddResourceInfoByAbility(const std::string &bundleName, const std::string &moduleName,
        const std::string &abilityName, const int32_t userId);
    ErrCode DeleteResourceInfo(const std::string &key);
    ErrCode OptimizeDisposedPredicates(const std::string &callingName, const std::string &appId,
        int32_t userId, int32_t appIndex, NativeRdb::AbsRdbPredicates &absRdbPredicates);

private:
    void ModifyLauncherAbilityInfo(AbilityInfo &abilityInfo) const;
    const std::shared_ptr<BundleDataMgr> GetDataMgr() const;

    std::shared_ptr<BmsExtensionDataMgr> bmsExtensionImpl_;
};
} // AppExecFwk
} // OHOS

#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BMS_EXTENSION_CLIENT_H