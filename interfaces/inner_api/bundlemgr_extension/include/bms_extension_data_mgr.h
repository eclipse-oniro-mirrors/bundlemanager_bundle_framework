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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BMS_EXTENSION_DATA_MGR_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BMS_EXTENSION_DATA_MGR_H
#include <mutex>
#include <string>

#include "ability_info.h"
#include "appexecfwk_errors.h"
#include "bms_extension.h"
#include "bundle_info.h"
#include "interfaces/hap_verify.h"
#include "want.h"
#include "abs_rdb_predicates.h"

namespace OHOS {
namespace AppExecFwk {
class BmsExtensionDataMgr {
public:
    using Want = OHOS::AAFwk::Want;

    BmsExtensionDataMgr();
    ErrCode Init();
    bool CheckApiInfo(const BundleInfo &bundleInfo, uint32_t sdkVersion);
    bool CheckApiInfo(uint32_t compatibleVersion, uint32_t sdkVersion);
    ErrCode HapVerify(const std::string &filePath, Security::Verify::HapVerifyResult &hapVerifyResult);
    ErrCode QueryAbilityInfos(const Want &want, int32_t userId, std::vector<AbilityInfo> &abilityInfos);
    ErrCode QueryAbilityInfosWithFlag(const Want &want, int32_t flags, int32_t userId,
        std::vector<AbilityInfo> &abilityInfos, bool isNewVersion = false);
    ErrCode GetBundleInfos(int32_t flags, std::vector<BundleInfo> &bundleInfos, int32_t userId,
        bool isNewVersion = false);
    ErrCode GetBundleInfo(const std::string &bundleName, int32_t flags, int32_t userId,
        BundleInfo &bundleInfo, bool isNewVersion = false);
    ErrCode Uninstall(const std::string &bundleName);
    ErrCode GetBundleStats(const std::string &bundleName, int32_t userId, std::vector<int64_t> &bundleStats);
    ErrCode ClearData(const std::string &bundleName, int32_t userId);
    ErrCode ClearCache(const std::string &bundleName, sptr<IRemoteObject> callback, int32_t userId);
    ErrCode GetUidByBundleName(const std::string &bundleName, int32_t userId, int32_t &uid);
    ErrCode GetBundleNameByUid(int32_t uid, std::string &bundleName);
    ErrCode VerifyActivationLock(bool &res);
    ErrCode GetBackupUninstallList(int32_t userId, std::set<std::string> &uninstallBundles);
    ErrCode ClearBackupUninstallFile(int32_t userId);
    ErrCode AddResourceInfoByBundleName(const std::string &bundleName, const int32_t userId);
    ErrCode AddResourceInfoByAbility(const std::string &bundleName, const std::string &moduleName,
        const std::string &abilityName, const int32_t userId);
    ErrCode DeleteResourceInfo(const std::string &key);
    ErrCode OptimizeDisposedPredicates(const std::string &callingName, const std::string &appId,
        int32_t userId, int32_t appIndex, NativeRdb::AbsRdbPredicates &absRdbPredicates);
    bool IsAppInBlocklist(const std::string &bundleName, const int32_t userId);
    bool CheckWhetherCanBeUninstalled(const std::string &bundleName);
    
    bool DetermineCloneNum(const std::string &bundleName, const std::string &appIdentifier, int32_t &cloneNum);
private:
    bool OpenHandler();
    static BmsExtension bmsExtension_;
    static void *handler_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BMS_EXTENSION_DATA_MGR_H