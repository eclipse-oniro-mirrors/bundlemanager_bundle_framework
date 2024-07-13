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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_EXT_INCLUDE_BUNDLE_MGR_EX_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_EXT_INCLUDE_BUNDLE_MGR_EX_H

#include "appexecfwk_errors.h"
#include "ability_info.h"
#include "bundle_info.h"
#include "interfaces/hap_verify.h"
#include "want.h"

namespace OHOS {
namespace AppExecFwk {
class BundleMgrExt {
public:
    using Want = OHOS::AAFwk::Want;

    virtual ~BundleMgrExt() = default;

    virtual bool CheckApiInfo(const BundleInfo& bundleInfo) = 0;
    virtual ErrCode HapVerify(const std::string &filePath, Security::Verify::HapVerifyResult &hapVerifyResult)
    {
        return ERR_BUNDLEMANAGER_INSTALL_FAILED_SIGNATURE_EXTENSION_NOT_EXISTED;
    }
    virtual ErrCode QueryAbilityInfos(const Want &want, int32_t userId,
        std::vector<AbilityInfo> &abilityInfos)
    {
        return ERR_BUNDLE_MANAGER_INSTALL_FAILED_BUNDLE_EXTENSION_NOT_EXISTED;
    }
    virtual ErrCode QueryAbilityInfosWithFlag(const Want &want, int32_t flags, int32_t userId,
        std::vector<AbilityInfo> &abilityInfos, bool isNewVersion = false)
    {
        return ERR_BUNDLE_MANAGER_INSTALL_FAILED_BUNDLE_EXTENSION_NOT_EXISTED;
    }
    virtual ErrCode GetBundleInfo(const std::string &bundleName, int32_t flags, int32_t userId,
        BundleInfo &bundleInfo, bool isNewVersion = false)
    {
        return ERR_BUNDLE_MANAGER_INSTALL_FAILED_BUNDLE_EXTENSION_NOT_EXISTED;
    }
    virtual ErrCode GetBundleInfos(int32_t flags, std::vector<BundleInfo> &bundleInfos, int32_t userId,
        bool isNewVersion = false)
    {
        return ERR_BUNDLE_MANAGER_INSTALL_FAILED_BUNDLE_EXTENSION_NOT_EXISTED;
    }
    virtual ErrCode Uninstall(const std::string &bundleName)
    {
        return ERR_BUNDLE_MANAGER_INSTALL_FAILED_BUNDLE_EXTENSION_NOT_EXISTED;
    }
    virtual ErrCode GetBundleStats(const std::string &bundleName, int32_t userId, std::vector<int64_t> &bundleStats)
    {
        return ERR_BUNDLE_MANAGER_EXTENSION_DEFAULT_ERR;
    }
    virtual ErrCode ClearData(const std::string &bundleName, int32_t userId)
    {
        return ERR_BUNDLE_MANAGER_EXTENSION_DEFAULT_ERR;
    }
    virtual ErrCode ClearCache(const std::string &bundleName, sptr<IRemoteObject> callback, int32_t userId)
    {
        return ERR_BUNDLE_MANAGER_EXTENSION_DEFAULT_ERR;
    }
    virtual ErrCode GetUidByBundleName(const std::string &bundleName, int32_t userId, int32_t &uid)
    {
        return ERR_BUNDLE_MANAGER_EXTENSION_DEFAULT_ERR;
    }
    virtual ErrCode GetBundleNameByUid(int32_t uid, std::string &bundleName)
    {
        return ERR_BUNDLE_MANAGER_EXTENSION_DEFAULT_ERR;
    }
    virtual ErrCode VerifyActivationLock(bool &res)
    {
        return ERR_BUNDLE_MANAGER_EXTENSION_DEFAULT_ERR;
    }
    virtual ErrCode GetBackupUninstallList(int32_t userId, std::set<std::string> &uninstallBundles)
    {
        return ERR_BUNDLE_MANAGER_EXTENSION_DEFAULT_ERR;
    }
    virtual ErrCode ClearBackupUninstallFile(int32_t userId)
    {
        return ERR_BUNDLE_MANAGER_EXTENSION_DEFAULT_ERR;
    }
    virtual ErrCode AddResourceInfoByBundleName(const std::string &bundleName, const int32_t userId)
    {
        return ERR_BUNDLE_MANAGER_EXTENSION_DEFAULT_ERR;
    }
    virtual ErrCode AddResourceInfoByAbility(const std::string &bundleName, const std::string &moduleName,
        const std::string &abilityName, const int32_t userId)
    {
        return ERR_BUNDLE_MANAGER_EXTENSION_DEFAULT_ERR;
    }
    virtual ErrCode DeleteResourceInfo(const std::string &key)
    {
        return ERR_BUNDLE_MANAGER_EXTENSION_DEFAULT_ERR;
    }
};

} // AppExecFwk
} // OHOS

#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_EXT_INCLUDE_BUNDLE_MGR_EX_H