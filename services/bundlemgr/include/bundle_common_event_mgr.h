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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_COMMON_EVENT_MGR_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_COMMON_EVENT_MGR_H

#include <functional>
#include <unordered_map>

#include "appexecfwk_errors.h"
#include "bundle_data_mgr.h"
#include "disposed_rule.h"
#include "inner_bundle_info.h"

namespace OHOS {
namespace AppExecFwk {
enum class NotifyType : uint8_t {
    INSTALL = 1,
    UPDATE,
    UNINSTALL_BUNDLE,
    UNINSTALL_MODULE,
    ABILITY_ENABLE,
    APPLICATION_ENABLE,
    BUNDLE_DATA_CLEARED,
    BUNDLE_CACHE_CLEARED,
    OVERLAY_INSTALL,
    OVERLAY_UPDATE,
    OVERLAY_STATE_CHANGED,
    DISPOSED_RULE_ADDED,
    DISPOSED_RULE_DELETED,
    START_INSTALL,
    UNINSTALL_STATE,
};

enum class SandboxInstallType : uint8_t {
    INSTALL = 0,
    UNINSTALL,
};

struct NotifyBundleEvents {
    bool isAgingUninstall = false;
    bool isBmsExtensionUninstalled = false;
    bool isModuleUpdate = false;
    NotifyType type = NotifyType::INSTALL;
    ErrCode resultCode = ERR_OK;
    uint32_t accessTokenId = 0;
    int32_t uid = 0;
    int32_t bundleType = 0;
    int32_t atomicServiceModuleUpgrade = 0;
    int32_t appIndex = 0;
    std::string bundleName = "";
    std::string modulePackage = "";
    std::string abilityName = "";
    std::string appId;
    std::string appIdentifier;
    std::string appDistributionType;
    std::string developerId;
    std::string assetAccessGroups;
    bool keepData = false;
};

class BundleCommonEventMgr {
public:
    BundleCommonEventMgr();
    virtual ~BundleCommonEventMgr() = default;
    void NotifyBundleStatus(const NotifyBundleEvents &installResult,
        const std::shared_ptr<BundleDataMgr> &dataMgr);
    ErrCode NotifySandboxAppStatus(const InnerBundleInfo &info, int32_t uid, int32_t userId,
        const SandboxInstallType &type);
    void NotifyOverlayModuleStateStatus(const std::string &bundleName, const std::string &moduleName, bool isEnabled,
        int32_t userId, int32_t uid);
    void NotifySetDiposedRule(const std::string &appId, int32_t userId, const std::string &data, int32_t appIndex);
    void NotifyDeleteDiposedRule(const std::string &appId, int32_t userId, int32_t appIndex);
    void NotifyDynamicIconEvent(
        const std::string &bundleName, bool isEnableDynamicIcon, int32_t userId, int32_t appIndex);
    void NotifyBundleResourcesChanged(const int32_t userId, const uint32_t type);
    void NotifyDefaultAppChanged(const int32_t userId, std::vector<std::string> &utdIdVec);
    void NotifyPluginEvents(const NotifyBundleEvents &event, const std::shared_ptr<BundleDataMgr> &dataMgr);
private:
    std::string GetCommonEventData(const NotifyType &type);
    void SetNotifyWant(OHOS::AAFwk::Want& want, const NotifyBundleEvents &installResult);
    void Init();

    std::unordered_map<NotifyType, std::string> commonEventMap_;
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_COMMON_EVENT_MGR_H