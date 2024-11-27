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

#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_APP_CONTROL_PROXY_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_APP_CONTROL_PROXY_H

#include "app_control_interface.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace AppExecFwk {
class AppControlProxy : public IRemoteProxy<IAppControlMgr> {
public:
    explicit AppControlProxy(const sptr<IRemoteObject>& object);
    virtual ~AppControlProxy();
    // for app install control rule
    virtual ErrCode AddAppInstallControlRule(const std::vector<std::string> &appIds,
        const AppInstallControlRuleType controlRuleType, int32_t userId) override;
    virtual ErrCode DeleteAppInstallControlRule(const AppInstallControlRuleType controlRuleType,
        const std::vector<std::string> &appIds, int32_t userId) override;
    virtual ErrCode DeleteAppInstallControlRule(
        const AppInstallControlRuleType controlRuleType, int32_t userId) override;
    virtual ErrCode GetAppInstallControlRule(
        const AppInstallControlRuleType controlRuleType, int32_t userId, std::vector<std::string> &appIds) override;
    // for app running control rule
    virtual ErrCode AddAppRunningControlRule(
        const std::vector<AppRunningControlRule> &controlRule, int32_t userId) override;
    virtual ErrCode DeleteAppRunningControlRule(
        const std::vector<AppRunningControlRule> &controlRule, int32_t userId) override;
    virtual ErrCode DeleteAppRunningControlRule(int32_t userId) override;
    virtual ErrCode GetAppRunningControlRule(int32_t userId, std::vector<std::string> &appIds) override;
    virtual ErrCode GetAppRunningControlRule(
        const std::string &bundleName, int32_t userId, AppRunningControlRuleResult &controlRuleResult) override;

    // for app jump control rule
    virtual ErrCode ConfirmAppJumpControlRule(const std::string &callerBundleName, const std::string &targetBundleName,
        int32_t userId) override;
    virtual ErrCode AddAppJumpControlRule(const std::vector<AppJumpControlRule> &controlRules, int32_t userId) override;
    virtual ErrCode DeleteAppJumpControlRule(const std::vector<AppJumpControlRule> &controlRules,
        int32_t userId) override;
    virtual ErrCode DeleteRuleByCallerBundleName(const std::string &callerBundleName, int32_t userId) override;
    virtual ErrCode DeleteRuleByTargetBundleName(const std::string &targetBundleName, int32_t userId) override;
    virtual ErrCode GetAppJumpControlRule(const std::string &callerBundleName, const std::string &targetBundleName,
        int32_t userId, AppJumpControlRule &controlRule) override;

    virtual ErrCode SetDisposedStatus(
        const std::string &appId, const Want &want, int32_t userId = Constants::UNSPECIFIED_USERID) override;
    virtual ErrCode DeleteDisposedStatus(
        const std::string &appId, int32_t userId = Constants::UNSPECIFIED_USERID) override;
    virtual ErrCode GetDisposedStatus(const std::string &appId, Want &want,
        int32_t userId = Constants::UNSPECIFIED_USERID) override;
    virtual ErrCode GetDisposedRule(const std::string &appId,
        DisposedRule& disposedRule, int32_t userId = Constants::UNSPECIFIED_USERID) override;
    virtual ErrCode SetDisposedRule(const std::string &appId,
        DisposedRule& disposedRule, int32_t userId = Constants::UNSPECIFIED_USERID) override;
    virtual ErrCode GetAbilityRunningControlRule(const std::string &bundleName, int32_t userId,
        std::vector<DisposedRule>& disposedRules, int32_t appIndex = Constants::MAIN_APP_INDEX) override;
    virtual ErrCode GetDisposedRuleForCloneApp(const std::string &appId, DisposedRule& disposedRule,
        int32_t appIndex, int32_t userId = Constants::UNSPECIFIED_USERID) override;
    virtual ErrCode SetDisposedRuleForCloneApp(const std::string &appId, DisposedRule& disposedRule,
        int32_t appIndex, int32_t userId = Constants::UNSPECIFIED_USERID) override;
    virtual ErrCode DeleteDisposedRuleForCloneApp(const std::string &appId, int32_t appIndex,
        int32_t userId = Constants::UNSPECIFIED_USERID) override;
    
    virtual ErrCode SetUninstallDisposedRule(const std::string &appIdentifier,
        const UninstallDisposedRule &disposedRule, int32_t appIndex, int32_t userId) override;
    virtual ErrCode GetUninstallDisposedRule(const std::string &appIdentifier, int32_t appIndex,
        int32_t userId, UninstallDisposedRule &rule) override;
    virtual ErrCode DeleteUninstallDisposedRule(const std::string &appIdentifier,
        int32_t appIndex, int32_t userId) override;

private:
    bool WriteParcelableVector(const std::vector<std::string> &stringVector, MessageParcel &data);
    template <typename T>
    ErrCode GetParcelableInfo(AppControlManagerInterfaceCode code, MessageParcel& data, T& parcelableInfo);
    template<typename T>
    bool WriteParcelableVector(const std::vector<T> &parcelableVector, MessageParcel &data);
    bool WriteStringVector(const std::vector<std::string> &stringVector, MessageParcel &data);
    int32_t GetParcelableInfos(
        AppControlManagerInterfaceCode code, MessageParcel &data, std::vector<std::string> &stringVector);
    int32_t SendRequest(AppControlManagerInterfaceCode code, MessageParcel &data, MessageParcel &reply);
    template <typename T>
    ErrCode GetParcelableInfosWithErrCode(AppControlManagerInterfaceCode code, MessageParcel &data,
        std::vector<T> &parcelableInfos);
    static inline BrokerDelegator<AppControlProxy> delegator_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_APP_CONTROL_PROXY_H