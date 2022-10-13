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

    virtual ErrCode SetDisposedStatus(const std::string &appId, const Want &want) override;
    virtual ErrCode DeleteDisposedStatus(const std::string &appId) override;
    virtual ErrCode GetDisposedStatus(const std::string &appId, Want &want) override;

private:
    bool WriteParcelableVector(const std::vector<std::string> &stringVector, MessageParcel &data);
    template <typename T>
    ErrCode GetParcelableInfo(IAppControlMgr::Message code, MessageParcel& data, T& parcelableInfo);
    template<typename T>
    bool WriteParcelableVector(const std::vector<T> &parcelableVector, MessageParcel &data);
    bool WriteStringVector(const std::vector<std::string> &stringVector, MessageParcel &data);
    int32_t GetParcelableInfos(
        IAppControlMgr::Message code, MessageParcel &data, std::vector<std::string> &stringVector);
    int32_t SendRequest(IAppControlMgr::Message code, MessageParcel &data, MessageParcel &reply);
    static inline BrokerDelegator<AppControlProxy> delegator_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_APP_CONTROL_PROXY_H