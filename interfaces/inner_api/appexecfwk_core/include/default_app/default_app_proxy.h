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

#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_DEFAULT_APP_PROXY_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_DEFAULT_APP_PROXY_H

#include "default_app_interface.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace AppExecFwk {
class DefaultAppProxy : public IRemoteProxy<IDefaultApp> {
public:
    explicit DefaultAppProxy(const sptr<IRemoteObject>& object);
    virtual ~DefaultAppProxy();

    virtual ErrCode IsDefaultApplication(const std::string& type, bool& isDefaultApp) override;
    virtual ErrCode GetDefaultApplication(int32_t userId, const std::string& type, BundleInfo& bundleInfo) override;
    virtual ErrCode SetDefaultApplication(int32_t userId, const std::string& type, const Want& want) override;
    virtual ErrCode ResetDefaultApplication(int32_t userId, const std::string& type) override;

private:
    template <typename T>
    ErrCode GetParcelableInfo(IDefaultApp::Message code, MessageParcel& data, T& parcelableInfo);
    bool SendRequest(IDefaultApp::Message code, MessageParcel& data, MessageParcel& reply);
    static inline BrokerDelegator<DefaultAppProxy> delegator_;
};
}
}
#endif
