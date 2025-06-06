/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_APP_CONTROL_HOST_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_APP_CONTROL_HOST_H


#include "app_control_interface.h"
#include "iremote_stub.h"
#include "nocopyable.h"

namespace OHOS {
namespace AppExecFwk {
class AppControlHost : public IRemoteStub<IAppControlMgr> {
public:
    AppControlHost();
    virtual ~AppControlHost();

    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    template<typename T>
    ErrCode ReadParcelableVector(MessageParcel &data, std::vector<T> &parcelableInfos);
    bool WriteStringVector(const std::vector<std::string> &stringVector, MessageParcel &reply);
    template<typename T>
    bool WriteParcelableVector(std::vector<T> &parcelableVector, MessageParcel &reply);
    ErrCode HandleAddAppInstallControlRule(MessageParcel& data, MessageParcel& reply);
    ErrCode HandleDeleteAppInstallControlRule(MessageParcel& data, MessageParcel& reply);
    ErrCode HandleCleanAppInstallControlRule(MessageParcel& data, MessageParcel& reply);
    ErrCode HandleGetAppInstallControlRule(MessageParcel& data, MessageParcel& reply);

    ErrCode HandleAddAppRunningControlRule(MessageParcel& data, MessageParcel& reply);
    ErrCode HandleDeleteAppRunningControlRule(MessageParcel& data, MessageParcel& reply);
    ErrCode HandleCleanAppRunningControlRule(MessageParcel& data, MessageParcel& reply);
    ErrCode HandleGetAppRunningControlRule(MessageParcel& data, MessageParcel& reply);
    ErrCode HandleGetAppRunningControlRuleResult(MessageParcel& data, MessageParcel& reply);

    ErrCode HandleConfirmAppJumpControlRule(MessageParcel& data, MessageParcel& reply);
    ErrCode HandleAddAppJumpControlRule(MessageParcel& data, MessageParcel& reply);
    ErrCode HandleDeleteAppJumpControlRule(MessageParcel& data, MessageParcel& reply);
    ErrCode HandleDeleteRuleByCallerBundleName(MessageParcel& data, MessageParcel& reply);
    ErrCode HandleDeleteRuleByTargetBundleName(MessageParcel& data, MessageParcel& reply);
    ErrCode HandleGetAppJumpControlRule(MessageParcel& data, MessageParcel& reply);

    ErrCode HandleGetDisposedStatus(MessageParcel& data, MessageParcel& reply);
    ErrCode HandleSetDisposedStatus(MessageParcel& data, MessageParcel& reply);
    ErrCode HandleDeleteDisposedStatus(MessageParcel& data, MessageParcel& reply);
    ErrCode HandleGetDisposedRule(MessageParcel& data, MessageParcel& reply);
    ErrCode HandleSetDisposedRule(MessageParcel& data, MessageParcel& reply);
    ErrCode HandleSetDisposedRules(MessageParcel& data, MessageParcel& reply);
    ErrCode HandleGetAbilityRunningControlRule(MessageParcel& data, MessageParcel& reply);
    ErrCode HandleGetDisposedRuleForCloneApp(MessageParcel& data, MessageParcel& reply);
    ErrCode HandleSetDisposedRuleForCloneApp(MessageParcel& data, MessageParcel& reply);
    ErrCode HandleDeleteDisposedRuleForCloneApp(MessageParcel& data, MessageParcel& reply);

    ErrCode HandleGetUninstallDisposedRule(MessageParcel& data, MessageParcel& reply);
    ErrCode HandleSetUninstallDisposedRule(MessageParcel& data, MessageParcel& reply);
    ErrCode HandleDeleteUninstallDisposedRule(MessageParcel& data, MessageParcel& reply);

    DISALLOW_COPY_AND_MOVE(AppControlHost);
    template<typename T>
    ErrCode GetVectorParcelInfo(MessageParcel &data, std::vector<T> &parcelInfos);
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_APP_CONTROL_HOST_H
