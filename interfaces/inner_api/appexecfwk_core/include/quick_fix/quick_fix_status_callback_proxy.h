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

#ifndef FOUNDATION_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_INCLUDE_QUICK_FIX_STATUS_CALLBACK_PROXY_H
#define FOUNDATION_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_INCLUDE_QUICK_FIX_STATUS_CALLBACK_PROXY_H

#include "iremote_proxy.h"

#include "quick_fix_status_callback_interface.h"

namespace OHOS {
namespace AppExecFwk {
class QuickFixStatusCallbackProxy : public IRemoteProxy<IQuickFixStatusCallback> {
public:
    explicit QuickFixStatusCallbackProxy(const sptr<IRemoteObject> &object);
    virtual ~QuickFixStatusCallbackProxy() override;

private:
    static inline BrokerDelegator<QuickFixStatusCallbackProxy> delegator_;
};
}
} // OHOS
#endif // FOUNDATION_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_INCLUDE_QUICK_FIX_STATUS_CALLBACK_PROXY_H
