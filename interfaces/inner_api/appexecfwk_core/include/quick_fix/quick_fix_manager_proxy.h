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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_INCLUDE_QUICK_FIX_MANAGER_PROXY_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_INCLUDE_QUICK_FIX_MANAGER_PROXY_H

#include "quick_fix_manager_interface.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace AppExecFwk {
class QuickFixManagerProxy : public IRemoteProxy<IQuickFixManager> {
public:
    explicit QuickFixManagerProxy(const sptr<IRemoteObject> &object);
    virtual ~QuickFixManagerProxy();

    virtual ErrCode DeployQuickFix(const std::vector<std::string> &bundleFilePaths,
        const sptr<IQuickFixStatusCallback> &statusCallback) override;

    virtual ErrCode SwitchQuickFix(const std::string &bundleName, bool enable,
        const sptr<IQuickFixStatusCallback> &statusCallback) override;

    virtual ErrCode DeleteQuickFix(const std::string &bundleName,
        const sptr<IQuickFixStatusCallback> &statusCallback) override;

    virtual ErrCode CopyFiles(const std::vector<std::string> &sourceFiles,
        std::vector<std::string> &destFiles) override;

private:
    virtual ErrCode CreateFd(const std::string &fileName, int32_t &fd, std::string &path) override;
    bool SendRequest(IQuickFixManager::Message code, MessageParcel &data, MessageParcel &reply);

    static inline BrokerDelegator<QuickFixManagerProxy> delegator_;
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_INCLUDE_QUICK_FIX_MANAGER_PROXY_H
