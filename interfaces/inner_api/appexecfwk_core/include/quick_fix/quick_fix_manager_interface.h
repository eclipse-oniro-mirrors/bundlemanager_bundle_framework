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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_INCLUDE_QUICK_FIX_MANAGER_INTERFACE_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_INCLUDE_QUICK_FIX_MANAGER_INTERFACE_H

#include "appexecfwk_errors.h"
#include "quick_fix_status_callback_interface.h"
#include "iremote_broker.h"

#include <vector>
#include <string>

namespace OHOS {
namespace AppExecFwk {
class IQuickFixManager : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.bundleManager.QuickFixManager");

    virtual ErrCode DeployQuickFix(const std::vector<std::string> &bundleFilePaths,
        const sptr<IQuickFixStatusCallback> &statusCallback) = 0;

    virtual ErrCode SwitchQuickFix(const std::string &bundleName, bool enable,
        const sptr<IQuickFixStatusCallback> &statusCallback) = 0;

    virtual ErrCode DeleteQuickFix(const std::string &bundleName,
        const sptr<IQuickFixStatusCallback> &statusCallback) = 0;

    virtual ErrCode CreateFd(const std::string &fileName, int32_t &fd, std::string &path) = 0;

    virtual ErrCode CopyFiles(const std::vector<std::string> &sourceFiles, std::vector<std::string> &destFiles)
    {
        return ERR_BUNDLEMANAGER_QUICK_FIX_INTERNAL_ERROR;
    }
    enum Message : uint32_t {
        DEPLOY_QUICK_FIX = 0,
        SWITCH_QUICK_FIX = 1,
        DELETE_QUICK_FIX = 2,
        CREATE_FD = 3
    };
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_INCLUDE_QUICK_FIX_MANAGER_INTERFACE_H