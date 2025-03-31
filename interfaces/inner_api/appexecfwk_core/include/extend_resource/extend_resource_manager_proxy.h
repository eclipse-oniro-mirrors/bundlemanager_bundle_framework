/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_INCLUDE_EXTEND_RESOURCE_MANAGER_PROXY_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_INCLUDE_EXTEND_RESOURCE_MANAGER_PROXY_H

#include "bundle_framework_core_ipc_interface_code.h"
#include "extend_resource_manager_interface.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace AppExecFwk {
class ExtendResourceManagerProxy : public IRemoteProxy<IExtendResourceManager> {
public:
    explicit ExtendResourceManagerProxy(const sptr<IRemoteObject> &object);
    virtual ~ExtendResourceManagerProxy();

    virtual ErrCode AddExtResource(
        const std::string &bundleName, const std::vector<std::string> &filePaths) override;
    virtual ErrCode RemoveExtResource(
        const std::string &bundleName, const std::vector<std::string> &moduleNames) override;
    virtual ErrCode GetExtResource(
        const std::string &bundleName, std::vector<std::string> &moduleNames) override;

    virtual ErrCode EnableDynamicIcon(
        const std::string &bundleName, const std::string &moduleName,
        const int32_t userId, const int32_t appIndex) override;
    virtual ErrCode DisableDynamicIcon(const std::string &bundleName,
        const int32_t userId, const int32_t appIndex) override;
    virtual ErrCode GetDynamicIcon(
        const std::string &bundleName, const int32_t userId, const int32_t appIndex, std::string &moduleName) override;

private:
    virtual ErrCode CopyFiles(
        const std::vector<std::string> &sourceFiles, std::vector<std::string> &destFiles) override;
    virtual ErrCode CreateFd(const std::string &fileName, int32_t &fd, std::string &path) override;
    bool SendRequest(ExtendResourceManagerInterfaceCode code, MessageParcel &data, MessageParcel &reply);

    static inline BrokerDelegator<ExtendResourceManagerProxy> delegator_;
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_INCLUDE_EXTEND_RESOURCE_MANAGER_PROXY_H
