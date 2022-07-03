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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_DISTRIBUTED_MANAGER_I_BUNDLE_MANAGER_CALLBACK_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_DISTRIBUTED_MANAGER_I_BUNDLE_MANAGER_CALLBACK_H

#include "iremote_broker.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @class IBundleManagerCallback
 * IBundleManagerCallback is used to notify caller ability that query complete.
 */
class IBundleManagerCallback : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.bundleFramework.BundleManagerCallback");

    /**
     * @brief Will be execute when free query rpc id is complete.
     * @param RpcIdResult the json of InstallResult
     */
    virtual int32_t OnQueryRpcIdFinished(const std::string &RpcIdResult) = 0;

    enum Message : uint32_t {
        QUERY_RPC_ID_CALLBACK = 0,
    };
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_DISTRIBUTED_MANAGER_I_BUNDLE_MANAGER_CALLBACK_H
