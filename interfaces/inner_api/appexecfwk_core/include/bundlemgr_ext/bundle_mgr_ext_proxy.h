/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLE_MGR_EXT_PROXY_H
#define FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLE_MGR_EXT_PROXY_H

#include "bundle_framework_core_ipc_interface_code.h"
#include "bundle_mgr_ext_interface.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace AppExecFwk {
class BundleMgrExtProxy : public IRemoteProxy<IBundleMgrExt> {
public:
    explicit BundleMgrExtProxy(const sptr<IRemoteObject>& object);
    virtual ~BundleMgrExtProxy();

    /**
     * @brief Obtains the bundleNames associated with the given UID.
     * @param uid Indicates the uid.
     * @param bundleNames Indicates the bundleNames.
     * @return Returns ERR_OK if execute success; returns errCode otherwise.
     */
    virtual ErrCode GetBundleNamesForUidExt(const int32_t uid, std::vector<std::string> &bundleNames) override;

private:
    /**
     * @brief Send a command message from the proxy object.
     * @param code Indicates the message code to be sent.
     * @param data Indicates the objects to be sent.
     * @param reply Indicates the reply to be sent;
     * @return Returns true if message send successfully; returns false otherwise.
     */
    ErrCode SendTransactCmd(BundleMgrExtInterfaceCode code, MessageParcel &data, MessageParcel &reply);

    static inline BrokerDelegator<BundleMgrExtProxy> delegator_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLE_MGR_EXT_PROXY_H