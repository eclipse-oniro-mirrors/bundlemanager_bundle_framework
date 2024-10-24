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

#ifndef FOUNDATION_APPEXECFWK_KITS_APPKIT_NATIVE_BUNDLE_INCLUDE_BUNDLE_MGR_PROXY_NATIVE_H
#define FOUNDATION_APPEXECFWK_KITS_APPKIT_NATIVE_BUNDLE_INCLUDE_BUNDLE_MGR_PROXY_NATIVE_H

#include <string>

#include "application_info.h"
#include "bundle_info.h"
#include "iremote_broker.h"
#include "iremote_object.h"

namespace OHOS {
namespace AppExecFwk {
class BundleMgrProxyNative {
public:
    BundleMgrProxyNative() = default;
    virtual ~BundleMgrProxyNative() = default;

    /**
     * @brief Obtains the BundleInfo based on calling uid.
     * @param bundleName Indicates the application bundle name to be queried.
     * @param flags Indicates the information contained in the BundleInfo object to be returned.
     * @param bundleInfo Indicates the obtained BundleInfo object.
     * @param userId Indicates the user ID.
     * @return Returns true if the BundleInfo is successfully obtained; returns false otherwise.
     */
    bool GetBundleInfoForSelf(int32_t flags, BundleInfo &bundleInfo);

    bool GetCompatibleDeviceTypeNative(std::string &deviceType);

    enum {
        GET_BUNDLE_INFO_FOR_SELF_NATIVE = 98,
        GET_COMPATIBLED_DEVICE_TYPE_NATIVE = 166
    };
private:
    sptr<IRemoteObject> GetBmsProxy();
    template <typename T>
    bool GetParcelableInfo(uint32_t code, MessageParcel &data, T &parcelableInfo);
    bool SendTransactCmd(uint32_t code, MessageParcel &data, MessageParcel &reply);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_KITS_APPKIT_NATIVE_BUNDLE_INCLUDE_BUNDLE_MGR_PROXY_NATIVE_H