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
#include "iremote_broker.h"
#include "iremote_object.h"

namespace OHOS {
namespace AppExecFwk {
class BundleMgrProxyNative {
public:
    BundleMgrProxyNative() = default;
    virtual ~BundleMgrProxyNative() = default;
    /**
     * @brief Obtains the bundle name of a specified application based on the given UID through the proxy object.
     * @param uid Indicates the uid.
     * @param bundleName Indicates the obtained bundle name.
     * @return Returns true if the bundle name is successfully obtained; returns false otherwise.
     */
    bool GetBundleNameForUid(const int uid, std::string &bundleName);
    /**
     * @brief Obtains the ApplicationInfo based on a given bundle name through the proxy object.
     * @param appName Indicates the application bundle name to be queried.
     * @param flag Indicates the flag used to specify information contained
     *             in the ApplicationInfo object that will be returned.
     * @param userId Indicates the user ID.
     * @param appInfo Indicates the obtained ApplicationInfo object.
     * @return Returns true if the application is successfully obtained; returns false otherwise.
     */
    bool GetApplicationInfo(
        const std::string &appName, ApplicationFlag flags, int32_t userId, ApplicationInfo &appInfo);

    enum {
        GET_APPLICATION_INFO = 0,
        GET_BUNDLE_NAME_FOR_UID = 7,
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