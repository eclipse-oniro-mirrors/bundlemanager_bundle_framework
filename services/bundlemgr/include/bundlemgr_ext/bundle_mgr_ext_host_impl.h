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

#ifndef FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_BUNDLE_MGR_EXT_HOST_IMPL_H
#define FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_BUNDLE_MGR_EXT_HOST_IMPL_H

#include "bundle_mgr_ext_host.h"

namespace OHOS {
namespace AppExecFwk {
class BundleMgrExtHostImpl : public OHOS::AppExecFwk::BundleMgrExtHost {
public:
    BundleMgrExtHostImpl();
    virtual ~BundleMgrExtHostImpl();

    /**
     * @brief Obtains the bundleNames associated with the given UID.
     * @param uid Indicates the uid.
     * @param bundleNames Indicates the bundleNames.
     * @return Returns ERR_OK if execute success; returns errCode otherwise.
     */
    virtual ErrCode GetBundleNamesForUidExt(const int32_t uid, std::vector<std::string> &bundleNames) override;
};
}
}
#endif // FOUNDATION_BUNDLE_FRAMEWORK_SERVICE_INCLUDE_BUNDLE_MGR_EXT_HOST_IMPL_H
