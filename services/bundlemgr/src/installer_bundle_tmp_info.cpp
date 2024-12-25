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

#include "installer_bundle_tmp_info.h"

namespace OHOS {
namespace AppExecFwk {
bool InstallerBundleTempInfo::GetTempBundleInfo(InnerBundleInfo &info) const
{
    if (!bundleInit_) {
        return bundleInit_;
    }
    info = tempBundleInfo_;
    return true;
}

bool InstallerBundleTempInfo::SetTempBundleInfo(const InnerBundleInfo &info)
{
    if (info.GetBundleName().empty()) {
        APP_LOGW("SetTempBundleInfo failed, empty bundleName");
        return false;
    }
    bundleInit_ = true;
    tempBundleInfo_ = info;
    return true;
}

}  // namespace AppExecFwk
}  // namespace OHOS