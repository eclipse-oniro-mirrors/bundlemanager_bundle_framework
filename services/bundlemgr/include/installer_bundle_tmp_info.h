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
#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_TEMP_INFO_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_TEMP_INFO_H
 
#include <string>

#include "nocopyable.h"

#include "inner_bundle_info.h"

namespace OHOS {
namespace AppExecFwk {
class InstallerBundleTempInfo {
public:
    InstallerBundleTempInfo() = default;
    ~InstallerBundleTempInfo() = default;
    bool FetchTempBundleInfo(InnerBundleInfo &info) const;
    InnerBundleInfo &GetCurrentBundleInfo();
    void InitTempBundle(InnerBundleInfo &info, bool isAppExist);
    bool UpdateTempBundleInfo(const InnerBundleInfo &info);
private:
    bool bundleInit_ = false;
    InnerBundleInfo tempBundleInfo_;
};

}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_TEMP_INFO_H