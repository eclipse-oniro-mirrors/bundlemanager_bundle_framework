/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_EXT_INCLUDE_BUNDLE_MGR_EX_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_EXT_INCLUDE_BUNDLE_MGR_EX_H

#include "bundle_info.h"

namespace OHOS {
namespace AppExecFwk {
class BundleMgrExt {
public:
    virtual bool CheckApiInfo(const BundleInfo& bundleInfo) = 0;
    virtual ~BundleMgrExt() = default;
};

} // AppExecFwk
} // OHOS

#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_EXT_INCLUDE_BUNDLE_MGR_EX_H