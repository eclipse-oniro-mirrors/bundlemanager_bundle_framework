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

#include "bundle_mgr_ext_register.h"

#include "app_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {

BundleMgrExtRegister &BundleMgrExtRegister::GetInstance()
{
    APP_LOGE("zhaogan   BundleMgrExtRegister::GetInstance");
    static BundleMgrExtRegister bundleMgrExt;
    return bundleMgrExt;
}

void BundleMgrExtRegister::RegisterBundleMgrExt(const std::string& bundleExtName, const CreateFunc& createFunc)
{
    bundleMgrExts_.emplace(bundleExtName, createFunc);
}

std::shared_ptr<BundleMgrExt> BundleMgrExtRegister::GetBundleMgrExt(const std::string &bundleExtName)
{
    APP_LOGE("zhaogan   BundleMgrExtRegister::GetBundleMgrExt");
    auto it = bundleMgrExts_.find(bundleExtName);
    if (it == bundleMgrExts_.end()) {
        APP_LOGE("zhaogan   BundleMgrExtRegister::GetBundleMgrExt11");
        return nullptr;
    } else {
        APP_LOGE("zhaogan   BundleMgrExtRegister::GetBundleMgrExt22");
        return it->second();
    }
}

} // AppExecFwk
} // OHOS
