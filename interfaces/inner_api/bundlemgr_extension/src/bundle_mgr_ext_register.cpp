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

#include "app_log_wrapper.h"
#include "bundle_mgr_ext_register.h"

namespace OHOS {
namespace AppExecFwk {
std::mutex BundleMgrExtRegister::mutex_;
BundleMgrExtRegister &BundleMgrExtRegister::GetInstance()
{
    std::lock_guard<std::mutex> lock(mutex_);
    static BundleMgrExtRegister bundleMgrExt;
    return bundleMgrExt;
}

void BundleMgrExtRegister::RegisterBundleMgrExt(const std::string& bundleExtName, const CreateFunc& createFunc)
{
    std::lock_guard<std::mutex> lock(BundleMgrExtMutex_);
    bundleMgrExts_.emplace(bundleExtName, createFunc);
}

std::shared_ptr<BundleMgrExt> BundleMgrExtRegister::GetBundleMgrExt(const std::string &bundleExtName)
{
    std::lock_guard<std::mutex> lock(BundleMgrExtMutex_);
    auto it = bundleMgrExts_.find(bundleExtName);
    if (it == bundleMgrExts_.end()) {
        return nullptr;
    }
    return it->second();
}
} // AppExecFwk
} // OHOS
