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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_EXT_INCLUDE_BUNDLE_MGR_EX_REGISTER_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_EXT_INCLUDE_BUNDLE_MGR_EX_REGISTER_H

#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>

#include "bundle_mgr_ext.h"
#include "nocopyable.h"

namespace OHOS {
namespace AppExecFwk {
using CreateFunc = std::function<std::shared_ptr<BundleMgrExt>(void)>;
class BundleMgrExtRegister {
public:
    static BundleMgrExtRegister &GetInstance();

    ~BundleMgrExtRegister() = default;

    void RegisterBundleMgrExt(const std::string& bundleExtName, const CreateFunc& createFunc);
    std::shared_ptr<BundleMgrExt> GetBundleMgrExt(const std::string &bundleExtName);
private:
    static std::mutex mutex_;
    mutable std::mutex BundleMgrExtMutex_;
    BundleMgrExtRegister() = default;
    std::unordered_map<std::string, CreateFunc> bundleMgrExts_;

    DISALLOW_COPY_AND_MOVE(BundleMgrExtRegister);
};

#define REGISTER_BUNDLEMGR_EXT(className)                                                                \
    __attribute__((constructor)) void RegisterBundleMgrExt##className() {                               \
        BundleMgrExtRegister::GetInstance().RegisterBundleMgrExt(#className, []()->std::shared_ptr<BundleMgrExt> { \
            return std::make_shared<className>();                                                             \
        });                                                                                   \
    }
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_EXT_INCLUDE_BUNDLE_MGR_EX_REGISTER_H
