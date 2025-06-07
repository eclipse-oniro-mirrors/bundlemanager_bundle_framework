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

#ifndef BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_RESOURCE_HELPER_H
#define BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_RESOURCE_HELPER_H

#include "bundle_resource_interface.h"
#include "bundle_resource_info.h"
#include "iservice_registry.h"

namespace OHOS {
namespace AppExecFwk {
class ResourceHelper {
public:
    static sptr<IBundleResource> GetBundleResourceMgr();

private:
    class BundleResourceMgrDeathRecipient : public IRemoteObject::DeathRecipient {
        void OnRemoteDied([[maybe_unused]] const wptr<IRemoteObject>& remote) override;
    };
    static sptr<IBundleResource> bundleResourceMgr_;
    static std::mutex bundleResourceMutex_;
    static sptr<IRemoteObject::DeathRecipient> deathRecipient_;
};
} // AppExecFwk
} // OHOS
#endif