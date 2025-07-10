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

#ifndef BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_ANI_BUNDLE_MONITOR_BUNDLE_MONITOR_CALLBACK_HANDLER_H
#define BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_ANI_BUNDLE_MONITOR_BUNDLE_MONITOR_CALLBACK_HANDLER_H

#include <list>
#include <mutex>

#include "common_fun_ani.h"
#include "nocopyable.h"

namespace OHOS {
namespace AppExecFwk {
struct BundleChangedInfo {
    std::string bundleName;
    int32_t userId = 0;
    int32_t appIndex = 0;
};

class ANIBundleMonitorCallbackHandler {
public:
    ANIBundleMonitorCallbackHandler() = default;
    ~ANIBundleMonitorCallbackHandler();
    void inline Stop()
    {
        stopFlag_ = true;
    }
    void AddCallback(ani_env* env, ani_object aniCallback);
    void RemoveCallback(ani_env* env, ani_object aniCallback);
    void RemoveAllCallback(ani_env* env);
    void InvokeCallback(ani_env* env, const BundleChangedInfo& info);

private:
    void inline ClearCallbackList(ani_env* env, std::list<ani_ref>& list)
    {
        for (auto& iter : list) {
            env->GlobalReference_Delete(iter);
        }
        list.clear();
    }

private:
    std::list<ani_ref> callbackList_;
    std::list<ani_ref> removedCallbackList_;
    std::mutex callbackMutex_;
    size_t notifyCounter_ = 0;
    std::atomic_bool stopFlag_ { false };
    DISALLOW_COPY_AND_MOVE(ANIBundleMonitorCallbackHandler);
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_ANI_BUNDLE_MONITOR_BUNDLE_MONITOR_CALLBACK_HANDLER_H