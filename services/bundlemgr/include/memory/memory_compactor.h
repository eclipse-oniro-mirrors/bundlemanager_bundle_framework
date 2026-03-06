/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_BUNDLE_FRAMEWORK_MEMORY_COMPACTOR_H
#define FOUNDATION_BUNDLE_FRAMEWORK_MEMORY_COMPACTOR_H

#include <mutex>

#include "common_event_subscriber.h"
#include "common_event_subscribe_info.h"

namespace OHOS {
namespace AppExecFwk {
class MemoryCompactor final {
public:
    static void RegisterScreenOffListener();

private:
    MemoryCompactor() = delete;
    ~MemoryCompactor() = delete;

    static void UnregisterScreenOffListener();
    static void OnFirstScreenOff();

    class ScreenOffEventSubscriber : public EventFwk::CommonEventSubscriber {
    public:
        explicit ScreenOffEventSubscriber(const EventFwk::CommonEventSubscribeInfo &info)
            : CommonEventSubscriber(info) {}
        ~ScreenOffEventSubscriber() override = default;
        void OnReceiveEvent(const EventFwk::CommonEventData &event) override;
    };

    static std::mutex mutex_;
    static std::once_flag defragOnceFlag_;
    static std::shared_ptr<ScreenOffEventSubscriber> screenOffSubscriber_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_BUNDLE_FRAMEWORK_MEMORY_COMPACTOR_H
