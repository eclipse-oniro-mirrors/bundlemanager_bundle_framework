/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_BUNDLE_FRAMEWORK_AOT_AOT_SIGN_DATA_CACHE_MGR
#define FOUNDATION_BUNDLE_FRAMEWORK_AOT_AOT_SIGN_DATA_CACHE_MGR

#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

#include "aot/aot_args.h"
#include "bundle_mgr_service.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "inner_bundle_info.h"
#include "iservice_registry.h"
#include "nocopyable.h"

namespace OHOS {
namespace AppExecFwk {
class AOTSignDataCacheMgr final {
public:
    static AOTSignDataCacheMgr& GetInstance();
    void RegisterScreenUnlockListener();
    void AddPendSignData(const AOTArgs &aotArgs, const uint32_t versionCode,
        const std::vector<uint8_t> &pendSignData, const ErrCode ret);
private:
    AOTSignDataCacheMgr() = default;
    ~AOTSignDataCacheMgr() = default;
    DISALLOW_COPY_AND_MOVE(AOTSignDataCacheMgr);

    bool RegisterScreenUnlockEvent();
    void UnregisterScreenUnlockEvent();
    void HandleUnlockEvent();
    ErrCode ExecutePendSign();
    class UnlockEventSubscriber : public OHOS::EventFwk::CommonEventSubscriber {
    public:
        UnlockEventSubscriber(const OHOS::EventFwk::CommonEventSubscribeInfo &info) : CommonEventSubscriber(info) {}
        ~UnlockEventSubscriber() override = default;
        void OnReceiveEvent(const OHOS::EventFwk::CommonEventData &event) override;
    };
private:
    struct PendingData {
        uint32_t versionCode {0};
        std::vector<uint8_t> signData;
    };
    std::atomic<bool> isLocked_ { true };
    mutable std::mutex mutex_;
    std::shared_ptr<UnlockEventSubscriber> unlockEventSubscriber_;
    std::unordered_map<std::string, std::unordered_map<std::string, PendingData>> pendingSignData_;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_BUNDLE_FRAMEWORK_AOT_AOT_SIGN_DATA_CACHE_MGR
