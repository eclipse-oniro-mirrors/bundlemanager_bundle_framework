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

#ifndef BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_BUNDLE_MANAGER_H
#define BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_BUNDLE_MANAGER_H

#include <string>

#include "ani.h"
#include "bundle_mgr_interface.h"
#include "common_event_manager.h"
#include "common_event_subscriber.h"
#include "common_event_support.h"

class ClearCacheListener final : public OHOS::EventFwk::CommonEventSubscriber {
public:
    explicit ClearCacheListener(const OHOS::EventFwk::CommonEventSubscribeInfo& subscribeInfo);
    virtual ~ClearCacheListener() = default;
    void OnReceiveEvent(const OHOS::EventFwk::CommonEventData& data) override;
    static void HandleCleanEnv(void* data);

private:
    static void DoClearCache();
};

struct Query {
    std::string bundleName_;
    std::string interfaceType_;
    int32_t flags_ = 0;
    int32_t userId_ = OHOS::AppExecFwk::Constants::UNSPECIFIED_USERID;
    Query(const std::string& bundleName, const std::string& interfaceType, int32_t flags, int32_t userId)
        : bundleName_(bundleName), interfaceType_(interfaceType), flags_(flags), userId_(userId)
    {}

    bool operator==(const Query& query) const
    {
        return bundleName_ == query.bundleName_ && interfaceType_ == query.interfaceType_ && flags_ == query.flags_ &&
               userId_ == query.userId_;
    }
};

struct QueryHash {
    size_t operator()(const Query& query) const
    {
        return std::hash<std::string>()(query.bundleName_) ^ std::hash<std::string>()(query.interfaceType_) ^
               std::hash<int32_t>()(query.flags_) ^ std::hash<int32_t>()(query.userId_);
    }
};

void RegisterClearCacheListenerAndEnv(ani_vm* vm);

#endif