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

#include "bundle_resource_event_subscriber.h"

#include <fstream>
#include <thread>

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_parser.h"
#include "bundle_resource_callback.h"
#include "bundle_resource_constants.h"
#include "common_event_support.h"
#include "json_util.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* OLD_USER_ID = "oldId";
}
BundleResourceEventSubscriber::BundleResourceEventSubscriber(
    const EventFwk::CommonEventSubscribeInfo &subscribeInfo) : EventFwk::CommonEventSubscriber(subscribeInfo)
{}

BundleResourceEventSubscriber::~BundleResourceEventSubscriber()
{}

void BundleResourceEventSubscriber::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    std::string action = data.GetWant().GetAction();
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED) {
        int32_t oldUserId = Constants::UNSPECIFIED_USERID;
        std::string oldId = data.GetWant().GetStringParam(OLD_USER_ID);
        if (oldId.empty() || !OHOS::StrToInt(oldId, oldUserId)) {
            APP_LOGE("oldId:%{public}s parse failed", oldId.c_str());
            oldUserId = Constants::UNSPECIFIED_USERID;
        }
        int32_t userId = data.GetCode();
        // when boot, user 0 or -1 switch to user 100, no need to flush resource rdb
        if (((oldUserId == Constants::DEFAULT_USERID) || (oldUserId == Constants::INVALID_USERID) ||
            (oldUserId == Constants::U1)) && !CheckUserSwitchWhenReboot(userId, oldUserId)) {
            APP_LOGI("switch userId %{public}d to %{public}d, no need to process", oldUserId, userId);
            return;
        }
        APP_LOGI("switch userId %{public}d to %{public}d", oldUserId, userId);
        std::thread userIdChangedThread(OnUserIdChanged, oldUserId, userId);
        userIdChangedThread.detach();
    }
    // for other event
}

void BundleResourceEventSubscriber::OnUserIdChanged(const int32_t oldUserId, const int32_t newUserId)
{
    BundleResourceCallback callback;
    callback.OnUserIdSwitched(oldUserId, newUserId);
}

bool BundleResourceEventSubscriber::CheckUserSwitchWhenReboot(const int32_t userId, int32_t &oldUserId)
{
    std::string path = std::string(BundleResourceConstants::BUNDLE_RESOURCE_RDB_PATH) +
        std::string(BundleResourceConstants::USER_FILE_NAME);
    nlohmann::json jsonBuf;
    if (!BundleParser::ReadFileIntoJson(path, jsonBuf)) {
        APP_LOGW("read user file failed, errno %{public}d", errno);
        return false;
    }
    const auto &jsonBufEnd = jsonBuf.end();
    int32_t parseResult = ERR_OK;
    int32_t lastUserId = 0;
    GetValueIfFindKey<int32_t>(jsonBuf, jsonBufEnd, BundleResourceConstants::USER, lastUserId,
        JsonType::NUMBER, false, parseResult, ArrayType::NOT_ARRAY);
    if ((parseResult == ERR_OK) && (lastUserId != userId)) {
        // The user before reboot and the current user do not match, need add resources.
        oldUserId = lastUserId;
        return true;
    }
    return false;
}
}  // namespace AppExecFwk
}  // namespace OHOS
