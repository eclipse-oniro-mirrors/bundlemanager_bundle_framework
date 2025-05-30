/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "aging/aging_handler_chain.h"
#include "app_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::vector<AgingCleanType> SUPPORT_AGING_CLEAN_TYPE = {
    AgingCleanType::CLEAN_CACHE,
    AgingCleanType::CLEAN_OTHERS,
};
}

AgingHandlerChain::AgingHandlerChain() {}

AgingHandlerChain::~AgingHandlerChain()
{
    handlers_.clear();
}

void AgingHandlerChain::AddHandler(const std::shared_ptr<AgingHandler> &handler)
{
    if (handler == nullptr) {
        APP_LOGE("agingHandler: invalid handler");
        return;
    }

    handlers_.emplace_back(handler);
}

bool AgingHandlerChain::Process(AgingRequest &request) const
{
    if (!request.IsReachStartAgingThreshold()) {
        APP_LOGI("Not reach agingThreshold and not need aging");
        return true;
    }

    bool isPassed = false;
    for (const auto &agingCleanType : SUPPORT_AGING_CLEAN_TYPE) {
        request.SetAgingCleanType(agingCleanType);
        isPassed = InnerProcess(request);
        if (isPassed) {
            break;
        }
    }

    APP_LOGD("agingHandler: aging handler chain process done");
    return isPassed;
}

bool AgingHandlerChain::InnerProcess(AgingRequest &request) const
{
    bool isPassed = false;
    for (auto handler : handlers_) {
        isPassed = !handler->Process(request);
        APP_LOGD("agingHandler: passed: %{public}d, type: %{public}d",
            isPassed, static_cast<int32_t>(request.GetAgingCleanType()));
        if (isPassed) {
            break;
        }
    }

    return isPassed;
}
}  //  namespace AppExecFwk
}  //  namespace OHOS