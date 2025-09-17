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
#include <uv.h>

#include "clean_cache_callback.h"

#include "napi/native_common.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr int32_t TIMEOUT = 60;
}

CleanCacheCallback::CleanCacheCallback() {}

CleanCacheCallback::~CleanCacheCallback() {}

void CleanCacheCallback::OnCleanCacheFinished(bool err)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!complete_) {
        complete_ = true;
        err_ = err;
        promise_.set_value();
    }
}

bool CleanCacheCallback::WaitForCompletion()
{
    if (future_.wait_for(std::chrono::seconds(TIMEOUT)) == std::future_status::ready) {
        return true;
    }
    return false;
}
} // AppExecFwk
} // OHOS
