/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "cleancache_callback.h"

#include "napi/native_common.h"

namespace {
constexpr int8_t OPERATION_SUCCESS = 0;
constexpr int8_t OPERATION_FAILED = 1;
constexpr uint8_t TIMEOUT = 60;
}

CleanCacheCallback::CleanCacheCallback(int32_t err) : err_(err) {}

CleanCacheCallback::~CleanCacheCallback() {}

void CleanCacheCallback::OnCleanCacheFinished(bool err)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!complete_) {
        complete_ = true;
        err_ = err ? OPERATION_SUCCESS : OPERATION_FAILED;
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
