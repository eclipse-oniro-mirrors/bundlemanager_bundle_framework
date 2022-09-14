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

#ifndef BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_BUNDLE_MANAGER_CLEAN_CACHE_CALLBACK_H
#define BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_BUNDLE_MANAGER_CLEAN_CACHE_CALLBACK_H

#include <future>
#include <uv.h>

#include "napi/native_api.h"
#include "napi/native_node_api.h"

#include "clean_cache_callback_host.h"
#include "nocopyable.h"

namespace OHOS {
namespace AppExecFwk {
class CleanCacheCallback : public CleanCacheCallbackHost {
public:
    CleanCacheCallback();
    virtual ~CleanCacheCallback();
    void OnCleanCacheFinished(bool err) override;

    bool GetErr() const
    {
        return err_;
    }

    uv_sem_t uvSem_;

private:
    bool err_ = false;
    DISALLOW_COPY_AND_MOVE(CleanCacheCallback);
};
} // AppExecFwk
} // OHOS

#endif // BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_BUNDLE_MANAGER_CLEAN_CACHE_CALLBACK_H
