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

#ifndef BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_BUNDLE_MONITOR_EVENT_LISTENER_H
#define BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_BUNDLE_MONITOR_EVENT_LISTENER_H

#include <string>
#include <list>

#include "napi/native_api.h"
#include "napi/native_node_api.h"

namespace OHOS {
namespace AppExecFwk {
// object must operater on js thread
class EventListener {
public:
    explicit EventListener(napi_env env, const std::string& type);
    virtual ~EventListener();
    void Add(napi_env env, napi_value handler);
    void Delete(napi_env env, napi_value handler);
    void DeleteAll();
    bool HasSameEnv(napi_env env) const;
    void Emit(std::string &bundleName, int32_t userId, int32_t appIndex);
    void SetValid(bool valid);
private:
    bool Find(napi_value handler);
    void EmitOnUV(const std::string &bundleName, int32_t userId, int32_t appIndex,
        std::pair<napi_ref, napi_threadsafe_function> callbackRef);
private:
    napi_env env_;
    std::string type_;
    std::list<std::pair<napi_ref, napi_threadsafe_function>> callbackRefs_;
    bool valid_ = true;
    std::mutex validMutex_;
};

struct AsyncCallbackInfo {
    std::string bundleName;
    int32_t userId;
    int32_t appIndex;
};
}
}
#endif // BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_BUNDLE_MONITOR_EVENT_LISTENER_H