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
#include "app_log_wrapper.h"
#include "base_cb_info.h"

namespace OHOS {
namespace AppExecFwk {
    AsyncWorkData::AsyncWorkData(napi_env napiEnv) : env(napiEnv)
    {}

    AsyncWorkData::~AsyncWorkData()
    {
        if (callback) {
            APP_LOGD("AsyncWorkData::~AsyncWorkData delete callback");
            napi_delete_reference(env, callback);
            callback = nullptr;
        }
        if (asyncWork) {
            APP_LOGD("AsyncWorkData::~AsyncWorkData delete asyncWork");
            napi_delete_async_work(env, asyncWork);
            asyncWork = nullptr;
        }
    }
}
}
