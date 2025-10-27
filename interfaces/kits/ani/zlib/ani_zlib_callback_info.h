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

#ifndef BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_ZLIB_CALLBACK_INFO_H
#define BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_ZLIB_CALLBACK_INFO_H

#include "zlib_callback_info_base.h"

namespace OHOS {
namespace AppExecFwk {
class ANIZlibCallbackInfo : public LIBZIP::ZlibCallbackInfoBase {
public:
    ANIZlibCallbackInfo() = default;
    virtual ~ANIZlibCallbackInfo() = default;
    virtual void OnZipUnZipFinish(ErrCode result)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        result_ = result;
    }
    virtual void DoTask(const OHOS::AppExecFwk::InnerEvent::Callback& task)
    {
        task();
    }

public:
    inline ErrCode GetResult()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return result_;
    }

private:
    ErrCode result_ = SUCCESS;
    std::mutex mutex_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // BUNDLE_FRAMEWORK_INTERFACES_KITS_ANI_ZLIB_CALLBACK_INFO_H