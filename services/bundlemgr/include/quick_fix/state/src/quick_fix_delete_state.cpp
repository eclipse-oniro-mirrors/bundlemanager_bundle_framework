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

#include "quick_fix_delete_state.h"

#include "quick_fix_deleter.h"

namespace OHOS {
namespace AppExecFwk {
QuickFixDeleteState::QuickFixDeleteState(const std::string &bundleName)
    : bundleName_(bundleName)
{
    APP_LOGI("create QuickFixDeleteState");
}

ErrCode QuickFixDeleteState::Process()
{
    APP_LOGD("start to process delete-status bundle %{public}s", bundleName_.c_str());
    std::unique_ptr<QuickFixDeleter> deleter = std::make_unique<QuickFixDeleter>(bundleName_);
    auto ret = deleter->Execute();
    if (ret != ERR_OK) {
        APP_LOGE("delete quick fix info and dir failed");
        return ret;
    }
    return ERR_OK;
}
} // AppExecFwk
} // OHOS