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

#include "quick_fix_deleter.h"

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "installd_client.h"

namespace OHOS {
namespace AppExecFwk {
QuickFixDeleter::QuickFixDeleter(const std::string &bundleName) : bundleName_(bundleName)
{
    APP_LOGI("enter QuickFixDeleter");
}

ErrCode QuickFixDeleter::Execute()
{
    APP_LOGI("start execute");
    return DeleteQuickFix();
}

ErrCode QuickFixDeleter::DeleteQuickFix()
{
    APP_LOGI("DeleteQuickFix start");
    if (bundleName_.empty()) {
        APP_LOGE("InnerDeleteQuickFix failed due to empty bundleName");
        return ERR_APPEXECFWK_QUICK_FIX_PARAM_ERROR;
    }

    return ERR_OK;
}

ErrCode QuickFixDeleter::ToDeletePatchDir(const InnerAppQuickFix &innerAppQuickFix)
{
    APP_LOGI("start to delete patch dir");
    return ERR_OK;
}
} // AppExecFwk
} // OHOS