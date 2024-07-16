/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "app_detail_ability.h"

#include "ability_loader.h"
#include "ability_manager_client.h"
#include "app_log_wrapper.h"
#include "element_name.h"
#include "session_info.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* SETTINGS_ACTION = "action.settings.app.info";
constexpr const char* SETTINGS_PARAM_BUNDLE_NAME = "settingsParamBundleName";
}

void AppDetailAbility::OnStart(const Want &want, sptr<AAFwk::SessionInfo> sessionInfo)
{
    std::string bundleName = want.GetBundle();
    APP_LOGD("AppDetailAbility::OnStart, bundleName: %{public}s", bundleName.c_str());
    Want newWant;
    if (sessionInfo != nullptr) {
        sessionToken_ = sessionInfo->sessionToken;
    }
    newWant.SetAction(SETTINGS_ACTION);
    newWant.SetParam(SETTINGS_PARAM_BUNDLE_NAME, bundleName);
    ErrCode errCode = AbilityManagerClient::GetInstance()->StartAbility(newWant);
    if (errCode != ERR_OK) {
        APP_LOGE("AppDetailAbility bundleName: %{public}s start ability failed, errCode: %{public}d",
            want.GetBundle().c_str(), errCode);
    }
    errCode = TerminateAbility();
    if (errCode != ERR_OK) {
        APP_LOGE("AppDetailAbility bundleName: %{public}s terminate ability failed, errCode: %{public}d",
            want.GetBundle().c_str(), errCode);
        return;
    }
    APP_LOGD("AppDetailAbility::OnStart end");
}

REGISTER_AA(AppDetailAbility)
}  // namespace AppExecFwk
}  // namespace OHOS