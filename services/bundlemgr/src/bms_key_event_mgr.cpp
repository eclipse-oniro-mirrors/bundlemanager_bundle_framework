/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "bms_key_event_mgr.h"

#include "app_log_tag_wrapper.h"
#include "inner_bundle_info.h"
#include "parameters.h"

#include <set>

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string BOOTEVENT_BMS_MAIN_BUNDLES_READY = "bootevent.bms.main.bundles.ready";
const std::string MAIN_BUNDLE_NAME_SCENE_BOARD = "com.ohos.sceneboard";
const std::string MAIN_BUNDLE_NAME_SCENE_BOARD_PATH = "/system/app/SceneBoard";
const std::set<std::string> MAIN_BUNDLES_SET = {
    MAIN_BUNDLE_NAME_SCENE_BOARD,
    MAIN_BUNDLE_NAME_SCENE_BOARD_PATH
};
constexpr const char *BMS_PARAM_TRUE = "true";
constexpr const char *BMS_PARAM_FALSE = "false";
}

std::atomic_uint BmsKeyEventMgr::isMainBundleReady_ = true;

void BmsKeyEventMgr::ProcessMainBundleStatusFinally()
{
    LOG_I(BMS_TAG_DEFAULT, "ProcessMainBundleStatus start");
    if (isMainBundleReady_) {
        if (!system::SetParameter(BOOTEVENT_BMS_MAIN_BUNDLES_READY, BMS_PARAM_TRUE)) {
            LOG_E(BMS_TAG_DEFAULT, "bms set parameter failed");
        }
    } else {
        LOG_E(BMS_TAG_DEFAULT, "ProcessMainBundleStatus main bundle not ready");
    }
    LOG_I(BMS_TAG_DEFAULT, "ProcessMainBundleStatus end");
}

void BmsKeyEventMgr::ProcessMainBundleInstallFailed(const std::string &bundleName, int32_t errCode)
{
    if (MAIN_BUNDLES_SET.find(bundleName) == MAIN_BUNDLES_SET.end()) {
        return;
    }
    LOG_I(BMS_TAG_DEFAULT, "bundleName:%{public}s install failed, errCode:%{public}d", bundleName.c_str(), errCode);
    isMainBundleReady_ = false;
    if (!system::SetParameter(BOOTEVENT_BMS_MAIN_BUNDLES_READY, BMS_PARAM_FALSE)) {
        LOG_E(BMS_TAG_DEFAULT, "bms set parameter failed");
    }
}
} // namespace AppExecFwk
} // namespace OHOS
