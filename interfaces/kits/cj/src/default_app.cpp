/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "default_app.h"
#include "app_log_wrapper.h"
#include "bundle_error.h"
#include "cj_common_ffi.h"
#include "bundle_mgr_proxy.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "common_func.h"

namespace OHOS {
namespace AppExecFwk {
using namespace CJSystemapi::BundleManager;

static const std::unordered_map<std::string, std::string> TYPE_MAPPING = {
    {"Web Browser", "BROWSER"},
    {"Image Gallery", "IMAGE"},
    {"Audio Player", "AUDIO"},
    {"Video Player", "VIDEO"},
    {"PDF Viewer", "PDF"},
    {"Word Viewer", "WORD"},
    {"Excel Viewer", "EXCEL"},
    {"PPT Viewer", "PPT"},
    {"Email", "EMAIL"}
};

static bool ParseType(std::string& result)
{
    if (TYPE_MAPPING.find(result) != TYPE_MAPPING.end()) {
        result = TYPE_MAPPING.at(result);
    }
    return true;
}

ErrCode ParamsProcessIsDefaultApplicationSync(std::string& type)
{
    if (!ParseType(type)) {
        APP_LOGE("type %{public}s invalid", type.c_str());
        return ERROR_PARAM_CHECK_ERROR;
    }
    return SUCCESS_CODE;
}

static OHOS::sptr<OHOS::AppExecFwk::IDefaultApp> GetDefaultAppProxy()
{
    auto systemAbilityManager = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        APP_LOGE("systemAbilityManager is null.");
        return nullptr;
    }
    auto bundleMgrSa = systemAbilityManager->GetSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (bundleMgrSa == nullptr) {
        APP_LOGE("bundleMgrSa is null.");
        return nullptr;
    }
    auto bundleMgr = OHOS::iface_cast<IBundleMgr>(bundleMgrSa);
    if (bundleMgr == nullptr) {
        APP_LOGE("iface_cast failed.");
        return nullptr;
    }
    auto defaultAppProxy = bundleMgr->GetDefaultAppProxy();
    if (defaultAppProxy == nullptr) {
        APP_LOGE("GetDefaultAppProxy failed.");
        return nullptr;
    }
    return defaultAppProxy;
}

extern "C" {
    RetDataBool FfiBundleManagerIsDefaultApplication(char* type)
    {
        RetDataBool nRet = {.code = -1, .data = false};
        bool isDefaultApp = false;
        std::string strType(type);
        if (ParamsProcessIsDefaultApplicationSync(strType) != SUCCESS_CODE) {
            return nRet;
        }

        auto defaultAppProxy = GetDefaultAppProxy();
        if (defaultAppProxy == nullptr) {
            nRet.code = ERROR_BUNDLE_SERVICE_EXCEPTION;
            return nRet;
        }

        ErrCode ret = defaultAppProxy->IsDefaultApplication(strType, isDefaultApp);
        ret = CommonFunc::ConvertErrCode(ret);
        if (ret != SUCCESS_CODE) {
            APP_LOGE("FfiBundleManagerIsDefaultApplication failed: %{public}d", ret);
            nRet.code = ret;
            return nRet;
        }
        nRet.data = isDefaultApp;
        nRet.code = ret;
        return nRet;
    }
}

}
}