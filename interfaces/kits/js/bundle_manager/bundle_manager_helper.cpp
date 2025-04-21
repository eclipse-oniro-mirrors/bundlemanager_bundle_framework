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

#include "bundle_manager_helper.h"

#include "app_log_wrapper.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "bundle_errors.h"
#include "business_error.h"
#include "common_func.h"

namespace OHOS {
namespace AppExecFwk {

ErrCode BundleManagerHelper::InnerBatchQueryAbilityInfos(const std::vector<OHOS::AAFwk::Want> &wants,
    int32_t flags, int32_t userId, std::vector<AbilityInfo> &abilityInfos)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        APP_LOGE("iBundleMgr is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = iBundleMgr->BatchQueryAbilityInfos(wants, flags, userId, abilityInfos);
    APP_LOGD("BatchQueryAbilityInfos ErrCode : %{public}d", ret);
    return CommonFunc::ConvertErrCode(ret);
}

ErrCode BundleManagerHelper::InnerGetDynamicIcon(const std::string &bundleName, std::string &moduleName)
{
    auto extResourceManager = CommonFunc::GetExtendResourceManager();
    if (extResourceManager == nullptr) {
        APP_LOGE("extResourceManager is null");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = extResourceManager->GetDynamicIcon(bundleName, moduleName);
    if (ret != ERR_OK) {
        APP_LOGE_NOFUNC("GetDynamicIcon failed");
    }
    return CommonFunc::ConvertErrCode(ret);
}

ErrCode BundleManagerHelper::InnerIsAbilityEnabled(
    const AbilityInfo &abilityInfo, bool &isEnable, int32_t appIndex)
{
    auto bundleMgr = CommonFunc::GetBundleMgr();
    if (bundleMgr == nullptr) {
        APP_LOGE("CommonFunc::GetBundleMgr failed");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = ERR_OK;
    if (appIndex != 0) {
        ret = bundleMgr->IsCloneAbilityEnabled(abilityInfo, appIndex, isEnable);
    } else {
        ret = bundleMgr->IsAbilityEnabled(abilityInfo, isEnable);
    }
    return CommonFunc::ConvertErrCode(ret);
}

ErrCode BundleManagerHelper::InnerSetAbilityEnabled(
    const AbilityInfo &abilityInfo, bool &isEnable, int32_t appIndex)
{
    auto bundleMgr = CommonFunc::GetBundleMgr();
    if (bundleMgr == nullptr) {
        APP_LOGE("CommonFunc::GetBundleMgr failed");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = ERR_OK;
    if (appIndex != 0) {
        ret = bundleMgr->SetCloneAbilityEnabled(abilityInfo, appIndex, isEnable);
    } else {
        ret = bundleMgr->SetAbilityEnabled(abilityInfo, isEnable);
    }
    return CommonFunc::ConvertErrCode(ret);
}

ErrCode BundleManagerHelper::InnerSetApplicationEnabled(
    const std::string &bundleName, bool &isEnable, int32_t appIndex)
{
    auto bundleMgr = CommonFunc::GetBundleMgr();
    if (bundleMgr == nullptr) {
        APP_LOGE("CommonFunc::GetBundleMgr failed");
        return ERROR_BUNDLE_SERVICE_EXCEPTION;
    }
    ErrCode ret = ERR_OK;
    if (appIndex == 0) {
        ret = bundleMgr->SetApplicationEnabled(bundleName, isEnable);
    } else {
        ret = bundleMgr->SetCloneApplicationEnabled(bundleName, appIndex, isEnable);
    }
    return CommonFunc::ConvertErrCode(ret);
}
} // AppExecFwk
} // OHOS