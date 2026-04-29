/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "share_file_helper.h"

#include "app_log_tag_wrapper.h"
#include "errors.h"
#ifdef BMS_ACCESSCONTROL_SANDBOX_MANAGER
#include "sandbox_manager_kit.h"
#endif

namespace OHOS {
namespace AppExecFwk {

int32_t ShareFileHelper::SetShareFileInfo(const std::string &cfgInfo, const std::string &bundleName,
    uint32_t userId, uint32_t tokenId)
{
    LOG_D(BMS_TAG_INSTALLER, "cfgInfo: %{public}s, bundleName: %{public}s, userId: %{public}d, tokenId: %{public}d",
        cfgInfo.c_str(), bundleName.c_str(), userId, tokenId);
#ifdef BMS_ACCESSCONTROL_SANDBOX_MANAGER
    int32_t ret = OHOS::AccessControl::SandboxManager::SandboxManagerKit::SetShareFileInfo(
        cfgInfo, bundleName, userId, tokenId);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLER,
            "cfgInfo: %{public}s, bundleName: %{public}s, userId: %{public}d, tokenId: %{public}d, ret: %{public}d",
            cfgInfo.c_str(), bundleName.c_str(), userId, tokenId, ret);
    }
    return ret;
#endif
    return ERR_OK;
}

int32_t ShareFileHelper::UpdateShareFileInfo(const std::string &cfgInfo, const std::string &bundleName,
    uint32_t userId, uint32_t tokenId)
{
    LOG_D(BMS_TAG_INSTALLER, "cfgInfo: %{public}s, bundleName: %{public}s, userId: %{public}d, tokenId: %{public}d",
        cfgInfo.c_str(), bundleName.c_str(), userId, tokenId);
#ifdef BMS_ACCESSCONTROL_SANDBOX_MANAGER
    int32_t ret = OHOS::AccessControl::SandboxManager::SandboxManagerKit::UpdateShareFileInfo(
        cfgInfo, bundleName, userId, tokenId);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLER,
            "cfgInfo: %{public}s, bundleName: %{public}s, userId: %{public}d, tokenId: %{public}d, ret: %{public}d",
            cfgInfo.c_str(), bundleName.c_str(), userId, tokenId, ret);
    }
    return ret;
#endif
    return ERR_OK;
}

int32_t ShareFileHelper::UnsetShareFileInfo(uint32_t tokenId, const std::string &bundleName, uint32_t userId)
{
    LOG_D(BMS_TAG_INSTALLER, "bundleName: %{public}s, userId: %{public}d, tokenId: %{public}d",
        bundleName.c_str(), userId, tokenId);
#ifdef BMS_ACCESSCONTROL_SANDBOX_MANAGER
    int32_t ret = OHOS::AccessControl::SandboxManager::SandboxManagerKit::UnsetShareFileInfo(
        tokenId, bundleName, userId);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLER,
            "bundleName: %{public}s, userId: %{public}d, tokenId: %{public}d, ret: %{public}d",
            bundleName.c_str(), userId, tokenId, ret);
    }
    return ret;
#endif
    return ERR_OK;
}

}  // namespace AppExecFwk
}  // namespace OHOS
