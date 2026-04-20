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

#include "skill_manager_host_impl.h"
#include "bundle_mgr_service.h"

#include "app_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {

ErrCode SkillManagerHostImpl::GetSkillInfoForSelf(const std::string &moduleName,
    const std::string &skillName, int32_t userId, uint32_t flags, SkillInfo &skillInfo)
{
    APP_LOGD("get skill info for self, moduleName:%{public}s, skillName:%{public}s, flags:%{public}u",
        moduleName.c_str(), skillName.c_str(), flags);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is null");
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    return dataMgr->GetSkillInfoForSelf(moduleName, skillName, userId, flags, skillInfo);
}

ErrCode SkillManagerHostImpl::GetSkillInfosForSelf(uint32_t flags, int32_t userId,
    std::vector<SkillInfo> &skillInfos)
{
    APP_LOGD("get skill infos for self, flags:%{public}u, userId:%{public}d", flags, userId);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is null");
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    return dataMgr->GetSkillInfosForSelf(flags, userId, skillInfos);
}

ErrCode SkillManagerHostImpl::GetSkillInfo(const std::string &bundleName, const std::string &moduleName,
    const std::string &skillName, uint32_t flags, int32_t userId, SkillInfo &skillInfo)
{
    APP_LOGD("get skill info, bundleName:%{public}s, moduleName:%{public}s, skillName:%{public}s, flags:%{public}u",
        bundleName.c_str(), moduleName.c_str(), skillName.c_str(), flags);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is null");
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    return dataMgr->GetSkillInfo(bundleName, moduleName, skillName, flags, userId, skillInfo);
}

ErrCode SkillManagerHostImpl::GetSkillInfos(const std::string &bundleName, uint32_t flags,
    int32_t userId, std::vector<SkillInfo> &skillInfos)
{
    APP_LOGD("get skill infos, bundleName:%{public}s, flags:%{public}u, userId:%{public}d",
        bundleName.c_str(), flags, userId);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is null");
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    return dataMgr->GetSkillInfos(bundleName, flags, userId, skillInfos);
}

ErrCode SkillManagerHostImpl::GetAllSkillInfos(uint32_t flags, int32_t userId,
    std::vector<SkillInfo> &skillInfos)
{
    APP_LOGD("get all skill infos, flags:%{public}u, userId:%{public}d", flags, userId);
    auto dataMgr = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
    if (dataMgr == nullptr) {
        APP_LOGE("dataMgr is null");
        return ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    return dataMgr->GetAllSkillInfos(flags, userId, skillInfos);
}

} // namespace AppExecFwk
} // namespace OHOS
