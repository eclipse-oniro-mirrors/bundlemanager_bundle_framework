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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_SKILL_SKILL_MANAGER_HOST_IMPL_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_SKILL_SKILL_MANAGER_HOST_IMPL_H

#include "skill_manager_host.h"
#include "bundle_skill/skill_info.h"

namespace OHOS {
namespace AppExecFwk {
class SkillManagerHostImpl : public BundleSkillManagerHost {
public:
    SkillManagerHostImpl() = default;
    virtual ~SkillManagerHostImpl() = default;

    virtual ErrCode GetSkillInfoForSelf(const std::string &moduleName, const std::string &skillName,
        int32_t userId, uint32_t flags, SkillInfo &skillInfo) override;

    virtual ErrCode GetSkillInfosForSelf(uint32_t flags, int32_t userId,
        std::vector<SkillInfo> &skillInfos) override;

    virtual ErrCode GetSkillInfo(const std::string &bundleName, const std::string &moduleName,
        const std::string &skillName, uint32_t flags, int32_t userId, SkillInfo &skillInfo) override;

    virtual ErrCode GetSkillInfos(const std::string &bundleName, uint32_t flags,
        int32_t userId, std::vector<SkillInfo> &skillInfos) override;

    virtual ErrCode GetAllSkillInfos(uint32_t flags, int32_t userId,
        std::vector<SkillInfo> &skillInfos) override;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_SERVICES_BUNDLEMGR_BUNDLE_SKILL_SKILL_MANAGER_HOST_IMPL_H
