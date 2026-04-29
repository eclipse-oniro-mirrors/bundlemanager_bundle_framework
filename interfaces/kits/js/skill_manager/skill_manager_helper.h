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

#ifndef BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_SKILL_MANAGER_HELPER_H
#define BUNDLE_FRAMEWORK_INTERFACES_KITS_JS_SKILL_MANAGER_HELPER_H

#include "bundle_skill/skill_manager_interface.h"
#include "bundle_skill/skill_info.h"
#include "iservice_registry.h"

namespace OHOS {
namespace AppExecFwk {
class SkillManagerHelper {
public:
    static sptr<IBundleSkillManager> GetSkillManager();
    static ErrCode InnerGetSkillInfoForSelf(const std::string &moduleName, const std::string &skillName,
        int32_t userId, uint32_t flags, SkillInfo &skillInfo);

    static ErrCode InnerGetSkillInfosForSelf(uint32_t flags, int32_t userId,
        std::vector<SkillInfo> &skillInfos);

    static ErrCode InnerGetSkillInfo(const std::string &bundleName, const std::string &moduleName,
        const std::string &skillName, uint32_t flags, int32_t userId, SkillInfo &skillInfo);

    static ErrCode InnerGetSkillInfos(const std::string &bundleName, uint32_t flags, int32_t userId,
        std::vector<SkillInfo> &skillInfos);

    static ErrCode InnerGetAllSkillInfos(uint32_t flags, int32_t userId,
        std::vector<SkillInfo> &skillInfos);

private:
    class SkillManagerDeathRecipient : public IRemoteObject::DeathRecipient {
        void OnRemoteDied([[maybe_unused]] const wptr<IRemoteObject>& remote) override;
    };
    static sptr<IBundleSkillManager> skillManager_;
    static std::mutex skillManagerMutex_;
    static sptr<IRemoteObject::DeathRecipient> deathRecipient_;
};
} // namespace AppExecFwk
} // namespace OHOS
#endif
