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

#include "skills_description_manager.h"
#include "app_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
SkillsDescriptionManager::SkillsDescriptionManager()
{
    skillsDescriptionRdb_ = std::make_shared<SkillsDescriptionRdb>();
}

SkillsDescriptionManager::~SkillsDescriptionManager()
{}

ErrCode SkillsDescriptionManager::AddSkillDescriptions(const std::vector<SkillsPackageInfo> &skillInfoList)
{
    APP_LOGD("SkillsDescriptionManager::AddSkillDescriptions size: %{public}zu", skillInfoList.size());
    return skillsDescriptionRdb_->AddSkillDescriptions(skillInfoList);
}

ErrCode SkillsDescriptionManager::DeleteSkillDescriptions(const std::string &bundleName)
{
    APP_LOGD("SkillsDescriptionManager::DeleteSkillDescriptions bundleName: %{public}s", bundleName.c_str());
    return skillsDescriptionRdb_->DeleteSkillDescriptions(bundleName);
}

ErrCode SkillsDescriptionManager::DeleteSkillDescriptions(const std::string &bundleName,
    const std::string &moduleName)
{
    APP_LOGD("SkillsDescriptionManager::DeleteSkillDescriptions bundleName: %{public}s, moduleName: %{public}s",
        bundleName.c_str(), moduleName.c_str());
    return skillsDescriptionRdb_->DeleteSkillDescriptions(bundleName, moduleName);
}

ErrCode SkillsDescriptionManager::DeleteSkillDescriptions(const std::string &bundleName,
    const std::string &moduleName, const std::string &skillName)
{
    APP_LOGD("DeleteSkillDescriptions bundleName: %{public}s, moduleName: %{public}s,skillName: %{public}s",
        bundleName.c_str(), moduleName.c_str(), skillName.c_str());
    return skillsDescriptionRdb_->DeleteSkillDescriptions(bundleName, moduleName, skillName);
}

ErrCode SkillsDescriptionManager::GetSkillDescription(const std::string &bundleName,
    const std::string &moduleName, const std::string &skillName, std::string &description)
{
    APP_LOGD("SkillsDescriptionManager::GetSkillDescription bundleName:%{public}s, "
        "moduleName:%{public}s, skillName:%{public}s",
        bundleName.c_str(), moduleName.c_str(), skillName.c_str());
    return skillsDescriptionRdb_->GetSkillDescription(bundleName, moduleName, skillName, description);
}
} // namespace AppExecFwk
} // namespace OHOS
