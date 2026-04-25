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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_SKILLS_INSTALLER_SKILLS_DESCRIPTION_MANAGER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_SKILLS_INSTALLER_SKILLS_DESCRIPTION_MANAGER_H

#include <string>
#include <vector>

#include "appexecfwk_errors.h"
#include "singleton.h"
#include "skills_package_info.h"
#include "skills_description_rdb.h"

namespace OHOS {
namespace AppExecFwk {
class SkillsDescriptionManager : public DelayedSingleton<SkillsDescriptionManager> {
public:
    SkillsDescriptionManager();
    ~SkillsDescriptionManager();

    /**
     * @brief Batch insert skill descriptions to database.
     * @param skillInfoList Vector of SkillsPackageInfo containing skill descriptions.
     * @return Returns ERR_OK if insert successfully; returns error code otherwise.
     */
    ErrCode AddSkillDescriptions(const std::vector<SkillsPackageInfo> &skillInfoList);

    /**
     * @brief Delete all skill descriptions by bundle name.
     * @param bundleName Indicates the bundle name.
     * @return Returns ERR_OK if delete successfully; returns error code otherwise.
     */
    ErrCode DeleteSkillDescriptions(const std::string &bundleName);

    /**
     * @brief Delete skill descriptions by bundle name and module name.
     * @param bundleName Indicates the bundle name.
     * @param moduleName Indicates the module name.
     * @return Returns ERR_OK if delete successfully; returns error code otherwise.
     */
    ErrCode DeleteSkillDescriptions(const std::string &bundleName, const std::string &moduleName);

    /**
     * @brief Delete skill description by bundle name, module name and skill name.
     * @param bundleName Indicates the bundle name.
     * @param moduleName Indicates the module name.
     * @param skillName Indicates the skill name.
     * @return Returns ERR_OK if delete successfully; returns error code otherwise.
     */
    ErrCode DeleteSkillDescriptions(const std::string &bundleName, const std::string &moduleName,
        const std::string &skillName);

    /**
     * @brief Get skill description by bundle name, module name and skill name.
     * @param bundleName Indicates the bundle name.
     * @param moduleName Indicates the module name.
     * @param skillName Indicates the skill name.
     * @param description Output the description string.
     * @return Returns ERR_OK if query successfully; returns error code otherwise.
     */
    ErrCode GetSkillDescription(const std::string &bundleName, const std::string &moduleName,
        const std::string &skillName, std::string &description);

private:
    std::shared_ptr<SkillsDescriptionRdb> skillsDescriptionRdb_;
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_SKILLS_INSTALLER_SKILLS_DESCRIPTION_MANAGER_H
