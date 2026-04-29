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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_SKILLS_INSTALLER_SKILLS_INSTALLER_UTIL_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_SKILLS_INSTALLER_SKILLS_INSTALLER_UTIL_H

#include <map>
#include <set>
#include <string>
#include <vector>

#include "appexecfwk_errors.h"
#include "inner_bundle_info.h"
#include "skills_package_info.h"

namespace OHOS {
namespace AppExecFwk {

/**
 * @brief SkillsInstallerUtil is a utility class for installing skills from HSP packages.
 * It provides methods to parse SKILL.md documentation and extract skill files.
 */
class SkillsInstallerUtil {
public:
    /**
     * @brief Extract skills package with validation.
     * @param bundleName Indicates the bundle name.
     * @param moduleName Indicates the module name.
     * @param hspPath Indicates the path to HSP file.
     * @param skillNameList Indicates the list of skill names to extract.
     * @param skillInfoList Output parameter containing skill extraction results with description.
     * @return Returns ERR_OK if extracted successfully; returns error code otherwise.
     */
    static ErrCode ExtractSkillsPackage(
        const std::string &bundleName,
        const std::string &moduleName,
        const std::string &extractModuleName,
        const std::string &hspPath,
        const std::vector<std::string> &skillNameList,
        std::vector<SkillsPackageInfo> &skillInfoList);

    /**
     * @brief Remove invalid skillsAgents from InnerModuleInfo.
     * @param skillInfoList Vector of successfully extracted skill packages.
     * @param innerBundleInfo Reference to InnerBundleInfo containing module info.
     * @return Returns ERR_OK if removal successful; returns error code otherwise.
     */
    static ErrCode RemoveInvalidSkillProfiles(
        const std::vector<SkillsPackageInfo> &skillInfoList,
        InnerBundleInfo &innerBundleInfo);
};

}  // namespace AppExecFwk
}  // namespace OHOS

#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_SKILLS_INSTALLER_SKILLS_INSTALLER_UTIL_H
