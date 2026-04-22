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

#include "skills_installer_util.h"

#include "app_log_wrapper.h"
#include "app_log_tag_wrapper.h"
#include "installd_client.h"

namespace OHOS {
namespace AppExecFwk {

ErrCode SkillsInstallerUtil::ExtractSkillsPackage(
    const std::string &bundleName,
    const std::string &moduleName,
    const std::string &hspPath,
    const std::vector<std::string> &skillNameList,
    std::vector<SkillsPackageInfo> &skillInfoList)
{
    LOG_I(BMS_TAG_INSTALLER, "bundleName=%{public}s, moduleName=%{public}s, hspPath=%{public}s, "
        "skillCount=%{public}zu", bundleName.c_str(), moduleName.c_str(), hspPath.c_str(), skillNameList.size());

    if (bundleName.empty() || moduleName.empty() || hspPath.empty()) {
        LOG_E(BMS_TAG_INSTALLER, "invalid input parameters");
        return ERR_APPEXECFWK_INSTALL_PARAM_ERROR;
    }

    // Prepare parameter for installd service call
    SkillsPackageParam param;
    param.bundleName = bundleName;
    param.moduleName = moduleName;
    param.hspPath = hspPath;
    param.skillNameList = skillNameList;

    // Call installd service via IPC
    ErrCode ret = InstalldClient::GetInstance()->ExtractSkillsPackage(param, skillInfoList);
    if (ret != ERR_OK) {
        LOG_E(BMS_TAG_INSTALLER, "installd service call failed, err=%{public}d", ret);
        return ret;
    }

    LOG_I(BMS_TAG_INSTALLER, "completed with %{public}zu skills", skillInfoList.size());
    return ERR_OK;
}

ErrCode SkillsInstallerUtil::RemoveInvalidSkillProfiles(
    const std::vector<SkillsPackageInfo> &skillInfoList,
    InnerBundleInfo &innerBundleInfo)
{
    LOG_I(BMS_TAG_INSTALLER, "skillInfoList size=%{public}zu", skillInfoList.size());
    if (skillInfoList.empty()) {
        return ERR_APPEXECFWK_INSTALL_PARAM_ERROR;
    }
    // Build a map of moduleName -> set of valid skill names
    std::map<std::string, std::set<std::string>> validSkillsMap;
    for (const auto &skillInfo : skillInfoList) {
        validSkillsMap[skillInfo.moduleName].insert(skillInfo.skillsName);
    }

    // Get all modules from InnerBundleInfo
    auto &innerModuleInfos = innerBundleInfo.FetchInnerModuleInfos();

    // Process each module
    for (auto &modulePair : innerModuleInfos) {
        const std::string &moduleName = modulePair.first;
        InnerModuleInfo &moduleInfo = modulePair.second;

        // Skip if this module has no valid skills to check
        if (validSkillsMap.find(moduleName) == validSkillsMap.end()) {
            LOG_D(BMS_TAG_INSTALLER, "no valid skills for module %{public}s", moduleName.c_str());
            continue;
        }

        const std::set<std::string> &validSkillNames = validSkillsMap[moduleName];

        // Check if this module has skillProfiles
        if (moduleInfo.skillProfiles.empty()) {
            LOG_D(BMS_TAG_INSTALLER, "module %{public}s has no skillProfiles", moduleName.c_str());
            continue;
        }

        // Remove invalid skillProfiles
        auto &skillProfiles = moduleInfo.skillProfiles;

        skillProfiles.erase(
            std::remove_if(skillProfiles.begin(), skillProfiles.end(),
                [&validSkillNames](const SkillProfile &skillProfile) {
                    return validSkillNames.find(skillProfile.name) == validSkillNames.end();
                }),
            skillProfiles.end());
    }

    LOG_I(BMS_TAG_INSTALLER, "completed");
    return ERR_OK;
}

}  // namespace AppExecFwk
}  // namespace OHOS
