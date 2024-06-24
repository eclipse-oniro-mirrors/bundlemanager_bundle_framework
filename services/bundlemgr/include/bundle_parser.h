/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_PARSER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_PARSER_H

#include <set>
#include <string>

#include "app_privilege_capability.h"
#include "appexecfwk_errors.h"
#include "default_permission.h"
#include "inner_bundle_info.h"
#include "pre_scan_info.h"

namespace OHOS {
namespace AppExecFwk {
class BundleParser {
private:
    bool CheckRouterData(nlohmann::json data) const;
public:
    static bool ReadFileIntoJson(const std::string &filePath, nlohmann::json &jsonBuf);
    /**
     * @brief Parse bundle by the path name, then save in innerBundleInfo info.
     * @param pathName Indicates the path of Bundle.
     * @param innerBundleInfo Indicates the obtained InnerBundleInfo object.
     * @return Returns ERR_OK if the bundle successfully parsed; returns ErrCode otherwise.
     */
    ErrCode Parse(
        const std::string &pathName,
        InnerBundleInfo &innerBundleInfo) const;

    ErrCode ParsePackInfo(const std::string &pathName, BundlePackInfo &bundlePackInfo) const;
    /**
     * @brief Parse bundle by the path name, then save in innerBundleInfo info.
     * @param pathName Indicates the path of Bundle.
     * @param sysCaps Indicates the sysCap.
     * @return Returns ERR_OK if the bundle successfully parsed; returns ErrCode otherwise.
     */
    ErrCode ParseSysCap(const std::string &pathName, std::vector<std::string> &sysCaps) const;
    /**
     * @brief Parse scanInfos by the configFile.
     * @param configFile Indicates the path of configFile.
     * @param scanInfos Indicates the obtained InnerBundleInfo object.
     * @return Returns ERR_OK if the bundle successfully parsed; returns ErrCode otherwise.
     */
    ErrCode ParsePreInstallConfig(
        const std::string &configFile, std::set<PreScanInfo> &scanInfos) const;
    /**
     * @brief Parse bundleNames by the configFile.
     * @param configFile Indicates the path of configFile.
     * @param uninstallList Indicates the uninstallList.
     * @return Returns ERR_OK if the bundle successfully parsed; returns ErrCode otherwise.
     */
    ErrCode ParsePreUnInstallConfig(
        const std::string &configFile,
        std::set<std::string> &uninstallList) const;
    /**
     * @brief Parse PreBundleConfigInfo by the configFile.
     * @param configFile Indicates the path of configFile.
     * @param preBundleConfigInfos Indicates the obtained preBundleConfigInfo object.
     * @return Returns ERR_OK if the bundle successfully parsed; returns ErrCode otherwise.
     */
    ErrCode ParsePreInstallAbilityConfig(
        const std::string &configFile, std::set<PreBundleConfigInfo> &preBundleConfigInfos) const;

    /**
     * @brief Parse default permission file, then save in DefaultPermission info.
     * @param permissionFile Indicates the permissionFile.
     * @param defaultPermissions Indicates the obtained DefaultPermission object.
     * @return Returns ERR_OK if the bundle successfully parsed; returns ErrCode otherwise.
     */
    ErrCode ParseDefaultPermission(
        const std::string &permissionFile, std::set<DefaultPermission> &defaultPermissions) const;

    /**
     * @brief Parse default extension type name file, then save in ParseExtensionTypeConfig info.
     * @param configFile Indicates the path of configFile.
     * @param extensionTypeList Indicates the obtained extension type name list.
     * @return Returns ERR_OK if the extensionType successfully parsed; returns ErrCode otherwise.
     */
    ErrCode ParseExtTypeConfig(
        const std::string &configFile, std::set<std::string> &extensionTypeList) const;

    /**
     * @brief Parse router map json file, then return router map info if necessary.
     * @param configFile Indicates the path of configFile.
     * @param routerArray Indicates the obtained router item list.
     * @return Returns ERR_OK if the router info successfully parsed; returns ErrCode otherwise.
     */
    ErrCode ParseRouterArray(
        const std::string &configFile, std::vector<RouterItem> &routerArray) const;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_BUNDLE_PARSER_H
