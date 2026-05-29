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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_DATA_CLONE_INSTALL_HELPER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_DATA_CLONE_INSTALL_HELPER_H

#include <string>
#include <vector>
#include <filesystem>

#include "app_log_wrapper.h"
#include "bundle_service_constants.h"

namespace OHOS {
namespace AppExecFwk {

class DataCloneInstallHelper {
public:
    /**
     * @brief Check if all paths in the list have the required clone install prefix.
     * @param bundlePaths The list of bundle paths to check (must contain exactly 1 path).
     * @return Returns true if the path has the clone install prefix, false otherwise.
     */
    static bool AreAllCloneInstallPaths(const std::vector<std::string> &bundlePaths);

    static std::string RenameDirToSecurityDir(const std::string &dirPath, std::vector<std::string> &bundlePaths,
        std::vector<std::string> &toDeletePaths, int32_t userId);

    static ErrCode RenameToRealCodePath(const std::vector<std::string> bundlePaths,
        const std::string &bundleName);
};

} // namespace AppExecFwk
} // namespace OHOS

#endif // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_DATA_CLONE_INSTALL_HELPER_H
