/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_DRIVER_DRIVER_DRIVER_INSTALLER_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_DRIVER_DRIVER_DRIVER_INSTALLER_H
#include <unordered_map>

#include "application_info.h"
#include "driver_install_ext.h"
#include "inner_bundle_info.h"

namespace OHOS {
namespace AppExecFwk {
class DriverInstaller {
public:
    DriverInstaller() = default;
    ~DriverInstaller() = default;

    ErrCode CopyAllDriverFile(const std::unordered_map<std::string, InnerBundleInfo> &newInfos,
        const InnerBundleInfo &oldInfo) const;

    ErrCode FilterDriverSoFile(const InnerBundleInfo &info, const Metadata &meta,
        std::unordered_multimap<std::string, std::string> &dirMap, bool isModuleExisted) const;

    void RemoveDriverSoFile(const InnerBundleInfo &info, const std::string &moduleName, bool isModuleExisted) const;

    std::string CreateDriverSoDestinedDir(const std::string &bundleName, const std::string &moduleName,
        const std::string &fileName, const std::string &destinedDir, bool isModuleExisted) const;

    std::string ConvertResfilePath(const std::string &originalDir) const;

private:
    ErrCode CopyDriverSoFile(const InnerBundleInfo &info, const std::string &srcPath, bool isModuleExisted) const;

    ErrCode ExtractDriverRawFiles(const InnerBundleInfo &info,
        const std::unordered_multimap<std::string, std::string> &rawfileDirMap) const;

    void RemoveAndReNameDriverFile(const std::unordered_map<std::string, InnerBundleInfo> &newInfos,
        const InnerBundleInfo &oldInfo) const;

    void RenameDriverFile(const InnerBundleInfo &info) const;

    void RenameDriverKoFile(const InnerBundleInfo &info, const std::string &moduleName, const Metadata &meta) const;

    mutable std::shared_ptr<DriverInstallExtHandler> driverInstallExtHandler_ = nullptr;

    bool HandleExternalDriverSource(const InnerBundleInfo &info, const Metadata &meta,
    std::unordered_multimap<std::string, std::string> &dirMap, bool isModuleExisted, ErrCode &result) const;

    bool RemoveDriverFile(const InnerBundleInfo &info, const std::string &moduleName,
        const Metadata &meta, bool isModuleExisted) const;

    ErrCode FilterDriverKoFile(const InnerBundleInfo &info, const Metadata &meta,
    std::unordered_multimap<std::string, std::string> &dirMap, bool isModuleExisted) const;

    std::string CreateDriverKoDestinedDir(const std::string &bundleName, const std::string &moduleName,
    const std::string &originalDir, const std::string &destinedDir, bool isModuleExisted) const;
};
} // AppExecFwk
} // OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_DRIVER_DRIVER_DRIVER_INSTALLER_H
