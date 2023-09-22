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

#include "driver_installer.h"

#include "base_bundle_installer.h"
#include "installd_client.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::vector<std::string> DRIVER_PROPERTIES {
    "cupsFilter", "cupsBackend", "cupsPpd", "saneConfig", "saneBackend"
};
} // namespace

ErrCode DriverInstaller::CopyDriverSoFile(const InnerBundleInfo &info, const std::string &srcPath) const
{
    APP_LOGD("CopyDriverSoFile begin");
    auto extensionAbilityInfos = info.GetInnerExtensionInfos();
    // key is the orignial dir in hap of driver so file
    // value is the destination dir of driver so file
    std::unordered_multimap<std::string, std::string> dirMap;
    // 1. filter driver so files
    ErrCode result = ERR_OK;
    for (const auto &extAbilityInfo : extensionAbilityInfos) {
        if (extAbilityInfo.second.type != ExtensionAbilityType::DRIVER) {
            continue;
        }

        auto &metadata = extAbilityInfo.second.metadata;
        auto filterFunc = [this, &result, &info, &dirMap](const Metadata &meta) {
            result = FilterDriverSoFile(info, meta, dirMap);
            return result != ERR_OK;
        };
        std::any_of(metadata.begin(), metadata.end(), filterFunc);
        CHECK_RESULT(result, "driver so path is invalid, error is %{public}d");
    }
    if (dirMap.empty()) {
        APP_LOGD("no driver so file needs to be cpoied");
        return ERR_OK;
    }
    // 2. copy driver so file to destined dir
    return InstalldClient::GetInstance()->ExtractDriverSoFiles(srcPath, dirMap);
}

ErrCode DriverInstaller::FilterDriverSoFile(const InnerBundleInfo &info, const Metadata &meta,
    std::unordered_multimap<std::string, std::string> &dirMap) const
{
    APP_LOGD("FilterDriverSoFile begin");
    // find driver metadata name in driver properties
    if (std::find(DRIVER_PROPERTIES.cbegin(), DRIVER_PROPERTIES.cend(), meta.name) ==
        DRIVER_PROPERTIES.cend()) {
        APP_LOGD("metadata name %{public}s is not existed in driver properties", meta.name.c_str());
        return ERR_OK;
    }

    // check dir and obtain name of the file which needs to be copied
    std::string originalDir = meta.resource;
    std::string destinedDir = meta.value;
    if (originalDir.find(Constants::RELATIVE_PATH) != std::string::npos ||
        destinedDir.find(Constants::RELATIVE_PATH) != std::string::npos) {
        APP_LOGW("metadata value %{public}s, resource %{public}s cannot support relevant path",
            destinedDir.c_str(), originalDir.c_str());
        return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
    }

    // create destined dir of driver files
    std::vector<std::string> originalDirVec;
    SplitStr(originalDir, Constants::PATH_SEPARATOR, originalDirVec, false, false);
    if (originalDirVec.empty()) {
        APP_LOGW("original dir is invalid");
        return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
    }
    auto fileName = originalDirVec.back();
    APP_LOGD("fileName is %{public}s", fileName.c_str());
    const auto &moduleName = info.GetModuleName(info.GetCurrentModulePackage());
    destinedDir = CreateDriverSoDestinedDir(info.GetBundleName(), moduleName, fileName, destinedDir);
    APP_LOGD("metadata destined dir is %{public}s", destinedDir.c_str());
    dirMap.emplace(originalDir, destinedDir);
    return ERR_OK;
}

void DriverInstaller::RemoveDriverSoFile(const InnerBundleInfo &info, const std::string &moduleName) const
{
    APP_LOGD("RemoveDriverSoFile begin");
    auto extensionAbilityInfos = info.GetInnerExtensionInfos();
    for (const auto &extAbilityInfo : extensionAbilityInfos) {
        // find module name from the extAbilityInfo
        std::string extModuleName = extAbilityInfo.second.moduleName;
        APP_LOGD("extModuleName is %{public}s", extModuleName.c_str());
        if ((!moduleName.empty() && moduleName.compare(extModuleName) != 0) ||
            (extAbilityInfo.second.type != ExtensionAbilityType::DRIVER)) {
            APP_LOGD("no driver extension(%{public}d) or moduleName(%{public}s) is not matched",
                static_cast<int32_t>(extAbilityInfo.second.type), moduleName.c_str());
            continue;
        }
        const auto &metadata = extAbilityInfo.second.metadata;
        for (const auto &meta : metadata) {
            if (std::find(DRIVER_PROPERTIES.cbegin(), DRIVER_PROPERTIES.cend(), meta.name) ==
                DRIVER_PROPERTIES.cend()) {
                APP_LOGD("metadata name %{public}s is not existed in driver properties", meta.name.c_str());
                continue;
            }
            std::vector<std::string> originalDirVec;
            SplitStr(meta.resource, Constants::PATH_SEPARATOR, originalDirVec, false, false);
            if (originalDirVec.empty()) {
                APP_LOGW("invalid metadata resource %{public}s", meta.resource.c_str());
                return;
            }
            auto fileName = originalDirVec.back();
            APP_LOGD("fileName is %{public}s", fileName.c_str());
            std::string destinedDir = CreateDriverSoDestinedDir(info.GetBundleName(), extModuleName, fileName,
                meta.value);
            APP_LOGD("Remove driver so file path is %{public}s", destinedDir.c_str());
            std::string systemServiceDir = Constants::SYSTEM_SERVICE_DIR;
            InstalldClient::GetInstance()->RemoveDir(systemServiceDir + destinedDir);
        }
    }
    APP_LOGD("RemoveDriverSoFile end");
}

std::string DriverInstaller::CreateDriverSoDestinedDir(const std::string &bundleName, const std::string &moduleName,
    const std::string &fileName, const std::string &destinedDir) const
{
    APP_LOGD("bundleName is %{public}s, moduleName is %{public}s, fileName is %{public}s, destinedDir is %{public}s",
        bundleName.c_str(), moduleName.c_str(), fileName.c_str(), destinedDir.c_str());
    if (bundleName.empty() || moduleName.empty() || fileName.empty() || destinedDir.empty()) {
        APP_LOGW("parameters are invalid");
        return "";
    }
    std::string resStr = destinedDir;
    if (resStr.back() != Constants::PATH_SEPARATOR[0]) {
        resStr += Constants::PATH_SEPARATOR;
    }
    resStr.append(bundleName).append(Constants::FILE_UNDERLINE).append(moduleName)
        .append(Constants::FILE_UNDERLINE).append(fileName);
    return resStr;
}
}  // namespace AppExecFwk
}  // namespace OHOS