/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PRE_INSTALL_BUNDLE_INFO_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PRE_INSTALL_BUNDLE_INFO_H

#include "inner_bundle_info.h"

namespace OHOS {
namespace AppExecFwk {
class PreInstallBundleInfo {
public:
    /**
     * @brief Transform the PreInstallBundleInfo object to json.
     * @param jsonObject Indicates the obtained json object.
     * @return
     */
    void ToJson(nlohmann::json &jsonObject) const;
    /**
     * @brief Transform the json object to PreInstallBundleInfo object.
     * @param jsonObject Indicates the obtained json object.
     * @return Returns 0 if the json object parsed successfully; returns error code otherwise.
     */
    int32_t FromJson(const nlohmann::json &jsonObject);
    /**
     * @brief Transform the PreInstallBundleInfo object to string.
     * @return Returns the string object
     */
    std::string ToString() const;
    /**
     * @brief Calculate Hap Total Size.
     */
    void CalculateHapTotalSize();
    /**
     * @brief Get HapTotalSize.
     * @return Returns the HapTotalSize.
     */
    int64_t GetHapTotalSize() const
    {
        return hapTotalSize_;
    }
    /**
     * @brief Add bundle path.
     * @param bundlePath bundle path.
     */
    void AddBundlePath(const std::string &bundlePath)
    {
        bool ret = std::find(
            bundlePaths_.begin(), bundlePaths_.end(), bundlePath) != bundlePaths_.end();
        if (!ret) {
            bundlePaths_.emplace_back(bundlePath);
        }
    }
    /**
     * @brief Delete bundle path.
     * @param bundlePath bundle path.
     */
    void DeleteBundlePath(const std::string &bundlePath)
    {
        auto iter = std::find(bundlePaths_.begin(), bundlePaths_.end(), bundlePath);
        if (iter != bundlePaths_.end()) {
            bundlePaths_.erase(iter);
        }
    }
    /**
     * @brief clear bundle path.
     * @param bundlePath bundle path.
     */
    void ClearBundlePath()
    {
        bundlePaths_.clear();
    }
    /**
     * @brief Has bundle path.
     * @param bundlePath bundle path.
     */
    bool HasBundlePath(const std::string &bundlePath)
    {
        return std::find(bundlePaths_.begin(), bundlePaths_.end(), bundlePath)
            != bundlePaths_.end();
    }
    /**
     * @brief operator.
     * @param PreInstallBundleInfo Indicates the PreInstallBundleInfo.
     */
    bool operator() (const PreInstallBundleInfo& info) const
    {
        return bundleName_ == info.GetBundleName();
    }

    bool operator < (const PreInstallBundleInfo &preInstallBundleInfo) const
    {
        if (bundlePaths_.size() == preInstallBundleInfo.GetBundlePaths().size()) {
            return hapTotalSize_ >= preInstallBundleInfo.GetHapTotalSize();
        }

        return bundlePaths_.size() > preInstallBundleInfo.GetBundlePaths().size();
    }

    BMS_DEFINE_PROPERTY(AppType, appType_, Constants::AppType);
    BMS_DEFINE_PROPERTY(Removable, removable_, bool);
    BMS_DEFINE_PROPERTY(IsUninstalled, isUninstalled_, bool);
    BMS_DEFINE_PROPERTY(BundleName, bundleName_, std::string);
    BMS_DEFINE_PROPERTY(VersionCode, versionCode_, uint32_t);
    BMS_DEFINE_PROPERTY_GET(BundlePaths, bundlePaths_, std::vector<std::string>);
    BMS_DEFINE_PROPERTY(ModuleName, moduleName_, std::string);
    BMS_DEFINE_PROPERTY(LabelId, labelId_, int32_t);
    BMS_DEFINE_PROPERTY(IconId, iconId_, int32_t);
private:
    std::string bundleName_;
    std::string moduleName_;
    int64_t hapTotalSize_ = 0;
    uint32_t versionCode_;
    int32_t labelId_ = 0;
    int32_t iconId_ = 0;
    std::vector<std::string> bundlePaths_;
    bool removable_ = true;
    bool isUninstalled_ = false;
    Constants::AppType appType_ = Constants::AppType::SYSTEM_APP;
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PRE_INSTALL_BUNDLE_INFO_H
