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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_SKILLS_INSTALLER_SKILLS_PACKAGE_INFO_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_SKILLS_INSTALLER_SKILLS_PACKAGE_INFO_H

#include <string>

#include "parcel.h"

namespace OHOS {
namespace AppExecFwk {
/**
 * @brief SkillsPackageInfo contains skill package information for extraction.
 * It includes bundle/module info and extraction result.
 */
struct SkillsPackageInfo : public Parcelable {
    std::string bundleName;
    std::string moduleName;
    std::string skillsName;
    std::string description;

    /**
     * @brief Constructor.
     */
    SkillsPackageInfo() = default;

    /**
     * @brief Destructor.
     */
    virtual ~SkillsPackageInfo() = default;

    /**
     * @brief Read from Parcel.
     * @param parcel Indicates the Parcel object.
     * @return Returns true if read successfully; returns false otherwise.
     */
    bool ReadFromParcel(Parcel &parcel)
    {
        if (!parcel.ReadString(bundleName)) {
            return false;
        }
        if (!parcel.ReadString(moduleName)) {
            return false;
        }
        if (!parcel.ReadString(skillsName)) {
            return false;
        }
        if (!parcel.ReadString(description)) {
            return false;
        }
        return true;
    }

    /**
     * @brief Write to Parcel.
     * @param parcel Indicates the Parcel object.
     * @return Returns true if write successfully; returns false otherwise.
     */
    virtual bool Marshalling(Parcel &parcel) const override
    {
        if (!parcel.WriteString(bundleName)) {
            return false;
        }
        if (!parcel.WriteString(moduleName)) {
            return false;
        }
        if (!parcel.WriteString(skillsName)) {
            return false;
        }
        if (!parcel.WriteString(description)) {
            return false;
        }
        return true;
    }

    /**
     * @brief Unmarshalling from Parcel.
     * @param parcel Indicates the Parcel object.
     * @return Returns the SkillsPackageInfo object.
     */
    static SkillsPackageInfo *Unmarshalling(Parcel &parcel)
    {
        auto *info = new (std::nothrow) SkillsPackageInfo();
        if (info && info->ReadFromParcel(parcel)) {
            return info;
        }
        delete info;
        return nullptr;
    }

    /**
     * @brief Convert to string for debug.
     * @return Returns the string representation.
     */
    std::string ToString() const
    {
        std::string result = "bundleName: " + bundleName +
                           ", moduleName: " + moduleName +
                           ", skillsName: " + skillsName +
                           ", description: " + description;
        return result;
    }
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_SKILLS_INSTALLER_SKILLS_PACKAGE_INFO_H
