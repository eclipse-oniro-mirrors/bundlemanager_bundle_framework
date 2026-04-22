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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IPC_SKILLS_PACKAGE_PARAM_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IPC_SKILLS_PACKAGE_PARAM_H

#include <map>
#include <string>
#include <vector>

#include "parcel.h"

namespace OHOS {
namespace AppExecFwk {
struct SkillsPackageParam : public Parcelable {
    std::string bundleName;
    std::string moduleName;
    std::string hspPath;
    std::vector<std::string> skillNameList;

    /**
     * @brief Constructor.
     */
    SkillsPackageParam() = default;

    /**
     * @brief Destructor.
     */
    virtual ~SkillsPackageParam() = default;

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
        if (!parcel.ReadString(hspPath)) {
            return false;
        }
        if (!parcel.ReadStringVector(&skillNameList)) {
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
        if (!parcel.WriteString(hspPath)) {
            return false;
        }
        if (!parcel.WriteStringVector(skillNameList)) {
            return false;
        }
        return true;
    }

    /**
     * @brief Unmarshalling from Parcel.
     * @param parcel Indicates the Parcel object.
     * @return Returns the SkillsPackageParam object.
     */
    static SkillsPackageParam *Unmarshalling(Parcel &parcel)
    {
        auto *param = new (std::nothrow) SkillsPackageParam();
        if (param && param->ReadFromParcel(parcel)) {
            return param;
        }
        delete param;
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
                           ", hspPath: " + hspPath +
                           ", skillCount: " + std::to_string(skillNameList.size());
        return result;
    }
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IPC_SKILLS_PACKAGE_PARAM_H
