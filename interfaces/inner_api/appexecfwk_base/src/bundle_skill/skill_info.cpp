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

#include "bundle_skill/skill_info.h"
#include "parcel_macro.h"

namespace OHOS {
namespace AppExecFwk {

bool SkillInfo::ReadFromParcel(Parcel &parcel)
{
    bundleName = parcel.ReadString();
    moduleName = parcel.ReadString();
    skillName = parcel.ReadString();
    skillId = parcel.ReadInt32();
    skillType = static_cast<SkillType>(parcel.ReadInt32());
    hapPath = parcel.ReadString();
    skillPath = parcel.ReadString();
    abilityName = parcel.ReadString();
    description = parcel.ReadString();

    int32_t srcEntriesSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, srcEntriesSize);
    CONTAINER_SECURITY_VERIFY(parcel, srcEntriesSize, &srcEntries);
    for (int32_t i = 0; i < srcEntriesSize; i++) {
        srcEntries.emplace_back(parcel.ReadString());
    }

    int32_t permissionsSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, permissionsSize);
    CONTAINER_SECURITY_VERIFY(parcel, permissionsSize, &permissions);
    for (int32_t i = 0; i < permissionsSize; i++) {
        permissions.emplace_back(parcel.ReadString());
    }

    int32_t requestPermissionsSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, requestPermissionsSize);
    CONTAINER_SECURITY_VERIFY(parcel, requestPermissionsSize, &requestPermissions);
    for (int32_t i = 0; i < requestPermissionsSize; i++) {
        requestPermissions.emplace_back(parcel.ReadString());
    }
    return true;
}

bool SkillInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, bundleName);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, moduleName);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, skillName);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, skillId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(skillType));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, hapPath);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, skillPath);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, abilityName);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, description);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, srcEntries.size());
    for (const auto &entry : srcEntries) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, entry);
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, permissions.size());
    for (const auto &permission : permissions) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, permission);
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, requestPermissions.size());
    for (const auto &reqPermission : requestPermissions) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, reqPermission);
    }
    return true;
}

SkillInfo *SkillInfo::Unmarshalling(Parcel &parcel)
{
    auto *info = new (std::nothrow) SkillInfo();
    if (info == nullptr) {
        return nullptr;
    }
    if (!info->ReadFromParcel(parcel)) {
        delete info;
        return nullptr;
    }
    return info;
}

} // namespace AppExecFwk
} // namespace OHOS
