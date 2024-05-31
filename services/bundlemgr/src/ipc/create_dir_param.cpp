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

#include "ipc/create_dir_param.h"

#include "app_log_wrapper.h"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
bool CreateDirParam::ReadFromParcel(Parcel &parcel)
{
    bundleName = Str16ToStr8(parcel.ReadString16());
    int32_t extensionDirsSize;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, extensionDirsSize);
    CONTAINER_SECURITY_VERIFY(parcel, extensionDirsSize, &extensionDirs);
    for (int32_t i = 0; i < extensionDirsSize; ++i) {
        std::string extensionDir = Str16ToStr8(parcel.ReadString16());
        extensionDirs.emplace_back(extensionDir);
    }
    apl = Str16ToStr8(parcel.ReadString16());
    userId = parcel.ReadInt32();
    uid = parcel.ReadInt32();
    gid = parcel.ReadInt32();
    isPreInstallApp = parcel.ReadBool();
    debug = parcel.ReadBool();
    isDlpSandbox = parcel.ReadBool();
    createDirFlag = static_cast<CreateDirFlag>(parcel.ReadInt32());
    return true;
}

bool CreateDirParam::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, extensionDirs.size());
    for (auto &item : extensionDirs) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(item));
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(apl));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, userId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, uid);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, gid);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isPreInstallApp);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, debug);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isDlpSandbox);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(createDirFlag));
    return true;
}

CreateDirParam *CreateDirParam::Unmarshalling(Parcel &parcel)
{
    CreateDirParam *info = new (std::nothrow) CreateDirParam();
    if (info) {
        info->ReadFromParcel(parcel);
    }
    return info;
}
}  // namespace AppExecFwk
}  // namespace OHOS
