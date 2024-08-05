/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "ipc/file_stat.h"

#include "parcel_macro.h"

namespace OHOS {
namespace AppExecFwk {
bool FileStat::ReadFromParcel(Parcel &parcel)
{
    uid = parcel.ReadInt32();
    gid = parcel.ReadInt32();
    lastModifyTime = parcel.ReadInt64();
    isDir = parcel.ReadBool();
    mode = parcel.ReadInt32();
    return true;
}

bool FileStat::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, uid);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, gid);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int64, parcel, lastModifyTime);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isDir);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, mode);
    return true;
}

FileStat *FileStat::Unmarshalling(Parcel &parcel)
{
    FileStat *info = new (std::nothrow) FileStat();
    if (info) {
        info->ReadFromParcel(parcel);
    }
    return info;
}
}  // namespace AppExecFwk
}  // namespace OHOS
