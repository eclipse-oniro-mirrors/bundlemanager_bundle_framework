/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IPC_CREATE_DIR_PARAM_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IPC_CREATE_DIR_PARAM_H

#include <string>

#include "bundle_dir.h"
#include "message_parcel.h"

namespace OHOS {
namespace AppExecFwk {
enum class CreateDirFlag : uint8_t {
    // Create all data directories regardless of whether the device is unlocked.
    // Inaccessible directories will fail to be created and errors will be ignored.
    CREATE_DIR_ALL = 0,
    // Only create directories that are inaccessible without unlocking.
    CREATE_DIR_UNLOCKED = 1
};

struct CreateDirParam : public Parcelable {
    bool isPreInstallApp = false;
    bool debug = false;
    bool isDlpSandbox = false;
    CreateDirFlag createDirFlag = CreateDirFlag::CREATE_DIR_ALL;
    DataDirEl dataDirEl = DataDirEl::NONE;
    int32_t userId = -1;
    int32_t uid = -1;
    int32_t gid = -1;
    int32_t appIndex = 0;
    std::string bundleName;
    std::string apl;
    std::vector<std::string> extensionDirs;
    std::string uuid;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static CreateDirParam *Unmarshalling(Parcel &parcel);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IPC_CREATE_DIR_PARAM_H
