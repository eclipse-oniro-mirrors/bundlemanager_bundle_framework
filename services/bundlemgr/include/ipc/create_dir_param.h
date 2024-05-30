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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IPC_CREATE_DIR_PARAM_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IPC_CREATE_DIR_PARAM_H

#include <map>
#include <string>
#include "message_parcel.h"

namespace OHOS {
namespace AppExecFwk {
enum class CreateDirFlag {
    // Create all data directories regardless of whether the device is unlocked.
    // Inaccessible directories will fail to be created and errors will be ignored.
    CREATE_DIR_ALL = 0,
    // Only create directories that are inaccessible without unlocking.
    CREATE_DIR_UNLOCKED = 1,
    // Fix the properties of folders and files
    FIX_DIR_AND_FILES_PROPERTIES = 2
};

struct CreateDirParam : public Parcelable {
    std::string bundleName;
    std::vector<std::string> extensionDirs;
    int32_t userId;
    int32_t uid;
    int32_t gid;
    std::string apl;
    bool isPreInstallApp = false;
    bool debug = false;
    bool isDlpSandbox = false;
    CreateDirFlag createDirFlag = CreateDirFlag::CREATE_DIR_ALL;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static CreateDirParam *Unmarshalling(Parcel &parcel);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IPC_CREATE_DIR_PARAM_H
