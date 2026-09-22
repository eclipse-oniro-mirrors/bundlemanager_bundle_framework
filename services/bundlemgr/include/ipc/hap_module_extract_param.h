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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IPC_HAP_MODULE_EXTRACT_PARAM_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IPC_HAP_MODULE_EXTRACT_PARAM_H

#include <string>

#include "installd/installd_constants.h"
#include "message_parcel.h"

namespace OHOS {
namespace AppExecFwk {
struct HapModuleExtractParam : public Parcelable {
    std::string bundleName;           // effectiveBundleName
    std::string moduleName;           // modulePackage
    std::string hapCopySubDir;        // dynamic sub dir under HAP_COPY_PATH/SECURITY_STREAM_INSTALL_PATH
    std::string hapFileName;          // hap file name, e.g. entry.hap
    std::string nativeLibraryPath;    // nativeLibraryPath (may be empty)
    std::string cpuAbi;               // CPU ABI
    int32_t installMode = static_cast<int32_t>(HapExtractMode::NORMAL);  // 0=NORMAL, 1=MODULE_UPDATE, 2=BUNDLE_UPDATE
    bool needFakeDecompression = false;
    bool isSystemApp = false;
    std::string hapSrcPath;           // external hap path for pre-install/OTA when not stream install

    std::string ToString() const;
    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static HapModuleExtractParam *Unmarshalling(Parcel &parcel);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IPC_HAP_MODULE_EXTRACT_PARAM_H
