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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IPC_EXTRACT_MODULE_FILES_PARAM_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IPC_EXTRACT_MODULE_FILES_PARAM_H

#include <string>

#include "parcel.h"

namespace OHOS {
namespace AppExecFwk {
struct ExtractModuleFilesParam : public Parcelable {
    // host bundle name, only used by plugin (Compatible with ExtractPluginModuleFiles)
    std::string hostBundleName;
    // bundle name with install timestamp, only used by plugin (Compatible with ExtractPluginModuleFiles)
    std::string bundleNameWithTime;
    // bundle name, only used by service/shared (Compatible with ExtractServiceModuleFiles/ExtractSharedModuleFiles)
    std::string bundleName;
    // version code, only used by service/shared (Compatible with ExtractServiceModuleFiles/ExtractSharedModuleFiles)
    int32_t versionCode = 0;
    // module name, used by all three scenarios
    std::string moduleName;
    // source hap/hsp file path, used by all three scenarios
    std::string bundlePath;
    // native library relative path inside the bundle, may contain multiple path segments, used by all three scenarios
    std::string nativeLibraryPath;
    // cpu abi, used by all three scenarios
    std::string cpuAbi;
    // whether to perform fake decompression, used by all three scenarios
    bool needFakeDecompression = false;
    // whether the bundle is a system app, used by all three scenarios
    bool isSystemApp = false;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static ExtractModuleFilesParam *Unmarshalling(Parcel &parcel);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_IPC_EXTRACT_MODULE_FILES_PARAM_H
