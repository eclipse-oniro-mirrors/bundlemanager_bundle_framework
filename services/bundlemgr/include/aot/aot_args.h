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

#ifndef FOUNDATION_BUNDLE_FRAMEWORK_AOT_AOT_ARGS
#define FOUNDATION_BUNDLE_FRAMEWORK_AOT_AOT_ARGS

#include "message_parcel.h"

namespace OHOS {
namespace AppExecFwk {
struct HspInfo : public Parcelable {
    std::string bundleName;
    std::string moduleName;
    uint32_t versionCode = 0;
    std::string hapPath;
    uint32_t offset = 0;
    uint32_t length = 0;

    std::string ToString() const;
    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static HspInfo *Unmarshalling(Parcel &parcel);
};

struct AOTArgs : public Parcelable {
    std::string bundleName;
    std::string moduleName;
    std::string compileMode;
    std::string hapPath;
    std::string coreLibPath;
    std::string outputPath;
    std::string arkProfilePath;
    std::string anFileName;
    uint32_t offset = 0;
    uint32_t length = 0;
    std::vector<HspInfo> hspVector;
    int32_t bundleUid = -1;
    int32_t bundleGid = -1;
    std::string appIdentifier;
    uint32_t isEncryptedBundle = 0;
    std::string optBCRangeList;
    uint32_t isScreenOff = 0;
    uint32_t isEnanleBaselinePgo = 0;

    std::string ToString() const;
    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static AOTArgs *Unmarshalling(Parcel &parcel);
};
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_BUNDLE_FRAMEWORK_AOT_AOT_ARGS
