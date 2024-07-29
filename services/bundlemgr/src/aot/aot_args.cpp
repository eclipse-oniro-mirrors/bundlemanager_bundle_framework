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

#include "aot/aot_args.h"

#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr uint32_t MAX_HSP_VECTOR_SIZE = 10000;
}
bool HspInfo::ReadFromParcel(Parcel &parcel)
{
    std::u16string bundleNameVal;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, bundleNameVal);
    bundleName = Str16ToStr8(bundleNameVal);
    std::u16string moduleNameVal;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, moduleNameVal);
    moduleName = Str16ToStr8(moduleNameVal);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, versionCode);
    std::u16string hapPathVal;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, hapPathVal);
    hapPath = Str16ToStr8(hapPathVal);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, offset);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, length);
    return true;
}

bool HspInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(moduleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, versionCode);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(hapPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, offset);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, length);
    return true;
}

HspInfo *HspInfo::Unmarshalling(Parcel &parcel)
{
    HspInfo *hspInfo = new (std::nothrow) HspInfo();
    if (hspInfo && !hspInfo->ReadFromParcel(parcel)) {
        APP_LOGE("read HspInfo from parcel failed");
        delete hspInfo;
        hspInfo = nullptr;
    }
    return hspInfo;
}

std::string HspInfo::ToString() const
{
    return "[ bundleName = " +  bundleName
            + ", moduleName = " + moduleName
            + ", versionCode = " + std::to_string(versionCode)
            + ", hapPath = " + hapPath
            + ", offset = " + std::to_string(offset)
            + ", length = " + std::to_string(length) + "]";
}

bool AOTArgs::ReadFromParcel(Parcel &parcel)
{
    std::u16string bundleNameVal;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, bundleNameVal);
    bundleName = Str16ToStr8(bundleNameVal);
    std::u16string moduleNameVal;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, moduleNameVal);
    moduleName = Str16ToStr8(moduleNameVal);
    std::u16string compileModeVal;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, compileModeVal);
    compileMode = Str16ToStr8(compileModeVal);
    std::u16string hapPathVal;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, hapPathVal);
    hapPath = Str16ToStr8(hapPathVal);
    std::u16string coreLibPathVal;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, coreLibPathVal);
    coreLibPath = Str16ToStr8(coreLibPathVal);
    std::u16string outputPathVal;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, outputPathVal);
    outputPath = Str16ToStr8(outputPathVal);
    std::u16string arkProfilePathVal;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, arkProfilePathVal);
    arkProfilePath = Str16ToStr8(arkProfilePathVal);
    std::u16string anFileNameVal;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, anFileNameVal);
    anFileName = Str16ToStr8(anFileNameVal);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, offset);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, length);
    uint32_t hspVectorSize = 0;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, hspVectorSize);
    hspVectorSize = std::min(hspVectorSize, MAX_HSP_VECTOR_SIZE);
    for (uint32_t i = 0; i < hspVectorSize; ++i) {
        std::unique_ptr<HspInfo> hspInfoPtr(parcel.ReadParcelable<HspInfo>());
        if (!hspInfoPtr) {
            APP_LOGE("read HspInfo failed");
            return false;
        }
        hspVector.emplace_back(*hspInfoPtr);
    }
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, bundleUid);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, bundleGid);
    std::u16string appIdentifilerVal;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, appIdentifilerVal);
    appIdentifier = Str16ToStr8(appIdentifilerVal);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, isEncryptedBundle);
    std::u16string optBCRangeVal;
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, optBCRangeVal);
    optBCRangeList = Str16ToStr8(optBCRangeVal);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, isScreenOff);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, isEnanleBaselinePgo);
    return true;
}

bool AOTArgs::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(moduleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(compileMode));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(hapPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(coreLibPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(outputPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(arkProfilePath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(anFileName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, offset);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, length);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, hspVector.size());
    for (const auto &hspInfo : hspVector) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &hspInfo);
    }
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, bundleUid);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, bundleGid);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(appIdentifier));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, isEncryptedBundle);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(optBCRangeList));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, isScreenOff);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, isEnanleBaselinePgo);
    return true;
}

AOTArgs *AOTArgs::Unmarshalling(Parcel &parcel)
{
    AOTArgs *aotArgs = new (std::nothrow) AOTArgs();
    if (aotArgs && !aotArgs->ReadFromParcel(parcel)) {
        APP_LOGE("read AOTArgs from parcel failed");
        delete aotArgs;
        aotArgs = nullptr;
    }
    return aotArgs;
}

std::string AOTArgs::ToString() const
{
    std::string ret = "[ bundleName = " +  bundleName
        + ", moduleName = " + moduleName
        + ", compileMode = " + compileMode
        + ", hapPath = " + hapPath
        + ", coreLibPath = " + coreLibPath
        + ", outputPath = " + outputPath
        + ", arkProfilePath = " + arkProfilePath
        + ", anFileName = " + anFileName
        + ", offset = " + std::to_string(offset)
        + ", length = " + std::to_string(length)
        + ", bundleUid = " + std::to_string(bundleUid)
        + ", bundleGid = " + std::to_string(bundleGid)
        + ", appIdentifier = " + appIdentifier
        + ", isEncryptedBundle = " + std::to_string(isEncryptedBundle)
        + ", optBCRangeList = " + optBCRangeList
        + ", isScreenOff = " + std::to_string(isScreenOff)
        + ", isEnanleBaselinePgo = " + std::to_string(isEnanleBaselinePgo) + "]";
    ret.append(" hspVector = ");
    for (const auto &hspInfo : hspVector) {
        ret.append(hspInfo.ToString());
    }
    return ret;
}
}  // namespace AppExecFwk
}  // namespace OHOS
