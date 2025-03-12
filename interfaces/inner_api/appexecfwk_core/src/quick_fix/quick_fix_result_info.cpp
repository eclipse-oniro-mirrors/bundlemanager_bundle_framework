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

#include "app_log_tag_wrapper.h"
#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "nlohmann/json.hpp"
#include "parcel_macro.h"
#include "quick_fix_result_info.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const char* QUICK_FIX_RESULT_CODE = "resultCode";
const char* QUICK_FIX_BUNDLE_NAME = "bundleName";
const char* QUICK_FIX_BUNDLE_VERSION_CODE = "bundleVersionCode";
const char* QUICK_FIX_PATCH_VERSION_CODE = "patchVersionCode";
const char* QUICK_FIX_IS_SO_CONTAINED = "isSoContained";
const char* QUICK_FIX_TYPE = "type";
const char* QUICK_FIX_MODULE_NAME = "moduleNames";
} // namespace

bool DeployQuickFixResult::ReadFromParcel(Parcel &parcel)
{
    resultCode = parcel.ReadInt32();
    bundleName = parcel.ReadString();
    bundleVersionCode = parcel.ReadUint32();
    patchVersionCode = parcel.ReadUint32();
    isSoContained = parcel.ReadBool();
    type = static_cast<QuickFixType>(parcel.ReadInt32());
    int32_t moduleNameSize = parcel.ReadInt32();
    CONTAINER_SECURITY_VERIFY(parcel, moduleNameSize, &moduleNames);
    for (int32_t index = 0; index < moduleNameSize; ++index) {
        moduleNames.emplace_back(parcel.ReadString());
    }
    return true;
}

bool DeployQuickFixResult::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, resultCode);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, bundleName);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, bundleVersionCode);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, patchVersionCode);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isSoContained);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, static_cast<int32_t>(type));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, moduleNames.size());
    for (const auto &name : moduleNames) {
        WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, name);
    }
    return true;
}

DeployQuickFixResult *DeployQuickFixResult::Unmarshalling(Parcel &parcel)
{
    DeployQuickFixResult *info = new (std::nothrow) DeployQuickFixResult();
    if ((info != nullptr) && (!info->ReadFromParcel(parcel))) {
        LOG_E(BMS_TAG_DEFAULT, "read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

std::string DeployQuickFixResult::ToString() const
{
    nlohmann::json deployResultJson = nlohmann::json {
        { QUICK_FIX_RESULT_CODE, resultCode },
        { QUICK_FIX_BUNDLE_NAME, bundleName },
        { QUICK_FIX_BUNDLE_VERSION_CODE, bundleVersionCode },
        { QUICK_FIX_PATCH_VERSION_CODE, patchVersionCode },
        { QUICK_FIX_IS_SO_CONTAINED, isSoContained },
        { QUICK_FIX_TYPE, static_cast<int32_t>(type) },
        { QUICK_FIX_MODULE_NAME, moduleNames }
    };
    return deployResultJson.dump(Constants::DUMP_INDENT);
}

void DeployQuickFixResult::SetResCode(int32_t resCode)
{
    resultCode = resCode;
}

int32_t DeployQuickFixResult::GetResCode()
{
    return resultCode;
}

bool SwitchQuickFixResult::ReadFromParcel(Parcel &parcel)
{
    resultCode = parcel.ReadInt32();
    bundleName = parcel.ReadString();
    return true;
}

bool SwitchQuickFixResult::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, resultCode);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, bundleName);
    return true;
}

SwitchQuickFixResult *SwitchQuickFixResult::Unmarshalling(Parcel &parcel)
{
    SwitchQuickFixResult *info = new (std::nothrow) SwitchQuickFixResult();
    if ((info != nullptr) && (!info->ReadFromParcel(parcel))) {
        LOG_E(BMS_TAG_DEFAULT, "read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

std::string SwitchQuickFixResult::ToString() const
{
    nlohmann::json switchResultJson = nlohmann::json {
        { QUICK_FIX_RESULT_CODE, resultCode },
        { QUICK_FIX_BUNDLE_NAME, bundleName }
    };
    return switchResultJson.dump(Constants::DUMP_INDENT);
}

int32_t SwitchQuickFixResult::GetResCode()
{
    return resultCode;
}

void SwitchQuickFixResult::SetResCode(int32_t resCode)
{
    resultCode = resCode;
}

bool DeleteQuickFixResult::ReadFromParcel(Parcel &parcel)
{
    resultCode = parcel.ReadInt32();
    bundleName = parcel.ReadString();
    return true;
}

bool DeleteQuickFixResult::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, resultCode);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, bundleName);
    return true;
}

DeleteQuickFixResult *DeleteQuickFixResult::Unmarshalling(Parcel &parcel)
{
    DeleteQuickFixResult *info = new (std::nothrow) DeleteQuickFixResult();
    if ((info != nullptr) && (!info->ReadFromParcel(parcel))) {
        LOG_E(BMS_TAG_DEFAULT, "read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

std::string DeleteQuickFixResult::ToString() const
{
    nlohmann::json deleteResultJson = nlohmann::json {
        { QUICK_FIX_RESULT_CODE, resultCode },
        { QUICK_FIX_BUNDLE_NAME, bundleName }
    };
    return deleteResultJson.dump(Constants::DUMP_INDENT);
}

int32_t DeleteQuickFixResult::GetResCode()
{
    return resultCode;
}

void DeleteQuickFixResult::SetResCode(int32_t resCode)
{
    resultCode = resCode;
}
} // AppExecFwk
} // OHOS