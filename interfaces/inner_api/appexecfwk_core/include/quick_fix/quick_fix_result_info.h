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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_INCLUDE_QUICK_FIX_RESULT_INFO_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_INCLUDE_QUICK_FIX_RESULT_INFO_H

#include <string>
#include <vector>

#include "parcel.h"
#include "quick_fix/appqf_info.h"

namespace OHOS {
namespace AppExecFwk {
struct QuickFixResult : public Parcelable {
    QuickFixResult() = default;
    virtual ~QuickFixResult() = default;

    virtual int32_t GetResCode() = 0;
    virtual void SetResCode(int32_t resCode) = 0;
    virtual std::string ToString() const = 0;
};

struct DeployQuickFixResult final : public QuickFixResult {
    int32_t resultCode = -1;
    std::string bundleName;
    uint32_t bundleVersionCode = 0; // bundle version code
    uint32_t patchVersionCode = 0; // patch version code
    bool isSoContained = false;
    QuickFixType type = QuickFixType::UNKNOWN;
    std::vector<std::string> moduleNames;

    DeployQuickFixResult() = default;
    virtual ~DeployQuickFixResult() = default;

    virtual int32_t GetResCode() override;
    virtual void SetResCode(int32_t resCode) override;
    virtual std::string ToString() const override;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static DeployQuickFixResult *Unmarshalling(Parcel &parcel);
};

struct SwitchQuickFixResult final : public QuickFixResult {
    int32_t resultCode = -1;
    std::string bundleName;

    SwitchQuickFixResult() = default;
    virtual ~SwitchQuickFixResult() = default;

    virtual int32_t GetResCode() override;
    virtual void SetResCode(int32_t resCode) override;
    virtual std::string ToString() const override;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static SwitchQuickFixResult *Unmarshalling(Parcel &parcel);
};

struct DeleteQuickFixResult final : public QuickFixResult {
    int32_t resultCode = -1;
    std::string bundleName;

    DeleteQuickFixResult() = default;
    virtual ~DeleteQuickFixResult() = default;

    virtual int32_t GetResCode() override;
    virtual void SetResCode(int32_t resCode) override;
    virtual std::string ToString() const override;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static DeleteQuickFixResult *Unmarshalling(Parcel &parcel);
};
} // AppExecFwk
} // OHOS
#endif // FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_INNERKITS_APPEXECFWK_CORE_INCLUDE_QUICK_FIX_RESULT_INFO_H