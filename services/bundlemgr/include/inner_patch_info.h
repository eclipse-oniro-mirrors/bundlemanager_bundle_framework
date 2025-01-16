/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INNER_PATCH_INFO_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INNER_PATCH_INFO_H

#include <string>

#include "json_util.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace AppExecFwk {

enum class AppPatchType : uint8_t {
    DEFAULT         = 0,
    INTERNAL        = 1,
    SERVICE_FWK     = 2,
    SHARED_BUNDLES  = 3,
};

struct PatchInfo {
    uint32_t versionCode = 0;
    AppPatchType appPatchType = AppPatchType::DEFAULT;
};

class InnerPatchInfo {
public:
    InnerPatchInfo() {};
    ~InnerPatchInfo() {};

    bool FromJson(const std::string &jsonObject);
    std::string ToString() const;
    void SetPatchInfo(const PatchInfo &patchInfo)
    {
        patchInfo_ = patchInfo;
    }

    uint32_t GetVersionCode() const
    {
        return patchInfo_.versionCode;
    }

    AppPatchType GetAppPatchType() const
    {
        return patchInfo_.appPatchType;
    }

private:
    void ToJson(nlohmann::json &jsonObject) const;
    PatchInfo patchInfo_;
};

}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_INNER_PATCH_INFO_H
