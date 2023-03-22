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

#include "inner_service_info.h"

namespace OHOS {
namespace AppExecFwk {
void InnerServiceInfo::FindBusinessAbilityInfos(const BusinessType &businessType,
    std::vector<BusinessAbilityInfo> &businessAbililtyInfos) const
{
    for (auto &businessAbililtyInfo : businessAbilityInfos_) {
        if (businessAbililtyInfo.businessType == businessType) {
            businessAbililtyInfos.emplace_back(businessAbililtyInfo);
        }
    }
}

void InnerServiceInfo::FindPurposeInfos(const std::string &purposeName, std::vector<PurposeInfo> &purposeInfos) const
{
    for (auto &purposeInfo : purposeInfos_) {
        if (purposeInfo.purposeName == purposeName) {
            purposeInfos.emplace_back(purposeInfo);
        }
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
