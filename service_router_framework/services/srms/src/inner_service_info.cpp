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
InnerServiceInfo::InnerServiceInfo()
{
}

InnerServiceInfo::~InnerServiceInfo()
{
    serviceInfos_.clear();
    intentInfos_.clear();
}

void InnerServiceInfo::FindServiceInfos(const ExtensionServiceType &serviceType,
    std::vector<ServiceInfo> &serviceInfos) const
{
    for (auto &serviceInfo : serviceInfos_) {
        if (serviceInfo.serviceType == serviceType) {
            serviceInfos.emplace_back(serviceInfo);
        }
    }
}

void InnerServiceInfo::FindIntentInfos(const std::string &intentName, std::vector<IntentInfo> &intentInfos) const
{
    for (auto &intentInfo : intentInfos_) {
        if (intentInfo.intentName == intentName) {
            intentInfos.emplace_back(intentInfo);
        }
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
