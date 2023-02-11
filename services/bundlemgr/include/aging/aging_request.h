/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_AGING_REQUEST_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_AGING_REQUEST_H

#include <vector>
#include <set>

#include "aging_bundle_info.h"
#include "aging_util.h"

namespace OHOS {
namespace AppExecFwk {
enum class AgingCleanType {
    CLEAN_CACHE = 0,
    CLEAN_OTHERS,
};

class AgingRequest {
public:
    AgingRequest();
    bool IsReachStartAgingThreshold() const;
    bool IsReachEndAgingThreshold() const;
    size_t SortAgingBundles();
    void ResetRequest();
    void Dump();
    void AddAgingBundle(AgingBundleInfo &bundleInfo);

    const std::vector<AgingBundleInfo> &GetAgingBundles() const
    {
        return agingBundles_;
    };

    void UpdateTotalDataBytesAfterUninstalled(const int64_t dataBytes)
    {
        tatalDataBytes_ -= dataBytes;
    };

    int64_t GetTotalDataBytes() const
    {
        return tatalDataBytes_;
    };

    void SetTotalDataBytes(const int64_t allBundleDataBytes)
    {
        tatalDataBytes_ = allBundleDataBytes;
    };

    void SetAgingCleanType(const AgingCleanType agingCleanType)
    {
        agingCleanType_ = agingCleanType;
    };

    AgingCleanType GetAgingCleanType() const
    {
        return agingCleanType_;
    };

    static int64_t GetTotalDataBytesThreshold()
    {
        return totalDataBytesThreshold_;
    };

    static int64_t GetOneDayTimeMs()
    {
        return oneDayTimeMs_;
    };

private:
    void InitAgingPolicySystemParameters();
    void InitAgingDatasizeThreshold();
    void InitAgingOneDayTimeMs();

    std::vector<AgingBundleInfo> agingBundles_;
    int64_t tatalDataBytes_ = 0;
    AgingCleanType agingCleanType_ = AgingCleanType::CLEAN_CACHE;

    static int64_t totalDataBytesThreshold_;
    static int64_t oneDayTimeMs_;
};
}  //  namespace AppExecFwk
}  //  namespace OHOS

#endif  //  FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_AGING_REQUEST_H
