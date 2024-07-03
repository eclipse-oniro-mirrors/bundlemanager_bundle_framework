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

#include "aging/aging_request.h"

#include <cinttypes>

#include "aging/aging_constants.h"
#include "app_log_wrapper.h"
#include "parameter.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string SYSTEM_PARAM_DATA_SIZE_THRESHOLD = "persist.sys.bms.aging.policy.data.size.threshold";
const std::string SYSTEM_PARAM_RECENILY_USED_THRESHOLD = "persist.sys.bms.aging.policy.recently.used.threshold";
}
int64_t AgingRequest::totalDataBytesThreshold_ = AgingConstants::DEFAULT_AGING_DATA_SIZE_THRESHOLD;
int64_t AgingRequest::oneDayTimeMs_ = AgingConstants::ONE_DAYS_MS;

AgingRequest::AgingRequest()
{
    InitAgingPolicySystemParameters();
}

size_t AgingRequest::SortAgingBundles()
{
    AgingUtil::SortAgingBundles(agingBundles_);
    return agingBundles_.size();
}

void AgingRequest::InitAgingDatasizeThreshold()
{
    char szDatasizeThreshold[AgingConstants::THRESHOLD_VAL_LEN] = {0};
    int32_t ret = GetParameter(SYSTEM_PARAM_DATA_SIZE_THRESHOLD.c_str(), "", szDatasizeThreshold,
        AgingConstants::THRESHOLD_VAL_LEN);
    APP_LOGD("ret is %{public}d, szDatasizeThreshold is %{public}d", ret, atoi(szDatasizeThreshold));
    if (ret <= 0) {
        APP_LOGD("GetParameter failed");
        return;
    }

    if (strcmp(szDatasizeThreshold, "") != 0) {
        totalDataBytesThreshold_ = atoi(szDatasizeThreshold);
        APP_LOGD("AgingRequest init aging data size threshold success");
    }
}

void AgingRequest::InitAgingOneDayTimeMs()
{
    char szOneDayTimeMs[AgingConstants::THRESHOLD_VAL_LEN] = {0};
    int32_t ret = GetParameter(SYSTEM_PARAM_RECENILY_USED_THRESHOLD.c_str(), "", szOneDayTimeMs,
        AgingConstants::THRESHOLD_VAL_LEN);
    APP_LOGD("ret is %{public}d, szOneDayTimeMs is %{public}d", ret, atoi(szOneDayTimeMs));
    if (ret <= 0) {
        APP_LOGD("GetParameter failed");
        return;
    }

    if (strcmp(szOneDayTimeMs, "") != 0) {
        oneDayTimeMs_ = atoi(szOneDayTimeMs);
        APP_LOGD("AgingRequest init aging one day time ms success");
    }
}

void AgingRequest::InitAgingPolicySystemParameters()
{
    InitAgingDatasizeThreshold();
    InitAgingOneDayTimeMs();
}

bool AgingRequest::IsReachStartAgingThreshold() const
{
    APP_LOGD("totalDataBytes: %{public}" PRId64 ", totalDataBytesThreshold: %{public}" PRId64,
        totalDataBytes_, totalDataBytesThreshold_);
    return totalDataBytes_ > totalDataBytesThreshold_;
}

bool AgingRequest::IsReachEndAgingThreshold() const
{
    APP_LOGD("totalDataBytes: %{public}" PRId64 ", totalDataBytesThreshold: %{public}" PRId64,
        totalDataBytes_, totalDataBytesThreshold_);
    return totalDataBytes_ < (int64_t)(totalDataBytesThreshold_ * AgingConstants::AGING_SIZE_RATIO);
}

void AgingRequest::AddAgingBundle(AgingBundleInfo &bundleInfo)
{
    agingBundles_.emplace_back(bundleInfo);
}

void AgingRequest::ResetRequest()
{
    agingBundles_.clear();
    agingCleanType_ = AgingCleanType::CLEAN_CACHE;
    totalDataBytes_ = 0;
}

void AgingRequest::Dump()
{
    for (const auto &agingBundle : agingBundles_) {
        APP_LOGD("bundle: %{public}s, lastTimeUsed: %{public}" PRId64 ", startCount: %{public}d",
            agingBundle.GetBundleName().c_str(), agingBundle.GetRecentlyUsedTime(), agingBundle.GetStartCount());
    }
}
}  //  namespace AppExecFwk
}  //  namespace OHOS