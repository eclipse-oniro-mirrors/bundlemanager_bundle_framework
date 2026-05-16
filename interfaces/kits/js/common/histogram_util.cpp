/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "histogram_util.h"

#include "app_log_tag_wrapper.h"
#include "business_error_map.h"
#ifdef API_METRICS_ENABLE
#include "histogram_plugin_macros.h"
#endif

namespace OHOS {
namespace AppExecFwk {
constexpr int32_t UNSUPPORTED_FEATURE_ERRCODE = 801;
constexpr int32_t CODE_FAILED = -1;
void HistogramUtil::ReportHistogramBoolean(const std::string& name, bool sample)
{
#ifdef API_METRICS_ENABLE
    LOG_NOFUNC_D(BMS_TAG_DEFAULT, "HistogramBoolean name: %{public}s, sample: %{public}d", name.c_str(), sample);
    HISTOGRAM_BOOLEAN(name.c_str(), static_cast<int32_t>(sample));
#endif
}

void HistogramUtil::ReportHistogramEnumeration(const std::string& name, int32_t sample, int32_t boundary)
{
#ifdef API_METRICS_ENABLE
    ConvertErrorCodeToHistogramEnumeration(sample);
    LOG_NOFUNC_D(BMS_TAG_DEFAULT, "HistogramEnumeration name: %{public}s, sample: %{public}d", name.c_str(), sample);
    HISTOGRAM_ENUMERATION(name.c_str(), sample, boundary);
#endif
}

void HistogramUtil::ReportHistogramCount(const std::string& name, int32_t sample,
    int32_t min, int32_t max, int32_t bucketCount)
{
#ifdef API_METRICS_ENABLE
    LOG_NOFUNC_D(BMS_TAG_DEFAULT, "HistogramCount name: %{public}s, sample: %{public}d", name.c_str(), sample);
    HISTOGRAM_CUSTOM_COUNTS(name.c_str(), sample, min, max, bucketCount);
#endif
}

void HistogramUtil::ReportHistogramTimes(const std::string& name, int32_t sampleMs)
{
#ifdef API_METRICS_ENABLE
    LOG_NOFUNC_D(BMS_TAG_DEFAULT, "HistogramTimes name: %{public}s, sampleMs: %{public}d", name.c_str(), sampleMs);
    HISTOGRAM_TIMES(name.c_str(), sampleMs);
#endif
}

void HistogramUtil::ReportHistogramPercentage(const std::string& name, int32_t sample)
{
#ifdef API_METRICS_ENABLE
    LOG_NOFUNC_D(BMS_TAG_DEFAULT, "HistogramPercentage name: %{public}s, sample: %{public}d", name.c_str(), sample);
    HISTOGRAM_PERCENTAGE(name.c_str(), sample);
#endif
}

void HistogramUtil::ConvertErrorCodeToHistogramEnumeration(int32_t& errCode)
{
    switch (errCode) {
        case UNSUPPORTED_FEATURE_ERRCODE:
            errCode = static_cast<int32_t>(CommonErrorType::UNSUPPORTED_FEATURE_ERRCODE);
            break;
        case CODE_FAILED:
            errCode = static_cast<int32_t>(CommonErrorType::OPERATION_FAILED);
            break;
        default:
            break;
    }
}
} // namespace AppExecFwk
} // namespace OHOS
