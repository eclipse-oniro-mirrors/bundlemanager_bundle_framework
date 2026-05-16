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

#ifndef BUNDLE_FRAMEWORK_HISTOGRAM_UTIL_H
#define BUNDLE_FRAMEWORK_HISTOGRAM_UTIL_H

#include <cstdint>
#include <string>

namespace OHOS {
namespace AppExecFwk {
enum class CommonErrorType {
    OPERATION_SUCCESS,
    OPERATION_FAILED,
    INVALID_PARAM,
    UNSUPPORTED_FEATURE_ERRCODE
};

class HistogramUtil {
public:
    static void ReportHistogramBoolean(const std::string& name, bool sample);
    static void ReportHistogramEnumeration(const std::string& name, int32_t sample, int32_t boundary);
    static void ReportHistogramCount(const std::string& name, int32_t sample,
        int32_t min, int32_t max, int32_t bucketCount);
    static void ReportHistogramTimes(const std::string& name, int32_t sampleMs);
    static void ReportHistogramPercentage(const std::string& name, int32_t sample);

private:
    HistogramUtil() = default;
    ~HistogramUtil() = default;
    static void ConvertErrorCodeToHistogramEnumeration(int32_t& errCode);
};
} // namespace AppExecFwk
} // namespace OHOS

#endif // BUNDLE_FRAMEWORK_HISTOGRAM_UTIL_H
