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

#ifndef FOUNDATION_APPEXECFWK_STANDARD_COMMON_LOG_INCLUDE_BUNDLE_HITRACE_CHAIN_H
#define FOUNDATION_APPEXECFWK_STANDARD_COMMON_LOG_INCLUDE_BUNDLE_HITRACE_CHAIN_H

#include "hitracechain.h"

#define BUNDLE_MANAGER_HITRACE_CHAIN_NAME(name, flag) BundleHitraceChain traceid(name, flag)
#define BUNDLE_MANAGER_TASK_CHAIN_ID(taskTraceId) TaskHitraceChain traceid(taskTraceId)

namespace OHOS {
namespace AppExecFwk {
class BundleHitraceChain {
public:
    BundleHitraceChain(const std::string &name, HiTraceFlag flags);

    ~BundleHitraceChain();
private:
    HiviewDFX::HiTraceId traceId_;
};

class TaskHitraceChain {
public:
    TaskHitraceChain(const HiviewDFX::HiTraceId &taskTraceId);

    ~TaskHitraceChain();
};

} // AppExecFwk
} // OHOS

#endif // #define FOUNDATION_APPEXECFWK_STANDARD_COMMON_LOG_INCLUDE_BUNDLE_HITRACE_CHAIN_H
