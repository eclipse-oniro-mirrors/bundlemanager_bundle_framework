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

#include "bundle_hitrace_chain.h"

namespace OHOS {
namespace AppExecFwk {
BundleHitraceChain::BundleHitraceChain(const std::string &name, HiTraceFlag flags)
{
    if (!HiviewDFX::HiTraceChain::GetId().IsValid()) {
        traceId_ = HiviewDFX::HiTraceChain::Begin(name, flags);
    }
}

BundleHitraceChain::~BundleHitraceChain()
{
    if (traceId_.IsValid()) {
        HiviewDFX::HiTraceChain::End(traceId_);
    }
}

TaskHitraceChain::TaskHitraceChain(const HiviewDFX::HiTraceId &taskTraceId)
{
    if (taskTraceId.IsValid()) {
        HiviewDFX::HiTraceChain::SetId(taskTraceId);
    }
}

TaskHitraceChain::~TaskHitraceChain()
{
    HiviewDFX::HiTraceChain::ClearId();
}

} // AppExecFwk
} // OHOS