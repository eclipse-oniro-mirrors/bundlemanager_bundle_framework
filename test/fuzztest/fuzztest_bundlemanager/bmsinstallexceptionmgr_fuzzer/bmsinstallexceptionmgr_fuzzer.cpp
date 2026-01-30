/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include "bmsinstallexceptionmgr_fuzzer.h"
#define private public
#include "install_exception_mgr.h"
#undef private
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    auto installExceptionMgr = DelayedSingleton<InstallExceptionMgr>::GetInstance();
    FuzzedDataProvider fdp(data, size);
    std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    InstallExceptionInfo installExceptionInfo;
    installExceptionMgr->SaveBundleExceptionInfo(bundleName, installExceptionInfo);
    installExceptionMgr->DeleteBundleExceptionInfo(bundleName);
    installExceptionMgr->HandleBundleExceptionInfo(bundleName, installExceptionInfo);
    installExceptionMgr->HandleAllBundleExceptionInfo();
    installExceptionMgr->installExceptionMgr_->SaveBundleExceptionInfo(bundleName, installExceptionInfo);
    installExceptionMgr->installExceptionMgr_->DeleteBundleExceptionInfo(bundleName);
    std::map<std::string, InstallExceptionInfo> bundleExceptionInfos;
    installExceptionMgr->installExceptionMgr_->GetAllBundleExceptionInfo(bundleExceptionInfos);
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
