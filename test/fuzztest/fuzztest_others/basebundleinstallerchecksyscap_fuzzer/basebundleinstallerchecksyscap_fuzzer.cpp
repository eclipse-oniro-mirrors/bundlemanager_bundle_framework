/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#define private public
#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include "basebundleinstallerchecksyscap_fuzzer.h"
#include "base_bundle_installer.h"
#include "bms_fuzztest_util.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {

    bool DoSomethingInterestingWithMyAPI(const uint8_t *data, size_t size)
    {
        BaseBundleInstaller basebundleinstall;
        FuzzedDataProvider fdp(data, size);
        std::vector<std::string> bundlePaths = {fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH)};
        auto ret1 = basebundleinstall.CheckSysCap(bundlePaths);
        return true;
    }
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}