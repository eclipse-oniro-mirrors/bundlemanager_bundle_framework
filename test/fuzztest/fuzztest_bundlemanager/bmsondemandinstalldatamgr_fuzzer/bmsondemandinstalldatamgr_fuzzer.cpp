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

#include "bmsondemandinstalldatamgr_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#include "on_demand_install_data_mgr.h"
#include "securec.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    OnDemandInstallDataMgr onDemandInstallDataMgr;
    FuzzedDataProvider fdp(data, size);
    std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    PreInstallBundleInfo preInstallBundleInfo;
    onDemandInstallDataMgr.SaveOnDemandInstallBundleInfo(bundleName, preInstallBundleInfo);
    onDemandInstallDataMgr.DeleteOnDemandInstallBundleInfo(bundleName);
    onDemandInstallDataMgr.GetOnDemandInstallBundleInfo("", preInstallBundleInfo);
    onDemandInstallDataMgr.GetOnDemandInstallBundleInfo(bundleName, preInstallBundleInfo);
    std::vector<PreInstallBundleInfo> preInstallBundleInfos;
    onDemandInstallDataMgr.GetAllOnDemandInstallBundleInfos(preInstallBundleInfos);
    onDemandInstallDataMgr.DeleteNoDataPreloadBundleInfos();
    InstallParam installParam;
    onDemandInstallDataMgr.IsOnDemandInstall(installParam);
    std::string bundlePath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    onDemandInstallDataMgr.GetAppidentifier(bundlePath);
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