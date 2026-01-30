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

#include "bmsondemandinstalldatastoragerdb_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#include "on_demand_install_data_storage_rdb.h"
#include "securec.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    OnDemandInstallDataStorageRdb onDemandInstallDataStorageRdb;
    FuzzedDataProvider fdp(data, size);
    PreInstallBundleInfo preInstallBundleInfo;
    onDemandInstallDataStorageRdb.SaveOnDemandInstallBundleInfo(preInstallBundleInfo);
    std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    onDemandInstallDataStorageRdb.DeleteOnDemandInstallBundleInfo(bundleName);
    onDemandInstallDataStorageRdb.DeleteOnDemandInstallBundleInfo("");
    onDemandInstallDataStorageRdb.GetOnDemandInstallBundleInfo(bundleName, preInstallBundleInfo);
    onDemandInstallDataStorageRdb.GetOnDemandInstallBundleInfo("", preInstallBundleInfo);
    std::vector<PreInstallBundleInfo> preInstallBundleInfos;
    onDemandInstallDataStorageRdb.GetAllOnDemandInstallBundleInfos(preInstallBundleInfos);
    std::map<std::string, std::string> datas;
    onDemandInstallDataStorageRdb.TransformStrToInfo(datas, preInstallBundleInfos);
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