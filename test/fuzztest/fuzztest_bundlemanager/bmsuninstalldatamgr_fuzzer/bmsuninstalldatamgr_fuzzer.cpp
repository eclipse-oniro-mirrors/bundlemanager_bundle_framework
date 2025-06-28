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

#define private public
#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "uninstall_data_mgr_storage_rdb.h"

#include "bmsuninstalldatamgr_fuzzer.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
void GenerateUninstallBundleInfo(FuzzedDataProvider& fdp, UninstallBundleInfo &uninstallbundleInfo)
{
    uninstallbundleInfo.appId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    uninstallbundleInfo.appIdentifier = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    uninstallbundleInfo.appProvisionType = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    uninstallbundleInfo.bundleType = static_cast<BundleType>(fdp.ConsumeIntegralInRange<uint8_t>(0, CODE_MAX_FOUR));
    uninstallbundleInfo.appId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    uninstallbundleInfo.extensionDirs = GenerateStringArray(fdp);
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    UninstallDataMgrStorageRdb uninstallDataMgrStorageRdb;
    FuzzedDataProvider fdp(data, size);
    std::string bundleName;
    UninstallBundleInfo uninstallbundleInfo;
    GenerateUninstallBundleInfo(fdp, uninstallbundleInfo);
    std::map<std::string, std::string> datas;
    std::map<std::string, UninstallBundleInfo> uninstallBundleInfos;
    uninstallDataMgrStorageRdb.TransformStrToInfo(datas, uninstallBundleInfos);

    uninstallDataMgrStorageRdb.UpdateUninstallBundleInfo(bundleName, uninstallbundleInfo);
    uninstallDataMgrStorageRdb.GetAllUninstallBundleInfo(uninstallBundleInfos);
    uninstallDataMgrStorageRdb.DeleteUninstallBundleInfo(bundleName);

    bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    GenerateMap(fdp, datas);
    uninstallDataMgrStorageRdb.TransformStrToInfo(datas, uninstallBundleInfos);
    UninstallBundleInfo uninstallbundleInfo2;
    uninstallDataMgrStorageRdb.UpdateUninstallBundleInfo(bundleName, uninstallbundleInfo2);
    uninstallDataMgrStorageRdb.DeleteUninstallBundleInfo(bundleName);

    uninstallDataMgrStorageRdb.rdbDataManager_ = nullptr;
    uninstallDataMgrStorageRdb.UpdateUninstallBundleInfo(bundleName, uninstallbundleInfo2);
    uninstallDataMgrStorageRdb.GetAllUninstallBundleInfo(uninstallBundleInfos);
    uninstallDataMgrStorageRdb.TransformStrToInfo(datas, uninstallBundleInfos);
    uninstallDataMgrStorageRdb.DeleteUninstallBundleInfo(bundleName);
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
