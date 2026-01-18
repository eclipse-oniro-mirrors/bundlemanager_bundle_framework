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

#include "bmsuninstallbundleresourcerdb_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#include "uninstall_bundle_resource_rdb.h"
#undef private
#include "securec.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    UninstallBundleResourceRdb uninstallBundleResourceRdb;
    std::string labels = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    uninstallBundleResourceRdb.FromString(labels);
    std::map<std::string, std::string> labelMap;
    uninstallBundleResourceRdb.ToString(labelMap);
    std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    int32_t userId = GenerateRandomUser(fdp);
    int32_t appIndex = fdp.ConsumeIntegral<int32_t>();
    BundleResourceInfo bundleResourceInfo;
    bundleResourceInfo.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleResourceInfo.label = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    bundleResourceInfo.icon = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    uninstallBundleResourceRdb.AddUninstallBundleResource(bundleName, userId, appIndex, labelMap, bundleResourceInfo);
    uninstallBundleResourceRdb.DeleteUninstallBundleResource(bundleName, userId, appIndex);
    uninstallBundleResourceRdb.DeleteUninstallBundleResource("", userId, appIndex);
    uninstallBundleResourceRdb.DeleteUninstallBundleResourceForUser(userId);
    uint32_t flags = fdp.ConsumeIntegral<uint32_t>();
    uninstallBundleResourceRdb.GetUninstallBundleResource(bundleName, userId, appIndex, flags, bundleResourceInfo);
    uninstallBundleResourceRdb.GetUninstallBundleResource("", userId, appIndex, flags, bundleResourceInfo);
    std::vector<BundleResourceInfo> bundleResourceInfos;
    bundleResourceInfos.push_back(bundleResourceInfo);
    uninstallBundleResourceRdb.GetAllUninstallBundleResource(userId, flags, bundleResourceInfos);
    std::shared_ptr<NativeRdb::ResultSet> absSharedResultSet;
    std::shared_ptr<NativeRdb::ResultSet> resultSet = nullptr;
    std::string language = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    uninstallBundleResourceRdb.ConvertToBundleResourceInfo(absSharedResultSet, flags, language, bundleResourceInfo);
    uninstallBundleResourceRdb.ConvertToBundleResourceInfo(absSharedResultSet, flags, language, bundleResourceInfo);
    uninstallBundleResourceRdb.ConvertToBundleResourceInfo(resultSet, flags, language, bundleResourceInfo);
    uninstallBundleResourceRdb.GetAvailableLabel(bundleName, language, labels);
    return true;
}
}

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}