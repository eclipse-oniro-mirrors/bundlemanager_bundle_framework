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

#include "bmsnavigation_fuzzer.h"
#include "bms_fuzztest_util.h"

#include "router_data_storage_rdb.h"
#include "router_item_compare.h"
#include "router_map_helper.h"
#include "securec.h"
#include "sem_ver.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
void GenerateRouterItem(FuzzedDataProvider &fdp, RouterItem &routerItem)
{
    routerItem.name = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    routerItem.pageSourceFile = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    routerItem.buildFunction = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    routerItem.customData = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    routerItem.ohmurl = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    routerItem.bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    routerItem.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    GenerateMap(fdp, routerItem.data);
}

void ProduceSemVerList(std::vector<SemVer> &semVerList)
{
    semVerList.emplace_back(SemVer("1.2.0"));
    semVerList.emplace_back(SemVer("1.2.1"));
    semVerList.emplace_back(SemVer("1.2.2"));
    semVerList.emplace_back(SemVer("2.2.2"));
    semVerList.emplace_back(SemVer("1.2.0-release.1"));
    semVerList.emplace_back(SemVer("2.2.2-beta1"));
    semVerList.emplace_back(SemVer("1.1.1-release.1"));
    semVerList.emplace_back(SemVer("1.2.0-release"));
    semVerList.emplace_back(SemVer("1.2.1-beta1"));
    semVerList.emplace_back(SemVer("01.2.0"));
    semVerList.emplace_back(SemVer("1.02.0"));
    semVerList.emplace_back(SemVer("a01.2.3"));
    semVerList.emplace_back(SemVer("1.2.3"));
    semVerList.emplace_back(SemVer("1.abc.3"));
    semVerList.emplace_back(SemVer("1.2.b03"));
    semVerList.emplace_back(SemVer("abc.2.3"));
    semVerList.emplace_back(SemVer("bcd.2.3"));
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    RouterDataStorageRdb routerDataStorageRdb;
    std::string bundleName;
    std::string moduleName;
    std::vector<RouterItem> routerInfos;
    std::set<std::string> bundleNames;
    std::map<std::string, std::string> routerInfoMap;
    routerDataStorageRdb.UpdateRouterInfo(bundleName, routerInfoMap);
    bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    GenerateMap(fdp, routerInfoMap);
    routerDataStorageRdb.UpdateRouterInfo(bundleName, routerInfoMap);

    routerDataStorageRdb.rdbDataManager_ = nullptr;
    routerDataStorageRdb.UpdateRouterInfo(bundleName, routerInfoMap);
    routerDataStorageRdb.GetRouterInfo(bundleName, moduleName, routerInfos);
    routerDataStorageRdb.GetAllBundleNames(bundleNames);
    routerDataStorageRdb.DeleteRouterInfo(bundleName);
    routerDataStorageRdb.DeleteRouterInfo(bundleName, moduleName);

    BundleInfo bundleInfo;
    GenerateBundleInfo(fdp, bundleInfo);
    HapModuleInfo hapModuleInfo1;
    hapModuleInfo1.name = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    hapModuleInfo1.moduleType = ModuleType::ENTRY;
    hapModuleInfo1.routerArray.emplace_back(RouterItem());
    RouterMapHelper::MergeRouter(bundleInfo);
    bundleInfo.hapModuleInfos.emplace_back(hapModuleInfo1);
    RouterMapHelper::MergeRouter(bundleInfo);
    std::string ohmurl = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    RouterMapHelper::ExtractVersionFromOhmurl(ohmurl);
    ohmurl += "&";
    RouterMapHelper::ExtractVersionFromOhmurl(ohmurl);

    std::vector<RouterItem> routerArrayList;
    RouterItem routerItem1;
    GenerateRouterItem(fdp, routerItem1);
    routerArrayList.emplace_back(routerItem1);
    std::vector<RouterItem> routerArray;
    std::set<std::string> moduleNameSet;
    RouterMapHelper::MergeRouter(routerArrayList, routerArray, moduleNameSet);

    std::string semRandom = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    SemVer fuzzSem(semRandom);
    SemVer semVer("");
    std::vector<SemVer> semVerList;
    ProduceSemVerList(semVerList);
    for (size_t i = 0; i < semVerList.size(); i++) {
        for (size_t j = i + 1; j < semVerList.size(); j++) {
            RouterMapHelper::CompareMain(semVerList[i], semVerList[j]);
            RouterMapHelper::ComparePre(semVerList[i], semVerList[j]);
            RouterMapHelper::Compare(semVerList[i], semVerList[j]);
        }
    }
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
