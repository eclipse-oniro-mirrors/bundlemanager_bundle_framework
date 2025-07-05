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

#include "parcel.h"

#include "bmsquickfixdatamgr_fuzzer.h"
#include "bms_fuzztest_util.h"
#include "quick_fix_checker.h"
#include "quick_fix_data_mgr.h"
#include "quick_fix_manager_rdb.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    QuickFixDataMgr quickFixDataMgr;
    std::map<std::string, InnerAppQuickFix> innerAppQuickFixes;
    quickFixDataMgr.QueryAllInnerAppQuickFix(innerAppQuickFixes);
    std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    InnerAppQuickFix fixInfo;
    quickFixDataMgr.quickFixManagerDb_ = nullptr;
    quickFixDataMgr.QueryInnerAppQuickFix(bundleName, fixInfo);
    quickFixDataMgr.SaveInnerAppQuickFix(fixInfo);
    quickFixDataMgr.DeleteInnerAppQuickFix(bundleName);

    QuickFixManagerRdb quickFixManagerRdb;
    std::map<std::string, InnerAppQuickFix> innerAppQuickFixes2;
    std::string bundleName2 = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    InnerAppQuickFix fixInfo2;
    quickFixManagerRdb.rdbDataManager_ = nullptr;
    quickFixManagerRdb.GetAllDataFromDb(innerAppQuickFixes2);
    quickFixManagerRdb.GetDataFromDb(bundleName2, fixInfo2);
    quickFixManagerRdb.SaveDataToDb(fixInfo2);
    quickFixManagerRdb.DeleteDataFromDb(bundleName2);
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
