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

#include <cstddef>
#include <cstdint>
#include <set>
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#include "bmspreinstallexceptionmgr_fuzzer.h"
#include "bundle_mgr_service.h"
#include "pre_install_exception_mgr.h"
#include "bms_fuzztest_util.h"
#include "securec.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
constexpr size_t U32_AT_SIZE = 4;
const std::string BUNDLE_TEMP_NAME = "temp_bundle_name";
const std::string BUNDLE_PATH = "test.hap";
namespace OHOS {
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    std::shared_ptr<BundleMgrService> bundleMgrService_ = DelayedSingleton<BundleMgrService>::GetInstance();
    bundleMgrService_->InitBmsParam();
    bundleMgrService_->InitPreInstallExceptionMgr();
    auto preInstallExceptionMgr = bundleMgrService_->GetPreInstallExceptionMgr();
    if (preInstallExceptionMgr == nullptr) {
        return false;
    }
    FuzzedDataProvider fdp(data, size);
    preInstallExceptionMgr->exceptionPaths_.insert("/module_update/test/");
    preInstallExceptionMgr->exceptionBundleNames_.insert("/module_update/test/");
    preInstallExceptionMgr->exceptionAppServicePaths_.insert("/module_update/test/");
    preInstallExceptionMgr->exceptionAppServiceBundleNames_.insert("/data/app/el1/bundle/public/test/");
    bundleMgrService_->GetBmsParam();
    std::set<std::string> oldExceptionPaths;
    std::set<std::string> oldExceptionBundleNames;
    std::set<std::string> exceptionAppServicePaths;
    std::set<std::string> exceptionAppServiceBundleNames;
    std::set<std::string> exceptionSharedPaths;
    preInstallExceptionMgr->GetAllPreInstallExceptionInfo(oldExceptionPaths, oldExceptionBundleNames,
        exceptionAppServicePaths, exceptionAppServiceBundleNames, exceptionSharedPaths);
    preInstallExceptionMgr->LoadPreInstallExceptionInfosFromDb();
    preInstallExceptionMgr->SavePreInstallExceptionInfosToDb();
    preInstallExceptionMgr->DeletePreInstallExceptionInfosFromDb();
    preInstallExceptionMgr->ClearAll();
    std::set<std::string> exceptionPaths;
    std::set<std::string> exceptionBundleNames;
    preInstallExceptionMgr->GetAllPreInstallExceptionInfo(exceptionPaths, exceptionBundleNames,
        exceptionAppServicePaths, exceptionAppServiceBundleNames, exceptionSharedPaths);
    std::string bundleDir = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string dir = "";
    std::string bundleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    std::string bundle = "";
    preInstallExceptionMgr->SavePreInstallExceptionBundleName(BUNDLE_TEMP_NAME);
    preInstallExceptionMgr->SavePreInstallExceptionBundleName(bundle);
    preInstallExceptionMgr->SavePreInstallExceptionPath(BUNDLE_PATH);
    preInstallExceptionMgr->SavePreInstallExceptionPath(bundle);
    preInstallExceptionMgr->GetAllPreInstallExceptionInfo(exceptionPaths, exceptionBundleNames,
        exceptionAppServicePaths, exceptionAppServiceBundleNames, exceptionSharedPaths);
    preInstallExceptionMgr->DeletePreInstallExceptionBundleName(BUNDLE_TEMP_NAME);
    preInstallExceptionMgr->DeletePreInstallExceptionBundleName(bundleName);
    preInstallExceptionMgr->DeletePreInstallExceptionBundleName(bundle);
    preInstallExceptionMgr->SavePreInstallExceptionAppServiceBundleName(BUNDLE_TEMP_NAME);
    preInstallExceptionMgr->SavePreInstallExceptionAppServiceBundleName(bundle);
    preInstallExceptionMgr->DeletePreInstallExceptionAppServiceBundleName(BUNDLE_TEMP_NAME);
    preInstallExceptionMgr->DeletePreInstallExceptionAppServiceBundleName(bundleName);
    preInstallExceptionMgr->DeletePreInstallExceptionAppServiceBundleName(bundle);
    preInstallExceptionMgr->SavePreInstallExceptionAppServicePath(BUNDLE_PATH);
    preInstallExceptionMgr->SavePreInstallExceptionAppServicePath(dir);
    preInstallExceptionMgr->DeletePreInstallExceptionPath(BUNDLE_PATH);
    preInstallExceptionMgr->DeletePreInstallExceptionPath(bundleDir);
    preInstallExceptionMgr->DeletePreInstallExceptionPath(dir);
    preInstallExceptionMgr->DeletePreInstallExceptionAppServicePath(BUNDLE_PATH);
    preInstallExceptionMgr->DeletePreInstallExceptionAppServicePath(bundleDir);
    preInstallExceptionMgr->DeletePreInstallExceptionAppServicePath(dir);
    preInstallExceptionMgr->GetAllPreInstallExceptionInfo(exceptionPaths, exceptionBundleNames,
        exceptionAppServicePaths, exceptionAppServiceBundleNames, exceptionSharedPaths);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    // Run your code on data.
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}