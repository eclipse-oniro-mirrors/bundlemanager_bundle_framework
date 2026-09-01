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

#define private public
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <fuzzer/FuzzedDataProvider.h>
#include "bmsbundleparser_fuzzer.h"
#include "bundle_parser.h"
#include "bundle_pack_info.h"
#include "bms_fuzztest_util.h"
#include "nlohmann/json.hpp"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;

namespace OHOS {
namespace {
constexpr const char* FUZZ_TEMP_FILE = "/data/local/tmp/bms_fuzz_parser.json";
}

void WriteFuzzDataToFile(const std::string& filePath, const std::string& content)
{
    std::ofstream ofs(filePath, std::ios::binary | std::ios::trunc);
    if (ofs.is_open()) {
        ofs << content;
        ofs.close();
    }
}

bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    BundleParser parser;

    // JSON string methods
    std::string jsonStr = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    BundleParser::ParseAclExtendedMap(jsonStr);

    std::vector<RouterItem> routerArray;
    std::string routerJsonStr = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    parser.ParseRouterArray(routerJsonStr, routerArray);

    // Private method via #define private public
    nlohmann::json routerData = nlohmann::json::parse(jsonStr, nullptr, false, true);
    parser.CheckRouterData(routerData);

    // File path methods (write temp file with fuzz data)
    std::string fileContent = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    WriteFuzzDataToFile(FUZZ_TEMP_FILE, fileContent);

    nlohmann::json jsonBuf;
    BundleParser::ReadFileIntoJson(FUZZ_TEMP_FILE, jsonBuf);

    std::set<PreScanInfo> scanInfos;
    parser.ParsePreInstallConfig(FUZZ_TEMP_FILE, scanInfos);

    std::set<PreScanInfo> scanAppInfos;
    std::set<PreScanInfo> scanDemandInfos;
    parser.ParsePreAppListConfig(FUZZ_TEMP_FILE, scanAppInfos, scanDemandInfos);

    std::set<PreScanInfo> demandScanInfos;
    parser.ParseDemandInstallConfig(FUZZ_TEMP_FILE, demandScanInfos);

    std::set<std::string> uninstallList;
    parser.ParsePreUnInstallConfig(FUZZ_TEMP_FILE, uninstallList);

    std::set<PreBundleConfigInfo> preBundleConfigInfos;
    parser.ParsePreInstallAbilityConfig(FUZZ_TEMP_FILE, preBundleConfigInfos);

    std::set<DefaultPermission> defaultPermissions;
    parser.ParseDefaultPermission(FUZZ_TEMP_FILE, defaultPermissions);

    std::set<std::string> extensionTypeList;
    parser.ParseExtTypeConfig(FUZZ_TEMP_FILE, extensionTypeList);

    std::vector<std::string> noDisablingList;
    BundleParser::ParseNoDisablingList(FUZZ_TEMP_FILE, noDisablingList);

    std::unordered_set<std::string> bundleNames;
    BundleParser::ParseArkStartupCacheConfig(FUZZ_TEMP_FILE, bundleNames);

    // HAP file methods (random path, covers error branches)
    std::string hapPath = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    InnerBundleInfo innerBundleInfo;
    bool isAbcCompressed = false;
    parser.Parse(hapPath, innerBundleInfo, isAbcCompressed);

    BundlePackInfo bundlePackInfo;
    parser.ParsePackInfo(hapPath, bundlePackInfo);

    std::vector<std::string> sysCaps;
    parser.ParseSysCap(hapPath, sysCaps);

    ModuleTestRunner testRunner;
    parser.ParseTestRunner(hapPath, testRunner);

    // Test with empty path
    parser.Parse("", innerBundleInfo, isAbcCompressed);
    parser.ParseSysCap("", sysCaps);

    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
