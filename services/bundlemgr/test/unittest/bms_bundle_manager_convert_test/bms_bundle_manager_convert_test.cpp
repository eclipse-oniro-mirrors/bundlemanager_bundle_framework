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

#include <gtest/gtest.h>

#include "ability_info.h"
#include "application_info.h"
#include "bundle_info.h"
#include "bundle_manager_convert.h"
#include "bundle_manager_utils.h"
#include "extension_ability_info.h"
#include "hap_module_info.h"

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {
class BundleManagerConvertTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.number: ConvertApplicationInfo_0001
 * @tc.name: ConvertApplicationInfo
 * @tc.desc: ConvertApplicationInfo
 */
HWTEST_F(BundleManagerConvertTest, ConvertApplicationInfo_0001, Function | SmallTest | Level0)
{
    ApplicationInfo cAppInfo;
    cAppInfo.appIndex = 1;
    CJSystemapi::BundleManager::RetApplicationInfo retApplicationInfoTest =
        CJSystemapi::BundleManager::Convert::ConvertApplicationInfo(cAppInfo);
    EXPECT_EQ(retApplicationInfoTest.appIndex, 1);
}

/**
 * @tc.number: ConvertExtensionAbilityInfo_0001
 * @tc.name: ConvertExtensionAbilityInfo
 * @tc.desc: ConvertExtensionAbilityInfo
 */
HWTEST_F(BundleManagerConvertTest, ConvertExtensionAbilityInfo_0001, Function | SmallTest | Level0)
{
    AppExecFwk::ExtensionAbilityInfo extensionInfos;
    extensionInfos.iconId = 1;
    CJSystemapi::BundleManager::RetExtensionAbilityInfo retExtensionAbilityInfo =
        CJSystemapi::BundleManager::Convert::ConvertExtensionAbilityInfo(extensionInfos);
    EXPECT_EQ(retExtensionAbilityInfo.iconId, 1);
}

/**
 * @tc.number: ConvertArrExtensionAbilityInfo_0001
 * @tc.name: ConvertArrExtensionAbilityInfo
 * @tc.desc: ConvertArrExtensionAbilityInfo
 */
HWTEST_F(BundleManagerConvertTest, ConvertArrExtensionAbilityInfo_0001, Function | SmallTest | Level0)
{
    AppExecFwk::ExtensionAbilityInfo extensionAbilityInfo;
    std::vector<AppExecFwk::ExtensionAbilityInfo> extensionInfos;
    extensionInfos.emplace_back(extensionAbilityInfo);
    CJSystemapi::BundleManager::CArrRetExtensionAbilityInfo cArrRetExtensionAbilityInfo =
        CJSystemapi::BundleManager::Convert::ConvertArrExtensionAbilityInfo(extensionInfos);
    EXPECT_NE(cArrRetExtensionAbilityInfo.head, nullptr);
}

/**
 * @tc.number: ConvertAbilityInfo_0001
 * @tc.name: ConvertAbilityInfo
 * @tc.desc: ConvertAbilityInfo
 */
HWTEST_F(BundleManagerConvertTest, ConvertAbilityInfo_0001, Function | SmallTest | Level0)
{
    AppExecFwk::AbilityInfo cAbilityInfos;
    cAbilityInfos.iconId = 1;
    CJSystemapi::BundleManager::RetAbilityInfo retAbilityInfo =
        CJSystemapi::BundleManager::Convert::ConvertAbilityInfo(cAbilityInfos);
    EXPECT_EQ(retAbilityInfo.iconId, 1);
}

/**
 * @tc.number: ConvertHapModuleInfo_0001
 * @tc.name: ConvertHapModuleInfo
 * @tc.desc: ConvertHapModuleInfo
 */
HWTEST_F(BundleManagerConvertTest, ConvertHapModuleInfo_0001, Function | SmallTest | Level0)
{
    AppExecFwk::HapModuleInfo hapModuleInfo;
    hapModuleInfo.iconId = 1;
    CJSystemapi::BundleManager::RetHapModuleInfo retHapModuleInfo =
        CJSystemapi::BundleManager::Convert::ConvertHapModuleInfo(hapModuleInfo);
    EXPECT_EQ(retHapModuleInfo.iconId, 1);
}

/**
 * @tc.number: ConvertBundleInfo_0001
 * @tc.name: ConvertBundleInfo
 * @tc.desc: ConvertBundleInfo
 */
HWTEST_F(BundleManagerConvertTest, ConvertBundleInfo_0001, Function | SmallTest | Level0)
{
    AppExecFwk::BundleInfo cBundleInfo;
    cBundleInfo.minCompatibleVersionCode = 1;
    int32_t flags = 1;
    CJSystemapi::BundleManager::RetBundleInfo retBundleInfo =
        CJSystemapi::BundleManager::Convert::ConvertBundleInfo(cBundleInfo, flags);
    EXPECT_EQ(retBundleInfo.minCompatibleVersionCode, 1);
}
} // namespace AppExecFwk
} // namespace OHOS