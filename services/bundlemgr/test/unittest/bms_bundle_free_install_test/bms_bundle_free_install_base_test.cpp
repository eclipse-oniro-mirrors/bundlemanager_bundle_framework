/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include <fstream>
#include <gtest/gtest.h>
#include <map>
#include <sstream>
#include <string>

#include "appexecfwk_errors.h"
#include "bundle_info.h"
#include "bundle_mgr_service.h"
#include "bundle_mgr_proxy.h"
#include "bundle_pack_info.h"
#include "inner_bundle_info.h"

#include "dispatch_info.h"
#include "install_result.h"
#include "json_util.h"
#include "nlohmann/json.hpp"
#include "parcel_macro.h"
#include "target_ability_info.h"

using namespace testing::ext;
using namespace std::chrono_literals;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const std::string VERSION = "1.0.0.1";
const std::string TRANSACT_ID = "transact_id";
const std::string RESULT_MSG = "result_msg";
const int32_t DOWNLOAD_SIZE = 10;
const int32_t TOTAL_SIZE = 20;
const int32_t REASON_FLAG = 2;
const int32_t VERSIONID = 1;
const std::string EXT_MAP_KEY = "EXT_MAP_KEY";
const std::string EXT_MAP_VALUE = "EXT_MAP_VALUE";
const std::string BUNDLE_NAME = "com.example.freeInstall";
const std::string MODULE_NAME = "entry";
const std::string ABILITY_NAME = "MainAbility";
}  // namespace

class BmsBundleFreeInstallBaseTest : public testing::Test {
public:
    BmsBundleFreeInstallBaseTest();
    ~BmsBundleFreeInstallBaseTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleFreeInstallBaseTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

BmsBundleFreeInstallBaseTest::BmsBundleFreeInstallBaseTest()
{}

BmsBundleFreeInstallBaseTest::~BmsBundleFreeInstallBaseTest()
{}

void BmsBundleFreeInstallBaseTest::SetUpTestCase()
{}

void BmsBundleFreeInstallBaseTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleFreeInstallBaseTest::SetUp()
{}

void BmsBundleFreeInstallBaseTest::TearDown()
{}

/**
 * @tc.number: BmsBundleFreeInstallBaseTest_0001
 * Function: DispatcherInfoJson
 * @tc.name: test DispatcherInfoJson
 * @tc.desc: DispatcherInfoJson
 */
HWTEST_F(BmsBundleFreeInstallBaseTest, BmsBundleFreeInstallBaseTest_0001, Function | SmallTest | Level0)
{
    DispatcherInfo info;
    info.version = VERSION;
    nlohmann::json jsonObj;
    DispatcherInfo result;
    from_json(jsonObj, result);
    EXPECT_NE(info.version, result.version);
    to_json(jsonObj, info);
    from_json(jsonObj, result);
    EXPECT_EQ(info.version, result.version);
}

/**
 * @tc.number: BmsBundleFreeInstallBaseTest_0002
 * Function: DispatcherInfoMarshall
 * @tc.name: test DispatcherInfoMarshall
 * @tc.desc: DispatcherInfoMarshall
 */
HWTEST_F(BmsBundleFreeInstallBaseTest, BmsBundleFreeInstallBaseTest_0002, Function | SmallTest | Level0)
{
    DispatcherInfo info;
    info.version = VERSION;
    Parcel parcel;
    auto result = DispatcherInfo::Unmarshalling(parcel);
    EXPECT_NE(result->version, VERSION);
    auto ret = info.Marshalling(parcel);
    EXPECT_TRUE(ret);
    result = DispatcherInfo::Unmarshalling(parcel);
    EXPECT_EQ(result->version, VERSION);
}

/**
 * @tc.number: BmsBundleFreeInstallBaseTest_0003
 * Function: ResultJson
 * @tc.name: test ResultJson
 * @tc.desc: ResultJson
 */
HWTEST_F(BmsBundleFreeInstallBaseTest, BmsBundleFreeInstallBaseTest_0003, Function | SmallTest | Level0)
{
    Result installResult;
    installResult.transactId = TRANSACT_ID;
    installResult.resultMsg = RESULT_MSG;
    installResult.retCode = VERSIONID;
    nlohmann::json jsonObj;
    Result result;
    from_json(jsonObj, result);
    EXPECT_NE(result.transactId, TRANSACT_ID);
    to_json(jsonObj, installResult);
    from_json(jsonObj, result);
    EXPECT_EQ(result.transactId, TRANSACT_ID);
}

/**
 * @tc.number: BmsBundleFreeInstallBaseTest_0004
 * Function: InstallResultJson
 * @tc.name: test InstallResultJson
 * @tc.desc: InstallResultJson
 */
HWTEST_F(BmsBundleFreeInstallBaseTest, BmsBundleFreeInstallBaseTest_0004, Function | SmallTest | Level0)
{
    InstallResult installResult;
    installResult.version = VERSION;
    nlohmann::json jsonObj;
    InstallResult result;
    from_json(jsonObj, result);
    EXPECT_NE(result.version, VERSION);
    to_json(jsonObj, installResult);
    from_json(jsonObj, result);
    EXPECT_EQ(result.version, VERSION);
}

/**
 * @tc.number: BmsBundleFreeInstallBaseTest_0005
 * Function: ResultMarshalling
 * @tc.name: test ResultMarshalling
 * @tc.desc: ResultMarshalling
 */
HWTEST_F(BmsBundleFreeInstallBaseTest, BmsBundleFreeInstallBaseTest_0005, Function | SmallTest | Level0)
{
    Result installResult;
    installResult.transactId = TRANSACT_ID;
    installResult.resultMsg = RESULT_MSG;
    installResult.retCode = 1;
    Parcel parcel;
    auto unmarshalledResult = Result::Unmarshalling(parcel);
    EXPECT_NE(unmarshalledResult->transactId, TRANSACT_ID);
    auto ret = installResult.Marshalling(parcel);
    EXPECT_TRUE(ret);
    unmarshalledResult = Result::Unmarshalling(parcel);
    EXPECT_EQ(unmarshalledResult->transactId, TRANSACT_ID);
    ret = unmarshalledResult->ReadFromParcel(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: BmsBundleFreeInstallBaseTest_0006
 * Function: ProgressMarshalling
 * @tc.name: test ProgressMarshalling
 * @tc.desc: ProgressMarshalling
 */
HWTEST_F(BmsBundleFreeInstallBaseTest, BmsBundleFreeInstallBaseTest_0006, Function | SmallTest | Level0)
{
    Progress progress;
    progress.downloadSize = DOWNLOAD_SIZE;
    progress.totalSize = TOTAL_SIZE;
    Parcel parcel;
    auto result = Progress::Unmarshalling(parcel);
    EXPECT_NE(result->downloadSize, DOWNLOAD_SIZE);
    auto ret = progress.Marshalling(parcel);
    EXPECT_TRUE(ret);
    result = Progress::Unmarshalling(parcel);
    EXPECT_EQ(result->downloadSize, DOWNLOAD_SIZE);
    EXPECT_EQ(result->totalSize, TOTAL_SIZE);
    ret = result->ReadFromParcel(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: BmsBundleFreeInstallBaseTest_0007
 * Function: InstallResultMarshalling
 * @tc.name: test InstallResultMarshalling
 * @tc.desc: InstallResultMarshalling
 */
HWTEST_F(BmsBundleFreeInstallBaseTest, BmsBundleFreeInstallBaseTest_0007, Function | SmallTest | Level0)
{
    Result installResult;
    installResult.transactId = TRANSACT_ID;
    installResult.resultMsg = RESULT_MSG;
    installResult.retCode = VERSIONID;
    Parcel parcel;
    auto ret = installResult.Marshalling(parcel);
    EXPECT_TRUE(ret);
    auto unmarshalledResult = Result::Unmarshalling(parcel);
    EXPECT_EQ(unmarshalledResult->transactId, TRANSACT_ID);
    ret = unmarshalledResult->ReadFromParcel(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: BmsBundleFreeInstallBaseTest_0008
 * Function: TargetInfo
 * @tc.name: test TargetInfo
 * @tc.desc: TargetInfo
 */
HWTEST_F(BmsBundleFreeInstallBaseTest, BmsBundleFreeInstallBaseTest_0008, Function | SmallTest | Level0)
{
    TargetInfo targetInfo;
    targetInfo.bundleName = Constants::BUNDLE_NAME;

    Parcel parcel;
    auto unmarshalledResult = TargetInfo::Unmarshalling(parcel);
    auto ret = targetInfo.Marshalling(parcel);
    EXPECT_TRUE(ret);
    unmarshalledResult = TargetInfo::Unmarshalling(parcel);
    EXPECT_EQ(unmarshalledResult->bundleName, Constants::BUNDLE_NAME);
}

/**
 * @tc.number: BmsBundleFreeInstallBaseTest_0009
 * Function: TargetInfo
 * @tc.name: test TargetInfo
 * @tc.desc: TargetInfo
 */
HWTEST_F(BmsBundleFreeInstallBaseTest, BmsBundleFreeInstallBaseTest_0009, Function | SmallTest | Level0)
{
    TargetInfo targetInfo;
    targetInfo.bundleName = Constants::BUNDLE_NAME;
    targetInfo.moduleName = Constants::MODULE_NAME;
    targetInfo.abilityName = Constants::ABILITY_NAME;
    targetInfo.flags = REASON_FLAG;
    targetInfo.reasonFlag = REASON_FLAG;

    nlohmann::json jsonObject;
    TargetInfo result;
    from_json(jsonObject, result);
    EXPECT_NE(result.bundleName, Constants::BUNDLE_NAME);
    to_json(jsonObject, targetInfo);
    from_json(jsonObject, result);
    EXPECT_EQ(result.bundleName, Constants::BUNDLE_NAME);
    EXPECT_EQ(result.moduleName, Constants::MODULE_NAME);
    EXPECT_EQ(result.abilityName, Constants::ABILITY_NAME);
    EXPECT_EQ(result.flags, REASON_FLAG);
    EXPECT_EQ(result.reasonFlag, REASON_FLAG);
}

/**
 * @tc.number: BmsBundleFreeInstallBaseTest_0010
 * Function: TargetExtSetting
 * @tc.name: test TargetExtSetting
 * @tc.desc: TargetExtSetting
 */
HWTEST_F(BmsBundleFreeInstallBaseTest, BmsBundleFreeInstallBaseTest_0010, Function | SmallTest | Level0)
{
    TargetExtSetting targetExtSetting;
    std::map<std::string, std::string> value;
    value.emplace("1", "2");
    targetExtSetting.extValues = value;

    Parcel parcel;
    auto unmarshalledResult = TargetExtSetting::Unmarshalling(parcel);
    bool ret = targetExtSetting.Marshalling(parcel);
    EXPECT_TRUE(ret);
    unmarshalledResult = TargetExtSetting::Unmarshalling(parcel);
    EXPECT_EQ(unmarshalledResult->extValues.size(), 1);
}

/**
 * @tc.number: BmsBundleFreeInstallBaseTest_0010
 * Function: TargetExtSetting
 * @tc.name: test TargetExtSetting
 * @tc.desc: TargetExtSetting
 */
HWTEST_F(BmsBundleFreeInstallBaseTest, BmsBundleFreeInstallBaseTest_0011, Function | SmallTest | Level0)
{
    TargetExtSetting targetExtSetting;
    std::map<std::string, std::string> value;
    value.emplace("1", "2");
    targetExtSetting.extValues = value;
    nlohmann::json jsonObject;
    TargetExtSetting result;
    from_json(jsonObject, result);
    EXPECT_NE(result.extValues, value);
    to_json(jsonObject, targetExtSetting);
    from_json(jsonObject, result);
    EXPECT_EQ(result.extValues, value);
}

/**
 * @tc.number: BmsBundleFreeInstallBaseTest_0012
 * Function: TargetExtSetting
 * @tc.name: test TargetExtSetting
 * @tc.desc: TargetExtSetting
 */
HWTEST_F(BmsBundleFreeInstallBaseTest, BmsBundleFreeInstallBaseTest_0012, Function | SmallTest | Level0)
{
    TargetAbilityInfo targetAbilityInfo;
    targetAbilityInfo.version = "version";

    Parcel parcel;
    auto unmarshalledResult = TargetAbilityInfo::Unmarshalling(parcel);
    bool ret = targetAbilityInfo.Marshalling(parcel);
    EXPECT_TRUE(ret);
    unmarshalledResult = TargetAbilityInfo::Unmarshalling(parcel);
    EXPECT_EQ(unmarshalledResult->version, "version");
}

/**
 * @tc.number: BmsBundleFreeInstallBaseTest_0013
 * Function: TargetExtSetting
 * @tc.name: test TargetExtSetting
 * @tc.desc: TargetExtSetting
 */
HWTEST_F(BmsBundleFreeInstallBaseTest, BmsBundleFreeInstallBaseTest_0013, Function | SmallTest | Level0)
{
    TargetAbilityInfo targetAbilityInfo;
    targetAbilityInfo.version = "version";
    nlohmann::json jsonObject;
    TargetAbilityInfo result;
    from_json(jsonObject, result);
    EXPECT_NE(result.version, "version");
    to_json(jsonObject, targetAbilityInfo);
    from_json(jsonObject, result);
    EXPECT_EQ(result.version, "version");
}

/**
 * @tc.number: BmsBundleFreeInstallBaseTest_0014
 * Function: ProgressMarshalling
 * @tc.name: test ProgressMarshalling
 * @tc.desc: ProgressMarshalling
 */
HWTEST_F(BmsBundleFreeInstallBaseTest, BmsBundleFreeInstallBaseTest_0014, Function | SmallTest | Level0)
{
    InstallResult installResult;
    installResult.version = TRANSACT_ID;
    installResult.result = Result();
    installResult.progress = Progress();
    Parcel parcel;
    bool ret = installResult.Marshalling(parcel);
    EXPECT_TRUE(ret);
    InstallResult *result = InstallResult::Unmarshalling(parcel);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->version, TRANSACT_ID);
    delete result;
}
}