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
};

BmsBundleFreeInstallBaseTest::BmsBundleFreeInstallBaseTest()
{}

BmsBundleFreeInstallBaseTest::~BmsBundleFreeInstallBaseTest()
{}

void BmsBundleFreeInstallBaseTest::SetUpTestCase()
{}

void BmsBundleFreeInstallBaseTest::TearDownTestCase()
{}

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
    to_json(jsonObj, info);
    DispatcherInfo result;
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
    auto ret = info.Marshalling(parcel);
    EXPECT_TRUE(ret);
    auto result = DispatcherInfo::Unmarshalling(parcel);
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
    installResult.retCode = 1;
    nlohmann::json jsonObj;
    to_json(jsonObj, installResult);
    Result result;
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
    to_json(jsonObj, installResult);
    InstallResult result;
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
    auto ret = installResult.Marshalling(parcel);
    EXPECT_TRUE(ret);
    auto unmarshalledResult = Result::Unmarshalling(parcel);
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
    auto ret = progress.Marshalling(parcel);
    EXPECT_TRUE(ret);
    auto result = Progress::Unmarshalling(parcel);
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
    installResult.retCode = 1;
    Parcel parcel;
    auto ret = installResult.Marshalling(parcel);
    EXPECT_TRUE(ret);
    auto unmarshalledResult = Result::Unmarshalling(parcel);
    EXPECT_EQ(unmarshalledResult->transactId, TRANSACT_ID);
    ret = unmarshalledResult->ReadFromParcel(parcel);
    EXPECT_TRUE(ret);
}
}