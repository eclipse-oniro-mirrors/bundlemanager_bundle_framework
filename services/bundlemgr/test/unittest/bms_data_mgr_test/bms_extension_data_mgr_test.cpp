/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <fstream>
#include <gtest/gtest.h>

#include "ability_manager_helper.h"
#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_data_storage_interface.h"
#include "bundle_data_mgr.h"
#include "bms_extension_data_mgr.h"
#include "bms_extension_profile.h"
#include "bundle_mgr_service.h"
#include "bundle_mgr_ext_register.h"
#include "json_constants.h"
#include "json_serializer.h"
#include "parcel.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using OHOS::Parcel;
using OHOS::AAFwk::Want;

namespace OHOS {
namespace {
const uint32_t SDK_VERSION = 10;
const std::string BMS_EXTENSION_PATH = "/system/etc/app/bms-extensions.json";
const std::string BMS_DATA_PATH = "data/data";
const std::string BUNDLE_EXT_NAME = "bundleExtName";
const nlohmann::json EXTENSIONS_JSON_1 = R"(
{
    "bms-extensions": {
        "bundle-mgr": {
            "extension-name": "HMOSBundleMgrExt",
            "libpath":"system/lib/libappexecfwk_test.z.so",
            "lib64path":"system/lib64/libappexecfwk_test.z.so"
        }
    }
}
)"_json;
const nlohmann::json EXTENSIONS_JSON_3 = R"(
{
    "no_extensions": {
        "bundle-mgr": {
            "extension-name": "HMOSBundleMgrExt",
            "libpath":"system/lib/libappexecfwk_test.z.so",
            "lib64path":"system/lib64/libappexecfwk_test.z.so"
        }
    }
}
)"_json;
const nlohmann::json EXTENSIONS_JSON_4 = R"(
{
    "bms-extensions": "bms-extensions"
}
)"_json;
const nlohmann::json EXTENSIONS_JSON_5 = R"(
{
    "bms-extensions": {
        "bundle-mgr": "bundle-mgr"
    }
}
)"_json;

}  // namespace

class BmsExtensionDataMgrTest : public testing::Test {
public:
    BmsExtensionDataMgrTest();
    ~BmsExtensionDataMgrTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    const std::shared_ptr<BundleDataMgr> GetDataMgr() const;

private:
    std::shared_ptr<BundleDataMgr> dataMgr_ = std::make_shared<BundleDataMgr>();
    std::ostringstream pathStream_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsExtensionDataMgrTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

BmsExtensionDataMgrTest::BmsExtensionDataMgrTest()
{}

BmsExtensionDataMgrTest::~BmsExtensionDataMgrTest()
{}

void BmsExtensionDataMgrTest::SetUpTestCase()
{}

void BmsExtensionDataMgrTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsExtensionDataMgrTest::SetUp()
{}

void BmsExtensionDataMgrTest::TearDown()
{
    pathStream_.clear();
}

const std::shared_ptr<BundleDataMgr> BmsExtensionDataMgrTest::GetDataMgr() const
{
    return dataMgr_;
}

/**
 * @tc.number: BmsExtensionDataMgr_0001
 * @tc.name: CheckApiInfo
 * @tc.desc: CheckApiInfo
 */
HWTEST_F(BmsExtensionDataMgrTest, BmsExtensionDataMgr_0001, Function | SmallTest | Level0)
{
    BmsExtensionDataMgr bmsExtensionDataMgr;
    BundleInfo bundleInfo;
    bundleInfo.compatibleVersion = 40000 * 1000 + 100;
    bool res = bmsExtensionDataMgr.CheckApiInfo(bundleInfo, SDK_VERSION);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: BmsExtensionDataMgr_0001
 * @tc.name: CheckApiInfo
 * @tc.desc: CheckApiInfo
 */
HWTEST_F(BmsExtensionDataMgrTest, BmsExtensionDataMgr_0002, Function | SmallTest | Level0)
{
    BmsExtensionDataMgr bmsExtensionDataMgr;
    bool res = bmsExtensionDataMgr.OpenHandler();
    #ifdef USE_EXTENSION_DATA
    EXPECT_EQ(res, true);
    #else
    EXPECT_EQ(res, false);
    #endif
}

/**
 * @tc.number: BmsExtensionDataMgr_0003
 * @tc.name: CheckApiInfo
 * @tc.desc: CheckApiInfo
 */
HWTEST_F(BmsExtensionDataMgrTest, BmsExtensionDataMgr_0003, Function | SmallTest | Level0)
{
    BmsExtensionDataMgr bmsExtensionDataMgr;
    BundleInfo bundleInfo;
    bundleInfo.compatibleVersion = 40000 * 1000 + 10;
    bool res = bmsExtensionDataMgr.CheckApiInfo(bundleInfo, SDK_VERSION);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number: BmsExtensionProfile_0001
 * @tc.name: TransformTo
 * @tc.desc: TransformTo
 */
HWTEST_F(BmsExtensionDataMgrTest, BmsExtensionProfile_0001, Function | SmallTest | Level0)
{
    BmsExtensionProfile bmsExtensionProfile;
    BmsExtension bmsExtension;
    ErrCode res = bmsExtensionProfile.TransformTo(EXTENSIONS_JSON_1, bmsExtension);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: BmsExtensionProfile_0003
 * @tc.name: TransformTo
 * @tc.desc: TransformTo
 */
HWTEST_F(BmsExtensionDataMgrTest, BmsExtensionProfile_0003, Function | SmallTest | Level0)
{
    BmsExtensionProfile bmsExtensionProfile;
    BmsExtension bmsExtension;
    ErrCode res = bmsExtensionProfile.TransformTo(EXTENSIONS_JSON_3, bmsExtension);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);
}

/**
 * @tc.number: BmsExtensionProfile_0004
 * @tc.name: TransformTo
 * @tc.desc: TransformTo
 */
HWTEST_F(BmsExtensionDataMgrTest, BmsExtensionProfile_0004, Function | SmallTest | Level0)
{
    BmsExtensionProfile bmsExtensionProfile;
    BmsExtension bmsExtension;
    ErrCode res = bmsExtensionProfile.TransformTo(EXTENSIONS_JSON_4, bmsExtension);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);
}

/**
 * @tc.number: BmsExtensionProfile_0005
 * @tc.name: TransformTo
 * @tc.desc: TransformTo
 */
HWTEST_F(BmsExtensionDataMgrTest, BmsExtensionProfile_0005, Function | SmallTest | Level0)
{
    BmsExtensionProfile bmsExtensionProfile;
    BmsExtension bmsExtension;
    ErrCode res = bmsExtensionProfile.TransformTo(EXTENSIONS_JSON_5, bmsExtension);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);
}

/**
 * @tc.number: BmsExtensionProfile_0006
 * @tc.name: ParseBmsExtension
 * @tc.desc: ParseBmsExtension
 */
HWTEST_F(BmsExtensionDataMgrTest, BmsExtensionProfile_0006, Function | SmallTest | Level0)
{
    BmsExtensionProfile bmsExtensionProfile;
    BmsExtension bmsExtension;
    ErrCode res = bmsExtensionProfile.ParseBmsExtension(BMS_EXTENSION_PATH, bmsExtension);
    #ifdef USE_EXTENSION_DATA
    EXPECT_EQ(res, ERR_OK);
    #else
    EXPECT_EQ(res, ERR_APPEXECFWK_PARSE_FILE_FAILED);
    #endif
}

/**
 * @tc.number: BmsExtensionProfile_0007
 * @tc.name: ReadFileIntoJson
 * @tc.desc: ReadFileIntoJson
 */
HWTEST_F(BmsExtensionDataMgrTest, BmsExtensionProfile_0007, Function | SmallTest | Level0)
{
    BmsExtensionProfile bmsExtensionProfile;
    nlohmann::json jsonBuf;
    bool res = bmsExtensionProfile.ReadFileIntoJson(BMS_DATA_PATH, jsonBuf);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number: BundleMgrExtRegister_0001
 * @tc.name: ReadFileIntoJson
 * @tc.desc: ReadFileIntoJson
 */
HWTEST_F(BmsExtensionDataMgrTest, BundleMgrExtRegister_0001, Function | SmallTest | Level0)
{
    auto res = BundleMgrExtRegister::GetInstance().GetBundleMgrExt(BUNDLE_EXT_NAME);
    EXPECT_EQ(res, nullptr);
}
} // OHOS