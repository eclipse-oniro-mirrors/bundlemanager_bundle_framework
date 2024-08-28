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
#include "code_protect_bundle_info.h"
#include "json_constants.h"
#include "json_serializer.h"
#include "parcel.h"
#include "abs_rdb_predicates.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using OHOS::Parcel;
using OHOS::AAFwk::Want;

namespace OHOS {
namespace {
const int32_t USERID = 100;
const int32_t TEST_UID = 20065535;
const uint32_t SDK_VERSION = 10;
const uint32_t COMPATIBLE_VERSION = 11;
const std::string BMS_EXTENSION_PATH = "/system/etc/app/bms-extensions.json";
const std::string BMS_DATA_PATH = "data/data";
const std::string BUNDLE_EXT_NAME = "bundleExtName";
const nlohmann::json EXTENSIONS_JSON_1 = R"(
{
    "bms-extensions": {
        "bundle-mgr": {
            "extension-name": "BundleMgrExt",
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
            "extension-name": "BundleMgrExt",
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
enum {
    BMS_BROKER_ERR_INSTALL_FAILED = 8585217,
    BMS_BROKER_ERR_UNINSTALL_FAILED = 8585218,
};
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

class BundleMgrExtTest : public BundleMgrExt {
public:
    bool CheckApiInfo(const BundleInfo& bundleInfo);
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

bool BundleMgrExtTest::CheckApiInfo(const BundleInfo& bundleInfo)
{
    return true;
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
    bundleInfo.compatibleVersion = COMPATIBLE_VERSION;
    bool res = bmsExtensionDataMgr.CheckApiInfo(bundleInfo, SDK_VERSION);
#ifdef USE_EXTENSION_DATA
    EXPECT_EQ(res, true);
#else
    EXPECT_EQ(res, false);
#endif
}

/**
 * @tc.number: BmsExtensionDataMgr_0002
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
    bool res = bmsExtensionDataMgr.CheckApiInfo(SDK_VERSION, SDK_VERSION);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: BmsExtensionDataMgr_0004
 * @tc.name: QueryAbilityInfosWithFlag
 * @tc.desc: QueryAbilityInfosWithFlag
 */
HWTEST_F(BmsExtensionDataMgrTest, BmsExtensionDataMgr_0004, Function | SmallTest | Level0)
{
    BmsExtensionDataMgr bmsExtensionDataMgr;
    Want want;
    int32_t userId = 0;
    std::vector<AbilityInfo> abilityInfos;
    ErrCode res = bmsExtensionDataMgr.QueryAbilityInfos(want, userId, abilityInfos);
    #ifdef USE_EXTENSION_DATA
    EXPECT_NE(res, ERR_OK);
    #else
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INSTALL_FAILED_BUNDLE_EXTENSION_NOT_EXISTED);
    #endif
}

/**
 * @tc.number: BmsExtensionDataMgr_0005
 * @tc.name: QueryAbilityInfosWithFlag
 * @tc.desc: QueryAbilityInfosWithFlag
 */
HWTEST_F(BmsExtensionDataMgrTest, BmsExtensionDataMgr_0005, Function | SmallTest | Level0)
{
    BmsExtensionDataMgr bmsExtensionDataMgr;
    Want want;
    int32_t flags = 0;
    int32_t userId = 0;
    std::vector<AbilityInfo> abilityInfos;
    ErrCode res = bmsExtensionDataMgr.QueryAbilityInfosWithFlag(want, flags, userId, abilityInfos);
    #ifdef USE_EXTENSION_DATA
    EXPECT_NE(res, ERR_OK);
    #else
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INSTALL_FAILED_BUNDLE_EXTENSION_NOT_EXISTED);
    #endif
}

/**
 * @tc.number: BmsExtensionDataMgr_0006
 * @tc.name: GetBundleInfos
 * @tc.desc: GetBundleInfos
 */
HWTEST_F(BmsExtensionDataMgrTest, BmsExtensionDataMgr_0006, Function | SmallTest | Level0)
{
    BmsExtensionDataMgr bmsExtensionDataMgr;
    int32_t flags = 0;
    int32_t userId = 0;
    std::vector<BundleInfo> bundleInfos;
    ErrCode res = bmsExtensionDataMgr.GetBundleInfos(flags, bundleInfos, userId);
    #ifdef USE_EXTENSION_DATA
    EXPECT_NE(res, ERR_OK);
    #else
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INSTALL_FAILED_BUNDLE_EXTENSION_NOT_EXISTED);
    #endif
}

/**
 * @tc.number: BmsExtensionDataMgr_0007
 * @tc.name: GetBundleInfo
 * @tc.desc: GetBundleInfo
 */
HWTEST_F(BmsExtensionDataMgrTest, BmsExtensionDataMgr_0007, Function | SmallTest | Level0)
{
    BmsExtensionDataMgr bmsExtensionDataMgr;
    std::string bundleName;
    int32_t flags = 0;
    int32_t userId = 0;
    BundleInfo bundleInfo;
    ErrCode res = bmsExtensionDataMgr.GetBundleInfo(bundleName, flags, userId, bundleInfo);
    #ifdef USE_EXTENSION_DATA
    EXPECT_NE(res, ERR_OK);
    #else
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INSTALL_FAILED_BUNDLE_EXTENSION_NOT_EXISTED);
    #endif
}

/**
 * @tc.number: BmsExtensionDataMgr_0008
 * @tc.name: HapVerify
 * @tc.desc: HapVerify
 */
HWTEST_F(BmsExtensionDataMgrTest, BmsExtensionDataMgr_0008, Function | SmallTest | Level0)
{
    BmsExtensionDataMgr bmsExtensionDataMgr;
    std::string filePath;
    Security::Verify::HapVerifyResult hapVerifyResult;
    ErrCode res = bmsExtensionDataMgr.HapVerify(filePath, hapVerifyResult);
    #ifdef USE_EXTENSION_DATA
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_FAILED_INVALID_SIGNATURE_FILE_PATH);
    #else
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_INSTALL_FAILED_SIGNATURE_EXTENSION_NOT_EXISTED);
    #endif
}

/**
 * @tc.number: BmsExtensionDataMgr_0009
 * @tc.name: HapVerify
 * @tc.desc: HapVerify
 */
HWTEST_F(BmsExtensionDataMgrTest, BmsExtensionDataMgr_0009, Function | SmallTest | Level0)
{
    BmsExtensionDataMgr bmsExtensionDataMgr;
    ErrCode res = bmsExtensionDataMgr.Uninstall("");
    #ifdef USE_EXTENSION_DATA
    EXPECT_NE(res, ERR_OK);
    #else
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INSTALL_FAILED_BUNDLE_EXTENSION_NOT_EXISTED);
    #endif
}

/**
 * @tc.number: BmsExtensionDataMgr_0010
 * @tc.name: Uninstall
 * @tc.desc: Uninstall
 */
HWTEST_F(BmsExtensionDataMgrTest, BmsExtensionDataMgr_0010, Function | SmallTest | Level0)
{
    BundleMgrExtTest bundleMgrExtTest;
    ErrCode res = bundleMgrExtTest.Uninstall("");
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INSTALL_FAILED_BUNDLE_EXTENSION_NOT_EXISTED);
}

/**
 * @tc.number: BmsExtensionDataMgr_0011
 * @tc.name: GetBundleStats
 * @tc.desc: GetBundleStats
 */
HWTEST_F(BmsExtensionDataMgrTest, BmsExtensionDataMgr_0011, Function | SmallTest | Level0)
{
    BmsExtensionDataMgr bmsExtensionDataMgr;
    std::vector<int64_t> bundleStats;
    ErrCode res = bmsExtensionDataMgr.GetBundleStats("", USERID, bundleStats);
    #ifdef USE_EXTENSION_DATA
    EXPECT_EQ(res, ERR_APPEXECFWK_FAILED_GET_REMOTE_PROXY);
    #else
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR);
    #endif
}

/**
 * @tc.number: BmsExtensionDataMgr_0012
 * @tc.name: ClearData
 * @tc.desc: ClearData
 */
HWTEST_F(BmsExtensionDataMgrTest, BmsExtensionDataMgr_0012, Function | SmallTest | Level0)
{
    BmsExtensionDataMgr bmsExtensionDataMgr;
    ErrCode res = bmsExtensionDataMgr.ClearData("", USERID);
    #ifdef USE_EXTENSION_DATA
    EXPECT_EQ(res, ERR_APPEXECFWK_FAILED_GET_REMOTE_PROXY);
    #else
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR);
    #endif
}

/**
 * @tc.number: BmsExtensionDataMgr_0013
 * @tc.name: ClearCache
 * @tc.desc: ClearCache
 */
HWTEST_F(BmsExtensionDataMgrTest, BmsExtensionDataMgr_0013, Function | SmallTest | Level0)
{
    BmsExtensionDataMgr bmsExtensionDataMgr;
    ErrCode res = bmsExtensionDataMgr.ClearCache("", nullptr, USERID);
    #ifdef USE_EXTENSION_DATA
    EXPECT_EQ(res, ERR_APPEXECFWK_FAILED_GET_REMOTE_PROXY);
    #else
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR);
    #endif
}

/**
 * @tc.number: BmsExtensionDataMgr_0014
 * @tc.name: GetUidByBundleName
 * @tc.desc: GetUidByBundleName
 */
HWTEST_F(BmsExtensionDataMgrTest, BmsExtensionDataMgr_0014, Function | SmallTest | Level0)
{
    BmsExtensionDataMgr bmsExtensionDataMgr;
    int32_t userId = 100;
    int32_t uid = -1;
    ErrCode res = bmsExtensionDataMgr.GetUidByBundleName("", userId, uid);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR);
}

/**
 * @tc.number: BmsExtensionDataMgr_0015
 * @tc.name: GetBundleNameByUid
 * @tc.desc: GetBundleNameByUid
 */
HWTEST_F(BmsExtensionDataMgrTest, BmsExtensionDataMgr_0015, Function | SmallTest | Level0)
{
    BmsExtensionDataMgr bmsExtensionDataMgr;
    std::string bundleName = "";
    ErrCode res = bmsExtensionDataMgr.GetBundleNameByUid(TEST_UID, bundleName);
    #ifdef USE_EXTENSION_DATA
    EXPECT_EQ(res, ERR_APPEXECFWK_FAILED_GET_REMOTE_PROXY);
    #else
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR);
    #endif
}

/**
 * @tc.number: BmsExtensionDataMgr_0016
 * @tc.name: GetBundleNameByUid
 * @tc.desc: GetBundleNameByUid
 */
HWTEST_F(BmsExtensionDataMgrTest, BmsExtensionDataMgr_0016, Function | SmallTest | Level0)
{
    BmsExtensionDataMgr bmsExtensionDataMgr;
    bool pass = false;
    ErrCode res = bmsExtensionDataMgr.VerifyActivationLock(pass);
    #ifdef USE_EXTENSION_DATA
    EXPECT_NE(res, ERR_OK);
    #else
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR);
    #endif
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

/**
 * @tc.number: BundleMgrExt_0001
 * @tc.name: HapVerify
 * @tc.desc: HapVerify
 */
HWTEST_F(BmsExtensionDataMgrTest, BundleMgrExt_0001, Function | SmallTest | Level0)
{
    BundleMgrExtTest bundleMgrExtTest;
    std::string filePath;
    Security::Verify::HapVerifyResult hapVerifyResult;
    ErrCode res = bundleMgrExtTest.HapVerify(filePath, hapVerifyResult);
    EXPECT_EQ(res, ERR_BUNDLEMANAGER_INSTALL_FAILED_SIGNATURE_EXTENSION_NOT_EXISTED);
}

/**
 * @tc.number: BundleMgrExt_0002
 * @tc.name: QueryAbilityInfos
 * @tc.desc: QueryAbilityInfos
 */
HWTEST_F(BmsExtensionDataMgrTest, BundleMgrExt_0002, Function | SmallTest | Level0)
{
    BundleMgrExtTest bundleMgrExtTest;
    Want want;
    int32_t userId = 0;
    std::vector<AbilityInfo> abilityInfos;
    ErrCode res = bundleMgrExtTest.QueryAbilityInfos(want, userId, abilityInfos);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INSTALL_FAILED_BUNDLE_EXTENSION_NOT_EXISTED);
}

/**
 * @tc.number: BundleMgrExt_0003
 * @tc.name: QueryAbilityInfosWithFlag
 * @tc.desc: QueryAbilityInfosWithFlag
 */
HWTEST_F(BmsExtensionDataMgrTest, BundleMgrExt_0003, Function | SmallTest | Level0)
{
    BundleMgrExtTest bundleMgrExtTest;
    Want want;
    int32_t flags = 0;
    int32_t userId = 0;
    std::vector<AbilityInfo> abilityInfos;
    ErrCode res = bundleMgrExtTest.QueryAbilityInfosWithFlag(want, flags, userId, abilityInfos);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INSTALL_FAILED_BUNDLE_EXTENSION_NOT_EXISTED);
}

/**
 * @tc.number: BundleMgrExt_0004
 * @tc.name: GetBundleInfo
 * @tc.desc: GetBundleInfo
 */
HWTEST_F(BmsExtensionDataMgrTest, BundleMgrExt_0004, Function | SmallTest | Level0)
{
    BundleMgrExtTest bundleMgrExtTest;
    std::string bundleName;
    int32_t flags = 0;
    int32_t userId = 0;
    BundleInfo bundleInfo;
    ErrCode res = bundleMgrExtTest.GetBundleInfo(bundleName, flags, userId, bundleInfo);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INSTALL_FAILED_BUNDLE_EXTENSION_NOT_EXISTED);
}

/**
 * @tc.number: BundleMgrExt_0005
 * @tc.name: GetBundleInfos
 * @tc.desc: GetBundleInfos
 */
HWTEST_F(BmsExtensionDataMgrTest, BundleMgrExt_0005, Function | SmallTest | Level0)
{
    BundleMgrExtTest bundleMgrExtTest;
    int32_t flags = 0;
    int32_t userId = 0;
    std::vector<BundleInfo> bundleInfos;
    ErrCode res = bundleMgrExtTest.GetBundleInfos(flags, bundleInfos, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INSTALL_FAILED_BUNDLE_EXTENSION_NOT_EXISTED);
}

/**
 * @tc.number: BundleMgrExt_0006
 * @tc.name: GetBundleStats
 * @tc.desc: GetBundleStats
 */
HWTEST_F(BmsExtensionDataMgrTest, BundleMgrExt_0006, Function | SmallTest | Level0)
{
    BundleMgrExtTest bundleMgrExtTest;
    std::vector<int64_t> bundleStats;
    ErrCode res = bundleMgrExtTest.GetBundleStats("", USERID, bundleStats);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_EXTENSION_DEFAULT_ERR);
}

/**
 * @tc.number: BundleMgrExt_0007
 * @tc.name: ClearData
 * @tc.desc: ClearData
 */
HWTEST_F(BmsExtensionDataMgrTest, BundleMgrExt_0007, Function | SmallTest | Level0)
{
    BundleMgrExtTest bundleMgrExtTest;
    ErrCode res = bundleMgrExtTest.ClearData("", USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_EXTENSION_DEFAULT_ERR);
}

/**
 * @tc.number: BundleMgrExt_0008
 * @tc.name: ClearCache
 * @tc.desc: ClearCache
 */
HWTEST_F(BmsExtensionDataMgrTest, BundleMgrExt_0008, Function | SmallTest | Level0)
{
    BundleMgrExtTest bundleMgrExtTest;
    ErrCode res = bundleMgrExtTest.ClearCache("", nullptr, USERID);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_EXTENSION_DEFAULT_ERR);
}

/**
 * @tc.number: BundleMgrExt_0009
 * @tc.name: GetUidByBundleName
 * @tc.desc: GetUidByBundleName
 */
HWTEST_F(BmsExtensionDataMgrTest, BundleMgrExt_0009, Function | SmallTest | Level0)
{
    BundleMgrExtTest bundleMgrExtTest;
    int32_t userId = 100;
    int32_t uid = -1;
    ErrCode res = bundleMgrExtTest.GetUidByBundleName("", userId, uid);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_EXTENSION_DEFAULT_ERR);
}

/**
 * @tc.number: BundleMgrExt_0010
 * @tc.name: GetBundleNameByUid
 * @tc.desc: GetBundleNameByUid
 */
HWTEST_F(BmsExtensionDataMgrTest, BundleMgrExt_0010, Function | SmallTest | Level0)
{
    BundleMgrExtTest bundleMgrExtTest;
    std::string bundleName = "";
    ErrCode res = bundleMgrExtTest.GetBundleNameByUid(TEST_UID, bundleName);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_EXTENSION_DEFAULT_ERR);
}

/**
 * @tc.number: BundleMgrExt_0011
 * @tc.name: VerifyActivationLock
 * @tc.desc: VerifyActivationLock
 */
HWTEST_F(BmsExtensionDataMgrTest, BundleMgrExt_0011, Function | SmallTest | Level0)
{
    BundleMgrExtTest bundleMgrExtTest;
    bool pass = false;
    ErrCode res = bundleMgrExtTest.VerifyActivationLock(pass);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_EXTENSION_DEFAULT_ERR);
}

/**
 * @tc.number: BundleMgrExt_0012
 * @tc.name: OptimizeDisposedPredicates
 * @tc.desc: OptimizeDisposedPredicates
 */
HWTEST_F(BmsExtensionDataMgrTest, BundleMgrExt_0012, Function | SmallTest | Level0)
{
    BundleMgrExtTest bundleMgrExtTest;
    bool pass = false;
    std::string callingName = "";
    std::string appId = "";
    NativeRdb::AbsRdbPredicates absRdbPredicates("");
    ErrCode res = bundleMgrExtTest.OptimizeDisposedPredicates(callingName, appId, USERID, 0, absRdbPredicates);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_EXTENSION_DEFAULT_ERR);
}

/**
 * @tc.number: BundleMgrExt_0013
 * @tc.name: GetBackupUninstallList
 * @tc.desc: GetBackupUninstallList
 */
HWTEST_F(BmsExtensionDataMgrTest, BundleMgrExt_0013, Function | SmallTest | Level0)
{
    BundleMgrExtTest bundleMgrExtTest;
    int32_t userId = 100;
    std::set<std::string> uninstallBundles;
    ErrCode res = bundleMgrExtTest.GetBackupUninstallList(userId, uninstallBundles);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_EXTENSION_DEFAULT_ERR);
}

/**
 * @tc.number: BundleMgrExt_0014
 * @tc.name: ClearBackupUninstallFile
 * @tc.desc: ClearBackupUninstallFile
 */
HWTEST_F(BmsExtensionDataMgrTest, BundleMgrExt_0014, Function | SmallTest | Level0)
{
    BundleMgrExtTest bundleMgrExtTest;
    int32_t userId = 100;
    ErrCode res = bundleMgrExtTest.ClearBackupUninstallFile(userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_EXTENSION_DEFAULT_ERR);
}

/**
 * @tc.number: BundleMgrExt_0015
 * @tc.name: AddResourceInfoByBundleName
 * @tc.desc: AddResourceInfoByBundleName
 */
HWTEST_F(BmsExtensionDataMgrTest, BundleMgrExt_0015, Function | SmallTest | Level0)
{
    BundleMgrExtTest bundleMgrExtTest;
    std::string bundleName{ "extension" };
    int32_t userId = 100;
    ErrCode res = bundleMgrExtTest.AddResourceInfoByBundleName(bundleName, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_EXTENSION_DEFAULT_ERR);
}

/**
 * @tc.number: BundleMgrExt_0016
 * @tc.name: AddResourceInfoByAbility
 * @tc.desc: AddResourceInfoByAbility
 */
HWTEST_F(BmsExtensionDataMgrTest, BundleMgrExt_0016, Function | SmallTest | Level0)
{
    BundleMgrExtTest bundleMgrExtTest;
    std::string bundleName{ "extension" };
    std::string moduleName{ "extension-module" };
    std::string abilityName{ "extension-ability" };
    int32_t userId = 100;
    ErrCode res = bundleMgrExtTest.AddResourceInfoByAbility(bundleName, moduleName, abilityName, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_EXTENSION_DEFAULT_ERR);
}

/**
 * @tc.number: BundleMgrExt_0017
 * @tc.name: DeleteResourceInfo
 * @tc.desc: DeleteResourceInfo
 */
HWTEST_F(BmsExtensionDataMgrTest, BundleMgrExt_0017, Function | SmallTest | Level0)
{
    BundleMgrExtTest bundleMgrExtTest;
    std::string key{ "extension-key" };
    int32_t userId = 100;
    ErrCode res = bundleMgrExtTest.DeleteResourceInfo(key);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_EXTENSION_DEFAULT_ERR);
}

/**
 * @tc.number: BundleMgrExt_0018
 * @tc.name: OptimizeDisposedPredicates
 * @tc.desc: OptimizeDisposedPredicates
 */
HWTEST_F(BmsExtensionDataMgrTest, BundleMgrExt_0018, Function | SmallTest | Level0)
{
    BundleMgrExtTest bundleMgrExtTest;
    std::string callingName{ "test" };
    std::string appId{ "20214524" };
    NativeRdb::AbsRdbPredicates absRdbPredicates("");
    int32_t userId = 100;
    ErrCode res = bundleMgrExtTest.OptimizeDisposedPredicates(callingName, appId, userId, 0, absRdbPredicates);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_EXTENSION_DEFAULT_ERR);
}

/**
 * @tc.number: BundleMgrExt_0019
 * @tc.name: IsAppInBlocklist
 * @tc.desc: IsAppInBlocklist
 */
HWTEST_F(BmsExtensionDataMgrTest, BundleMgrExt_0019, Function | SmallTest | Level0)
{
    BundleMgrExtTest bundleMgrExtTest;
    std::string bundleName{ "extension" };
    auto res = bundleMgrExtTest.IsAppInBlocklist(bundleName);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: BundleMgrExt_0020
 * @tc.name: CheckWhetherCanBeUninstalled
 * @tc.desc: CheckWhetherCanBeUninstalled
 */
HWTEST_F(BmsExtensionDataMgrTest, BundleMgrExt_0020, Function | SmallTest | Level0)
{
    BundleMgrExtTest bundleMgrExtTest;
    std::string bundleName{ "extension" };
    auto res = bundleMgrExtTest.CheckWhetherCanBeUninstalled(bundleName);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: BmsExtensionDataMgr_0017
 * @tc.name: GetBackupUninstallList
 * @tc.desc: GetBackupUninstallList
 */
HWTEST_F(BmsExtensionDataMgrTest, BmsExtensionDataMgr_0017, Function | SmallTest | Level0)
{
    BmsExtensionDataMgr bmsExtensionDataMgr;

    int32_t userId = 100;
    std::set<std::string> uninstallBundles;
    ErrCode res = bmsExtensionDataMgr.GetBackupUninstallList(userId, uninstallBundles);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR);
}

/**
 * @tc.number: BmsExtensionDataMgr_0018
 * @tc.name: ClearBackupUninstallFile
 * @tc.desc: ClearBackupUninstallFile
 */
HWTEST_F(BmsExtensionDataMgrTest, BmsExtensionDataMgr_0018, Function | SmallTest | Level0)
{
    BmsExtensionDataMgr bmsExtensionDataMgr;

    int32_t userId = 100;
    ErrCode res = bmsExtensionDataMgr.ClearBackupUninstallFile(userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR);
}

/**
 * @tc.number: BmsExtensionDataMgr_0019
 * @tc.name: AddResourceInfoByBundleName
 * @tc.desc: AddResourceInfoByBundleName
 */
HWTEST_F(BmsExtensionDataMgrTest, BmsExtensionDataMgr_0019, Function | SmallTest | Level0)
{
    BmsExtensionDataMgr bmsExtensionDataMgr;

    std::string bundleName{ "extension" };
    int32_t userId = 100;
    ErrCode res = bmsExtensionDataMgr.AddResourceInfoByBundleName(bundleName, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR);
}

/**
 * @tc.number: BmsExtensionDataMgr_0020
 * @tc.name: AddResourceInfoByAbility
 * @tc.desc: AddResourceInfoByAbility
 */
HWTEST_F(BmsExtensionDataMgrTest, BmsExtensionDataMgr_0020, Function | SmallTest | Level0)
{
    BmsExtensionDataMgr bmsExtensionDataMgr;

    std::string bundleName{ "extension" };
    std::string moduleName{ "extension-module" };
    std::string abilityName{ "extension-ability" };
    int32_t userId = 100;
    ErrCode res = bmsExtensionDataMgr.AddResourceInfoByAbility(bundleName, moduleName, abilityName, userId);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR);
}

/**
 * @tc.number: BmsExtensionDataMgr_0021
 * @tc.name: DeleteResourceInfo
 * @tc.desc: DeleteResourceInfo
 */
HWTEST_F(BmsExtensionDataMgrTest, BmsExtensionDataMgr_0021, Function | SmallTest | Level0)
{
    BmsExtensionDataMgr bmsExtensionDataMgr;

    std::string key{ "10-15-26" };
    int32_t userId = 100;
    ErrCode res = bmsExtensionDataMgr.DeleteResourceInfo(key);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_EXTENSION_INTERNAL_ERR);
}

/**
 * @tc.number: BmsExtensionDataMgr_0022
 * @tc.name: IsAppInBlocklist
 * @tc.desc: IsAppInBlocklist
 */
HWTEST_F(BmsExtensionDataMgrTest, BmsExtensionDataMgr_0022, Function | SmallTest | Level0)
{
    BmsExtensionDataMgr bmsExtensionDataMgr;

    std::string bundleName{ "extension" };
    auto res = bmsExtensionDataMgr.IsAppInBlocklist(bundleName);
    EXPECT_FALSE(res);
}

/**
 * @tc.number: BmsExtensionDataMgr_0023
 * @tc.name: CheckWhetherCanBeUninstalled
 * @tc.desc: CheckWhetherCanBeUninstalled
 */
HWTEST_F(BmsExtensionDataMgrTest, BmsExtensionDataMgr_0023, Function | SmallTest | Level0)
{
    BmsExtensionDataMgr bmsExtensionDataMgr;

    std::string bundleName{ "extension" };
    auto res = bmsExtensionDataMgr.CheckWhetherCanBeUninstalled(bundleName);
    EXPECT_TRUE(res);
}

/**
 * @tc.number: BmsExtensionDataMgr_0024
 * @tc.name: Init
 * @tc.desc: Init
 */
HWTEST_F(BmsExtensionDataMgrTest, BmsExtensionDataMgr_0024, Function | SmallTest | Level0)
{
    BmsExtensionDataMgr bmsExtensionDataMgr;
    bool res = bmsExtensionDataMgr.Init();
    EXPECT_TRUE(res);
}

/**
 * @tc.number: BmsExtensionKeyOperation_0001
 * @tc.name: KeyOperation
 * @tc.desc: KeyOperation
 */
HWTEST_F(BmsExtensionDataMgrTest, BmsExtensionKeyOperation_0001, Function | SmallTest | Level0)
{
    BmsExtensionDataMgr bmsExtensionDataMgr;
    std::vector<CodeProtectBundleInfo> codeProtectBundleInfos;
    auto res = bmsExtensionDataMgr.KeyOperation(codeProtectBundleInfos, 1);
    EXPECT_NE(res, ERR_OK);
}

/**
 * @tc.number: BmsExtensionKeyOperation_0002
 * @tc.name: KeyOperation
 * @tc.desc: KeyOperation
 */
HWTEST_F(BmsExtensionDataMgrTest, BmsExtensionKeyOperation_0002, Function | SmallTest | Level0)
{
    BundleMgrExtTest bundleMgrExtTest;
    std::vector<CodeProtectBundleInfo> codeProtectBundleInfos;
    auto res = bundleMgrExtTest.KeyOperation(codeProtectBundleInfos, 1);
    EXPECT_NE(res, ERR_OK);
}
} // OHOS