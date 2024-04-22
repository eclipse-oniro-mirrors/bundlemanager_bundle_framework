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

#include <gtest/gtest.h>
#include <unordered_map>
#include <vector>

#include "appexecfwk_errors.h"
#include "bundle_install_checker.h"
#include "inner_bundle_info.h"
#include "bundle_mgr_service.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
namespace OHOS {
namespace {
const std::string TEST_BUNDLE_NAME = "com.test.demo";
const std::string DEVICE_TYPE_OF_PHONE = "phone";
const std::string DEVICE_TYPE_OF_DEFAULT = "default";
const std::string DEVICE_TYPE_OF_CAR = "car";
}; // namespace

extern char *g_testDeviceType;

class BmsBundleInstallDeviceTypeTest : public testing::Test {
public:
    BmsBundleInstallDeviceTypeTest();
    ~BmsBundleInstallDeviceTypeTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    static void SetDeviceTypes(std::unordered_map<std::string, InnerBundleInfo> &infos,
        const std::vector<std::string> &deviceTypes);
    void SetUp();
    void TearDown();
private:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsBundleInstallDeviceTypeTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

BmsBundleInstallDeviceTypeTest::BmsBundleInstallDeviceTypeTest()
{
}

BmsBundleInstallDeviceTypeTest::~BmsBundleInstallDeviceTypeTest()
{
}

void BmsBundleInstallDeviceTypeTest::SetUpTestCase()
{
}

void BmsBundleInstallDeviceTypeTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleInstallDeviceTypeTest::SetUp()
{
}

void BmsBundleInstallDeviceTypeTest::TearDown()
{
}

void BmsBundleInstallDeviceTypeTest::SetDeviceTypes(std::unordered_map<std::string, InnerBundleInfo> &infos,
                                                    const std::vector<std::string> &deviceTypes)
{
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetCurrentModulePackage(TEST_BUNDLE_NAME);
    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.deviceTypes = deviceTypes;
    std::map<std::string, InnerModuleInfo> moduleInfoMap = {{TEST_BUNDLE_NAME, innerModuleInfo}};
    innerBundleInfo.AddInnerModuleInfo(moduleInfoMap);
    infos[TEST_BUNDLE_NAME] = innerBundleInfo;
}

/**
 * @tc.number: DeviceTypeTest_0100
 * @tc.name: test CheckDeviceType function of BundleInstallChecker
 * @tc.desc: 1. Obtain current device type
 *           2. Obtain device type list of the unordered_map of InnerbundleInfo
 * @tc.require: issueI5XD60
 */
HWTEST_F(BmsBundleInstallDeviceTypeTest, DeviceTypeTest_0100, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, InnerBundleInfo> infos;
    std::vector<std::string> vec;
    SetDeviceTypes(infos, vec);

    // device type list is empty
    BundleInstallChecker checker;
    auto ret = checker.CheckDeviceType(infos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: DeviceTypeTest_0200
 * @tc.name: test CheckDeviceType function of BundleInstallChecker
 * @tc.desc: 1. Obtain current device type
 *           2. Obtain device type list of the unordered_map of InnerbundleInfo
 * @tc.require: issueI5XD60
 */
HWTEST_F(BmsBundleInstallDeviceTypeTest, DeviceTypeTest_0200, Function | SmallTest | Level0)
{
    // mock innerbundleinfo with default device type
    std::unordered_map<std::string, InnerBundleInfo> infos;
    std::vector<std::string> vec = {DEVICE_TYPE_OF_DEFAULT};
    SetDeviceTypes(infos, vec);

    g_testDeviceType = const_cast<char *>(DEVICE_TYPE_OF_PHONE.c_str());
    // device type list is default and current device is phone
    BundleInstallChecker checker;
    auto ret = checker.CheckDeviceType(infos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: DeviceTypeTest_0300
 * @tc.name: test CheckDeviceType function of BundleInstallChecker
 * @tc.desc: 1. Obtain current device type
 *           2. Obtain device type list of the unordered_map of InnerbundleInfo
 * @tc.require: issueI5XD60
 */
HWTEST_F(BmsBundleInstallDeviceTypeTest, DeviceTypeTest_0300, Function | SmallTest | Level0)
{
    // mock innerbundleinfo with default device type
    std::unordered_map<std::string, InnerBundleInfo> infos;
    std::vector<std::string> vec = {DEVICE_TYPE_OF_PHONE};
    SetDeviceTypes(infos, vec);

    g_testDeviceType = const_cast<char *>(DEVICE_TYPE_OF_PHONE.c_str());
    // device type list is phone and current device is phone
    BundleInstallChecker checker;
    auto ret = checker.CheckDeviceType(infos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: DeviceTypeTest_0400
 * @tc.name: test CheckDeviceType function of BundleInstallChecker
 * @tc.desc: 1. Obtain current device type
 *           2. Obtain device type list of the unordered_map of InnerbundleInfo
 * @tc.require: issueI5XD60
 */
HWTEST_F(BmsBundleInstallDeviceTypeTest, DeviceTypeTest_0400, Function | SmallTest | Level0)
{
    // mock innerbundleinfo with default device type
    std::unordered_map<std::string, InnerBundleInfo> infos;
    std::vector<std::string> vec = {DEVICE_TYPE_OF_CAR};
    SetDeviceTypes(infos, vec);

    g_testDeviceType = const_cast<char *>(DEVICE_TYPE_OF_PHONE.c_str());
    // device type list is car and current device is phone
    BundleInstallChecker checker;
    auto ret = checker.CheckDeviceType(infos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_DEVICE_TYPE_NOT_SUPPORTED);
}

/**
 * @tc.number: DeviceTypeTest_0500
 * @tc.name: test CheckDeviceType function of BundleInstallChecker
 * @tc.desc: 1. Obtain current device type
 *           2. Obtain device type list of the unordered_map of InnerbundleInfo
 * @tc.require: issueI5XD60
 */
HWTEST_F(BmsBundleInstallDeviceTypeTest, DeviceTypeTest_0500, Function | SmallTest | Level0)
{
    // mock innerbundleinfo with default device type
    std::unordered_map<std::string, InnerBundleInfo> infos;
    std::vector<std::string> vec = {DEVICE_TYPE_OF_DEFAULT};
    SetDeviceTypes(infos, vec);

    g_testDeviceType = const_cast<char *>(DEVICE_TYPE_OF_DEFAULT.c_str());
    // device type list is default and current device is default
    BundleInstallChecker checker;
    auto ret = checker.CheckDeviceType(infos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: DeviceTypeTest_0600
 * @tc.name: test CheckDeviceType function of BundleInstallChecker
 * @tc.desc: 1. Obtain current device type
 *           2. Obtain device type list of the unordered_map of InnerbundleInfo
 * @tc.require: issueI5XD60
 */
HWTEST_F(BmsBundleInstallDeviceTypeTest, DeviceTypeTest_0600, Function | SmallTest | Level0)
{
    // mock innerbundleinfo with default device type
    std::unordered_map<std::string, InnerBundleInfo> infos;
    std::vector<std::string> vec = {DEVICE_TYPE_OF_PHONE};
    SetDeviceTypes(infos, vec);

    g_testDeviceType = const_cast<char *>(DEVICE_TYPE_OF_DEFAULT.c_str());
    // device type list is phone and current device is default
    BundleInstallChecker checker;
    auto ret = checker.CheckDeviceType(infos);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.number: DeviceTypeTest_0700
 * @tc.name: test CheckDeviceType function of BundleInstallChecker
 * @tc.desc: 1. Obtain current device type
 *           2. Obtain device type list of the unordered_map of InnerbundleInfo
 * @tc.require: issueI5XD60
 */
HWTEST_F(BmsBundleInstallDeviceTypeTest, DeviceTypeTest_0700, Function | SmallTest | Level0)
{
    // mock innerbundleinfo with default device type
    std::unordered_map<std::string, InnerBundleInfo> infos;
    std::vector<std::string> vec = {DEVICE_TYPE_OF_CAR};
    SetDeviceTypes(infos, vec);

    g_testDeviceType = const_cast<char *>(DEVICE_TYPE_OF_DEFAULT.c_str());
    // device type list is car and current device is default
    BundleInstallChecker checker;
    auto ret = checker.CheckDeviceType(infos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_DEVICE_TYPE_NOT_SUPPORTED);
}

/**
 * @tc.number: CheckSupportAppTypes_0100
 * @tc.name: test CheckSupportAppTypes function of BundleInstallChecker
 * @tc.desc: 1. system run normally
 *           2. test CheckSupportAppTypes
 */
HWTEST_F(BmsBundleInstallDeviceTypeTest, CheckSupportAppTypes_0100, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, InnerBundleInfo> infos;
    std::vector<std::string> vec;
    SetDeviceTypes(infos, vec);
    std::string supportAppTypes = "";
    BundleInstallChecker checker;
    bool ret = checker.CheckSupportAppTypes(infos, supportAppTypes);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: CheckSupportAppTypes_0200
 * @tc.name: test CheckSupportAppTypes function of BundleInstallChecker
 * @tc.desc: 1. system run normally
 *           2. test CheckSupportAppTypes
 */
HWTEST_F(BmsBundleInstallDeviceTypeTest, CheckSupportAppTypes_0200, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, InnerBundleInfo> infos;
    std::vector<std::string> vec = {DEVICE_TYPE_OF_PHONE};
    SetDeviceTypes(infos, vec);
    std::string supportAppTypes = "";
    BundleInstallChecker checker;
    bool ret = checker.CheckSupportAppTypes(infos, supportAppTypes);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: CheckSupportAppTypes_0300
 * @tc.name: test CheckSupportAppTypes function of BundleInstallChecker
 * @tc.desc: 1. system run normally
 *           2. test CheckSupportAppTypes
 */
HWTEST_F(BmsBundleInstallDeviceTypeTest, CheckSupportAppTypes_0300, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, InnerBundleInfo> infos;
    std::vector<std::string> vec;
    SetDeviceTypes(infos, vec);
    std::string supportAppTypes = DEVICE_TYPE_OF_PHONE;
    BundleInstallChecker checker;
    bool ret = checker.CheckSupportAppTypes(infos, supportAppTypes);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: CheckSupportAppTypes_0400
 * @tc.name: test CheckSupportAppTypes function of BundleInstallChecker
 * @tc.desc: 1. system run normally
 *           2. test CheckSupportAppTypes
 */
HWTEST_F(BmsBundleInstallDeviceTypeTest, CheckSupportAppTypes_0400, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, InnerBundleInfo> infos;
    std::vector<std::string> vec = {DEVICE_TYPE_OF_PHONE};
    SetDeviceTypes(infos, vec);
    std::string supportAppTypes = DEVICE_TYPE_OF_PHONE;
    BundleInstallChecker checker;
    bool ret = checker.CheckSupportAppTypes(infos, supportAppTypes);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: CheckSupportAppTypes_0500
 * @tc.name: test CheckSupportAppTypes function of BundleInstallChecker
 * @tc.desc: 1. system run normally
 *           2. test CheckSupportAppTypes
 */
HWTEST_F(BmsBundleInstallDeviceTypeTest, CheckSupportAppTypes_0500, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, InnerBundleInfo> infos;
    std::vector<std::string> vec = {DEVICE_TYPE_OF_PHONE};
    SetDeviceTypes(infos, vec);
    std::string supportAppTypes = DEVICE_TYPE_OF_DEFAULT;
    BundleInstallChecker checker;
    bool ret = checker.CheckSupportAppTypes(infos, supportAppTypes);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: CheckSupportAppTypes_0600
 * @tc.name: test CheckSupportAppTypes function of BundleInstallChecker
 * @tc.desc: 1. system run normally
 *           2. test CheckSupportAppTypes
 */
HWTEST_F(BmsBundleInstallDeviceTypeTest, CheckSupportAppTypes_0600, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, InnerBundleInfo> infos;
    std::vector<std::string> vec = {DEVICE_TYPE_OF_DEFAULT};
    SetDeviceTypes(infos, vec);
    std::string supportAppTypes = DEVICE_TYPE_OF_PHONE;
    BundleInstallChecker checker;
    bool ret = checker.CheckSupportAppTypes(infos, supportAppTypes);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: CheckSupportAppTypes_0700
 * @tc.name: test CheckSupportAppTypes function of BundleInstallChecker
 * @tc.desc: 1. system run normally
 *           2. test CheckSupportAppTypes
 */
HWTEST_F(BmsBundleInstallDeviceTypeTest, CheckSupportAppTypes_0700, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, InnerBundleInfo> infos;
    std::vector<std::string> vec = {DEVICE_TYPE_OF_DEFAULT};
    SetDeviceTypes(infos, vec);
    std::string supportAppTypes = DEVICE_TYPE_OF_DEFAULT;
    BundleInstallChecker checker;
    bool ret = checker.CheckSupportAppTypes(infos, supportAppTypes);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: CheckSupportAppTypes_0800
 * @tc.name: test CheckSupportAppTypes function of BundleInstallChecker
 * @tc.desc: 1. system run normally
 *           2. test CheckSupportAppTypes
 */
HWTEST_F(BmsBundleInstallDeviceTypeTest, CheckSupportAppTypes_0800, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, InnerBundleInfo> infos;
    std::vector<std::string> vec = {DEVICE_TYPE_OF_CAR};
    SetDeviceTypes(infos, vec);
    std::string supportAppTypes = DEVICE_TYPE_OF_DEFAULT;
    BundleInstallChecker checker;
    bool ret = checker.CheckSupportAppTypes(infos, supportAppTypes);
    EXPECT_FALSE(ret);
}
} // OHOS