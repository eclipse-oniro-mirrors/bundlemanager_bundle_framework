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
#include <sstream>
#include <unordered_map>
#include <vector>

#include "appexecfwk_errors.h"
#include "bundle_install_checker.h"
#include "bundle_extractor.h"
#include "bundle_profile.h"
#include "inner_bundle_info.h"
#include "bundle_mgr_service.h"
#include "parameters.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
namespace OHOS {
namespace {
const std::string TEST_BUNDLE_NAME = "com.test.demo";
const std::string DEVICE_TYPE_OF_PHONE = "phone";
const std::string DEVICE_TYPE_OF_DEFAULT = "default";
const std::string DEVICE_TYPE_OF_CAR = "car";
const std::string FA_MODULE_PACKAGE = "com.example.fadevfeat";

const nlohmann::json FA_CONFIG_JSON = R"(
{
    "app":{
        "apiVersion":{
            "compatible":8,
            "releaseType":"Release",
            "target":8
        },
        "bundleName":"com.example.fadevfeat",
        "vendor":"example",
        "version":{
            "code":1000000,
            "name":"1.0.0"
        }
    },
    "deviceConfig":{
        "default":{
            "debug":true
        }
    },
    "module":{
        "abilities":[
            {
                "icon":"$media:icon",
                "label":"$string:MainAbility_label",
                "launchType":"standard",
                "name":".MainAbility",
                "orientation":"unspecified",
                "srcLanguage":"ets",
                "srcPath":"MainAbility",
                "type":"page",
                "visible":true
            }
        ],
        "deviceType":[
            "car"
        ],
        "requiredDeviceFeatures":{
            "phone":[
                "large_screen",
                "paint"
            ],
            "2in1":[
                "paint"
            ],
            "wearable":[
                "child"
            ]
        },
        "distro":{
            "deliveryWithInstall":true,
            "installationFree":false,
            "moduleName":"entry",
            "moduleType":"entry",
            "virtualMachine":"ark0.0.0.2"
        },
        "js":[
            {
                "mode":{
                    "syntax":"ets",
                    "type":"pageAbility"
                },
                "name":".MainAbility",
                "pages":[
                    "pages/index"
                ],
                "window":{
                    "autoDesignWidth":false,
                    "designWidth":720
                }
            }
        ],
        "mainAbility":".MainAbility",
        "name":".entry",
        "package":"com.example.fadevfeat"
    }
}
)"_json;
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
    auto ret = checker.CheckDeviceType(infos, ERR_OK);
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
    auto ret = checker.CheckDeviceType(infos, ERR_OK);
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
    auto ret = checker.CheckDeviceType(infos, ERR_OK);
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
    auto ret = checker.CheckDeviceType(infos, ERR_OK);
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
    auto ret = checker.CheckDeviceType(infos, ERR_OK);
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
    auto ret = checker.CheckDeviceType(infos, ERR_OK);
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
    auto ret = checker.CheckDeviceType(infos, ERR_OK);
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

/**
 * @tc.number: IsSubSet
 * @tc.name: test IsSubSet
 * @tc.desc: IsSubSet
 */
HWTEST_F(BmsBundleInstallDeviceTypeTest, IsSubSet_0100, Function | SmallTest | Level0)
{
    std::vector<std::string> vec = {"111"};
    std::vector<std::string> vec2 = {"111"};
    std::vector<std::string> vec3 = {"222"};
    std::vector<std::string> vec4 = {"222", "333"};
    std::vector<std::string> vec5 = {"111", "222", "333"};
    std::vector<std::string> vec6 = {"222", "333", "444"};
    BundleInstallChecker checker;
    EXPECT_TRUE(checker.IsSubSet(vec, vec2));
    EXPECT_TRUE(checker.IsSubSet(vec2, vec));

    EXPECT_FALSE(checker.IsSubSet(vec3, vec4));
    EXPECT_TRUE(checker.IsSubSet(vec4, vec3));

    EXPECT_FALSE(checker.IsSubSet(vec4, vec5));
    EXPECT_TRUE(checker.IsSubSet(vec5, vec4));

    EXPECT_FALSE(checker.IsSubSet(vec5, vec6));
    EXPECT_FALSE(checker.IsSubSet(vec6, vec5));
}

/**
 * @tc.number: DeviceTypeTest_1100
 * @tc.name: test FA config.json requiredDeviceFeatures fallback passes in CheckDeviceType
 * @tc.desc: 1. Parse FA config.json with requiredDeviceFeatures declared in module
 *           2. Module deviceTypes does not contain current device type
 *           3. Required features are subset of provided device features, install check passes
 */
HWTEST_F(BmsBundleInstallDeviceTypeTest, DeviceTypeTest_1100, Function | SmallTest | Level0)
{
    BundleProfile bundleProfile;
    InnerBundleInfo innerBundleInfo;
    std::ostringstream profileFileBuffer;
    profileFileBuffer << FA_CONFIG_JSON.dump();
    BundleExtractor bundleExtractor("");
    ErrCode parseResult = bundleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    ASSERT_EQ(parseResult, ERR_OK);

    // requiredDeviceFeatures is parsed from FA config.json
    auto requiredDeviceFeatures = innerBundleInfo.GetRequiredDeviceFeatures(FA_MODULE_PACKAGE);
    ASSERT_EQ(requiredDeviceFeatures.size(), 3);
    auto itPhone = requiredDeviceFeatures.find(DEVICE_TYPE_OF_PHONE);
    ASSERT_NE(itPhone, requiredDeviceFeatures.end());
    EXPECT_EQ(itPhone->second.size(), 2);
    EXPECT_EQ(itPhone->second[0], "large_screen");
    EXPECT_EQ(itPhone->second[1], "paint");
    auto it2in1 = requiredDeviceFeatures.find("2in1");
    ASSERT_NE(it2in1, requiredDeviceFeatures.end());
    EXPECT_EQ(it2in1->second.size(), 1);
    EXPECT_EQ(it2in1->second[0], "paint");
    auto itWearable = requiredDeviceFeatures.find("wearable");
    ASSERT_NE(itWearable, requiredDeviceFeatures.end());
    EXPECT_EQ(itWearable->second.size(), 1);
    EXPECT_EQ(itWearable->second[0], "child");

    innerBundleInfo.SetCurrentModulePackage(FA_MODULE_PACKAGE);
    std::unordered_map<std::string, InnerBundleInfo> infos;
    infos.emplace("test.hap", innerBundleInfo);

    // current device type is phone while module only declares car, fallback to requiredDeviceFeatures
    g_testDeviceType = const_cast<char *>(DEVICE_TYPE_OF_PHONE.c_str());
    constexpr const char* supportAppTypesKey = "const.bms.supportAppTypes";
    constexpr const char* providedDeviceFeaturesKey = "const.product.providedDeviceFeatures";
    OHOS::system::SetParameter(supportAppTypesKey, "");
    OHOS::system::SetParameter(providedDeviceFeaturesKey, "large_screen,paint,child");

    BundleInstallChecker checker;
    auto ret = checker.CheckDeviceType(infos, ERR_OK);
    EXPECT_EQ(ret, ERR_OK);

    OHOS::system::SetParameter(providedDeviceFeaturesKey, "");
    g_testDeviceType = const_cast<char *>("");
}

/**
 * @tc.number: DeviceTypeTest_1200
 * @tc.name: test FA config.json requiredDeviceFeatures fallback rejected in CheckDeviceType
 * @tc.desc: 1. Parse FA config.json with requiredDeviceFeatures declared in module
 *           2. Module deviceTypes does not contain current device type
 *           3. Required features are not subset of provided device features, install check fails
 */
HWTEST_F(BmsBundleInstallDeviceTypeTest, DeviceTypeTest_1200, Function | SmallTest | Level0)
{
    BundleProfile bundleProfile;
    InnerBundleInfo innerBundleInfo;
    std::ostringstream profileFileBuffer;
    profileFileBuffer << FA_CONFIG_JSON.dump();
    BundleExtractor bundleExtractor("");
    ErrCode parseResult = bundleProfile.TransformTo(
        profileFileBuffer, bundleExtractor, innerBundleInfo);
    ASSERT_EQ(parseResult, ERR_OK);

    innerBundleInfo.SetCurrentModulePackage(FA_MODULE_PACKAGE);
    std::unordered_map<std::string, InnerBundleInfo> infos;
    infos.emplace("test.hap", innerBundleInfo);

    g_testDeviceType = const_cast<char *>(DEVICE_TYPE_OF_PHONE.c_str());
    constexpr const char* supportAppTypesKey = "const.bms.supportAppTypes";
    constexpr const char* providedDeviceFeaturesKey = "const.product.providedDeviceFeatures";
    OHOS::system::SetParameter(supportAppTypesKey, "");
    OHOS::system::SetParameter(providedDeviceFeaturesKey, "paint");

    BundleInstallChecker checker;
    auto ret = checker.CheckDeviceType(infos, ERR_OK);
    EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_DEVICE_TYPE_NOT_SUPPORTED);

    OHOS::system::SetParameter(providedDeviceFeaturesKey, "");
    g_testDeviceType = const_cast<char *>("");
}
} // OHOS