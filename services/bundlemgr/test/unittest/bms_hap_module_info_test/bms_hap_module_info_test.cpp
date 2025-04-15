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
#define private public
#define protected public
#include <fstream>
#include <future>
#include <gtest/gtest.h>

#include "app_jump_control_rule.h"
#include "application_info.h"
#include "bundle_file_util.h"
#include "bundle_pack_info.h"
#include "code_protect_bundle_info.h"
#include "data_group_info.h"
#include "disposed_rule.h"
#include "extension_ability_info.h"
#include "form_info.h"
#include "hap_module_info.h"
#include "json_util.h"
#include "preinstalled_application_info.h"
#include "nlohmann/json.hpp"
#include "skill.h"
#include "recoverable_application_info.h"
#include "want.h"

using namespace testing::ext;
using OHOS::AAFwk::Want;

namespace OHOS {
namespace AppExecFwk {

const char* PRELOAD_ITEM_MODULE_NAME = "moduleName";
const uint32_t HAP_MODULE_INFO_VERSION_CODE = 0;
constexpr const char* BUNDLE_NAME = "bundleName";
constexpr const char* MODULE_NAME = "moduleName";
const char* ROUTER_ITEM_KEY_NAME = "name";
const char* ROUTER_ITEM_KEY_BUILD_FUNCTION = "buildFunction";
const char* APP_ENVIRONMENTS_NAME = "name";
const char* APP_ENVIRONMENTS_VALUE = "value";
const uint32_t HAP_MODULE_INFO_LABEL_ID = 10;
const char* HAP_MODULE_INFO_HAP_PATH = "hapPath";
const uint32_t JSON_KEY_LABEL_ID = 20;
const uint32_t JSON_KEY_ICON_ID = 30;
const std::string DATAGROUPID = "dataGroupId";
const std::string UUID = "uuid";
const uint32_t UID = 2;
const uint32_t GID = 3;
const uint32_t USERID = 4;
const int32_t ZERO_SIZE = 0;
const int32_t INVALIED_ID = -1;
const std::string HOST = "host";
const std::string PORT = "port";
const std::string PATH = "path";
const std::string SCHEME = "scheme";
const std::string PATHREGEX = "pathRegex";
const std::string PORT1 = "port";
const std::string PACKAGE = "package";
const std::string TYPE = "type";
const std::string NAME = "name";
const std::string VALUE = "value";
const std::string CALLERPKG = "caller";
const std::string TARGETPKG = "target";
const std::string CONTROLMESSAGE = "control";
const std::string BUNDLENAME = "bundleName";
const std::string MODULENAME = "moduleName";
const std::uint32_t LABEL_ID = 10;
const std::uint32_t ICON_ID = 20;
constexpr int32_t JUMP_MODE = static_cast<int32_t>(AbilityJumpMode::DIRECT);
const std::string BUNDLE_NAME1 = "testBundleName";
constexpr int32_t UID1 = 100;
constexpr int32_t APPINDEX = 10;
constexpr uint32_t VERSIONCODE = 20;
constexpr uint32_t APPLICATIONRESERVEDFLAG = 30;
const std::string BUNDLE_NAME2 = "testBundleName";
const std::string MODULE_NAME2 = "testModuleName";
const std::string ABILITY_NAME = "testAbilityName";
const char* DEVICE_ID = "deviceId";

void to_json(nlohmann::json &jsonObject, const PreloadItem &preloadItem);
void from_json(const nlohmann::json &jsonObject, PreloadItem &preloadItem);
void to_json(nlohmann::json &jsonObject, const Dependency &dependency);
void from_json(const nlohmann::json &jsonObject, Dependency &dependency);
void to_json(nlohmann::json &jsonObject, const RouterItem &routerItem);
void from_json(const nlohmann::json &jsonObject, RouterItem &routerItem);
void to_json(nlohmann::json &jsonObject, const AppEnvironment &appEnvironment);
void from_json(const nlohmann::json &jsonObject, AppEnvironment &appEnvironment);
void to_json(nlohmann::json &jsonObject, const HapModuleInfo &hapModuleInfo);
void to_json(nlohmann::json &jsonObject, const RecoverableApplicationInfo &recoverableApplicationInfo);
void from_json(const nlohmann::json &jsonObject, RecoverableApplicationInfo &recoverableApplicationInfo);
void to_json(nlohmann::json &jsonObject, const ApplicationEnvironment &applicationEnvironment);
void from_json(const nlohmann::json &jsonObject, ApplicationEnvironment &applicationEnvironment);
void to_json(nlohmann::json &jsonObject, const HnpPackage &hnpPackage);
void from_json(const nlohmann::json &jsonObject, HnpPackage &hnpPackage);
void to_json(nlohmann::json &jsonObject, const FormCustomizeData &customizeDatas);
void to_json(nlohmann::json &jsonObject, const CodeProtectBundleInfo &CodeProtectBundleInfo);
void from_json(const nlohmann::json &jsonObject, CodeProtectBundleInfo &CodeProtectBundleInfo);
void to_json(nlohmann::json &jsonObject, const ElementName &elementName);
void from_json(const nlohmann::json &jsonObject, ElementName &elementName);
void to_json(nlohmann::json &jsonObject, const DisposedRule &disposedRule);
void from_json(const nlohmann::json &jsonObject, DisposedRule &disposedRule);

class BmsHapModuleInfoTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BmsHapModuleInfoTest::SetUpTestCase()
{}

void BmsHapModuleInfoTest::TearDownTestCase()
{}

void BmsHapModuleInfoTest::SetUp()
{}

void BmsHapModuleInfoTest::TearDown()
{}

/**
 * @tc.number: BmsHapModuleInfoTest_0100
 * @tc.name: test to_json interface in HapModuleInfo.
 */
HWTEST_F(BmsHapModuleInfoTest, to_json_0100, Function | SmallTest | Level0)
{
    PreloadItem preloadItem;
    preloadItem.moduleName = "moduleName";
    nlohmann::json jsonObject;
    to_json(jsonObject, preloadItem);
    EXPECT_EQ(preloadItem.moduleName, PRELOAD_ITEM_MODULE_NAME);
}

/**
 * @tc.number: BmsHapModuleInfoTest_0200
 * @tc.name: test from_json interface in HapModuleInfo.
 */
HWTEST_F(BmsHapModuleInfoTest, from_json_0100, Function | SmallTest | Level0)
{
    PreloadItem preloadItem;
    preloadItem.moduleName = "moduleName";
    nlohmann::json jsonObject;
    PreloadItem result;
    from_json(jsonObject, result);
    EXPECT_NE(preloadItem.moduleName, result.moduleName);
}

/**
 * @tc.number: BmsHapModuleInfoTest_0300
 * @tc.name: test to_json interface in HapModuleInfo.
 */
HWTEST_F(BmsHapModuleInfoTest, to_json_0200, Function | SmallTest | Level0)
{
    Dependency dependency;
    dependency.bundleName = "bundleName";
    dependency.moduleName = "moduleName";
    dependency.versionCode = 0;
    nlohmann::json jsonObject;
    to_json(jsonObject, dependency);
    EXPECT_EQ(dependency.bundleName, BUNDLE_NAME);
    EXPECT_EQ(dependency.moduleName, MODULE_NAME);
    EXPECT_EQ(dependency.versionCode, HAP_MODULE_INFO_VERSION_CODE);
}

/**
 * @tc.number: BmsHapModuleInfoTest_0400
 * @tc.name: test from_json interface in HapModuleInfo.
 */
HWTEST_F(BmsHapModuleInfoTest, from_json_0200, Function | SmallTest | Level0)
{
    Dependency dependency;
    dependency.bundleName = "bundleName";
    dependency.moduleName = "moduleName";
    dependency.versionCode = 0;
    nlohmann::json jsonObject;
    Dependency result;
    from_json(jsonObject, result);
    EXPECT_NE(dependency.bundleName, result.bundleName);
    EXPECT_NE(dependency.moduleName, result.moduleName);
    EXPECT_EQ(dependency.versionCode, result.versionCode);
}

/**
 * @tc.number: BmsHapModuleInfoTest_0500
 * @tc.name: test to_json interface in HapModuleInfo.
 */
HWTEST_F(BmsHapModuleInfoTest, to_json_0300, Function | SmallTest | Level0)
{
    RouterItem routerItem;
    routerItem.name = "name";
    routerItem.buildFunction = "buildFunction";
    nlohmann::json jsonObject;
    to_json(jsonObject, routerItem);
    EXPECT_EQ(routerItem.name, ROUTER_ITEM_KEY_NAME);
    EXPECT_EQ(routerItem.buildFunction, ROUTER_ITEM_KEY_BUILD_FUNCTION);
}

/**
 * @tc.number: BmsHapModuleInfoTest_0600
 * @tc.name: test from_json interface in HapModuleInfo.
 */
HWTEST_F(BmsHapModuleInfoTest, from_json_0300, Function | SmallTest | Level0)
{
    RouterItem routerItem;
    routerItem.name = "name";
    routerItem.buildFunction = "buildFunction";
    nlohmann::json jsonObject;
    RouterItem result;
    from_json(jsonObject, result);
    EXPECT_NE(routerItem.name, result.name);
    EXPECT_NE(routerItem.buildFunction, result.buildFunction);
}

/**
 * @tc.number: BmsHapModuleInfoTest_0700
 * @tc.name: test Marshalling interface in HapModuleInfo.
 */
HWTEST_F(BmsHapModuleInfoTest, Marshalling_0100, Function | SmallTest | Level0)
{
    AppEnvironment appEnvironment;
    Parcel parcel;
    std::string name = "IsName";
    std::string value = "value";
    parcel.WriteString16(Str8ToStr16(name));
    parcel.WriteString16(Str8ToStr16(value));
    auto ret = appEnvironment.Marshalling(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: BmsHapModuleInfoTest_0800
 * @tc.name: test to_json interface in HapModuleInfo.
 */
HWTEST_F(BmsHapModuleInfoTest, to_json_0400, Function | SmallTest | Level0)
{
    AppEnvironment appEnvironment;
    appEnvironment.name = "name";
    appEnvironment.value = "value";
    nlohmann::json jsonObject;
    to_json(jsonObject, appEnvironment);
    EXPECT_EQ(appEnvironment.name, APP_ENVIRONMENTS_NAME);
    EXPECT_EQ(appEnvironment.value, APP_ENVIRONMENTS_VALUE);
}

/**
 * @tc.number: BmsHapModuleInfoTest_0900
 * @tc.name: test from_json interface in HapModuleInfo.
 */
HWTEST_F(BmsHapModuleInfoTest, from_json_0400, Function | SmallTest | Level0)
{
    AppEnvironment appEnvironment;
    appEnvironment.name = "name";
    appEnvironment.value = "value";
    nlohmann::json jsonObject;
    AppEnvironment result;
    from_json(jsonObject, result);
    EXPECT_NE(appEnvironment.name, result.name);
    EXPECT_NE(appEnvironment.value, result.value);
}

/**
 * @tc.number: BmsHapModuleInfoTest_1000
 * @tc.name: test to_json interface in HapModuleInfo.
 */
HWTEST_F(BmsHapModuleInfoTest, to_json_0500, Function | SmallTest | Level0)
{
    HapModuleInfo hapModuleInfo;
    hapModuleInfo.labelId = 10;
    hapModuleInfo.hapPath = "hapPath";
    nlohmann::json jsonObject;
    to_json(jsonObject, hapModuleInfo);
    EXPECT_EQ(hapModuleInfo.labelId, HAP_MODULE_INFO_LABEL_ID);
    EXPECT_EQ(hapModuleInfo.hapPath, HAP_MODULE_INFO_HAP_PATH);
}

/**
 * @tc.number: BmsHapModuleInfoTest_1100
 * @tc.name: test to_json interface in RecoverableApplicationInfo.
 */
HWTEST_F(BmsHapModuleInfoTest, to_json_0600, Function | SmallTest | Level0)
{
    RecoverableApplicationInfo recoverableApplicationInfo;
    recoverableApplicationInfo.labelId = 20;
    recoverableApplicationInfo.iconId = 30;
    nlohmann::json jsonObject;
    to_json(jsonObject, recoverableApplicationInfo);
    EXPECT_EQ(recoverableApplicationInfo.labelId, JSON_KEY_LABEL_ID);
    EXPECT_EQ(recoverableApplicationInfo.iconId, JSON_KEY_ICON_ID);
}

/**
 * @tc.number: BmsHapModuleInfoTest_1200
 * @tc.name: test from_json interface in RecoverableApplicationInfo.
 */
HWTEST_F(BmsHapModuleInfoTest, from_json_0500, Function | SmallTest | Level0)
{
    RecoverableApplicationInfo recoverableApplicationInfo;
    recoverableApplicationInfo.labelId = 20;
    recoverableApplicationInfo.iconId = 30;
    nlohmann::json jsonObject;
    RecoverableApplicationInfo result;
    from_json(jsonObject, result);
    EXPECT_NE(recoverableApplicationInfo.labelId, result.labelId);
    EXPECT_NE(recoverableApplicationInfo.iconId, result.iconId);
}

/**
 * @tc.number: BmsHapModuleInfoTest_1300
 * @tc.name: test ReadFromParcel interface in DataGroupInfo.
 */
HWTEST_F(BmsHapModuleInfoTest, ReadFromParcel_0100, Function | SmallTest | Level0)
{
    DataGroupInfo dataGroupInfo;
    Parcel parcel;
    parcel.WriteString16(Str8ToStr16(DATAGROUPID));
    parcel.WriteString16(Str8ToStr16(UUID));
    parcel.WriteInt32(UID);
    parcel.WriteInt32(GID);
    parcel.WriteInt32(USERID);
    bool result = dataGroupInfo.ReadFromParcel(parcel);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: BmsHapModuleInfoTest_1400
 * @tc.name: test Marshalling interface in DataGroupInfo.
 */
HWTEST_F(BmsHapModuleInfoTest, Marshalling_0200, Function | SmallTest | Level0)
{
    DataGroupInfo dataGroupInfo;
    Parcel parcel;
    parcel.WriteString16(Str8ToStr16(DATAGROUPID));
    parcel.WriteString16(Str8ToStr16(UUID));
    parcel.WriteInt32(UID);
    parcel.WriteInt32(GID);
    parcel.WriteInt32(USERID);
    auto ret = dataGroupInfo.Marshalling(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: BmsHapModuleInfoTest_1500
 * @tc.name: test Unmarshalling interface in DataGroupInfo.
 */
HWTEST_F(BmsHapModuleInfoTest, Unmarshalling_0100, Function | SmallTest | Level0)
{
    DataGroupInfo dataGroupInfo;
    std::shared_ptr<OHOS::AppExecFwk::DataGroupInfo> info =
        std::make_shared<OHOS::AppExecFwk::DataGroupInfo>();
    ASSERT_NE(info, nullptr);
    Parcel parcel;
    parcel.WriteString16(Str8ToStr16(DATAGROUPID));
    parcel.WriteString16(Str8ToStr16(UUID));
    parcel.WriteInt32(UID);
    parcel.WriteInt32(GID);
    parcel.WriteInt32(USERID);
    auto result = dataGroupInfo.Unmarshalling(parcel);
    ASSERT_NE(result, nullptr);
}

/**
 * @tc.number: BmsHapModuleInfoTest_1600
 * @tc.name: test Marshalling interface in Skill.
 */
HWTEST_F(BmsHapModuleInfoTest, Marshalling_0300, Function | SmallTest | Level0)
{
    Skill skill;
    Parcel parcel;
    parcel.WriteString16(Str8ToStr16(HOST));
    parcel.WriteString16(Str8ToStr16(PATH));
    parcel.WriteString16(Str8ToStr16(PORT));
    auto ret = skill.Marshalling(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: BmsHapModuleInfoTest_1700
 * @tc.name: test Dump interface in Skill.
 */
HWTEST_F(BmsHapModuleInfoTest, BundleMgrHostImpl_0500, Function | MediumTest | Level1)
{
    Skill skill;
    std::string prefix = "prefix";
    int fd = 2;
    skill.Dump(prefix, fd);
    long length = lseek(fd, ZERO_SIZE, SEEK_END);
    EXPECT_EQ(length, INVALIED_ID);
}

/**
 * @tc.number: BmsHapModuleInfoTest_1800
 * @tc.name: test MarshallingSkillUri interface in ExtensionAbilityInfo.
 */
HWTEST_F(BmsHapModuleInfoTest, MarshallingSkillUri_0100, Function | SmallTest | Level0)
{
    ExtensionAbilityInfo extensionAbilityInfo;
    Parcel parcel;
    SkillUriForAbilityAndExtension uri;
    uri.maxFileSupported = 0;
    parcel.WriteString16(Str8ToStr16(SCHEME));
    parcel.WriteString16(Str8ToStr16(PATHREGEX));
    parcel.WriteString16(Str8ToStr16(PORT1));
    auto ret = extensionAbilityInfo.MarshallingSkillUri(parcel, uri);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: BmsHapModuleInfoTest_1900
 * @tc.name: test Marshalling interface in BundlePackInfo.
 */
HWTEST_F(BmsHapModuleInfoTest, Marshalling_0400, Function | SmallTest | Level1)
{
    BundlePackInfo bundlePackInfo;
    Parcel parcel;
    auto moduleType = static_cast<int32_t>(ModuleType::UNKNOWN);
    parcel.WriteInt32(moduleType);
    auto ret = bundlePackInfo.Marshalling(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: BmsHapModuleInfoTest_2000
 * @tc.name: test to_json interface in ApplicationInfo.
 */
HWTEST_F(BmsHapModuleInfoTest, to_json_0700, Function | SmallTest | Level0)
{
    ApplicationEnvironment applicationEnvironment;
    applicationEnvironment.name = "name";
    applicationEnvironment.value = "value";
    nlohmann::json jsonObject;
    to_json(jsonObject, applicationEnvironment);
    EXPECT_EQ(applicationEnvironment.name, NAME);
    EXPECT_EQ(applicationEnvironment.value, VALUE);
}

/**
 * @tc.number: BmsHapModuleInfoTest_2100
 * @tc.name: test from_json interface in ApplicationInfo.
 */
HWTEST_F(BmsHapModuleInfoTest, from_json_0600, Function | SmallTest | Level0)
{
    ApplicationEnvironment applicationEnvironment;
    applicationEnvironment.name = "name";
    applicationEnvironment.value = "value";
    nlohmann::json jsonObject;
    ApplicationEnvironment result;
    from_json(jsonObject, result);
    EXPECT_NE(applicationEnvironment.name, result.name);
    EXPECT_NE(applicationEnvironment.value, result.value);
}

/**
 * @tc.number: BmsHapModuleInfoTest_2200
 * @tc.name: test to_json interface in ApplicationInfo.
 */
HWTEST_F(BmsHapModuleInfoTest, to_json_0800, Function | SmallTest | Level0)
{
    HnpPackage hnpPackage;
    hnpPackage.package = "package";
    hnpPackage.type = "type";
    nlohmann::json jsonObject;
    to_json(jsonObject, hnpPackage);
    EXPECT_EQ(hnpPackage.package, PACKAGE);
    EXPECT_EQ(hnpPackage.type, TYPE);
}

/**
 * @tc.number: BmsHapModuleInfoTest_2300
 * @tc.name: test from_json interface in ApplicationInfo.
 */
HWTEST_F(BmsHapModuleInfoTest, from_json_0700, Function | SmallTest | Level0)
{
    HnpPackage hnpPackage;
    hnpPackage.package = "package";
    hnpPackage.type = "type";
    nlohmann::json jsonObject;
    HnpPackage result;
    from_json(jsonObject, result);
    EXPECT_NE(hnpPackage.package, result.package);
    EXPECT_NE(hnpPackage.type, result.type);
}

/**
 * @tc.number: BmsHapModuleInfoTest_2400
 * @tc.name: test to_json interface in FormInfo.
 */
HWTEST_F(BmsHapModuleInfoTest, to_json_0900, Function | SmallTest | Level0)
{
    FormCustomizeData customizeDatas;
    customizeDatas.name = "name";
    customizeDatas.value = "value";
    nlohmann::json jsonObject;
    to_json(jsonObject, customizeDatas);
    EXPECT_EQ(customizeDatas.name, NAME);
    EXPECT_EQ(customizeDatas.value, VALUE);
}

/**
 * @tc.number: BmsHapModuleInfoTest_2500
 * @tc.name: test IsExistDir interface in BundleFileUtil.
 */
HWTEST_F(BmsHapModuleInfoTest, IsExistDir_0100, Function | SmallTest | Level0)
{
    std::string dirPath = "PATH";
    auto ret = BundleFileUtil::IsExistDir(dirPath);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: BmsAppJumpControlRuleTest_0100
 * @tc.name: test to_json interface in DisposedRule.
 */
HWTEST_F(BmsHapModuleInfoTest, to_json_1000, Function | SmallTest | Level0)
{
    AppJumpControlRule appJumpControlRule;
    Parcel parcel;
    parcel.WriteString16(Str8ToStr16(CALLERPKG));
    parcel.WriteString16(Str8ToStr16(TARGETPKG));
    parcel.WriteString16(Str8ToStr16(CONTROLMESSAGE));
    parcel.WriteInt32(JUMP_MODE);
    bool result = appJumpControlRule.ReadFromParcel(parcel);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: BmsAppJumpControlRuleTest_0200
 * @tc.name: test Unmarshalling interface in DisposedRule.
 */
HWTEST_F(BmsHapModuleInfoTest, Unmarshalling_0200, Function | SmallTest | Level0)
{
    AppJumpControlRule appJumpControlRule;
    std::shared_ptr<OHOS::AppExecFwk::AppJumpControlRule> info =
        std::make_shared<OHOS::AppExecFwk::AppJumpControlRule>();
    ASSERT_NE(info, nullptr);
    Parcel parcel;
    parcel.WriteString16(Str8ToStr16(CALLERPKG));
    parcel.WriteString16(Str8ToStr16(TARGETPKG));
    parcel.WriteString16(Str8ToStr16(CONTROLMESSAGE));
    parcel.WriteInt32(JUMP_MODE);
    auto result = appJumpControlRule.Unmarshalling(parcel);
    ASSERT_NE(result, nullptr);
}

/**
 * @tc.number: BmsAppJumpControlRuleTest_0300
 * @tc.name: test Marshalling interface in DisposedRule.
 */
HWTEST_F(BmsHapModuleInfoTest, Marshalling_0500, Function | SmallTest | Level0)
{
    PreinstalledApplicationInfo preinstalledApplicationInfo;
    Parcel parcel;
    parcel.WriteString16(Str8ToStr16(BUNDLENAME));
    parcel.WriteString16(Str8ToStr16(MODULENAME));
    parcel.WriteUint32(LABEL_ID);
    parcel.WriteUint32(ICON_ID);
    auto ret = preinstalledApplicationInfo.Marshalling(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: BmsCodeProtectBundleInfoTest_0100
 * @tc.name: test ReadFromParcel interface in CodeProtectBundleInfo.
 * @tc.desc: 1.construct parcel.
 *           2.calling ReadFromParcel interface by using input parameter parcel.
 */
HWTEST_F(BmsHapModuleInfoTest, ReadFromParcel_0200, Function | SmallTest | Level0)
{
    CodeProtectBundleInfo codeProtectBundleInfo;
    Parcel parcel;
    parcel.WriteString16(Str8ToStr16(BUNDLE_NAME1));
    parcel.WriteInt32(UID1);
    parcel.WriteInt32(APPINDEX);
    parcel.WriteUint32(VERSIONCODE);
    parcel.WriteInt32(APPLICATIONRESERVEDFLAG);
    bool result = codeProtectBundleInfo.ReadFromParcel(parcel);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: BmsCodeProtectBundleInfoTest_0200
 * @tc.name: test to_json interface in CodeProtectBundleInfo.
 */
HWTEST_F(BmsHapModuleInfoTest, to_json_1100, Function | SmallTest | Level0)
{
    CodeProtectBundleInfo codeProtectBundleInfo;
    codeProtectBundleInfo.bundleName = "TestBundleName";
    codeProtectBundleInfo.uid = 10;
    codeProtectBundleInfo.appIndex = 20;
    codeProtectBundleInfo.versionCode = 30;
    codeProtectBundleInfo.applicationReservedFlag = 40;
    nlohmann::json jsonObject;
    to_json(jsonObject, codeProtectBundleInfo);
    CodeProtectBundleInfo result;
    from_json(jsonObject, result);
    EXPECT_EQ(result.bundleName, "TestBundleName");
    EXPECT_EQ(result.uid, 10);
    EXPECT_EQ(result.appIndex, 20);
    EXPECT_EQ(result.versionCode, 30);
    EXPECT_EQ(result.applicationReservedFlag, 40);
}

/**
 * @tc.number: BmsCodeProtectBundleInfoTest_0300
 * @tc.name: test to_json interface in CodeProtectBundleInfo.
 */
HWTEST_F(BmsHapModuleInfoTest, from_json_0800, Function | SmallTest | Level0)
{
    CodeProtectBundleInfo codeProtectBundleInfo;
    codeProtectBundleInfo.bundleName = "TestBundleName";
    codeProtectBundleInfo.uid = 10;
    codeProtectBundleInfo.appIndex = 20;
    codeProtectBundleInfo.versionCode = 30;
    codeProtectBundleInfo.applicationReservedFlag = 40;
    nlohmann::json jsonObject;
    CodeProtectBundleInfo result;
    from_json(jsonObject, result);
    EXPECT_NE(codeProtectBundleInfo.bundleName, result.bundleName);
    EXPECT_NE(codeProtectBundleInfo.uid, result.uid);
    EXPECT_NE(codeProtectBundleInfo.appIndex, result.appIndex);
    EXPECT_NE(codeProtectBundleInfo.versionCode, result.versionCode);
    EXPECT_NE(codeProtectBundleInfo.applicationReservedFlag, result.applicationReservedFlag);
}

/**
 * @tc.number: BmsDisposedRuleTest_0100
 * @tc.name: test to_json interface in DisposedRule.
 */
HWTEST_F(BmsHapModuleInfoTest, to_json_1200, Function | SmallTest | Level0)
{
    DisposedRule disPosedRule;
    ElementName element;
    element.SetBundleName(BUNDLE_NAME);
    element.SetModuleName(MODULE_NAME);
    element.SetAbilityName(ABILITY_NAME);
    element.SetDeviceID(DEVICE_ID);
    nlohmann::json jsonObject;
    to_json(jsonObject, element);
    EXPECT_EQ(element.GetBundleName(), BUNDLE_NAME);
    EXPECT_EQ(element.GetDeviceID(), DEVICE_ID);
    EXPECT_EQ(element.GetAbilityName(), ABILITY_NAME);
    EXPECT_EQ(element.GetModuleName(), MODULE_NAME);
}

/**
 * @tc.number: BmsDisposedRuleTest_0200
 * @tc.name: test to_json interface in DisposedRule.
 */
HWTEST_F(BmsHapModuleInfoTest, to_json_1300, Function | SmallTest | Level0)
{
    DisposedRule disPosedRule;
    nlohmann::json jsonObject;
    std::vector<ElementName> elementList;
    std::shared_ptr<AAFwk::Want> want = std::make_shared<AAFwk::Want>();
    ASSERT_NE(want, nullptr);
    disPosedRule.want = want;
    elementList.emplace_back(BUNDLE_NAME, ABILITY_NAME, DEVICE_ID);
    to_json(jsonObject, disPosedRule);
    EXPECT_EQ(disPosedRule.componentType, ComponentType::UI_ABILITY);
    EXPECT_EQ(disPosedRule.controlType, ControlType::ALLOWED_LIST);
    EXPECT_EQ(disPosedRule.disposedType, DisposedType::BLOCK_APPLICATION);
}

/**
 * @tc.number: BmsDisposedRuleTest_0300
 * @tc.name: test from_json interface in DisposedRule.
 */
HWTEST_F(BmsHapModuleInfoTest, from_json_0900, Function | SmallTest | Level0)
{
    DisposedRule disPosedRule;
    ElementName element;
    element.SetBundleName(BUNDLE_NAME);
    element.SetModuleName(MODULE_NAME);
    element.SetAbilityName(ABILITY_NAME);
    element.SetDeviceID(DEVICE_ID);
    nlohmann::json jsonObject;
    ElementName result;
    from_json(jsonObject, result);
    EXPECT_NE(element.GetBundleName(), result.bundleName_);
    EXPECT_NE(element.GetDeviceID(), result.deviceId_);
    EXPECT_NE(element.GetAbilityName(), result.abilityName_);
    EXPECT_NE(element.GetModuleName(), result.moduleName_);
}

/**
 * @tc.number: BmsDisposedRuleTest_0400
 * @tc.name: test from_json interface in DisposedRule.
 */
HWTEST_F(BmsHapModuleInfoTest, from_json_1000, Function | SmallTest | Level0)
{
    DisposedRule disPosedRule;
    nlohmann::json jsonObject;
    std::shared_ptr<AAFwk::Want> want = std::make_shared<AAFwk::Want>();
    ASSERT_NE(want, nullptr);
    disPosedRule.want = want;
    std::vector<ElementName> elementList;
    elementList.emplace_back(BUNDLE_NAME, ABILITY_NAME, DEVICE_ID);
    DisposedRule result;
    from_json(jsonObject, result);
    EXPECT_EQ(result.componentType, ComponentType::UI_ABILITY);
    EXPECT_EQ(result.controlType, ControlType::ALLOWED_LIST);
    EXPECT_EQ(result.disposedType, DisposedType::BLOCK_APPLICATION);
}

/**
 * @tc.number: BmsDisposedRuleTest_0500
 * @tc.name: test FromString interface in DisposedRule.
 */
HWTEST_F(BmsHapModuleInfoTest, FromString_0100, Function | SmallTest | Level0)
{
    DisposedRule disPosedRule;
    nlohmann::json jsonObject;
    std::string ruleString = "rule";
    DisposedRule rule;
    bool result = disPosedRule.FromString(ruleString, rule);
    EXPECT_FALSE(result);
}

/**
 * @tc.number: BmsHapModuleInfoTest_DeleteDir_0100
 * @tc.name: test DeleteDir when path is a valid directory.
 */
HWTEST_F(BmsHapModuleInfoTest, DeleteDir_0100, Function | SmallTest | Level0)
{
    std::string dirPath = "/tmp/testdir";
    mkdir(dirPath.c_str(), 0777);
    auto ret = BundleFileUtil::DeleteDir(dirPath);
    EXPECT_TRUE(ret);
    EXPECT_FALSE(BundleFileUtil::IsExistDir(dirPath));
}

/**
 * @tc.number: BmsHapModuleInfoTest_DeleteDir_0200
 * @tc.name: test DeleteDir when path is invalid or directory deletion fails.
 */
HWTEST_F(BmsHapModuleInfoTest, DeleteDir_0200, Function | SmallTest | Level0)
{
    std::string invalidPath = "/tmp/nonexistentpath";
    auto ret = BundleFileUtil::DeleteDir(invalidPath);
    EXPECT_TRUE(ret);
    std::string dirPath = "/tmp/testdir";
    mkdir(dirPath.c_str(), 0777);
    errno = EACCES;
    auto ret1 = BundleFileUtil::DeleteDir(dirPath);
    EXPECT_TRUE(ret1);
}
}
}