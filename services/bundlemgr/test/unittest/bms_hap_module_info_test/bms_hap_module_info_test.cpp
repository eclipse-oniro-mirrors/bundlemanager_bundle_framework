/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include "ipc/verify_bin_param.h"
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
constexpr int32_t CLONE_APP_INDEX_MAX_DEFAULT = 5;
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
const char* APP_ID = "appId";
constexpr uint32_t APP_INDEX = 0;
const char* DISPOSED_RULE = "disposedRule";
const std::string LAUNCH_SERVICE_NAME = "testLaunchService";
const std::string LAUNCH_SERVICE_BINARY_PATH = "/data/app/el1/bundle/public/com.example.app/libs/daemon.bin";

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
void to_json(nlohmann::json &jsonObject, const DisposedRuleConfiguration &disposedRuleConfiguration);
void from_json(const nlohmann::json &jsonObject, DisposedRuleConfiguration &disposedRuleConfiguration);
void to_json(nlohmann::json &jsonObject, const ExecutableBinaryPath &executableBinaryPath);
void from_json(const nlohmann::json &jsonObject, ExecutableBinaryPath &executableBinaryPath);
void to_json(nlohmann::json &jsonObject, const LaunchService &launchService);
void from_json(const nlohmann::json &jsonObject, LaunchService &launchService);
void from_json(const nlohmann::json &jsonObject, HapModuleInfo &hapModuleInfo);

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
 * @tc.number: PreinstalledApplicationInfo_Marshalling_0600
 * @tc.name: test PreinstalledApplicationInfo Marshalling with descriptionId round trip
 */
HWTEST_F(BmsHapModuleInfoTest, PreinstalledApplicationInfo_Marshalling_0600, Function | SmallTest | Level0)
{
    PreinstalledApplicationInfo orig;
    orig.bundleName = BUNDLENAME;
    orig.moduleName = MODULENAME;
    orig.labelId = LABEL_ID;
    orig.iconId = ICON_ID;
    orig.descriptionId = 16777216;
    Parcel parcel;
    EXPECT_TRUE(orig.Marshalling(parcel));
    auto* unm = PreinstalledApplicationInfo::Unmarshalling(parcel);
    ASSERT_NE(unm, nullptr);
    EXPECT_EQ(unm->bundleName, orig.bundleName);
    EXPECT_EQ(unm->moduleName, orig.moduleName);
    EXPECT_EQ(unm->labelId, orig.labelId);
    EXPECT_EQ(unm->iconId, orig.iconId);
    EXPECT_EQ(unm->descriptionId, orig.descriptionId);
    delete unm;
}

/**
 * @tc.number: PreinstalledApplicationInfo_Marshalling_0700
 * @tc.name: test PreinstalledApplicationInfo Unmarshalling without trailing descriptionId
 */
HWTEST_F(BmsHapModuleInfoTest, PreinstalledApplicationInfo_Marshalling_0700, Function | SmallTest | Level0)
{
    Parcel parcel;
    parcel.WriteString16(Str8ToStr16(BUNDLENAME));
    parcel.WriteString16(Str8ToStr16(MODULENAME));
    parcel.WriteUint32(LABEL_ID);
    parcel.WriteUint32(ICON_ID);
    auto* unm = PreinstalledApplicationInfo::Unmarshalling(parcel);
    ASSERT_NE(unm, nullptr);
    EXPECT_EQ(unm->descriptionId, 0);
    delete unm;
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

/**
 * @tc.number: ReadFromParcel_0300
 * @tc.name: test ReadFromParcel interface in DisposedRuleConfiguration.
 * @tc.desc: 1.construct parcel.
 *           2.calling ReadFromParcel interface by using input parameter parcel.
 */
HWTEST_F(BmsHapModuleInfoTest, ReadFromParcel_0300, Function | SmallTest | Level0)
{
    DisposedRuleConfiguration disposedRuleConfiguration;
    DisposedRule disposedRule;
    Parcel parcel;
    parcel.WriteParcelable(&disposedRule);
    parcel.WriteString16(Str8ToStr16(APP_ID));
    parcel.WriteInt32(APP_INDEX);
    bool result = disposedRuleConfiguration.ReadFromParcel(parcel);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: Marshalling_0600
 * @tc.name: test Marshalling interface in DisposedRuleConfiguration.
 */
HWTEST_F(BmsHapModuleInfoTest, Marshalling_0600, Function | SmallTest | Level0)
{
    DisposedRuleConfiguration disposedRuleConfiguration;
    DisposedRule disposedRule;
    Parcel parcel;
    parcel.WriteParcelable(&disposedRule);
    parcel.WriteString16(Str8ToStr16(APP_ID));
    parcel.WriteInt32(APP_INDEX);
    auto ret = disposedRuleConfiguration.Marshalling(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: Unmarshalling_0300
 * @tc.name: test Unmarshalling interface in DisposedRuleConfiguration.
 */
HWTEST_F(BmsHapModuleInfoTest, Unmarshalling_0300, Function | SmallTest | Level0)
{
    DisposedRuleConfiguration disposedRuleConfiguration;
    DisposedRule disposedRule;
    Parcel parcel;
    parcel.WriteParcelable(&disposedRule);
    parcel.WriteString16(Str8ToStr16(APP_ID));
    parcel.WriteInt32(APP_INDEX);
    auto result = disposedRuleConfiguration.Unmarshalling(parcel);
    ASSERT_NE(result, nullptr);
}

/**
 * @tc.number: ExecutableBinaryPath_Marshalling_001
 * @tc.name: test Marshalling interface in ExecutableBinaryPath.
 * @tc.desc: 1. create ExecutableBinaryPath with path data
 *           2. verify marshalling success
 */
HWTEST_F(BmsHapModuleInfoTest, ExecutableBinaryPath_Marshalling_001, Function | SmallTest | Level0)
{
    ExecutableBinaryPath executableBinaryPath;
    executableBinaryPath.path = "/data/app/el1/bundle/public/com.example.app/libs/test.bin";
    executableBinaryPath.permissionControlMode = PermissionControlMode::INHERIT_PARENT_PROCESS;

    Parcel parcel;
    bool result = executableBinaryPath.Marshalling(parcel);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: ExecutableBinaryPath_ReadFromParcel_001
 * @tc.name: test ReadFromParcel interface in ExecutableBinaryPath.
 * @tc.desc: 1. write path and permissionControlMode to parcel
 *           2. verify ReadFromParcel reads correctly
 */
HWTEST_F(BmsHapModuleInfoTest, ExecutableBinaryPath_ReadFromParcel_001, Function | SmallTest | Level0)
{
    std::string testPath = "/data/app/el1/bundle/public/com.example.app/libs/test.bin";
    ExecutableBinaryPath executableBinaryPath;
    Parcel parcel;
    parcel.WriteString16(Str8ToStr16(testPath));
    parcel.WriteInt32(static_cast<int32_t>(PermissionControlMode::INHERIT_PARENT_PROCESS));

    bool result = executableBinaryPath.ReadFromParcel(parcel);
    EXPECT_TRUE(result);
    EXPECT_EQ(executableBinaryPath.path, testPath);
    EXPECT_EQ(executableBinaryPath.permissionControlMode, PermissionControlMode::INHERIT_PARENT_PROCESS);
}

/**
 * @tc.number: ExecutableBinaryPath_Unmarshalling_001
 * @tc.name: test Unmarshalling interface in ExecutableBinaryPath.
 * @tc.desc: 1. marshal ExecutableBinaryPath with permissionControlMode
 *           2. verify unmarshalling data matches
 */
HWTEST_F(BmsHapModuleInfoTest, ExecutableBinaryPath_Unmarshalling_001, Function | SmallTest | Level0)
{
    ExecutableBinaryPath originalPath;
    originalPath.path = "/data/app/el1/bundle/public/com.example.app/libs/test.bin";
    originalPath.permissionControlMode = PermissionControlMode::INHERIT_PARENT_PROCESS;

    Parcel parcel;
    ASSERT_TRUE(originalPath.Marshalling(parcel));
    parcel.RewindRead(0);

    ExecutableBinaryPath* unmarshalledPath = ExecutableBinaryPath::Unmarshalling(parcel);
    ASSERT_NE(unmarshalledPath, nullptr);
    EXPECT_EQ(unmarshalledPath->path, originalPath.path);
    EXPECT_EQ(unmarshalledPath->permissionControlMode, originalPath.permissionControlMode);
    delete unmarshalledPath;
}

/**
 * @tc.number: ExecutableBinaryPath_to_json_001
 * @tc.name: test to_json interface in ExecutableBinaryPath.
 * @tc.desc: 1. create ExecutableBinaryPath with data
 *           2. verify to_json success
 */
HWTEST_F(BmsHapModuleInfoTest, ExecutableBinaryPath_to_json_001, Function | SmallTest | Level0)
{
    ExecutableBinaryPath executableBinaryPath;
    executableBinaryPath.path = "/data/app/libs/test.bin";
    executableBinaryPath.permissionControlMode = PermissionControlMode::INHERIT_PARENT_PROCESS;

    nlohmann::json jsonObject;
    to_json(jsonObject, executableBinaryPath);
    EXPECT_EQ(executableBinaryPath.path, "/data/app/libs/test.bin");
    EXPECT_TRUE(jsonObject.contains("permissionControlMode"));
    EXPECT_EQ(jsonObject.at("permissionControlMode").get<int32_t>(),
        static_cast<int32_t>(PermissionControlMode::INHERIT_PARENT_PROCESS));
}

/**
 * @tc.number: ExecutableBinaryPath_from_json_001
 * @tc.name: test from_json interface in ExecutableBinaryPath.
 * @tc.desc: 1. create json with path only
 *           2. verify from_json parses correctly and permissionControlMode defaults to independent
 */
HWTEST_F(BmsHapModuleInfoTest, ExecutableBinaryPath_from_json_001, Function | SmallTest | Level0)
{
    nlohmann::json jsonObject;
    jsonObject["path"] = "/data/app/libs/test.bin";

    ExecutableBinaryPath result;
    from_json(jsonObject, result);
    EXPECT_EQ(result.path, "/data/app/libs/test.bin");
    EXPECT_EQ(result.permissionControlMode, PermissionControlMode::INDEPENDENT);
}

/**
 * @tc.number: ExecutableBinaryPath_from_json_002
 * @tc.name: test from_json with permissionControlMode numeric values
 * @tc.desc: 1. parse permissionControlMode as number
 *           2. verify values match enum
 */
HWTEST_F(BmsHapModuleInfoTest, ExecutableBinaryPath_from_json_002, Function | SmallTest | Level0)
{
    nlohmann::json jsonInherit;
    jsonInherit["path"] = "/data/app/libs/a.bin";
    jsonInherit["permissionControlMode"] =
        static_cast<int32_t>(PermissionControlMode::INHERIT_PARENT_PROCESS);
    ExecutableBinaryPath resultInherit;
    from_json(jsonInherit, resultInherit);
    EXPECT_EQ(resultInherit.permissionControlMode, PermissionControlMode::INHERIT_PARENT_PROCESS);

    nlohmann::json jsonIndependent;
    jsonIndependent["path"] = "/data/app/libs/b.bin";
    jsonIndependent["permissionControlMode"] =
        static_cast<int32_t>(PermissionControlMode::INDEPENDENT);
    ExecutableBinaryPath resultIndependent;
    from_json(jsonIndependent, resultIndependent);
    EXPECT_EQ(resultIndependent.permissionControlMode, PermissionControlMode::INDEPENDENT);
}

/**
 * @tc.number: ExecutableBinaryPath_from_json_003
 * @tc.name: test from_json with non-number permissionControlMode
 * @tc.desc: 1. permissionControlMode is string
 *           2. verify field stays independent
 */
HWTEST_F(BmsHapModuleInfoTest, ExecutableBinaryPath_from_json_003, Function | SmallTest | Level0)
{
    nlohmann::json jsonObject;
    jsonObject["path"] = "/data/app/libs/test.bin";
    jsonObject["permissionControlMode"] = "true";

    ExecutableBinaryPath result;
    result.permissionControlMode = PermissionControlMode::INDEPENDENT;
    from_json(jsonObject, result);
    EXPECT_EQ(result.permissionControlMode, PermissionControlMode::INDEPENDENT);
    EXPECT_NE(result.permissionControlMode, PermissionControlMode::INHERIT_PARENT_PROCESS);
}

/**
 * @tc.number: LaunchService_Unmarshalling_001
 * @tc.name: test Unmarshalling round-trip in LaunchService.
 * @tc.desc: 1. marshal LaunchService
 *           2. verify unmarshalling data matches
 */
HWTEST_F(BmsHapModuleInfoTest, LaunchService_Unmarshalling_001, Function | SmallTest | Level0)
{
    LaunchService original;
    original.name = LAUNCH_SERVICE_NAME;
    original.binaryPath = LAUNCH_SERVICE_BINARY_PATH;
    original.runAtLoad = true;
    original.keepAlive = false;
    original.provideIpcService = true;
    original.type = LaunchServiceType::DAEMON;

    Parcel parcel;
    ASSERT_TRUE(original.Marshalling(parcel));
    parcel.RewindRead(0);

    LaunchService *unmarshalled = LaunchService::Unmarshalling(parcel);
    ASSERT_NE(unmarshalled, nullptr);
    EXPECT_EQ(unmarshalled->name, original.name);
    EXPECT_EQ(unmarshalled->binaryPath, original.binaryPath);
    EXPECT_EQ(unmarshalled->runAtLoad, original.runAtLoad);
    EXPECT_EQ(unmarshalled->keepAlive, original.keepAlive);
    EXPECT_EQ(unmarshalled->provideIpcService, original.provideIpcService);
    EXPECT_EQ(unmarshalled->type, original.type);
    delete unmarshalled;
}

/**
 * @tc.number: LaunchService_to_json_001
 * @tc.name: test to_json/from_json round-trip in LaunchService.
 * @tc.desc: 1. create LaunchService with data
 *           2. verify json round-trip keeps values
 */
HWTEST_F(BmsHapModuleInfoTest, LaunchService_to_json_001, Function | SmallTest | Level0)
{
    LaunchService original;
    original.name = LAUNCH_SERVICE_NAME;
    original.binaryPath = LAUNCH_SERVICE_BINARY_PATH;
    original.runAtLoad = true;
    original.keepAlive = true;
    original.provideIpcService = false;
    original.type = LaunchServiceType::DAEMON;

    nlohmann::json jsonObject;
    to_json(jsonObject, original);

    LaunchService result;
    from_json(jsonObject, result);
    EXPECT_EQ(result.name, original.name);
    EXPECT_EQ(result.binaryPath, original.binaryPath);
    EXPECT_EQ(result.runAtLoad, original.runAtLoad);
    EXPECT_EQ(result.keepAlive, original.keepAlive);
    EXPECT_EQ(result.provideIpcService, original.provideIpcService);
    EXPECT_EQ(result.type, original.type);
}

/**
 * @tc.number: LaunchService_from_json_002
 * @tc.name: test from_json default compatibility in LaunchService.
 * @tc.desc: 1. create json with missing optional keys
 *           2. verify defaults are preserved
 */
HWTEST_F(BmsHapModuleInfoTest, LaunchService_from_json_002, Function | SmallTest | Level0)
{
    nlohmann::json jsonObject;
    jsonObject["name"] = LAUNCH_SERVICE_NAME;
    jsonObject["binaryPath"] = LAUNCH_SERVICE_BINARY_PATH;

    LaunchService result;
    from_json(jsonObject, result);
    EXPECT_EQ(result.name, LAUNCH_SERVICE_NAME);
    EXPECT_EQ(result.binaryPath, LAUNCH_SERVICE_BINARY_PATH);
    EXPECT_EQ(result.runAtLoad, false);
    EXPECT_EQ(result.keepAlive, false);
    EXPECT_EQ(result.provideIpcService, false);
    EXPECT_EQ(result.type, LaunchServiceType::DAEMON);
}

/**
 * @tc.number: HapModuleInfo_LaunchServices_Marshalling_001
 * @tc.name: test HapModuleInfo marshalling with launchServices.
 * @tc.desc: 1. create HapModuleInfo with launchServices
 *           2. verify parcel round-trip keeps values
 */
HWTEST_F(BmsHapModuleInfoTest, HapModuleInfo_LaunchServices_Marshalling_001, Function | SmallTest | Level1)
{
    LaunchService launchService;
    launchService.name = LAUNCH_SERVICE_NAME;
    launchService.binaryPath = LAUNCH_SERVICE_BINARY_PATH;
    launchService.runAtLoad = true;
    launchService.type = LaunchServiceType::DAEMON;

    HapModuleInfo original;
    original.moduleName = MODULE_NAME2;
    original.launchServices.emplace_back(launchService);

    Parcel parcel;
    ASSERT_TRUE(original.Marshalling(parcel));
    parcel.RewindRead(0);

    HapModuleInfo *unmarshalled = HapModuleInfo::Unmarshalling(parcel);
    ASSERT_NE(unmarshalled, nullptr);
    ASSERT_EQ(unmarshalled->launchServices.size(), 1);
    EXPECT_EQ(unmarshalled->launchServices[0].name, launchService.name);
    EXPECT_EQ(unmarshalled->launchServices[0].binaryPath, launchService.binaryPath);
    EXPECT_EQ(unmarshalled->launchServices[0].runAtLoad, true);
    EXPECT_EQ(unmarshalled->launchServices[0].type, LaunchServiceType::DAEMON);
    delete unmarshalled;
}

/**
 * @tc.number: HapModuleInfo_LaunchServices_to_json_001
 * @tc.name: test HapModuleInfo json round-trip with launchServices.
 * @tc.desc: 1. create HapModuleInfo with launchServices
 *           2. verify json round-trip keeps values
 */
HWTEST_F(BmsHapModuleInfoTest, HapModuleInfo_LaunchServices_to_json_001, Function | SmallTest | Level1)
{
    LaunchService launchService;
    launchService.name = LAUNCH_SERVICE_NAME;
    launchService.binaryPath = LAUNCH_SERVICE_BINARY_PATH;
    launchService.provideIpcService = true;

    HapModuleInfo original;
    original.moduleName = MODULE_NAME2;
    original.launchServices.emplace_back(launchService);

    nlohmann::json jsonObject;
    to_json(jsonObject, original);

    HapModuleInfo result;
    from_json(jsonObject, result);
    ASSERT_EQ(result.launchServices.size(), 1);
    EXPECT_EQ(result.launchServices[0].name, launchService.name);
    EXPECT_EQ(result.launchServices[0].binaryPath, launchService.binaryPath);
    EXPECT_EQ(result.launchServices[0].provideIpcService, true);
}

/**
 * @tc.number: HapModuleInfo_LaunchServices_Compatible_001
 * @tc.name: test HapModuleInfo json compatibility without launchServices.
 * @tc.desc: 1. create json without launchServices key
 *           2. verify from_json keeps empty container
 */
HWTEST_F(BmsHapModuleInfoTest, HapModuleInfo_LaunchServices_Compatible_001, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    jsonObject["name"] = MODULE_NAME2;

    HapModuleInfo result;
    from_json(jsonObject, result);
    EXPECT_TRUE(result.launchServices.empty());
}

/**
 * @tc.number: LaunchService_Unmarshalling_002
 * @tc.name: test LaunchService unmarshalling with an invalid type value.
 * @tc.desc: 1. write a launch service parcel whose type is not DAEMON
 *           2. strict parcel validation rejects it and Unmarshalling returns nullptr
 */
HWTEST_F(BmsHapModuleInfoTest, LaunchService_Unmarshalling_002, Function | SmallTest | Level0)
{
    Parcel parcel;
    parcel.WriteString16(Str8ToStr16(LAUNCH_SERVICE_NAME));
    parcel.WriteString16(Str8ToStr16(LAUNCH_SERVICE_BINARY_PATH));
    parcel.WriteBool(true);
    parcel.WriteBool(false);
    parcel.WriteBool(true);
    parcel.WriteInt32(99);

    LaunchService *unmarshalled = LaunchService::Unmarshalling(parcel);
    EXPECT_EQ(unmarshalled, nullptr);
}

/**
 * @tc.number: LaunchService_Unmarshalling_003
 * @tc.name: test LaunchService unmarshalling from an empty parcel.
 * @tc.desc: 1. call Unmarshalling with an empty parcel
 *           2. the Int32 read fails and Unmarshalling returns nullptr
 */
HWTEST_F(BmsHapModuleInfoTest, LaunchService_Unmarshalling_003, Function | SmallTest | Level0)
{
    Parcel parcel;
    LaunchService *unmarshalled = LaunchService::Unmarshalling(parcel);
    EXPECT_EQ(unmarshalled, nullptr);
}

/**
 * @tc.number: LaunchServicesResult_Unmarshalling_001
 * @tc.name: test LaunchServicesResult parcel round-trip.
 * @tc.desc: 1. create LaunchServicesResult with two launch services and meta fields
 *           2. verify unmarshalling keeps the list order and developerId/appIdentifier
 */
HWTEST_F(BmsHapModuleInfoTest, LaunchServicesResult_Unmarshalling_001, Function | SmallTest | Level0)
{
    LaunchService first;
    first.name = "svc-first";
    first.binaryPath = "/bin/first";
    first.runAtLoad = true;
    first.type = LaunchServiceType::DAEMON;
    LaunchService second;
    second.name = "svc-second";
    second.binaryPath = "/bin/second";
    second.provideIpcService = true;

    LaunchServicesResult original;
    original.launchServices = {first, second};
    original.developerId = "developer-001";
    original.appIdentifier = "appIdentifier-001";

    Parcel parcel;
    ASSERT_TRUE(original.Marshalling(parcel));
    parcel.RewindRead(0);

    LaunchServicesResult *unmarshalled = LaunchServicesResult::Unmarshalling(parcel);
    ASSERT_NE(unmarshalled, nullptr);
    ASSERT_EQ(unmarshalled->launchServices.size(), 2);
    EXPECT_EQ(unmarshalled->launchServices[0].name, "svc-first");
    EXPECT_EQ(unmarshalled->launchServices[0].binaryPath, "/bin/first");
    EXPECT_EQ(unmarshalled->launchServices[0].runAtLoad, true);
    EXPECT_EQ(unmarshalled->launchServices[1].name, "svc-second");
    EXPECT_EQ(unmarshalled->launchServices[1].provideIpcService, true);
    EXPECT_EQ(unmarshalled->developerId, "developer-001");
    EXPECT_EQ(unmarshalled->appIdentifier, "appIdentifier-001");
    delete unmarshalled;
}

/**
 * @tc.number: LaunchServicesResult_Unmarshalling_002
 * @tc.name: test LaunchServicesResult unmarshalling from an empty parcel.
 * @tc.desc: 1. call Unmarshalling with an empty parcel
 *           2. the size read fails and Unmarshalling returns nullptr
 */
HWTEST_F(BmsHapModuleInfoTest, LaunchServicesResult_Unmarshalling_002, Function | SmallTest | Level0)
{
    Parcel parcel;
    LaunchServicesResult *unmarshalled = LaunchServicesResult::Unmarshalling(parcel);
    EXPECT_EQ(unmarshalled, nullptr);
}

/**
 * @tc.number: HapModuleInfo_LaunchServices_Marshalling_002
 * @tc.name: test HapModuleInfo marshalling with multiple launchServices.
 * @tc.desc: 1. create HapModuleInfo with three launch services
 *           2. verify parcel round-trip keeps the whole list in order
 */
HWTEST_F(BmsHapModuleInfoTest, HapModuleInfo_LaunchServices_Marshalling_002, Function | SmallTest | Level1)
{
    HapModuleInfo original;
    original.moduleName = MODULE_NAME2;
    for (const char *name : {"svc-one", "svc-two", "svc-three"}) {
        LaunchService launchService;
        launchService.name = name;
        launchService.binaryPath = std::string("/bin/") + name;
        launchService.type = LaunchServiceType::DAEMON;
        original.launchServices.emplace_back(launchService);
    }

    Parcel parcel;
    ASSERT_TRUE(original.Marshalling(parcel));
    parcel.RewindRead(0);

    HapModuleInfo *unmarshalled = HapModuleInfo::Unmarshalling(parcel);
    ASSERT_NE(unmarshalled, nullptr);
    ASSERT_EQ(unmarshalled->launchServices.size(), 3);
    EXPECT_EQ(unmarshalled->launchServices[0].name, "svc-one");
    EXPECT_EQ(unmarshalled->launchServices[1].name, "svc-two");
    EXPECT_EQ(unmarshalled->launchServices[2].name, "svc-three");
    EXPECT_EQ(unmarshalled->launchServices[2].binaryPath, "/bin/svc-three");
    delete unmarshalled;
}

/**
 * @tc.number: LaunchService_to_json_002
 * @tc.name: test LaunchService to_json key set.
 * @tc.desc: 1. serialize a LaunchService with all fields set
 *           2. verify the json object carries exactly the six documented keys
 */
HWTEST_F(BmsHapModuleInfoTest, LaunchService_to_json_002, Function | SmallTest | Level0)
{
    LaunchService original;
    original.name = LAUNCH_SERVICE_NAME;
    original.binaryPath = LAUNCH_SERVICE_BINARY_PATH;
    original.runAtLoad = true;
    original.keepAlive = true;
    original.provideIpcService = true;
    original.type = LaunchServiceType::DAEMON;

    nlohmann::json jsonObject;
    to_json(jsonObject, original);
    EXPECT_EQ(jsonObject.size(), 6);
    EXPECT_TRUE(jsonObject.contains("name"));
    EXPECT_TRUE(jsonObject.contains("binaryPath"));
    EXPECT_TRUE(jsonObject.contains("runAtLoad"));
    EXPECT_TRUE(jsonObject.contains("keepAlive"));
    EXPECT_TRUE(jsonObject.contains("provideIpcService"));
    EXPECT_TRUE(jsonObject.contains("type"));
    EXPECT_EQ(jsonObject["type"], "daemon");
}

/**
 * @tc.number: LaunchService_from_json_003
 * @tc.name: test LaunchService from_json with an unknown type string.
 * @tc.desc: 1. build json with an unsupported type value
 *           2. the json round-trip path is lenient: the entry is kept with the default
 *              DAEMON type (strict validation only happens for module.json parsing)
 */
HWTEST_F(BmsHapModuleInfoTest, LaunchService_from_json_003, Function | SmallTest | Level0)
{
    nlohmann::json jsonObject;
    jsonObject["name"] = LAUNCH_SERVICE_NAME;
    jsonObject["binaryPath"] = LAUNCH_SERVICE_BINARY_PATH;
    jsonObject["type"] = "unknownStr";

    LaunchService result;
    from_json(jsonObject, result);
    EXPECT_EQ(result.name, LAUNCH_SERVICE_NAME);
    EXPECT_EQ(result.binaryPath, LAUNCH_SERVICE_BINARY_PATH);
    EXPECT_EQ(result.type, LaunchServiceType::DAEMON);
}

/**
 * @tc.number: LaunchService_Marshalling_001
 * @tc.name: test LaunchService marshalling with empty fields.
 * @tc.desc: 1. marshal a LaunchService with default empty name/binaryPath
 *           2. verify unmarshalling keeps the empty values and defaults
 */
HWTEST_F(BmsHapModuleInfoTest, LaunchService_Marshalling_001, Function | SmallTest | Level0)
{
    LaunchService original;

    Parcel parcel;
    ASSERT_TRUE(original.Marshalling(parcel));
    parcel.RewindRead(0);

    LaunchService *unmarshalled = LaunchService::Unmarshalling(parcel);
    ASSERT_NE(unmarshalled, nullptr);
    EXPECT_TRUE(unmarshalled->name.empty());
    EXPECT_TRUE(unmarshalled->binaryPath.empty());
    EXPECT_EQ(unmarshalled->runAtLoad, false);
    EXPECT_EQ(unmarshalled->keepAlive, false);
    EXPECT_EQ(unmarshalled->provideIpcService, false);
    EXPECT_EQ(unmarshalled->type, LaunchServiceType::DAEMON);
    delete unmarshalled;
}

/**
 * @tc.number: LaunchServicesResult_Unmarshalling_003
 * @tc.name: test LaunchServicesResult parcel round-trip with an empty result.
 * @tc.desc: 1. marshal a LaunchServicesResult without launch services or meta fields
 *           2. verify unmarshalling keeps the empty list and empty strings
 */
HWTEST_F(BmsHapModuleInfoTest, LaunchServicesResult_Unmarshalling_003, Function | SmallTest | Level0)
{
    LaunchServicesResult original;

    Parcel parcel;
    ASSERT_TRUE(original.Marshalling(parcel));
    parcel.RewindRead(0);

    LaunchServicesResult *unmarshalled = LaunchServicesResult::Unmarshalling(parcel);
    ASSERT_NE(unmarshalled, nullptr);
    EXPECT_TRUE(unmarshalled->launchServices.empty());
    EXPECT_TRUE(unmarshalled->developerId.empty());
    EXPECT_TRUE(unmarshalled->appIdentifier.empty());
    delete unmarshalled;
}

/**
 * @tc.number: VerifyBinParam_Marshalling_001
 * @tc.name: test VerifyBinParam marshalling
 * @tc.desc: 1. create VerifyBinParam with data
 *           2. verify marshalling success
 */
HWTEST_F(BmsHapModuleInfoTest, VerifyBinParam_Marshalling_001, Function | SmallTest | Level0)
{
    VerifyBinParam param;
    param.bundleName = "com.example.test";
    param.appIdentifier = "testAppId";
    param.userId = 100;
    param.binFilePaths = {"/data/app/libs/test1.bin", "/data/app/libs/test2.bin"};
    param.permissionControlModes = {
        static_cast<int32_t>(PermissionControlMode::INHERIT_PARENT_PROCESS),
        static_cast<int32_t>(PermissionControlMode::INDEPENDENT)};
    param.isDebug = false;
    param.isUninstall = true;
 
    Parcel parcel;
    bool result = param.Marshalling(parcel);
    EXPECT_TRUE(result);
}

/**
 * @tc.number: VerifyBinParam_ReadFromParcel_001
 * @tc.name: test VerifyBinParam ReadFromParcel
 * @tc.desc: 1. write data to parcel
 *           2. verify ReadFromParcel reads correctly
 */
HWTEST_F(BmsHapModuleInfoTest, VerifyBinParam_ReadFromParcel_001, Function | SmallTest | Level0)
{
    VerifyBinParam originalParam;
    originalParam.bundleName = "com.example.test";
    originalParam.appIdentifier = "testAppId";
    originalParam.userId = 100;
    originalParam.binFilePaths = {"/data/app/libs/test1.bin", "/data/app/libs/test2.bin"};
    originalParam.permissionControlModes = {
        static_cast<int32_t>(PermissionControlMode::INHERIT_PARENT_PROCESS),
        static_cast<int32_t>(PermissionControlMode::INHERIT_PARENT_PROCESS)};
    originalParam.isDebug = false;
    originalParam.isUninstall = true;
 
    Parcel parcel;
    ASSERT_TRUE(originalParam.Marshalling(parcel));
    parcel.RewindRead(0);
    VerifyBinParam resultParam;
    bool readResult = resultParam.ReadFromParcel(parcel);
    EXPECT_TRUE(readResult);
    EXPECT_EQ(resultParam.bundleName, originalParam.bundleName);
    EXPECT_EQ(resultParam.appIdentifier, originalParam.appIdentifier);
    EXPECT_EQ(resultParam.userId, originalParam.userId);
    EXPECT_EQ(resultParam.binFilePaths.size(), originalParam.binFilePaths.size());
    EXPECT_EQ(resultParam.binFilePaths[0], originalParam.binFilePaths[0]);
    EXPECT_EQ(resultParam.binFilePaths[1], originalParam.binFilePaths[1]);
    ASSERT_EQ(resultParam.permissionControlModes.size(), originalParam.permissionControlModes.size());
    EXPECT_EQ(resultParam.permissionControlModes[0], originalParam.permissionControlModes[0]);
    EXPECT_EQ(resultParam.permissionControlModes[1], originalParam.permissionControlModes[1]);
    EXPECT_EQ(resultParam.isDebug, originalParam.isDebug);
    EXPECT_EQ(resultParam.isUninstall, originalParam.isUninstall);
}

/**
 * @tc.number: VerifyBinParam_Unmarshalling_001
 * @tc.name: test VerifyBinParam Unmarshalling
 * @tc.desc: 1. marshal VerifyBinParam
 *           2. verify unmarshalling data matches
 */
HWTEST_F(BmsHapModuleInfoTest, VerifyBinParam_Unmarshalling_001, Function | SmallTest | Level0)
{
    VerifyBinParam originalParam;
    originalParam.bundleName = "com.example.test";
    originalParam.appIdentifier = "testAppId";
    originalParam.userId = 100;
    originalParam.binFilePaths = {"/data/app/libs/test.bin"};
    originalParam.permissionControlModes = {
        static_cast<int32_t>(PermissionControlMode::INHERIT_PARENT_PROCESS)};
    originalParam.isDebug = true;
    originalParam.isUninstall = true;

    Parcel parcel;
    ASSERT_TRUE(originalParam.Marshalling(parcel));
    parcel.RewindRead(0);

    VerifyBinParam* unmarshalledParam = VerifyBinParam::Unmarshalling(parcel);
    ASSERT_NE(unmarshalledParam, nullptr);
    EXPECT_EQ(unmarshalledParam->bundleName, originalParam.bundleName);
    EXPECT_EQ(unmarshalledParam->appIdentifier, originalParam.appIdentifier);
    EXPECT_EQ(unmarshalledParam->userId, originalParam.userId);
    EXPECT_EQ(unmarshalledParam->binFilePaths.size(), originalParam.binFilePaths.size());
    EXPECT_EQ(unmarshalledParam->binFilePaths[0], originalParam.binFilePaths[0]);
    ASSERT_EQ(unmarshalledParam->permissionControlModes.size(), 1);
    EXPECT_EQ(unmarshalledParam->permissionControlModes[0],
        static_cast<int32_t>(PermissionControlMode::INHERIT_PARENT_PROCESS));
    EXPECT_EQ(unmarshalledParam->isDebug, originalParam.isDebug);
    EXPECT_EQ(unmarshalledParam->isUninstall, originalParam.isUninstall);
    delete unmarshalledParam;
}

/**
 * @tc.number: ExecutableBinaryPath_Unmarshalling_002
 * @tc.name: test Unmarshalling interface with independent mode
 * @tc.desc: 1. marshal ExecutableBinaryPath with independent mode
 *           2. verify unmarshalling data matches
 */
HWTEST_F(BmsHapModuleInfoTest, ExecutableBinaryPath_Unmarshalling_002, Function | SmallTest | Level0)
{
    ExecutableBinaryPath originalPath;
    originalPath.path = "/data/app/el1/bundle/public/com.example.app/libs/indep.bin";
    EXPECT_EQ(originalPath.permissionControlMode, PermissionControlMode::INDEPENDENT);

    Parcel parcel;
    ASSERT_TRUE(originalPath.Marshalling(parcel));
    parcel.RewindRead(0);
    ExecutableBinaryPath *unmarshalled = ExecutableBinaryPath::Unmarshalling(parcel);
    ASSERT_NE(unmarshalled, nullptr);
    EXPECT_EQ(unmarshalled->path, originalPath.path);
    EXPECT_EQ(unmarshalled->permissionControlMode, PermissionControlMode::INDEPENDENT);
    delete unmarshalled;
}

/**
 * @tc.number: ExecutableBinaryPath_ReadFromParcel_002
 * @tc.name: test ReadFromParcel clamps out-of-range mode
 * @tc.desc: 1. write an illegal mode value
 *           2. verify it falls back to INDEPENDENT instead of failing
 */
HWTEST_F(BmsHapModuleInfoTest, ExecutableBinaryPath_ReadFromParcel_002, Function | SmallTest | Level0)
{
    Parcel parcel;
    parcel.WriteString16(Str8ToStr16("/data/app/el1/bundle/public/com.example.app/libs/test.bin"));
    parcel.WriteInt32(5);

    ExecutableBinaryPath resultPath;
    ASSERT_TRUE(resultPath.ReadFromParcel(parcel));
    EXPECT_EQ(resultPath.path, "/data/app/el1/bundle/public/com.example.app/libs/test.bin");
    EXPECT_EQ(resultPath.permissionControlMode, PermissionControlMode::INDEPENDENT);
}

/**
 * @tc.number: ExecutableBinaryPath_ReadFromParcel_003
 * @tc.name: test ReadFromParcel with truncated parcel
 * @tc.desc: 1. write only path, mode is missing
 *           2. verify ReadFromParcel returns false
 */
HWTEST_F(BmsHapModuleInfoTest, ExecutableBinaryPath_ReadFromParcel_003, Function | SmallTest | Level0)
{
    Parcel parcel;
    parcel.WriteString16(Str8ToStr16("/data/app/el1/bundle/public/com.example.app/libs/test.bin"));

    ExecutableBinaryPath resultPath;
    EXPECT_FALSE(resultPath.ReadFromParcel(parcel));
}

/**
 * @tc.number: ExecutableBinaryPath_from_json_004
 * @tc.name: test from_json after to_json with independent mode
 * @tc.desc: 1. to_json with default independent mode
 *           2. verify from_json keeps independent
 */
HWTEST_F(BmsHapModuleInfoTest, ExecutableBinaryPath_from_json_004, Function | SmallTest | Level0)
{
    ExecutableBinaryPath originalPath;
    originalPath.path = "/data/app/el1/bundle/public/com.example.app/libs/indep.bin";

    nlohmann::json jsonObject;
    to_json(jsonObject, originalPath);
    ExecutableBinaryPath fromJsonPath;
    from_json(jsonObject, fromJsonPath);
    EXPECT_EQ(fromJsonPath.path, originalPath.path);
    EXPECT_EQ(fromJsonPath.permissionControlMode, PermissionControlMode::INDEPENDENT);
}

/**
 * @tc.number: VerifyBinParam_ReadFromParcel_002
 * @tc.name: test VerifyBinParam ReadFromParcel with empty permissionControlModes
 * @tc.desc: 1. permissionControlModes is empty
 *           2. verify ReadFromParcel keeps userId and empty modes
 */
HWTEST_F(BmsHapModuleInfoTest, VerifyBinParam_ReadFromParcel_002, Function | SmallTest | Level0)
{
    VerifyBinParam originalParam;
    originalParam.bundleName = "com.example.test";
    originalParam.appIdentifier = "testAppId";
    originalParam.userId = 200;
    originalParam.binFilePaths = {"/data/app/libs/only-path.bin"};
    originalParam.permissionControlModes.clear();
    originalParam.isDebug = false;

    Parcel parcel;
    ASSERT_TRUE(originalParam.Marshalling(parcel));
    parcel.RewindRead(0);

    VerifyBinParam resultParam;
    ASSERT_TRUE(resultParam.ReadFromParcel(parcel));
    EXPECT_EQ(resultParam.userId, 200);
    ASSERT_EQ(resultParam.binFilePaths.size(), 1);
    EXPECT_TRUE(resultParam.permissionControlModes.empty());
}

/**
 * @tc.number: LibrarySupportDirectory_Marshalling_001
 * @tc.name: test Marshalling interface for librarySupportDirectory
 * @tc.desc: test vector<string> librarySupportDirectory serialization
 */
HWTEST_F(BmsHapModuleInfoTest, LibrarySupportDirectory_Marshalling_001, Function | SmallTest | Level0)
{
    HapModuleInfo hapModuleInfo;
    hapModuleInfo.librarySupportDirectory = {"subA/subB", "subA/subC"};
    Parcel parcel;
    bool ret = hapModuleInfo.Marshalling(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: LibrarySupportDirectory_Marshalling_002
 * @tc.name: test Marshalling interface for empty librarySupportDirectory
 * @tc.desc: test empty vector<string> librarySupportDirectory serialization
 */
HWTEST_F(BmsHapModuleInfoTest, LibrarySupportDirectory_Marshalling_002, Function | SmallTest | Level0)
{
    HapModuleInfo hapModuleInfo;
    hapModuleInfo.librarySupportDirectory = {};
    Parcel parcel;
    bool ret = hapModuleInfo.Marshalling(parcel);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: LibrarySupportDirectory_to_json_001
 * @tc.name: test to_json interface for librarySupportDirectory
 * @tc.desc: test vector<string> librarySupportDirectory to_json
 */
HWTEST_F(BmsHapModuleInfoTest, LibrarySupportDirectory_to_json_001, Function | SmallTest | Level0)
{
    HapModuleInfo hapModuleInfo;
    hapModuleInfo.librarySupportDirectory = {"subA/subB", "subA/subC"};
    nlohmann::json jsonObject;
    to_json(jsonObject, hapModuleInfo);
    EXPECT_EQ(jsonObject["librarySupportDirectory"].size(), 2);
}

/**
 * @tc.number: LibrarySupportDirectory_from_json_001
 * @tc.name: test from_json interface for librarySupportDirectory
 * @tc.desc: test vector<string> librarySupportDirectory from_json
 */
HWTEST_F(BmsHapModuleInfoTest, LibrarySupportDirectory_from_json_001, Function | SmallTest | Level0)
{
    nlohmann::json jsonObject = {
        {"librarySupportDirectory", {"subA/subB", "subA/subC"}}
    };
    HapModuleInfo hapModuleInfo;
    from_json(jsonObject, hapModuleInfo);
    EXPECT_EQ(hapModuleInfo.librarySupportDirectory.size(), 2);
    EXPECT_EQ(hapModuleInfo.librarySupportDirectory[0], "subA/subB");
}

/**
 * @tc.number: LibrarySupportDirectory_from_json_002
 * @tc.name: test from_json interface for empty librarySupportDirectory
 * @tc.desc: test empty vector<string> librarySupportDirectory from_json
 */
HWTEST_F(BmsHapModuleInfoTest, LibrarySupportDirectory_from_json_002, Function | SmallTest | Level0)
{
    nlohmann::json jsonObject = {
        {"librarySupportDirectory", {}}
    };
    HapModuleInfo hapModuleInfo;
    from_json(jsonObject, hapModuleInfo);
    EXPECT_EQ(hapModuleInfo.librarySupportDirectory.size(), 0);
}

/**
 * @tc.number: GetCloneMaxCount_0001
 * @tc.name: test GetCloneMaxCount returns consistent value
 * @tc.desc: 1. call GetCloneMaxCount
 */
HWTEST_F(BmsHapModuleInfoTest, GetCloneMaxCount_0001, Function | SmallTest | Level0)
{
    int32_t maxCount = BundleFileUtil::GetCloneMaxCount();
    EXPECT_TRUE(maxCount >= CLONE_APP_INDEX_MAX_DEFAULT);
}

/**
 * @tc.number: IsExistFile_0100
 * @tc.name: test IsExistFile with empty path
 * @tc.desc: empty filePath → returns false
 */
HWTEST_F(BmsHapModuleInfoTest, IsExistFile_0100, Function | SmallTest | Level0)
{
    EXPECT_FALSE(BundleFileUtil::IsExistFile(""));
}

/**
 * @tc.number: IsExistDir_0200
 * @tc.name: test IsExistDir with empty path
 * @tc.desc: empty dirPath → returns false
 */
HWTEST_F(BmsHapModuleInfoTest, IsExistDir_0200, Function | SmallTest | Level0)
{
    EXPECT_FALSE(BundleFileUtil::IsExistDir(""));
}
}
}