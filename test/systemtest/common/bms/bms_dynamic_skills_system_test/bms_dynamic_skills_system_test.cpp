/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_mgr_proxy.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AppExecFwk {
using namespace testing::ext;

namespace {
const std::string MODULE_NAME = "moduleName";
const std::string ABILITY_NAME = "abilityName";
const std::vector<std::string> FILE_TYPES = {"general.png", "general.jpeg"};
} // namespace

class BmsDynamicSkillsSystemTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    static sptr<IBundleMgr> GetBMSProxy();
};

void BmsDynamicSkillsSystemTest::SetUpTestCase()
{}

void BmsDynamicSkillsSystemTest::TearDownTestCase()
{}

void BmsDynamicSkillsSystemTest::SetUp()
{}

void BmsDynamicSkillsSystemTest::TearDown()
{}

sptr<IBundleMgr> BmsDynamicSkillsSystemTest::GetBMSProxy()
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        APP_LOGE("GetSystemAbilityManager failed");
        return nullptr;
    }
    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (remoteObject == nullptr) {
        APP_LOGE("GetSystemAbility failed");
        return nullptr;
    }
    return iface_cast<IBundleMgr>(remoteObject);
}

/**
 * @tc.number: SetAbilityFileTypesForSelf_0100
 * @tc.name: test SetAbilityFileTypesForSelf
 * @tc.desc: 1.moduleName is empty, expect return ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST
 */
HWTEST_F(BmsDynamicSkillsSystemTest, SetAbilityFileTypesForSelf_0100, Function | MediumTest | Level1)
{
    sptr<IBundleMgr> proxy = GetBMSProxy();
    ASSERT_NE(proxy, nullptr);
    const std::string moduleName;
    const std::string abilityName = ABILITY_NAME;
    std::vector<std::string> fileTypes = FILE_TYPES;
    ErrCode ret = proxy->SetAbilityFileTypesForSelf(moduleName, abilityName, fileTypes);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
}

/**
 * @tc.number: SetAbilityFileTypesForSelf_0200
 * @tc.name: test SetAbilityFileTypesForSelf
 * @tc.desc: 1.abilityName is empty, expect return ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST
 */
HWTEST_F(BmsDynamicSkillsSystemTest, SetAbilityFileTypesForSelf_0200, Function | MediumTest | Level1)
{
    sptr<IBundleMgr> proxy = GetBMSProxy();
    ASSERT_NE(proxy, nullptr);
    const std::string moduleName = MODULE_NAME;
    const std::string abilityName;
    const std::vector<std::string> fileTypes = FILE_TYPES;
    ErrCode ret = proxy->SetAbilityFileTypesForSelf(moduleName, abilityName, fileTypes);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_ABILITY_NOT_EXIST);
}

/**
 * @tc.number: SetAbilityFileTypesForSelf_0300
 * @tc.name: test SetAbilityFileTypesForSelf
 * @tc.desc: 1.fileTypes is empty, expect return ERR_BUNDLE_MANAGER_PERMISSION_DENIED
 */
HWTEST_F(BmsDynamicSkillsSystemTest, SetAbilityFileTypesForSelf_0300, Function | MediumTest | Level1)
{
    sptr<IBundleMgr> proxy = GetBMSProxy();
    ASSERT_NE(proxy, nullptr);
    const std::string moduleName = MODULE_NAME;
    const std::string abilityName = ABILITY_NAME;
    const std::vector<std::string> fileTypes;
    ErrCode ret = proxy->SetAbilityFileTypesForSelf(moduleName, abilityName, fileTypes);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: SetAbilityFileTypesForSelf_0400
 * @tc.name: test SetAbilityFileTypesForSelf
 * @tc.desc: 1.fileTypes size exceeds 1024, expect return ERR_APPEXECFWK_SET_ABILITY_FILE_TYPES_FOR_SELF
 */
HWTEST_F(BmsDynamicSkillsSystemTest, SetAbilityFileTypesForSelf_0400, Function | MediumTest | Level1)
{
    sptr<IBundleMgr> proxy = GetBMSProxy();
    ASSERT_NE(proxy, nullptr);
    const std::string moduleName = MODULE_NAME;
    const std::string abilityName = ABILITY_NAME;
    const size_t count = 1025;
    std::vector<std::string> fileTypes;
    fileTypes.reserve(count);
    for (size_t i = 0; i < count; i++)
    {
        fileTypes.emplace_back(std::to_string(i));
    }
    ErrCode ret = proxy->SetAbilityFileTypesForSelf(moduleName, abilityName, fileTypes);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SET_ABILITY_FILE_TYPES_FOR_SELF);
}

/**
 * @tc.number: SetAbilityFileTypesForSelf_0500
 * @tc.name: test SetAbilityFileTypesForSelf
 * @tc.desc: 1.fileTypes contains empty fileType, expect return ERR_APPEXECFWK_SET_ABILITY_FILE_TYPES_FOR_SELF
 */
HWTEST_F(BmsDynamicSkillsSystemTest, SetAbilityFileTypesForSelf_0500, Function | MediumTest | Level1)
{
    sptr<IBundleMgr> proxy = GetBMSProxy();
    ASSERT_NE(proxy, nullptr);
    const std::string moduleName = MODULE_NAME;
    const std::string abilityName = ABILITY_NAME;
    std::vector<std::string> fileTypes;
    fileTypes.emplace_back("");
    ErrCode ret = proxy->SetAbilityFileTypesForSelf(moduleName, abilityName, fileTypes);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SET_ABILITY_FILE_TYPES_FOR_SELF);
}

/**
 * @tc.number: SetAbilityFileTypesForSelf_0600
 * @tc.name: test SetAbilityFileTypesForSelf
 * @tc.desc: 1.fileType size exceeds 512, expect return ERR_APPEXECFWK_SET_ABILITY_FILE_TYPES_FOR_SELF
 */
HWTEST_F(BmsDynamicSkillsSystemTest, SetAbilityFileTypesForSelf_0600, Function | MediumTest | Level1)
{
    sptr<IBundleMgr> proxy = GetBMSProxy();
    ASSERT_NE(proxy, nullptr);
    const std::string moduleName = MODULE_NAME;
    const std::string abilityName = ABILITY_NAME;
    std::vector<std::string> fileTypes;
    size_t count = 513;
    char repeatChar = 'a';
    std::string longFileType(count, repeatChar);
    fileTypes.emplace_back(longFileType);
    ErrCode ret = proxy->SetAbilityFileTypesForSelf(moduleName, abilityName, fileTypes);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SET_ABILITY_FILE_TYPES_FOR_SELF);
}

/**
 * @tc.number: SetAbilityFileTypesForSelf_0700
 * @tc.name: test SetAbilityFileTypesForSelf
 * @tc.desc: 1.fileTypes contains wildcard, expect return ERR_APPEXECFWK_SET_ABILITY_FILE_TYPES_FOR_SELF
 */
HWTEST_F(BmsDynamicSkillsSystemTest, SetAbilityFileTypesForSelf_0700, Function | MediumTest | Level1)
{
    sptr<IBundleMgr> proxy = GetBMSProxy();
    ASSERT_NE(proxy, nullptr);
    const std::string moduleName = MODULE_NAME;
    const std::string abilityName = ABILITY_NAME;
    std::vector<std::string> fileTypes;
    fileTypes.emplace_back(Constants::TYPE_WILDCARD);
    ErrCode ret = proxy->SetAbilityFileTypesForSelf(moduleName, abilityName, fileTypes);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SET_ABILITY_FILE_TYPES_FOR_SELF);
}

/**
 * @tc.number: SetAbilityFileTypesForSelf_0800
 * @tc.name: test SetAbilityFileTypesForSelf
 * @tc.desc: 1.fileTypes contains general.object, expect return ERR_APPEXECFWK_SET_ABILITY_FILE_TYPES_FOR_SELF
 */
HWTEST_F(BmsDynamicSkillsSystemTest, SetAbilityFileTypesForSelf_0800, Function | MediumTest | Level1)
{
    sptr<IBundleMgr> proxy = GetBMSProxy();
    ASSERT_NE(proxy, nullptr);
    const std::string moduleName = MODULE_NAME;
    const std::string abilityName = ABILITY_NAME;
    std::vector<std::string> fileTypes;
    fileTypes.emplace_back(Constants::GENERAL_OBJECT);
    ErrCode ret = proxy->SetAbilityFileTypesForSelf(moduleName, abilityName, fileTypes);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SET_ABILITY_FILE_TYPES_FOR_SELF);
}

/**
 * @tc.number: SetAbilityFileTypesForSelf_0900
 * @tc.name: test SetAbilityFileTypesForSelf
 * @tc.desc: 1.expect return ERR_BUNDLE_MANAGER_PERMISSION_DENIED
 */
HWTEST_F(BmsDynamicSkillsSystemTest, SetAbilityFileTypesForSelf_0900, Function | MediumTest | Level1)
{
    sptr<IBundleMgr> proxy = GetBMSProxy();
    ASSERT_NE(proxy, nullptr);
    const std::string moduleName = MODULE_NAME;
    const std::string abilityName = ABILITY_NAME;
    std::vector<std::string> fileTypes = FILE_TYPES;
    ErrCode ret = proxy->SetAbilityFileTypesForSelf(moduleName, abilityName, fileTypes);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}
}  // namespace AppExecFwk
}  // namespace OHOS
