/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <memory>

#include <gtest/gtest.h>

#include "bundle_skill/skill_info.h"
#include "skill_manager_host_impl.h"
#include "skill_manager_host.h"
#include "skill_manager_proxy.h"
#include "skill_manager_interface.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "ipc_types.h"
#include "message_parcel.h"
#include "appexecfwk_errors.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const std::string BUNDLE_NAME = "com.example.skill.test";
const std::string MODULE_NAME = "entry";
const std::string SKILL_NAME = "testSkill";
const int32_t USER_ID = 100;
} // namespace

class BmsSkillManagerTest : public testing::Test {
public:
    BmsSkillManagerTest();
    ~BmsSkillManagerTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

BmsSkillManagerTest::BmsSkillManagerTest()
{}

BmsSkillManagerTest::~BmsSkillManagerTest()
{}

void BmsSkillManagerTest::SetUpTestCase()
{}

void BmsSkillManagerTest::TearDownTestCase()
{}

void BmsSkillManagerTest::SetUp()
{}

void BmsSkillManagerTest::TearDown()
{}

/**
 * @tc.number: SkillManagerHostImpl_0001
 * @tc.name: GetSkillInfoForSelf with empty moduleName
 * @tc.desc: Test GetSkillInfoForSelf returns ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST when moduleName is empty
 */
HWTEST_F(BmsSkillManagerTest, SkillManagerHostImpl_0001, TestSize.Level1)
{
    std::shared_ptr<SkillManagerHostImpl> skillManager = std::make_shared<SkillManagerHostImpl>();
    ASSERT_NE(skillManager, nullptr);

    SkillInfo skillInfo;
    auto ret = skillManager->GetSkillInfoForSelf("", SKILL_NAME, 0, skillInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
}

/**
 * @tc.number: SkillManagerHostImpl_0002
 * @tc.name: GetSkillInfoForSelf with empty skillName
 * @tc.desc: Test GetSkillInfoForSelf returns ERR_BUNDLE_MANAGER_SKILL_INFO_NOT_EXIST when skillName is empty
 */
HWTEST_F(BmsSkillManagerTest, SkillManagerHostImpl_0002, TestSize.Level1)
{
    std::shared_ptr<SkillManagerHostImpl> skillManager = std::make_shared<SkillManagerHostImpl>();
    ASSERT_NE(skillManager, nullptr);

    SkillInfo skillInfo;
    auto ret = skillManager->GetSkillInfoForSelf(MODULE_NAME, "", 0, skillInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_SKILL_INFO_NOT_EXIST);
}

/**
 * @tc.number: SkillManagerHostImpl_0003
 * @tc.name: GetSkillInfoForSelf with both empty moduleName and skillName
 * @tc.desc: Test moduleName is checked before skillName
 */
HWTEST_F(BmsSkillManagerTest, SkillManagerHostImpl_0003, TestSize.Level1)
{
    std::shared_ptr<SkillManagerHostImpl> skillManager = std::make_shared<SkillManagerHostImpl>();
    ASSERT_NE(skillManager, nullptr);

    SkillInfo skillInfo;
    auto ret = skillManager->GetSkillInfoForSelf("", "", 0, skillInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
}

/**
 * @tc.number: SkillManagerHostImpl_0004
 * @tc.name: GetSkillInfoForSelf with valid params but dataMgr is null
 * @tc.desc: Test returns ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR when dataMgr is null
 */
HWTEST_F(BmsSkillManagerTest, SkillManagerHostImpl_0004, TestSize.Level1)
{
    std::shared_ptr<SkillManagerHostImpl> skillManager = std::make_shared<SkillManagerHostImpl>();
    ASSERT_NE(skillManager, nullptr);

    SkillInfo skillInfo;
    auto ret = skillManager->GetSkillInfoForSelf(MODULE_NAME, SKILL_NAME, 0, skillInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

/**
 * @tc.number: SkillManagerHostImpl_0005
 * @tc.name: GetSkillInfoForSelf with GET_SKILL_INFO_WITH_DESCRIPTION flag
 * @tc.desc: Test flag is passed through to dataMgr
 */
HWTEST_F(BmsSkillManagerTest, SkillManagerHostImpl_0005, TestSize.Level1)
{
    std::shared_ptr<SkillManagerHostImpl> skillManager = std::make_shared<SkillManagerHostImpl>();
    ASSERT_NE(skillManager, nullptr);

    uint32_t flags = static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_DESCRIPTION);
    SkillInfo skillInfo;
    auto ret = skillManager->GetSkillInfoForSelf(MODULE_NAME, SKILL_NAME, flags, skillInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

/**
 * @tc.number: SkillManagerHostImpl_0006
 * @tc.name: GetSkillInfoForSelf with all flags combined
 * @tc.desc: Test combined flags are passed through to dataMgr
 */
HWTEST_F(BmsSkillManagerTest, SkillManagerHostImpl_0006, TestSize.Level1)
{
    std::shared_ptr<SkillManagerHostImpl> skillManager = std::make_shared<SkillManagerHostImpl>();
    ASSERT_NE(skillManager, nullptr);

    uint32_t flags = static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_DESCRIPTION) |
        static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_SRC_ENTRIES) |
        static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_PERMISSIONS) |
        static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_REQUEST_PERMISSIONS);
    SkillInfo skillInfo;
    auto ret = skillManager->GetSkillInfoForSelf(MODULE_NAME, SKILL_NAME, flags, skillInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

/**
 * @tc.number: SkillManagerHostImpl_0007
 * @tc.name: GetSkillInfosForSelf with dataMgr is null
 * @tc.desc: Test returns ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR when dataMgr is null
 */
HWTEST_F(BmsSkillManagerTest, SkillManagerHostImpl_0007, TestSize.Level1)
{
    std::shared_ptr<SkillManagerHostImpl> skillManager = std::make_shared<SkillManagerHostImpl>();
    ASSERT_NE(skillManager, nullptr);

    std::vector<SkillInfo> skillInfos;
    auto ret = skillManager->GetSkillInfosForSelf(0, skillInfos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

/**
 * @tc.number: SkillManagerHostImpl_0008
 * @tc.name: GetSkillInfosForSelf with different flags
 * @tc.desc: Test various flags are passed through correctly
 */
HWTEST_F(BmsSkillManagerTest, SkillManagerHostImpl_0008, TestSize.Level1)
{
    std::shared_ptr<SkillManagerHostImpl> skillManager = std::make_shared<SkillManagerHostImpl>();
    ASSERT_NE(skillManager, nullptr);

    std::vector<SkillInfo> skillInfos;
    uint32_t flags = static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_SRC_ENTRIES) |
        static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_PERMISSIONS);
    auto ret = skillManager->GetSkillInfosForSelf(flags, skillInfos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

/**
 * @tc.number: SkillManagerHostImpl_0009
 * @tc.name: GetSkillInfo permission denied
 * @tc.desc: Test GetSkillInfo returns ERR_BUNDLE_MANAGER_PERMISSION_DENIED without permission
 */
HWTEST_F(BmsSkillManagerTest, SkillManagerHostImpl_0009, TestSize.Level1)
{
    std::shared_ptr<SkillManagerHostImpl> skillManager = std::make_shared<SkillManagerHostImpl>();
    ASSERT_NE(skillManager, nullptr);

    SkillInfo skillInfo;
    auto ret = skillManager->GetSkillInfo(BUNDLE_NAME, MODULE_NAME, SKILL_NAME, 0, USER_ID, skillInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: SkillManagerHostImpl_0010
 * @tc.name: GetSkillInfo with empty bundleName
 * @tc.desc: Test permission check happens before empty param check
 */
HWTEST_F(BmsSkillManagerTest, SkillManagerHostImpl_0010, TestSize.Level1)
{
    std::shared_ptr<SkillManagerHostImpl> skillManager = std::make_shared<SkillManagerHostImpl>();
    ASSERT_NE(skillManager, nullptr);

    SkillInfo skillInfo;
    auto ret = skillManager->GetSkillInfo("", MODULE_NAME, SKILL_NAME, 0, USER_ID, skillInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: SkillManagerHostImpl_0011
 * @tc.name: GetSkillInfo with different flags
 * @tc.desc: Test flags are passed through after permission check
 */
HWTEST_F(BmsSkillManagerTest, SkillManagerHostImpl_0011, TestSize.Level1)
{
    std::shared_ptr<SkillManagerHostImpl> skillManager = std::make_shared<SkillManagerHostImpl>();
    ASSERT_NE(skillManager, nullptr);

    uint32_t flags = static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_DESCRIPTION);
    SkillInfo skillInfo;
    auto ret = skillManager->GetSkillInfo(BUNDLE_NAME, MODULE_NAME, SKILL_NAME, flags, USER_ID, skillInfo);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: SkillManagerHostImpl_0012
 * @tc.name: GetSkillInfos permission denied
 * @tc.desc: Test GetSkillInfos returns ERR_BUNDLE_MANAGER_PERMISSION_DENIED without permission
 */
HWTEST_F(BmsSkillManagerTest, SkillManagerHostImpl_0012, TestSize.Level1)
{
    std::shared_ptr<SkillManagerHostImpl> skillManager = std::make_shared<SkillManagerHostImpl>();
    ASSERT_NE(skillManager, nullptr);

    std::vector<SkillInfo> skillInfos;
    auto ret = skillManager->GetSkillInfos(BUNDLE_NAME, 0, USER_ID, skillInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: SkillManagerHostImpl_0013
 * @tc.name: GetSkillInfos with empty bundleName
 * @tc.desc: Test permission check happens before empty param check
 */
HWTEST_F(BmsSkillManagerTest, SkillManagerHostImpl_0013, TestSize.Level1)
{
    std::shared_ptr<SkillManagerHostImpl> skillManager = std::make_shared<SkillManagerHostImpl>();
    ASSERT_NE(skillManager, nullptr);

    std::vector<SkillInfo> skillInfos;
    auto ret = skillManager->GetSkillInfos("", 0, USER_ID, skillInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: SkillManagerHostImpl_0014
 * @tc.name: GetAllSkillInfos permission denied
 * @tc.desc: Test GetAllSkillInfos returns ERR_BUNDLE_MANAGER_PERMISSION_DENIED without permission
 */
HWTEST_F(BmsSkillManagerTest, SkillManagerHostImpl_0014, TestSize.Level1)
{
    std::shared_ptr<SkillManagerHostImpl> skillManager = std::make_shared<SkillManagerHostImpl>();
    ASSERT_NE(skillManager, nullptr);

    std::vector<SkillInfo> skillInfos;
    auto ret = skillManager->GetAllSkillInfos(0, USER_ID, skillInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: SkillManagerHostImpl_0015
 * @tc.name: GetAllSkillInfos with different flags
 * @tc.desc: Test flags are passed through after permission check
 */
HWTEST_F(BmsSkillManagerTest, SkillManagerHostImpl_0015, TestSize.Level1)
{
    std::shared_ptr<SkillManagerHostImpl> skillManager = std::make_shared<SkillManagerHostImpl>();
    ASSERT_NE(skillManager, nullptr);

    uint32_t flags = static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_REQUEST_PERMISSIONS);
    std::vector<SkillInfo> skillInfos;
    auto ret = skillManager->GetAllSkillInfos(flags, USER_ID, skillInfos);
    EXPECT_EQ(ret, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: SkillManagerHost_0001
 * @tc.name: OnRemoteRequest with descriptor mismatch
 * @tc.desc: Test OnRemoteRequest returns OBJECT_NULL when descriptor mismatch
 */
HWTEST_F(BmsSkillManagerTest, SkillManagerHost_0001, TestSize.Level1)
{
    std::shared_ptr<SkillManagerHostImpl> skillManager = std::make_shared<SkillManagerHostImpl>();
    ASSERT_NE(skillManager, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"ohos.bundleManager.WrongDescriptor");
    uint32_t code = static_cast<uint32_t>(SkillManagerInterfaceCode::GET_SKILL_INFO_FOR_SELF);
    auto ret = skillManager->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, OBJECT_NULL);
}

/**
 * @tc.number: SkillManagerHost_0002
 * @tc.name: OnRemoteRequest with unknown code
 * @tc.desc: Test OnRemoteRequest handles unknown code via default dispatch
 */
HWTEST_F(BmsSkillManagerTest, SkillManagerHost_0002, TestSize.Level1)
{
    std::shared_ptr<SkillManagerHostImpl> skillManager = std::make_shared<SkillManagerHostImpl>();
    ASSERT_NE(skillManager, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(BundleSkillManagerHost::GetDescriptor());
    uint32_t code = 99; // unknown code
    auto ret = skillManager->OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(ret, NO_ERROR);
}

/**
 * @tc.number: SkillManagerHost_0003
 * @tc.name: OnRemoteRequest HandleGetSkillInfoForSelf
 * @tc.desc: Test HandleGetSkillInfoForSelf via OnRemoteRequest
 */
HWTEST_F(BmsSkillManagerTest, SkillManagerHost_0003, TestSize.Level1)
{
    std::shared_ptr<SkillManagerHostImpl> skillManager = std::make_shared<SkillManagerHostImpl>();
    ASSERT_NE(skillManager, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(BundleSkillManagerHost::GetDescriptor());
    data.WriteString("");  // empty moduleName
    data.WriteString(SKILL_NAME);
    data.WriteUint32(0);
    uint32_t code = static_cast<uint32_t>(SkillManagerInterfaceCode::GET_SKILL_INFO_FOR_SELF);
    auto ret = skillManager->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, NO_ERROR);
    int32_t replyRet = reply.ReadInt32();
    EXPECT_EQ(replyRet, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
}

/**
 * @tc.number: SkillManagerHost_0004
 * @tc.name: OnRemoteRequest HandleGetSkillInfosForSelf
 * @tc.desc: Test HandleGetSkillInfosForSelf via OnRemoteRequest
 */
HWTEST_F(BmsSkillManagerTest, SkillManagerHost_0004, TestSize.Level1)
{
    std::shared_ptr<SkillManagerHostImpl> skillManager = std::make_shared<SkillManagerHostImpl>();
    ASSERT_NE(skillManager, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(BundleSkillManagerHost::GetDescriptor());
    data.WriteUint32(0);
    uint32_t code = static_cast<uint32_t>(SkillManagerInterfaceCode::GET_SKILL_INFOS_FOR_SELF);
    auto ret = skillManager->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, NO_ERROR);
    int32_t replyRet = reply.ReadInt32();
    EXPECT_EQ(replyRet, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

/**
 * @tc.number: SkillManagerHost_0005
 * @tc.name: OnRemoteRequest HandleGetSkillInfo
 * @tc.desc: Test HandleGetSkillInfo via OnRemoteRequest with permission denied
 */
HWTEST_F(BmsSkillManagerTest, SkillManagerHost_0005, TestSize.Level1)
{
    std::shared_ptr<SkillManagerHostImpl> skillManager = std::make_shared<SkillManagerHostImpl>();
    ASSERT_NE(skillManager, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(BundleSkillManagerHost::GetDescriptor());
    data.WriteString(BUNDLE_NAME);
    data.WriteString(MODULE_NAME);
    data.WriteString(SKILL_NAME);
    data.WriteUint32(0);
    data.WriteInt32(USER_ID);
    uint32_t code = static_cast<uint32_t>(SkillManagerInterfaceCode::GET_SKILL_INFO);
    auto ret = skillManager->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, NO_ERROR);
    int32_t replyRet = reply.ReadInt32();
    EXPECT_EQ(replyRet, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: SkillManagerHost_0006
 * @tc.name: OnRemoteRequest HandleGetSkillInfos
 * @tc.desc: Test HandleGetSkillInfos via OnRemoteRequest with permission denied
 */
HWTEST_F(BmsSkillManagerTest, SkillManagerHost_0006, TestSize.Level1)
{
    std::shared_ptr<SkillManagerHostImpl> skillManager = std::make_shared<SkillManagerHostImpl>();
    ASSERT_NE(skillManager, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(BundleSkillManagerHost::GetDescriptor());
    data.WriteString(BUNDLE_NAME);
    data.WriteUint32(0);
    data.WriteInt32(USER_ID);
    uint32_t code = static_cast<uint32_t>(SkillManagerInterfaceCode::GET_SKILL_INFOS);
    auto ret = skillManager->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, NO_ERROR);
    int32_t replyRet = reply.ReadInt32();
    EXPECT_EQ(replyRet, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: SkillManagerHost_0007
 * @tc.name: OnRemoteRequest HandleGetAllSkillInfos
 * @tc.desc: Test HandleGetAllSkillInfos via OnRemoteRequest with permission denied
 */
HWTEST_F(BmsSkillManagerTest, SkillManagerHost_0007, TestSize.Level1)
{
    std::shared_ptr<SkillManagerHostImpl> skillManager = std::make_shared<SkillManagerHostImpl>();
    ASSERT_NE(skillManager, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(BundleSkillManagerHost::GetDescriptor());
    data.WriteUint32(0);
    data.WriteInt32(USER_ID);
    uint32_t code = static_cast<uint32_t>(SkillManagerInterfaceCode::GET_ALL_SKILL_INFOS);
    auto ret = skillManager->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, NO_ERROR);
    int32_t replyRet = reply.ReadInt32();
    EXPECT_EQ(replyRet, ERR_BUNDLE_MANAGER_PERMISSION_DENIED);
}

/**
 * @tc.number: SkillManagerHost_0008
 * @tc.name: OnRemoteRequest HandleGetSkillInfoForSelf with empty skillName
 * @tc.desc: Test HandleGetSkillInfoForSelf via OnRemoteRequest with empty skillName
 */
HWTEST_F(BmsSkillManagerTest, SkillManagerHost_0008, TestSize.Level1)
{
    std::shared_ptr<SkillManagerHostImpl> skillManager = std::make_shared<SkillManagerHostImpl>();
    ASSERT_NE(skillManager, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(BundleSkillManagerHost::GetDescriptor());
    data.WriteString(MODULE_NAME);
    data.WriteString("");  // empty skillName
    data.WriteUint32(0);
    uint32_t code = static_cast<uint32_t>(SkillManagerInterfaceCode::GET_SKILL_INFO_FOR_SELF);
    auto ret = skillManager->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, NO_ERROR);
    int32_t replyRet = reply.ReadInt32();
    EXPECT_EQ(replyRet, ERR_BUNDLE_MANAGER_SKILL_INFO_NOT_EXIST);
}

/**
 * @tc.number: SkillManagerHost_0009
 * @tc.name: OnRemoteRequest HandleGetSkillInfoForSelf with valid params
 * @tc.desc: Test HandleGetSkillInfoForSelf with valid params returns dataMgr error
 */
HWTEST_F(BmsSkillManagerTest, SkillManagerHost_0009, TestSize.Level1)
{
    std::shared_ptr<SkillManagerHostImpl> skillManager = std::make_shared<SkillManagerHostImpl>();
    ASSERT_NE(skillManager, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(BundleSkillManagerHost::GetDescriptor());
    data.WriteString(MODULE_NAME);
    data.WriteString(SKILL_NAME);
    data.WriteUint32(0);
    uint32_t code = static_cast<uint32_t>(SkillManagerInterfaceCode::GET_SKILL_INFO_FOR_SELF);
    auto ret = skillManager->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ret, NO_ERROR);
    int32_t replyRet = reply.ReadInt32();
    EXPECT_EQ(replyRet, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

/**
 * @tc.number: SkillManagerProxy_0001
 * @tc.name: GetSkillInfoForSelf with null remote
 * @tc.desc: Test GetSkillInfoForSelf returns error when remote is null
 */
HWTEST_F(BmsSkillManagerTest, SkillManagerProxy_0001, TestSize.Level1)
{
    sptr<IRemoteObject> nullRemote = nullptr;
    std::shared_ptr<BundleSkillManagerProxy> proxy = std::make_shared<BundleSkillManagerProxy>(nullRemote);
    ASSERT_NE(proxy, nullptr);

    SkillInfo skillInfo;
    auto ret = proxy->GetSkillInfoForSelf(MODULE_NAME, SKILL_NAME, 0, skillInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: SkillManagerProxy_0002
 * @tc.name: GetSkillInfosForSelf with null remote
 * @tc.desc: Test GetSkillInfosForSelf returns error when remote is null
 */
HWTEST_F(BmsSkillManagerTest, SkillManagerProxy_0002, TestSize.Level1)
{
    sptr<IRemoteObject> nullRemote = nullptr;
    std::shared_ptr<BundleSkillManagerProxy> proxy = std::make_shared<BundleSkillManagerProxy>(nullRemote);
    ASSERT_NE(proxy, nullptr);

    std::vector<SkillInfo> skillInfos;
    auto ret = proxy->GetSkillInfosForSelf(0, skillInfos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: SkillManagerProxy_0003
 * @tc.name: GetSkillInfo with null remote
 * @tc.desc: Test GetSkillInfo returns error when remote is null
 */
HWTEST_F(BmsSkillManagerTest, SkillManagerProxy_0003, TestSize.Level1)
{
    sptr<IRemoteObject> nullRemote = nullptr;
    std::shared_ptr<BundleSkillManagerProxy> proxy = std::make_shared<BundleSkillManagerProxy>(nullRemote);
    ASSERT_NE(proxy, nullptr);

    SkillInfo skillInfo;
    auto ret = proxy->GetSkillInfo(BUNDLE_NAME, MODULE_NAME, SKILL_NAME, 0, USER_ID, skillInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: SkillManagerProxy_0004
 * @tc.name: GetSkillInfos with null remote
 * @tc.desc: Test GetSkillInfos returns error when remote is null
 */
HWTEST_F(BmsSkillManagerTest, SkillManagerProxy_0004, TestSize.Level1)
{
    sptr<IRemoteObject> nullRemote = nullptr;
    std::shared_ptr<BundleSkillManagerProxy> proxy = std::make_shared<BundleSkillManagerProxy>(nullRemote);
    ASSERT_NE(proxy, nullptr);

    std::vector<SkillInfo> skillInfos;
    auto ret = proxy->GetSkillInfos(BUNDLE_NAME, 0, USER_ID, skillInfos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: SkillManagerProxy_0005
 * @tc.name: GetAllSkillInfos with null remote
 * @tc.desc: Test GetAllSkillInfos returns error when remote is null
 */
HWTEST_F(BmsSkillManagerTest, SkillManagerProxy_0005, TestSize.Level1)
{
    sptr<IRemoteObject> nullRemote = nullptr;
    std::shared_ptr<BundleSkillManagerProxy> proxy = std::make_shared<BundleSkillManagerProxy>(nullRemote);
    ASSERT_NE(proxy, nullptr);

    std::vector<SkillInfo> skillInfos;
    auto ret = proxy->GetAllSkillInfos(0, USER_ID, skillInfos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: SkillInfo_0001
 * @tc.name: SkillInfo default values
 * @tc.desc: Test SkillInfo struct default field values
 */
HWTEST_F(BmsSkillManagerTest, SkillInfo_0001, TestSize.Level1)
{
    SkillInfo skillInfo;
    EXPECT_EQ(skillInfo.bundleName, "");
    EXPECT_EQ(skillInfo.moduleName, "");
    EXPECT_EQ(skillInfo.skillName, "");
    EXPECT_EQ(skillInfo.skillType, SkillType::APP_SKILL);
    EXPECT_EQ(skillInfo.hapPath, "");
    EXPECT_EQ(skillInfo.skillPath, "");
    EXPECT_EQ(skillInfo.versionCode, static_cast<uint32_t>(0));
    EXPECT_EQ(skillInfo.version, "");
    EXPECT_EQ(skillInfo.visibility, "");
    EXPECT_EQ(skillInfo.abilityName, "");
    EXPECT_EQ(skillInfo.description, "");
    EXPECT_TRUE(skillInfo.srcEntries.empty());
    EXPECT_TRUE(skillInfo.permissions.empty());
    EXPECT_TRUE(skillInfo.requestPermissions.empty());
}

/**
 * @tc.number: SkillInfo_0002
 * @tc.name: SkillInfo field assignment
 * @tc.desc: Test SkillInfo struct field assignment
 */
HWTEST_F(BmsSkillManagerTest, SkillInfo_0002, TestSize.Level1)
{
    SkillInfo skillInfo;
    skillInfo.bundleName = BUNDLE_NAME;
    skillInfo.moduleName = MODULE_NAME;
    skillInfo.skillName = SKILL_NAME;
    skillInfo.skillType = SkillType::INDEPENDENT_SKILL;
    skillInfo.hapPath = "/data/app/test.hap";
    skillInfo.skillPath = "/data/app/el1/skills/public/com.test/entry/skills/testSkill";
    skillInfo.versionCode = 100200;
    skillInfo.version = "1.0.0";
    skillInfo.visibility = "public";
    skillInfo.abilityName = "TestAbility";
    skillInfo.description = "test skill description";
    skillInfo.srcEntries = {"src/entry1.js", "src/entry2.js"};
    skillInfo.permissions = {"ohos.permission.READ", "ohos.permission.WRITE"};
    skillInfo.requestPermissions = {"ohos.permission.CAMERA"};

    EXPECT_EQ(skillInfo.bundleName, BUNDLE_NAME);
    EXPECT_EQ(skillInfo.moduleName, MODULE_NAME);
    EXPECT_EQ(skillInfo.skillName, SKILL_NAME);
    EXPECT_EQ(skillInfo.skillType, SkillType::INDEPENDENT_SKILL);
    EXPECT_EQ(skillInfo.hapPath, "/data/app/test.hap");
    EXPECT_EQ(skillInfo.skillPath, "/data/app/el1/skills/public/com.test/entry/skills/testSkill");
    EXPECT_EQ(skillInfo.versionCode, static_cast<uint32_t>(100200));
    EXPECT_EQ(skillInfo.version, "1.0.0");
    EXPECT_EQ(skillInfo.visibility, "public");
    EXPECT_EQ(skillInfo.abilityName, "TestAbility");
    EXPECT_EQ(skillInfo.description, "test skill description");
    EXPECT_EQ(skillInfo.srcEntries.size(), static_cast<size_t>(2));
    EXPECT_EQ(skillInfo.permissions.size(), static_cast<size_t>(2));
    EXPECT_EQ(skillInfo.requestPermissions.size(), static_cast<size_t>(1));
}

/**
 * @tc.number: SkillInfo_0003
 * @tc.name: SkillInfo parcel
 * @tc.desc: Test SkillInfo parcel marshalling and unmarshalling
 */
HWTEST_F(BmsSkillManagerTest, SkillInfo_0003, TestSize.Level1)
{
    SkillInfo skillInfo;
    skillInfo.bundleName = BUNDLE_NAME;
    skillInfo.moduleName = MODULE_NAME;
    skillInfo.skillName = SKILL_NAME;
    skillInfo.skillType = SkillType::INDEPENDENT_SKILL;
    skillInfo.hapPath = "/data/app/test.hap";
    skillInfo.skillPath = "/data/app/el1/skills/public/com.test/entry/skills/testSkill";
    skillInfo.versionCode = 100200;
    skillInfo.version = "1.0.0";
    skillInfo.visibility = "public";
    skillInfo.abilityName = "TestAbility";
    skillInfo.description = "test skill description";
    skillInfo.srcEntries = {"src/entry1.js", "src/entry2.js"};
    skillInfo.permissions = {"ohos.permission.READ", "ohos.permission.WRITE"};
    skillInfo.requestPermissions = {"ohos.permission.CAMERA"};

    Parcel parcel;
    ASSERT_TRUE(skillInfo.Marshalling(parcel));
    std::unique_ptr<SkillInfo> restored(SkillInfo::Unmarshalling(parcel));
    ASSERT_NE(restored, nullptr);
    EXPECT_EQ(restored->bundleName, skillInfo.bundleName);
    EXPECT_EQ(restored->moduleName, skillInfo.moduleName);
    EXPECT_EQ(restored->skillName, skillInfo.skillName);
    EXPECT_EQ(restored->skillType, skillInfo.skillType);
    EXPECT_EQ(restored->hapPath, skillInfo.hapPath);
    EXPECT_EQ(restored->skillPath, skillInfo.skillPath);
    EXPECT_EQ(restored->versionCode, skillInfo.versionCode);
    EXPECT_EQ(restored->version, skillInfo.version);
    EXPECT_EQ(restored->visibility, skillInfo.visibility);
    EXPECT_EQ(restored->abilityName, skillInfo.abilityName);
    EXPECT_EQ(restored->description, skillInfo.description);
    EXPECT_EQ(restored->srcEntries, skillInfo.srcEntries);
    EXPECT_EQ(restored->permissions, skillInfo.permissions);
    EXPECT_EQ(restored->requestPermissions, skillInfo.requestPermissions);
}

/**
 * @tc.number: SkillInfoFlag_0001
 * @tc.name: SkillInfoFlag enum values
 * @tc.desc: Test SkillInfoFlag enum values are correct
 */
HWTEST_F(BmsSkillManagerTest, SkillInfoFlag_0001, TestSize.Level1)
{
    EXPECT_EQ(static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_DEFAULT), 0x00000000);
    EXPECT_EQ(static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_DESCRIPTION), 0x00000001);
    EXPECT_EQ(static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_SRC_ENTRIES), 0x00000002);
    EXPECT_EQ(static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_PERMISSIONS), 0x00000004);
    EXPECT_EQ(static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_REQUEST_PERMISSIONS), 0x00000008);
}

/**
 * @tc.number: SkillInfoFlag_0002
 * @tc.name: SkillInfoFlag combined flags
 * @tc.desc: Test SkillInfoFlag values can be combined with bitwise OR
 */
HWTEST_F(BmsSkillManagerTest, SkillInfoFlag_0002, TestSize.Level1)
{
    uint32_t allFlags = static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_DESCRIPTION) |
        static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_SRC_ENTRIES) |
        static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_PERMISSIONS) |
        static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_REQUEST_PERMISSIONS);
    EXPECT_EQ(allFlags, 0x0000000F);

    EXPECT_TRUE(allFlags & static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_DESCRIPTION));
    EXPECT_TRUE(allFlags & static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_SRC_ENTRIES));
    EXPECT_TRUE(allFlags & static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_PERMISSIONS));
    EXPECT_TRUE(allFlags & static_cast<uint32_t>(SkillInfoFlag::GET_SKILL_INFO_WITH_REQUEST_PERMISSIONS));
}

/**
 * @tc.number: SkillType_0001
 * @tc.name: SkillType enum values
 * @tc.desc: Test SkillType enum values are correct
 */
HWTEST_F(BmsSkillManagerTest, SkillType_0001, TestSize.Level1)
{
    EXPECT_EQ(static_cast<int>(SkillType::APP_SKILL), 0);
    EXPECT_EQ(static_cast<int>(SkillType::INDEPENDENT_SKILL), 1);
}

/**
 * @tc.number: SkillManagerInterfaceCode_0001
 * @tc.name: SkillManagerInterfaceCode enum values
 * @tc.desc: Test SkillManagerInterfaceCode enum values are correct
 */
HWTEST_F(BmsSkillManagerTest, SkillManagerInterfaceCode_0001, TestSize.Level1)
{
    EXPECT_EQ(static_cast<uint8_t>(SkillManagerInterfaceCode::GET_SKILL_INFO_FOR_SELF), 0);
    EXPECT_EQ(static_cast<uint8_t>(SkillManagerInterfaceCode::GET_SKILL_INFOS_FOR_SELF), 1);
    EXPECT_EQ(static_cast<uint8_t>(SkillManagerInterfaceCode::GET_SKILL_INFO), 2);
    EXPECT_EQ(static_cast<uint8_t>(SkillManagerInterfaceCode::GET_SKILL_INFOS), 3);
    EXPECT_EQ(static_cast<uint8_t>(SkillManagerInterfaceCode::GET_ALL_SKILL_INFOS), 4);
}
} // namespace OHOS
