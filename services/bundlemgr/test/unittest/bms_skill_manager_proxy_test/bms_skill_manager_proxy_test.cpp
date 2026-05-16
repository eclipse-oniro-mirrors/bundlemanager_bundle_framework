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

#include <gtest/gtest.h>
#include "bundle_skill/skill_manager_proxy.h"
#include "bundle_skill/skill_info.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "iremote_object.h"
#include "iremote_proxy.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
constexpr int32_t TEST_SKILL_INFO_COUNT_TWO = 2;
constexpr int32_t TEST_SKILL_INFO_COUNT_THREE = 3;
}

class MockRemoteObject : public IRemoteObject {
public:
    MockRemoteObject() : IRemoteObject(u"ohos.bundleManager.SkillManager") {}
    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override
    {
        sendRequestCalled_ = true;
        lastCode_ = code;
        if (shouldFail_) {
            return -1;
        }
        reply.WriteInt32(replyErrCode_);
        if (replyErrCode_ == ERR_OK && writeSkillInfo_) {
            SkillInfo info;
            info.bundleName = "com.test";
            info.moduleName = "module";
            info.skillName = "skill";
            info.skillType = SkillType::APP_SKILL;
            info.versionCode = 1;
            reply.WriteParcelable(&info);
        }
        if (writeSkillInfos_) {
            int32_t size = skillInfoCount_;
            reply.WriteInt32(size);
            for (int32_t i = 0; i < size; i++) {
                SkillInfo info;
                info.bundleName = "com.test" + std::to_string(i);
                info.moduleName = "module";
                info.skillName = "skill" + std::to_string(i);
                reply.WriteParcelable(&info);
            }
        }
        return 0;
    }
    sptr<IRemoteBroker> AsInterface() override { return nullptr; }
    int32_t GetObjectRefCount() override { return 0; }
    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient) override { return true; }
    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient) override { return true; }
    int Dump(int fd, const std::vector<std::u16string> &args) override { return 0; }

    bool sendRequestCalled_ = false;
    uint32_t lastCode_ = 0;
    bool shouldFail_ = false;
    int32_t replyErrCode_ = ERR_OK;
    bool writeSkillInfo_ = true;
    bool writeSkillInfos_ = false;
    int32_t skillInfoCount_ = 0;
};

class BmsSkillManagerProxyTest : public testing::Test {
public:
    void SetUp() override
    {
        mockRemote = new MockRemoteObject();
        proxy = std::make_unique<BundleSkillManagerProxy>(mockRemote);
    }
    void TearDown() override { proxy.reset(); }
protected:
    sptr<MockRemoteObject> mockRemote;
    std::unique_ptr<BundleSkillManagerProxy> proxy;
};

// === GetSkillInfoForSelf ===

TEST_F(BmsSkillManagerProxyTest, GetSkillInfoForSelf_Success)
{
    mockRemote->writeSkillInfo_ = true;
    SkillInfo skillInfo;
    ErrCode ret = proxy->GetSkillInfoForSelf("module", "skill", 0, skillInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(skillInfo.bundleName, "com.test");
    EXPECT_TRUE(mockRemote->sendRequestCalled_);
    EXPECT_EQ(mockRemote->lastCode_, static_cast<uint32_t>(SkillManagerInterfaceCode::GET_SKILL_INFO_FOR_SELF));
}

TEST_F(BmsSkillManagerProxyTest, GetSkillInfoForSelf_SendRequestFailed)
{
    mockRemote->shouldFail_ = true;
    SkillInfo skillInfo;
    ErrCode ret = proxy->GetSkillInfoForSelf("module", "skill", 0, skillInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

TEST_F(BmsSkillManagerProxyTest, GetSkillInfoForSelf_HostError)
{
    mockRemote->replyErrCode_ = ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    SkillInfo skillInfo;
    ErrCode ret = proxy->GetSkillInfoForSelf("module", "skill", 0, skillInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

// === GetSkillInfosForSelf ===

TEST_F(BmsSkillManagerProxyTest, GetSkillInfosForSelf_Success)
{
    mockRemote->writeSkillInfo_ = false;
    mockRemote->writeSkillInfos_ = true;
    mockRemote->skillInfoCount_ = TEST_SKILL_INFO_COUNT_TWO;
    std::vector<SkillInfo> skillInfos;
    ErrCode ret = proxy->GetSkillInfosForSelf(0, skillInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(skillInfos.size(), 2u);
}

TEST_F(BmsSkillManagerProxyTest, GetSkillInfosForSelf_SendRequestFailed)
{
    mockRemote->shouldFail_ = true;
    std::vector<SkillInfo> skillInfos;
    ErrCode ret = proxy->GetSkillInfosForSelf(0, skillInfos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

TEST_F(BmsSkillManagerProxyTest, GetSkillInfosForSelf_HostError)
{
    mockRemote->replyErrCode_ = ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    mockRemote->writeSkillInfo_ = false;
    std::vector<SkillInfo> skillInfos;
    ErrCode ret = proxy->GetSkillInfosForSelf(0, skillInfos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

// === GetSkillInfo ===

TEST_F(BmsSkillManagerProxyTest, GetSkillInfo_Success)
{
    mockRemote->writeSkillInfo_ = true;
    SkillInfo skillInfo;
    ErrCode ret = proxy->GetSkillInfo("com.test", "module", "skill", 0, 100, skillInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(mockRemote->lastCode_, static_cast<uint32_t>(SkillManagerInterfaceCode::GET_SKILL_INFO));
}

TEST_F(BmsSkillManagerProxyTest, GetSkillInfo_SendRequestFailed)
{
    mockRemote->shouldFail_ = true;
    SkillInfo skillInfo;
    ErrCode ret = proxy->GetSkillInfo("com.test", "module", "skill", 0, 100, skillInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

TEST_F(BmsSkillManagerProxyTest, GetSkillInfo_HostError)
{
    mockRemote->replyErrCode_ = ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    SkillInfo skillInfo;
    ErrCode ret = proxy->GetSkillInfo("com.test", "module", "skill", 0, 100, skillInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
}

// === GetSkillInfos ===

TEST_F(BmsSkillManagerProxyTest, GetSkillInfos_Success)
{
    mockRemote->writeSkillInfo_ = false;
    mockRemote->writeSkillInfos_ = true;
    mockRemote->skillInfoCount_ = 1;
    std::vector<SkillInfo> skillInfos;
    ErrCode ret = proxy->GetSkillInfos("com.test", 0, 100, skillInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(skillInfos.size(), 1u);
}

TEST_F(BmsSkillManagerProxyTest, GetSkillInfos_SendRequestFailed)
{
    mockRemote->shouldFail_ = true;
    std::vector<SkillInfo> skillInfos;
    ErrCode ret = proxy->GetSkillInfos("com.test", 0, 100, skillInfos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

// === GetAllSkillInfos ===

TEST_F(BmsSkillManagerProxyTest, GetAllSkillInfos_Success)
{
    mockRemote->writeSkillInfo_ = false;
    mockRemote->writeSkillInfos_ = true;
    mockRemote->skillInfoCount_ = TEST_SKILL_INFO_COUNT_THREE;
    std::vector<SkillInfo> skillInfos;
    ErrCode ret = proxy->GetAllSkillInfos(0, 100, skillInfos);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(skillInfos.size(), 3u);
    EXPECT_EQ(mockRemote->lastCode_, static_cast<uint32_t>(SkillManagerInterfaceCode::GET_ALL_SKILL_INFOS));
}

TEST_F(BmsSkillManagerProxyTest, GetAllSkillInfos_SendRequestFailed)
{
    mockRemote->shouldFail_ = true;
    std::vector<SkillInfo> skillInfos;
    ErrCode ret = proxy->GetAllSkillInfos(0, 100, skillInfos);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}

// === SendRequest with null remote ===

TEST_F(BmsSkillManagerProxyTest, SendRequest_NullRemote)
{
    auto nullProxy = std::make_unique<BundleSkillManagerProxy>(nullptr);
    SkillInfo skillInfo;
    ErrCode ret = nullProxy->GetSkillInfoForSelf("module", "skill", 0, skillInfo);
    EXPECT_EQ(ret, ERR_APPEXECFWK_PARCEL_ERROR);
}
