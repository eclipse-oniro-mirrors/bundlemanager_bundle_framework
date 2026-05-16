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
#include "bundle_skill/skill_manager_host.h"
#include "bundle_skill/skill_info.h"
#include "bundle_framework_core_ipc_interface_code.h"
#include "ipc_types.h"
#include "message_parcel.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace {
constexpr int32_t TEST_USER_ID = 100;
}

class TestSkillManagerHost : public BundleSkillManagerHost {
public:
    ErrCode lastRet_ = ERR_OK;
    ErrCode GetSkillInfoForSelf(const std::string &moduleName, const std::string &skillName,
        uint32_t flags, SkillInfo &skillInfo) override
    {
        skillInfo.bundleName = "com.test.self";
        skillInfo.moduleName = moduleName;
        skillInfo.skillName = skillName;
        return lastRet_;
    }
    ErrCode GetSkillInfosForSelf(uint32_t flags, std::vector<SkillInfo> &skillInfos) override
    {
        if (lastRet_ == ERR_OK) {
            SkillInfo info;
            info.bundleName = "com.test.self";
            skillInfos.push_back(info);
        }
        return lastRet_;
    }
    ErrCode GetSkillInfo(const std::string &bundleName, const std::string &moduleName,
        const std::string &skillName, uint32_t flags, int32_t userId, SkillInfo &skillInfo) override
    {
        skillInfo.bundleName = bundleName;
        return lastRet_;
    }
    ErrCode GetSkillInfos(const std::string &bundleName, uint32_t flags,
        int32_t userId, std::vector<SkillInfo> &skillInfos) override
    {
        if (lastRet_ == ERR_OK) {
            SkillInfo info;
            info.bundleName = bundleName;
            skillInfos.push_back(info);
        }
        return lastRet_;
    }
    ErrCode GetAllSkillInfos(uint32_t flags, int32_t userId,
        std::vector<SkillInfo> &skillInfos) override
    {
        if (lastRet_ == ERR_OK) {
            SkillInfo info;
            info.bundleName = "all";
            skillInfos.push_back(info);
        }
        return lastRet_;
    }
};

class BmsSkillManagerHostTest : public testing::Test {
public:
    void SetUp() override { host_ = std::make_unique<TestSkillManagerHost>(); }
    void TearDown() override { host_.reset(); }
protected:
    std::unique_ptr<TestSkillManagerHost> host_;
};

// Write valid interface token to parcel
void WriteInterfaceToken(MessageParcel &data)
{
    data.WriteInterfaceToken(BundleSkillManagerHost::GetDescriptor());
}

// === OnRemoteRequest ===

TEST_F(BmsSkillManagerHostTest, OnRemoteRequest_DescriptorMismatch)
{
    MessageParcel data;
    data.WriteInterfaceToken(u"wrong.descriptor");
    MessageParcel reply;
    MessageOption option;
    int32_t ret = host_->OnRemoteRequest(
        static_cast<uint32_t>(SkillManagerInterfaceCode::GET_SKILL_INFO_FOR_SELF), data, reply, option);
    EXPECT_EQ(ret, OBJECT_NULL);
}

TEST_F(BmsSkillManagerHostTest, OnRemoteRequest_UnknownCode)
{
    MessageParcel data;
    WriteInterfaceToken(data);
    MessageParcel reply;
    MessageOption option;
    int32_t ret = host_->OnRemoteRequest(999, data, reply, option);
    // Unknown code falls through to IPCObjectStub
    EXPECT_NE(ret, NO_ERROR);
}

// === HandleGetSkillInfoForSelf ===

TEST_F(BmsSkillManagerHostTest, HandleGetSkillInfoForSelf_Success)
{
    MessageParcel data;
    WriteInterfaceToken(data);
    data.WriteString("module");
    data.WriteString("skill");
    data.WriteUint32(0);
    MessageParcel reply;
    MessageOption option;
    host_->lastRet_ = ERR_OK;
    int32_t ret = host_->OnRemoteRequest(
        static_cast<uint32_t>(SkillManagerInterfaceCode::GET_SKILL_INFO_FOR_SELF), data, reply, option);
    EXPECT_EQ(ret, NO_ERROR);
    ErrCode errCode = reply.ReadInt32();
    EXPECT_EQ(errCode, ERR_OK);
}

TEST_F(BmsSkillManagerHostTest, HandleGetSkillInfoForSelf_HostError)
{
    MessageParcel data;
    WriteInterfaceToken(data);
    data.WriteString("module");
    data.WriteString("skill");
    data.WriteUint32(0);
    MessageParcel reply;
    MessageOption option;
    host_->lastRet_ = ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    int32_t ret = host_->OnRemoteRequest(
        static_cast<uint32_t>(SkillManagerInterfaceCode::GET_SKILL_INFO_FOR_SELF), data, reply, option);
    EXPECT_EQ(ret, NO_ERROR);
}

// === HandleGetSkillInfosForSelf ===

TEST_F(BmsSkillManagerHostTest, HandleGetSkillInfosForSelf_Success)
{
    MessageParcel data;
    WriteInterfaceToken(data);
    data.WriteUint32(0);
    MessageParcel reply;
    MessageOption option;
    host_->lastRet_ = ERR_OK;
    int32_t ret = host_->OnRemoteRequest(
        static_cast<uint32_t>(SkillManagerInterfaceCode::GET_SKILL_INFOS_FOR_SELF), data, reply, option);
    EXPECT_EQ(ret, NO_ERROR);
}

// === HandleGetSkillInfo ===

TEST_F(BmsSkillManagerHostTest, HandleGetSkillInfo_Success)
{
    MessageParcel data;
    WriteInterfaceToken(data);
    data.WriteString("com.test");
    data.WriteString("module");
    data.WriteString("skill");
    data.WriteUint32(0);
    data.WriteInt32(TEST_USER_ID);
    MessageParcel reply;
    MessageOption option;
    host_->lastRet_ = ERR_OK;
    int32_t ret = host_->OnRemoteRequest(
        static_cast<uint32_t>(SkillManagerInterfaceCode::GET_SKILL_INFO), data, reply, option);
    EXPECT_EQ(ret, NO_ERROR);
}

// === HandleGetSkillInfos ===

TEST_F(BmsSkillManagerHostTest, HandleGetSkillInfos_Success)
{
    MessageParcel data;
    WriteInterfaceToken(data);
    data.WriteString("com.test");
    data.WriteUint32(0);
    data.WriteInt32(TEST_USER_ID);
    MessageParcel reply;
    MessageOption option;
    host_->lastRet_ = ERR_OK;
    int32_t ret = host_->OnRemoteRequest(
        static_cast<uint32_t>(SkillManagerInterfaceCode::GET_SKILL_INFOS), data, reply, option);
    EXPECT_EQ(ret, NO_ERROR);
}

// === HandleGetAllSkillInfos ===

TEST_F(BmsSkillManagerHostTest, HandleGetAllSkillInfos_Success)
{
    MessageParcel data;
    WriteInterfaceToken(data);
    data.WriteUint32(0);
    data.WriteInt32(TEST_USER_ID);
    MessageParcel reply;
    MessageOption option;
    host_->lastRet_ = ERR_OK;
    int32_t ret = host_->OnRemoteRequest(
        static_cast<uint32_t>(SkillManagerInterfaceCode::GET_ALL_SKILL_INFOS), data, reply, option);
    EXPECT_EQ(ret, NO_ERROR);
}

TEST_F(BmsSkillManagerHostTest, HandleGetAllSkillInfos_HostError)
{
    MessageParcel data;
    WriteInterfaceToken(data);
    data.WriteUint32(0);
    data.WriteInt32(TEST_USER_ID);
    MessageParcel reply;
    MessageOption option;
    host_->lastRet_ = ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    int32_t ret = host_->OnRemoteRequest(
        static_cast<uint32_t>(SkillManagerInterfaceCode::GET_ALL_SKILL_INFOS), data, reply, option);
    EXPECT_EQ(ret, NO_ERROR);
}
