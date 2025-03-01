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

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "appexecfwk_errors.h"
#define private public
#include "bundle_mgr_service_death_recipient.h"
#undef private

using namespace testing::ext;
using testing::_;
namespace OHOS {
namespace AppExecFwk {

class BmsBundleMgrServiceDeathRecipientTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BmsBundleMgrServiceDeathRecipientTest::SetUpTestCase() {}

void BmsBundleMgrServiceDeathRecipientTest::TearDownTestCase() {}

void BmsBundleMgrServiceDeathRecipientTest::SetUp() {}

void BmsBundleMgrServiceDeathRecipientTest::TearDown() {}

/**
 * @tc.number: BundleMgrServiceDeathRecipient_001
 * @tc.name: OnRemoteDied
 * @tc.desc: When deathCallback_ is not empty, Successful case of verifying OnRemoteDied.
 */
HWTEST_F(BmsBundleMgrServiceDeathRecipientTest, BundleMgrServiceDeathRecipient_001, TestSize.Level1)
{
    const std::function<void(const wptr<IRemoteObject>& object)> deathCallback;
    const wptr<IRemoteObject> object;
    BundleMgrServiceDeathRecipient bundleMgrServiceDeathRecipient(deathCallback);
    bundleMgrServiceDeathRecipient.OnRemoteDied(object);
    EXPECT_EQ(bundleMgrServiceDeathRecipient.deathCallback_, nullptr);
}

/**
 * @tc.number: BundleMgrServiceDeathRecipient_002
 * @tc.name: OnRemoteDied
 * @tc.desc: When deathCallback_ is empty, Successful case of verifying OnRemoteDied.
 */
HWTEST_F(BmsBundleMgrServiceDeathRecipientTest, BundleMgrServiceDeathRecipient_002, TestSize.Level2)
{
    const wptr<IRemoteObject> object;
    const std::function<void(const wptr<IRemoteObject>& object)> deathCallback;
    BundleMgrServiceDeathRecipient bundleMgrServiceDeathRecipient(deathCallback);
    bundleMgrServiceDeathRecipient.deathCallback_ = nullptr;
    bundleMgrServiceDeathRecipient.OnRemoteDied(object);
    EXPECT_EQ(bundleMgrServiceDeathRecipient.deathCallback_, nullptr);
}
} // namespace AppExecFwk
} // namespace OHOS