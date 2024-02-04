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

#include <fstream>
#include <future>
#include <gtest/gtest.h>
#include "bundle_mgr_host.h"

using namespace testing::ext;

namespace OHOS {
namespace AppExecFwk {

class BmsBundleMgrHostTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BmsBundleMgrHostTest::SetUpTestCase()
{}

void BmsBundleMgrHostTest::TearDownTestCase()
{}

void BmsBundleMgrHostTest::SetUp()
{}

void BmsBundleMgrHostTest::TearDown()
{}

/**
 * @tc.number: HandleGetApplicationInfo_0100
 * @tc.name: test the HandleGetApplicationInfo
 * @tc.desc: 1. system running normally
 *           2. test HandleGetApplicationInfo
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetApplicationInfo_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetApplicationInfo(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetApplicationInfoWithIntFlags_0100
 * @tc.name: test the HandleGetApplicationInfoWithIntFlags
 * @tc.desc: 1. system running normally
 *           2. test HandleGetApplicationInfoWithIntFlags
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetApplicationInfoWithIntFlags_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetApplicationInfoWithIntFlags(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetApplicationInfoWithIntFlagsV9_0100
 * @tc.name: test the HandleGetApplicationInfoWithIntFlagsV9
 * @tc.desc: 1. system running normally
 *           2. test HandleGetApplicationInfoWithIntFlagsV9
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetApplicationInfoWithIntFlagsV9_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetApplicationInfoWithIntFlagsV9(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetApplicationInfosWithIntFlags_0100
 * @tc.name: test the HandleGetApplicationInfosWithIntFlags
 * @tc.desc: 1. system running normally
 *           2. test HandleGetApplicationInfosWithIntFlags
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetApplicationInfosWithIntFlags_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetApplicationInfosWithIntFlags(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetApplicationInfosWithIntFlagsV9_0100
 * @tc.name: test the HandleGetApplicationInfosWithIntFlagsV9
 * @tc.desc: 1. system running normally
 *           2. test HandleGetApplicationInfosWithIntFlagsV9
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetApplicationInfosWithIntFlagsV9_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetApplicationInfosWithIntFlagsV9(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetBundleInfoForSelf_0100
 * @tc.name: test the HandleGetBundleInfoForSelf
 * @tc.desc: 1. system running normally
 *           2. test HandleGetBundleInfoForSelf
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetBundleInfoForSelf_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetBundleInfoForSelf(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetDependentBundleInfo_0100
 * @tc.name: test the HandleGetDependentBundleInfo
 * @tc.desc: 1. system running normally
 *           2. test HandleGetDependentBundleInfo
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetDependentBundleInfo_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetDependentBundleInfo(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetBundleInfoWithIntFlagsV9_0100
 * @tc.name: test the HandleGetBundleInfoWithIntFlagsV9
 * @tc.desc: 1. system running normally
 *           2. test HandleGetBundleInfoWithIntFlagsV9
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetBundleInfoWithIntFlagsV9_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetBundleInfoWithIntFlagsV9(data, reply);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: HandleGetBundlePackInfo_0100
 * @tc.name: test the HandleGetBundlePackInfo
 * @tc.desc: 1. system running normally
 *           2. test HandleGetBundlePackInfo
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetBundlePackInfo_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetBundlePackInfo(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetBundlePackInfoWithIntFlags_0100
 * @tc.name: test the HandleGetBundlePackInfoWithIntFlags
 * @tc.desc: 1. system running normally
 *           2. test HandleGetBundlePackInfoWithIntFlags
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetBundlePackInfoWithIntFlags_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetBundlePackInfoWithIntFlags(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetBundleInfos_0100
 * @tc.name: test the HandleGetBundleInfos
 * @tc.desc: 1. system running normally
 *           2. test HandleGetBundleInfos
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetBundleInfos_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetBundleInfos(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetBundleInfosWithIntFlags_0100
 * @tc.name: test the HandleGetBundleInfosWithIntFlags
 * @tc.desc: 1. system running normally
 *           2. test HandleGetBundleInfosWithIntFlags
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetBundleInfosWithIntFlags_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetBundleInfosWithIntFlags(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetBundleInfosWithIntFlagsV9_0100
 * @tc.name: test the HandleGetBundleInfosWithIntFlagsV9
 * @tc.desc: 1. system running normally
 *           2. test HandleGetBundleInfosWithIntFlagsV9
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetBundleInfosWithIntFlagsV9_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetBundleInfosWithIntFlagsV9(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetBundleNameForUid_0100
 * @tc.name: test the HandleGetBundleNameForUid
 * @tc.desc: 1. system running normally
 *           2. test HandleGetBundleNameForUid
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetBundleNameForUid_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetBundleNameForUid(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetBundlesForUid_0100
 * @tc.name: test the HandleGetBundlesForUid
 * @tc.desc: 1. system running normally
 *           2. test HandleGetBundlesForUid
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetBundlesForUid_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetBundlesForUid(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetBundleGids_0100
 * @tc.name: test the HandleGetBundleGids
 * @tc.desc: 1. system running normally
 *           2. test HandleGetBundleGids
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetBundleGids_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetBundleGids(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetBundleGidsByUid_0100
 * @tc.name: test the HandleGetBundleGidsByUid
 * @tc.desc: 1. system running normally
 *           2. test HandleGetBundleGidsByUid
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetBundleGidsByUid_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetBundleGidsByUid(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetBundleInfosByMetaData_0100
 * @tc.name: test the HandleGetBundleInfosByMetaData
 * @tc.desc: 1. system running normally
 *           2. test HandleGetBundleInfosByMetaData
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetBundleInfosByMetaData_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetBundleInfosByMetaData(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleQueryAbilityInfo_0100
 * @tc.name: test the HandleQueryAbilityInfo
 * @tc.desc: 1. system running normally
 *           2. test HandleQueryAbilityInfo
 */
HWTEST_F(BmsBundleMgrHostTest, HandleQueryAbilityInfo_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleQueryAbilityInfo(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleQueryAbilityInfoMutiparam_0100
 * @tc.name: test the HandleQueryAbilityInfoMutiparam
 * @tc.desc: 1. system running normally
 *           2. test HandleQueryAbilityInfoMutiparam
 */
HWTEST_F(BmsBundleMgrHostTest, HandleQueryAbilityInfoMutiparam_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleQueryAbilityInfoMutiparam(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleQueryAbilityInfos_0100
 * @tc.name: test the HandleQueryAbilityInfos
 * @tc.desc: 1. system running normally
 *           2. test HandleQueryAbilityInfos
 */
HWTEST_F(BmsBundleMgrHostTest, HandleQueryAbilityInfos_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleQueryAbilityInfos(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleQueryAbilityInfosMutiparam_0100
 * @tc.name: test the HandleQueryAbilityInfosMutiparam
 * @tc.desc: 1. system running normally
 *           2. test HandleQueryAbilityInfosMutiparam
 */
HWTEST_F(BmsBundleMgrHostTest, HandleQueryAbilityInfosMutiparam_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleQueryAbilityInfosMutiparam(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}
} // AppExecFwk
} // OHOS