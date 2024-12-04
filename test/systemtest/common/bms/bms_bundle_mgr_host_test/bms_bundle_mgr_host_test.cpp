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

/**
 * @tc.number: HandleQueryAbilityInfosV9_0100
 * @tc.name: test the HandleQueryAbilityInfosV9
 * @tc.desc: 1. system running normally
 *           2. test HandleQueryAbilityInfosV9
 */
HWTEST_F(BmsBundleMgrHostTest, HandleQueryAbilityInfosV9_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleQueryAbilityInfosV9(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleQueryLauncherAbilityInfos_0100
 * @tc.name: test the HandleQueryLauncherAbilityInfos
 * @tc.desc: 1. system running normally
 *           2. test HandleQueryLauncherAbilityInfos
 */
HWTEST_F(BmsBundleMgrHostTest, HandleQueryLauncherAbilityInfos_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleQueryLauncherAbilityInfos(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleQueryAllAbilityInfos_0100
 * @tc.name: test the HandleQueryAllAbilityInfos
 * @tc.desc: 1. system running normally
 *           2. test HandleQueryAllAbilityInfos
 */
HWTEST_F(BmsBundleMgrHostTest, HandleQueryAllAbilityInfos_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleQueryAllAbilityInfos(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleQueryAbilityInfoByUriForUserId_0100
 * @tc.name: test the HandleQueryAbilityInfoByUriForUserId
 * @tc.desc: 1. system running normally
 *           2. test HandleQueryAbilityInfoByUriForUserId
 */
HWTEST_F(BmsBundleMgrHostTest, HandleQueryAbilityInfoByUriForUserId_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleQueryAbilityInfoByUriForUserId(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleQueryKeepAliveBundleInfos_0100
 * @tc.name: test the HandleQueryKeepAliveBundleInfos
 * @tc.desc: 1. system running normally
 *           2. test HandleQueryKeepAliveBundleInfos
 */
HWTEST_F(BmsBundleMgrHostTest, HandleQueryKeepAliveBundleInfos_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleQueryKeepAliveBundleInfos(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetAbilityLabel_0100
 * @tc.name: test the HandleGetAbilityLabel
 * @tc.desc: 1. system running normally
 *           2. test HandleGetAbilityLabel
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetAbilityLabel_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetAbilityLabel(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetAbilityLabelWithModuleName_0100
 * @tc.name: test the HandleGetAbilityLabelWithModuleName
 * @tc.desc: 1. system running normally
 *           2. test HandleGetAbilityLabelWithModuleName
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetAbilityLabelWithModuleName_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetAbilityLabelWithModuleName(data, reply);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INVALID_PARAMETER);
}

/**
 * @tc.number: HandleCheckIsSystemAppByUid_0100
 * @tc.name: test the HandleCheckIsSystemAppByUid
 * @tc.desc: 1. system running normally
 *           2. test HandleCheckIsSystemAppByUid
 */
HWTEST_F(BmsBundleMgrHostTest, HandleCheckIsSystemAppByUid_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleCheckIsSystemAppByUid(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetBundleArchiveInfo_0100
 * @tc.name: test the HandleGetBundleArchiveInfo
 * @tc.desc: 1. system running normally
 *           2. test HandleGetBundleArchiveInfo
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetBundleArchiveInfo_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetBundleArchiveInfo(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetBundleArchiveInfoWithIntFlags_0100
 * @tc.name: test the HandleGetBundleArchiveInfoWithIntFlags
 * @tc.desc: 1. system running normally
 *           2. test HandleGetBundleArchiveInfoWithIntFlags
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetBundleArchiveInfoWithIntFlags_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetBundleArchiveInfoWithIntFlags(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetBundleArchiveInfoWithIntFlagsV9_0100
 * @tc.name: test the HandleGetBundleArchiveInfoWithIntFlagsV9
 * @tc.desc: 1. system running normally
 *           2. test HandleGetBundleArchiveInfoWithIntFlagsV9
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetBundleArchiveInfoWithIntFlagsV9_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetBundleArchiveInfoWithIntFlagsV9(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetHapModuleInfo_0100
 * @tc.name: test the HandleGetHapModuleInfo
 * @tc.desc: 1. system running normally
 *           2. test HandleGetHapModuleInfo
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetHapModuleInfo_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetHapModuleInfo(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleGetHapModuleInfoWithUserId_0100
 * @tc.name: test the HandleGetHapModuleInfoWithUserId
 * @tc.desc: 1. system running normally
 *           2. test HandleGetHapModuleInfoWithUserId
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetHapModuleInfoWithUserId_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetHapModuleInfoWithUserId(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleGetLaunchWantForBundle_0100
 * @tc.name: test the HandleGetLaunchWantForBundle
 * @tc.desc: 1. system running normally
 *           2. test HandleGetLaunchWantForBundle
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetLaunchWantForBundle_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetLaunchWantForBundle(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetPermissionDef_0100
 * @tc.name: test the HandleGetPermissionDef
 * @tc.desc: 1. system running normally
 *           2. test HandleGetPermissionDef
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetPermissionDef_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetPermissionDef(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleCleanBundleCacheFiles_0100
 * @tc.name: test the HandleCleanBundleCacheFiles
 * @tc.desc: 1. system running normally
 *           2. test HandleCleanBundleCacheFiles
 */
HWTEST_F(BmsBundleMgrHostTest, HandleCleanBundleCacheFiles_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleCleanBundleCacheFiles(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleCleanBundleDataFiles_0100
 * @tc.name: test the HandleCleanBundleDataFiles
 * @tc.desc: 1. system running normally
 *           2. test HandleCleanBundleDataFiles
 */
HWTEST_F(BmsBundleMgrHostTest, HandleCleanBundleDataFiles_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleCleanBundleDataFiles(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleRegisterBundleStatusCallback_0100
 * @tc.name: test the HandleRegisterBundleStatusCallback
 * @tc.desc: 1. system running normally
 *           2. test HandleRegisterBundleStatusCallback
 */
HWTEST_F(BmsBundleMgrHostTest, HandleRegisterBundleStatusCallback_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleRegisterBundleStatusCallback(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleRegisterBundleEventCallback_0100
 * @tc.name: test the HandleRegisterBundleEventCallback
 * @tc.desc: 1. system running normally
 *           2. test HandleRegisterBundleEventCallback
 */
HWTEST_F(BmsBundleMgrHostTest, HandleRegisterBundleEventCallback_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleRegisterBundleEventCallback(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleUnregisterBundleEventCallback_0100
 * @tc.name: test the HandleUnregisterBundleEventCallback
 * @tc.desc: 1. system running normally
 *           2. test HandleUnregisterBundleEventCallback
 */
HWTEST_F(BmsBundleMgrHostTest, HandleUnregisterBundleEventCallback_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleUnregisterBundleEventCallback(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleClearBundleStatusCallback_0100
 * @tc.name: test the HandleClearBundleStatusCallback
 * @tc.desc: 1. system running normally
 *           2. test HandleClearBundleStatusCallback
 */
HWTEST_F(BmsBundleMgrHostTest, HandleClearBundleStatusCallback_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleClearBundleStatusCallback(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleUnregisterBundleStatusCallback_0100
 * @tc.name: test the HandleUnregisterBundleStatusCallback
 * @tc.desc: 1. system running normally
 *           2. test HandleUnregisterBundleStatusCallback
 */
HWTEST_F(BmsBundleMgrHostTest, HandleUnregisterBundleStatusCallback_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleUnregisterBundleStatusCallback(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleDumpInfos_0100
 * @tc.name: test the HandleDumpInfos
 * @tc.desc: 1. system running normally
 *           2. test HandleDumpInfos
 */
HWTEST_F(BmsBundleMgrHostTest, HandleDumpInfos_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleDumpInfos(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleCompileProcessAOT_0100
 * @tc.name: test the HandleCompileProcessAOT
 * @tc.desc: 1. system running normally
 *           2. test HandleCompileProcessAOT
 */
HWTEST_F(BmsBundleMgrHostTest, HandleCompileProcessAOT_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleCompileProcessAOT(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleCompileReset_0100
 * @tc.name: test the HandleCompileReset
 * @tc.desc: 1. system running normally
 *           2. test HandleCompileReset
 */
HWTEST_F(BmsBundleMgrHostTest, HandleCompileReset_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleCompileReset(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetBundleInstaller_0100
 * @tc.name: test the HandleGetBundleInstaller
 * @tc.desc: 1. system running normally
 *           2. test HandleGetBundleInstaller
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetBundleInstaller_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetBundleInstaller(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_HOST_INSTALLER_FAILED);
}

/**
 * @tc.number: HandleGetBundleUserMgr_0100
 * @tc.name: test the HandleGetBundleUserMgr
 * @tc.desc: 1. system running normally
 *           2. test HandleGetBundleUserMgr
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetBundleUserMgr_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetBundleUserMgr(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_INSTALL_HOST_INSTALLER_FAILED);
}

/**
 * @tc.number: HandleGetVerifyManager_0100
 * @tc.name: test the HandleGetVerifyManager
 * @tc.desc: 1. system running normally
 *           2. test HandleGetVerifyManager
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetVerifyManager_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetVerifyManager(data, reply);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_VERIFY_GET_VERIFY_MGR_FAILED);
}

/**
 * @tc.number: HandleIsApplicationEnabled_0100
 * @tc.name: test the HandleIsApplicationEnabled
 * @tc.desc: 1. system running normally
 *           2. test HandleIsApplicationEnabled
 */
HWTEST_F(BmsBundleMgrHostTest, HandleIsApplicationEnabled_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleIsApplicationEnabled(data, reply);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PARAM_ERROR);
}

/**
 * @tc.number: HandleSetApplicationEnabled_0100
 * @tc.name: test the HandleSetApplicationEnabled
 * @tc.desc: 1. system running normally
 *           2. test HandleSetApplicationEnabled
 */
HWTEST_F(BmsBundleMgrHostTest, HandleSetApplicationEnabled_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleSetApplicationEnabled(data, reply);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_PARAM_ERROR);
}

/**
 * @tc.number: HandleIsAbilityEnabled_0100
 * @tc.name: test the HandleIsAbilityEnabled
 * @tc.desc: 1. system running normally
 *           2. test HandleIsAbilityEnabled
 */
HWTEST_F(BmsBundleMgrHostTest, HandleIsAbilityEnabled_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleIsAbilityEnabled(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleSetAbilityEnabled_0100
 * @tc.name: test the HandleSetAbilityEnabled
 * @tc.desc: 1. system running normally
 *           2. test HandleSetAbilityEnabled
 */
HWTEST_F(BmsBundleMgrHostTest, HandleSetAbilityEnabled_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleSetAbilityEnabled(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleGetAllFormsInfo_0100
 * @tc.name: test the HandleGetAllFormsInfo
 * @tc.desc: 1. system running normally
 *           2. test HandleGetAllFormsInfo
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetAllFormsInfo_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetAllFormsInfo(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetFormsInfoByApp_0100
 * @tc.name: test the HandleGetFormsInfoByApp
 * @tc.desc: 1. system running normally
 *           2. test HandleGetFormsInfoByApp
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetFormsInfoByApp_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetFormsInfoByApp(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetFormsInfoByModule_0100
 * @tc.name: test the HandleGetFormsInfoByModule
 * @tc.desc: 1. system running normally
 *           2. test HandleGetFormsInfoByModule
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetFormsInfoByModule_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetFormsInfoByModule(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetShortcutInfos_0100
 * @tc.name: test the HandleGetShortcutInfos
 * @tc.desc: 1. system running normally
 *           2. test HandleGetShortcutInfos
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetShortcutInfos_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetShortcutInfos(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetShortcutInfoV9_0100
 * @tc.name: test the HandleGetShortcutInfoV9
 * @tc.desc: 1. system running normally
 *           2. test HandleGetShortcutInfoV9
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetShortcutInfoV9_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetShortcutInfoV9(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetAllCommonEventInfo_0100
 * @tc.name: test the HandleGetAllCommonEventInfo
 * @tc.desc: 1. system running normally
 *           2. test HandleGetAllCommonEventInfo
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetAllCommonEventInfo_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetAllCommonEventInfo(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetDistributedBundleInfo_0100
 * @tc.name: test the HandleGetDistributedBundleInfo
 * @tc.desc: 1. system running normally
 *           2. test HandleGetDistributedBundleInfo
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetDistributedBundleInfo_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetDistributedBundleInfo(data, reply);
    EXPECT_EQ(res, ERR_INVALID_VALUE);
}

/**
 * @tc.number: HandleGetAppPrivilegeLevel_0100
 * @tc.name: test the HandleGetAppPrivilegeLevel
 * @tc.desc: 1. system running normally
 *           2. test HandleGetAppPrivilegeLevel
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetAppPrivilegeLevel_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetAppPrivilegeLevel(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleQueryExtAbilityInfosWithoutType_0100
 * @tc.name: test the HandleQueryExtAbilityInfosWithoutType
 * @tc.desc: 1. system running normally
 *           2. test HandleQueryExtAbilityInfosWithoutType
 */
HWTEST_F(BmsBundleMgrHostTest, HandleQueryExtAbilityInfosWithoutType_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleQueryExtAbilityInfosWithoutType(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleQueryExtAbilityInfosWithoutTypeV9_0100
 * @tc.name: test the HandleQueryExtAbilityInfosWithoutTypeV9
 * @tc.desc: 1. system running normally
 *           2. test HandleQueryExtAbilityInfosWithoutTypeV9
 */
HWTEST_F(BmsBundleMgrHostTest, HandleQueryExtAbilityInfosWithoutTypeV9_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleQueryExtAbilityInfosWithoutTypeV9(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleQueryExtAbilityInfos
 * @tc.name: test the HandleQueryExtAbilityInfos
 * @tc.desc: 1. system running normally
 *           2. test HandleQueryExtAbilityInfos
 */
HWTEST_F(BmsBundleMgrHostTest, HandleQueryExtAbilityInfos_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleQueryExtAbilityInfos(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleQueryExtAbilityInfosV9
 * @tc.name: test the HandleQueryExtAbilityInfosV9
 * @tc.desc: 1. system running normally
 *           2. test HandleQueryExtAbilityInfosV9
 */
HWTEST_F(BmsBundleMgrHostTest, HandleQueryExtAbilityInfosV9_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleQueryExtAbilityInfosV9(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleQueryExtAbilityInfosByType
 * @tc.name: test the HandleQueryExtAbilityInfosByType
 * @tc.desc: 1. system running normally
 *           2. test HandleQueryExtAbilityInfosByType
 */
HWTEST_F(BmsBundleMgrHostTest, HandleQueryExtAbilityInfosByType_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleQueryExtAbilityInfosByType(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleVerifyCallingPermission
 * @tc.name: test the HandleVerifyCallingPermission
 * @tc.desc: 1. system running normally
 *           2. test HandleVerifyCallingPermission
 */
HWTEST_F(BmsBundleMgrHostTest, HandleVerifyCallingPermission_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleVerifyCallingPermission(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleQueryExtensionAbilityInfoByUri
 * @tc.name: test the HandleQueryExtensionAbilityInfoByUri
 * @tc.desc: 1. system running normally
 *           2. test HandleQueryExtensionAbilityInfoByUri
 */
HWTEST_F(BmsBundleMgrHostTest, HandleQueryExtensionAbilityInfoByUri_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleQueryExtensionAbilityInfoByUri(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetAppIdByBundleName
 * @tc.name: test the HandleGetAppIdByBundleName
 * @tc.desc: 1. system running normally
 *           2. test HandleGetAppIdByBundleName
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetAppIdByBundleName_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetAppIdByBundleName(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetAppType
 * @tc.name: test the HandleGetAppType
 * @tc.desc: 1. system running normally
 *           2. test HandleGetAppType
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetAppType_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetAppType(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetUidByBundleName
 * @tc.name: test the HandleGetUidByBundleName
 * @tc.desc: 1. system running normally
 *           2. test HandleGetUidByBundleName
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetUidByBundleName_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetUidByBundleName(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetUidByDebugBundleName
 * @tc.name: test the HandleGetUidByDebugBundleName
 * @tc.desc: 1. system running normally
 *           2. test HandleGetUidByDebugBundleName
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetUidByDebugBundleName_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetUidByDebugBundleName(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetAbilityInfo
 * @tc.name: test the HandleGetAbilityInfo
 * @tc.desc: 1. system running normally
 *           2. test HandleGetAbilityInfo
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetAbilityInfo_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetAbilityInfo(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetAbilityInfoWithModuleName
 * @tc.name: test the HandleGetAbilityInfoWithModuleName
 * @tc.desc: 1. system running normally
 *           2. test HandleGetAbilityInfoWithModuleName
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetAbilityInfoWithModuleName_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetAbilityInfoWithModuleName(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetModuleUpgradeFlag
 * @tc.name: test the HandleGetModuleUpgradeFlag
 * @tc.desc: 1. system running normally
 *           2. test HandleGetModuleUpgradeFlag
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetModuleUpgradeFlag_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetModuleUpgradeFlag(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleSetModuleUpgradeFlag
 * @tc.name: test the HandleSetModuleUpgradeFlag
 * @tc.desc: 1. system running normally
 *           2. test HandleSetModuleUpgradeFlag
 */
HWTEST_F(BmsBundleMgrHostTest, HandleSetModuleUpgradeFlag_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleSetModuleUpgradeFlag(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleIsModuleRemovable
 * @tc.name: test the HandleIsModuleRemovable
 * @tc.desc: 1. system running normally
 *           2. test HandleIsModuleRemovable
 */
HWTEST_F(BmsBundleMgrHostTest, HandleIsModuleRemovable_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleIsModuleRemovable(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleSetModuleRemovable
 * @tc.name: test the HandleSetModuleRemovable
 * @tc.desc: 1. system running normally
 *           2. test HandleSetModuleRemovable
 */
HWTEST_F(BmsBundleMgrHostTest, HandleSetModuleRemovable_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleSetModuleRemovable(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleImplicitQueryInfoByPriority
 * @tc.name: test the HandleImplicitQueryInfoByPriority
 * @tc.desc: 1. system running normally
 *           2. test HandleImplicitQueryInfoByPriority
 */
HWTEST_F(BmsBundleMgrHostTest, HandleImplicitQueryInfoByPriority_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleImplicitQueryInfoByPriority(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleImplicitQueryInfos
 * @tc.name: test the HandleImplicitQueryInfos
 * @tc.desc: 1. system running normally
 *           2. test HandleImplicitQueryInfos
 */
HWTEST_F(BmsBundleMgrHostTest, HandleImplicitQueryInfos_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleImplicitQueryInfos(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleGetAllDependentModuleNames
 * @tc.name: test the HandleGetAllDependentModuleNames
 * @tc.desc: 1. system running normally
 *           2. test HandleGetAllDependentModuleNames
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetAllDependentModuleNames_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetAllDependentModuleNames(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetSandboxBundleInfo
 * @tc.name: test the HandleGetSandboxBundleInfo
 * @tc.desc: 1. system running normally
 *           2. test HandleGetSandboxBundleInfo
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetSandboxBundleInfo_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetSandboxBundleInfo(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleObtainCallingBundleName
 * @tc.name: test the HandleObtainCallingBundleName
 * @tc.desc: 1. system running normally
 *           2. test HandleObtainCallingBundleName
 */
HWTEST_F(BmsBundleMgrHostTest, HandleObtainCallingBundleName_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleObtainCallingBundleName(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetBundleStats
 * @tc.name: test the HandleGetBundleStats
 * @tc.desc: 1. system running normally
 *           2. test HandleGetBundleStats
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetBundleStats_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetBundleStats(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetAllBundleStats
 * @tc.name: test the HandleGetAllBundleStats
 * @tc.desc: 1. system running normally
 *           2. test HandleGetAllBundleStats
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetAllBundleStats_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetAllBundleStats(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleCheckAbilityEnableInstall
 * @tc.name: test the HandleCheckAbilityEnableInstall
 * @tc.desc: 1. system running normally
 *           2. test HandleCheckAbilityEnableInstall
 */
HWTEST_F(BmsBundleMgrHostTest, HandleCheckAbilityEnableInstall_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleCheckAbilityEnableInstall(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleGetSandboxAbilityInfo
 * @tc.name: test the HandleGetSandboxAbilityInfo
 * @tc.desc: 1. system running normally
 *           2. test HandleGetSandboxAbilityInfo
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetSandboxAbilityInfo_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetSandboxAbilityInfo(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleGetSandboxExtAbilityInfos
 * @tc.name: test the HandleGetSandboxExtAbilityInfos
 * @tc.desc: 1. system running normally
 *           2. test HandleGetSandboxExtAbilityInfos
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetSandboxExtAbilityInfos_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetSandboxExtAbilityInfos(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleGetSandboxHapModuleInfo
 * @tc.name: test the HandleGetSandboxHapModuleInfo
 * @tc.desc: 1. system running normally
 *           2. test HandleGetSandboxHapModuleInfo
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetSandboxHapModuleInfo_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetSandboxHapModuleInfo(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleGetMediaData
 * @tc.name: test the HandleGetMediaData
 * @tc.desc: 1. system running normally
 *           2. test HandleGetMediaData
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetMediaData_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetMediaData(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetStringById
 * @tc.name: test the HandleGetStringById
 * @tc.desc: 1. system running normally
 *           2. test HandleGetStringById
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetStringById_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetStringById(data, reply);
    EXPECT_EQ(res, ERR_INVALID_VALUE);
}

/**
 * @tc.number: HandleGetIconById
 * @tc.name: test the HandleGetIconById
 * @tc.desc: 1. system running normally
 *           2. test HandleGetIconById
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetIconById_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetIconById(data, reply);
    EXPECT_EQ(res, ERR_INVALID_VALUE);
}

/**
 * @tc.number: HandleGetQuickFixManagerProxy
 * @tc.name: test the HandleGetQuickFixManagerProxy
 * @tc.desc: 1. system running normally
 *           2. test HandleGetQuickFixManagerProxy
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetQuickFixManagerProxy_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetQuickFixManagerProxy(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleSetDebugMode
 * @tc.name: test the HandleSetDebugMode
 * @tc.desc: 1. system running normally
 *           2. test HandleSetDebugMode
 */
HWTEST_F(BmsBundleMgrHostTest, HandleSetDebugMode_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleSetDebugMode(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleVerifySystemApi
 * @tc.name: test the HandleVerifySystemApi
 * @tc.desc: 1. system running normally
 *           2. test HandleVerifySystemApi
 */
HWTEST_F(BmsBundleMgrHostTest, HandleVerifySystemApi_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleVerifySystemApi(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetOverlayManagerProxy
 * @tc.name: test the HandleGetOverlayManagerProxy
 * @tc.desc: 1. system running normally
 *           2. test HandleGetOverlayManagerProxy
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetOverlayManagerProxy_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetOverlayManagerProxy(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleProcessPreload
 * @tc.name: test the HandleProcessPreload
 * @tc.desc: 1. system running normally
 *           2. test HandleProcessPreload
 */
HWTEST_F(BmsBundleMgrHostTest, HandleProcessPreload_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleProcessPreload(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleGetAppProvisionInfo
 * @tc.name: test the HandleGetAppProvisionInfo
 * @tc.desc: 1. system running normally
 *           2. test HandleGetAppProvisionInfo
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetAppProvisionInfo_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetAppProvisionInfo(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetProvisionMetadata
 * @tc.name: test the HandleGetProvisionMetadata
 * @tc.desc: 1. system running normally
 *           2. test HandleGetProvisionMetadata
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetProvisionMetadata_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetProvisionMetadata(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetBaseSharedBundleInfos
 * @tc.name: test the HandleGetBaseSharedBundleInfos
 * @tc.desc: 1. system running normally
 *           2. test HandleGetBaseSharedBundleInfos
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetBaseSharedBundleInfos_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetBaseSharedBundleInfos(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetAllSharedBundleInfo
 * @tc.name: test the HandleGetAllSharedBundleInfo
 * @tc.desc: 1. system running normally
 *           2. test HandleGetAllSharedBundleInfo
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetAllSharedBundleInfo_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetAllSharedBundleInfo(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetSharedBundleInfo
 * @tc.name: test the HandleGetSharedBundleInfo
 * @tc.desc: 1. system running normally
 *           2. test HandleGetSharedBundleInfo
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetSharedBundleInfo_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetSharedBundleInfo(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetSharedBundleInfoBySelf
 * @tc.name: test the HandleGetSharedBundleInfoBySelf
 * @tc.desc: 1. system running normally
 *           2. test HandleGetSharedBundleInfoBySelf
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetSharedBundleInfoBySelf_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetSharedBundleInfoBySelf(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetSharedDependencies
 * @tc.name: test the HandleGetSharedDependencies
 * @tc.desc: 1. system running normally
 *           2. test HandleGetSharedDependencies
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetSharedDependencies_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetSharedDependencies(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetProxyDataInfos
 * @tc.name: test the HandleGetProxyDataInfos
 * @tc.desc: 1. system running normally
 *           2. test HandleGetProxyDataInfos
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetProxyDataInfos_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetProxyDataInfos(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetAllProxyDataInfos
 * @tc.name: test the HandleGetAllProxyDataInfos
 * @tc.desc: 1. system running normally
 *           2. test HandleGetAllProxyDataInfos
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetAllProxyDataInfos_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetAllProxyDataInfos(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetSpecifiedDistributionType
 * @tc.name: test the HandleGetSpecifiedDistributionType
 * @tc.desc: 1. system running normally
 *           2. test HandleGetSpecifiedDistributionType
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetSpecifiedDistributionType_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetSpecifiedDistributionType(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetAdditionalInfo
 * @tc.name: test the HandleGetAdditionalInfo
 * @tc.desc: 1. system running normally
 *           2. test HandleGetAdditionalInfo
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetAdditionalInfo_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetAdditionalInfo(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleSetExtNameOrMIMEToApp
 * @tc.name: test the HandleSetExtNameOrMIMEToApp
 * @tc.desc: 1. system running normally
 *           2. test HandleSetExtNameOrMIMEToApp
 */
HWTEST_F(BmsBundleMgrHostTest, HandleSetExtNameOrMIMEToApp_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleSetExtNameOrMIMEToApp(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleDelExtNameOrMIMEToApp
 * @tc.name: test the HandleDelExtNameOrMIMEToApp
 * @tc.desc: 1. system running normally
 *           2. test HandleDelExtNameOrMIMEToApp
 */
HWTEST_F(BmsBundleMgrHostTest, HandleDelExtNameOrMIMEToApp_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleDelExtNameOrMIMEToApp(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleQueryDataGroupInfos
 * @tc.name: test the HandleQueryDataGroupInfos
 * @tc.desc: 1. system running normally
 *           2. test HandleQueryDataGroupInfos
 */
HWTEST_F(BmsBundleMgrHostTest, HandleQueryDataGroupInfos_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleQueryDataGroupInfos(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetPreferenceDirByGroupId
 * @tc.name: test the HandleGetPreferenceDirByGroupId
 * @tc.desc: 1. system running normally
 *           2. test HandleGetPreferenceDirByGroupId
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetPreferenceDirByGroupId_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetPreferenceDirByGroupId(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleQueryAppGalleryBundleName
 * @tc.name: test the HandleQueryAppGalleryBundleName
 * @tc.desc: 1. system running normally
 *           2. test HandleQueryAppGalleryBundleName
 */
HWTEST_F(BmsBundleMgrHostTest, HandleQueryAppGalleryBundleName_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleQueryAppGalleryBundleName(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleQueryExtensionAbilityInfosWithTypeName
 * @tc.name: test the HandleQueryExtensionAbilityInfosWithTypeName
 * @tc.desc: 1. system running normally
 *           2. test HandleQueryExtensionAbilityInfosWithTypeName
 */
HWTEST_F(BmsBundleMgrHostTest, HandleQueryExtensionAbilityInfosWithTypeName_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleQueryExtensionAbilityInfosWithTypeName(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleQueryExtensionAbilityInfosOnlyWithTypeName
 * @tc.name: test the HandleQueryExtensionAbilityInfosOnlyWithTypeName
 * @tc.desc: 1. system running normally
 *           2. test HandleQueryExtensionAbilityInfosOnlyWithTypeName
 */
HWTEST_F(BmsBundleMgrHostTest, HandleQueryExtensionAbilityInfosOnlyWithTypeName_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleQueryExtensionAbilityInfosOnlyWithTypeName(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleResetAOTCompileStatus
 * @tc.name: test the HandleResetAOTCompileStatus
 * @tc.desc: 1. system running normally
 *           2. test HandleResetAOTCompileStatus
 */
HWTEST_F(BmsBundleMgrHostTest, HandleResetAOTCompileStatus_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleResetAOTCompileStatus(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetJsonProfile
 * @tc.name: test the HandleGetJsonProfile
 * @tc.desc: 1. system running normally
 *           2. test HandleGetJsonProfile
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetJsonProfile_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetJsonProfile(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetBundleResourceProxy
 * @tc.name: test the HandleGetBundleResourceProxy
 * @tc.desc: 1. system running normally
 *           2. test HandleGetBundleResourceProxy
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetBundleResourceProxy_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetBundleResourceProxy(data, reply);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: HandleSetAdditionalInfo
 * @tc.name: test the HandleSetAdditionalInfo
 * @tc.desc: 1. system running normally
 *           2. test HandleSetAdditionalInfo
 */
HWTEST_F(BmsBundleMgrHostTest, HandleSetAdditionalInfo_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleSetAdditionalInfo(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetRecoverableApplicationInfo
 * @tc.name: test the HandleGetRecoverableApplicationInfo
 * @tc.desc: 1. system running normally
 *           2. test HandleGetRecoverableApplicationInfo
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetRecoverableApplicationInfo_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetRecoverableApplicationInfo(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetUninstalledBundleInfo
 * @tc.name: test the HandleGetUninstalledBundleInfo
 * @tc.desc: 1. system running normally
 *           2. test HandleGetUninstalledBundleInfo
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetUninstalledBundleInfo_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetUninstalledBundleInfo(data, reply);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_INTERNAL_ERROR);
}

/**
 * @tc.number: HandleCreateBundleDataDir
 * @tc.name: test the HandleCreateBundleDataDir
 * @tc.desc: 1. system running normally
 *           2. test HandleCreateBundleDataDir
 */
HWTEST_F(BmsBundleMgrHostTest, HandleCreateBundleDataDir_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleCreateBundleDataDir(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetAllPreinstalledApplicationInfos
 * @tc.name: test the HandleGetAllPreinstalledApplicationInfos
 * @tc.desc: 1. system running normally
 *           2. test HandleGetAllPreinstalledApplicationInfos
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetAllPreinstalledApplicationInfos_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleCreateBundleDataDir(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleCanOpenLink
 * @tc.name: test the HandleCanOpenLink
 * @tc.desc: 1. system running normally
 *           2. test HandleCanOpenLink
 */
HWTEST_F(BmsBundleMgrHostTest, HandleCanOpenLink_0100, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleCanOpenLink(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleIsBundleInstalled_0001
 * @tc.name: test the HandleIsBundleInstalled
 * @tc.desc: 1. system running normally
 *           2. test HandleIsBundleInstalled
 */
HWTEST_F(BmsBundleMgrHostTest, HandleIsBundleInstalled_0001, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleIsBundleInstalled(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetCompatibleDeviceTypeNative_0001
 * @tc.name: test the HandleGetCompatibleDeviceTypeNative
 * @tc.desc: 1. system running normally
 *           2. test HandleGetCompatibleDeviceTypeNative
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetCompatibleDeviceTypeNative_0001, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetCompatibleDeviceTypeNative(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetCompatibleDeviceType_0001
 * @tc.name: test the HandleGetCompatibleDeviceType
 * @tc.desc: 1. system running normally
 *           2. test HandleGetCompatibleDeviceType
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetCompatibleDeviceType_0001, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetCompatibleDeviceType(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: HandleGetBundleNameByAppId_0001
 * @tc.name: test the HandleGetBundleNameByAppId
 * @tc.desc: 1. system running normally
 *           2. test HandleGetBundleNameByAppId
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetBundleNameByAppId_0001, Function | MediumTest | Level1)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    ErrCode res = bundleMgrHost.HandleGetBundleNameByAppId(data, reply);
    EXPECT_EQ(res, ERR_OK);
}

/**
 * @tc.number: AllocatAshmemNum_0001
 * @tc.name: test the AllocatAshmemNum
 * @tc.desc: 1. system running normally
 *           2. test AllocatAshmemNum
 */
HWTEST_F(BmsBundleMgrHostTest, AllocatAshmemNum_0001, Function | MediumTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    bundleMgrHost.ashmemNum_ = 0;
    bundleMgrHost.AllocatAshmemNum();
    EXPECT_EQ(bundleMgrHost.ashmemNum_, 1);
}

/**
 * @tc.number: WriteBigString_0001
 * @tc.name: test the WriteBigString
 * @tc.desc: 1. system running normally
 *           2. test WriteBigString
 */
HWTEST_F(BmsBundleMgrHostTest, WriteBigString_0001, Function | MediumTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    std::string str;
    MessageParcel reply;
    auto ret = bundleMgrHost.WriteBigString(str, reply);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.number: HandleGetOdidByBundleName_0001
 * @tc.name: test the HandleGetOdidByBundleName
 * @tc.desc: 1. system running normally
 *           2. test HandleGetOdidByBundleName
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetOdidByBundleName_0001, Function | MediumTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    auto ret = bundleMgrHost.HandleGetOdidByBundleName(data, reply);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.number: HandleGetSignatureInfoByBundleName_0001
 * @tc.name: test the HandleGetSignatureInfoByBundleName
 * @tc.desc: 1. system running normally
 *           2. test HandleGetSignatureInfoByBundleName
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetSignatureInfoByBundleName_0001, Function | MediumTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    auto ret = bundleMgrHost.HandleGetSignatureInfoByBundleName(data, reply);
    EXPECT_EQ(ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR, ret);
}

/**
 * @tc.number: HandleUpdateAppEncryptedStatus_0001
 * @tc.name: test the HandleUpdateAppEncryptedStatus
 * @tc.desc: 1. system running normally
 *           2. test HandleUpdateAppEncryptedStatus
 */
HWTEST_F(BmsBundleMgrHostTest, HandleUpdateAppEncryptedStatus_0001, Function | MediumTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    auto ret = bundleMgrHost.HandleUpdateAppEncryptedStatus(data, reply);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.number: HandleGetBundleInfosForContinuation_0001
 * @tc.name: test the HandleGetBundleInfosForContinuation
 * @tc.desc: 1. system running normally
 *           2. test HandleGetBundleInfosForContinuation
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetBundleInfosForContinuation_0001, Function | MediumTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    auto ret = bundleMgrHost.HandleGetBundleInfosForContinuation(data, reply);
    EXPECT_EQ(ERR_OK, ret);
}

/**
 * @tc.number: HandleGetContinueBundleNames_0001
 * @tc.name: test the HandleGetContinueBundleNames
 * @tc.desc: 1. system running normally
 *           2. test HandleGetContinueBundleNames
 */
HWTEST_F(BmsBundleMgrHostTest, HandleGetContinueBundleNames_0001, Function | MediumTest | Level0)
{
    BundleMgrHost bundleMgrHost;
    MessageParcel data;
    MessageParcel reply;
    auto ret = bundleMgrHost.HandleGetContinueBundleNames(data, reply);
    EXPECT_EQ(ERR_OK, ret);
}
} // AppExecFwk
} // OHOS