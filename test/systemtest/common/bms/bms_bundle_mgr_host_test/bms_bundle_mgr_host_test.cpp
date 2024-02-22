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
} // AppExecFwk
} // OHOS