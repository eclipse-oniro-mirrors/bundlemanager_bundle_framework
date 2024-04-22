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
#include "extend_resource_manager_proxy.h"

using namespace testing::ext;
namespace {
const std::string BUNDLE_NAME = "ExtendResourceManagerProxyTest";
const std::string EMPTY_STRING = "";
const std::string MODULE_NAME = "entry";
const int32_t FD = 0;
const std::string FILE_PATH = "data/test";
}

namespace OHOS {
namespace AppExecFwk {

class ExtendResourceManagerProxyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void ExtendResourceManagerProxyTest::SetUpTestCase()
{}

void ExtendResourceManagerProxyTest::TearDownTestCase()
{}

void ExtendResourceManagerProxyTest::SetUp()
{}

void ExtendResourceManagerProxyTest::TearDown()
{}

/**
 * @tc.number: AddExtResource_0100
 * @tc.name: test the AddExtResource
 * @tc.desc: 1. system running normally
 *           2. test AddExtResource
 */
HWTEST_F(ExtendResourceManagerProxyTest, AddExtResource_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    ExtendResourceManagerProxy extendResource(object);
    std::vector<std::string> filePaths;
    ErrCode res = extendResource.AddExtResource(EMPTY_STRING, filePaths);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    res = extendResource.AddExtResource(BUNDLE_NAME, filePaths);
    EXPECT_EQ(res, ERR_EXT_RESOURCE_MANAGER_COPY_FILE_FAILED);

    filePaths.push_back(BUNDLE_NAME);
    res = extendResource.AddExtResource(BUNDLE_NAME, filePaths);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: RemoveExtResource_0100
 * @tc.name: test the RemoveExtResource
 * @tc.desc: 1. system running normally
 *           2. test RemoveExtResource
 */
HWTEST_F(ExtendResourceManagerProxyTest, RemoveExtResource_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    ExtendResourceManagerProxy extendResource(object);
    std::vector<std::string> moduleNames;
    ErrCode res = extendResource.RemoveExtResource(EMPTY_STRING, moduleNames);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    res = extendResource.RemoveExtResource(BUNDLE_NAME, moduleNames);
    EXPECT_EQ(res, ERR_EXT_RESOURCE_MANAGER_REMOVE_EXT_RESOURCE_FAILED);

    moduleNames.push_back(BUNDLE_NAME);
    res = extendResource.RemoveExtResource(BUNDLE_NAME, moduleNames);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: GetExtResource_0100
 * @tc.name: test the GetExtResource
 * @tc.desc: 1. system running normally
 *           2. test GetExtResource
 */
HWTEST_F(ExtendResourceManagerProxyTest, GetExtResource_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    ExtendResourceManagerProxy extendResource(object);
    std::vector<std::string> moduleNames;
    ErrCode res = extendResource.GetExtResource(EMPTY_STRING, moduleNames);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    res = extendResource.GetExtResource(BUNDLE_NAME, moduleNames);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: EnableDynamicIcon_0100
 * @tc.name: test the EnableDynamicIcon
 * @tc.desc: 1. system running normally
 *           2. test EnableDynamicIcon
 */
HWTEST_F(ExtendResourceManagerProxyTest, EnableDynamicIcon_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    ExtendResourceManagerProxy extendResource(object);
    std::vector<std::string> moduleNames;
    ErrCode res = extendResource.EnableDynamicIcon(EMPTY_STRING, EMPTY_STRING);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    res = extendResource.EnableDynamicIcon(BUNDLE_NAME, EMPTY_STRING);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);

    moduleNames.push_back(BUNDLE_NAME);
    res = extendResource.EnableDynamicIcon(BUNDLE_NAME, MODULE_NAME);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: DisableDynamicIcon_0100
 * @tc.name: test the DisableDynamicIcon
 * @tc.desc: 1. system running normally
 *           2. test DisableDynamicIcon
 */
HWTEST_F(ExtendResourceManagerProxyTest, DisableDynamicIcon_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    ExtendResourceManagerProxy extendResource(object);
    ErrCode res = extendResource.DisableDynamicIcon(EMPTY_STRING);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    res = extendResource.DisableDynamicIcon(BUNDLE_NAME);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: GetDynamicIcon_0100
 * @tc.name: test the GetDynamicIcon
 * @tc.desc: 1. system running normally
 *           2. test GetDynamicIcon
 */
HWTEST_F(ExtendResourceManagerProxyTest, GetDynamicIcon_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    ExtendResourceManagerProxy extendResource(object);
    std::string moduleName = FILE_PATH;
    ErrCode res = extendResource.GetDynamicIcon(EMPTY_STRING, moduleName);
    EXPECT_EQ(res, ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);

    res = extendResource.GetDynamicIcon(BUNDLE_NAME, moduleName);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: CreateFd_0100
 * @tc.name: test the CreateFd
 * @tc.desc: 1. system running normally
 *           2. test CreateFd
 */
HWTEST_F(ExtendResourceManagerProxyTest, CreateFd_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    ExtendResourceManagerProxy extendResource(object);
    int32_t fd = FD;
    std::string path = FILE_PATH;
    ErrCode res = extendResource.CreateFd(EMPTY_STRING, fd, path);
    EXPECT_EQ(res, ERR_EXT_RESOURCE_MANAGER_CREATE_FD_FAILED);

    res = extendResource.CreateFd(BUNDLE_NAME, fd, path);
    EXPECT_EQ(res, ERR_APPEXECFWK_PARCEL_ERROR);
}

/**
 * @tc.number: CopyFiles_0100
 * @tc.name: test the CopyFiles
 * @tc.desc: 1. system running normally
 *           2. test CopyFiles
 */
HWTEST_F(ExtendResourceManagerProxyTest, CopyFiles_0100, Function | MediumTest | Level1)
{
    sptr<IRemoteObject> object;
    ExtendResourceManagerProxy extendResource(object);
    std::vector<std::string> sourceFiles;
    std::vector<std::string> destFiles;
    ErrCode res = extendResource.CopyFiles(sourceFiles, destFiles);
    EXPECT_EQ(res, ERR_EXT_RESOURCE_MANAGER_COPY_FILE_FAILED);

    sourceFiles.push_back(BUNDLE_NAME);
    res = extendResource.CopyFiles(sourceFiles, destFiles);
    EXPECT_EQ(res, ERR_EXT_RESOURCE_MANAGER_COPY_FILE_FAILED);
}
} // AppExecFwk
} // OHOS