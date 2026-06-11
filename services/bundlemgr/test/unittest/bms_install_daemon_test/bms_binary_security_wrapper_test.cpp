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

#include <dlfcn.h>

#define private public
#include "installd/binary_security_wrapper.h"
#undef private

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const std::string TEST_BUNDLE_NAME = "com.ohos.test";
const std::string TEST_APP_IDENTIFIER = "test.app.identifier";
const int32_t TEST_USER_ID = 100;
const std::string TEST_BIN_FILE_PATH = "/data/app/el1/bundle/public/com.ohos.test/bin/test.so";
}

class BmsBinarySecurityWrapperTest : public testing::Test {
public:
    BmsBinarySecurityWrapperTest();
    ~BmsBinarySecurityWrapperTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

BmsBinarySecurityWrapperTest::BmsBinarySecurityWrapperTest()
{}

BmsBinarySecurityWrapperTest::~BmsBinarySecurityWrapperTest()
{}

void BmsBinarySecurityWrapperTest::SetUpTestCase()
{}

void BmsBinarySecurityWrapperTest::TearDownTestCase()
{}

void BmsBinarySecurityWrapperTest::SetUp()
{}

void BmsBinarySecurityWrapperTest::TearDown()
{}

/**
 * @tc.number: BmsBinarySecurityWrapperTest_001
 * @tc.name: test GetInstance
 * @tc.desc: 1. verify singleton pattern works correctly
 */
HWTEST_F(BmsBinarySecurityWrapperTest, BmsBinarySecurityWrapperTest_001, Function | SmallTest | Level0)
{
    auto& instance1 = BinarySecurityWrapper::GetInstance();
    auto& instance2 = BinarySecurityWrapper::GetInstance();
    EXPECT_EQ(&instance1, &instance2);
}

/**
 * @tc.number: BmsBinarySecurityWrapperTest_002
 * @tc.name: test LoadLibraryNoLock when handle is nullptr
 * @tc.desc: 1. LoadLibraryNoLock returns result based on dlopen
 */
HWTEST_F(BmsBinarySecurityWrapperTest, BmsBinarySecurityWrapperTest_002, Function | SmallTest | Level0)
{
    BinarySecurityWrapper& instance = BinarySecurityWrapper::GetInstance();

    void* originalHandle = instance.handle_;
    instance.handle_ = nullptr;

    bool ret = instance.LoadLibraryNoLock();
    if (ret) {
        EXPECT_NE(instance.handle_, nullptr);
        EXPECT_NE(instance.processHapBinInstallFunc_, nullptr);
        instance.UnloadLibrary();
    } else {
        EXPECT_EQ(instance.handle_, nullptr);
    }

    instance.handle_ = originalHandle;
}

/**
 * @tc.number: BmsBinarySecurityWrapperTest_003
 * @tc.name: test LoadLibraryNoLock when handle already exists
 * @tc.desc: 1. LoadLibraryNoLock returns true when handle is not nullptr
 */
HWTEST_F(BmsBinarySecurityWrapperTest, BmsBinarySecurityWrapperTest_003, Function | SmallTest | Level0)
{
    BinarySecurityWrapper& instance = BinarySecurityWrapper::GetInstance();

    void* originalHandle = instance.handle_;
    instance.handle_ = nullptr;

    bool loadRet = instance.LoadLibraryNoLock();
    if (loadRet) {
        EXPECT_NE(instance.handle_, nullptr);
        bool ret = instance.LoadLibraryNoLock();
        EXPECT_TRUE(ret);
        instance.UnloadLibrary();
    }

    instance.handle_ = originalHandle;
}

/**
 * @tc.number: BmsBinarySecurityWrapperTest_004
 * @tc.name: test LoadLibraryNoLock when dlopen fails
 * @tc.desc: 1. LoadLibraryNoLock returns false when dlopen fails
 */
HWTEST_F(BmsBinarySecurityWrapperTest, BmsBinarySecurityWrapperTest_004, Function | SmallTest | Level0)
{
    BinarySecurityWrapper& instance = BinarySecurityWrapper::GetInstance();

    void* originalHandle = instance.handle_;
    instance.handle_ = nullptr;

    bool ret = instance.LoadLibraryNoLock();
    if (!ret) {
        EXPECT_EQ(instance.handle_, nullptr);
    }

    instance.handle_ = originalHandle;
}

/**
 * @tc.number: BmsBinarySecurityWrapperTest_005
 * @tc.name: test UnloadLibrary
 * @tc.desc: 1. UnloadLibrary sets handle to nullptr
 */
HWTEST_F(BmsBinarySecurityWrapperTest, BmsBinarySecurityWrapperTest_005, Function | SmallTest | Level0)
{
    BinarySecurityWrapper& instance = BinarySecurityWrapper::GetInstance();

    void* originalHandle = instance.handle_;
    instance.handle_ = nullptr;

    bool loadRet = instance.LoadLibraryNoLock();
    if (loadRet) {
        EXPECT_NE(instance.handle_, nullptr);
        instance.UnloadLibrary();
        EXPECT_EQ(instance.handle_, nullptr);
        EXPECT_EQ(instance.processHapBinInstallFunc_, nullptr);
    }

    instance.handle_ = originalHandle;
}

/**
 * @tc.number: BmsBinarySecurityWrapperTest_006
 * @tc.name: test UnloadLibrary when handle is nullptr
 * @tc.desc: 1. UnloadLibrary handles nullptr case
 */
HWTEST_F(BmsBinarySecurityWrapperTest, BmsBinarySecurityWrapperTest_006, Function | SmallTest | Level0)
{
    BinarySecurityWrapper& instance = BinarySecurityWrapper::GetInstance();

    void* originalHandle = instance.handle_;

    instance.handle_ = nullptr;
    instance.UnloadLibrary();
    EXPECT_EQ(instance.handle_, nullptr);

    instance.handle_ = originalHandle;
}

/**
 * @tc.number: BmsBinarySecurityWrapperTest_007
 * @tc.name: test ProcessHapBinInstall with empty binFileInfos
 * @tc.desc: 1. ProcessHapBinInstall with empty vector
 */
HWTEST_F(BmsBinarySecurityWrapperTest, BmsBinarySecurityWrapperTest_007, Function | SmallTest | Level0)
{
    BinarySecurityWrapper& instance = BinarySecurityWrapper::GetInstance();

    void* originalHandle = instance.handle_;
    instance.handle_ = nullptr;

    std::vector<BinFileInfo> infos;
    ErrCode ret = instance.ProcessHapBinInstall(TEST_BUNDLE_NAME, TEST_APP_IDENTIFIER, TEST_USER_ID, 0, infos);

    if (ret == ERR_OK) {
        EXPECT_NE(instance.handle_, nullptr);
    } else {
        EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FAILED_VERIFY_BIN_PERMISSION);
    }

    instance.handle_ = originalHandle;
}

/**
 * @tc.number: BmsBinarySecurityWrapperTest_008
 * @tc.name: test ProcessHapBinInstall with valid params
 * @tc.desc: 1. ProcessHapBinInstall with valid params
 */
HWTEST_F(BmsBinarySecurityWrapperTest, BmsBinarySecurityWrapperTest_008, Function | SmallTest | Level0)
{
    BinarySecurityWrapper& instance = BinarySecurityWrapper::GetInstance();

    void* originalHandle = instance.handle_;
    instance.handle_ = nullptr;

    std::vector<BinFileInfo> infos;
    BinFileInfo info;
    info.path = TEST_BIN_FILE_PATH;
    infos.emplace_back(info);

    ErrCode ret = instance.ProcessHapBinInstall(TEST_BUNDLE_NAME, TEST_APP_IDENTIFIER, TEST_USER_ID, 0, infos);

    if (ret == ERR_OK) {
        EXPECT_NE(instance.handle_, nullptr);
    } else {
        EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FAILED_VERIFY_BIN_PERMISSION);
    }

    instance.handle_ = originalHandle;
}

/**
 * @tc.number: BmsBinarySecurityWrapperTest_009
 * @tc.name: test BinFileInfo struct
 * @tc.desc: 1. BinFileInfo can be created and assigned
 */
HWTEST_F(BmsBinarySecurityWrapperTest, BmsBinarySecurityWrapperTest_009, Function | SmallTest | Level0)
{
    BinFileInfo info1;
    info1.path = TEST_BIN_FILE_PATH;
    EXPECT_EQ(info1.path, TEST_BIN_FILE_PATH);

    BinFileInfo info2;
    info2 = info1;
    EXPECT_EQ(info2.path, TEST_BIN_FILE_PATH);

    BinFileInfo info3 = info1;
    EXPECT_EQ(info3.path, TEST_BIN_FILE_PATH);
}

/**
 * @tc.number: BmsBinarySecurityWrapperTest_010
 * @tc.name: test LoadLibraryNoLock twice after reset
 * @tc.desc: 1. LoadLibraryNoLock can be called multiple times after reset
 */
HWTEST_F(BmsBinarySecurityWrapperTest, BmsBinarySecurityWrapperTest_010, Function | SmallTest | Level0)
{
    BinarySecurityWrapper& instance = BinarySecurityWrapper::GetInstance();

    void* originalHandle = instance.handle_;
    instance.handle_ = nullptr;
    bool ret1 = instance.LoadLibraryNoLock();
    instance.UnloadLibrary();
    bool ret2 = instance.LoadLibraryNoLock();
    EXPECT_EQ(ret1, ret2);

    if (ret2) {
        instance.UnloadLibrary();
    }

    instance.handle_ = originalHandle;
}

/**
 * @tc.number: BmsBinarySecurityWrapperTest_011
 * @tc.name: test ProcessHapBinInstall with multiple binFileInfos
 * @tc.desc: 1. ProcessHapBinInstall with multiple bin files
 */
HWTEST_F(BmsBinarySecurityWrapperTest, BmsBinarySecurityWrapperTest_011, Function | SmallTest | Level0)
{
    BinarySecurityWrapper& instance = BinarySecurityWrapper::GetInstance();

    void* originalHandle = instance.handle_;
    instance.handle_ = nullptr;

    std::vector<BinFileInfo> infos;
    BinFileInfo info1;
    info1.path = "/data/app/el1/bundle/public/com.ohos.test/bin/test1.so";
    infos.emplace_back(info1);

    BinFileInfo info2;
    info2.path = "/data/app/el1/bundle/public/com.ohos.test/bin/test2.so";
    infos.emplace_back(info2);

    ErrCode ret = instance.ProcessHapBinInstall(TEST_BUNDLE_NAME, TEST_APP_IDENTIFIER, TEST_USER_ID, 0, infos);

    if (ret == ERR_OK) {
        EXPECT_NE(instance.handle_, nullptr);
    } else {
        EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FAILED_VERIFY_BIN_PERMISSION);
    }

    instance.handle_ = originalHandle;
}

/**
 * @tc.number: BmsBinarySecurityWrapperTest_012
 * @tc.name: test HasNoResolvedSymbolsNoLock when all func ptrs are null
 * @tc.desc: 1. HasNoResolvedSymbolsNoLock returns true
 */
HWTEST_F(BmsBinarySecurityWrapperTest, BmsBinarySecurityWrapperTest_012, Function | SmallTest | Level0)
{
    BinarySecurityWrapper& instance = BinarySecurityWrapper::GetInstance();

    void* originalHandle = instance.handle_;
    instance.handle_ = nullptr;
    instance.processHapBinInstallFunc_ = nullptr;
    instance.requestIndependentBinarySwitchAsyncFunc_ = nullptr;
    instance.checkHspPluginCertValidityFunc_ = nullptr;

    EXPECT_TRUE(instance.HasNoResolvedSymbolsNoLock());

    instance.handle_ = originalHandle;
}

/**
 * @tc.number: BmsBinarySecurityWrapperTest_013
 * @tc.name: test HasNoResolvedSymbolsNoLock when one func ptr is set
 * @tc.desc: 1. HasNoResolvedSymbolsNoLock returns false
 */
HWTEST_F(BmsBinarySecurityWrapperTest, BmsBinarySecurityWrapperTest_013, Function | SmallTest | Level0)
{
    BinarySecurityWrapper& instance = BinarySecurityWrapper::GetInstance();

    void* originalHandle = instance.handle_;
    instance.handle_ = nullptr;
    auto savedProcessFunc = instance.processHapBinInstallFunc_;
    auto savedSwitchFunc = instance.requestIndependentBinarySwitchAsyncFunc_;
    auto savedCertFunc = instance.checkHspPluginCertValidityFunc_;

    instance.processHapBinInstallFunc_ =
        reinterpret_cast<decltype(instance.processHapBinInstallFunc_)>(0x1);
    EXPECT_FALSE(instance.HasNoResolvedSymbolsNoLock());

    instance.processHapBinInstallFunc_ = savedProcessFunc;
    instance.requestIndependentBinarySwitchAsyncFunc_ = savedSwitchFunc;
    instance.checkHspPluginCertValidityFunc_ = savedCertFunc;
    instance.handle_ = originalHandle;
}

/**
 * @tc.number: BmsBinarySecurityWrapperTest_014
 * @tc.name: test ResolveSymbolNoLock with null func param
 * @tc.desc: 1. ResolveSymbolNoLock returns false when func is nullptr
 */
HWTEST_F(BmsBinarySecurityWrapperTest, BmsBinarySecurityWrapperTest_014, Function | SmallTest | Level0)
{
    BinarySecurityWrapper& instance = BinarySecurityWrapper::GetInstance();
    bool ret = instance.ResolveSymbolNoLock("test", nullptr);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: BmsBinarySecurityWrapperTest_015
 * @tc.name: test ResolveSymbolNoLock with null symbolName
 * @tc.desc: 1. ResolveSymbolNoLock returns false when symbolName is nullptr
 */
HWTEST_F(BmsBinarySecurityWrapperTest, BmsBinarySecurityWrapperTest_015, Function | SmallTest | Level0)
{
    BinarySecurityWrapper& instance = BinarySecurityWrapper::GetInstance();
    void* dummy = nullptr;
    bool ret = instance.ResolveSymbolNoLock(nullptr, &dummy);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: BmsBinarySecurityWrapperTest_016
 * @tc.name: test ResolveSymbolNoLock when handle is null
 * @tc.desc: 1. ResolveSymbolNoLock returns false when handle_ is nullptr
 */
HWTEST_F(BmsBinarySecurityWrapperTest, BmsBinarySecurityWrapperTest_016, Function | SmallTest | Level0)
{
    BinarySecurityWrapper& instance = BinarySecurityWrapper::GetInstance();

    void* originalHandle = instance.handle_;
    instance.handle_ = nullptr;
    void* dummy = nullptr;

    bool ret = instance.ResolveSymbolNoLock("test", &dummy);
    EXPECT_FALSE(ret);

    instance.handle_ = originalHandle;
}

/**
 * @tc.number: BmsBinarySecurityWrapperTest_017
 * @tc.name: test ResolveSymbolNoLock when func already resolved
 * @tc.desc: 1. ResolveSymbolNoLock returns true when *func is non-null
 */
HWTEST_F(BmsBinarySecurityWrapperTest, BmsBinarySecurityWrapperTest_017, Function | SmallTest | Level0)
{
    BinarySecurityWrapper& instance = BinarySecurityWrapper::GetInstance();

    void* originalHandle = instance.handle_;
    auto savedProcessFunc = instance.processHapBinInstallFunc_;

    instance.handle_ = dlopen(nullptr, RTLD_LAZY);
    ASSERT_NE(instance.handle_, nullptr);
    instance.processHapBinInstallFunc_ =
        reinterpret_cast<decltype(instance.processHapBinInstallFunc_)>(0x1);

    bool ret = instance.ResolveProcessHapBinInstallNoLock();
    EXPECT_TRUE(ret);

    instance.processHapBinInstallFunc_ = savedProcessFunc;
    dlclose(instance.handle_);
    instance.handle_ = originalHandle;
}

/**
 * @tc.number: BmsBinarySecurityWrapperTest_018
 * @tc.name: test ResolveProcessHapBinInstallNoLock with null handle
 * @tc.desc: 1. ResolveProcessHapBinInstallNoLock returns false when handle_ is null
 */
HWTEST_F(BmsBinarySecurityWrapperTest, BmsBinarySecurityWrapperTest_018, Function | SmallTest | Level0)
{
    BinarySecurityWrapper& instance = BinarySecurityWrapper::GetInstance();

    void* originalHandle = instance.handle_;
    instance.handle_ = nullptr;
    instance.processHapBinInstallFunc_ = nullptr;

    bool ret = instance.ResolveProcessHapBinInstallNoLock();
    EXPECT_FALSE(ret);

    instance.handle_ = originalHandle;
}

/**
 * @tc.number: BmsBinarySecurityWrapperTest_019
 * @tc.name: test ResolveRequestIndependentBinarySwitchAsyncNoLock with null handle
 * @tc.desc: 1. ResolveRequestIndependentBinarySwitchAsyncNoLock returns false when handle_ is null
 */
HWTEST_F(BmsBinarySecurityWrapperTest, BmsBinarySecurityWrapperTest_019, Function | SmallTest | Level0)
{
    BinarySecurityWrapper& instance = BinarySecurityWrapper::GetInstance();

    void* originalHandle = instance.handle_;
    instance.handle_ = nullptr;
    instance.requestIndependentBinarySwitchAsyncFunc_ = nullptr;

    bool ret = instance.ResolveRequestIndependentBinarySwitchAsyncNoLock();
    EXPECT_FALSE(ret);

    instance.handle_ = originalHandle;
}

/**
 * @tc.number: BmsBinarySecurityWrapperTest_020
 * @tc.name: test ResolveCheckHspPluginCertValidityNoLock with null handle
 * @tc.desc: 1. ResolveCheckHspPluginCertValidityNoLock returns false when handle_ is null
 */
HWTEST_F(BmsBinarySecurityWrapperTest, BmsBinarySecurityWrapperTest_020, Function | SmallTest | Level0)
{
    BinarySecurityWrapper& instance = BinarySecurityWrapper::GetInstance();

    void* originalHandle = instance.handle_;
    instance.handle_ = nullptr;
    instance.checkHspPluginCertValidityFunc_ = nullptr;

    bool ret = instance.ResolveCheckHspPluginCertValidityNoLock();
    EXPECT_FALSE(ret);

    instance.handle_ = originalHandle;
}

/**
 * @tc.number: BmsBinarySecurityWrapperTest_021
 * @tc.name: test UnloadLibraryNoLock when handle is null
 * @tc.desc: 1. UnloadLibraryNoLock handles nullptr handle gracefully
 */
HWTEST_F(BmsBinarySecurityWrapperTest, BmsBinarySecurityWrapperTest_021, Function | SmallTest | Level0)
{
    BinarySecurityWrapper& instance = BinarySecurityWrapper::GetInstance();

    void* originalHandle = instance.handle_;
    instance.handle_ = nullptr;

    instance.UnloadLibraryNoLock();
    EXPECT_EQ(instance.handle_, nullptr);

    instance.handle_ = originalHandle;
}

/**
 * @tc.number: BmsBinarySecurityWrapperTest_022
 * @tc.name: test UnloadLibraryNoLock after load resets handle and func ptrs
 * @tc.desc: 1. UnloadLibraryNoLock resets handle_ and all func ptrs to nullptr
 */
HWTEST_F(BmsBinarySecurityWrapperTest, BmsBinarySecurityWrapperTest_022, Function | SmallTest | Level0)
{
    BinarySecurityWrapper& instance = BinarySecurityWrapper::GetInstance();

    void* originalHandle = instance.handle_;
    instance.handle_ = dlopen(nullptr, RTLD_LAZY);
    ASSERT_NE(instance.handle_, nullptr);

    instance.UnloadLibraryNoLock();
    EXPECT_EQ(instance.handle_, nullptr);
    EXPECT_EQ(instance.processHapBinInstallFunc_, nullptr);
    EXPECT_EQ(instance.requestIndependentBinarySwitchAsyncFunc_, nullptr);
    EXPECT_EQ(instance.checkHspPluginCertValidityFunc_, nullptr);

    instance.handle_ = originalHandle;
}

/**
 * @tc.number: BmsBinarySecurityWrapperTest_023
 * @tc.name: test RequestIndependentBinarySwitchAsync without library
 * @tc.desc: 1. RequestIndependentBinarySwitchAsync returns permission error when library unavailable
 */
HWTEST_F(BmsBinarySecurityWrapperTest, BmsBinarySecurityWrapperTest_023, Function | SmallTest | Level0)
{
    BinarySecurityWrapper& instance = BinarySecurityWrapper::GetInstance();

    void* originalHandle = instance.handle_;
    instance.handle_ = nullptr;

    int32_t outSwitchStatus = 0;
    ErrCode ret = instance.RequestIndependentBinarySwitchAsync(outSwitchStatus);

    if (ret == ERR_OK) {
        EXPECT_NE(instance.handle_, nullptr);
    } else {
        EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FAILED_VERIFY_BIN_PERMISSION);
    }

    instance.handle_ = originalHandle;
}

/**
 * @tc.number: BmsBinarySecurityWrapperTest_024
 * @tc.name: test CheckHspPluginCertValidity without library
 * @tc.desc: 1. CheckHspPluginCertValidity returns permission error when library unavailable
 */
HWTEST_F(BmsBinarySecurityWrapperTest, BmsBinarySecurityWrapperTest_024, Function | SmallTest | Level0)
{
    BinarySecurityWrapper& instance = BinarySecurityWrapper::GetInstance();

    void* originalHandle = instance.handle_;
    instance.handle_ = nullptr;

    Security::Verify::HspPlugin hspPlugin{};
    ErrCode ret = instance.CheckHspPluginCertValidity(hspPlugin);

    if (ret == ERR_OK) {
        EXPECT_NE(instance.handle_, nullptr);
    } else {
        EXPECT_EQ(ret, ERR_APPEXECFWK_INSTALL_FAILED_VERIFY_BIN_PERMISSION);
    }

    instance.handle_ = originalHandle;
}

/**
 * @tc.number: BmsBinarySecurityWrapperTest_025
 * @tc.name: test UnloadLibrary delegates to UnloadLibraryNoLock
 * @tc.desc: 1. UnloadLibrary resets handle_ and func ptrs to nullptr
 */
HWTEST_F(BmsBinarySecurityWrapperTest, BmsBinarySecurityWrapperTest_025, Function | SmallTest | Level0)
{
    BinarySecurityWrapper& instance = BinarySecurityWrapper::GetInstance();

    void* originalHandle = instance.handle_;
    instance.handle_ = dlopen(nullptr, RTLD_LAZY);
    ASSERT_NE(instance.handle_, nullptr);

    instance.UnloadLibrary();
    EXPECT_EQ(instance.handle_, nullptr);
    EXPECT_EQ(instance.processHapBinInstallFunc_, nullptr);
    EXPECT_EQ(instance.requestIndependentBinarySwitchAsyncFunc_, nullptr);
    EXPECT_EQ(instance.checkHspPluginCertValidityFunc_, nullptr);

    instance.handle_ = originalHandle;
}
} // OHOS
