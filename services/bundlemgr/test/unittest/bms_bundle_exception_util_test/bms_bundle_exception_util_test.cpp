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

#include <atomic>
#include <dlfcn.h>
#include <gtest/gtest.h>
#include <string>
#include <thread>
#include <vector>

#include "exception_util.h"
#include "nlohmann/json.hpp"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

// Declare the extern "C" function from exception_wrapper.cpp for direct testing
// Must be declared outside of any namespace as extern "C" has C linkage
extern "C" bool BundleMgrSafeDump(const nlohmann::json& jsonObject, std::string& result, int32_t indent);

namespace OHOS {
namespace {
constexpr int32_t THREAD_COUNT = 8;
constexpr int32_t ITERATIONS_PER_THREAD = 10;
} // namespace

class BmsBundleExceptionUtilTest : public testing::Test {
public:
    BmsBundleExceptionUtilTest();
    ~BmsBundleExceptionUtilTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

BmsBundleExceptionUtilTest::BmsBundleExceptionUtilTest()
{}

BmsBundleExceptionUtilTest::~BmsBundleExceptionUtilTest()
{}

void BmsBundleExceptionUtilTest::SetUpTestCase()
{}

void BmsBundleExceptionUtilTest::TearDownTestCase()
{}

void BmsBundleExceptionUtilTest::SetUp()
{}

void BmsBundleExceptionUtilTest::TearDown()
{}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0001
 * @tc.name: test GetInstance function
 * @tc.desc: 1.GetInstance returns the same instance
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0001, Function | SmallTest | Level1)
{
    ExceptionUtil& instance1 = ExceptionUtil::GetInstance();
    ExceptionUtil& instance2 = ExceptionUtil::GetInstance();
    EXPECT_EQ(&instance1, &instance2);
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0002
 * @tc.name: test SafeDump function with empty json object
 * @tc.desc: 1.SafeDump with empty json object
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0002, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject = nlohmann::json::object();
    std::string result;
    bool ret = ExceptionUtil::GetInstance().SafeDump(jsonObject, result);
    if (ret) {
        EXPECT_EQ(result, "{}");
    } else {
        // If library not loaded, SafeDump returns false
        EXPECT_TRUE(result.empty());
    }
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0003
 * @tc.name: test SafeDump function with simple json object
 * @tc.desc: 1.SafeDump with simple json object
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0003, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    jsonObject["key"] = "value";
    jsonObject["number"] = 123;
    jsonObject["boolean"] = true;

    std::string result;
    bool ret = ExceptionUtil::GetInstance().SafeDump(jsonObject, result);
    if (ret) {
        EXPECT_FALSE(result.empty());
        EXPECT_NE(result.find("key"), std::string::npos);
        EXPECT_NE(result.find("value"), std::string::npos);
        EXPECT_NE(result.find("123"), std::string::npos);
        EXPECT_NE(result.find("true"), std::string::npos);
    } else {
        EXPECT_TRUE(result.empty());
    }
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0004
 * @tc.name: test SafeDump function with indent
 * @tc.desc: 1.SafeDump with indent parameter
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0004, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    jsonObject["name"] = "test";

    std::string result;
    int32_t indent = 4;
    bool ret = ExceptionUtil::GetInstance().SafeDump(jsonObject, result, indent);
    if (ret) {
        EXPECT_FALSE(result.empty());
        // With indent, result should contain newlines and spaces
        EXPECT_NE(result.find("\n"), std::string::npos);
    } else {
        EXPECT_TRUE(result.empty());
    }
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0005
 * @tc.name: test SafeDump function with nested json object
 * @tc.desc: 1.SafeDump with nested json object
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0005, Function | SmallTest | Level1)
{
    nlohmann::json innerObject;
    innerObject["innerKey"] = "innerValue";

    nlohmann::json jsonObject;
    jsonObject["outer"] = innerObject;
    jsonObject["array"] = nlohmann::json::array({1, 2, 3});

    std::string result;
    bool ret = ExceptionUtil::GetInstance().SafeDump(jsonObject, result);
    if (ret) {
        EXPECT_FALSE(result.empty());
        EXPECT_NE(result.find("outer"), std::string::npos);
        EXPECT_NE(result.find("innerKey"), std::string::npos);
        EXPECT_NE(result.find("innerValue"), std::string::npos);
    } else {
        EXPECT_TRUE(result.empty());
    }
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0006
 * @tc.name: test SafeDump function with json array
 * @tc.desc: 1.SafeDump with json array
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0006, Function | SmallTest | Level1)
{
    nlohmann::json jsonArray = nlohmann::json::array();
    jsonArray.push_back("item1");
    jsonArray.push_back("item2");
    jsonArray.push_back(123);

    std::string result;
    bool ret = ExceptionUtil::GetInstance().SafeDump(jsonArray, result);
    if (ret) {
        EXPECT_FALSE(result.empty());
        EXPECT_NE(result.find("item1"), std::string::npos);
        EXPECT_NE(result.find("item2"), std::string::npos);
    } else {
        EXPECT_TRUE(result.empty());
    }
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0007
 * @tc.name: test SafeDump function with null json
 * @tc.desc: 1.SafeDump with null json
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0007, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject = nullptr;

    std::string result;
    bool ret = ExceptionUtil::GetInstance().SafeDump(jsonObject, result);
    if (ret) {
        EXPECT_EQ(result, "null");
    } else {
        EXPECT_TRUE(result.empty());
    }
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0008
 * @tc.name: test SafeDump function with special characters
 * @tc.desc: 1.SafeDump with special characters in string
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0008, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    jsonObject["special"] = "Hello\nWorld\t\"Test\"";

    std::string result;
    bool ret = ExceptionUtil::GetInstance().SafeDump(jsonObject, result);
    if (ret) {
        EXPECT_FALSE(result.empty());
        // Special characters should be escaped
        EXPECT_NE(result.find("\\n"), std::string::npos);
        EXPECT_NE(result.find("\\t"), std::string::npos);
    } else {
        EXPECT_TRUE(result.empty());
    }
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0009
 * @tc.name: test SafeDump function with unicode characters
 * @tc.desc: 1.SafeDump with unicode characters
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0009, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    jsonObject["chinese"] = "中文测试";

    std::string result;
    bool ret = ExceptionUtil::GetInstance().SafeDump(jsonObject, result);
    if (ret) {
        EXPECT_FALSE(result.empty());
    } else {
        EXPECT_TRUE(result.empty());
    }
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0010
 * @tc.name: test SafeDump function with large json object
 * @tc.desc: 1.SafeDump with large json object
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0010, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    for (int32_t i = 0; i < 100; i++) {
        jsonObject["key" + std::to_string(i)] = "value" + std::to_string(i);
    }

    std::string result;
    bool ret = ExceptionUtil::GetInstance().SafeDump(jsonObject, result);
    if (ret) {
        EXPECT_FALSE(result.empty());
        EXPECT_NE(result.find("key0"), std::string::npos);
        EXPECT_NE(result.find("key99"), std::string::npos);
    } else {
        EXPECT_TRUE(result.empty());
    }
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0011
 * @tc.name: test SafeDump function with different indent values
 * @tc.desc: 1.SafeDump with indent = 0
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0011, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    jsonObject["key"] = "value";

    std::string result;
    bool ret = ExceptionUtil::GetInstance().SafeDump(jsonObject, result, 0);
    if (ret) {
        EXPECT_FALSE(result.empty());
    } else {
        EXPECT_TRUE(result.empty());
    }
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0012
 * @tc.name: test SafeDump function with indent = 2
 * @tc.desc: 1.SafeDump with indent = 2
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0012, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    jsonObject["key"] = "value";

    std::string result;
    bool ret = ExceptionUtil::GetInstance().SafeDump(jsonObject, result, 2);
    if (ret) {
        EXPECT_FALSE(result.empty());
        EXPECT_NE(result.find("\n"), std::string::npos);
    } else {
        EXPECT_TRUE(result.empty());
    }
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0013
 * @tc.name: test LoadLibraryNoLock function
 * @tc.desc: 1.LoadLibraryNoLock test
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0013, Function | SmallTest | Level1)
{
    ExceptionUtil& instance = ExceptionUtil::GetInstance();

    // Test LoadLibraryNoLock - may fail if SO not present
    bool ret = instance.LoadLibraryNoLock();
    if (ret) {
        EXPECT_NE(instance.handle_, nullptr);
        EXPECT_NE(instance.safeDumpFunc_, nullptr);
    } else {
        EXPECT_EQ(instance.handle_, nullptr);
    }
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0014
 * @tc.name: test UnloadLibrary function
 * @tc.desc: 1.UnloadLibrary test when handle is nullptr (early return branch)
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0014, Function | SmallTest | Level1)
{
    ExceptionUtil& instance = ExceptionUtil::GetInstance();

    // Save original state
    void* originalHandle = instance.handle_;
    auto originalFunc = instance.safeDumpFunc_;

    // Set handle to nullptr to test early return branch
    instance.handle_ = nullptr;
    // Keep safeDumpFunc_ as originalFunc (may be non-null if library was loaded)

    instance.UnloadLibrary();  // Should do nothing when handle_ is nullptr

    // Verify: handle_ should still be nullptr
    EXPECT_EQ(instance.handle_, nullptr);

    // Verify: safeDumpFunc_ should remain unchanged (not cleared)
    // because UnloadLibrary returns early when handle_ is nullptr
    EXPECT_EQ(instance.safeDumpFunc_, originalFunc);

    // Restore original state
    instance.handle_ = originalHandle;
    instance.safeDumpFunc_ = originalFunc;
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0015
 * @tc.name: test delayedTaskMgr initialization
 * @tc.desc: 1.delayedTaskMgr should be initialized
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0015, Function | SmallTest | Level1)
{
    ExceptionUtil& instance = ExceptionUtil::GetInstance();
    EXPECT_NE(instance.delayedTaskMgr_, nullptr);
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0016
 * @tc.name: test SafeDump function with numeric types
 * @tc.desc: 1.SafeDump with various numeric types
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0016, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    jsonObject["int"] = 42;
    jsonObject["double"] = 3.14159;
    jsonObject["negative"] = -100;
    jsonObject["zero"] = 0;

    std::string result;
    bool ret = ExceptionUtil::GetInstance().SafeDump(jsonObject, result);
    if (ret) {
        EXPECT_FALSE(result.empty());
        EXPECT_NE(result.find("42"), std::string::npos);
        EXPECT_NE(result.find("3.14159"), std::string::npos);
        EXPECT_NE(result.find("-100"), std::string::npos);
    } else {
        EXPECT_TRUE(result.empty());
    }
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0017
 * @tc.name: test SafeDump function with boolean values
 * @tc.desc: 1.SafeDump with boolean values
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0017, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    jsonObject["trueValue"] = true;
    jsonObject["falseValue"] = false;

    std::string result;
    bool ret = ExceptionUtil::GetInstance().SafeDump(jsonObject, result);
    if (ret) {
        EXPECT_FALSE(result.empty());
        EXPECT_NE(result.find("true"), std::string::npos);
        EXPECT_NE(result.find("false"), std::string::npos);
    } else {
        EXPECT_TRUE(result.empty());
    }
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0018
 * @tc.name: test SafeDump function with empty string value
 * @tc.desc: 1.SafeDump with empty string value
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0018, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    jsonObject["emptyString"] = "";

    std::string result;
    bool ret = ExceptionUtil::GetInstance().SafeDump(jsonObject, result);
    if (ret) {
        EXPECT_FALSE(result.empty());
        EXPECT_NE(result.find("\"\""), std::string::npos);
    } else {
        EXPECT_TRUE(result.empty());
    }
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0019
 * @tc.name: test SafeDump function with deeply nested json
 * @tc.desc: 1.SafeDump with deeply nested json object
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0019, Function | SmallTest | Level1)
{
    nlohmann::json level3;
    level3["level3Key"] = "level3Value";

    nlohmann::json level2;
    level2["level2Key"] = level3;

    nlohmann::json level1;
    level1["level1Key"] = level2;

    nlohmann::json jsonObject;
    jsonObject["root"] = level1;

    std::string result;
    bool ret = ExceptionUtil::GetInstance().SafeDump(jsonObject, result);
    if (ret) {
        EXPECT_FALSE(result.empty());
        EXPECT_NE(result.find("root"), std::string::npos);
        EXPECT_NE(result.find("level3Value"), std::string::npos);
    } else {
        EXPECT_TRUE(result.empty());
    }
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0020
 * @tc.name: test LoadLibraryNoLock when already loaded
 * @tc.desc: 1.LoadLibraryNoLock returns true when handle_ is not nullptr
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0020, Function | SmallTest | Level1)
{
    ExceptionUtil& instance = ExceptionUtil::GetInstance();

    // First load
    bool ret1 = instance.LoadLibraryNoLock();

    if (ret1) {
        // Second load should return true immediately (handle_ != nullptr branch)
        bool ret2 = instance.LoadLibraryNoLock();
        EXPECT_TRUE(ret2);
        EXPECT_NE(instance.handle_, nullptr);
    }
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0021
 * @tc.name: test LoadLibraryNoLock when dlopen fails
 * @tc.desc: 1.LoadLibraryNoLock returns false when dlopen fails
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0021, Function | SmallTest | Level1)
{
    ExceptionUtil& instance = ExceptionUtil::GetInstance();

    // Save original state
    void* originalHandle = instance.handle_;
    auto originalFunc = instance.safeDumpFunc_;

    // Reset state to simulate fresh load
    instance.handle_ = nullptr;
    instance.safeDumpFunc_ = nullptr;

    // Try to load - if SO doesn't exist, dlopen will fail
    bool ret = instance.LoadLibraryNoLock();

    if (ret) {
        // Load succeeded - verify state is valid
        EXPECT_NE(instance.handle_, nullptr);
        EXPECT_NE(instance.safeDumpFunc_, nullptr);

        // Must close the newly loaded handle to avoid memory leak
        if (instance.handle_ != originalHandle && instance.handle_ != nullptr) {
            dlclose(instance.handle_);
        }
    } else {
        // Load failed - verify state is clean
        EXPECT_EQ(instance.handle_, nullptr);
        EXPECT_EQ(instance.safeDumpFunc_, nullptr);
    }

    // Restore original state
    instance.handle_ = originalHandle;
    instance.safeDumpFunc_ = originalFunc;
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0022
 * @tc.name: test UnloadLibrary when handle is not nullptr
 * @tc.desc: 1.UnloadLibrary properly unloads when handle is valid
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0022, Function | SmallTest | Level1)
{
    ExceptionUtil& instance = ExceptionUtil::GetInstance();

    // Try to load first
    bool loaded = instance.LoadLibraryNoLock();

    if (loaded) {
        EXPECT_NE(instance.handle_, nullptr);
        EXPECT_NE(instance.safeDumpFunc_, nullptr);

        // Unload
        instance.UnloadLibrary();

        // Verify unload
        EXPECT_EQ(instance.handle_, nullptr);
        EXPECT_EQ(instance.safeDumpFunc_, nullptr);

        // Reload library to restore state for subsequent tests
        instance.LoadLibraryNoLock();
    }
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0023
 * @tc.name: test SafeDump when LoadLibraryNoLock fails
 * @tc.desc: 1.SafeDump returns false when library cannot be loaded
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0023, Function | SmallTest | Level1)
{
    ExceptionUtil& instance = ExceptionUtil::GetInstance();

    // Save original state
    void* originalHandle = instance.handle_;
    auto originalFunc = instance.safeDumpFunc_;

    // Reset state
    instance.handle_ = nullptr;
    instance.safeDumpFunc_ = nullptr;

    nlohmann::json jsonObject;
    jsonObject["key"] = "value";
    std::string result;

    // SafeDump will try to reload the library
    bool ret = instance.SafeDump(jsonObject, result);

    // Check for newly loaded handle to avoid memory leak
    void* newHandle = instance.handle_;

    // If reload succeeded, ret is true; if library not found, ret is false
    if (ret) {
        EXPECT_FALSE(result.empty());
        EXPECT_NE(newHandle, nullptr);
    } else {
        EXPECT_TRUE(result.empty());
    }

    // Clean up: close newly loaded handle if different from original
    if (newHandle != nullptr && newHandle != originalHandle) {
        dlclose(newHandle);
    }

    // Restore original state
    instance.handle_ = originalHandle;
    instance.safeDumpFunc_ = originalFunc;
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0024
 * @tc.name: test SafeDump when safeDumpFunc_ is nullptr
 * @tc.desc: 1.SafeDump returns false when safeDumpFunc_ is nullptr after LoadLibraryNoLock
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0024, Function | SmallTest | Level1)
{
    ExceptionUtil& instance = ExceptionUtil::GetInstance();

    // Ensure library is loaded first
    bool loaded = instance.LoadLibraryNoLock();
    if (!loaded) {
        // Library not available, skip this test with meaningful assertion
        EXPECT_EQ(instance.handle_, nullptr);
        return;
    }

    // Save original state
    void* originalHandle = instance.handle_;
    auto originalFunc = instance.safeDumpFunc_;

    // Simulate: handle loaded but function pointer is null
    EXPECT_NE(originalHandle, nullptr);
    instance.safeDumpFunc_ = nullptr;

    nlohmann::json jsonObject;
    jsonObject["key"] = "value";
    std::string result;

    // SafeDump should fail because safeDumpFunc_ is nullptr
    // LoadLibraryNoLock will return true (handle_ != nullptr) but won't reload safeDumpFunc_
    bool ret = instance.SafeDump(jsonObject, result);
    EXPECT_FALSE(ret);
    EXPECT_TRUE(result.empty());

    // Restore
    instance.safeDumpFunc_ = originalFunc;
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0025
 * @tc.name: test ScheduleUnload function
 * @tc.desc: 1.ScheduleUnload schedules the unload task
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0025, Function | SmallTest | Level1)
{
    ExceptionUtil& instance = ExceptionUtil::GetInstance();
    EXPECT_NE(instance.delayedTaskMgr_, nullptr);

    // ScheduleUnload should not crash
    instance.ScheduleUnload();
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0026
 * @tc.name: test ExceptionUtil constructor
 * @tc.desc: 1.Constructor initializes delayedTaskMgr_
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0026, Function | SmallTest | Level1)
{
    ExceptionUtil& instance = ExceptionUtil::GetInstance();

    // Verify constructor initialized the delayed task manager
    EXPECT_NE(instance.delayedTaskMgr_, nullptr);
    // Note: handle_ and safeDumpFunc_ may not be nullptr if library was loaded by previous tests
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0035
 * @tc.name: test SafeDump thread safety
 * @tc.desc: 1.SafeDump is thread-safe with multiple concurrent threads
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0035, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    jsonObject["key"] = "value";
    jsonObject["number"] = 42;

    std::atomic<int32_t> successCount{0};
    std::atomic<int32_t> failCount{0};
    std::atomic<int32_t> totalIterations{0};

    auto task = [&jsonObject, &successCount, &failCount, &totalIterations]() {
        for (int32_t i = 0; i < ITERATIONS_PER_THREAD; i++) {
            std::string result;
            bool ret = ExceptionUtil::GetInstance().SafeDump(jsonObject, result);
            if (ret) {
                successCount++;
            } else {
                failCount++;
            }
            totalIterations++;
        }
    };

    std::vector<std::thread> threads;
    threads.reserve(THREAD_COUNT);
    for (int32_t i = 0; i < THREAD_COUNT; i++) {
        threads.emplace_back(task);
    }

    for (auto& t : threads) {
        t.join();
    }

    EXPECT_EQ(totalIterations.load(), THREAD_COUNT * ITERATIONS_PER_THREAD);
    int32_t total = successCount.load() + failCount.load();
    EXPECT_EQ(total, THREAD_COUNT * ITERATIONS_PER_THREAD);
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0036
 * @tc.name: test SafeDump function in exception_wrapper.cpp directly
 * @tc.desc: 1.Direct call to SafeDump with empty json object (try branch - success)
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0036, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject = nlohmann::json::object();
    std::string result;

    bool ret = BundleMgrSafeDump(jsonObject, result, -1);

    EXPECT_TRUE(ret);
    EXPECT_EQ(result, "{}");
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0037
 * @tc.name: test SafeDump function in exception_wrapper.cpp with simple json
 * @tc.desc: 1.Direct call to SafeDump with simple json object (try branch - success)
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0037, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    jsonObject["key"] = "value";
    jsonObject["number"] = 42;

    std::string result;
    bool ret = BundleMgrSafeDump(jsonObject, result, -1);

    EXPECT_TRUE(ret);
    EXPECT_FALSE(result.empty());
    EXPECT_NE(result.find("key"), std::string::npos);
    EXPECT_NE(result.find("value"), std::string::npos);
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0038
 * @tc.name: test SafeDump function in exception_wrapper.cpp with indent
 * @tc.desc: 1.Direct call to SafeDump with indent parameter (try branch - success)
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0038, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    jsonObject["key"] = "value";

    std::string result;
    bool ret = BundleMgrSafeDump(jsonObject, result, 4);

    EXPECT_TRUE(ret);
    EXPECT_FALSE(result.empty());
    EXPECT_NE(result.find("\n"), std::string::npos);
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0039
 * @tc.name: test SafeDump function in exception_wrapper.cpp with null json
 * @tc.desc: 1.Direct call to SafeDump with null json (try branch - success)
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0039, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject = nullptr;
    std::string result;

    bool ret = BundleMgrSafeDump(jsonObject, result, -1);

    EXPECT_TRUE(ret);
    EXPECT_EQ(result, "null");
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0040
 * @tc.name: test SafeDump function in exception_wrapper.cpp with array
 * @tc.desc: 1.Direct call to SafeDump with json array (try branch - success)
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0040, Function | SmallTest | Level1)
{
    nlohmann::json jsonArray = nlohmann::json::array({1, 2, 3, "test"});
    std::string result;

    bool ret = BundleMgrSafeDump(jsonArray, result, -1);

    EXPECT_TRUE(ret);
    EXPECT_FALSE(result.empty());
    EXPECT_NE(result.find("test"), std::string::npos);
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0041
 * @tc.name: test SafeDump function in exception_wrapper.cpp with nested json
 * @tc.desc: 1.Direct call to SafeDump with nested json (try branch - success)
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0041, Function | SmallTest | Level1)
{
    nlohmann::json inner;
    inner["innerKey"] = "innerValue";

    nlohmann::json jsonObject;
    jsonObject["outer"] = inner;

    std::string result;
    bool ret = BundleMgrSafeDump(jsonObject, result, -1);

    EXPECT_TRUE(ret);
    EXPECT_FALSE(result.empty());
    EXPECT_NE(result.find("innerValue"), std::string::npos);
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0042
 * @tc.name: test SafeDump function in exception_wrapper.cpp with special chars
 * @tc.desc: 1.Direct call to SafeDump with special characters (try branch - success)
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0042, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    jsonObject["special"] = "line1\nline2\ttab\"quote";

    std::string result;
    bool ret = BundleMgrSafeDump(jsonObject, result, -1);

    EXPECT_TRUE(ret);
    EXPECT_FALSE(result.empty());
    // Characters should be escaped
    EXPECT_NE(result.find("\\n"), std::string::npos);
    EXPECT_NE(result.find("\\t"), std::string::npos);
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0043
 * @tc.name: test SafeDump function with indent 0
 * @tc.desc: 1.Direct call to SafeDump with indent = 0
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0043, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    jsonObject["key"] = "value";

    std::string result;
    bool ret = BundleMgrSafeDump(jsonObject, result, 0);

    EXPECT_TRUE(ret);
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0044
 * @tc.name: test SafeDump function with indent 2
 * @tc.desc: 1.Direct call to SafeDump with indent = 2
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0044, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    jsonObject["key"] = "value";

    std::string result;
    bool ret = BundleMgrSafeDump(jsonObject, result, 2);

    EXPECT_TRUE(ret);
    EXPECT_FALSE(result.empty());
    EXPECT_NE(result.find("\n"), std::string::npos);
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0045
 * @tc.name: test SafeDump function with boolean values
 * @tc.desc: 1.Direct call to SafeDump with boolean values
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0045, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    jsonObject["boolTrue"] = true;
    jsonObject["boolFalse"] = false;

    std::string result;
    bool ret = BundleMgrSafeDump(jsonObject, result, -1);

    EXPECT_TRUE(ret);
    EXPECT_NE(result.find("true"), std::string::npos);
    EXPECT_NE(result.find("false"), std::string::npos);
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0046
 * @tc.name: test SafeDump function with numeric values
 * @tc.desc: 1.Direct call to SafeDump with various numeric types
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0046, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    jsonObject["int"] = 123;
    jsonObject["negative"] = -456;
    jsonObject["float"] = 3.14;

    std::string result;
    bool ret = BundleMgrSafeDump(jsonObject, result, -1);

    EXPECT_TRUE(ret);
    EXPECT_NE(result.find("123"), std::string::npos);
    EXPECT_NE(result.find("-456"), std::string::npos);
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0047
 * @tc.name: test SafeDump function with empty string
 * @tc.desc: 1.Direct call to SafeDump with empty string value
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0047, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    jsonObject["empty"] = "";

    std::string result;
    bool ret = BundleMgrSafeDump(jsonObject, result, -1);

    EXPECT_TRUE(ret);
    EXPECT_NE(result.find("\"\""), std::string::npos);
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0048
 * @tc.name: test SafeDump function with unicode
 * @tc.desc: 1.Direct call to SafeDump with unicode characters
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0048, Function | SmallTest | Level1)
{
    nlohmann::json jsonObject;
    jsonObject["chinese"] = "中文";

    std::string result;
    bool ret = BundleMgrSafeDump(jsonObject, result, -1);

    EXPECT_TRUE(ret);
    EXPECT_FALSE(result.empty());
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0049
 * @tc.name: test SafeDump function with invalid UTF-8 string
 * @tc.desc: 1.Direct call to SafeDump with invalid UTF-8 (catch branch - exception)
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0049, Function | SmallTest | Level1)
{
    // Construct invalid UTF-8 string (GBK encoded string in UTF-8 context)
    std::string invalidUtf8 = "\xC4\xE3\xBA\xCA";

    nlohmann::json jsonObject;
    jsonObject["invalid"] = invalidUtf8;

    std::string result;
    bool ret = BundleMgrSafeDump(jsonObject, result, -1);

    // dump() with invalid UTF-8 may throw exception and return false
    // or succeed with replacement chars depending on json version
    if (ret) {
        EXPECT_FALSE(result.empty());
    } else {
        EXPECT_TRUE(result.empty());
    }
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0050
 * @tc.name: test SafeDump function with invalid UTF-8 bytes
 * @tc.desc: 1.Direct call to SafeDump with various invalid UTF-8 bytes
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0050, Function | SmallTest | Level1)
{
    // Invalid UTF-8: byte 0xFF is never valid in UTF-8
    std::string invalidUtf8;
    invalidUtf8 += static_cast<char>(0xFF);
    invalidUtf8 += static_cast<char>(0xFE);

    nlohmann::json jsonObject;
    jsonObject["invalid"] = invalidUtf8;

    std::string result;
    bool ret = BundleMgrSafeDump(jsonObject, result, -1);
    if (ret) {
        EXPECT_FALSE(result.empty());
    } else {
        EXPECT_TRUE(result.empty());
    }
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0051
 * @tc.name: test SafeDump function with truncated UTF-8 sequence
 * @tc.desc: 1.Direct call to SafeDump with truncated multi-byte UTF-8
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0051, Function | SmallTest | Level1)
{
    // Truncated UTF-8: 0xE4 starts a 3-byte sequence but only 1 byte provided
    std::string truncatedUtf8;
    truncatedUtf8 += static_cast<char>(0xE4);

    nlohmann::json jsonObject;
    jsonObject["truncated"] = truncatedUtf8;

    std::string result;
    bool ret = BundleMgrSafeDump(jsonObject, result, -1);
    if (ret) {
        EXPECT_FALSE(result.empty());
    } else {
        EXPECT_TRUE(result.empty());
    }
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0052
 * @tc.name: test SafeDump function with overlong UTF-8 encoding
 * @tc.desc: 1.Direct call to SafeDump with overlong UTF-8 encoding
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0052, Function | SmallTest | Level1)
{
    // Overlong encoding of ASCII 'A' (0x41) using 2 bytes instead of 1
    // Valid representation: 0x41
    // Overlong (invalid): 0xC1 0x81
    std::string overlongUtf8;
    overlongUtf8 += static_cast<char>(0xC1);
    overlongUtf8 += static_cast<char>(0x81);

    nlohmann::json jsonObject;
    jsonObject["overlong"] = overlongUtf8;

    std::string result;
    bool ret = BundleMgrSafeDump(jsonObject, result, -1);
    if (ret) {
        EXPECT_FALSE(result.empty());
    } else {
        EXPECT_TRUE(result.empty());
    }
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0053
 * @tc.name: test SafeDump function with surrogate pairs
 * @tc.desc: 1.Direct call to SafeDump with invalid surrogate pair encoding
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0053, Function | SmallTest | Level1)
{
    // Invalid surrogate code point encoded as UTF-8: 0xED 0xA0 0x80
    std::string surrogateUtf8;
    surrogateUtf8 += static_cast<char>(0xED);
    surrogateUtf8 += static_cast<char>(0xA0);
    surrogateUtf8 += static_cast<char>(0x80);

    nlohmann::json jsonObject;
    jsonObject["surrogate"] = surrogateUtf8;

    std::string result;
    bool ret = BundleMgrSafeDump(jsonObject, result, -1);
    if (ret) {
        EXPECT_FALSE(result.empty());
    } else {
        EXPECT_TRUE(result.empty());
    }
}

/**
 * @tc.number: BmsBundleExceptionUtilTest_0054
 * @tc.name: test SafeDump via ExceptionUtil with invalid UTF-8
 * @tc.desc: 1.SafeDump via ExceptionUtil with invalid UTF-8 string
 */
HWTEST_F(BmsBundleExceptionUtilTest, BmsBundleExceptionUtilTest_0054, Function | SmallTest | Level1)
{
    std::string invalidUtf8 = "\xC4\xE3\xBA\xCA";

    nlohmann::json jsonObject;
    jsonObject["invalid"] = invalidUtf8;

    std::string result;
    bool ret = ExceptionUtil::GetInstance().SafeDump(jsonObject, result);

    // Result depends on library availability and UTF-8 handling
    if (ret) {
        // Dump succeeded (library loaded and handled invalid UTF-8)
        EXPECT_FALSE(result.empty());
    } else {
        // Dump failed (library not loaded or exception thrown)
        EXPECT_TRUE(result.empty());
    }
}
} // OHOS
