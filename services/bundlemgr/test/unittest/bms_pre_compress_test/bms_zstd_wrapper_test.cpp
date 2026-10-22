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

#include <chrono>
#include <dlfcn.h>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "app_log_tag_wrapper.h"
#include "mock_pre_compress_hooks.h"
#include "mock_zstd.h"
#define private public
#include "single_delayed_task_mgr.h"
#include "zstd_wrapper.h"
#undef private

// compile zstd_wrapper.cpp here with its dynamic loading routed to the hooks, so the cases decide how libzstd
// loads and which of its symbols resolve; the target removes zstd_wrapper.cpp from its own sources
#define dlopen(file, mode) OHOS::AppExecFwk::PreCompressHook::HookDlopen(file, mode)
#define dlsym(handle, symbolName) OHOS::AppExecFwk::PreCompressHook::HookDlsym(handle, symbolName)
#define dlclose(handle) OHOS::AppExecFwk::PreCompressHook::HookDlclose(handle)
#define dlerror() OHOS::AppExecFwk::PreCompressHook::HookDlerror()
#include "zstd_wrapper.cpp"
#undef dlerror
#undef dlclose
#undef dlsym
#undef dlopen

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr const char* TEST_UNLOAD_TASK_NAME = "BmsZstdWrapperTestUnloadTask";
// the unload task of the suite never fires while the cases run
constexpr uint64_t TEST_LONG_UNLOAD_DELAY_MS = 24 * 60 * 60 * 1000;
constexpr uint64_t TEST_SHORT_UNLOAD_DELAY_MS = 10;
constexpr int32_t WAIT_ROUNDS = 300;
constexpr int32_t WAIT_INTERVAL_MS = 10;
constexpr int32_t NO_UNLOAD_WAIT_MS = 100;
constexpr size_t TEST_CONTENT_SIZE = 100;
constexpr uint8_t TEST_CONTENT_SEED = 9;
constexpr size_t TEST_IN_SIZE = 32;
constexpr size_t TEST_OUT_SIZE = 64;

std::shared_ptr<SingleDelayedTaskMgr> g_originalUnloadTaskMgr = nullptr;
std::shared_ptr<SingleDelayedTaskMgr> g_suiteUnloadTaskMgr = nullptr;

bool WaitUntil(const std::function<bool()> &condition)
{
    for (int32_t i = 0; i < WAIT_ROUNDS; i++) {
        if (condition()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_INTERVAL_MS));
    }
    return condition();
}

bool IsLoaded()
{
    ZstdWrapper &zstd = ZstdWrapper::GetInstance();
    std::lock_guard<std::mutex> lock(zstd.mutex_);
    return zstd.handle_ != nullptr;
}

void ResetZstdWrapper()
{
    ZstdWrapper &zstd = ZstdWrapper::GetInstance();
    std::lock_guard<std::mutex> lock(zstd.mutex_);
    zstd.handle_ = nullptr;
    zstd.refCount_ = 0;
    zstd.api_ = ZstdWrapper::ZstdApi();
}

// the resolved entries in resolving order, nullptr for an entry not resolved
std::vector<void *> GetApiEntries(const ZstdWrapper::ZstdApi &api)
{
    return {
        reinterpret_cast<void *>(api.createDStream),
        reinterpret_cast<void *>(api.freeDStream),
        reinterpret_cast<void *>(api.decompressStream),
        reinterpret_cast<void *>(api.dStreamInSize),
        reinterpret_cast<void *>(api.dStreamOutSize),
        reinterpret_cast<void *>(api.getFrameContentSize),
        reinterpret_cast<void *>(api.isError),
        reinterpret_cast<void *>(api.getErrorName),
    };
}

void ExpectApiResolved(const ZstdWrapper::ZstdApi &api)
{
    std::vector<void *> entries = GetApiEntries(api);
    const std::vector<std::string> &symbolNames = MockZstd::GetSymbolNames();
    ASSERT_EQ(entries.size(), symbolNames.size());
    for (size_t i = 0; i < entries.size(); ++i) {
        EXPECT_EQ(entries[i], MockZstd::GetSymbol(symbolNames[i])) << symbolNames[i];
    }
}

void ExpectApiEmpty(const ZstdWrapper::ZstdApi &api)
{
    for (void *entry : GetApiEntries(api)) {
        EXPECT_EQ(entry, nullptr);
    }
}
}  // namespace

class BmsZstdWrapperTest : public testing::Test {
public:
    BmsZstdWrapperTest();
    ~BmsZstdWrapperTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

BmsZstdWrapperTest::BmsZstdWrapperTest()
{}

BmsZstdWrapperTest::~BmsZstdWrapperTest()
{}

void BmsZstdWrapperTest::SetUpTestCase()
{
    ZstdWrapper &zstd = ZstdWrapper::GetInstance();
    g_originalUnloadTaskMgr = zstd.unloadTaskMgr_;
    g_suiteUnloadTaskMgr = std::make_shared<SingleDelayedTaskMgr>(TEST_UNLOAD_TASK_NAME, TEST_LONG_UNLOAD_DELAY_MS);
}

void BmsZstdWrapperTest::TearDownTestCase()
{
    ZstdWrapper::GetInstance().unloadTaskMgr_ = g_originalUnloadTaskMgr;
    g_suiteUnloadTaskMgr = nullptr;
}

void BmsZstdWrapperTest::SetUp()
{
    PreCompressHook::ResetDlHooks();
    MockZstd::SetStreamSizes(MockZstd::MOCK_DEFAULT_IN_SIZE, MockZstd::MOCK_DEFAULT_OUT_SIZE);
    ZstdWrapper::GetInstance().unloadTaskMgr_ = g_suiteUnloadTaskMgr;
    ResetZstdWrapper();
}

void BmsZstdWrapperTest::TearDown()
{
    ResetZstdWrapper();
    ZstdWrapper::GetInstance().unloadTaskMgr_ = g_suiteUnloadTaskMgr;
    MockZstd::SetStreamSizes(MockZstd::MOCK_DEFAULT_IN_SIZE, MockZstd::MOCK_DEFAULT_OUT_SIZE);
    PreCompressHook::ResetDlHooks();
}

/**
 * @tc.number: ZstdWrapper_GetInstance_0100
 * @tc.name: test GetInstance
 * @tc.desc: 1. GetInstance always returns the same wrapper
 */
HWTEST_F(BmsZstdWrapperTest, ZstdWrapper_GetInstance_0100, Function | SmallTest | Level0)
{
    ZstdWrapper &first = ZstdWrapper::GetInstance();
    ZstdWrapper &second = ZstdWrapper::GetInstance();
    EXPECT_EQ(&first, &second);
    EXPECT_NE(first.unloadTaskMgr_, nullptr);
}

/**
 * @tc.number: ZstdWrapper_ResolveSymbol_0100
 * @tc.name: test ResolveSymbol
 * @tc.desc: 1. the found symbol is stored into the function pointer
 *           2. a missing symbol returns false and leaves the function pointer untouched
 */
HWTEST_F(BmsZstdWrapperTest, ZstdWrapper_ResolveSymbol_0100, Function | SmallTest | Level0)
{
    PreCompressHook::SetDlopenMode(PreCompressHook::DlopenMode::MOCK_LIB);
    void *handle = PreCompressHook::HookDlopen(LIB_ZSTD_SO_NAME, RTLD_NOW | RTLD_LOCAL);
    ASSERT_NE(handle, nullptr);

    ZstdIsErrorFunc isError = nullptr;
    EXPECT_TRUE(ResolveSymbol(handle, ZSTD_IS_ERROR_FUNC, isError));
    EXPECT_EQ(reinterpret_cast<void *>(isError), MockZstd::GetSymbol(ZSTD_IS_ERROR_FUNC));

    PreCompressHook::SetMissingSymbol(ZSTD_GET_ERROR_NAME_FUNC);
    ZstdGetErrorNameFunc getErrorName = nullptr;
    EXPECT_FALSE(ResolveSymbol(handle, ZSTD_GET_ERROR_NAME_FUNC, getErrorName));
    EXPECT_TRUE(getErrorName == nullptr);
}

/**
 * @tc.number: ZstdWrapper_ResolveApi_0100
 * @tc.name: test ResolveApi
 * @tc.desc: 1. every libzstd entry is resolved when the library exports all of them
 */
HWTEST_F(BmsZstdWrapperTest, ZstdWrapper_ResolveApi_0100, Function | SmallTest | Level0)
{
    PreCompressHook::SetDlopenMode(PreCompressHook::DlopenMode::MOCK_LIB);
    void *handle = PreCompressHook::HookDlopen(LIB_ZSTD_SO_NAME, RTLD_NOW | RTLD_LOCAL);
    ASSERT_NE(handle, nullptr);

    ZstdWrapper::ZstdApi api;
    EXPECT_TRUE(ZstdWrapper::ResolveApi(handle, api));
    ExpectApiResolved(api);
}

/**
 * @tc.number: ZstdWrapper_ResolveApi_0200
 * @tc.name: test ResolveApi
 * @tc.desc: 1. ResolveApi fails as soon as one libzstd entry is missing, whichever it is
 *           2. the entries before the missing one are resolved and the rest are not touched
 */
HWTEST_F(BmsZstdWrapperTest, ZstdWrapper_ResolveApi_0200, Function | SmallTest | Level0)
{
    PreCompressHook::SetDlopenMode(PreCompressHook::DlopenMode::MOCK_LIB);
    void *handle = PreCompressHook::HookDlopen(LIB_ZSTD_SO_NAME, RTLD_NOW | RTLD_LOCAL);
    ASSERT_NE(handle, nullptr);

    const std::vector<std::string> &symbolNames = MockZstd::GetSymbolNames();
    for (size_t missing = 0; missing < symbolNames.size(); ++missing) {
        PreCompressHook::SetMissingSymbol(symbolNames[missing]);
        ZstdWrapper::ZstdApi api;
        EXPECT_FALSE(ZstdWrapper::ResolveApi(handle, api)) << symbolNames[missing];
        std::vector<void *> entries = GetApiEntries(api);
        ASSERT_EQ(entries.size(), symbolNames.size());
        for (size_t i = 0; i < entries.size(); ++i) {
            void *expected = (i < missing) ? MockZstd::GetSymbol(symbolNames[i]) : nullptr;
            EXPECT_EQ(entries[i], expected) << "missing " << symbolNames[missing] << " entry " << symbolNames[i];
        }
    }
}

/**
 * @tc.number: ZstdWrapper_LoadNoLock_0100
 * @tc.name: test LoadNoLock
 * @tc.desc: 1. a loaded library is reused without opening it again
 */
HWTEST_F(BmsZstdWrapperTest, ZstdWrapper_LoadNoLock_0100, Function | SmallTest | Level0)
{
    PreCompressHook::SetDlopenMode(PreCompressHook::DlopenMode::MOCK_LIB);
    ZstdWrapper &zstd = ZstdWrapper::GetInstance();
    EXPECT_TRUE(zstd.LoadNoLock());
    void *handle = zstd.handle_;
    EXPECT_EQ(PreCompressHook::GetDlopenCount(), 1);

    EXPECT_TRUE(zstd.LoadNoLock());
    EXPECT_EQ(zstd.handle_, handle);
    EXPECT_EQ(PreCompressHook::GetDlopenCount(), 1);
}

/**
 * @tc.number: ZstdWrapper_LoadNoLock_0200
 * @tc.name: test LoadNoLock
 * @tc.desc: 1. LoadNoLock fails and keeps the wrapper unloaded when libzstd can not be opened
 */
HWTEST_F(BmsZstdWrapperTest, ZstdWrapper_LoadNoLock_0200, Function | SmallTest | Level0)
{
    PreCompressHook::SetDlopenMode(PreCompressHook::DlopenMode::FAIL);
    ZstdWrapper &zstd = ZstdWrapper::GetInstance();
    EXPECT_FALSE(zstd.LoadNoLock());
    EXPECT_EQ(zstd.handle_, nullptr);
    ExpectApiEmpty(zstd.api_);
    EXPECT_EQ(PreCompressHook::GetDlopenCount(), 1);
    EXPECT_EQ(PreCompressHook::GetDlcloseCount(), 0);
}

/**
 * @tc.number: ZstdWrapper_LoadNoLock_0300
 * @tc.name: test LoadNoLock
 * @tc.desc: 1. a library missing a libzstd entry is closed again and not used at all
 */
HWTEST_F(BmsZstdWrapperTest, ZstdWrapper_LoadNoLock_0300, Function | SmallTest | Level0)
{
    PreCompressHook::SetDlopenMode(PreCompressHook::DlopenMode::MOCK_LIB);
    PreCompressHook::SetMissingSymbol(ZSTD_DECOMPRESS_STREAM_FUNC);
    ZstdWrapper &zstd = ZstdWrapper::GetInstance();
    EXPECT_FALSE(zstd.LoadNoLock());
    EXPECT_EQ(zstd.handle_, nullptr);
    ExpectApiEmpty(zstd.api_);
    EXPECT_EQ(PreCompressHook::GetDlcloseCount(), 1);
}

/**
 * @tc.number: ZstdWrapper_LoadNoLock_0400
 * @tc.name: test LoadNoLock
 * @tc.desc: 1. a complete library is kept open with every entry resolved
 */
HWTEST_F(BmsZstdWrapperTest, ZstdWrapper_LoadNoLock_0400, Function | SmallTest | Level0)
{
    PreCompressHook::SetDlopenMode(PreCompressHook::DlopenMode::MOCK_LIB);
    ZstdWrapper &zstd = ZstdWrapper::GetInstance();
    EXPECT_TRUE(zstd.LoadNoLock());
    EXPECT_NE(zstd.handle_, nullptr);
    ExpectApiResolved(zstd.api_);
    EXPECT_EQ(PreCompressHook::GetDlcloseCount(), 0);
}

/**
 * @tc.number: ZstdWrapper_Acquire_0100
 * @tc.name: test Acquire
 * @tc.desc: 1. no lease is handed out and no reference is taken when libzstd can not be loaded
 */
HWTEST_F(BmsZstdWrapperTest, ZstdWrapper_Acquire_0100, Function | SmallTest | Level0)
{
    PreCompressHook::SetDlopenMode(PreCompressHook::DlopenMode::FAIL);
    ZstdWrapper &zstd = ZstdWrapper::GetInstance();
    auto lease = zstd.Acquire();
    EXPECT_EQ(lease, nullptr);
    EXPECT_EQ(zstd.refCount_, 0U);
    EXPECT_FALSE(IsLoaded());
}

/**
 * @tc.number: ZstdWrapper_Acquire_0200
 * @tc.name: test Acquire
 * @tc.desc: 1. every lease takes one reference and all leases share one loaded library
 *           2. releasing a lease drops its reference
 */
HWTEST_F(BmsZstdWrapperTest, ZstdWrapper_Acquire_0200, Function | SmallTest | Level0)
{
    PreCompressHook::SetDlopenMode(PreCompressHook::DlopenMode::MOCK_LIB);
    ZstdWrapper &zstd = ZstdWrapper::GetInstance();
    auto first = zstd.Acquire();
    ASSERT_NE(first, nullptr);
    EXPECT_EQ(first.get(), &zstd);
    EXPECT_EQ(zstd.refCount_, 1U);
    {
        auto second = zstd.Acquire();
        ASSERT_NE(second, nullptr);
        EXPECT_EQ(zstd.refCount_, 2U);
        EXPECT_EQ(PreCompressHook::GetDlopenCount(), 1);
    }
    EXPECT_EQ(zstd.refCount_, 1U);
    first.reset();
    EXPECT_EQ(zstd.refCount_, 0U);
}

/**
 * @tc.number: ZstdWrapper_Release_0100
 * @tc.name: test Release
 * @tc.desc: 1. releasing the last lease unloads libzstd after the delay
 *           2. the next lease loads libzstd again
 */
HWTEST_F(BmsZstdWrapperTest, ZstdWrapper_Release_0100, Function | SmallTest | Level0)
{
    PreCompressHook::SetDlopenMode(PreCompressHook::DlopenMode::MOCK_LIB);
    ZstdWrapper &zstd = ZstdWrapper::GetInstance();
    zstd.unloadTaskMgr_ = std::make_shared<SingleDelayedTaskMgr>(TEST_UNLOAD_TASK_NAME, TEST_SHORT_UNLOAD_DELAY_MS);
    {
        auto lease = zstd.Acquire();
        ASSERT_NE(lease, nullptr);
    }
    EXPECT_TRUE(WaitUntil([] { return !IsLoaded(); }));
    EXPECT_EQ(PreCompressHook::GetDlcloseCount(), 1);
    {
        std::lock_guard<std::mutex> lock(zstd.mutex_);
        ExpectApiEmpty(zstd.api_);
    }

    // a new task manager keeps the second unload independent from the task that just finished
    zstd.unloadTaskMgr_ = std::make_shared<SingleDelayedTaskMgr>(TEST_UNLOAD_TASK_NAME, TEST_SHORT_UNLOAD_DELAY_MS);
    {
        auto lease = zstd.Acquire();
        ASSERT_NE(lease, nullptr);
        EXPECT_EQ(PreCompressHook::GetDlopenCount(), 2);
    }
    EXPECT_TRUE(WaitUntil([] { return !IsLoaded(); }));
    EXPECT_EQ(PreCompressHook::GetDlcloseCount(), 2);
}

/**
 * @tc.number: ZstdWrapper_Release_0200
 * @tc.name: test Release
 * @tc.desc: 1. libzstd stays loaded while a lease is still held
 */
HWTEST_F(BmsZstdWrapperTest, ZstdWrapper_Release_0200, Function | SmallTest | Level0)
{
    PreCompressHook::SetDlopenMode(PreCompressHook::DlopenMode::MOCK_LIB);
    ZstdWrapper &zstd = ZstdWrapper::GetInstance();
    zstd.unloadTaskMgr_ = std::make_shared<SingleDelayedTaskMgr>(TEST_UNLOAD_TASK_NAME, TEST_SHORT_UNLOAD_DELAY_MS);
    auto first = zstd.Acquire();
    ASSERT_NE(first, nullptr);
    auto second = zstd.Acquire();
    ASSERT_NE(second, nullptr);

    second.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(NO_UNLOAD_WAIT_MS));
    EXPECT_TRUE(IsLoaded());
    EXPECT_EQ(PreCompressHook::GetDlcloseCount(), 0);

    first.reset();
    EXPECT_TRUE(WaitUntil([] { return !IsLoaded(); }));
    EXPECT_EQ(PreCompressHook::GetDlcloseCount(), 1);
}

/**
 * @tc.number: ZstdWrapper_Unload_0100
 * @tc.name: test Unload
 * @tc.desc: 1. Unload keeps libzstd loaded while it is referenced
 */
HWTEST_F(BmsZstdWrapperTest, ZstdWrapper_Unload_0100, Function | SmallTest | Level0)
{
    PreCompressHook::SetDlopenMode(PreCompressHook::DlopenMode::MOCK_LIB);
    ZstdWrapper &zstd = ZstdWrapper::GetInstance();
    auto lease = zstd.Acquire();
    ASSERT_NE(lease, nullptr);

    zstd.Unload();
    EXPECT_TRUE(IsLoaded());
    ExpectApiResolved(zstd.api_);
    EXPECT_EQ(PreCompressHook::GetDlcloseCount(), 0);
}

/**
 * @tc.number: ZstdWrapper_Unload_0200
 * @tc.name: test Unload
 * @tc.desc: 1. Unload does nothing when libzstd is not loaded
 */
HWTEST_F(BmsZstdWrapperTest, ZstdWrapper_Unload_0200, Function | SmallTest | Level0)
{
    ZstdWrapper &zstd = ZstdWrapper::GetInstance();
    zstd.Unload();
    EXPECT_FALSE(IsLoaded());
    EXPECT_EQ(PreCompressHook::GetDlcloseCount(), 0);
}

/**
 * @tc.number: ZstdWrapper_Unload_0300
 * @tc.name: test Unload
 * @tc.desc: 1. Unload closes the unreferenced libzstd and clears every entry
 */
HWTEST_F(BmsZstdWrapperTest, ZstdWrapper_Unload_0300, Function | SmallTest | Level0)
{
    PreCompressHook::SetDlopenMode(PreCompressHook::DlopenMode::MOCK_LIB);
    ZstdWrapper &zstd = ZstdWrapper::GetInstance();
    {
        std::lock_guard<std::mutex> lock(zstd.mutex_);
        ASSERT_TRUE(zstd.LoadNoLock());
    }
    EXPECT_EQ(zstd.refCount_, 0U);

    zstd.Unload();
    EXPECT_FALSE(IsLoaded());
    ExpectApiEmpty(zstd.api_);
    EXPECT_EQ(PreCompressHook::GetDlcloseCount(), 1);
}

/**
 * @tc.number: ZstdWrapper_CreateDStream_0100
 * @tc.name: test CreateDStream and FreeDStreamDeleter
 * @tc.desc: 1. CreateDStream returns the stream of libzstd
 *           2. the stream is freed by libzstd when it goes out of scope
 */
HWTEST_F(BmsZstdWrapperTest, ZstdWrapper_CreateDStream_0100, Function | SmallTest | Level0)
{
    PreCompressHook::SetDlopenMode(PreCompressHook::DlopenMode::MOCK_LIB);
    ZstdWrapper &zstd = ZstdWrapper::GetInstance();
    auto lease = zstd.Acquire();
    ASSERT_NE(lease, nullptr);

    int32_t liveStreams = MockZstd::GetLiveStreamCount();
    {
        auto zds = zstd.CreateDStream();
        ASSERT_NE(zds, nullptr);
        EXPECT_EQ(MockZstd::GetLiveStreamCount(), liveStreams + 1);
    }
    EXPECT_EQ(MockZstd::GetLiveStreamCount(), liveStreams);
}

/**
 * @tc.number: ZstdWrapper_DecompressStream_0100
 * @tc.name: test the libzstd entries forwarded by ZstdWrapper
 * @tc.desc: 1. DStreamInSize, DStreamOutSize and GetFrameContentSize return the values of libzstd
 *           2. DecompressStream decodes a frame through libzstd
 *           3. IsError and GetErrorName tell an error code from a result
 */
HWTEST_F(BmsZstdWrapperTest, ZstdWrapper_DecompressStream_0100, Function | SmallTest | Level0)
{
    PreCompressHook::SetDlopenMode(PreCompressHook::DlopenMode::MOCK_LIB);
    MockZstd::SetStreamSizes(TEST_IN_SIZE, TEST_OUT_SIZE);
    ZstdWrapper &zstd = ZstdWrapper::GetInstance();
    auto lease = zstd.Acquire();
    ASSERT_NE(lease, nullptr);
    EXPECT_EQ(zstd.DStreamInSize(), TEST_IN_SIZE);
    EXPECT_EQ(zstd.DStreamOutSize(), TEST_OUT_SIZE);

    std::vector<uint8_t> content = MockZstd::MakeContent(TEST_CONTENT_SIZE, TEST_CONTENT_SEED);
    std::vector<uint8_t> frame = MockZstd::BuildRawFrame(content, true);
    EXPECT_EQ(zstd.GetFrameContentSize(frame.data(), frame.size()), TEST_CONTENT_SIZE);

    auto zds = zstd.CreateDStream();
    ASSERT_NE(zds, nullptr);
    std::vector<uint8_t> decoded(TEST_CONTENT_SIZE);
    ZstdInBuffer input { frame.data(), frame.size(), 0 };
    ZstdOutBuffer output { decoded.data(), decoded.size(), 0 };
    size_t ret = zstd.DecompressStream(zds.get(), &output, &input);
    EXPECT_EQ(ret, 0U);
    EXPECT_FALSE(zstd.IsError(ret));
    EXPECT_EQ(input.pos, frame.size());
    EXPECT_EQ(output.pos, TEST_CONTENT_SIZE);
    EXPECT_EQ(decoded, content);
    EXPECT_STREQ(zstd.GetErrorName(ret), MockZstd::GetErrorName(ret));

    EXPECT_TRUE(zstd.IsError(MockZstd::MOCK_ERROR_CORRUPTION));
    EXPECT_STREQ(zstd.GetErrorName(MockZstd::MOCK_ERROR_CORRUPTION),
        MockZstd::GetErrorName(MockZstd::MOCK_ERROR_CORRUPTION));
    EXPECT_STRNE(zstd.GetErrorName(MockZstd::MOCK_ERROR_CORRUPTION), zstd.GetErrorName(ret));
}
}  // namespace OHOS
