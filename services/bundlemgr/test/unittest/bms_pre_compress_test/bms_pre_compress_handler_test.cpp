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

#include <algorithm>
#include <cerrno>
#include <cinttypes>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>
#include <utility>
#include <vector>

#include "app_log_tag_wrapper.h"
#include "directory_ex.h"
#include "iremote_proxy.h"
#include "mock_pre_compress_hooks.h"
#include "mock_zstd.h"
#define private public
#include "bundle_constants.h"
#include "bundle_service_constants.h"
#include "bundle_util.h"
#include "inner_bundle_info.h"
#include "installd_client.h"
#include "pre_compress_handler.h"
#include "scope_guard.h"
#include "single_delayed_task_mgr.h"
#include "zstd_wrapper.h"
#undef private

// compile pre_compress_handler.cpp here: the preload image dir /preload/app/ is served from a test dir and
// failures are injected through the hooks; the target removes pre_compress_handler.cpp from its own sources
#ifdef open
#undef open
#endif
#define open(...) OHOS::AppExecFwk::PreCompressHook::HookOpen(__VA_ARGS__)
#define opendir(path) OHOS::AppExecFwk::PreCompressHook::HookOpendir(path)
#define mkdtemp(pathTemplate) OHOS::AppExecFwk::PreCompressHook::HookMkdtemp(pathTemplate)
#define PathToRealPath(path, realPath) OHOS::AppExecFwk::PreCompressHook::HookPathToRealPath(path, realPath)
// a name in its own replacement is not expanded again, so this only maps the argument
#define IsExistDirNoLog(path) IsExistDirNoLog(OHOS::AppExecFwk::PreCompressHook::MapPreloadPath(path))
#include "pre_compress_handler.cpp"
#undef IsExistDirNoLog
#undef PathToRealPath
#undef mkdtemp
#undef opendir
#undef open

using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
const std::string TEST_ROOT_DIR = "/data/test/bms_pre_compress_handler_test";
const std::string TEST_PRELOAD_ROOT = TEST_ROOT_DIR + "/root";
const std::string VIRTUAL_BUNDLE_DIR = "/preload/app/com.example.precompress";
const std::string ENTRY_ARCHIVE_NAME = "entry.hap.zst";
const std::string FEATURE_ARCHIVE_NAME = "feature.hsp.zst";
const std::string ENTRY_HAP_NAME = "entry.hap";
const std::string FEATURE_HSP_NAME = "feature.hsp";
const std::string AG_CONFIG_CONTENT = "{\"agConfig\":\"test\"}";
const std::string SECURITY_DIR = std::string(ServiceConstants::HAP_COPY_PATH) +
    ServiceConstants::PATH_SEPARATOR + ServiceConstants::SECURITY_STREAM_INSTALL_PATH;
const std::string TEMP_DIR_KEYWORD = "/pre_compress_";
const std::string ENTRY_BUNDLE_NAME = "com.example.precompress.entry";
const std::string PLAIN_BUNDLE_NAME = "com.example.precompress.plain";
constexpr const char* TEST_UNLOAD_TASK_NAME = "BmsPreCompressHandlerTestUnloadTask";
// the unload task of the suite never fires while the cases run
constexpr uint64_t TEST_LONG_UNLOAD_DELAY_MS = 24 * 60 * 60 * 1000;
constexpr mode_t TEST_FILE_MODE = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;
constexpr size_t ENTRY_CONTENT_SIZE = 1000;
constexpr size_t FEATURE_CONTENT_SIZE = 300;
constexpr size_t SMALL_CONTENT_SIZE = 100;
constexpr size_t SMALL_BLOCK_SIZE = 64;
constexpr size_t TRUNCATED_BYTES = 5;
constexpr size_t SIZE_CAP_BELOW_CONTENT = 50;
constexpr uint8_t ENTRY_SEED = 1;
constexpr uint8_t FEATURE_SEED = 2;
constexpr uint8_t SMALL_SEED = 3;

std::shared_ptr<SingleDelayedTaskMgr> g_originalUnloadTaskMgr = nullptr;
std::shared_ptr<SingleDelayedTaskMgr> g_suiteUnloadTaskMgr = nullptr;

class PreCompressInstalldProxy : public IRemoteProxy<IInstalld> {
public:
    PreCompressInstalldProxy() : IRemoteProxy<IInstalld>(nullptr) {}

    ErrCode Mkdir(const std::string &dir, const int32_t mode, const int32_t uid, const int32_t gid,
        const CreateDirParam &createDirParam) override
    {
        mkdirDirs.emplace_back(dir);
        mkdirScenes.emplace_back(createDirParam.bundleDirScene);
        if (mkdirResult != ERR_OK) {
            return mkdirResult;
        }
        // create the dir the way installd does
        if (!BundleUtil::IsExistDirNoLog(dir) &&
            ((mkdir(dir.c_str(), static_cast<mode_t>(mode)) != 0) || (chown(dir.c_str(), uid, gid) != 0))) {
            return ERR_APPEXECFWK_INSTALLD_MKDIR_FAILED;
        }
        return ERR_OK;
    }

    std::vector<std::string> mkdirDirs;
    std::vector<BundleDirScene> mkdirScenes;
    ErrCode mkdirResult = ERR_OK;
};

bool WriteBytes(const std::string &path, const std::vector<uint8_t> &data)
{
    if (!OHOS::ForceCreateDirectory(path.substr(0, path.rfind(ServiceConstants::FILE_SEPARATOR_CHAR)))) {
        return false;
    }
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file.is_open()) {
        return false;
    }
    file.write(reinterpret_cast<const char *>(data.data()), static_cast<std::streamsize>(data.size()));
    return file.good();
}

bool WriteText(const std::string &path, const std::string &text)
{
    return WriteBytes(path, std::vector<uint8_t>(text.begin(), text.end()));
}

std::vector<uint8_t> ReadBytes(const std::string &path)
{
    std::ifstream file(path, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

std::string VirtualArchive(const std::string &name)
{
    return VIRTUAL_BUNDLE_DIR + ServiceConstants::PATH_SEPARATOR + name;
}

std::string RealPathOf(const std::string &path)
{
    std::string realPath;
    return OHOS::PathToRealPath(path, realPath) ? realPath : "";
}

void ResetZstdWrapper()
{
    ZstdWrapper &zstd = ZstdWrapper::GetInstance();
    std::lock_guard<std::mutex> lock(zstd.mutex_);
    zstd.handle_ = nullptr;
    zstd.refCount_ = 0;
    zstd.api_ = ZstdWrapper::ZstdApi();
}

DecompressContext MakeContext(int64_t sizeCap)
{
    ZstdWrapper &zstd = ZstdWrapper::GetInstance();
    DecompressContext ctx;
    ctx.realSrcPath = VirtualArchive(ENTRY_ARCHIVE_NAME);
    ctx.sizeCap = sizeCap;
    ctx.inBuf.resize(zstd.DStreamInSize());
    ctx.outBuf.resize(zstd.DStreamOutSize());
    return ctx;
}

void SetInput(DecompressContext &ctx, const std::vector<uint8_t> &data)
{
    ctx.inBuf.assign(data.begin(), data.end());
    ctx.inLen = static_cast<ssize_t>(data.size());
}

class FdGuard final {
public:
    explicit FdGuard(int32_t fd) : fd_(fd) {}
    ~FdGuard()
    {
        if (fd_ >= 0) {
            close(fd_);
        }
    }
    int32_t Get() const
    {
        return fd_;
    }

private:
    int32_t fd_ = -1;
};
}  // namespace

class BmsPreCompressHandlerTest : public testing::Test {
public:
    BmsPreCompressHandlerTest();
    ~BmsPreCompressHandlerTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
    std::string RealArchive(const std::string &name) const;
    bool PrepareArchive(const std::string &name, const std::vector<uint8_t> &content, bool withContentSize) const;
    bool PrepareSecurityDir() const;

    std::string preloadRoot_;
    bool securityDirExisted_ = false;
    sptr<IInstalld> originalInstalldProxy_ = nullptr;
    sptr<PreCompressInstalldProxy> installdProxy_ = nullptr;
    std::vector<uint8_t> entryContent_;
    std::vector<uint8_t> featureContent_;
};

BmsPreCompressHandlerTest::BmsPreCompressHandlerTest()
{}

BmsPreCompressHandlerTest::~BmsPreCompressHandlerTest()
{}

void BmsPreCompressHandlerTest::SetUpTestCase()
{
    g_originalUnloadTaskMgr = ZstdWrapper::GetInstance().unloadTaskMgr_;
    g_suiteUnloadTaskMgr = std::make_shared<SingleDelayedTaskMgr>(TEST_UNLOAD_TASK_NAME, TEST_LONG_UNLOAD_DELAY_MS);
}

void BmsPreCompressHandlerTest::TearDownTestCase()
{
    ZstdWrapper::GetInstance().unloadTaskMgr_ = g_originalUnloadTaskMgr;
    g_suiteUnloadTaskMgr = nullptr;
}

void BmsPreCompressHandlerTest::SetUp()
{
    PreCompressHook::ResetDlHooks();
    PreCompressHook::ResetIoHooks();
    MockZstd::SetStreamSizes(MockZstd::MOCK_DEFAULT_IN_SIZE, MockZstd::MOCK_DEFAULT_OUT_SIZE);
    ResetZstdWrapper();
    ZstdWrapper::GetInstance().unloadTaskMgr_ = g_suiteUnloadTaskMgr;
    PreCompressHook::SetDlopenMode(PreCompressHook::DlopenMode::MOCK_LIB);

    securityDirExisted_ = BundleUtil::IsExistDirNoLog(SECURITY_DIR);
    installdProxy_ = new (std::nothrow) PreCompressInstalldProxy();
    originalInstalldProxy_ = InstalldClient::GetInstance()->installdProxy_;
    InstalldClient::GetInstance()->installdProxy_ = installdProxy_;

    entryContent_ = MockZstd::MakeContent(ENTRY_CONTENT_SIZE, ENTRY_SEED);
    featureContent_ = MockZstd::MakeContent(FEATURE_CONTENT_SIZE, FEATURE_SEED);
    (void)OHOS::ForceRemoveDirectory(TEST_ROOT_DIR);
    ASSERT_TRUE(OHOS::ForceCreateDirectory(TEST_PRELOAD_ROOT + VIRTUAL_BUNDLE_DIR));
    ASSERT_TRUE(OHOS::PathToRealPath(TEST_PRELOAD_ROOT, preloadRoot_));
    PreCompressHook::SetPreloadRoot(preloadRoot_);
}

void BmsPreCompressHandlerTest::TearDown()
{
    InstalldClient::GetInstance()->installdProxy_ = originalInstalldProxy_;
    ResetZstdWrapper();
    ZstdWrapper::GetInstance().unloadTaskMgr_ = g_suiteUnloadTaskMgr;
    PreCompressHook::ResetIoHooks();
    PreCompressHook::ResetDlHooks();
    MockZstd::SetStreamSizes(MockZstd::MOCK_DEFAULT_IN_SIZE, MockZstd::MOCK_DEFAULT_OUT_SIZE);
    (void)OHOS::ForceRemoveDirectory(TEST_ROOT_DIR);
    if (!securityDirExisted_) {
        (void)rmdir(SECURITY_DIR.c_str());
    }
}

std::string BmsPreCompressHandlerTest::RealArchive(const std::string &name) const
{
    return preloadRoot_ + VirtualArchive(name);
}

bool BmsPreCompressHandlerTest::PrepareArchive(const std::string &name, const std::vector<uint8_t> &content,
    bool withContentSize) const
{
    return WriteBytes(RealArchive(name), MockZstd::BuildRawFrame(content, withContentSize, SMALL_BLOCK_SIZE));
}

bool BmsPreCompressHandlerTest::PrepareSecurityDir() const
{
    if (BundleUtil::IsExistDirNoLog(SECURITY_DIR)) {
        return true;
    }
    return (mkdir(SECURITY_DIR.c_str(), SECURITY_DIR_MODE) == 0) &&
        (chown(SECURITY_DIR.c_str(), Constants::FOUNDATION_UID, ServiceConstants::BMS_GID) == 0);
}

/**
 * @tc.number: PreCompressHandler_IsCompressedArchive_0100
 * @tc.name: test IsCompressedArchive and GetDecompressedFileName
 * @tc.desc: 1. only a .hap or .hsp followed by .zst names a compressed archive
 *           2. the decompressed file name drops the archive suffix
 */
HWTEST_F(BmsPreCompressHandlerTest, PreCompressHandler_IsCompressedArchive_0100, Function | SmallTest | Level0)
{
    EXPECT_TRUE(PreCompressHandler::IsCompressedArchive(VirtualArchive(ENTRY_ARCHIVE_NAME)));
    EXPECT_TRUE(PreCompressHandler::IsCompressedArchive(VirtualArchive(FEATURE_ARCHIVE_NAME)));
    EXPECT_TRUE(PreCompressHandler::IsCompressedArchive(VirtualArchive("ENTRY.HAP.zst")));
    EXPECT_FALSE(PreCompressHandler::IsCompressedArchive(VirtualArchive(ENTRY_HAP_NAME)));
    EXPECT_FALSE(PreCompressHandler::IsCompressedArchive(VirtualArchive("entry.hap.ZST")));
    EXPECT_FALSE(PreCompressHandler::IsCompressedArchive(VirtualArchive("readme.txt.zst")));
    EXPECT_FALSE(PreCompressHandler::IsCompressedArchive(VirtualArchive(".zst")));
    EXPECT_FALSE(PreCompressHandler::IsCompressedArchive(""));
    EXPECT_EQ(GetDecompressedFileName(ENTRY_ARCHIVE_NAME), ENTRY_HAP_NAME);
    EXPECT_EQ(GetDecompressedFileName(FEATURE_ARCHIVE_NAME), FEATURE_HSP_NAME);
    EXPECT_EQ(GetDecompressedFileName("entry.zst"), "");
}

/**
 * @tc.number: PreCompressHandler_WriteAll_0100
 * @tc.name: test WriteAll
 * @tc.desc: 1. all the data is written to the file
 *           2. nothing to write succeeds without writing
 *           3. a write error fails
 */
HWTEST_F(BmsPreCompressHandlerTest, PreCompressHandler_WriteAll_0100, Function | SmallTest | Level0)
{
    std::string path = TEST_ROOT_DIR + "/write_all.bin";
    std::vector<uint8_t> data = MockZstd::MakeContent(SMALL_CONTENT_SIZE, SMALL_SEED);
    {
        FdGuard fd(::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, TEST_FILE_MODE));
        ASSERT_GE(fd.Get(), 0);
        EXPECT_TRUE(WriteAll(fd.Get(), reinterpret_cast<const char *>(data.data()), 0));
        EXPECT_TRUE(WriteAll(fd.Get(), reinterpret_cast<const char *>(data.data()), data.size()));
    }
    EXPECT_EQ(ReadBytes(path), data);

    FdGuard readOnlyFd(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
    ASSERT_GE(readOnlyFd.Get(), 0);
    EXPECT_FALSE(WriteAll(readOnlyFd.Get(), reinterpret_cast<const char *>(data.data()), data.size()));
}

/**
 * @tc.number: PreCompressHandler_CheckDecompressPath_0100
 * @tc.name: test CheckDecompressPath
 * @tc.desc: 1. relative path segments in the source or the destination are rejected
 *           2. a source that does not exist is rejected
 */
HWTEST_F(BmsPreCompressHandlerTest, PreCompressHandler_CheckDecompressPath_0100, Function | SmallTest | Level0)
{
    std::string dstPath = TEST_ROOT_DIR + ServiceConstants::PATH_SEPARATOR + ENTRY_HAP_NAME;
    std::string realSrcPath;
    EXPECT_EQ(CheckDecompressPath(VIRTUAL_BUNDLE_DIR + "/../" + ENTRY_ARCHIVE_NAME, dstPath, realSrcPath),
        ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
    EXPECT_EQ(CheckDecompressPath(VirtualArchive(ENTRY_ARCHIVE_NAME), TEST_ROOT_DIR + "/../" + ENTRY_HAP_NAME,
        realSrcPath), ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
    EXPECT_EQ(CheckDecompressPath(VirtualArchive(ENTRY_ARCHIVE_NAME), dstPath, realSrcPath),
        ERR_APPEXECFWK_INSTALL_FILE_PATH_IS_NOT_REAL);
    EXPECT_TRUE(realSrcPath.empty());
}

/**
 * @tc.number: PreCompressHandler_CheckDecompressPath_0200
 * @tc.name: test CheckDecompressPath
 * @tc.desc: 1. a source whose real path is outside the preload app dir is rejected, a symlink included
 *           2. a source under the preload app dir passes with its real path
 */
HWTEST_F(BmsPreCompressHandlerTest, PreCompressHandler_CheckDecompressPath_0200, Function | SmallTest | Level0)
{
    std::string dstPath = TEST_ROOT_DIR + ServiceConstants::PATH_SEPARATOR + ENTRY_HAP_NAME;
    std::string outsideArchive = TEST_ROOT_DIR + "/outside/" + ENTRY_ARCHIVE_NAME;
    ASSERT_TRUE(WriteBytes(outsideArchive, MockZstd::BuildRawFrame(entryContent_, true)));
    std::string realSrcPath;
    EXPECT_EQ(CheckDecompressPath(outsideArchive, dstPath, realSrcPath), ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);

    ASSERT_EQ(symlink(outsideArchive.c_str(), RealArchive(FEATURE_ARCHIVE_NAME).c_str()), 0);
    EXPECT_EQ(CheckDecompressPath(VirtualArchive(FEATURE_ARCHIVE_NAME), dstPath, realSrcPath),
        ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);

    ASSERT_TRUE(PrepareArchive(ENTRY_ARCHIVE_NAME, entryContent_, true));
    EXPECT_EQ(CheckDecompressPath(VirtualArchive(ENTRY_ARCHIVE_NAME), dstPath, realSrcPath), ERR_OK);
    EXPECT_EQ(realSrcPath, VirtualArchive(ENTRY_ARCHIVE_NAME));
}

/**
 * @tc.number: PreCompressHandler_CheckDecompressedSize_0100
 * @tc.name: test CheckDecompressedSize
 * @tc.desc: 1. data that is not a zstd frame is rejected
 *           2. a content size above the cap is rejected, the cap itself is allowed
 *           3. a frame of unknown content size is left to the decompression
 */
HWTEST_F(BmsPreCompressHandlerTest, PreCompressHandler_CheckDecompressedSize_0100, Function | SmallTest | Level0)
{
    auto lease = ZstdWrapper::GetInstance().Acquire();
    ASSERT_NE(lease, nullptr);
    std::vector<uint8_t> content = MockZstd::MakeContent(SMALL_CONTENT_SIZE, SMALL_SEED);

    DecompressContext ctx = MakeContext(SMALL_CONTENT_SIZE);
    SetInput(ctx, content);
    EXPECT_EQ(CheckDecompressedSize(ctx), ERR_APPEXECFWK_INSTALL_DECOMPRESS_APP_FAILED);

    SetInput(ctx, MockZstd::BuildRawFrame(content, true));
    EXPECT_EQ(CheckDecompressedSize(ctx), ERR_OK);
    ctx.sizeCap = SMALL_CONTENT_SIZE - 1;
    EXPECT_EQ(CheckDecompressedSize(ctx), ERR_APPEXECFWK_INSTALL_INVALID_HAP_SIZE);

    SetInput(ctx, MockZstd::BuildRawFrame(content, false));
    EXPECT_EQ(CheckDecompressedSize(ctx), ERR_OK);
}

/**
 * @tc.number: PreCompressHandler_DecompressChunk_0100
 * @tc.name: test DecompressChunk
 * @tc.desc: 1. a chunk is decompressed through several output buffers into the destination
 *           2. an empty chunk writes nothing
 */
HWTEST_F(BmsPreCompressHandlerTest, PreCompressHandler_DecompressChunk_0100, Function | SmallTest | Level0)
{
    auto lease = ZstdWrapper::GetInstance().Acquire();
    ASSERT_NE(lease, nullptr);
    auto zds = ZstdWrapper::GetInstance().CreateDStream();
    ASSERT_NE(zds, nullptr);
    std::string dstPath = TEST_ROOT_DIR + ServiceConstants::PATH_SEPARATOR + ENTRY_HAP_NAME;
    FdGuard dstFd(::open(dstPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, TEST_FILE_MODE));
    ASSERT_GE(dstFd.Get(), 0);

    DecompressContext ctx = MakeContext(MAX_DECOMPRESSED_SIZE);
    ctx.dstFd = dstFd.Get();
    SetInput(ctx, {});
    EXPECT_EQ(DecompressChunk(zds.get(), ctx), ERR_OK);
    EXPECT_EQ(ctx.written, 0);

    SetInput(ctx, MockZstd::BuildRawFrame(entryContent_, false, SMALL_BLOCK_SIZE));
    EXPECT_EQ(DecompressChunk(zds.get(), ctx), ERR_OK);
    EXPECT_EQ(ctx.written, static_cast<int64_t>(ENTRY_CONTENT_SIZE));
    EXPECT_EQ(ctx.lastRet, 0U);
    EXPECT_EQ(ReadBytes(dstPath), entryContent_);
}

/**
 * @tc.number: PreCompressHandler_DecompressChunk_0200
 * @tc.name: test DecompressChunk
 * @tc.desc: 1. a corrupted chunk fails
 *           2. writing more than the cap fails
 *           3. a write error fails
 */
HWTEST_F(BmsPreCompressHandlerTest, PreCompressHandler_DecompressChunk_0200, Function | SmallTest | Level0)
{
    auto lease = ZstdWrapper::GetInstance().Acquire();
    ASSERT_NE(lease, nullptr);
    std::string dstPath = TEST_ROOT_DIR + ServiceConstants::PATH_SEPARATOR + ENTRY_HAP_NAME;
    FdGuard dstFd(::open(dstPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, TEST_FILE_MODE));
    ASSERT_GE(dstFd.Get(), 0);
    std::vector<uint8_t> content = MockZstd::MakeContent(SMALL_CONTENT_SIZE, SMALL_SEED);
    {
        auto zds = ZstdWrapper::GetInstance().CreateDStream();
        DecompressContext ctx = MakeContext(MAX_DECOMPRESSED_SIZE);
        ctx.dstFd = dstFd.Get();
        SetInput(ctx, MockZstd::BuildReservedBlockFrame());
        EXPECT_EQ(DecompressChunk(zds.get(), ctx), ERR_APPEXECFWK_INSTALL_DECOMPRESS_APP_FAILED);
        EXPECT_EQ(ctx.lastRet, MockZstd::MOCK_ERROR_CORRUPTION);
    }
    {
        auto zds = ZstdWrapper::GetInstance().CreateDStream();
        DecompressContext ctx = MakeContext(SIZE_CAP_BELOW_CONTENT);
        ctx.dstFd = dstFd.Get();
        SetInput(ctx, MockZstd::BuildRawFrame(content, false));
        EXPECT_EQ(DecompressChunk(zds.get(), ctx), ERR_APPEXECFWK_INSTALL_INVALID_HAP_SIZE);
        EXPECT_GT(ctx.written, static_cast<int64_t>(SIZE_CAP_BELOW_CONTENT));
    }
    {
        FdGuard readOnlyFd(::open(dstPath.c_str(), O_RDONLY | O_CLOEXEC));
        ASSERT_GE(readOnlyFd.Get(), 0);
        auto zds = ZstdWrapper::GetInstance().CreateDStream();
        DecompressContext ctx = MakeContext(MAX_DECOMPRESSED_SIZE);
        ctx.dstFd = readOnlyFd.Get();
        SetInput(ctx, MockZstd::BuildRawFrame(content, false));
        EXPECT_EQ(DecompressChunk(zds.get(), ctx), ERR_APPEXECFWK_INSTALL_DECOMPRESS_APP_FAILED);
    }
}

/**
 * @tc.number: PreCompressHandler_DecompressAllChunks_0100
 * @tc.name: test DecompressAllChunks
 * @tc.desc: 1. a frame read in many chunks is decompressed completely and its stream is freed
 */
HWTEST_F(BmsPreCompressHandlerTest, PreCompressHandler_DecompressAllChunks_0100, Function | SmallTest | Level0)
{
    auto lease = ZstdWrapper::GetInstance().Acquire();
    ASSERT_NE(lease, nullptr);
    ASSERT_TRUE(PrepareArchive(ENTRY_ARCHIVE_NAME, entryContent_, false));
    std::string dstPath = TEST_ROOT_DIR + ServiceConstants::PATH_SEPARATOR + ENTRY_HAP_NAME;
    FdGuard srcFd(::open(RealArchive(ENTRY_ARCHIVE_NAME).c_str(), O_RDONLY | O_CLOEXEC));
    FdGuard dstFd(::open(dstPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, TEST_FILE_MODE));
    ASSERT_GE(srcFd.Get(), 0);
    ASSERT_GE(dstFd.Get(), 0);
    int32_t liveStreams = MockZstd::GetLiveStreamCount();

    DecompressContext ctx = MakeContext(MAX_DECOMPRESSED_SIZE);
    ctx.srcFd = srcFd.Get();
    ctx.dstFd = dstFd.Get();
    ctx.inLen = read(ctx.srcFd, ctx.inBuf.data(), ctx.inBuf.size());
    ASSERT_GT(ctx.inLen, 0);
    EXPECT_EQ(DecompressAllChunks(ctx), ERR_OK);
    EXPECT_EQ(ctx.inLen, 0);
    EXPECT_EQ(ctx.lastRet, 0U);
    EXPECT_EQ(ctx.written, static_cast<int64_t>(ENTRY_CONTENT_SIZE));
    EXPECT_EQ(ReadBytes(dstPath), entryContent_);
    EXPECT_EQ(MockZstd::GetLiveStreamCount(), liveStreams);
}

/**
 * @tc.number: PreCompressHandler_DecompressAllChunks_0200
 * @tc.name: test DecompressAllChunks
 * @tc.desc: 1. it fails when libzstd can not create a stream
 *           2. a chunk failure stops the decompression and the stream is still freed
 */
HWTEST_F(BmsPreCompressHandlerTest, PreCompressHandler_DecompressAllChunks_0200, Function | SmallTest | Level0)
{
    auto lease = ZstdWrapper::GetInstance().Acquire();
    ASSERT_NE(lease, nullptr);
    int32_t liveStreams = MockZstd::GetLiveStreamCount();
    DecompressContext ctx = MakeContext(MAX_DECOMPRESSED_SIZE);
    SetInput(ctx, MockZstd::BuildReservedBlockFrame());
    EXPECT_EQ(DecompressAllChunks(ctx), ERR_APPEXECFWK_INSTALL_DECOMPRESS_APP_FAILED);
    EXPECT_EQ(ctx.lastRet, MockZstd::MOCK_ERROR_CORRUPTION);
    EXPECT_EQ(MockZstd::GetLiveStreamCount(), liveStreams);

    ZstdWrapper::GetInstance().api_.createDStream = &MockZstd::CreateDStreamFailed;
    DecompressContext failedCtx = MakeContext(MAX_DECOMPRESSED_SIZE);
    SetInput(failedCtx, MockZstd::BuildRawFrame(entryContent_, true));
    EXPECT_EQ(DecompressAllChunks(failedCtx), ERR_APPEXECFWK_INSTALL_DECOMPRESS_APP_FAILED);
    EXPECT_EQ(failedCtx.written, 0);
}

/**
 * @tc.number: PreCompressHandler_DecompressAllChunks_0300
 * @tc.name: test DecompressAllChunks
 * @tc.desc: 1. a read error of the source fails
 *           2. a source ending inside the frame fails
 */
HWTEST_F(BmsPreCompressHandlerTest, PreCompressHandler_DecompressAllChunks_0300, Function | SmallTest | Level0)
{
    auto lease = ZstdWrapper::GetInstance().Acquire();
    ASSERT_NE(lease, nullptr);
    std::vector<uint8_t> frame = MockZstd::BuildRawFrame(entryContent_, false, SMALL_BLOCK_SIZE);
    std::string archive = RealArchive(ENTRY_ARCHIVE_NAME);
    ASSERT_TRUE(WriteBytes(archive,
        std::vector<uint8_t>(frame.begin(), frame.end() - static_cast<std::ptrdiff_t>(TRUNCATED_BYTES))));
    std::string dstPath = TEST_ROOT_DIR + ServiceConstants::PATH_SEPARATOR + ENTRY_HAP_NAME;
    FdGuard dstFd(::open(dstPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, TEST_FILE_MODE));
    ASSERT_GE(dstFd.Get(), 0);
    {
        FdGuard writeOnlyFd(::open(archive.c_str(), O_WRONLY | O_CLOEXEC));
        ASSERT_GE(writeOnlyFd.Get(), 0);
        DecompressContext ctx = MakeContext(MAX_DECOMPRESSED_SIZE);
        ctx.srcFd = writeOnlyFd.Get();
        ctx.dstFd = dstFd.Get();
        SetInput(ctx, std::vector<uint8_t>(frame.begin(),
            frame.begin() + static_cast<std::ptrdiff_t>(MockZstd::MOCK_DEFAULT_IN_SIZE)));
        EXPECT_EQ(DecompressAllChunks(ctx), ERR_APPEXECFWK_INSTALL_ACCESS_FILE_FAILED);
        EXPECT_LT(ctx.inLen, 0);
    }
    {
        FdGuard srcFd(::open(archive.c_str(), O_RDONLY | O_CLOEXEC));
        ASSERT_GE(srcFd.Get(), 0);
        DecompressContext ctx = MakeContext(MAX_DECOMPRESSED_SIZE);
        ctx.srcFd = srcFd.Get();
        ctx.dstFd = dstFd.Get();
        ctx.inLen = read(ctx.srcFd, ctx.inBuf.data(), ctx.inBuf.size());
        ASSERT_GT(ctx.inLen, 0);
        EXPECT_EQ(DecompressAllChunks(ctx), ERR_APPEXECFWK_INSTALL_DECOMPRESS_APP_FAILED);
        EXPECT_EQ(ctx.inLen, 0);
        EXPECT_NE(ctx.lastRet, 0U);
    }
}

/**
 * @tc.number: PreCompressHandler_WriteDecompressedFile_0100
 * @tc.name: test WriteDecompressedFile
 * @tc.desc: 1. an existing destination is never overwritten
 *           2. a new destination receives the decompressed content
 */
HWTEST_F(BmsPreCompressHandlerTest, PreCompressHandler_WriteDecompressedFile_0100, Function | SmallTest | Level0)
{
    auto lease = ZstdWrapper::GetInstance().Acquire();
    ASSERT_NE(lease, nullptr);
    ASSERT_TRUE(PrepareArchive(ENTRY_ARCHIVE_NAME, entryContent_, true));
    std::string existingPath = TEST_ROOT_DIR + "/existing.hap";
    ASSERT_TRUE(WriteText(existingPath, AG_CONFIG_CONTENT));
    FdGuard srcFd(::open(RealArchive(ENTRY_ARCHIVE_NAME).c_str(), O_RDONLY | O_CLOEXEC));
    ASSERT_GE(srcFd.Get(), 0);

    DecompressContext existingCtx = MakeContext(MAX_DECOMPRESSED_SIZE);
    existingCtx.srcFd = srcFd.Get();
    EXPECT_EQ(WriteDecompressedFile(existingCtx, existingPath), ERR_APPEXECFWK_INSTALL_ACCESS_FILE_FAILED);
    EXPECT_LT(existingCtx.dstFd, 0);
    EXPECT_EQ(ReadBytes(existingPath), std::vector<uint8_t>(AG_CONFIG_CONTENT.begin(), AG_CONFIG_CONTENT.end()));

    std::string dstPath = TEST_ROOT_DIR + ServiceConstants::PATH_SEPARATOR + ENTRY_HAP_NAME;
    DecompressContext ctx = MakeContext(MAX_DECOMPRESSED_SIZE);
    ctx.srcFd = srcFd.Get();
    ctx.inLen = read(ctx.srcFd, ctx.inBuf.data(), ctx.inBuf.size());
    ASSERT_GT(ctx.inLen, 0);
    EXPECT_EQ(WriteDecompressedFile(ctx, dstPath), ERR_OK);
    EXPECT_EQ(ReadBytes(dstPath), entryContent_);
}

/**
 * @tc.number: PreCompressHandler_DecompressFile_0100
 * @tc.name: test DecompressFile
 * @tc.desc: 1. archives under the preload app dir are decompressed
 *           2. the decompressed sizes add up in totalSize
 */
HWTEST_F(BmsPreCompressHandlerTest, PreCompressHandler_DecompressFile_0100, Function | SmallTest | Level0)
{
    auto lease = ZstdWrapper::GetInstance().Acquire();
    ASSERT_NE(lease, nullptr);
    ASSERT_TRUE(PrepareArchive(ENTRY_ARCHIVE_NAME, entryContent_, true));
    ASSERT_TRUE(PrepareArchive(FEATURE_ARCHIVE_NAME, featureContent_, false));
    std::string entryPath = TEST_ROOT_DIR + ServiceConstants::PATH_SEPARATOR + ENTRY_HAP_NAME;
    std::string featurePath = TEST_ROOT_DIR + ServiceConstants::PATH_SEPARATOR + FEATURE_HSP_NAME;

    int64_t totalSize = 0;
    EXPECT_EQ(DecompressFile(VirtualArchive(ENTRY_ARCHIVE_NAME), entryPath, totalSize), ERR_OK);
    EXPECT_EQ(totalSize, static_cast<int64_t>(ENTRY_CONTENT_SIZE));
    EXPECT_EQ(DecompressFile(VirtualArchive(FEATURE_ARCHIVE_NAME), featurePath, totalSize), ERR_OK);
    EXPECT_EQ(totalSize, static_cast<int64_t>(ENTRY_CONTENT_SIZE + FEATURE_CONTENT_SIZE));
    EXPECT_EQ(ReadBytes(entryPath), entryContent_);
    EXPECT_EQ(ReadBytes(featurePath), featureContent_);
}

/**
 * @tc.number: PreCompressHandler_DecompressFile_0200
 * @tc.name: test DecompressFile
 * @tc.desc: 1. an invalid source path fails before anything is opened
 *           2. a source that can not be opened, an empty source or a source that is not zstd fails
 *           3. an existing destination fails
 */
HWTEST_F(BmsPreCompressHandlerTest, PreCompressHandler_DecompressFile_0200, Function | SmallTest | Level0)
{
    auto lease = ZstdWrapper::GetInstance().Acquire();
    ASSERT_NE(lease, nullptr);
    ASSERT_TRUE(PrepareArchive(ENTRY_ARCHIVE_NAME, entryContent_, true));
    ASSERT_TRUE(WriteBytes(RealArchive("empty.hap.zst"), {}));
    ASSERT_TRUE(WriteBytes(RealArchive("plain.hap.zst"), entryContent_));
    std::string dstPath = TEST_ROOT_DIR + ServiceConstants::PATH_SEPARATOR + ENTRY_HAP_NAME;
    int64_t totalSize = 0;

    EXPECT_EQ(DecompressFile(VIRTUAL_BUNDLE_DIR + "/../" + ENTRY_ARCHIVE_NAME, dstPath, totalSize),
        ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
    PreCompressHook::SetOpenFailKeyword(ENTRY_ARCHIVE_NAME);
    EXPECT_EQ(DecompressFile(VirtualArchive(ENTRY_ARCHIVE_NAME), dstPath, totalSize),
        ERR_APPEXECFWK_INSTALL_ACCESS_FILE_FAILED);
    PreCompressHook::SetOpenFailKeyword("");
    EXPECT_EQ(DecompressFile(VirtualArchive("empty.hap.zst"), dstPath, totalSize),
        ERR_APPEXECFWK_INSTALL_ACCESS_FILE_FAILED);
    EXPECT_EQ(DecompressFile(VirtualArchive("plain.hap.zst"), dstPath, totalSize),
        ERR_APPEXECFWK_INSTALL_DECOMPRESS_APP_FAILED);
    EXPECT_EQ(totalSize, 0);
    EXPECT_FALSE(BundleUtil::IsExistFileNoLog(dstPath));

    ASSERT_TRUE(WriteText(dstPath, AG_CONFIG_CONTENT));
    EXPECT_EQ(DecompressFile(VirtualArchive(ENTRY_ARCHIVE_NAME), dstPath, totalSize),
        ERR_APPEXECFWK_INSTALL_ACCESS_FILE_FAILED);
    EXPECT_EQ(totalSize, 0);
}

/**
 * @tc.number: PreCompressHandler_DecompressFile_0300
 * @tc.name: test DecompressFile
 * @tc.desc: 1. an archive declaring more than the remaining size is rejected before decompressing
 *           2. an archive of unknown size is stopped once it exceeds the remaining size
 */
HWTEST_F(BmsPreCompressHandlerTest, PreCompressHandler_DecompressFile_0300, Function | SmallTest | Level0)
{
    auto lease = ZstdWrapper::GetInstance().Acquire();
    ASSERT_NE(lease, nullptr);
    std::vector<uint8_t> content = MockZstd::MakeContent(SMALL_CONTENT_SIZE, SMALL_SEED);
    ASSERT_TRUE(PrepareArchive(ENTRY_ARCHIVE_NAME, content, true));
    ASSERT_TRUE(PrepareArchive(FEATURE_ARCHIVE_NAME, content, false));
    std::string entryPath = TEST_ROOT_DIR + ServiceConstants::PATH_SEPARATOR + ENTRY_HAP_NAME;
    std::string featurePath = TEST_ROOT_DIR + ServiceConstants::PATH_SEPARATOR + FEATURE_HSP_NAME;

    int64_t totalSize = MAX_DECOMPRESSED_SIZE - static_cast<int64_t>(SIZE_CAP_BELOW_CONTENT);
    EXPECT_EQ(DecompressFile(VirtualArchive(ENTRY_ARCHIVE_NAME), entryPath, totalSize),
        ERR_APPEXECFWK_INSTALL_INVALID_HAP_SIZE);
    EXPECT_EQ(totalSize, MAX_DECOMPRESSED_SIZE - static_cast<int64_t>(SIZE_CAP_BELOW_CONTENT));
    EXPECT_FALSE(BundleUtil::IsExistFileNoLog(entryPath));

    EXPECT_EQ(DecompressFile(VirtualArchive(FEATURE_ARCHIVE_NAME), featurePath, totalSize),
        ERR_APPEXECFWK_INSTALL_INVALID_HAP_SIZE);
    EXPECT_GT(totalSize, MAX_DECOMPRESSED_SIZE);
}

/**
 * @tc.number: PreCompressHandler_CreateDecompressTempDir_0100
 * @tc.name: test CreateDecompressTempDir
 * @tc.desc: 1. the temp dir is created in the security dir prepared by installd and owned by foundation
 */
HWTEST_F(BmsPreCompressHandlerTest, PreCompressHandler_CreateDecompressTempDir_0100, Function | SmallTest | Level0)
{
    std::string tempDir = CreateDecompressTempDir();
    ASSERT_FALSE(tempDir.empty());
    ScopeGuard tempDirGuard([tempDir] { (void)BundleUtil::DeleteDir(tempDir); });
    EXPECT_EQ(tempDir.compare(0, SECURITY_DIR.size() + TEMP_DIR_KEYWORD.size(), SECURITY_DIR + TEMP_DIR_KEYWORD), 0);
    EXPECT_EQ(tempDir.back(), ServiceConstants::FILE_SEPARATOR_CHAR);
    EXPECT_TRUE(BundleUtil::IsExistDirNoLog(tempDir));
    struct stat tempDirStat = {};
    ASSERT_EQ(stat(tempDir.c_str(), &tempDirStat), 0);
    EXPECT_EQ(tempDirStat.st_uid, static_cast<uid_t>(Constants::FOUNDATION_UID));
    EXPECT_EQ(tempDirStat.st_gid, static_cast<gid_t>(ServiceConstants::BMS_GID));
    ASSERT_EQ(installdProxy_->mkdirDirs.size(), 1U);
    EXPECT_EQ(installdProxy_->mkdirDirs[0], SECURITY_DIR);
    EXPECT_EQ(installdProxy_->mkdirScenes[0], BundleDirScene::SERVICE_BMS_SECURITY_STREAM_INSTALL_DIR);
}

/**
 * @tc.number: PreCompressHandler_CreateDecompressTempDir_0200
 * @tc.name: test CreateDecompressTempDir
 * @tc.desc: 1. a failure of installd to prepare the security dir is tolerated when the dir is there
 */
HWTEST_F(BmsPreCompressHandlerTest, PreCompressHandler_CreateDecompressTempDir_0200, Function | SmallTest | Level0)
{
    ASSERT_TRUE(PrepareSecurityDir());
    installdProxy_->mkdirResult = ERR_APPEXECFWK_INSTALLD_MKDIR_FAILED;
    std::string tempDir = CreateDecompressTempDir();
    ASSERT_FALSE(tempDir.empty());
    ScopeGuard tempDirGuard([tempDir] { (void)BundleUtil::DeleteDir(tempDir); });
    EXPECT_TRUE(BundleUtil::IsExistDirNoLog(tempDir));
    EXPECT_EQ(installdProxy_->mkdirDirs.size(), 1U);
}

/**
 * @tc.number: PreCompressHandler_CreateDecompressTempDir_0300
 * @tc.name: test CreateDecompressTempDir
 * @tc.desc: 1. it fails when the temp dir can not be made
 *           2. it fails and leaves nothing when the made temp dir can not be prepared
 */
HWTEST_F(BmsPreCompressHandlerTest, PreCompressHandler_CreateDecompressTempDir_0300, Function | SmallTest | Level0)
{
    PreCompressHook::SetMkdtempMode(PreCompressHook::MkdtempMode::FAIL);
    EXPECT_EQ(CreateDecompressTempDir(), "");

    PreCompressHook::SetMkdtempMode(PreCompressHook::MkdtempMode::BLOCKED);
    EXPECT_EQ(CreateDecompressTempDir(), "");
    std::string blockedPath = PreCompressHook::GetBlockedPath();
    ASSERT_FALSE(blockedPath.empty());
    EXPECT_TRUE(BundleUtil::IsExistFileNoLog(blockedPath));
    EXPECT_FALSE(BundleUtil::IsExistDirNoLog(blockedPath));
}

/**
 * @tc.number: PreCompressHandler_DecompressArchives_0100
 * @tc.name: test DecompressArchives
 * @tc.desc: 1. every archive is decompressed into one temp dir handed to the caller to delete
 *           2. every decompressed path is mapped back to its archive and libzstd is released
 */
HWTEST_F(BmsPreCompressHandlerTest, PreCompressHandler_DecompressArchives_0100, Function | SmallTest | Level0)
{
    ASSERT_TRUE(PrepareArchive(ENTRY_ARCHIVE_NAME, entryContent_, true));
    ASSERT_TRUE(PrepareArchive(FEATURE_ARCHIVE_NAME, featureContent_, false));
    std::vector<std::string> archives = { VirtualArchive(ENTRY_ARCHIVE_NAME), VirtualArchive(FEATURE_ARCHIVE_NAME) };
    std::vector<std::string> hapPaths;
    std::vector<std::string> toDeletePaths;
    std::unordered_map<std::string, std::string> sourceMap;
    ErrCode ret = DecompressArchives(archives, hapPaths, toDeletePaths, sourceMap);
    ScopeGuard tempDirGuard([&toDeletePaths] { BundleUtil::DeleteTempDirs(toDeletePaths); });

    EXPECT_EQ(ret, ERR_OK);
    ASSERT_EQ(toDeletePaths.size(), 1U);
    ASSERT_EQ(hapPaths.size(), archives.size());
    EXPECT_EQ(hapPaths[0], toDeletePaths[0] + ENTRY_HAP_NAME);
    EXPECT_EQ(hapPaths[1], toDeletePaths[0] + FEATURE_HSP_NAME);
    EXPECT_EQ(ReadBytes(hapPaths[0]), entryContent_);
    EXPECT_EQ(ReadBytes(hapPaths[1]), featureContent_);
    EXPECT_EQ(sourceMap.size(), archives.size());
    EXPECT_EQ(sourceMap[RealPathOf(hapPaths[0])], archives[0]);
    EXPECT_EQ(sourceMap[RealPathOf(hapPaths[1])], archives[1]);
    EXPECT_EQ(ZstdWrapper::GetInstance().refCount_, 0U);
}

/**
 * @tc.number: PreCompressHandler_DecompressArchives_0200
 * @tc.name: test DecompressArchives
 * @tc.desc: 1. nothing is created when libzstd is not available
 *           2. nothing is left when the temp dir can not be created
 */
HWTEST_F(BmsPreCompressHandlerTest, PreCompressHandler_DecompressArchives_0200, Function | SmallTest | Level0)
{
    ASSERT_TRUE(PrepareArchive(ENTRY_ARCHIVE_NAME, entryContent_, true));
    std::vector<std::string> archives = { VirtualArchive(ENTRY_ARCHIVE_NAME) };
    std::vector<std::string> hapPaths;
    std::vector<std::string> toDeletePaths;
    std::unordered_map<std::string, std::string> sourceMap;

    PreCompressHook::SetDlopenMode(PreCompressHook::DlopenMode::FAIL);
    EXPECT_EQ(DecompressArchives(archives, hapPaths, toDeletePaths, sourceMap),
        ERR_APPEXECFWK_INSTALL_DECOMPRESS_APP_FAILED);
    EXPECT_TRUE(installdProxy_->mkdirDirs.empty());

    PreCompressHook::SetDlopenMode(PreCompressHook::DlopenMode::MOCK_LIB);
    PreCompressHook::SetMkdtempMode(PreCompressHook::MkdtempMode::FAIL);
    EXPECT_EQ(DecompressArchives(archives, hapPaths, toDeletePaths, sourceMap),
        ERR_APPEXECFWK_INSTALL_COPY_HAP_FAILED);
    EXPECT_TRUE(hapPaths.empty());
    EXPECT_TRUE(toDeletePaths.empty());
    EXPECT_TRUE(sourceMap.empty());
    EXPECT_EQ(ZstdWrapper::GetInstance().refCount_, 0U);
}

/**
 * @tc.number: PreCompressHandler_DecompressArchives_0300
 * @tc.name: test DecompressArchives
 * @tc.desc: 1. an archive name that is not a compressed hap or hsp fails
 *           2. a failed archive stops the batch after the archives already decompressed
 */
HWTEST_F(BmsPreCompressHandlerTest, PreCompressHandler_DecompressArchives_0300, Function | SmallTest | Level0)
{
    ASSERT_TRUE(PrepareArchive(ENTRY_ARCHIVE_NAME, entryContent_, true));
    std::vector<std::string> hapPaths;
    std::vector<std::string> toDeletePaths;
    std::unordered_map<std::string, std::string> sourceMap;
    ScopeGuard tempDirGuard([&toDeletePaths] { BundleUtil::DeleteTempDirs(toDeletePaths); });

    EXPECT_EQ(DecompressArchives({ VirtualArchive("entry.zst") }, hapPaths, toDeletePaths, sourceMap),
        ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
    EXPECT_TRUE(hapPaths.empty());
    EXPECT_EQ(toDeletePaths.size(), 1U);

    std::vector<std::string> archives = { VirtualArchive(ENTRY_ARCHIVE_NAME), VirtualArchive(FEATURE_ARCHIVE_NAME) };
    EXPECT_EQ(DecompressArchives(archives, hapPaths, toDeletePaths, sourceMap),
        ERR_APPEXECFWK_INSTALL_FILE_PATH_IS_NOT_REAL);
    ASSERT_EQ(toDeletePaths.size(), 2U);
    ASSERT_EQ(hapPaths.size(), 1U);
    EXPECT_EQ(hapPaths[0], toDeletePaths[1] + ENTRY_HAP_NAME);
    EXPECT_EQ(sourceMap.size(), 1U);
}

/**
 * @tc.number: PreCompressHandler_DecompressArchives_0400
 * @tc.name: test DecompressArchives
 * @tc.desc: 1. the decompressed path itself is the key when its real path can not be resolved
 */
HWTEST_F(BmsPreCompressHandlerTest, PreCompressHandler_DecompressArchives_0400, Function | SmallTest | Level0)
{
    ASSERT_TRUE(PrepareArchive(ENTRY_ARCHIVE_NAME, entryContent_, true));
    PreCompressHook::SetRealPathFailKeyword(TEMP_DIR_KEYWORD);
    std::vector<std::string> hapPaths;
    std::vector<std::string> toDeletePaths;
    std::unordered_map<std::string, std::string> sourceMap;
    ErrCode ret = DecompressArchives({ VirtualArchive(ENTRY_ARCHIVE_NAME) }, hapPaths, toDeletePaths, sourceMap);
    ScopeGuard tempDirGuard([&toDeletePaths] { BundleUtil::DeleteTempDirs(toDeletePaths); });

    EXPECT_EQ(ret, ERR_OK);
    ASSERT_EQ(hapPaths.size(), 1U);
    ASSERT_EQ(sourceMap.size(), 1U);
    EXPECT_EQ(sourceMap.begin()->first, hapPaths[0]);
    EXPECT_EQ(sourceMap.begin()->second, VirtualArchive(ENTRY_ARCHIVE_NAME));
}

/**
 * @tc.number: PreCompressHandler_GetCompressedArchivesFromBundlePath_0100
 * @tc.name: test GetCompressedArchivesFromBundlePath
 * @tc.desc: 1. only the compressed archives directly under the dir are collected, with their real paths
 *           2. other files and dangling archives are skipped, a trailing separator makes no difference
 *           3. the dir is read the same when it is named by its path under the preload image
 */
HWTEST_F(BmsPreCompressHandlerTest, PreCompressHandler_GetCompressedArchivesFromBundlePath_0100,
    Function | SmallTest | Level0)
{
    ASSERT_TRUE(PrepareArchive(ENTRY_ARCHIVE_NAME, entryContent_, true));
    ASSERT_TRUE(PrepareArchive(FEATURE_ARCHIVE_NAME, featureContent_, false));
    std::string bundleDir = preloadRoot_ + VIRTUAL_BUNDLE_DIR;
    ASSERT_TRUE(WriteText(bundleDir + ServiceConstants::PATH_SEPARATOR + ServiceConstants::AG_CONFIG_FILE,
        AG_CONFIG_CONTENT));
    ASSERT_TRUE(WriteText(bundleDir + "/readme.txt", AG_CONFIG_CONTENT));
    ASSERT_EQ(symlink((TEST_ROOT_DIR + "/missing.hap.zst").c_str(), RealArchive("ghost.hap.zst").c_str()), 0);
    std::vector<std::string> expected = { VirtualArchive(ENTRY_ARCHIVE_NAME), VirtualArchive(FEATURE_ARCHIVE_NAME) };
    std::sort(expected.begin(), expected.end());

    std::vector<std::string> archives;
    EXPECT_EQ(PreCompressHandler::GetCompressedArchivesFromBundlePath(bundleDir, archives), ERR_OK);
    std::sort(archives.begin(), archives.end());
    EXPECT_EQ(archives, expected);

    std::vector<std::string> archivesWithSeparator;
    EXPECT_EQ(PreCompressHandler::GetCompressedArchivesFromBundlePath(
        bundleDir + ServiceConstants::PATH_SEPARATOR, archivesWithSeparator), ERR_OK);
    std::sort(archivesWithSeparator.begin(), archivesWithSeparator.end());
    EXPECT_EQ(archivesWithSeparator, expected);

    std::vector<std::string> imageArchives;
    EXPECT_EQ(PreCompressHandler::GetCompressedArchivesFromBundlePath(VIRTUAL_BUNDLE_DIR, imageArchives), ERR_OK);
    std::sort(imageArchives.begin(), imageArchives.end());
    EXPECT_EQ(imageArchives, expected);
}

/**
 * @tc.number: PreCompressHandler_GetCompressedArchivesFromBundlePath_0200
 * @tc.name: test GetCompressedArchivesFromBundlePath
 * @tc.desc: 1. a dir that can not be opened fails
 *           2. a dir mixing plain hap or hsp files with archives fails
 */
HWTEST_F(BmsPreCompressHandlerTest, PreCompressHandler_GetCompressedArchivesFromBundlePath_0200,
    Function | SmallTest | Level0)
{
    std::vector<std::string> archives;
    EXPECT_EQ(PreCompressHandler::GetCompressedArchivesFromBundlePath(TEST_ROOT_DIR + "/not_exist", archives),
        ERR_APPEXECFWK_INSTALL_OPENDIR_FAILED);

    std::string hapDir = TEST_ROOT_DIR + "/mixed_hap";
    ASSERT_TRUE(WriteBytes(hapDir + ServiceConstants::PATH_SEPARATOR + ENTRY_HAP_NAME, entryContent_));
    EXPECT_EQ(PreCompressHandler::GetCompressedArchivesFromBundlePath(hapDir, archives),
        ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);

    std::string hspDir = TEST_ROOT_DIR + "/mixed_hsp";
    ASSERT_TRUE(WriteBytes(hspDir + ServiceConstants::PATH_SEPARATOR + FEATURE_HSP_NAME, featureContent_));
    EXPECT_EQ(PreCompressHandler::GetCompressedArchivesFromBundlePath(hspDir, archives),
        ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
    EXPECT_TRUE(archives.empty());
}

/**
 * @tc.number: PreCompressHandler_PrepareCompressedPaths_0100
 * @tc.name: test PrepareCompressedPaths
 * @tc.desc: 1. the archives of a preload dir are decompressed and mapped back to the archives
 */
HWTEST_F(BmsPreCompressHandlerTest, PreCompressHandler_PrepareCompressedPaths_0100, Function | SmallTest | Level0)
{
    ASSERT_TRUE(PrepareArchive(ENTRY_ARCHIVE_NAME, entryContent_, true));
    ASSERT_TRUE(PrepareArchive(FEATURE_ARCHIVE_NAME, featureContent_, false));
    std::vector<std::string> outPaths;
    std::vector<std::string> toDeletePaths;
    std::unordered_map<std::string, std::string> sourceMap;
    ErrCode ret = PreCompressHandler::PrepareCompressedPaths({ preloadRoot_ + VIRTUAL_BUNDLE_DIR }, outPaths,
        toDeletePaths, sourceMap);
    ScopeGuard tempDirGuard([&toDeletePaths] { BundleUtil::DeleteTempDirs(toDeletePaths); });

    EXPECT_EQ(ret, ERR_OK);
    ASSERT_EQ(outPaths.size(), 2U);
    EXPECT_EQ(toDeletePaths.size(), 1U);
    ASSERT_EQ(sourceMap.size(), 2U);
    for (const auto &outPath : outPaths) {
        bool isEntry = BundleUtil::EndWith(outPath, ENTRY_HAP_NAME);
        EXPECT_EQ(ReadBytes(outPath), isEntry ? entryContent_ : featureContent_);
        EXPECT_EQ(sourceMap[RealPathOf(outPath)],
            VirtualArchive(isEntry ? ENTRY_ARCHIVE_NAME : FEATURE_ARCHIVE_NAME));
    }
}

/**
 * @tc.number: PreCompressHandler_PrepareCompressedPaths_0200
 * @tc.name: test PrepareCompressedPaths
 * @tc.desc: 1. an archive given by its path is decompressed
 */
HWTEST_F(BmsPreCompressHandlerTest, PreCompressHandler_PrepareCompressedPaths_0200, Function | SmallTest | Level0)
{
    ASSERT_TRUE(PrepareArchive(ENTRY_ARCHIVE_NAME, entryContent_, true));
    std::vector<std::string> outPaths;
    std::vector<std::string> toDeletePaths;
    std::unordered_map<std::string, std::string> sourceMap;
    ErrCode ret = PreCompressHandler::PrepareCompressedPaths({ VirtualArchive(ENTRY_ARCHIVE_NAME) }, outPaths,
        toDeletePaths, sourceMap);
    ScopeGuard tempDirGuard([&toDeletePaths] { BundleUtil::DeleteTempDirs(toDeletePaths); });

    EXPECT_EQ(ret, ERR_OK);
    ASSERT_EQ(outPaths.size(), 1U);
    EXPECT_EQ(ReadBytes(outPaths[0]), entryContent_);
    EXPECT_EQ(sourceMap[RealPathOf(outPaths[0])], VirtualArchive(ENTRY_ARCHIVE_NAME));
}

/**
 * @tc.number: PreCompressHandler_PrepareCompressedPaths_0300
 * @tc.name: test PrepareCompressedPaths
 * @tc.desc: 1. a dir mixing plain packages with archives fails without decompressing
 *           2. no archive at all fails
 */
HWTEST_F(BmsPreCompressHandlerTest, PreCompressHandler_PrepareCompressedPaths_0300, Function | SmallTest | Level0)
{
    std::vector<std::string> outPaths;
    std::vector<std::string> toDeletePaths;
    std::unordered_map<std::string, std::string> sourceMap;
    ASSERT_TRUE(PrepareArchive(ENTRY_ARCHIVE_NAME, entryContent_, true));
    std::string mixedDir = TEST_ROOT_DIR + "/mixed";
    ASSERT_TRUE(WriteBytes(mixedDir + ServiceConstants::PATH_SEPARATOR + ENTRY_HAP_NAME, entryContent_));
    EXPECT_EQ(PreCompressHandler::PrepareCompressedPaths({ VirtualArchive(ENTRY_ARCHIVE_NAME), mixedDir }, outPaths,
        toDeletePaths, sourceMap), ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);

    std::string emptyDir = TEST_ROOT_DIR + "/empty";
    ASSERT_TRUE(OHOS::ForceCreateDirectory(emptyDir));
    EXPECT_EQ(PreCompressHandler::PrepareCompressedPaths({ emptyDir }, outPaths, toDeletePaths, sourceMap),
        ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
    EXPECT_EQ(PreCompressHandler::PrepareCompressedPaths({}, outPaths, toDeletePaths, sourceMap),
        ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID);
    EXPECT_TRUE(outPaths.empty());
    EXPECT_TRUE(toDeletePaths.empty());
    EXPECT_TRUE(installdProxy_->mkdirDirs.empty());
}

/**
 * @tc.number: PreCompressHandler_PrepareScanPaths_0100
 * @tc.name: test PrepareScanPaths
 * @tc.desc: 1. a compressed scan path gives the decompressed haps and the temp dir to delete
 *           2. a compressed scan path without archive gives nothing
 */
HWTEST_F(BmsPreCompressHandlerTest, PreCompressHandler_PrepareScanPaths_0100, Function | SmallTest | Level0)
{
    ASSERT_TRUE(PrepareArchive(ENTRY_ARCHIVE_NAME, entryContent_, true));
    ASSERT_TRUE(PrepareArchive(FEATURE_ARCHIVE_NAME, featureContent_, false));
    std::vector<std::string> realPaths;
    std::vector<std::string> tempDirs;
    std::unordered_map<std::string, std::string> sourceMap;
    bool ret = PreCompressHandler::PrepareScanPaths(preloadRoot_ + VIRTUAL_BUNDLE_DIR, true, realPaths, tempDirs,
        sourceMap);
    ScopeGuard tempDirGuard([&tempDirs] { BundleUtil::DeleteTempDirs(tempDirs); });
    EXPECT_TRUE(ret);
    EXPECT_EQ(realPaths.size(), 2U);
    EXPECT_EQ(tempDirs.size(), 1U);
    EXPECT_EQ(sourceMap.size(), 2U);

    std::string emptyDir = TEST_ROOT_DIR + "/empty";
    ASSERT_TRUE(OHOS::ForceCreateDirectory(emptyDir));
    std::vector<std::string> emptyPaths;
    std::vector<std::string> emptyTempDirs;
    std::unordered_map<std::string, std::string> emptySourceMap;
    EXPECT_FALSE(PreCompressHandler::PrepareScanPaths(emptyDir, true, emptyPaths, emptyTempDirs, emptySourceMap));
    EXPECT_TRUE(emptyPaths.empty());
    EXPECT_TRUE(emptyTempDirs.empty());
}

/**
 * @tc.number: PreCompressHandler_PrepareScanPaths_0200
 * @tc.name: test PrepareScanPaths
 * @tc.desc: 1. a plain scan path gives its real path without decompressing
 *           2. a plain scan path that does not exist gives nothing
 */
HWTEST_F(BmsPreCompressHandlerTest, PreCompressHandler_PrepareScanPaths_0200, Function | SmallTest | Level0)
{
    std::string plainHap = TEST_ROOT_DIR + "/plain/" + ENTRY_HAP_NAME;
    ASSERT_TRUE(WriteBytes(plainHap, entryContent_));
    std::vector<std::string> realPaths;
    std::vector<std::string> tempDirs;
    std::unordered_map<std::string, std::string> sourceMap;
    EXPECT_TRUE(PreCompressHandler::PrepareScanPaths(plainHap, false, realPaths, tempDirs, sourceMap));
    ASSERT_EQ(realPaths.size(), 1U);
    EXPECT_EQ(realPaths[0], RealPathOf(plainHap));
    EXPECT_TRUE(tempDirs.empty());
    EXPECT_TRUE(sourceMap.empty());

    std::vector<std::string> missingPaths;
    EXPECT_FALSE(PreCompressHandler::PrepareScanPaths(TEST_ROOT_DIR + "/plain/missing.hap", false, missingPaths,
        tempDirs, sourceMap));
    EXPECT_TRUE(missingPaths.empty());
}

/**
 * @tc.number: PreCompressHandler_RekeyInfosToSource_0100
 * @tc.name: test RekeyInfosToSource
 * @tc.desc: 1. the infos parsed from decompressed paths are keyed by their archives
 *           2. the other infos and the paths without info are left as they are
 */
HWTEST_F(BmsPreCompressHandlerTest, PreCompressHandler_RekeyInfosToSource_0100, Function | SmallTest | Level0)
{
    std::string tempEntry = SECURITY_DIR + "/pre_compress_test/" + ENTRY_HAP_NAME;
    std::string tempMissing = SECURITY_DIR + "/pre_compress_test/" + FEATURE_HSP_NAME;
    std::string plainPath = VIRTUAL_BUNDLE_DIR + "/plain.hap";
    ApplicationInfo entryApplicationInfo;
    entryApplicationInfo.bundleName = ENTRY_BUNDLE_NAME;
    InnerBundleInfo entryInfo;
    entryInfo.SetBaseApplicationInfo(entryApplicationInfo);
    ApplicationInfo plainApplicationInfo;
    plainApplicationInfo.bundleName = PLAIN_BUNDLE_NAME;
    InnerBundleInfo plainInfo;
    plainInfo.SetBaseApplicationInfo(plainApplicationInfo);
    std::unordered_map<std::string, InnerBundleInfo> infos = { { tempEntry, entryInfo }, { plainPath, plainInfo } };

    PreCompressHandler::RekeyInfosToSource({}, infos);
    EXPECT_EQ(infos.size(), 2U);
    EXPECT_EQ(infos.count(tempEntry), 1U);

    std::unordered_map<std::string, std::string> sourceMap = {
        { tempEntry, VirtualArchive(ENTRY_ARCHIVE_NAME) },
        { tempMissing, VirtualArchive(FEATURE_ARCHIVE_NAME) },
    };
    PreCompressHandler::RekeyInfosToSource(sourceMap, infos);
    EXPECT_EQ(infos.size(), 2U);
    EXPECT_EQ(infos.count(tempEntry), 0U);
    EXPECT_EQ(infos.count(VirtualArchive(FEATURE_ARCHIVE_NAME)), 0U);
    ASSERT_EQ(infos.count(VirtualArchive(ENTRY_ARCHIVE_NAME)), 1U);
    EXPECT_EQ(infos.at(VirtualArchive(ENTRY_ARCHIVE_NAME)).GetBundleName(), ENTRY_BUNDLE_NAME);
    ASSERT_EQ(infos.count(plainPath), 1U);
    EXPECT_EQ(infos.at(plainPath).GetBundleName(), PLAIN_BUNDLE_NAME);
}

/**
 * @tc.number: PreCompressHandler_StageAgConfigFile_0100
 * @tc.name: test StageAgConfigFile
 * @tc.desc: 1. nothing is staged without decompressed archive
 *           2. nothing is staged when the preload dir has no ag_config.json
 */
HWTEST_F(BmsPreCompressHandlerTest, PreCompressHandler_StageAgConfigFile_0100, Function | SmallTest | Level0)
{
    std::string stagedPath;
    EXPECT_EQ(PreCompressHandler::StageAgConfigFile({}, stagedPath), ERR_OK);
    EXPECT_TRUE(stagedPath.empty());

    std::string sourceDir = TEST_ROOT_DIR + "/stage_src/";
    std::string tempDir = TEST_ROOT_DIR + "/stage_temp/";
    ASSERT_TRUE(WriteBytes(sourceDir + ENTRY_ARCHIVE_NAME, entryContent_));
    ASSERT_TRUE(OHOS::ForceCreateDirectory(tempDir));
    EXPECT_EQ(PreCompressHandler::StageAgConfigFile({ { tempDir + ENTRY_HAP_NAME, sourceDir + ENTRY_ARCHIVE_NAME } },
        stagedPath), ERR_OK);
    EXPECT_TRUE(stagedPath.empty());
    EXPECT_FALSE(BundleUtil::IsExistFileNoLog(tempDir + ServiceConstants::AG_CONFIG_FILE));
}

/**
 * @tc.number: PreCompressHandler_StageAgConfigFile_0200
 * @tc.name: test StageAgConfigFile
 * @tc.desc: 1. the ag_config.json beside the archives is copied into the temp dir
 *           2. a failed copy is reported and nothing is staged
 */
HWTEST_F(BmsPreCompressHandlerTest, PreCompressHandler_StageAgConfigFile_0200, Function | SmallTest | Level0)
{
    std::string sourceDir = TEST_ROOT_DIR + "/stage_src/";
    std::string tempDir = TEST_ROOT_DIR + "/stage_temp/";
    ASSERT_TRUE(WriteBytes(sourceDir + ENTRY_ARCHIVE_NAME, entryContent_));
    ASSERT_TRUE(WriteText(sourceDir + ServiceConstants::AG_CONFIG_FILE, AG_CONFIG_CONTENT));
    ASSERT_TRUE(OHOS::ForceCreateDirectory(tempDir));

    std::string stagedPath;
    EXPECT_EQ(PreCompressHandler::StageAgConfigFile({ { tempDir + ENTRY_HAP_NAME, sourceDir + ENTRY_ARCHIVE_NAME } },
        stagedPath), ERR_OK);
    EXPECT_EQ(stagedPath, tempDir + ServiceConstants::AG_CONFIG_FILE);
    EXPECT_EQ(ReadBytes(stagedPath), std::vector<uint8_t>(AG_CONFIG_CONTENT.begin(), AG_CONFIG_CONTENT.end()));

    std::string failedStagedPath;
    std::string missingTempDir = TEST_ROOT_DIR + "/stage_missing/";
    EXPECT_EQ(PreCompressHandler::StageAgConfigFile(
        { { missingTempDir + ENTRY_HAP_NAME, sourceDir + ENTRY_ARCHIVE_NAME } }, failedStagedPath),
        ERR_APPEXECFWK_INSTALL_COPY_HAP_FAILED);
    EXPECT_TRUE(failedStagedPath.empty());
}

/**
 * @tc.number: ScopedDecompressedHap_0100
 * @tc.name: test ScopedDecompressedHap
 * @tc.desc: 1. a plain package is used as it is and nothing is created
 */
HWTEST_F(BmsPreCompressHandlerTest, ScopedDecompressedHap_0100, Function | SmallTest | Level0)
{
    std::string plainHap = VIRTUAL_BUNDLE_DIR + ServiceConstants::PATH_SEPARATOR + ENTRY_HAP_NAME;
    ScopedDecompressedHap scopedHap(plainHap);
    EXPECT_TRUE(scopedHap.IsValid());
    EXPECT_EQ(scopedHap.GetHapPath(), plainHap);
    EXPECT_TRUE(scopedHap.toDeletePaths_.empty());
    EXPECT_TRUE(installdProxy_->mkdirDirs.empty());
}

/**
 * @tc.number: ScopedDecompressedHap_0200
 * @tc.name: test ScopedDecompressedHap
 * @tc.desc: 1. an archive is decompressed for the scope and its temp dir is deleted with the scope
 */
HWTEST_F(BmsPreCompressHandlerTest, ScopedDecompressedHap_0200, Function | SmallTest | Level0)
{
    ASSERT_TRUE(PrepareArchive(ENTRY_ARCHIVE_NAME, entryContent_, true));
    std::vector<std::string> tempDirs;
    {
        ScopedDecompressedHap scopedHap(VirtualArchive(ENTRY_ARCHIVE_NAME));
        EXPECT_TRUE(scopedHap.IsValid());
        EXPECT_TRUE(BundleUtil::EndWith(scopedHap.GetHapPath(), ENTRY_HAP_NAME));
        EXPECT_EQ(ReadBytes(scopedHap.GetHapPath()), entryContent_);
        tempDirs = scopedHap.toDeletePaths_;
        ASSERT_EQ(tempDirs.size(), 1U);
        EXPECT_TRUE(BundleUtil::IsExistDirNoLog(tempDirs[0]));
    }
    EXPECT_FALSE(BundleUtil::IsExistDirNoLog(tempDirs[0]));
}

/**
 * @tc.number: ScopedDecompressedHap_0300
 * @tc.name: test ScopedDecompressedHap
 * @tc.desc: 1. an archive that can not be decompressed gives no hap and its temp dir is still deleted
 */
HWTEST_F(BmsPreCompressHandlerTest, ScopedDecompressedHap_0300, Function | SmallTest | Level0)
{
    std::string outsideArchive = TEST_ROOT_DIR + "/outside/" + ENTRY_ARCHIVE_NAME;
    ASSERT_TRUE(WriteBytes(outsideArchive, MockZstd::BuildRawFrame(entryContent_, true)));
    std::vector<std::string> tempDirs;
    {
        ScopedDecompressedHap scopedHap(outsideArchive);
        EXPECT_FALSE(scopedHap.IsValid());
        EXPECT_TRUE(scopedHap.GetHapPath().empty());
        tempDirs = scopedHap.toDeletePaths_;
        ASSERT_EQ(tempDirs.size(), 1U);
        EXPECT_TRUE(BundleUtil::IsExistDirNoLog(tempDirs[0]));
    }
    EXPECT_FALSE(BundleUtil::IsExistDirNoLog(tempDirs[0]));
}
}  // namespace OHOS
