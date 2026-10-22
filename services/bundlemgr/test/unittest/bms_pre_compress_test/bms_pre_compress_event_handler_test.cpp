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

#include <dirent.h>
#include <fstream>
#include <iterator>
#include <limits>
#include <map>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#include "directory_ex.h"
#include "iremote_proxy.h"
#include "mock_pre_compress_hooks.h"
#include "mock_zstd.h"
#define private public
#include "bundle_data_mgr.h"
#include "bundle_mgr_host_impl.h"
#include "bundle_mgr_service.h"
#include "bundle_mgr_service_event_handler.h"
#include "installd_client.h"
#include "single_delayed_task_mgr.h"
#include "zstd_wrapper.h"
#undef private
#include "bundle_constants.h"
#include "bundle_service_constants.h"
#include "bundle_util.h"
#include "inner_bundle_info.h"
#include "pre_compress_handler.h"
#include "pre_install_bundle_info.h"
#include "preinstall_data_storage_interface.h"

using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using OHOS::DelayedSingleton;

// The cases run the event handler and the host impl on compressed preloads. The preload image dir /preload/app/ is
// served from a test dir and libzstd from MockZstd, through the hooks pre_compress_handler.cpp is compiled with.
namespace OHOS {
namespace {
const std::string TEST_ROOT_DIR = "/data/test/bms_pre_compress_event_handler_test";
const std::string TEST_PRELOAD_ROOT = TEST_ROOT_DIR + "/root";
const std::string PROFILE_DIR = TEST_ROOT_DIR + "/profile";
const std::string RESET_PROFILE_DIR = TEST_ROOT_DIR + "/reset_profile";
const std::string INSTALL_LIST_FILE = "/install_list.json";
const std::string RIGHT_HAP_PATH = "/data/test/resource/bms/pre_compress/right.hap";
const std::string RIGHT_BUNDLE_NAME = "com.example.l3jsdemo";
const std::string IMAGE_BUNDLE_DIR = "/preload/app/com.example.precompress.handler";
const std::string IMAGE_EMPTY_DIR = "/preload/app/com.example.precompress.empty";
const std::string IMAGE_MISSING_DIR = "/preload/app/com.example.precompress.missing";
const std::string IMAGE_PLAIN_DIR = "/preload/app/com.example.precompress.plain";
const std::string IMAGE_OTHER_DIR = "/preload/app/com.example.precompress.other";
const std::string ON_DEMAND_DIR = "/preload/app/com.example.precompress.ondemand";
const std::string ON_DEMAND_PLAIN_DIR = "/preload/app/com.example.precompress.ondemand.plain";
const std::string ENTRY_ARCHIVE_NAME = "entry.hap.zst";
const std::string BROKEN_ARCHIVE_NAME = "broken.hap.zst";
const std::string GARBAGE_ARCHIVE_NAME = "garbage.hap.zst";
const std::string MISSING_HAP_PATH = TEST_ROOT_DIR + "/missing/entry.hap";
const std::string SECURITY_DIR = std::string(ServiceConstants::HAP_COPY_PATH) +
    ServiceConstants::PATH_SEPARATOR + ServiceConstants::SECURITY_STREAM_INSTALL_PATH;
const std::string TEMP_DIR_PREFIX = "pre_compress_";
const std::string BROKEN_BUNDLE_NAME = "com.example.precompress.broken";
const std::string MISSING_BUNDLE_NAME = "com.example.precompress.missing";
const std::string UNINSTALL_BUNDLE_NAME = "com.example.precompress.uninstall";
const std::string TEST_MODULE_NAME = "entry";
const std::string SENTINEL_MODULE_NAME = "sentinelModule";
constexpr const char* TEST_UNLOAD_TASK_NAME = "BmsPreCompressEventHandlerTestUnloadTask";
// the unload task of the suite never fires while the cases run
constexpr uint64_t TEST_LONG_UNLOAD_DELAY_MS = 24 * 60 * 60 * 1000;
constexpr uint32_t SENTINEL_RESOURCE_ID = std::numeric_limits<uint32_t>::max();
constexpr int32_t TEST_USER_ID = 100;
constexpr size_t TEST_STREAM_BUFFER_SIZE = 64 * 1024;
constexpr size_t GARBAGE_CONTENT_SIZE = 512;
constexpr uint8_t GARBAGE_SEED = 7;

std::shared_ptr<SingleDelayedTaskMgr> g_originalUnloadTaskMgr = nullptr;
std::shared_ptr<SingleDelayedTaskMgr> g_suiteUnloadTaskMgr = nullptr;

class EventHandlerInstalldProxy : public IRemoteProxy<IInstalld> {
public:
    EventHandlerInstalldProxy() : IRemoteProxy<IInstalld>(nullptr) {}

    ErrCode Mkdir(const std::string &dir, const int32_t mode, const int32_t uid, const int32_t gid,
        const CreateDirParam &createDirParam) override
    {
        mkdirDirs.emplace_back(dir);
        // create the dir the way installd does
        if (!BundleUtil::IsExistDirNoLog(dir) &&
            ((mkdir(dir.c_str(), static_cast<mode_t>(mode)) != 0) || (chown(dir.c_str(), uid, gid) != 0))) {
            return ERR_APPEXECFWK_INSTALLD_MKDIR_FAILED;
        }
        return ERR_OK;
    }

    std::vector<std::string> mkdirDirs;
};

// keeps the preinstall records of a case in memory, away from the preinstall db of the device
class MemoryPreInstallDataStorage : public IPreInstallDataStorage {
public:
    bool SavePreInstallStorageBundleInfo(const PreInstallBundleInfo &preInstallBundleInfo) override
    {
        infos[preInstallBundleInfo.GetBundleName()] = preInstallBundleInfo;
        return true;
    }

    bool LoadAllPreInstallBundleInfos(std::vector<PreInstallBundleInfo> &preInstallBundleInfos) override
    {
        for (const auto &item : infos) {
            preInstallBundleInfos.emplace_back(item.second);
        }
        return true;
    }

    bool DeletePreInstallStorageBundleInfo(const PreInstallBundleInfo &preInstallBundleInfo) override
    {
        return infos.erase(preInstallBundleInfo.GetBundleName()) > 0;
    }

    bool LoadPreInstallBundleInfo(const std::string &bundleName, PreInstallBundleInfo &preInstallBundleInfo) override
    {
        auto iter = infos.find(bundleName);
        if (iter == infos.end()) {
            return false;
        }
        preInstallBundleInfo = iter->second;
        return true;
    }

    std::map<std::string, PreInstallBundleInfo> infos;
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

std::string ImageArchive(const std::string &name)
{
    return IMAGE_BUNDLE_DIR + ServiceConstants::PATH_SEPARATOR + name;
}

std::string AppDirItem(const std::string &appDir, const std::string &compressed)
{
    std::string item = "{\"app_dir\":\"" + appDir + "\"";
    if (!compressed.empty()) {
        item += ",\"compressed\":" + compressed;
    }
    return item + "}";
}

// the preload dirs of the install list and the on demand install list, a parsed dir replaces the same dir parsed
// before, so parsing the list again with compressed false declares every dir plain again
std::string BuildInstallListConfig(bool compressed)
{
    std::string flag = compressed ? "true" : "false";
    return "{\"install_list\":[" + AppDirItem(IMAGE_BUNDLE_DIR, flag) + "," +
        AppDirItem(IMAGE_EMPTY_DIR, flag) + "," + AppDirItem(IMAGE_MISSING_DIR, flag) + "," +
        AppDirItem(IMAGE_PLAIN_DIR, "false") + "],\"on_demand_install_list\":[" +
        AppDirItem(ON_DEMAND_DIR, flag) + "," + AppDirItem(ON_DEMAND_PLAIN_DIR, "") + "]}";
}

size_t CountDecompressTempDirs()
{
    DIR *dir = opendir(SECURITY_DIR.c_str());
    if (dir == nullptr) {
        return 0;
    }
    size_t count = 0;
    struct dirent *entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        if (std::string(entry->d_name).compare(0, TEMP_DIR_PREFIX.size(), TEMP_DIR_PREFIX) == 0) {
            ++count;
        }
    }
    closedir(dir);
    return count;
}

void ResetZstdWrapper()
{
    ZstdWrapper &zstd = ZstdWrapper::GetInstance();
    std::lock_guard<std::mutex> lock(zstd.mutex_);
    zstd.handle_ = nullptr;
    zstd.refCount_ = 0;
    zstd.api_ = ZstdWrapper::ZstdApi();
}

PreInstallBundleInfo MakePreInstallInfo(const std::string &bundleName, const std::string &bundlePath)
{
    PreInstallBundleInfo preInstallBundleInfo;
    preInstallBundleInfo.SetBundleName(bundleName);
    preInstallBundleInfo.AddBundlePath(bundlePath);
    preInstallBundleInfo.SetLabelId(SENTINEL_RESOURCE_ID);
    preInstallBundleInfo.SetIconId(SENTINEL_RESOURCE_ID);
    preInstallBundleInfo.SetDescriptionId(SENTINEL_RESOURCE_ID);
    preInstallBundleInfo.SetModuleName(SENTINEL_MODULE_NAME);
    return preInstallBundleInfo;
}

bool IsSentinelResource(const PreInstallBundleInfo &preInstallBundleInfo)
{
    return (preInstallBundleInfo.GetLabelId() == SENTINEL_RESOURCE_ID) &&
        (preInstallBundleInfo.GetIconId() == SENTINEL_RESOURCE_ID) &&
        (preInstallBundleInfo.GetDescriptionId() == SENTINEL_RESOURCE_ID) &&
        (preInstallBundleInfo.GetModuleName() == SENTINEL_MODULE_NAME);
}

InnerBundleInfo MakeParsedInfo(const std::string &bundleName)
{
    ApplicationInfo applicationInfo;
    applicationInfo.bundleName = bundleName;
    InnerBundleInfo innerBundleInfo;
    innerBundleInfo.SetBaseApplicationInfo(applicationInfo);
    return innerBundleInfo;
}

// a preinstalled bundle whose hap sits in the code dir, as a compressed preload or an updated bundle does
InnerBundleInfo MakeInstalledInfo(const std::string &bundleName, bool isCompressedPreload, bool withUser)
{
    InnerBundleInfo innerBundleInfo = MakeParsedInfo(bundleName);
    BundleInfo bundleInfo;
    bundleInfo.name = bundleName;
    bundleInfo.isPreInstallApp = true;
    innerBundleInfo.SetBaseBundleInfo(bundleInfo);
    innerBundleInfo.SetCompressedPreload(isCompressedPreload);
    InnerModuleInfo moduleInfo;
    moduleInfo.name = TEST_MODULE_NAME;
    moduleInfo.moduleName = TEST_MODULE_NAME;
    moduleInfo.modulePackage = TEST_MODULE_NAME;
    moduleInfo.hapPath = std::string(Constants::BUNDLE_CODE_DIR) + ServiceConstants::PATH_SEPARATOR + bundleName +
        ServiceConstants::PATH_SEPARATOR + TEST_MODULE_NAME + ServiceConstants::INSTALL_FILE_SUFFIX;
    innerBundleInfo.InsertInnerModuleInfo(TEST_MODULE_NAME, moduleInfo);
    if (withUser) {
        InnerBundleUserInfo userInfo;
        userInfo.bundleName = bundleName;
        userInfo.bundleUserInfo.userId = TEST_USER_ID;
        userInfo.bundleUserInfo.enabled = true;
        innerBundleInfo.AddInnerBundleUserInfo(userInfo);
    }
    return innerBundleInfo;
}
}  // namespace

class BmsPreCompressEventHandlerTest : public testing::Test {
public:
    BmsPreCompressEventHandlerTest();
    ~BmsPreCompressEventHandlerTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
    bool PrepareImageArchive(const std::string &imageDir, const std::string &name,
        const std::vector<uint8_t> &content) const;
    bool PrepareBrokenImageArchive(const std::string &name) const;
    bool RegisterCompressedPreloadDirs() const;
    void ResetPreloadDirs() const;
    bool GetRightArchiveInfo(BundleInfo &bundleInfo) const;

    std::string preloadRoot_;
    bool securityDirExisted_ = false;
    std::vector<uint8_t> rightHapContent_;
    std::shared_ptr<BMSEventHandler> handler_ = nullptr;
    std::shared_ptr<BundleDataMgr> dataMgr_ = nullptr;
    std::shared_ptr<BundleDataMgr> originalDataMgr_ = nullptr;
    std::shared_ptr<MemoryPreInstallDataStorage> preInstallStorage_ = nullptr;
    sptr<IInstalld> originalInstalldProxy_ = nullptr;
    sptr<EventHandlerInstalldProxy> installdProxy_ = nullptr;
};

BmsPreCompressEventHandlerTest::BmsPreCompressEventHandlerTest()
{}

BmsPreCompressEventHandlerTest::~BmsPreCompressEventHandlerTest()
{}

void BmsPreCompressEventHandlerTest::SetUpTestCase()
{
    g_originalUnloadTaskMgr = ZstdWrapper::GetInstance().unloadTaskMgr_;
    g_suiteUnloadTaskMgr = std::make_shared<SingleDelayedTaskMgr>(TEST_UNLOAD_TASK_NAME, TEST_LONG_UNLOAD_DELAY_MS);
}

void BmsPreCompressEventHandlerTest::TearDownTestCase()
{
    ZstdWrapper::GetInstance().unloadTaskMgr_ = g_originalUnloadTaskMgr;
    g_suiteUnloadTaskMgr = nullptr;
}

void BmsPreCompressEventHandlerTest::SetUp()
{
    PreCompressHook::ResetDlHooks();
    PreCompressHook::ResetIoHooks();
    MockZstd::SetStreamSizes(TEST_STREAM_BUFFER_SIZE, TEST_STREAM_BUFFER_SIZE);
    ResetZstdWrapper();
    ZstdWrapper::GetInstance().unloadTaskMgr_ = g_suiteUnloadTaskMgr;
    PreCompressHook::SetDlopenMode(PreCompressHook::DlopenMode::MOCK_LIB);

    securityDirExisted_ = BundleUtil::IsExistDirNoLog(SECURITY_DIR);
    installdProxy_ = new (std::nothrow) EventHandlerInstalldProxy();
    originalInstalldProxy_ = InstalldClient::GetInstance()->installdProxy_;
    InstalldClient::GetInstance()->installdProxy_ = installdProxy_;

    auto bundleMgrService = DelayedSingleton<BundleMgrService>::GetInstance();
    originalDataMgr_ = bundleMgrService->dataMgr_;
    dataMgr_ = std::make_shared<BundleDataMgr>();
    preInstallStorage_ = std::make_shared<MemoryPreInstallDataStorage>();
    dataMgr_->preInstallDataStorage_ = preInstallStorage_;
    bundleMgrService->dataMgr_ = dataMgr_;

    handler_ = std::make_shared<BMSEventHandler>();
    rightHapContent_ = ReadBytes(RIGHT_HAP_PATH);
    (void)OHOS::ForceRemoveDirectory(TEST_ROOT_DIR);
    ASSERT_TRUE(OHOS::ForceCreateDirectory(TEST_PRELOAD_ROOT + IMAGE_BUNDLE_DIR));
    ASSERT_TRUE(OHOS::PathToRealPath(TEST_PRELOAD_ROOT, preloadRoot_));
    PreCompressHook::SetPreloadRoot(preloadRoot_);
}

void BmsPreCompressEventHandlerTest::TearDown()
{
    ResetPreloadDirs();
    handler_ = nullptr;
    DelayedSingleton<BundleMgrService>::GetInstance()->dataMgr_ = originalDataMgr_;
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

bool BmsPreCompressEventHandlerTest::PrepareImageArchive(const std::string &imageDir, const std::string &name,
    const std::vector<uint8_t> &content) const
{
    std::string path = preloadRoot_ + imageDir + ServiceConstants::PATH_SEPARATOR + name;
    return WriteBytes(path, MockZstd::BuildRawFrame(content, true));
}

bool BmsPreCompressEventHandlerTest::PrepareBrokenImageArchive(const std::string &name) const
{
    std::string path = preloadRoot_ + IMAGE_BUNDLE_DIR + ServiceConstants::PATH_SEPARATOR + name;
    return WriteBytes(path, MockZstd::BuildReservedBlockFrame());
}

bool BmsPreCompressEventHandlerTest::RegisterCompressedPreloadDirs() const
{
    if (!WriteText(PROFILE_DIR + INSTALL_LIST_FILE, BuildInstallListConfig(true))) {
        return false;
    }
    BMSEventHandler::ParsePreBundleProFile(PROFILE_DIR);
    return true;
}

void BmsPreCompressEventHandlerTest::ResetPreloadDirs() const
{
    if (WriteText(RESET_PROFILE_DIR + INSTALL_LIST_FILE, BuildInstallListConfig(false))) {
        BMSEventHandler::ParsePreBundleProFile(RESET_PROFILE_DIR);
    }
}

bool BmsPreCompressEventHandlerTest::GetRightArchiveInfo(BundleInfo &bundleInfo) const
{
    BundleMgrHostImpl impl;
    return impl.GetBundleArchiveInfo(RIGHT_HAP_PATH, BundleFlag::GET_BUNDLE_DEFAULT, bundleInfo);
}

/**
 * @tc.number: EventHandler_IsPreInstallCompressed_0100
 * @tc.name: test IsPreInstallCompressed
 * @tc.desc: 1. a compressed archive is compressed without any configuration
 *           2. a dir is compressed only when the install list or the on demand install list marks it compressed
 *           3. a dir declared plain again is no longer compressed
 */
HWTEST_F(BmsPreCompressEventHandlerTest, EventHandler_IsPreInstallCompressed_0100, Function | SmallTest | Level0)
{
    EXPECT_TRUE(BMSEventHandler::IsPreInstallCompressed(ImageArchive(ENTRY_ARCHIVE_NAME)));
    EXPECT_FALSE(BMSEventHandler::IsPreInstallCompressed(IMAGE_BUNDLE_DIR));

    ASSERT_TRUE(RegisterCompressedPreloadDirs());
    EXPECT_TRUE(BMSEventHandler::IsPreInstallCompressed(IMAGE_BUNDLE_DIR));
    EXPECT_FALSE(BMSEventHandler::IsPreInstallCompressed(IMAGE_PLAIN_DIR));
    EXPECT_TRUE(BMSEventHandler::IsPreInstallCompressed(ON_DEMAND_DIR));
    EXPECT_FALSE(BMSEventHandler::IsPreInstallCompressed(ON_DEMAND_PLAIN_DIR));
    EXPECT_FALSE(BMSEventHandler::IsPreInstallCompressed(IMAGE_OTHER_DIR));

    ResetPreloadDirs();
    EXPECT_FALSE(BMSEventHandler::IsPreInstallCompressed(IMAGE_BUNDLE_DIR));
    EXPECT_FALSE(BMSEventHandler::IsPreInstallCompressed(ON_DEMAND_DIR));
}

/**
 * @tc.number: EventHandler_NeedProcessOtaNewPreloadInstall_0100
 * @tc.name: test NeedProcessOtaNewPreloadInstall
 * @tc.desc: 1. a compressed preload dir that can not be listed or holds no archive is not installed by OTA
 *           2. a plain preload dir that does not exist is not installed by OTA
 *           3. the whitelist makes no difference when the haps can not be found
 */
HWTEST_F(BmsPreCompressEventHandlerTest, EventHandler_NeedProcessOtaNewPreloadInstall_0100,
    Function | SmallTest | Level0)
{
    ASSERT_TRUE(RegisterCompressedPreloadDirs());
    ASSERT_TRUE(OHOS::ForceCreateDirectory(preloadRoot_ + IMAGE_EMPTY_DIR));
    handler_->otaNewInstallEnable_ = false;
    handler_->otaNewInstallWhitelist_.insert(RIGHT_BUNDLE_NAME);

    EXPECT_FALSE(handler_->NeedProcessOtaNewPreloadInstall(RIGHT_BUNDLE_NAME, IMAGE_MISSING_DIR));
    EXPECT_FALSE(handler_->NeedProcessOtaNewPreloadInstall(RIGHT_BUNDLE_NAME, IMAGE_EMPTY_DIR));
    EXPECT_FALSE(handler_->NeedProcessOtaNewPreloadInstall(RIGHT_BUNDLE_NAME, IMAGE_PLAIN_DIR));
    EXPECT_TRUE(installdProxy_->mkdirDirs.empty());
}

/**
 * @tc.number: EventHandler_NeedProcessOtaNewPreloadInstall_0200
 * @tc.name: test NeedProcessOtaNewPreloadInstall
 * @tc.desc: 1. the hap of a compressed preload dir is decompressed to read its desktop icon capability
 *           2. a hap that shows its desktop icon still needs the whitelist
 *           3. the decompressed hap is removed after the check
 */
HWTEST_F(BmsPreCompressEventHandlerTest, EventHandler_NeedProcessOtaNewPreloadInstall_0200,
    Function | SmallTest | Level0)
{
    ASSERT_FALSE(rightHapContent_.empty());
    ASSERT_TRUE(PrepareImageArchive(IMAGE_BUNDLE_DIR, ENTRY_ARCHIVE_NAME, rightHapContent_));
    ASSERT_TRUE(RegisterCompressedPreloadDirs());
    handler_->otaNewInstallEnable_ = false;
    size_t tempDirCount = CountDecompressTempDirs();

    EXPECT_FALSE(handler_->NeedProcessOtaNewPreloadInstall(RIGHT_BUNDLE_NAME, IMAGE_BUNDLE_DIR));
    EXPECT_FALSE(installdProxy_->mkdirDirs.empty());
    EXPECT_EQ(CountDecompressTempDirs(), tempDirCount);

    handler_->otaNewInstallWhitelist_.insert(RIGHT_BUNDLE_NAME);
    EXPECT_TRUE(handler_->NeedProcessOtaNewPreloadInstall(RIGHT_BUNDLE_NAME, IMAGE_BUNDLE_DIR));
    EXPECT_EQ(CountDecompressTempDirs(), tempDirCount);
}

/**
 * @tc.number: EventHandler_NeedProcessOtaNewPreloadInstall_0300
 * @tc.name: test NeedProcessOtaNewPreloadInstall
 * @tc.desc: 1. a compressed preload whose archive is broken still needs the whitelist
 *           2. a compressed preload whose archive does not hold a hap still needs the whitelist
 */
HWTEST_F(BmsPreCompressEventHandlerTest, EventHandler_NeedProcessOtaNewPreloadInstall_0300,
    Function | SmallTest | Level0)
{
    ASSERT_TRUE(RegisterCompressedPreloadDirs());
    handler_->otaNewInstallEnable_ = false;
    std::string brokenArchive = preloadRoot_ + ImageArchive(BROKEN_ARCHIVE_NAME);
    ASSERT_TRUE(PrepareBrokenImageArchive(BROKEN_ARCHIVE_NAME));
    EXPECT_FALSE(handler_->NeedProcessOtaNewPreloadInstall(RIGHT_BUNDLE_NAME, IMAGE_BUNDLE_DIR));
    handler_->otaNewInstallWhitelist_.insert(RIGHT_BUNDLE_NAME);
    EXPECT_TRUE(handler_->NeedProcessOtaNewPreloadInstall(RIGHT_BUNDLE_NAME, IMAGE_BUNDLE_DIR));
    ASSERT_EQ(unlink(brokenArchive.c_str()), 0);

    handler_->otaNewInstallWhitelist_.clear();
    ASSERT_TRUE(PrepareImageArchive(IMAGE_BUNDLE_DIR, GARBAGE_ARCHIVE_NAME,
        MockZstd::MakeContent(GARBAGE_CONTENT_SIZE, GARBAGE_SEED)));
    EXPECT_FALSE(handler_->NeedProcessOtaNewPreloadInstall(RIGHT_BUNDLE_NAME, IMAGE_BUNDLE_DIR));
    handler_->otaNewInstallWhitelist_.insert(RIGHT_BUNDLE_NAME);
    EXPECT_TRUE(handler_->NeedProcessOtaNewPreloadInstall(RIGHT_BUNDLE_NAME, IMAGE_BUNDLE_DIR));
}

/**
 * @tc.number: EventHandler_ParseHapFiles_0100
 * @tc.name: test ParseHapFiles
 * @tc.desc: 1. a compressed archive is parsed after decompressing and keyed by the archive
 *           2. a compressed preload dir is parsed the same way
 *           3. the decompressed haps are removed after parsing
 */
HWTEST_F(BmsPreCompressEventHandlerTest, EventHandler_ParseHapFiles_0100, Function | SmallTest | Level0)
{
    ASSERT_FALSE(rightHapContent_.empty());
    ASSERT_TRUE(PrepareImageArchive(IMAGE_BUNDLE_DIR, ENTRY_ARCHIVE_NAME, rightHapContent_));
    size_t tempDirCount = CountDecompressTempDirs();

    std::unordered_map<std::string, InnerBundleInfo> archiveInfos;
    EXPECT_TRUE(BMSEventHandler::ParseHapFiles(ImageArchive(ENTRY_ARCHIVE_NAME), archiveInfos));
    ASSERT_EQ(archiveInfos.size(), 1U);
    EXPECT_EQ(archiveInfos.begin()->first, ImageArchive(ENTRY_ARCHIVE_NAME));
    EXPECT_EQ(archiveInfos.begin()->second.GetBundleName(), RIGHT_BUNDLE_NAME);
    EXPECT_EQ(CountDecompressTempDirs(), tempDirCount);

    ASSERT_TRUE(RegisterCompressedPreloadDirs());
    std::unordered_map<std::string, InnerBundleInfo> dirInfos;
    EXPECT_TRUE(BMSEventHandler::ParseHapFiles(IMAGE_BUNDLE_DIR, dirInfos));
    ASSERT_EQ(dirInfos.size(), 1U);
    EXPECT_EQ(dirInfos.begin()->first, ImageArchive(ENTRY_ARCHIVE_NAME));
    EXPECT_EQ(dirInfos.begin()->second.GetBundleName(), RIGHT_BUNDLE_NAME);
    EXPECT_EQ(CountDecompressTempDirs(), tempDirCount);
}

/**
 * @tc.number: EventHandler_ParseHapFiles_0200
 * @tc.name: test ParseHapFiles
 * @tc.desc: 1. a plain path that does not exist is not parsed
 *           2. a compressed preload dir that does not exist is not parsed
 *           3. an archive that does not hold a hap gives nothing
 */
HWTEST_F(BmsPreCompressEventHandlerTest, EventHandler_ParseHapFiles_0200, Function | SmallTest | Level0)
{
    std::unordered_map<std::string, InnerBundleInfo> infos;
    EXPECT_FALSE(BMSEventHandler::ParseHapFiles(MISSING_HAP_PATH, infos));

    ASSERT_TRUE(RegisterCompressedPreloadDirs());
    EXPECT_FALSE(BMSEventHandler::ParseHapFiles(IMAGE_MISSING_DIR, infos));

    ASSERT_TRUE(PrepareImageArchive(IMAGE_BUNDLE_DIR, GARBAGE_ARCHIVE_NAME,
        MockZstd::MakeContent(GARBAGE_CONTENT_SIZE, GARBAGE_SEED)));
    EXPECT_FALSE(BMSEventHandler::ParseHapFiles(ImageArchive(GARBAGE_ARCHIVE_NAME), infos));
    EXPECT_TRUE(infos.empty());
}

/**
 * @tc.number: EventHandler_ParseOnDemandHapFiles_0100
 * @tc.name: test ParseOnDemandHapFiles
 * @tc.desc: 1. a plain path that does not exist is not parsed
 *           2. a compressed archive is verified and parsed after decompressing, keyed by the archive
 */
HWTEST_F(BmsPreCompressEventHandlerTest, EventHandler_ParseOnDemandHapFiles_0100, Function | SmallTest | Level0)
{
    std::vector<Security::Verify::HapVerifyResult> missingResults;
    std::unordered_map<std::string, InnerBundleInfo> missingInfos;
    EXPECT_FALSE(handler_->ParseOnDemandHapFiles(MISSING_HAP_PATH, missingResults, missingInfos));
    EXPECT_TRUE(missingInfos.empty());

    ASSERT_FALSE(rightHapContent_.empty());
    ASSERT_TRUE(PrepareImageArchive(IMAGE_BUNDLE_DIR, ENTRY_ARCHIVE_NAME, rightHapContent_));
    size_t tempDirCount = CountDecompressTempDirs();
    std::vector<Security::Verify::HapVerifyResult> hapVerifyResults;
    std::unordered_map<std::string, InnerBundleInfo> infos;
    EXPECT_TRUE(handler_->ParseOnDemandHapFiles(ImageArchive(ENTRY_ARCHIVE_NAME), hapVerifyResults, infos));
    EXPECT_EQ(hapVerifyResults.size(), 1U);
    ASSERT_EQ(infos.size(), 1U);
    EXPECT_EQ(infos.begin()->first, ImageArchive(ENTRY_ARCHIVE_NAME));
    EXPECT_EQ(infos.begin()->second.GetBundleName(), RIGHT_BUNDLE_NAME);
    EXPECT_EQ(CountDecompressTempDirs(), tempDirCount);
}

/**
 * @tc.number: EventHandler_InnerProcessCheckPreinstallData_0100
 * @tc.name: test InnerProcessCheckPreinstallData
 * @tc.desc: 1. the resource ids of a compressed preload are read from its decompressed hap
 *           2. a broken archive or a missing hap leaves the record as it is
 */
HWTEST_F(BmsPreCompressEventHandlerTest, EventHandler_InnerProcessCheckPreinstallData_0100,
    Function | SmallTest | Level0)
{
    ASSERT_FALSE(rightHapContent_.empty());
    ASSERT_TRUE(PrepareImageArchive(IMAGE_BUNDLE_DIR, ENTRY_ARCHIVE_NAME, rightHapContent_));
    ASSERT_TRUE(PrepareBrokenImageArchive(BROKEN_ARCHIVE_NAME));
    BundleInfo expected;
    ASSERT_TRUE(GetRightArchiveInfo(expected));
    preInstallStorage_->infos[RIGHT_BUNDLE_NAME] =
        MakePreInstallInfo(RIGHT_BUNDLE_NAME, ImageArchive(ENTRY_ARCHIVE_NAME));
    preInstallStorage_->infos[BROKEN_BUNDLE_NAME] =
        MakePreInstallInfo(BROKEN_BUNDLE_NAME, ImageArchive(BROKEN_ARCHIVE_NAME));
    preInstallStorage_->infos[MISSING_BUNDLE_NAME] = MakePreInstallInfo(MISSING_BUNDLE_NAME, MISSING_HAP_PATH);
    size_t tempDirCount = CountDecompressTempDirs();

    handler_->InnerProcessCheckPreinstallData();
    const PreInstallBundleInfo &rightInfo = preInstallStorage_->infos[RIGHT_BUNDLE_NAME];
    EXPECT_EQ(rightInfo.GetLabelId(), expected.applicationInfo.labelResource.id);
    EXPECT_EQ(rightInfo.GetIconId(), expected.applicationInfo.iconResource.id);
    EXPECT_EQ(rightInfo.GetDescriptionId(), expected.applicationInfo.descriptionId);
    EXPECT_EQ(rightInfo.GetModuleName(), expected.applicationInfo.labelResource.moduleName);
    EXPECT_TRUE(IsSentinelResource(preInstallStorage_->infos[BROKEN_BUNDLE_NAME]));
    EXPECT_TRUE(IsSentinelResource(preInstallStorage_->infos[MISSING_BUNDLE_NAME]));
    EXPECT_EQ(CountDecompressTempDirs(), tempDirCount);
}

/**
 * @tc.number: EventHandler_InnerProcessCheckRecoverableApplicationInfo_0100
 * @tc.name: test InnerProcessCheckRecoverableApplicationInfo
 * @tc.desc: 1. the system app flag and the bundle type of a compressed preload are read from its decompressed hap
 *           2. a broken archive or a missing hap leaves the record as it is
 */
HWTEST_F(BmsPreCompressEventHandlerTest, EventHandler_InnerProcessCheckRecoverableApplicationInfo_0100,
    Function | SmallTest | Level0)
{
    ASSERT_FALSE(rightHapContent_.empty());
    ASSERT_TRUE(PrepareImageArchive(IMAGE_BUNDLE_DIR, ENTRY_ARCHIVE_NAME, rightHapContent_));
    ASSERT_TRUE(PrepareBrokenImageArchive(BROKEN_ARCHIVE_NAME));
    BundleInfo expected;
    ASSERT_TRUE(GetRightArchiveInfo(expected));
    ASSERT_TRUE(expected.isNewVersion);
    bool presetSystemApp = !expected.applicationInfo.isSystemApp;
    BundleType presetBundleType = (expected.applicationInfo.bundleType == BundleType::APP) ?
        BundleType::ATOMIC_SERVICE : BundleType::APP;
    std::vector<std::pair<std::string, std::string>> records = {
        { RIGHT_BUNDLE_NAME, ImageArchive(ENTRY_ARCHIVE_NAME) },
        { BROKEN_BUNDLE_NAME, ImageArchive(BROKEN_ARCHIVE_NAME) },
        { MISSING_BUNDLE_NAME, MISSING_HAP_PATH },
    };
    for (const auto &[bundleName, bundlePath] : records) {
        PreInstallBundleInfo preInstallBundleInfo = MakePreInstallInfo(bundleName, bundlePath);
        preInstallBundleInfo.SetSystemApp(presetSystemApp);
        preInstallBundleInfo.SetBundleType(presetBundleType);
        preInstallStorage_->infos[bundleName] = preInstallBundleInfo;
    }

    handler_->InnerProcessCheckRecoverableApplicationInfo();
    EXPECT_EQ(preInstallStorage_->infos[RIGHT_BUNDLE_NAME].GetSystemApp(), expected.applicationInfo.isSystemApp);
    EXPECT_EQ(preInstallStorage_->infos[RIGHT_BUNDLE_NAME].GetBundleType(), expected.applicationInfo.bundleType);
    for (const auto &bundleName : { BROKEN_BUNDLE_NAME, MISSING_BUNDLE_NAME }) {
        EXPECT_EQ(preInstallStorage_->infos[bundleName].GetSystemApp(), presetSystemApp);
        EXPECT_EQ(preInstallStorage_->infos[bundleName].GetBundleType(), presetBundleType);
    }
}

/**
 * @tc.number: BundleMgrHostImpl_GetPreferableBundleInfoFromHapPaths_0100
 * @tc.name: test GetPreferableBundleInfoFromHapPaths
 * @tc.desc: 1. a broken archive or a missing hap gives no bundle info
 *           2. the bundle info of a compressed archive is read from its decompressed hap
 *           3. the hap path in the bundle info stays the archive under the image
 */
HWTEST_F(BmsPreCompressEventHandlerTest, BundleMgrHostImpl_GetPreferableBundleInfoFromHapPaths_0100,
    Function | SmallTest | Level0)
{
    ASSERT_TRUE(PrepareBrokenImageArchive(BROKEN_ARCHIVE_NAME));
    BundleMgrHostImpl impl;
    BundleInfo brokenInfo;
    EXPECT_FALSE(impl.GetPreferableBundleInfoFromHapPaths({ ImageArchive(BROKEN_ARCHIVE_NAME) }, brokenInfo));
    BundleInfo missingInfo;
    EXPECT_FALSE(impl.GetPreferableBundleInfoFromHapPaths({ MISSING_HAP_PATH }, missingInfo));

    ASSERT_FALSE(rightHapContent_.empty());
    ASSERT_TRUE(PrepareImageArchive(IMAGE_BUNDLE_DIR, ENTRY_ARCHIVE_NAME, rightHapContent_));
    size_t tempDirCount = CountDecompressTempDirs();
    BundleInfo bundleInfo;
    EXPECT_TRUE(impl.GetPreferableBundleInfoFromHapPaths({ ImageArchive(ENTRY_ARCHIVE_NAME) }, bundleInfo));
    EXPECT_EQ(bundleInfo.name, RIGHT_BUNDLE_NAME);
    ASSERT_FALSE(bundleInfo.hapModuleInfos.empty());
    EXPECT_EQ(bundleInfo.hapModuleInfos[0].hapPath, ImageArchive(ENTRY_ARCHIVE_NAME));
    EXPECT_EQ(CountDecompressTempDirs(), tempDirCount);
}

/**
 * @tc.number: EventHandler_UpdatePreinstallDBForNotUpdatedBundle_0100
 * @tc.name: test UpdatePreinstallDBForNotUpdatedBundle
 * @tc.desc: 1. the record is marked compressed when the scanned paths are compressed archives
 *           2. the record is marked plain again when the scanned paths are plain haps
 */
HWTEST_F(BmsPreCompressEventHandlerTest, EventHandler_UpdatePreinstallDBForNotUpdatedBundle_0100,
    Function | SmallTest | Level0)
{
    preInstallStorage_->infos[RIGHT_BUNDLE_NAME] = MakePreInstallInfo(RIGHT_BUNDLE_NAME, MISSING_HAP_PATH);
    std::unordered_map<std::string, InnerBundleInfo> archiveInfos = {
        { ImageArchive(ENTRY_ARCHIVE_NAME), MakeParsedInfo(RIGHT_BUNDLE_NAME) }
    };
    handler_->UpdatePreinstallDBForNotUpdatedBundle(RIGHT_BUNDLE_NAME, archiveInfos);
    EXPECT_TRUE(preInstallStorage_->infos[RIGHT_BUNDLE_NAME].IsCompressed());
    EXPECT_EQ(preInstallStorage_->infos[RIGHT_BUNDLE_NAME].GetBundlePaths(),
        std::vector<std::string> { ImageArchive(ENTRY_ARCHIVE_NAME) });

    std::unordered_map<std::string, InnerBundleInfo> plainInfos = {
        { MISSING_HAP_PATH, MakeParsedInfo(RIGHT_BUNDLE_NAME) }
    };
    handler_->UpdatePreinstallDBForNotUpdatedBundle(RIGHT_BUNDLE_NAME, plainInfos);
    EXPECT_FALSE(preInstallStorage_->infos[RIGHT_BUNDLE_NAME].IsCompressed());
    EXPECT_EQ(preInstallStorage_->infos[RIGHT_BUNDLE_NAME].GetBundlePaths(),
        std::vector<std::string> { MISSING_HAP_PATH });
}

/**
 * @tc.number: EventHandler_ConvertToOnDemandInstallBundleInfo_0100
 * @tc.name: test ConvertToOnDemandInstallBundleInfo
 * @tc.desc: 1. an on demand bundle parsed from compressed archives is recorded compressed
 *           2. an on demand bundle parsed from plain haps is recorded plain
 */
HWTEST_F(BmsPreCompressEventHandlerTest, EventHandler_ConvertToOnDemandInstallBundleInfo_0100,
    Function | SmallTest | Level0)
{
    std::unordered_map<std::string, InnerBundleInfo> archiveInfos = {
        { ImageArchive(ENTRY_ARCHIVE_NAME), MakeParsedInfo(RIGHT_BUNDLE_NAME) }
    };
    PreInstallBundleInfo archiveRecord;
    handler_->ConvertToOnDemandInstallBundleInfo(archiveInfos, archiveRecord);
    EXPECT_EQ(archiveRecord.GetBundleName(), RIGHT_BUNDLE_NAME);
    EXPECT_TRUE(archiveRecord.IsCompressed());
    EXPECT_EQ(archiveRecord.GetBundlePaths(), std::vector<std::string> { ImageArchive(ENTRY_ARCHIVE_NAME) });

    std::unordered_map<std::string, InnerBundleInfo> plainInfos = {
        { MISSING_HAP_PATH, MakeParsedInfo(RIGHT_BUNDLE_NAME) }
    };
    PreInstallBundleInfo plainRecord;
    handler_->ConvertToOnDemandInstallBundleInfo(plainInfos, plainRecord);
    EXPECT_FALSE(plainRecord.IsCompressed());
    EXPECT_EQ(plainRecord.GetBundlePaths(), std::vector<std::string> { MISSING_HAP_PATH });
}

/**
 * @tc.number: EventHandler_ProcessRecoverList_0100
 * @tc.name: test ProcessRecoverList
 * @tc.desc: 1. the recovered bundle is recorded compressed when its paths are compressed archives
 *           2. the recovered bundle is recorded plain when its paths are plain haps
 */
HWTEST_F(BmsPreCompressEventHandlerTest, EventHandler_ProcessRecoverList_0100, Function | SmallTest | Level0)
{
    std::vector<int32_t> noUserIds;
    std::unordered_map<std::string, InnerBundleInfo> archiveInfos = {
        { ImageArchive(ENTRY_ARCHIVE_NAME), MakeParsedInfo(RIGHT_BUNDLE_NAME) }
    };
    handler_->ProcessRecoverList(RIGHT_BUNDLE_NAME, ImageArchive(ENTRY_ARCHIVE_NAME), true,
        Constants::AppType::SYSTEM_APP, noUserIds, archiveInfos);
    ASSERT_EQ(preInstallStorage_->infos.count(RIGHT_BUNDLE_NAME), 1U);
    EXPECT_TRUE(preInstallStorage_->infos[RIGHT_BUNDLE_NAME].IsCompressed());
    EXPECT_TRUE(preInstallStorage_->infos[RIGHT_BUNDLE_NAME].IsUninstalled());

    std::unordered_map<std::string, InnerBundleInfo> plainInfos = {
        { MISSING_HAP_PATH, MakeParsedInfo(RIGHT_BUNDLE_NAME) }
    };
    handler_->ProcessRecoverList(RIGHT_BUNDLE_NAME, MISSING_HAP_PATH, true,
        Constants::AppType::SYSTEM_APP, noUserIds, plainInfos);
    EXPECT_FALSE(preInstallStorage_->infos[RIGHT_BUNDLE_NAME].IsCompressed());
    EXPECT_TRUE(preInstallStorage_->infos[RIGHT_BUNDLE_NAME].IsUninstalled());
}

/**
 * @tc.number: EventHandler_ProcessRebootBundleUninstall_0100
 * @tc.name: test ProcessRebootBundleUninstall
 * @tc.desc: 1. a plain preload gone from the image whose hap is in the code dir is kept as an updated bundle,
 *              it is no longer a preinstall bundle and its preinstall record is removed
 */
HWTEST_F(BmsPreCompressEventHandlerTest, EventHandler_ProcessRebootBundleUninstall_0100,
    Function | SmallTest | Level0)
{
    InnerBundleInfo installedInfo = MakeInstalledInfo(UNINSTALL_BUNDLE_NAME, false, true);
    dataMgr_->AddUserId(TEST_USER_ID);
    dataMgr_->bundleInfos_.emplace(UNINSTALL_BUNDLE_NAME, installedInfo);
    PreInstallBundleInfo preInstallBundleInfo;
    preInstallBundleInfo.SetBundleName(UNINSTALL_BUNDLE_NAME);
    preInstallStorage_->infos[UNINSTALL_BUNDLE_NAME] = preInstallBundleInfo;
    handler_->loadExistData_.emplace(UNINSTALL_BUNDLE_NAME, preInstallBundleInfo);

    handler_->ProcessRebootBundleUninstall();
    auto iter = dataMgr_->bundleInfos_.find(UNINSTALL_BUNDLE_NAME);
    ASSERT_NE(iter, dataMgr_->bundleInfos_.end());
    EXPECT_FALSE(iter->second.IsPreInstallApp());
    EXPECT_EQ(preInstallStorage_->infos.count(UNINSTALL_BUNDLE_NAME), 0U);
    (void)dataMgr_->dataStorage_->DeleteStorageBundleInfo(installedInfo);
}

/**
 * @tc.number: EventHandler_ProcessRebootBundleUninstall_0200
 * @tc.name: test ProcessRebootBundleUninstall
 * @tc.desc: 1. a compressed preload gone from the image is uninstalled although its hap is in the code dir,
 *              it is not taken for an updated bundle and its preinstall record is removed
 */
HWTEST_F(BmsPreCompressEventHandlerTest, EventHandler_ProcessRebootBundleUninstall_0200,
    Function | SmallTest | Level0)
{
    dataMgr_->bundleInfos_.emplace(UNINSTALL_BUNDLE_NAME, MakeInstalledInfo(UNINSTALL_BUNDLE_NAME, true, false));
    PreInstallBundleInfo preInstallBundleInfo;
    preInstallBundleInfo.SetBundleName(UNINSTALL_BUNDLE_NAME);
    preInstallStorage_->infos[UNINSTALL_BUNDLE_NAME] = preInstallBundleInfo;
    handler_->loadExistData_.emplace(UNINSTALL_BUNDLE_NAME, preInstallBundleInfo);

    handler_->ProcessRebootBundleUninstall();
    auto iter = dataMgr_->bundleInfos_.find(UNINSTALL_BUNDLE_NAME);
    ASSERT_NE(iter, dataMgr_->bundleInfos_.end());
    EXPECT_TRUE(iter->second.IsPreInstallApp());
    EXPECT_EQ(preInstallStorage_->infos.count(UNINSTALL_BUNDLE_NAME), 0U);
}
}  // namespace OHOS
