/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#define protected public

#include <algorithm>
#include <chrono>
#include <fstream>
#include <future>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <gtest/gtest.h>

#include "bundle_data_mgr.h"
#include "bundle_info.h"
#include "bundle_permission_mgr.h"
#include "bundle_mgr_service.h"
#include "bundle_mgr_proxy.h"
#include "directory_ex.h"
#include "hidump_helper.h"
#include "install_param.h"
#include "installd/installd_service.h"
#include "inner_bundle_info.h"
#include "navigation/router_data_storage_interface.h"
#include "shared/inner_shared_bundle_installer.h"
#include "shared/shared_bundle_installer.h"
#include "bundle_install_checker.h"
#include "system_ability_helper.h"
#include "scope_guard.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using OHOS::AAFwk::Want;

namespace OHOS {
namespace {
    const int32_t USERID = 100;
    const int32_t WAIT_TIME = 2; // init mocked bms
    const std::string MODULE_TEST = "moduleNameTest";
    const std::string MODULE_NOT_EXIST = "notExist";
}  // namespace

class BmsBundleDataMgrSharedTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;

public:
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
    static std::shared_ptr<InstalldService> installdService_;
};

std::shared_ptr<BundleMgrService> BmsBundleDataMgrSharedTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundleDataMgrSharedTest::installdService_ =
    std::make_shared<InstalldService>();

void BmsBundleDataMgrSharedTest::SetUpTestCase()
{
    bundleMgrService_->InitBundleInstaller();
    bundleMgrService_->InitBundleDataMgr();
    bundleMgrService_->GetDataMgr()->AddUserId(USERID);
    bundleMgrService_->GetDataMgr()->LoadDataFromPersistentStorage();
}

void BmsBundleDataMgrSharedTest::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleDataMgrSharedTest::SetUp()
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
}

void BmsBundleDataMgrSharedTest::TearDown()
{}

std::shared_ptr<BundleDataMgr> BmsBundleDataMgrSharedTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

/**
 * @tc.number: GetAdaptBaseShareBundleInfo_0001
 * @tc.name: test GetAdaptBaseShareBundleInfo
 * @tc.desc: 1.system run normally, mock QueryRunningSharedBundles
 *           2.check GetAdaptBaseShareBundleInfo failed
 */
HWTEST_F(BmsBundleDataMgrSharedTest, GetAdaptBaseShareBundleInfo_0001, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    Dependency dependency;
    dependency.moduleName = MODULE_NOT_EXIST;
    BaseSharedBundleInfo baseSharedBundleInfo;
    bool ret = GetBundleDataMgr()->GetAdaptBaseShareBundleInfo(innerBundleInfo, dependency, baseSharedBundleInfo);
    EXPECT_FALSE(ret);

    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.bundleType = BundleType::SHARED;
    innerModuleInfo.versionCode = 2;
    innerBundleInfo.innerSharedModuleInfos_[MODULE_TEST].push_back(innerModuleInfo);
    innerModuleInfo.versionCode = 3;
    innerBundleInfo.innerSharedModuleInfos_[MODULE_TEST].push_back(innerModuleInfo);
    ret = GetBundleDataMgr()->GetAdaptBaseShareBundleInfo(innerBundleInfo, dependency, baseSharedBundleInfo);
    EXPECT_FALSE(ret);
    dependency.bundleName = MODULE_TEST;
    dependency.moduleName = MODULE_TEST;
    ret = GetBundleDataMgr()->GetAdaptBaseShareBundleInfo(innerBundleInfo, dependency, baseSharedBundleInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(baseSharedBundleInfo.versionCode, 2);

    innerModuleInfo.versionCode = 1;
    innerBundleInfo.innerSharedModuleInfos_[MODULE_TEST].push_back(innerModuleInfo);
    ret = GetBundleDataMgr()->GetAdaptBaseShareBundleInfo(innerBundleInfo, dependency, baseSharedBundleInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(baseSharedBundleInfo.versionCode, 1);
}

namespace {
constexpr uint32_t TEST_VERSION_CODE_V2 = 2;
constexpr int32_t LOCK_WAIT_TIMEOUT_MS = 100;
constexpr uint32_t ZIP_SHORT_BYTES = 2;
constexpr uint32_t ZIP_LONG_BYTES = 4;
constexpr uint32_t BITS_PER_BYTE = 8;
constexpr uint32_t ZIP_VERSION = 20;
constexpr uint32_t ZIP_LOCAL_HEADER_SIZE = 30;
constexpr uint32_t ZIP_DIRECTORY_HEADER_SIZE = 46;
constexpr uint32_t ZIP_EMPTY_DIRECTORY_FIELDS = 4;

InnerModuleInfo EscapeTestModule(uint32_t version, bool escape)
{
    InnerModuleInfo module;
    module.name = "library";
    module.moduleName = "library";
    module.modulePackage = "library";
    module.distro.moduleName = "library";
    module.bundleType = BundleType::SHARED;
    module.versionCode = version;
    module.alternateModule = escape;
    module.hapPath = "/data/app/el1/bundle/public/com.example.escape/v" + std::to_string(version) +
        "/library/library" + (escape ? "_escape.hsp" : ".hsp");
    module.hashValue = escape ? "escape-hash" : "business-hash";
    module.description = escape ? "escape-description" : "business-description";
    return module;
}

InnerBundleInfo EscapeTestBundle(uint32_t version, bool escape)
{
    InnerBundleInfo info;
    ApplicationInfo app;
    app.bundleName = "com.example.escape";
    app.bundleType = BundleType::SHARED;
    app.versionCode = version;
    info.SetBaseApplicationInfo(app);
    BundleInfo bundle;
    bundle.name = app.bundleName;
    bundle.versionCode = version;
    info.SetBaseBundleInfo(bundle);
    auto module = EscapeTestModule(version, escape);
    info.InsertInnerModuleInfo(module.moduleName, module);
    info.InsertInnerSharedModuleInfo(module.moduleName, module);
    return info;
}

InnerBundleInfo EscapeTestMultiModuleBundle()
{
    auto old = EscapeTestBundle(1, false);
    old.InsertInnerSharedModuleInfo("library", EscapeTestModule(1, true));
    old.InsertInnerSharedModuleInfo("library", EscapeTestModule(TEST_VERSION_CODE_V2, false));
    old.InsertInnerSharedModuleInfo("library", EscapeTestModule(TEST_VERSION_CODE_V2, true));
    old.ReplaceInnerModuleInfo("library", EscapeTestModule(TEST_VERSION_CODE_V2, false));
    for (bool escape : {false, true}) {
        auto module = EscapeTestModule(1, escape);
        module.moduleName = "other";
        module.modulePackage = "other";
        module.hapPath = "/data/app/el1/bundle/public/com.example.escape/v1/other/other" +
            std::string(escape ? "_escape.hsp" : ".hsp");
        old.InsertInnerSharedModuleInfo("other", module);
        if (!escape) {
            old.InsertInnerModuleInfo("other", module);
        }
    }
    return old;
}

class EscapeTestStorage final : public IBundleDataStorage {
public:
    bool failSave = false;
    int32_t saveAttempts = 0;
    InnerBundleInfo saved;
    bool LoadAllData(std::map<std::string, InnerBundleInfo> &infos) override { return true; }
    bool SaveStorageBundleInfo(const InnerBundleInfo &info) override
    {
        ++saveAttempts;
        if (failSave) {
            return false;
        }
        saved = info;
        return true;
    }
    ErrCode SaveStorageBundleInfoWithCode(const InnerBundleInfo &info) override
    {
        return SaveStorageBundleInfo(info) ? ERR_OK : ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR;
    }
    bool DeleteStorageBundleInfo(const InnerBundleInfo &info) override
    {
        return true;
    }
};

class EscapeRouterStorage final : public IRouterDataStorage {
public:
    int32_t reads = 0;
    bool GetRouterInfo(const std::string &, const std::string &, const uint32_t,
        std::vector<RouterItem> &items) override
    {
        ++reads;
        RouterItem item;
        item.name = "route";
        item.pageSourceFile = "pages/Business";
        items.emplace_back(item);
        return true;
    }
    bool UpdateRouterInfo(const std::string &, const std::map<std::string, std::string> &,
        const uint32_t) override { return true; }
    bool InsertRouterInfo(const std::string &, const std::map<std::string, std::string> &,
        const uint32_t) override { return true; }
    void GetAllBundleNames(std::set<std::string> &) override {}
    bool DeleteRouterInfo(const std::string &) override { return true; }
    bool DeleteRouterInfo(const std::string &, const std::string &) override { return true; }
    bool DeleteRouterInfo(const std::string &, const std::string &, const uint32_t) override { return true; }
    bool UpdateDB() override { return true; }
};

// Create a stored ZIP entry, following CreateSimpleZipFile in the adjacent kit tests.
bool WriteEscapeRouterHsp(const std::string &path, const std::string &profile,
    const std::string &name = "resources/base/profile/router.json")
{
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    auto writeNumber = [&file](uint32_t value, uint32_t bytes) {
        for (uint32_t i = 0; i < bytes; ++i) {
            file.put(static_cast<char>((value >> (i * BITS_PER_BYTE)) & 0xff));
        }
    };
    uint32_t crc = 0xffffffff;
    for (unsigned char byte : profile) {
        crc ^= byte;
        for (uint32_t i = 0; i < BITS_PER_BYTE; ++i) {
            crc = (crc >> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
        }
    }
    crc ^= 0xffffffff;
    writeNumber(0x04034b50, ZIP_LONG_BYTES);
    for (auto value : {ZIP_VERSION, 0u, 0u, 0u, 0u}) {
        writeNumber(value, ZIP_SHORT_BYTES);
    }
    writeNumber(crc, ZIP_LONG_BYTES);
    writeNumber(profile.size(), ZIP_LONG_BYTES);
    writeNumber(profile.size(), ZIP_LONG_BYTES);
    writeNumber(name.size(), ZIP_SHORT_BYTES);
    writeNumber(0, ZIP_SHORT_BYTES);
    file << name << profile;
    const uint32_t directoryOffset = ZIP_LOCAL_HEADER_SIZE + name.size() + profile.size();
    writeNumber(0x02014b50, ZIP_LONG_BYTES);
    for (auto value : {ZIP_VERSION, ZIP_VERSION, 0u, 0u, 0u, 0u}) {
        writeNumber(value, ZIP_SHORT_BYTES);
    }
    writeNumber(crc, ZIP_LONG_BYTES);
    writeNumber(profile.size(), ZIP_LONG_BYTES);
    writeNumber(profile.size(), ZIP_LONG_BYTES);
    writeNumber(name.size(), ZIP_SHORT_BYTES);
    for (uint32_t i = 0; i < ZIP_EMPTY_DIRECTORY_FIELDS; ++i) {
        writeNumber(0, ZIP_SHORT_BYTES);
    }
    writeNumber(0, ZIP_LONG_BYTES);
    writeNumber(0, ZIP_LONG_BYTES);
    file << name;
    writeNumber(0x06054b50, ZIP_LONG_BYTES);
    for (auto value : {0, 0, 1, 1}) {
        writeNumber(value, ZIP_SHORT_BYTES);
    }
    writeNumber(ZIP_DIRECTORY_HEADER_SIZE + name.size(), ZIP_LONG_BYTES);
    writeNumber(directoryOffset, ZIP_LONG_BYTES);
    writeNumber(0, ZIP_SHORT_BYTES);
    file.close();
    return file.good();
}

void RunAlternateModuleInstallAndSet(BundleDataMgr &dataMgr, InnerSharedBundleInstaller &installer,
    const std::string &bundleName)
{
    std::unique_lock providerLock(dataMgr.GetBundleMutex(bundleName));
    std::promise<void> installStarted;
    auto installEntered = installStarted.get_future();
    std::promise<ErrCode> installPromise;
    auto installResult = installPromise.get_future();
    std::promise<void> setStarted;
    auto setEntered = setStarted.get_future();
    std::promise<ErrCode> setPromise;
    auto setResult = setPromise.get_future();
    std::thread setter;
    std::thread installing([&installStarted, &installPromise, &installer] {
        installStarted.set_value();
        installPromise.set_value(installer.Install(InstallParam {}));
    });
    ScopeGuard join([&providerLock, &installing, &setter] {
        if (providerLock.owns_lock()) {
            providerLock.unlock();
        }
        installing.join();
        if (setter.joinable()) {
            setter.join();
        }
    });
    installEntered.wait();
    EXPECT_EQ(installResult.wait_for(std::chrono::milliseconds(LOCK_WAIT_TIMEOUT_MS)), std::future_status::timeout);
    setter = std::thread([&setStarted, &setPromise, &dataMgr, &bundleName] {
        setStarted.set_value();
        setPromise.set_value(dataMgr.SetAlternateModuleState(bundleName, "library", 1, true));
    });
    setEntered.wait();
    EXPECT_EQ(setResult.wait_for(std::chrono::milliseconds(LOCK_WAIT_TIMEOUT_MS)), std::future_status::timeout);
    providerLock.unlock();
    EXPECT_EQ(installResult.get(), ERR_APPEXECFWK_INSTALL_DEPENDENT_MODULE_NOT_EXIST);
    EXPECT_EQ(setResult.get(), ERR_OK);
}

} // namespace

// AC-01/02: either input order retains two roles and selects business by default.
HWTEST_F(BmsBundleDataMgrSharedTest, AlternateModuleCoexist_0001, Function | SmallTest | Level1)
{
    for (bool escapeFirst : {false, true}) {
        InnerSharedBundleInstaller installer("");
        installer.parsedBundles_ = {{"first.hsp", InnerBundleInfo {}}, {"second.hsp", InnerBundleInfo {}}};
        auto iter = installer.parsedBundles_.begin();
        iter->second = EscapeTestBundle(1, escapeFirst);
        installer.bundleName_ = iter->second.GetBundleName();
        (++iter)->second = EscapeTestBundle(1, !escapeFirst);
        ASSERT_EQ(installer.CheckAlternateModuleModules(), ERR_OK);
        installer.MergeBundleInfos();
        auto &info = installer.newBundleInfo_;
        EXPECT_FALSE(info.GetInnerModuleInfos().at("library").alternateModule);
        ASSERT_EQ(info.GetInnerSharedModuleInfos().at("library").size(), 2u);
        BaseSharedBundleInfo result;
        ASSERT_TRUE(info.GetMaxVerBaseSharedBundleInfo("library", result));
        EXPECT_EQ(result.hapPath, EscapeTestModule(1, false).hapPath);
        info.InsertInnerSharedModuleInfo("library", EscapeTestModule(1, true));
        EXPECT_EQ(info.GetInnerSharedModuleInfos().at("library").size(), 2u);
    }
}

HWTEST_F(BmsBundleDataMgrSharedTest, AlternateModuleNamesForVersion_0001, Function | SmallTest | Level1)
{
    auto info = EscapeTestBundle(1, false);
    info.InsertInnerSharedModuleInfo("library", EscapeTestModule(1, true));
    info.InsertInnerSharedModuleInfo("library", EscapeTestModule(2, false));
    info.InsertInnerSharedModuleInfo("library", EscapeTestModule(2, true));
    for (bool alternate : {false, true}) {
        auto module = EscapeTestModule(1, alternate);
        module.moduleName = "other";
        module.modulePackage = "other";
        info.InsertInnerSharedModuleInfo("other", module);
    }
    const std::vector<std::string> versionOneModules = {"library", "other"};
    const std::vector<std::string> versionTwoModules = {"library"};
    EXPECT_EQ(info.GetAllHspModuleNamesForVersion(1), versionOneModules);
    EXPECT_EQ(info.GetAllHspModuleNamesForVersion(2), versionTwoModules);
    EXPECT_TRUE(info.GetAllHspModuleNamesForVersion(3).empty());
}

// AC-03/04/05: full metadata follows the selection on all module query surfaces.
HWTEST_F(BmsBundleDataMgrSharedTest, AlternateModuleQueries_0001, Function | SmallTest | Level1)
{
    auto info = EscapeTestBundle(1, false);
    auto alternate = EscapeTestModule(1, true);
    alternate.pages = "$profile:recovery";
    alternate.moduleResPath = "/data/app/el1/bundle/public/com.example.escape/recovery/resources.index";
    info.InsertInnerSharedModuleInfo("library", alternate);
    for (bool enable : {true, true, false, false}) {
        ASSERT_EQ(info.SetAlternateModuleState("library", 1, enable), ERR_OK);
        bool enabled = !enable;
        ASSERT_EQ(info.GetAlternateModuleState("library", 1, enabled), ERR_OK);
        EXPECT_EQ(enabled, enable);
        BaseSharedBundleInfo base;
        ASSERT_TRUE(info.GetBaseSharedBundleInfo("library", 1, base));
        EXPECT_EQ(base.hapPath, EscapeTestModule(1, enable).hapPath);
        SharedBundleInfo shared;
        ASSERT_TRUE(info.GetSharedBundleInfo(shared));
        ASSERT_EQ(shared.sharedModuleInfos.size(), 1u);
        EXPECT_EQ(shared.sharedModuleInfos[0].description, EscapeTestModule(1, enable).description);
        auto hap = info.FindHapModuleInfo("library");
        ASSERT_TRUE(hap.has_value());
        EXPECT_EQ(hap->hapPath, base.hapPath);
        EXPECT_EQ(hap->moduleName, "library");
        EXPECT_EQ(hap->versionCode, 1u);
        EXPECT_EQ(hap->pages, enable ? alternate.pages : EscapeTestModule(1, false).pages);
        EXPECT_EQ(hap->resourcePath, enable ? alternate.moduleResPath : EscapeTestModule(1, false).moduleResPath);
        BundleInfo bundle;
        ASSERT_TRUE(info.GetSharedBundleInfo(
            static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE), bundle));
        ASSERT_EQ(bundle.hapModuleInfos.size(), 1u);
        EXPECT_EQ(bundle.hapModuleInfos[0].hapPath, hap->hapPath);
        EXPECT_EQ(bundle.hapModuleInfos[0].pages, hap->pages);
        EXPECT_EQ(bundle.hapModuleInfos[0].resourcePath, hap->resourcePath);
        EXPECT_EQ(bundle.hapModuleInfos[0].hashValue, EscapeTestModule(1, enable).hashValue);
    }
}

HWTEST_F(BmsBundleDataMgrSharedTest, AlternateModuleQueryBundleType_0001, Function | SmallTest | Level1)
{
    for (auto type : {BundleType::APP, BundleType::ATOMIC_SERVICE, BundleType::SHARED,
        BundleType::APP_SERVICE_FWK, BundleType::APP_PLUGIN, BundleType::SKILL}) {
        auto info = EscapeTestBundle(1, false);
        info.InsertInnerSharedModuleInfo("library", EscapeTestModule(1, true));
        ASSERT_EQ(info.SetAlternateModuleState("library", 1, true), ERR_OK);
        auto app = info.GetBaseApplicationInfo();
        app.bundleType = type;
        info.SetBaseApplicationInfo(app);
        auto hap = info.FindHapModuleInfo("library");
        ASSERT_TRUE(hap.has_value());
        const auto expected = EscapeTestModule(1, type == BundleType::SHARED);
        EXPECT_EQ(hap->hapPath, expected.hapPath);
        EXPECT_EQ(hap->description, expected.description);
        info.GetModuleWithHashValue(GET_BUNDLE_WITH_HASH_VALUE, "library", *hap);
        EXPECT_EQ(hap->hashValue, expected.hashValue);
        BundleInfo bundle;
        info.ProcessBundleWithHapModuleInfoFlag(
            static_cast<int32_t>(GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_HAP_MODULE),
            bundle, Constants::ALL_USERID);
        ASSERT_EQ(bundle.hapModuleInfos.size(), 1u);
        EXPECT_EQ(bundle.hapModuleInfos[0].hapPath, expected.hapPath);
        EXPECT_EQ(bundle.hapModuleInfos[0].description, expected.description);
        EXPECT_EQ(bundle.hapModuleInfos[0].hashValue, expected.hashValue);
    }
}

HWTEST_F(BmsBundleDataMgrSharedTest, AlternateModuleInstalledPaths_0001, Function | SmallTest | Level1)
{
    for (bool alternate : {false, true}) {
        auto info = EscapeTestBundle(1, false);
        info.InsertInnerSharedModuleInfo("library", EscapeTestModule(1, true));
        info.SetCurrentModulePackage("library");
        auto installed = EscapeTestModule(1, alternate);
        installed.hapPath += ".installed";
        installed.modulePath = "/data/app/el1/bundle/public/com.example.escape/v1/library";
        installed.moduleResPath = installed.modulePath + "/resources.index";
        installed.description = "not an installation path";
        info.ReplaceInnerModuleInfo("library", installed);
        info.UpdateSharedModuleInfo();
        const auto *updated = info.FindSharedModule("library", 1, alternate);
        ASSERT_NE(updated, nullptr);
        EXPECT_EQ(updated->hapPath, installed.hapPath);
        EXPECT_EQ(updated->modulePath, installed.modulePath);
        EXPECT_EQ(updated->moduleResPath, installed.moduleResPath);
        EXPECT_EQ(updated->description, EscapeTestModule(1, alternate).description);
        const auto *other = info.FindSharedModule("library", 1, !alternate);
        ASSERT_NE(other, nullptr);
        EXPECT_EQ(other->hapPath, EscapeTestModule(1, !alternate).hapPath);
    }
}

HWTEST_F(BmsBundleDataMgrSharedTest, AlternateModuleVersions_0001, Function | SmallTest | Level1)
{
    auto info = EscapeTestBundle(1, false);
    EXPECT_EQ(info.SetAlternateModuleState("library", 2, true), ERR_BUNDLE_MANAGER_MODULE_VERSION_NOT_EXIST);
    info.InsertInnerSharedModuleInfo("library", EscapeTestModule(2, true));
    EXPECT_EQ(info.SetAlternateModuleState("library", 2, true), ERR_BUNDLE_MANAGER_MODULE_VERSION_NOT_EXIST);
    info.InsertInnerSharedModuleInfo("library", EscapeTestModule(2, false));
    for (bool enable : {true, false, true}) {
        ASSERT_EQ(info.SetAlternateModuleState("library", 2, enable), ERR_OK);
        bool enabled = !enable;
        ASSERT_EQ(info.GetAlternateModuleState("library", 2, enabled), ERR_OK);
        EXPECT_EQ(enabled, enable);
        BaseSharedBundleInfo result;
        ASSERT_TRUE(info.GetMaxVerBaseSharedBundleInfo("library", result));
        EXPECT_EQ(result.versionCode, 2u);
        EXPECT_EQ(result.hapPath, EscapeTestModule(2, enable).hapPath);
        ASSERT_TRUE(info.GetBaseSharedBundleInfo("library", 1, result));
        EXPECT_EQ(result.versionCode, 1u);
        EXPECT_EQ(result.hapPath, EscapeTestModule(1, false).hapPath);
        SharedBundleInfo shared;
        ASSERT_TRUE(info.GetSharedBundleInfo(shared));
        ASSERT_EQ(shared.sharedModuleInfos.size(), 2u);
        EXPECT_EQ(shared.sharedModuleInfos[0].hapPath, EscapeTestModule(2, enable).hapPath);
        EXPECT_EQ(shared.sharedModuleInfos[1].hapPath, EscapeTestModule(1, false).hapPath);
    }
    EXPECT_EQ(info.GetAllHspModuleNamesForVersion(1).size(), 1u);
    info.DeleteHspModuleByVersion(2);
    EXPECT_EQ(info.FindSharedModule("library", 2, false), nullptr);
    EXPECT_EQ(info.FindSharedModule("library", 2, true), nullptr);
    BaseSharedBundleInfo result;
    ASSERT_TRUE(info.GetMaxVerBaseSharedBundleInfo("library", result));
    EXPECT_EQ(result.versionCode, 1u);
    EXPECT_EQ(result.hapPath, EscapeTestModule(1, false).hapPath);
    bool enabled = true;
    ASSERT_EQ(info.GetAlternateModuleState("library", 1, enabled), ERR_OK);
    EXPECT_FALSE(enabled);
    EXPECT_EQ(info.SetAlternateModuleState("library", 1, true), ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
    EXPECT_EQ(info.SetAlternateModuleState("library", 1, false), ERR_OK);
    EXPECT_EQ(info.GetInnerSharedModuleInfos().at("library").size(), 1u);
    info.DeleteHspModuleByVersion(1);
    EXPECT_TRUE(info.GetInnerSharedModuleInfos().empty());
    EXPECT_TRUE(info.alternateModuleState_.empty());
}

HWTEST_F(BmsBundleDataMgrSharedTest, AlternateModuleVersionIsolation_0001, Function | SmallTest | Level1)
{
    auto info = EscapeTestBundle(1, false);
    info.InsertInnerSharedModuleInfo("library", EscapeTestModule(1, true));
    info.InsertInnerSharedModuleInfo("library", EscapeTestModule(2, false));
    info.InsertInnerSharedModuleInfo("library", EscapeTestModule(2, true));
    for (bool enableV1 : {false, true}) {
        for (bool enableV2 : {false, true}) {
            ASSERT_EQ(info.SetAlternateModuleState("library", 1, enableV1), ERR_OK);
            ASSERT_EQ(info.SetAlternateModuleState("library", 2, enableV2), ERR_OK);
            for (uint32_t version : {1u, 2u}) {
                bool enabled = false;
                ASSERT_EQ(info.GetAlternateModuleState("library", version, enabled), ERR_OK);
                EXPECT_EQ(enabled, version == 1 ? enableV1 : enableV2);
                BaseSharedBundleInfo selected;
                ASSERT_TRUE(info.GetBaseSharedBundleInfo("library", version, selected));
                EXPECT_EQ(selected.hapPath, EscapeTestModule(version, enabled).hapPath);
            }
        }
    }
    bool enabled = true;
    EXPECT_EQ(info.GetAlternateModuleState("library", 3, enabled), ERR_BUNDLE_MANAGER_MODULE_VERSION_NOT_EXIST);
    EXPECT_FALSE(enabled);
    EXPECT_EQ(info.SetAlternateModuleState("library", 3, false), ERR_BUNDLE_MANAGER_MODULE_VERSION_NOT_EXIST);
    info.DeleteHspModuleByVersion(2);
    ASSERT_EQ(info.GetAlternateModuleState("library", 1, enabled), ERR_OK);
    EXPECT_TRUE(enabled);
    EXPECT_EQ(info.alternateModuleState_.at("library").count(2), 0u);
    info.InsertInnerSharedModuleInfo("library", EscapeTestModule(2, false));
    info.InsertInnerSharedModuleInfo("library", EscapeTestModule(2, true));
    ASSERT_EQ(info.GetAlternateModuleState("library", 2, enabled), ERR_OK);
    EXPECT_FALSE(enabled);
}

HWTEST_F(BmsBundleDataMgrSharedTest, AlternateModuleMissingVersion_0001, Function | SmallTest | Level1)
{
    BundleDataMgr manager;
    auto info = EscapeTestBundle(1, false);
    info.InsertInnerSharedModuleInfo("library", EscapeTestModule(1, true));
    info.InsertInnerSharedModuleInfo("library", EscapeTestModule(2, false));
    ASSERT_EQ(info.SetAlternateModuleState("library", 1, true), ERR_OK);
    manager.bundleInfos_.emplace(info.GetBundleName(), info);
    const auto &bundleName = info.GetBundleName();
    for (bool enable : {false, true}) {
        EXPECT_EQ(manager.SetAlternateModuleState("missing", "missing", 3, enable),
            ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
        EXPECT_EQ(manager.SetAlternateModuleState(bundleName, "missing", 3, enable),
            ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
        EXPECT_EQ(manager.SetAlternateModuleState(bundleName, "library", 3, enable),
            ERR_BUNDLE_MANAGER_MODULE_VERSION_NOT_EXIST);
    }
    bool enabled = true;
    EXPECT_EQ(manager.GetAlternateModuleState("missing", "missing", 3, enabled), ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    EXPECT_FALSE(enabled);
    enabled = true;
    EXPECT_EQ(manager.GetAlternateModuleState(bundleName, "missing", 3, enabled), ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
    EXPECT_FALSE(enabled);
    enabled = true;
    EXPECT_EQ(manager.GetAlternateModuleState(bundleName, "library", 3, enabled),
        ERR_BUNDLE_MANAGER_MODULE_VERSION_NOT_EXIST);
    EXPECT_FALSE(enabled);
    EXPECT_EQ(manager.SetAlternateModuleState(bundleName, "library", 2, true), ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
    EXPECT_EQ(manager.SetAlternateModuleState(bundleName, "library", 2, false), ERR_OK);
    EXPECT_EQ(manager.GetAlternateModuleState(bundleName, "library", 2, enabled), ERR_OK);
    EXPECT_FALSE(enabled);
    EXPECT_EQ(manager.GetAlternateModuleState(bundleName, "library", 1, enabled), ERR_OK);
    EXPECT_TRUE(enabled);
}

HWTEST_F(BmsBundleDataMgrSharedTest, AlternateModuleVersionNoTruncation_0001, Function | SmallTest | Level1)
{
    BundleDataMgr manager;
    auto store = std::make_shared<EscapeTestStorage>();
    manager.dataStorage_ = store;
    auto info = EscapeTestBundle(1, false);
    info.InsertInnerSharedModuleInfo("library", EscapeTestModule(1, true));
    ASSERT_EQ(info.SetAlternateModuleState("library", 1, true), ERR_OK);
    manager.bundleInfos_.emplace(info.GetBundleName(), info);
    for (int64_t versionCode : std::vector<int64_t> {-1, 4294967296LL, 4294967297LL, INT64_MIN, INT64_MAX}) {
        SCOPED_TRACE(testing::Message() << "versionCode=" << versionCode);
        for (bool enable : {false, true}) {
            EXPECT_EQ(manager.SetAlternateModuleState("missing", "missing", versionCode, enable),
                ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
            EXPECT_EQ(manager.SetAlternateModuleState(info.GetBundleName(), "missing", versionCode, enable),
                ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
            EXPECT_EQ(manager.SetAlternateModuleState(info.GetBundleName(), "library", versionCode, enable),
                ERR_BUNDLE_MANAGER_MODULE_VERSION_NOT_EXIST);
        }
        bool enabled = true;
        EXPECT_EQ(manager.GetAlternateModuleState("missing", "missing", versionCode, enabled),
            ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
        EXPECT_FALSE(enabled);
        EXPECT_EQ(manager.GetAlternateModuleState(info.GetBundleName(), "missing", versionCode, enabled),
            ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
        EXPECT_EQ(manager.GetAlternateModuleState(info.GetBundleName(), "library", versionCode, enabled),
            ERR_BUNDLE_MANAGER_MODULE_VERSION_NOT_EXIST);
        EXPECT_FALSE(enabled);
        ASSERT_EQ(manager.GetAlternateModuleState(info.GetBundleName(), "library", 1, enabled), ERR_OK);
        EXPECT_TRUE(enabled);
        EXPECT_EQ(store->saveAttempts, 0);
    }
}

HWTEST_F(BmsBundleDataMgrSharedTest, AlternateModuleEmptyNames_0001, Function | SmallTest | Level1)
{
    BundleDataMgr manager;
    auto store = std::make_shared<EscapeTestStorage>();
    manager.dataStorage_ = store;
    auto info = EscapeTestBundle(1, false);
    info.InsertInnerSharedModuleInfo("library", EscapeTestModule(1, true));
    ASSERT_EQ(info.SetAlternateModuleState("library", 1, true), ERR_OK);
    manager.bundleInfos_.emplace(info.GetBundleName(), info);
    store->saved = info;
    struct ErrorCase {
        std::string bundleName;
        std::string moduleName;
        ErrCode expected;
    };
    for (const auto &item : std::vector<ErrorCase> {
        {"", "library", ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST},
        {"", "", ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST},
        {"missing", "", ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST},
        {info.GetBundleName(), "", ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST}}) {
        SCOPED_TRACE(testing::Message() << "bundle=" << item.bundleName << ", module=" << item.moduleName);
        for (bool enable : {false, true}) {
            EXPECT_EQ(manager.SetAlternateModuleState(item.bundleName, item.moduleName, 1, enable), item.expected);
        }
        bool enabled = true;
        EXPECT_EQ(manager.GetAlternateModuleState(item.bundleName, item.moduleName, 1, enabled), item.expected);
        EXPECT_FALSE(enabled);
        ASSERT_EQ(manager.GetAlternateModuleState(info.GetBundleName(), "library", 1, enabled), ERR_OK);
        EXPECT_TRUE(enabled);
        ASSERT_EQ(store->saved.GetAlternateModuleState("library", 1, enabled), ERR_OK);
        EXPECT_TRUE(enabled);
        EXPECT_EQ(store->saveAttempts, 0);
    }
}

HWTEST_F(BmsBundleDataMgrSharedTest, AlternateModulePersistence_0001, Function | SmallTest | Level1)
{
    auto info = EscapeTestBundle(1, false);
    info.InsertInnerSharedModuleInfo("library", EscapeTestModule(1, true));
    info.InsertInnerSharedModuleInfo("library", EscapeTestModule(2, false));
    info.InsertInnerSharedModuleInfo("library", EscapeTestModule(2, true));
    ASSERT_EQ(info.SetAlternateModuleState("library", 2, true), ERR_OK);
    nlohmann::json json;
    info.ToJson(json);
    EXPECT_EQ(json["alternateModuleState"]["library"], nlohmann::json::array({2}));
    EXPECT_FALSE(json.contains("safeEscapeState"));
    InnerBundleInfo restored;
    ASSERT_EQ(restored.FromJson(json), ERR_OK);
    bool enabled = false;
    EXPECT_EQ(restored.GetAlternateModuleState("library", 2, enabled), ERR_OK);
    EXPECT_TRUE(enabled);
    EXPECT_EQ(restored.GetAlternateModuleState("library", 1, enabled), ERR_OK);
    EXPECT_FALSE(enabled);
    BaseSharedBundleInfo result;
    ASSERT_TRUE(restored.GetMaxVerBaseSharedBundleInfo("library", result));
    EXPECT_EQ(result.hapPath, EscapeTestModule(2, true).hapPath);
    ASSERT_TRUE(restored.GetBaseSharedBundleInfo("library", 1, result));
    EXPECT_EQ(result.hapPath, EscapeTestModule(1, false).hapPath);
    json.erase("alternateModuleState");
    ASSERT_EQ(restored.FromJson(json), ERR_OK);
    EXPECT_EQ(restored.GetAlternateModuleState("library", 2, enabled), ERR_OK);
    EXPECT_FALSE(enabled);
    for (const auto &invalid : {nlohmann::json("true"), nlohmann::json(-1), nlohmann::json(1.5),
        nlohmann::json(4294967296ULL), nlohmann::json(18446744073709551615ULL)}) {
        ASSERT_EQ(restored.SetAlternateModuleState("library", 2, true), ERR_OK);
        json["alternateModuleState"] = {{"first", nlohmann::json::array({1})},
            {"library", nlohmann::json::array({2, invalid, 1})}, {"last", nlohmann::json::array({1})}};
        EXPECT_EQ(restored.FromJson(json), ERR_APPEXECFWK_PARSE_PROFILE_PROP_TYPE_ERROR);
        EXPECT_TRUE(restored.alternateModuleState_.empty());
    }
    nlohmann::json module = EscapeTestModule(1, true);
    EXPECT_EQ(module["alternateModule"], true);
    EXPECT_FALSE(module.contains("safeEscape"));
    module.erase("alternateModule");
    EXPECT_FALSE(module.get<InnerModuleInfo>().alternateModule);
}

HWTEST_F(BmsBundleDataMgrSharedTest, AlternateModuleStorageFailure_0001, Function | SmallTest | Level1)
{
    BundleDataMgr manager;
    auto store = std::make_shared<EscapeTestStorage>();
    manager.dataStorage_ = store;
    auto info = EscapeTestBundle(1, false);
    info.InsertInnerSharedModuleInfo("library", EscapeTestModule(1, true));
    manager.bundleInfos_.emplace(info.GetBundleName(), info);
    store->failSave = true;
    EXPECT_EQ(manager.SetAlternateModuleState(info.GetBundleName(), "library", 1, true),
        ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
    bool enabled = true;
    EXPECT_EQ(manager.GetAlternateModuleState(info.GetBundleName(), "library", 1, enabled), ERR_OK);
    EXPECT_FALSE(enabled);
    store->failSave = false;
    EXPECT_EQ(manager.SetAlternateModuleState(info.GetBundleName(), "library", 1, true), ERR_OK);
    EXPECT_EQ(store->saved.GetAlternateModuleState("library", 1, enabled), ERR_OK);
    EXPECT_TRUE(enabled);
    store->failSave = true;
    EXPECT_EQ(manager.SetAlternateModuleState(info.GetBundleName(), "library", 1, false),
        ERR_APPEXECFWK_SERVICE_INTERNAL_ERROR);
    EXPECT_EQ(manager.GetAlternateModuleState(info.GetBundleName(), "library", 1, enabled), ERR_OK);
    EXPECT_TRUE(enabled);
    EXPECT_EQ(manager.SetAlternateModuleState("", "library", 1, true), ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    EXPECT_EQ(manager.SetAlternateModuleState("absent", "library", 1, true), ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    EXPECT_EQ(manager.SetAlternateModuleState(info.GetBundleName(), "absent", 1, true),
        ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
}

HWTEST_F(BmsBundleDataMgrSharedTest, AlternateModulePrecheckFailureState_0001, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    auto originalStorage = dataMgr->dataStorage_;
    auto store = std::make_shared<EscapeTestStorage>();
    auto originalInfo = EscapeTestBundle(1, false);
    originalInfo.InsertInnerSharedModuleInfo("library", EscapeTestModule(1, true));
    const auto bundleName = originalInfo.GetBundleName();
    ASSERT_EQ(dataMgr->bundleInfos_.count(bundleName), 0u);
    ScopeGuard restore([&dataMgr, &bundleName, &originalStorage] {
        dataMgr->bundleInfos_.erase(bundleName);
        dataMgr->dataStorage_ = originalStorage;
    });
    dataMgr->dataStorage_ = store;
    for (bool enabled : {false, true}) {
        SCOPED_TRACE(testing::Message() << "enabled=" << enabled);
        ASSERT_EQ(originalInfo.SetAlternateModuleState("library", 1, !enabled), ERR_OK);
        dataMgr->bundleInfos_.insert_or_assign(bundleName, originalInfo);
        store->saved = originalInfo;
        auto installer = std::make_shared<InnerSharedBundleInstaller>("");
        installer->parsedBundles_ = {{"business.hsp", EscapeTestBundle(2, false)},
            {"alternate.hsp", EscapeTestBundle(2, true)}};
        installer->hapVerifyResults_.emplace_back();
        // Capture the parse-time snapshot before the successful state change.
        ASSERT_EQ(installer->CheckAppLabelInfo(), ERR_OK);
        ASSERT_EQ(installer->CheckAlternateModuleModules(), ERR_OK);
        ASSERT_EQ(dataMgr->SetAlternateModuleState(bundleName, "library", 1, enabled), ERR_OK);
        const auto saveAttempts = store->saveAttempts;
        installer->parsedBundles_.erase("business.hsp");
        SharedBundleInstaller batch(InstallParam {}, Constants::AppType::THIRD_PARTY_APP);
        batch.innerInstallers_.emplace(bundleName, installer);
        EXPECT_EQ(batch.Install(EventInfo {}), ERR_APPEXECFWK_INSTALL_DEPENDENT_MODULE_NOT_EXIST);
        InnerBundleInfo current;
        ASSERT_TRUE(dataMgr->FetchInnerBundleInfo(bundleName, current));
        for (const auto &info : {current, store->saved}) {
            bool actual = !enabled;
            ASSERT_EQ(info.GetAlternateModuleState("library", 1, actual), ERR_OK);
            EXPECT_EQ(actual, enabled);
            EXPECT_NE(info.FindSharedModule("library", 1, false), nullptr);
            EXPECT_NE(info.FindSharedModule("library", 1, true), nullptr);
            EXPECT_EQ(info.FindSharedModule("library", 2, false), nullptr);
            EXPECT_EQ(info.FindSharedModule("library", 2, true), nullptr);
        }
        EXPECT_EQ(store->saveAttempts, saveAttempts);
    }
}

HWTEST_F(BmsBundleDataMgrSharedTest, AlternateModuleInstallConcurrentSet_0001, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    auto originalStorage = dataMgr->dataStorage_;
    auto store = std::make_shared<EscapeTestStorage>();
    auto oldInfo = EscapeTestBundle(1, false);
    oldInfo.InsertInnerSharedModuleInfo("library", EscapeTestModule(1, true));
    const auto bundleName = oldInfo.GetBundleName();
    ASSERT_EQ(dataMgr->bundleInfos_.count(bundleName), 0u);
    ScopeGuard restore([&dataMgr, &bundleName, &originalStorage] {
        dataMgr->bundleInfos_.erase(bundleName);
        dataMgr->dataStorage_ = originalStorage;
    });
    dataMgr->dataStorage_ = store;
    dataMgr->bundleInfos_.emplace(bundleName, oldInfo);
    store->saved = oldInfo;

    InnerSharedBundleInstaller installer("");
    installer.parsedBundles_ = {{"alternate.hsp", EscapeTestBundle(2, true)}};
    installer.hapVerifyResults_.emplace_back();

    RunAlternateModuleInstallAndSet(*dataMgr, installer, bundleName);
    installer.RollBack();
    EXPECT_FALSE(installer.installStarted_);
    EXPECT_EQ(store->saveAttempts, 1);
    bool enabled = false;
    ASSERT_EQ(dataMgr->GetAlternateModuleState(bundleName, "library", 1, enabled), ERR_OK);
    EXPECT_TRUE(enabled);
    EXPECT_NE(store->saved.FindSharedModule("library", 1, true), nullptr);
    EXPECT_EQ(store->saved.FindSharedModule("library", 2, false), nullptr);
    ASSERT_EQ(store->saved.GetAlternateModuleState("library", 1, enabled), ERR_OK);
    EXPECT_TRUE(enabled);
}

HWTEST_F(BmsBundleDataMgrSharedTest, AlternateModuleInstallPairing_0001, Function | SmallTest | Level1)
{
    auto business = EscapeTestBundle(1, false);
    auto escape = EscapeTestBundle(1, true);
    BundleInstallChecker checker;
    std::unordered_map<std::string, InnerBundleInfo> files = {{"business.hsp", business}, {"escape.hsp", escape}};
    EXPECT_EQ(checker.CheckModuleNameForMulitHaps(files), ERR_OK);
    files.emplace("duplicate.hsp", escape);
    EXPECT_EQ(checker.CheckModuleNameForMulitHaps(files), ERR_APPEXECFWK_INSTALL_NOT_UNIQUE_DISTRO_MODULE_NAME);
    InnerSharedBundleInstaller installer("");
    installer.parsedBundles_ = {{"escape.hsp", escape}};
    EXPECT_EQ(installer.CheckAlternateModuleModules(), ERR_APPEXECFWK_INSTALL_DEPENDENT_MODULE_NOT_EXIST);
    installer.oldBundleInfo_ = business;
    installer.isBundleExist_ = true;
    EXPECT_EQ(installer.CheckAlternateModuleModules(), ERR_OK);
    installer.parsedBundles_.emplace("business.hsp", business);
    EXPECT_EQ(installer.CheckAlternateModuleModules(), ERR_OK);
    auto invalidEscape = escape;
    auto invalidModule = EscapeTestModule(1, true);
    invalidModule.isEncrypted = true;
    invalidEscape.ReplaceInnerModuleInfo("library", invalidModule);
    installer.parsedBundles_["escape.hsp"] = invalidEscape;
    EXPECT_EQ(installer.CheckAlternateModuleContents(), ERR_OK);
    invalidModule.isEncrypted = false;
    invalidEscape.SetNativeLibraryPath("libs/arm64");
    invalidEscape.ReplaceInnerModuleInfo("library", invalidModule);
    installer.parsedBundles_["escape.hsp"] = invalidEscape;
    EXPECT_EQ(installer.CheckAlternateModuleContents(), ERR_APPEXECFWK_INSTALL_ALTERNATE_MODULE_INVALID);
    installer.parsedBundles_["escape.hsp"] = EscapeTestBundle(2, true);
    EXPECT_EQ(installer.CheckAlternateModuleModules(), ERR_APPEXECFWK_INSTALL_DEPENDENT_MODULE_NOT_EXIST);
    installer.parsedBundles_["escape.hsp"] = escape;
    installer.MergeBundleInfos();
    EXPECT_EQ(installer.newBundleInfo_.GetInnerSharedModuleInfos().at("library").size(), 2u);
    EXPECT_FALSE(installer.newBundleInfo_.GetInnerModuleInfos().at("library").alternateModule);
}

HWTEST_F(BmsBundleDataMgrSharedTest, AlternateModulePairingAfterUninstall_0001, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    auto business = EscapeTestBundle(1, false);
    const auto bundleName = business.GetBundleName();
    ASSERT_EQ(dataMgr->bundleInfos_.count(bundleName), 0u);
    ScopeGuard restore([&dataMgr, &bundleName] { dataMgr->bundleInfos_.erase(bundleName); });
    dataMgr->bundleInfos_.emplace(bundleName, business);
    InnerSharedBundleInstaller installer("");
    installer.parsedBundles_.emplace("escape.hsp", EscapeTestBundle(1, true));
    ASSERT_EQ(installer.CheckAppLabelInfo(), ERR_OK);
    ASSERT_TRUE(installer.isBundleExist_);
    ASSERT_EQ(installer.CheckAlternateModuleModules(), ERR_OK);

    // Uninstall completes after parsing but before the locked installation check.
    dataMgr->bundleInfos_.erase(bundleName);
    ASSERT_EQ(installer.CheckAppLabelInfo(), ERR_OK);
    EXPECT_FALSE(installer.isBundleExist_);
    EXPECT_EQ(installer.oldBundleInfo_.FindSharedModule("library", 1, false), nullptr);
    EXPECT_EQ(installer.CheckAlternateModuleModules(), ERR_APPEXECFWK_INSTALL_DEPENDENT_MODULE_NOT_EXIST);
    installer.oldBundleInfo_ = business;
    EXPECT_EQ(installer.CheckAlternateModuleModules(), ERR_APPEXECFWK_INSTALL_DEPENDENT_MODULE_NOT_EXIST);
    installer.parsedBundles_.emplace("business.hsp", business);
    EXPECT_EQ(installer.CheckAlternateModuleModules(), ERR_OK);
}

// Per-package native metadata must be checked before the checker shares application attributes.
HWTEST_F(BmsBundleDataMgrSharedTest, AlternateModuleNativeContents_0001, Function | SmallTest | Level1)
{
    for (bool compressed : {false, true}) {
        for (bool isolated : {false, true}) {
            auto escape = EscapeTestBundle(1, true);
            auto module = EscapeTestModule(1, true);
            module.compressNativeLibs = compressed;
            module.isLibIsolated = isolated;
            escape.ReplaceInnerModuleInfo("library", module);
            InnerSharedBundleInstaller installer("");
            installer.parsedBundles_ = {{"escape.hsp", escape}};
            EXPECT_EQ(installer.CheckAlternateModuleContents(), ERR_OK);
            if (compressed && !isolated) {
                escape.SetNativeLibraryPath("libs/arm64");
            } else {
                module.nativeLibraryPath = "libs/arm64";
            }
            escape.ReplaceInnerModuleInfo("library", module);
            installer.parsedBundles_ = {{"escape.hsp", escape}};
            EXPECT_EQ(installer.CheckAlternateModuleContents(), ERR_APPEXECFWK_INSTALL_ALTERNATE_MODULE_INVALID);
        }
    }
}

HWTEST_F(BmsBundleDataMgrSharedTest, AlternateModuleBusinessNativeContents_0001, Function | SmallTest | Level1)
{
    std::string pattern = testing::TempDir() + "bms_safe_escape_contents_XXXXXX";
    std::vector<char> path(pattern.begin(), pattern.end());
    path.emplace_back('\0');
    int fd = mkstemp(path.data());
    ASSERT_GE(fd, 0);
    close(fd);
    ScopeGuard cleanup([&path] { unlink(path.data()); });
    ASSERT_TRUE(WriteEscapeRouterHsp(path.data(), "{}"));
    auto business = EscapeTestBundle(1, false);
    business.SetNativeLibraryPath("libs/arm64");
    business.SetCpuAbi("arm64-v8a");
    InnerSharedBundleInstaller installer("");
    installer.parsedBundles_ = {{"business.hsp", business}, {path.data(), EscapeTestBundle(1, true)}};
    ASSERT_EQ(installer.CheckAlternateModuleContents(), ERR_OK);
    BundleInstallChecker checker;
    ASSERT_EQ(checker.CheckMultiNativeFile(installer.parsedBundles_), ERR_OK);
    EXPECT_EQ(installer.CheckAlternateModuleModules(), ERR_OK);
}

// The existing HSP rollback restores the escape roles and selection with the old bundle snapshot.
HWTEST_F(BmsBundleDataMgrSharedTest, AlternateModuleRollbackState_0001, Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    auto originalStorage = dataMgr->dataStorage_;
    auto store = std::make_shared<EscapeTestStorage>();
    auto originalInfo = EscapeTestBundle(1, false);
    originalInfo.InsertInnerSharedModuleInfo("library", EscapeTestModule(1, true));
    ASSERT_EQ(originalInfo.SetAlternateModuleState("library", 1, true), ERR_OK);
    const auto bundleName = originalInfo.GetBundleName();
    ASSERT_EQ(dataMgr->bundleInfos_.count(bundleName), 0u);
    ScopeGuard restore([&dataMgr, &bundleName, &originalStorage] {
        dataMgr->bundleInfos_.erase(bundleName);
        dataMgr->dataStorage_ = originalStorage;
    });
    dataMgr->dataStorage_ = store;
    for (bool committed : {false, true}) {
        InnerSharedBundleInstaller installer("");
        installer.bundleName_ = bundleName;
        installer.oldBundleInfo_ = originalInfo;
        installer.isBundleExist_ = true;
        installer.installStarted_ = true;
        installer.parsedBundles_ = {{"business.hsp", EscapeTestBundle(2, false)},
            {"escape.hsp", EscapeTestBundle(2, true)}};
        dataMgr->bundleInfos_.insert_or_assign(bundleName, originalInfo);
        store->saved = originalInfo;
        installer.MergeBundleInfos();
        ASSERT_EQ(installer.SaveBundleInfoToStorage(), ERR_OK);
        if (committed) {
            ASSERT_EQ(installer.MarkInstallFinish(), ERR_OK);
        }
        installer.RollBack();
        InnerBundleInfo restored;
        ASSERT_TRUE(dataMgr->FetchInnerBundleInfo(bundleName, restored));
        for (const auto &info : {restored, store->saved}) {
            bool enabled = false;
            ASSERT_EQ(info.GetAlternateModuleState("library", 1, enabled), ERR_OK);
            EXPECT_TRUE(enabled);
            EXPECT_NE(info.FindSharedModule("library", 1, false), nullptr);
            EXPECT_NE(info.FindSharedModule("library", 1, true), nullptr);
            EXPECT_EQ(info.FindSharedModule("library", 2, false), nullptr);
            EXPECT_EQ(info.FindSharedModule("library", 2, true), nullptr);
        }
    }
}

HWTEST_F(BmsBundleDataMgrSharedTest, AlternateModuleRouterSelection_0001, Function | SmallTest | Level1)
{
    char filePath[] = "/data/test/escape_router_XXXXXX";
    int fd = mkstemp(filePath);
    ASSERT_GE(fd, 0);
    close(fd);
    ScopeGuard removeFile([&filePath] { unlink(filePath); });
    ASSERT_TRUE(WriteEscapeRouterHsp(filePath,
        R"({"routerMap":[{"name":"route","pageSourceFile":"pages/Recovery","buildFunction":"build"}]})"));
    BundleDataMgr manager;
    auto storage = std::make_shared<EscapeRouterStorage>();
    manager.routerStorage_ = storage;
    auto provider = EscapeTestBundle(1, false);
    auto escape = EscapeTestModule(1, true);
    escape.hapPath = filePath;
    escape.routerMap = "$profile:router";
    provider.InsertInnerSharedModuleInfo("library", escape);
    const auto bundleName = provider.GetBundleName();
    manager.bundleInfos_.emplace(bundleName, provider);
    InnerBundleInfo host;
    InnerModuleInfo entry;
    Dependency dependency;
    dependency.bundleName = bundleName;
    dependency.moduleName = "library";
    entry.dependencies.emplace_back(dependency);
    host.InsertInnerModuleInfo("entry", entry);

    for (bool enabled : {false, true, false}) {
        ASSERT_EQ(manager.bundleInfos_.at(bundleName).SetAlternateModuleState("library", 1, enabled), ERR_OK);
        std::vector<RouterItem> routes;
        manager.GetRouterInfoForSharedBundle(host, routes);
        ASSERT_EQ(routes.size(), 1u);
        EXPECT_EQ(routes[0].pageSourceFile, enabled ? "pages/Recovery" : "pages/Business");
    }
    ASSERT_EQ(manager.bundleInfos_.at(bundleName).SetAlternateModuleState("library", 1, true), ERR_OK);
    EXPECT_EQ(storage->reads, 2);
    for (const auto &profile : {std::string("{}"), std::string(R"({"routerMap":[]})")}) {
        ASSERT_TRUE(WriteEscapeRouterHsp(filePath, profile));
        std::vector<RouterItem> routes;
        manager.GetRouterInfoForSharedBundle(host, routes);
        EXPECT_TRUE(routes.empty());
    }
    unlink(filePath);
    std::vector<RouterItem> routes;
    manager.GetRouterInfoForSharedBundle(host, routes);
    EXPECT_TRUE(routes.empty());
    escape.routerMap.clear();
    manager.bundleInfos_.at(bundleName).InsertInnerSharedModuleInfo("library", escape);
    manager.GetRouterInfoForSharedBundle(host, routes);
    EXPECT_TRUE(routes.empty());
    EXPECT_EQ(storage->reads, 2);
}

HWTEST_F(BmsBundleDataMgrSharedTest, AlternateModuleSupplementInstall_0001, Function | SmallTest | Level1)
{
    for (uint32_t version : {1u, 2u}) {
        InnerSharedBundleInstaller installer("");
        installer.oldBundleInfo_ = EscapeTestBundle(2, false);
        installer.oldBundleInfo_.InsertInnerSharedModuleInfo("library", EscapeTestModule(1, false));
        uint32_t retainedVersion = version == 1 ? 2 : 1;
        installer.oldBundleInfo_.InsertInnerSharedModuleInfo("library", EscapeTestModule(retainedVersion, true));
        ASSERT_EQ(installer.oldBundleInfo_.SetAlternateModuleState("library", retainedVersion, true), ERR_OK);
        installer.isBundleExist_ = true;
        installer.parsedBundles_ = {{"escape.hsp", EscapeTestBundle(version, true)}};
        if (version < 2) {
            EXPECT_EQ(installer.CheckBundleTypeWithInstalledVersion(), ERR_APPEXECFWK_INSTALL_VERSION_DOWNGRADE);
            installer.oldBundleInfo_.InsertInnerSharedModuleInfo("library", EscapeTestModule(version, true));
            EXPECT_EQ(installer.CheckBundleTypeWithInstalledVersion(), ERR_APPEXECFWK_INSTALL_VERSION_DOWNGRADE);
            continue;
        }
        ASSERT_EQ(installer.CheckBundleTypeWithInstalledVersion(), ERR_OK);
        ASSERT_EQ(installer.CheckAlternateModuleModules(), ERR_OK);
        installer.MergeBundleInfos();
        EXPECT_NE(installer.newBundleInfo_.FindSharedModule("library", version, false), nullptr);
        EXPECT_NE(installer.newBundleInfo_.FindSharedModule("library", version, true), nullptr);
        EXPECT_EQ(installer.newBundleInfo_.GetInnerModuleInfos().at("library").versionCode, 2u);
        EXPECT_FALSE(installer.newBundleInfo_.GetInnerModuleInfos().at("library").alternateModule);
        EXPECT_EQ(installer.newBundleInfo_.GetBaseBundleInfo().versionCode, 2u);
        bool enabled = true;
        ASSERT_EQ(installer.newBundleInfo_.GetAlternateModuleState("library", version, enabled), ERR_OK);
        EXPECT_FALSE(enabled);
        ASSERT_EQ(installer.newBundleInfo_.GetAlternateModuleState("library", retainedVersion, enabled), ERR_OK);
        EXPECT_TRUE(enabled);

        // Replacing the alternate at the latest business version is also allowed.
        installer.oldBundleInfo_ = installer.newBundleInfo_;
        EXPECT_EQ(installer.CheckBundleTypeWithInstalledVersion(), ERR_OK);
        EXPECT_EQ(installer.CheckAlternateModuleModules(), ERR_OK);
        installer.newBundleInfo_.DeleteHspModuleByVersion(static_cast<int32_t>(version));
        EXPECT_EQ(installer.newBundleInfo_.FindSharedModule("library", version, false), nullptr);
        EXPECT_EQ(installer.newBundleInfo_.FindSharedModule("library", version, true), nullptr);
        ASSERT_EQ(installer.newBundleInfo_.GetAlternateModuleState("library", retainedVersion, enabled), ERR_OK);
        EXPECT_TRUE(enabled);
    }
}

HWTEST_F(BmsBundleDataMgrSharedTest, AlternateModuleSupplementInstallBoundary_0001, Function | SmallTest | Level1)
{
    InnerSharedBundleInstaller installer("");
    installer.oldBundleInfo_ = EscapeTestBundle(2, false);
    installer.isBundleExist_ = true;
    installer.parsedBundles_ = {{"escape.hsp", EscapeTestBundle(1, true)}};
    EXPECT_EQ(installer.CheckBundleTypeWithInstalledVersion(), ERR_APPEXECFWK_INSTALL_VERSION_DOWNGRADE);
    EXPECT_EQ(installer.CheckAlternateModuleModules(), ERR_APPEXECFWK_INSTALL_DEPENDENT_MODULE_NOT_EXIST);
    installer.parsedBundles_ = {{"escape.hsp", EscapeTestBundle(3, true)}};
    EXPECT_EQ(installer.CheckAlternateModuleModules(), ERR_APPEXECFWK_INSTALL_DEPENDENT_MODULE_NOT_EXIST);
    installer.oldBundleInfo_.InsertInnerSharedModuleInfo("library", EscapeTestModule(1, false));
    installer.parsedBundles_ = {{"business.hsp", EscapeTestBundle(1, false)}};
    EXPECT_EQ(installer.CheckBundleTypeWithInstalledVersion(), ERR_APPEXECFWK_INSTALL_VERSION_DOWNGRADE);
    installer.parsedBundles_.emplace("escape.hsp", EscapeTestBundle(1, true));
    EXPECT_EQ(installer.CheckBundleTypeWithInstalledVersion(), ERR_APPEXECFWK_INSTALL_VERSION_DOWNGRADE);
    installer.parsedBundles_ = {{"escape.hsp", EscapeTestBundle(2, true)}};
    installer.oldBundleInfo_ = EscapeTestBundle(2, true);
    EXPECT_EQ(installer.CheckAlternateModuleModules(), ERR_APPEXECFWK_INSTALL_DEPENDENT_MODULE_NOT_EXIST);
    auto other = EscapeTestModule(2, false);
    other.moduleName = "other";
    other.modulePackage = "other";
    installer.oldBundleInfo_.InsertInnerSharedModuleInfo("other", other);
    EXPECT_EQ(installer.CheckAlternateModuleModules(), ERR_APPEXECFWK_INSTALL_DEPENDENT_MODULE_NOT_EXIST);
}

HWTEST_F(BmsBundleDataMgrSharedTest, AlternateModuleSupplementConcurrentInstall_0001,
    Function | SmallTest | Level1)
{
    auto dataMgr = GetBundleDataMgr();
    auto business = EscapeTestBundle(1, false);
    const auto bundleName = business.GetBundleName();
    ASSERT_EQ(dataMgr->bundleInfos_.count(bundleName), 0u);
    ScopeGuard restore([&dataMgr, &bundleName] { dataMgr->bundleInfos_.erase(bundleName); });
    dataMgr->bundleInfos_.emplace(bundleName, business);
    InnerSharedBundleInstaller installer("");
    installer.parsedBundles_.emplace("escape.hsp", EscapeTestBundle(1, true));
    ASSERT_EQ(installer.CheckAppLabelInfo(), ERR_OK);
    ASSERT_EQ(installer.CheckAlternateModuleModules(), ERR_OK);

    // Another installation finishes before the locked installation check.
    dataMgr->bundleInfos_.at(bundleName).InsertInnerSharedModuleInfo("library", EscapeTestModule(1, true));
    ASSERT_EQ(installer.CheckAppLabelInfo(), ERR_OK);
    EXPECT_EQ(installer.CheckAlternateModuleModules(), ERR_OK);
}

HWTEST_F(BmsBundleDataMgrSharedTest, AlternateModulePairedUpdate_0001, Function | SmallTest | Level1)
{
    for (bool enabled : {false, true}) {
        InnerSharedBundleInstaller installer("");
        installer.oldBundleInfo_ = EscapeTestBundle(1, false);
        installer.oldBundleInfo_.InsertInnerSharedModuleInfo("library", EscapeTestModule(1, true));
        ASSERT_EQ(installer.oldBundleInfo_.SetAlternateModuleState("library", 1, enabled), ERR_OK);
        installer.isBundleExist_ = true;
        for (uint32_t version : {1u, 2u}) {
            for (bool escape : {false, true}) {
                installer.parsedBundles_ = {{"single.hsp", EscapeTestBundle(version, escape)}};
                if (version == 1) {
                    ASSERT_EQ(installer.CheckAlternateModuleModules(), ERR_OK);
                    installer.MergeBundleInfos();
                    bool state = true;
                    ASSERT_EQ(installer.newBundleInfo_.GetAlternateModuleState("library", 1, state), ERR_OK);
                    EXPECT_FALSE(state);
                    EXPECT_NE(installer.newBundleInfo_.FindSharedModule("library", 1, !escape), nullptr);
                } else if (!escape) {
                    EXPECT_EQ(installer.CheckAlternateModuleModules(), ERR_OK);
                } else {
                    EXPECT_EQ(installer.CheckAlternateModuleModules(),
                        ERR_APPEXECFWK_INSTALL_DEPENDENT_MODULE_NOT_EXIST);
                }
            }
            installer.parsedBundles_ = {{"business.hsp", EscapeTestBundle(version, false)},
                {"escape.hsp", EscapeTestBundle(version + 1, true)}};
            EXPECT_EQ(installer.CheckAlternateModuleModules(), ERR_APPEXECFWK_INSTALL_DEPENDENT_MODULE_NOT_EXIST);
            installer.parsedBundles_["escape.hsp"] = EscapeTestBundle(version, true);
            EXPECT_EQ(installer.CheckAlternateModuleModules(), ERR_OK);
            bool retained = !enabled;
            ASSERT_EQ(installer.oldBundleInfo_.GetAlternateModuleState("library", 1, retained), ERR_OK);
            EXPECT_EQ(retained, enabled);
            EXPECT_NE(installer.oldBundleInfo_.FindSharedModule("library", 1, false), nullptr);
            EXPECT_NE(installer.oldBundleInfo_.FindSharedModule("library", 1, true), nullptr);
        }
    }
}

// Another module's escape package must not restrict an ordinary HSP update.
HWTEST_F(BmsBundleDataMgrSharedTest, AlternateModulePairingScope_0001, Function | SmallTest | Level1)
{
    InnerSharedBundleInstaller installer("");
    installer.oldBundleInfo_ = EscapeTestBundle(2, false);
    for (bool escape : {false, true}) {
        auto module = EscapeTestModule(1, escape);
        module.moduleName = "other";
        module.modulePackage = "other";
        installer.oldBundleInfo_.InsertInnerSharedModuleInfo("other", module);
    }
    installer.isBundleExist_ = true;
    installer.parsedBundles_ = {{"business.hsp", EscapeTestBundle(3, false)}};
    EXPECT_EQ(installer.CheckAlternateModuleModules(), ERR_OK);
    // An earlier pair does not restrict a business-only update.
    installer.oldBundleInfo_.InsertInnerSharedModuleInfo("library", EscapeTestModule(1, false));
    installer.oldBundleInfo_.InsertInnerSharedModuleInfo("library", EscapeTestModule(1, true));
    EXPECT_EQ(installer.CheckAlternateModuleModules(), ERR_OK);
    installer.isBundleExist_ = false;
    EXPECT_EQ(installer.CheckAlternateModuleModules(), ERR_OK);
}

// AC-16/17: paired updates preserve earlier versions and reset the selection.
HWTEST_F(BmsBundleDataMgrSharedTest, AlternateModuleProviderUpdate_0001, Function | SmallTest | Level1)
{
    for (bool includesEscape : {false, true}) {
        InnerSharedBundleInstaller installer("");
        installer.oldBundleInfo_ = EscapeTestBundle(1, false);
        installer.bundleName_ = installer.oldBundleInfo_.GetBundleName();
        installer.oldBundleInfo_.InsertInnerSharedModuleInfo("library", EscapeTestModule(1, true));
        ASSERT_EQ(installer.oldBundleInfo_.SetAlternateModuleState("library", 1, true), ERR_OK);
        installer.isBundleExist_ = true;
        installer.parsedBundles_ = {{"business.hsp", EscapeTestBundle(2, false)}};
        if (includesEscape) {
            installer.parsedBundles_.emplace("escape.hsp", EscapeTestBundle(2, true));
        }
        ASSERT_EQ(installer.CheckAlternateModuleModules(), ERR_OK);
        installer.MergeBundleInfos();
        bool enabled = true;
        ASSERT_EQ(installer.newBundleInfo_.GetAlternateModuleState("library", 2, enabled), ERR_OK);
        EXPECT_FALSE(enabled);
        ASSERT_EQ(installer.newBundleInfo_.GetAlternateModuleState("library", 1, enabled), ERR_OK);
        EXPECT_TRUE(enabled);
        BaseSharedBundleInfo selected;
        ASSERT_TRUE(installer.newBundleInfo_.GetMaxVerBaseSharedBundleInfo("library", selected));
        EXPECT_EQ(selected.hapPath, EscapeTestModule(2, false).hapPath);
        ASSERT_TRUE(installer.newBundleInfo_.GetBaseSharedBundleInfo("library", 1, selected));
        EXPECT_EQ(selected.hapPath, EscapeTestModule(1, true).hapPath);
        EXPECT_EQ(installer.newBundleInfo_.SetAlternateModuleState("library", 2, true),
            includesEscape ? ERR_OK : ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST);
        ASSERT_TRUE(installer.newBundleInfo_.GetBaseSharedBundleInfo("library", 1, selected));
        EXPECT_EQ(selected.hapPath, EscapeTestModule(1, true).hapPath);
        ASSERT_TRUE(installer.newBundleInfo_.GetMaxVerBaseSharedBundleInfo("library", selected));
        EXPECT_EQ(selected.hapPath, EscapeTestModule(2, includesEscape).hapPath);
        EXPECT_EQ(installer.oldBundleInfo_.GetAlternateModuleState("library", 1, enabled), ERR_OK);
        EXPECT_TRUE(enabled);
    }
}

// Updating one escape-enabled module preserves earlier versions and other modules.
HWTEST_F(BmsBundleDataMgrSharedTest, AlternateModuleUpdateIsolation_0001, Function | SmallTest | Level1)
{
    for (uint32_t updateVersion : {2u, 3u}) {
        InnerSharedBundleInstaller installer("");
        auto &old = installer.oldBundleInfo_;
        old = EscapeTestMultiModuleBundle();
        ASSERT_EQ(old.SetAlternateModuleState("library", 1, true), ERR_OK);
        ASSERT_EQ(old.SetAlternateModuleState("library", 2, true), ERR_OK);
        ASSERT_EQ(old.SetAlternateModuleState("other", 1, true), ERR_OK);
        installer.bundleName_ = old.GetBundleName();
        installer.isBundleExist_ = true;
        installer.parsedBundles_ = {{"business.hsp", EscapeTestBundle(updateVersion, false)},
            {"escape.hsp", EscapeTestBundle(updateVersion, true)}};
        ASSERT_EQ(installer.CheckAlternateModuleModules(), ERR_OK);
        installer.MergeBundleInfos();
        const auto &modules = installer.newBundleInfo_.GetInnerModuleInfos();
        EXPECT_EQ(modules.at("library").versionCode, updateVersion);
        EXPECT_FALSE(modules.at("library").alternateModule);
        EXPECT_EQ(modules.at("other").hapPath, old.GetInnerModuleInfos().at("other").hapPath);
        for (uint32_t version : {1u, 2u}) {
            EXPECT_NE(installer.newBundleInfo_.FindSharedModule("library", version, true), nullptr);
            EXPECT_NE(installer.newBundleInfo_.FindSharedModule("library", version, false), nullptr);
            EXPECT_NE(old.FindSharedModule("library", version, true), nullptr);
        }
        EXPECT_NE(installer.newBundleInfo_.FindSharedModule("library", updateVersion, true), nullptr);
        EXPECT_NE(installer.newBundleInfo_.FindSharedModule("library", updateVersion, false), nullptr);
        EXPECT_EQ(installer.newBundleInfo_.GetInnerSharedModuleInfos().at("library").size(),
            updateVersion == 2u ? 4u : 6u);
        EXPECT_NE(installer.newBundleInfo_.FindSharedModule("other", 1, true), nullptr);
        bool enabled = false;
        ASSERT_EQ(installer.newBundleInfo_.GetAlternateModuleState("other", 1, enabled), ERR_OK);
        EXPECT_TRUE(enabled);
        for (uint32_t version : {1u, 2u, updateVersion}) {
            ASSERT_EQ(installer.newBundleInfo_.GetAlternateModuleState("library", version, enabled), ERR_OK);
            EXPECT_EQ(enabled, version != updateVersion);
            BaseSharedBundleInfo selected;
            ASSERT_TRUE(installer.newBundleInfo_.GetBaseSharedBundleInfo("library", version, selected));
            EXPECT_EQ(selected.hapPath, EscapeTestModule(version, version != updateVersion).hapPath);
        }
        EXPECT_EQ(old.GetAlternateModuleState("library", 1, enabled), ERR_OK);
        EXPECT_TRUE(enabled);
    }
}

HWTEST_F(BmsBundleDataMgrSharedTest, AlternateModuleUpdatePreinstalled_0001, Function | SmallTest | Level1)
{
    InnerSharedBundleInstaller installer("");
    installer.oldBundleInfo_ = EscapeTestBundle(1, false);
    auto business = EscapeTestModule(1, false);
    business.hapPath = "/system/app/example/library.hsp";
    installer.oldBundleInfo_.InsertInnerSharedModuleInfo("library", business);
    auto escape = EscapeTestModule(1, true);
    escape.hapPath = "/system/app/example/library_escape.hsp";
    installer.oldBundleInfo_.InsertInnerSharedModuleInfo("library", escape);
    installer.bundleName_ = installer.oldBundleInfo_.GetBundleName();
    installer.isBundleExist_ = true;
    installer.parsedBundles_ = {{"business.hsp", EscapeTestBundle(2, false)},
        {"escape.hsp", EscapeTestBundle(2, true)}};
    ASSERT_EQ(installer.CheckAlternateModuleModules(), ERR_OK);
    installer.MergeBundleInfos();
    const auto *retainedEscape = installer.newBundleInfo_.FindSharedModule("library", 1, true);
    const auto *retainedBusiness = installer.newBundleInfo_.FindSharedModule("library", 1, false);
    ASSERT_NE(retainedEscape, nullptr);
    ASSERT_NE(retainedBusiness, nullptr);
    EXPECT_EQ(retainedEscape->hapPath, escape.hapPath);
    EXPECT_EQ(retainedBusiness->hapPath, business.hapPath);
    EXPECT_EQ(installer.newBundleInfo_.SetAlternateModuleState("library", 1, true), ERR_OK);
}

// Introducing an alternate module preserves business-only versions and selects each version independently.
HWTEST_F(BmsBundleDataMgrSharedTest, AlternateModuleLegacyUpdate_0001, Function | SmallTest | Level1)
{
    for (bool escapeOnly : {false, true}) {
        InnerSharedBundleInstaller installer("");
        installer.oldBundleInfo_ = EscapeTestBundle(1, false);
        installer.bundleName_ = installer.oldBundleInfo_.GetBundleName();
        installer.isBundleExist_ = true;
        if (escapeOnly) {
            installer.oldBundleInfo_.InsertInnerSharedModuleInfo("library", EscapeTestModule(2, false));
        } else {
            installer.parsedBundles_.emplace("business.hsp", EscapeTestBundle(2, false));
        }
        installer.parsedBundles_.emplace("escape.hsp", EscapeTestBundle(2, true));
        ASSERT_EQ(installer.CheckBundleTypeWithInstalledVersion(), ERR_OK);
        ASSERT_EQ(installer.CheckAlternateModuleModules(), ERR_OK);
        installer.MergeBundleInfos();
        EXPECT_NE(installer.newBundleInfo_.FindSharedModule("library", 1, false), nullptr);
        EXPECT_NE(installer.oldBundleInfo_.FindSharedModule("library", 1, false), nullptr);
        ASSERT_EQ(installer.newBundleInfo_.GetInnerSharedModuleInfos().at("library").size(), 3u);
        bool enabled = true;
        ASSERT_EQ(installer.newBundleInfo_.GetAlternateModuleState("library", 2, enabled), ERR_OK);
        EXPECT_FALSE(enabled);
        BaseSharedBundleInfo selected;
        ASSERT_TRUE(installer.newBundleInfo_.GetBaseSharedBundleInfo("library", 1, selected));
        EXPECT_EQ(selected.hapPath, EscapeTestModule(1, false).hapPath);
        ASSERT_TRUE(installer.newBundleInfo_.GetMaxVerBaseSharedBundleInfo("library", selected));
        EXPECT_EQ(selected.hapPath, EscapeTestModule(2, false).hapPath);
        ASSERT_EQ(installer.newBundleInfo_.SetAlternateModuleState("library", 2, true), ERR_OK);
        ASSERT_EQ(installer.newBundleInfo_.GetAlternateModuleState("library", 2, enabled), ERR_OK);
        EXPECT_TRUE(enabled);
        ASSERT_TRUE(installer.newBundleInfo_.GetBaseSharedBundleInfo("library", 1, selected));
        EXPECT_EQ(selected.versionCode, 1u);
        EXPECT_EQ(selected.hapPath, EscapeTestModule(1, false).hapPath);
        ASSERT_TRUE(installer.newBundleInfo_.GetMaxVerBaseSharedBundleInfo("library", selected));
        EXPECT_EQ(selected.versionCode, 2u);
        EXPECT_EQ(selected.hapPath, EscapeTestModule(2, true).hapPath);
        EXPECT_EQ(installer.newBundleInfo_.GetInnerSharedModuleInfos().at("library").size(), 3u);
        ASSERT_EQ(installer.newBundleInfo_.SetAlternateModuleState("library", 2, false), ERR_OK);
        ASSERT_TRUE(installer.newBundleInfo_.GetMaxVerBaseSharedBundleInfo("library", selected));
        EXPECT_EQ(selected.hapPath, EscapeTestModule(2, false).hapPath);
    }
}

HWTEST_F(BmsBundleDataMgrSharedTest, SharedUpdateWithoutEscape_0001, Function | SmallTest | Level1)
{
    InnerSharedBundleInstaller installer("");
    installer.oldBundleInfo_ = EscapeTestBundle(1, false);
    installer.bundleName_ = installer.oldBundleInfo_.GetBundleName();
    installer.isBundleExist_ = true;
    installer.parsedBundles_ = {{"business.hsp", EscapeTestBundle(2, false)}};
    ASSERT_EQ(installer.CheckAlternateModuleModules(), ERR_OK);
    installer.MergeBundleInfos();
    EXPECT_NE(installer.newBundleInfo_.FindSharedModule("library", 1, false), nullptr);
    EXPECT_NE(installer.newBundleInfo_.FindSharedModule("library", 2, false), nullptr);
}

// Escape and business HSPs use the same ordinary package-size check.
HWTEST_F(BmsBundleDataMgrSharedTest, AlternateModuleFileSize_0001, Function | SmallTest | Level1)
{
    std::string pattern = testing::TempDir() + "bms_alternate_size_XXXXXX.hsp";
    std::vector<char> path(pattern.begin(), pattern.end());
    path.emplace_back('\0');
    const int suffixLength = 4;
    int fd = mkstemps(path.data(), suffixLength);
    ASSERT_GE(fd, 0);
    ScopeGuard cleanup([fd, &path] {
        close(fd);
        unlink(path.data());
    });
    for (off_t size : {204799, 204800, 204801, 1024 * 1024}) {
        ASSERT_EQ(ftruncate(fd, size), 0);
        std::vector<std::string> checkedPaths;
        EXPECT_EQ(BundleUtil::CheckFilePath({path.data()}, checkedPaths), ERR_OK);
    }
}

HWTEST_F(BmsBundleDataMgrSharedTest, SharedHspFilePath_0001, Function | SmallTest | Level1)
{
    std::string pattern = testing::TempDir() + "bms_shared_path_XXXXXX.hsp";
    std::vector<char> path(pattern.begin(), pattern.end());
    path.emplace_back('\0');
    const int suffixLength = 4;
    int fd = mkstemps(path.data(), suffixLength);
    ASSERT_GE(fd, 0);
    ScopeGuard cleanup([fd, &path] {
        close(fd);
        unlink(path.data());
    });
    ASSERT_EQ(ftruncate(fd, 1), 0);
    std::vector<std::string> checkedPaths;
    EXPECT_EQ(BundleUtil::CheckFilePath({path.data()}, checkedPaths), ERR_OK);
    checkedPaths.clear();
    EXPECT_EQ(BundleUtil::CheckFilePath({}, checkedPaths), ERR_APPEXECFWK_INSTALL_FILE_PATH_EMPTY);
    ASSERT_EQ(unlink(path.data()), 0);
    EXPECT_EQ(BundleUtil::CheckFilePath({path.data()}, checkedPaths), ERR_APPEXECFWK_INSTALL_STAT_FILE_FAILED);
}
} // OHOS
