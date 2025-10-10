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

#include <chrono>
#include <fstream>
#include <thread>
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
#include "installd_client.h"
#include "inner_bundle_info.h"
#include "system_ability_helper.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using OHOS::AAFwk::Want;

namespace OHOS {
namespace {
    const int32_t USERID = 100;
    const int32_t WAIT_TIME = 1; // init mocked bms
    const std::string MODULE_TEST = "moduleNameTest";
    const std::string MODULE_NOT_EXIST = "notExist";
}  // namespace

class BmsBundleDataMgrSharedTestNoMock : public testing::Test {
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

std::shared_ptr<BundleMgrService> BmsBundleDataMgrSharedTestNoMock::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsBundleDataMgrSharedTestNoMock::installdService_ =
    std::make_shared<InstalldService>();

void BmsBundleDataMgrSharedTestNoMock::SetUpTestCase()
{}

void BmsBundleDataMgrSharedTestNoMock::TearDownTestCase()
{
    bundleMgrService_->OnStop();
}

void BmsBundleDataMgrSharedTestNoMock::SetUp()
{
    if (!installdService_->IsServiceReady()) {
        installdService_->Start();
    }
    if (!bundleMgrService_->IsServiceReady()) {
        bundleMgrService_->OnStart();
        bundleMgrService_->GetDataMgr()->AddUserId(USERID);
        std::this_thread::sleep_for(std::chrono::seconds(WAIT_TIME));
    }
}

void BmsBundleDataMgrSharedTestNoMock::TearDown()
{}

std::shared_ptr<BundleDataMgr> BmsBundleDataMgrSharedTestNoMock::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

/**
 * @tc.number: GetAdaptBaseShareBundleInfo_0001
 * @tc.name: test GetAdaptBaseShareBundleInfo
 * @tc.desc: 1.system run normally
 *           2.check GetAdaptBaseShareBundleInfo failed
 */
HWTEST_F(BmsBundleDataMgrSharedTestNoMock, GetAdaptBaseShareBundleInfo_0001, Function | SmallTest | Level1)
{
    InnerBundleInfo innerBundleInfo;
    Dependency dependency;
    dependency.moduleName = MODULE_NOT_EXIST;
    BaseSharedBundleInfo baseSharedBundleInfo;

    InnerModuleInfo innerModuleInfo;
    innerModuleInfo.bundleType = BundleType::SHARED;
    innerModuleInfo.versionCode = 2;
    innerBundleInfo.innerSharedModuleInfos_[MODULE_TEST].push_back(innerModuleInfo);
    innerModuleInfo.versionCode = 1;
    innerBundleInfo.innerSharedModuleInfos_[MODULE_TEST].push_back(innerModuleInfo);
    bool ret = GetBundleDataMgr()->GetAdaptBaseShareBundleInfo(innerBundleInfo, dependency, baseSharedBundleInfo);
    EXPECT_FALSE(ret);

    dependency.moduleName = MODULE_TEST;
    ret = GetBundleDataMgr()->GetAdaptBaseShareBundleInfo(innerBundleInfo, dependency, baseSharedBundleInfo);
    EXPECT_TRUE(ret);
    EXPECT_EQ(baseSharedBundleInfo.versionCode, 2);
}
} // OHOS
