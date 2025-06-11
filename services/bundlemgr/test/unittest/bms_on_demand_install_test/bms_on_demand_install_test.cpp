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
#include <fstream>
#include <gtest/gtest.h>
#include <sstream>
#include <string>

#include "bundle_installer_host.h"
#include "bundle_mgr_service.h"
#include "installd/installd_service.h"
#include "installd_client.h"
#include "iservice_registry.h"
#include "on_demand_install_data_mgr.h"
#include "on_demand_install_data_storage_rdb.h"
#include "permission_define.h"
#include "system_ability_definition.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::Security;
using OHOS::AAFwk::Want;
namespace OHOS {
namespace {
}  // namespace

class BmsOnDemandInstallTest : public testing::Test {
public:
BmsOnDemandInstallTest();
    ~BmsOnDemandInstallTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    const std::shared_ptr<BundleDataMgr> GetBundleDataMgr() const;

private:
    static std::shared_ptr<InstalldService> installdService_;
    static std::shared_ptr<BundleMgrService> bundleMgrService_;
};

std::shared_ptr<BundleMgrService> BmsOnDemandInstallTest::bundleMgrService_ =
    DelayedSingleton<BundleMgrService>::GetInstance();

std::shared_ptr<InstalldService> BmsOnDemandInstallTest::installdService_ =
    std::make_shared<InstalldService>();

BmsOnDemandInstallTest::BmsOnDemandInstallTest()
{}

BmsOnDemandInstallTest::~BmsOnDemandInstallTest()
{}

void BmsOnDemandInstallTest::SetUpTestCase()
{}

void BmsOnDemandInstallTest::TearDownTestCase()
{}

void BmsOnDemandInstallTest::SetUp()
{}

void BmsOnDemandInstallTest::TearDown()
{}

const std::shared_ptr<BundleDataMgr> BmsOnDemandInstallTest::GetBundleDataMgr() const
{
    return bundleMgrService_->GetDataMgr();
}

/**
 * @tc.number: OnDemandInstallDataMgr_0001
 * @tc.name: OnDemandInstallDataMgr_0001
 * @tc.desc: test SaveOnDemandInstallBundleInfo
 */
HWTEST_F(BmsOnDemandInstallTest, OnDemandInstallDataMgr_0001, Function | SmallTest | Level1)
{
    OnDemandInstallDataMgr onDemandInstallDataMgr;
    std::string bundleName;
    PreInstallBundleInfo preInstallBundleInfo;
    bool ret = onDemandInstallDataMgr.SaveOnDemandInstallBundleInfo(bundleName, preInstallBundleInfo);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: OnDemandInstallDataMgr_0002
 * @tc.name: OnDemandInstallDataMgr_0002
 * @tc.desc: test SaveOnDemandInstallBundleInfo
 */
HWTEST_F(BmsOnDemandInstallTest, OnDemandInstallDataMgr_0002, Function | SmallTest | Level1)
{
    OnDemandInstallDataMgr onDemandInstallDataMgr;
    std::string bundleName;
    PreInstallBundleInfo preInstallBundleInfo;
    preInstallBundleInfo.bundleName_ = "test";
    bool ret = onDemandInstallDataMgr.SaveOnDemandInstallBundleInfo(bundleName, preInstallBundleInfo);
    EXPECT_TRUE(ret);
}

/**
 * @tc.number: OnDemandInstallDataMgr_0003
 * @tc.name: OnDemandInstallDataMgr_0003
 * @tc.desc: test SaveOnDemandInstallBundleInfo
 */
HWTEST_F(BmsOnDemandInstallTest, OnDemandInstallDataMgr_0003, Function | SmallTest | Level1)
{
    OnDemandInstallDataMgr onDemandInstallDataMgr;
    std::string bundleName;
    bool ret = onDemandInstallDataMgr.DeleteOnDemandInstallBundleInfo(bundleName);
    EXPECT_FALSE(ret);

    bundleName = "test";
    bool ret2 = onDemandInstallDataMgr.DeleteOnDemandInstallBundleInfo(bundleName);
    EXPECT_TRUE(ret2);
}

/**
 * @tc.number: OnDemandInstallDataMgr_0004
 * @tc.name: OnDemandInstallDataMgr_0004
 * @tc.desc: test GetOnDemandInstallBundleInfo
 */
HWTEST_F(BmsOnDemandInstallTest, OnDemandInstallDataMgr_0004, Function | SmallTest | Level1)
{
    OnDemandInstallDataMgr onDemandInstallDataMgr;
    std::string bundleName;
    PreInstallBundleInfo preInstallBundleInfo;
    bool ret = onDemandInstallDataMgr.GetOnDemandInstallBundleInfo(bundleName, preInstallBundleInfo);
    EXPECT_FALSE(ret);

    bundleName = "test";
    bool ret2 = onDemandInstallDataMgr.GetOnDemandInstallBundleInfo(bundleName, preInstallBundleInfo);
    EXPECT_FALSE(ret2);
}

/**
 * @tc.number: OnDemandInstallDataMgr_0005
 * @tc.name: OnDemandInstallDataMgr_0005
 * @tc.desc: test GetOnDemandInstallBundleInfo
 */
HWTEST_F(BmsOnDemandInstallTest, OnDemandInstallDataMgr_0005, Function | SmallTest | Level1)
{
    OnDemandInstallDataMgr onDemandInstallDataMgr;
    std::vector<PreInstallBundleInfo> preInstallBundleInfos;
    bool ret = onDemandInstallDataMgr.GetAllOnDemandInstallBundleInfos(preInstallBundleInfos);
    EXPECT_FALSE(ret);
}

/**
 * @tc.number: OnDemandInstallDataMgr_0006
 * @tc.name: OnDemandInstallDataMgr_0006
 * @tc.desc: test TransformStrToInfo
 */
HWTEST_F(BmsOnDemandInstallTest, OnDemandInstallDataMgr_0006, Function | SmallTest | Level1)
{
    OnDemandInstallDataMgr onDemandInstallDataMgr;
    std::map<std::string, std::string> datas;
    std::vector<PreInstallBundleInfo> preInstallBundleInfos;
    onDemandInstallDataMgr.onDemandDataStorage_->TransformStrToInfo(datas, preInstallBundleInfos);
    EXPECT_TRUE(preInstallBundleInfos.empty());
}

/**
 * @tc.number: OnDemandInstallDataMgr_0007
 * @tc.name: OnDemandInstallDataMgr_0007
 * @tc.desc: test TransformStrToInfo
 */
HWTEST_F(BmsOnDemandInstallTest, OnDemandInstallDataMgr_0007, Function | SmallTest | Level1)
{
    OnDemandInstallDataMgr onDemandInstallDataMgr;
    std::map<std::string, std::string> datas;
    datas["test"] = "{";
    std::vector<PreInstallBundleInfo> preInstallBundleInfos;
    onDemandInstallDataMgr.onDemandDataStorage_->TransformStrToInfo(datas, preInstallBundleInfos);
    EXPECT_TRUE(preInstallBundleInfos.empty());
}

/**
 * @tc.number: OnDemandInstallDataMgr_0008
 * @tc.name: OnDemandInstallDataMgr_0008
 * @tc.desc: test TransformStrToInfo
 */
HWTEST_F(BmsOnDemandInstallTest, OnDemandInstallDataMgr_0008, Function | SmallTest | Level1)
{
    OnDemandInstallDataMgr onDemandInstallDataMgr;
    std::map<std::string, std::string> datas;
    datas["test"] = R"({"name":"John","age":30,"city":"New York"})";
    std::vector<PreInstallBundleInfo> preInstallBundleInfos;
    onDemandInstallDataMgr.onDemandDataStorage_->TransformStrToInfo(datas, preInstallBundleInfos);
    EXPECT_TRUE(preInstallBundleInfos.empty());
}

/**
 * @tc.number: OnDemandInstallDataMgr_0009
 * @tc.name: OnDemandInstallDataMgr_0009
 * @tc.desc: test TransformStrToInfo
 */
HWTEST_F(BmsOnDemandInstallTest, OnDemandInstallDataMgr_0009, Function | SmallTest | Level1)
{
    OnDemandInstallDataMgr onDemandInstallDataMgr;
    PreInstallBundleInfo preInstallBundleInfo;
    preInstallBundleInfo.bundleName_ = "test";
    nlohmann::json jsonObject;
    preInstallBundleInfo.ToJson(jsonObject);

    std::map<std::string, std::string> datas;
    datas["test"] = jsonObject.dump();
    std::vector<PreInstallBundleInfo> preInstallBundleInfos;
    onDemandInstallDataMgr.onDemandDataStorage_->TransformStrToInfo(datas, preInstallBundleInfos);
    EXPECT_FALSE(preInstallBundleInfos.empty());
}

/**
 * @tc.number: OnDemandInstallDataMgr_0010
 * @tc.name: OnDemandInstallDataMgr_0010
 * @tc.desc: test GetAppidentifier
 */
HWTEST_F(BmsOnDemandInstallTest, OnDemandInstallDataMgr_0010, Function | SmallTest | Level1)
{
    OnDemandInstallDataMgr onDemandInstallDataMgr;
    std::string bundlePath;
    std::string res = onDemandInstallDataMgr.GetAppidentifier(bundlePath);
    EXPECT_TRUE(res.empty());
}
} // OHOS