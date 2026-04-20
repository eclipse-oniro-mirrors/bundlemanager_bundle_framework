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

#include <atomic>
#include <cstring>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include "xcollie_helper.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace {
constexpr const char* BOOT_DETECTOR_DEV_PATH = "/dev/bbox";
std::atomic<int> g_openCallCount{0};

static int (*g_realOpen)(const char *pathname, int flags, ...) = nullptr;
extern "C" int open(const char *pathname, int flags, ...)
{
    if (g_realOpen == nullptr) {
        g_realOpen = (int (*)(const char *, int, ...))dlsym(RTLD_NEXT, "open");
    }
    if (pathname != nullptr && strcmp(pathname, BOOT_DETECTOR_DEV_PATH) == 0) {
        g_openCallCount.fetch_add(1);
        errno = ENOENT;
        return -1;
    }
    return g_realOpen(pathname, flags);
}

void ResetMocks()
{
    g_openCallCount.store(0);
}
}  // namespace

class XCollieHelperTest : public testing::Test {
public:
    XCollieHelperTest();
    ~XCollieHelperTest();
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

XCollieHelperTest::XCollieHelperTest()
{}

XCollieHelperTest::~XCollieHelperTest()
{}

void XCollieHelperTest::SetUpTestCase()
{}

void XCollieHelperTest::TearDownTestCase()
{}

void XCollieHelperTest::SetUp()
{}

void XCollieHelperTest::TearDown()
{}

HWTEST_F(XCollieHelperTest, PauseAndResumeWatchdog_001, TestSize.Level1)
{
    ResetMocks();
    XCollieHelper::PauseFoundationWatchdog();
    EXPECT_GT(g_openCallCount.load(), 0);
    XCollieHelper::ResumeFoundationWatchdog();
    EXPECT_GT(g_openCallCount.load(), 1);
}
}  // namespace OHOS