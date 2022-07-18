/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "bundle_test_tool.h"

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <future>
#include <getopt.h>
#include <unistd.h>
#include <vector>

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_command_common.h"
#include "bundle_death_recipient.h"
#include "bundle_mgr_client.h"
#include "bundle_mgr_proxy.h"
#include "bundle_tool_callback_stub.h"
#include "parameter.h"
#include "status_receiver_impl.h"
#include "string_ex.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
static const std::string TOOL_NAME = "bundle_test_tool";
static const std::string HELP_MSG = "usage: bundle_test_tool <command> <options>\n"
                             "These are common bundle_test_tool commands list:\n"
                             "  help         list available commands\n";
const std::string SHORT_OPTIONS = "hn:m:a:d:u";
const struct option LONG_OPTIONS[] = {
    {"help", no_argument, nullptr, 'h'},
    {"bundle-name", required_argument, nullptr, 'n'},
    {"module-name", required_argument, nullptr, 'm'},
    {"ability-name", required_argument, nullptr, 'a'},
    {"device-id", required_argument, nullptr, 'd'},
    {"user-id", required_argument, nullptr, 'u'},
    {nullptr, 0, nullptr, 0},
};
}  // namespace

BundleTestTool::BundleTestTool(int argc, char *argv[]) : ShellCommand(argc, argv, TOOL_NAME)
{}

BundleTestTool::~BundleTestTool()
{}

ErrCode BundleTestTool::CreateCommandMap()
{
    commandMap_ = {
        {"help", std::bind(&BundleTestTool::RunAsHelpCommand, this)},
        {"check", std::bind(&BundleTestTool::RunAsCheckCommand, this)},
    };

    return OHOS::ERR_OK;
}

ErrCode BundleTestTool::CreateMessageMap()
{
    messageMap_ = BundleCommandCommon::bundleMessageMap_;

    return OHOS::ERR_OK;
}

ErrCode BundleTestTool::Init()
{
    APP_LOGI("BundleTestTool Init()");
    ErrCode result = OHOS::ERR_OK;
    if (bundleMgrProxy_ == nullptr) {
        bundleMgrProxy_ = BundleCommandCommon::GetBundleMgrProxy();
        if (bundleMgrProxy_) {
            if (bundleInstallerProxy_ == nullptr) {
                bundleInstallerProxy_ = bundleMgrProxy_->GetBundleInstaller();
            }
        }
    }

    if ((bundleMgrProxy_ == nullptr) || (bundleInstallerProxy_ == nullptr) ||
        (bundleInstallerProxy_->AsObject() == nullptr)) {
        result = OHOS::ERR_INVALID_VALUE;
    }

    return result;
}

ErrCode BundleTestTool::RunAsHelpCommand()
{
    resultReceiver_.append(HELP_MSG);

    return OHOS::ERR_OK;
}

ErrCode BundleTestTool::CheckOperation(int userId, std::string deviceId, std::string bundleName,
    std::string moduleName, std::string abilityName)
{
    std::unique_lock<std::mutex> lock(mutex_);
    sptr<BundleToolCallbackStub> bundleToolCallbackStub = new(std::nothrow) BundleToolCallbackStub(cv_);
    APP_LOGI("CheckAbilityEnableInstall param: userId:%{public}d, bundleName:%{public}s, moduleName:%{public}s," \
        "abilityName:%{public}s", userId, bundleName.c_str(), moduleName.c_str(), abilityName.c_str());
    AAFwk::Want want;
    want.SetElementName(deviceId, bundleName, abilityName, moduleName);
    bool ret = bundleMgrProxy_->CheckAbilityEnableInstall(want, 1, userId, bundleToolCallbackStub);
    if (!ret) {
        APP_LOGE("CheckAbilityEnableInstall failed");
        return OHOS::ERR_OK;
    }
    APP_LOGI("CheckAbilityEnableInstall wait");
    cv_.wait(lock);
    return OHOS::ERR_OK;
}

ErrCode BundleTestTool::RunAsCheckCommand()
{
    int option = -1;
    int counter = 0;
    int userId = 100;
    std::string deviceId = "";
    std::string bundleName = "";
    std::string moduleName = "";
    std::string abilityName = "";
    while (true) {
        counter++;
        option = getopt_long(argc_, argv_, SHORT_OPTIONS.c_str(), LONG_OPTIONS, nullptr);
        APP_LOGD("option: %{public}d, optopt: %{public}d, optind: %{public}d", option, optopt, optind);
        if (optind < 0 || optind > argc_) {
            return OHOS::ERR_INVALID_VALUE;
        }
        if (option == -1) {
            // When scanning the first argument
            if ((counter == 1) && (strcmp(argv_[optind], cmd_.c_str()) == 0)) {
                // 'CheckAbilityEnableInstall' with no option: CheckAbilityEnableInstall
                // 'CheckAbilityEnableInstall' with a wrong argument: CheckAbilityEnableInstall
                APP_LOGD("'CheckAbilityEnableInstall' with no option.");
                return OHOS::ERR_INVALID_VALUE;
            }
            break;
        }
        switch (option) {
            case 'n': {
                bundleName = optarg;
                break;
            }
            case 'm': {
                moduleName = optarg;
                break;
            }
            case 'a': {
                abilityName = optarg;
                break;
            }
            case 'd': {
                deviceId = optarg;
                break;
            }
            case 'u': {
                userId = std::stoi(optarg);
                break;
            }
            default: {
                return OHOS::ERR_INVALID_VALUE;
            }
        }
    }
    return CheckOperation(userId, deviceId, bundleName, moduleName, abilityName);
}
} // AppExecFwk
} // OHOS