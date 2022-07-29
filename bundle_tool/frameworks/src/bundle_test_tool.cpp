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
#include <iostream>

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
#include "json_util.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
static const std::string TOOL_NAME = "bundle_test_tool";
static const std::string HELP_MSG = "usage: bundle_test_tool <command> <options>\n"
                             "These are common bundle_test_tool commands list:\n"
                             "  help         list available commands\n"
                             "  setrm        set module isRemovable by given bundle name and module name\n"
                             "  getrm        obtain the value of isRemovable by given bundle name and module name\n"
                             "  installSandbox      indicates install sandbox\n"
                             "  uninstallSandbox    indicates uninstall sandbox\n"
                             "  dumpSandbox         indicates dump sandbox info\n";

const std::string HELP_MSG_GET_REMOVABLE =
    "usage: bundle_test_tool getrm <options>\n"
    "eg:bundle_test_tool getrm -m <module-name> -n <bundle-name> \n"
    "options list:\n"
    "  -h, --help                             list available commands\n"
    "  -n, --bundle-name  <bundle-name>       get isRemovable by moduleNmae and bundleName\n"
    "  -m, --module-name <module-name>        get isRemovable by moduleNmae and bundleName\n";

const std::string HELP_MSG_NO_REMOVABLE_OPTION =
    "error: you must specify a bundle name with '-n' or '--bundle-name' \n"
    "and a module name with '-m' or '--module-name' \n";

const std::string HELP_MSG_SET =
    "usage: bundle_test_tool setrm <options>\n"
    "eg:bundle_test_tool setrm -m <module-name> -n <bundle-name> -i 1\n"
    "options list:\n"
    "  -h, --help                               list available commands\n"
    "  -n, --bundle-name  <bundle-name>         set isRemovable by moduleNmae and bundleName\n"
    "  -i, --is-removable <is-removable>        set isRemovable  0 or 1\n"
    "  -m, --module-name <module-name>          set isRemovable by moduleNmae and bundleName\n";

const std::string HELP_MSG_INSTALL_SANDBOX =
    "usage: bundle_test_tool installSandbox <options>\n"
    "options list:\n"
    "  -h, --help                             list available commands\n"
    "  -u, --user-id <user-id>                specify a user id\n"
    "  -n, --bundle-name <bundle-name>        install a sandbox of a bundle\n"
    "  -d, --dlp-type <dlp-type>              specify type of the sandbox application\n";

const std::string HELP_MSG_UNINSTALL_SANDBOX =
    "usage: bundle_test_tool uninstallSandbox <options>\n"
    "options list:\n"
    "  -h, --help                             list available commands\n"
    "  -u, --user-id <user-id>                specify a user id\n"
    "  -a, --app-index <app-index>            specify a app index\n"
    "  -n, --bundle-nam e <bundle-name>        install a sandbox of a bundle\n";

const std::string HELP_MSG_DUMP_SANDBOX =
    "usage: bundle_test_tool dumpSandbox <options>\n"
    "options list:\n"
    "  -h, --help                             list available commands\n"
    "  -u, --user-id <user-id>                specify a user id\n"
    "  -a, --app-index <app-index>            specify a app index\n"
    "  -n, --bundle-name <bundle-name>        install a sandbox of a bundle\n";

const std::string HELP_MSG_NO_BUNDLE_NAME_OPTION =
    "error: you must specify a bundle name with '-n' or '--bundle-name' \n";

const std::string STRING_SET_REMOVABLE_OK = "set removable is ok \n";
const std::string STRING_SET_REMOVABLE_NG = "error: failed to set removable \n";
const std::string STRING_GET_REMOVABLE_OK = "get removable is ok \n";
const std::string STRING_GET_REMOVABLE_NG = "error: failed to get removable \n";
const std::string STRING_REQUIRE_CORRECT_VALUE =
    "error: option requires a correct value or note that\n"
    "the difference in expressions between short option and long option. \n";

const std::string STRING_INSTALL_SANDBOX_SUCCESSFULLY = "install sandbox app successfully \n";
const std::string STRING_INSTALL_SANDBOX_FAILED = "install sandbox app failed \n";

const std::string STRING_UNINSTALL_SANDBOX_SUCCESSFULLY = "uninstall sandbox app successfully\n";
const std::string STRING_UNINSTALL_SANDBOX_FAILED = "uninstall sandbox app failed\n";

const std::string STRING_DUMP_SANDBOX_FAILED = "dump sandbox app info failed\n";

const std::string GET_RM = "getrm";
const std::string SET_RM = "setrm";
const std::string INSTALL_SANDBOX = "installSandbox";
const std::string UNINSTALL_SANDBOX = "uninstallSandbox";
const std::string DUMP_SANDBOX = "dumpSandbox";

const std::string SHORT_OPTIONS = "hn:m:a:d:u:i:";
const struct option LONG_OPTIONS[] = {
    {"help", no_argument, nullptr, 'h'},
    {"bundle-name", required_argument, nullptr, 'n'},
    {"module-name", required_argument, nullptr, 'm'},
    {"ability-name", required_argument, nullptr, 'a'},
    {"device-id", required_argument, nullptr, 'd'},
    {"user-id", required_argument, nullptr, 'u'},
    {"is-removable", required_argument, nullptr, 'i'},
    {nullptr, 0, nullptr, 0},
};

const std::string SHORT_OPTIONS_SANDBOX = "hn:d:u:a:";
const struct option LONG_OPTIONS_SANDBOX[] = {
    {"help", no_argument, nullptr, 'h'},
    {"bundle-name", required_argument, nullptr, 'n'},
    {"user-id", required_argument, nullptr, 'u'},
    {"dlp-type", required_argument, nullptr, 'd'},
    {"app-index", required_argument, nullptr, 'a'},
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
        {"setrm", std::bind(&BundleTestTool::RunAsSetRemovableCommand, this)},
        {"getrm", std::bind(&BundleTestTool::RunAsGetRemovableCommand, this)},
        {"installSandbox", std::bind(&BundleTestTool::RunAsInstallSandboxCommand, this)},
        {"uninstallSandbox", std::bind(&BundleTestTool::RunAsUninstallSandboxCommand, this)},
        {"dumpSandbox", std::bind(&BundleTestTool::RunAsDumpSandboxCommand, this)},
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

bool BundleTestTool::SetIsRemovableOperation(
    const std::string &bundleName, const std::string &moduleName, int isRemovable) const
{
    bool enable = true;
    if (isRemovable == 0) {
        enable = false;
    }
    APP_LOGD("bundleName: %{public}s, moduleName:%{public}s, enable:%{public}d", bundleName.c_str(), moduleName.c_str(),
        enable);
    auto ret = bundleMgrProxy_->SetModuleRemovable(bundleName, moduleName, enable);
    APP_LOGD("SetModuleRemovable end bundleName: %{public}d", ret);
    if (!ret) {
        APP_LOGE("SetIsRemovableOperation failed");
        return false;
    }
    return ret;
}

bool BundleTestTool::GetIsRemovableOperation(
    const std::string &bundleName, const std::string &moduleName, std::string &result) const
{
    APP_LOGD("bundleName: %{public}s, moduleName:%{public}s", bundleName.c_str(), moduleName.c_str());
    auto ret = bundleMgrProxy_->IsModuleRemovable(bundleName, moduleName);
    APP_LOGD("IsModuleRemovable end bundleName: %{public}s, ret:%{public}d", bundleName.c_str(), ret);
    result.append("isRemovable: " + std::to_string(ret) + "\n");
    return ret;
}

bool BundleTestTool::CheckRemovableErrorOption(int option, int counter, const std::string &commandName)
{
    if (option == -1) {
        if (counter == 1) {
            if (strcmp(argv_[optind], cmd_.c_str()) == 0) {
                // 'bundle_test_tool setrm/getrm' with no option: bundle_test_tool setrm/getrm
                // 'bundle_test_tool setrm/getrm' with a wrong argument: bundle_test_tool setrm/getrm xxx
                APP_LOGD("'bundle_test_tool %{public}s' with no option.", commandName.c_str());
                resultReceiver_.append(HELP_MSG_NO_OPTION + "\n");
                return false;
            }
        }
        return true;
    } else if (option == '?') {
        switch (optopt) {
            case 'i': {
                if (commandName == GET_RM) {
                    std::string unknownOption = "";
                    std::string unknownOptionMsg = GetUnknownOptionMsg(unknownOption);
                    APP_LOGD("'bundle_test_tool %{public}s' with an unknown option.", commandName.c_str());
                    resultReceiver_.append(unknownOptionMsg);
                } else {
                    APP_LOGD("'bundle_test_tool %{public}s -i' with no argument.", commandName.c_str());
                    resultReceiver_.append("error: -i option requires a value.\n");
                }
                break;
            }
            case 'm': {
                APP_LOGD("'bundle_test_tool %{public}s -m' with no argument.", commandName.c_str());
                resultReceiver_.append("error: -m option requires a value.\n");
                break;
            }
            case 'n': {
                APP_LOGD("'bundle_test_tool %{public}s -n' with no argument.", commandName.c_str());
                resultReceiver_.append("error: -n option requires a value.\n");
                break;
            }
            default: {
                std::string unknownOption = "";
                std::string unknownOptionMsg = GetUnknownOptionMsg(unknownOption);
                APP_LOGD("'bundle_test_tool %{public}s' with an unknown option.", commandName.c_str());
                resultReceiver_.append(unknownOptionMsg);
                break;
            }
        }
    }
    return false;
}

bool BundleTestTool::CheckRemovableCorrectOption(
    int option, const std::string &commandName, int &isRemovable, std::string &name)
{
    bool ret = true;
    switch (option) {
        case 'h': {
            APP_LOGD("'bundle_test_tool %{public}s %{public}s'", commandName.c_str(), argv_[optind - 1]);
            ret = false;
            break;
        }
        case 'n': {
            name = optarg;
            APP_LOGD("'bundle_test_tool %{public}s -n %{public}s'", commandName.c_str(), argv_[optind - 1]);
            break;
        }
        case 'i': {
            if (commandName == GET_RM) {
                std::string unknownOption = "";
                std::string unknownOptionMsg = GetUnknownOptionMsg(unknownOption);
                APP_LOGD("'bundle_test_tool %{public}s' with an unknown option.", commandName.c_str());
                resultReceiver_.append(unknownOptionMsg);
                ret = false;
            } else if (OHOS::StrToInt(optarg, isRemovable)) {
                APP_LOGD("'bundle_test_tool %{public}s -i isRemovable:%{public}d, %{public}s'",
                    commandName.c_str(), isRemovable, argv_[optind - 1]);
            } else {
                APP_LOGE("bundle_test_tool setrm with error %{private}s", optarg);
                resultReceiver_.append(STRING_REQUIRE_CORRECT_VALUE);
                ret = false;
            }
            break;
        }
        case 'm': {
            name = optarg;
            APP_LOGD("'bundle_test_tool %{public}s -m module-name:%{public}s, %{public}s'",
                commandName.c_str(), name.c_str(), argv_[optind - 1]);
            break;
        }
        default: {
            std::string unknownOption = "";
            std::string unknownOptionMsg = GetUnknownOptionMsg(unknownOption);
            APP_LOGD("'bundle_test_tool %{public}s' with an unknown option.", commandName.c_str());
            resultReceiver_.append(unknownOptionMsg);
            ret = false;
            break;
        }
    }
    return ret;
}

ErrCode BundleTestTool::RunAsSetRemovableCommand()
{
    int result = OHOS::ERR_OK;
    int option = -1;
    int counter = 0;
    int isRemovable = 0;
    std::string commandName = SET_RM;
    std::string name = "";
    std::string bundleName = "";
    std::string moduleName = "";
    APP_LOGD("RunAsSetCommand is start");
    while (true) {
        counter++;
        option = getopt_long(argc_, argv_, SHORT_OPTIONS.c_str(), LONG_OPTIONS, nullptr);
        if (optind < 0 || optind > argc_) {
            return OHOS::ERR_INVALID_VALUE;
        }
        APP_LOGD("option: %{public}d, optopt: %{public}d, optind: %{public}d, argv_[optind - 1]:%{public}s", option,
            optopt, optind, argv_[optind - 1]);
        if (option == -1 || option == '?') {
            result = !CheckRemovableErrorOption(option, counter, commandName)? OHOS::ERR_INVALID_VALUE : result;
            break;
        }
        result = !CheckRemovableCorrectOption(option, commandName, isRemovable, name)
            ? OHOS::ERR_INVALID_VALUE : result;
        moduleName = option == 'm' ? name : moduleName;
        bundleName = option == 'n' ? name : bundleName;
    }
    if (result == OHOS::ERR_OK) {
        if (resultReceiver_ == "" && (bundleName.size() == 0 || moduleName.size() == 0)) {
            APP_LOGD("'bundle_test_tool setrm' with not enough option.");
            resultReceiver_.append(HELP_MSG_NO_REMOVABLE_OPTION);
            result = OHOS::ERR_INVALID_VALUE;
        }
    }
    if (result != OHOS::ERR_OK) {
        resultReceiver_.append(HELP_MSG_SET);
    } else {
        bool setResult = false;
        setResult = SetIsRemovableOperation(bundleName, moduleName, isRemovable);
        APP_LOGD("'bundle_test_tool setrm' isRemovable is %{public}d", isRemovable);
        resultReceiver_ = setResult ? STRING_SET_REMOVABLE_OK : STRING_SET_REMOVABLE_NG;
    }
    return result;
}

ErrCode BundleTestTool::RunAsGetRemovableCommand()
{
    int result = OHOS::ERR_OK;
    int option = -1;
    int counter = 0;
    std::string commandName = GET_RM;
    std::string name = "";
    std::string bundleName = "";
    std::string moduleName = "";
    APP_LOGD("RunAsGetRemovableCommand is start");
    while (true) {
        counter++;
        option = getopt_long(argc_, argv_, SHORT_OPTIONS.c_str(), LONG_OPTIONS, nullptr);
        APP_LOGD("option: %{public}d, optopt: %{public}d, optind: %{public}d", option, optopt, optind);
        if (optind < 0 || optind > argc_) {
            return OHOS::ERR_INVALID_VALUE;
        }
        if (option == -1 || option == '?') {
            result = !CheckRemovableErrorOption(option, counter, commandName) ? OHOS::ERR_INVALID_VALUE : result;
            break;
        }
        int tempIsRem = 0;
        result = !CheckRemovableCorrectOption(option, commandName, tempIsRem, name)
            ? OHOS::ERR_INVALID_VALUE : result;
        moduleName = option == 'm' ? name : moduleName;
        bundleName = option == 'n' ? name : bundleName;
    }

    if (result == OHOS::ERR_OK) {
        if (resultReceiver_ == "" && (bundleName.size() == 0 || moduleName.size() == 0)) {
            APP_LOGD("'bundle_test_tool getrm' with no option.");
            resultReceiver_.append(HELP_MSG_NO_REMOVABLE_OPTION);
            result = OHOS::ERR_INVALID_VALUE;
        }
    }

    if (result != OHOS::ERR_OK) {
        resultReceiver_.append(HELP_MSG_GET_REMOVABLE);
    } else {
        std::string results = "";
        GetIsRemovableOperation(bundleName, moduleName, results);
        if (results.empty()) {
            resultReceiver_.append(STRING_GET_REMOVABLE_NG);
            return result;
        }
        resultReceiver_.append(results);
    }
    return result;
}

bool BundleTestTool::CheckSandboxErrorOption(int option, int counter, const std::string &commandName)
{
    if (option == -1) {
        if (counter == 1) {
            if (strcmp(argv_[optind], cmd_.c_str()) == 0) {
                APP_LOGD("'bundle_test_tool %{public}s' with no option.", commandName.c_str());
                resultReceiver_.append(HELP_MSG_NO_OPTION + "\n");
                return false;
            }
        }
        return true;
    } else if (option == '?') {
        switch (optopt) {
            case 'n':
            case 'u':
            case 'd':
            case 'a': {
                if ((commandName != INSTALL_SANDBOX && optopt == 'd') ||
                    (commandName == INSTALL_SANDBOX && optopt == 'a')) {
                    std::string unknownOption = "";
                    std::string unknownOptionMsg = GetUnknownOptionMsg(unknownOption);
                    APP_LOGD("'bundle_test_tool %{public}s' with an unknown option.", commandName.c_str());
                    resultReceiver_.append(unknownOptionMsg);
                    break;
                }
                APP_LOGD("'bundle_test_tool %{public}s' -%{public}c with no argument.", commandName.c_str(), optopt);
                resultReceiver_.append("error: option requires a value.\n");
                break;
            }
            default: {
                std::string unknownOption = "";
                std::string unknownOptionMsg = GetUnknownOptionMsg(unknownOption);
                APP_LOGD("'bundle_test_tool %{public}s' with an unknown option.", commandName.c_str());
                resultReceiver_.append(unknownOptionMsg);
                break;
            }
        }
    }
    return false;
}

bool BundleTestTool::CheckSandboxCorrectOption(
    int option, const std::string &commandName, int &data, std::string &bundleName)
{
    bool ret = true;
    switch (option) {
        case 'h': {
            APP_LOGD("'bundle_test_tool %{public}s %{public}s'", commandName.c_str(), argv_[optind - 1]);
            ret = false;
            break;
        }
        case 'n': {
            APP_LOGD("'bundle_test_tool %{public}s %{public}s'", commandName.c_str(), argv_[optind - 1]);
            bundleName = optarg;
            break;
        }
        case 'u':
        case 'a':
        case 'd': {
            if ((commandName != INSTALL_SANDBOX && option == 'd') ||
                (commandName == INSTALL_SANDBOX && option == 'a')) {
                std::string unknownOption = "";
                std::string unknownOptionMsg = GetUnknownOptionMsg(unknownOption);
                APP_LOGD("'bundle_test_tool %{public}s' with an unknown option.", commandName.c_str());
                resultReceiver_.append(unknownOptionMsg);
                ret = false;
                break;
            }

            APP_LOGD("'bundle_test_tool %{public}s %{public}s %{public}s'", commandName.c_str(),
                argv_[optind - OFFSET_REQUIRED_ARGUMENT], optarg);

            if (!OHOS::StrToInt(optarg, data)) {
                if (option == 'u') {
                    APP_LOGE("bundle_test_tool %{public}s with error -u %{private}s", commandName.c_str(), optarg);
                } else if (option == 'a') {
                    APP_LOGE("bundle_test_tool %{public}s with error -a %{private}s", commandName.c_str(), optarg);
                } else {
                    APP_LOGE("bundle_test_tool %{public}s with error -d %{private}s", commandName.c_str(), optarg);
                }
                resultReceiver_.append(STRING_REQUIRE_CORRECT_VALUE);
                ret = false;
            }
            break;
        }
        default: {
            ret = false;
            break;
        }
    }
    return ret;
}

ErrCode BundleTestTool::InstallSandboxOperation(
    const std::string &bundleName, const int32_t userId, const int32_t dlpType, int32_t &appIndex) const
{
    APP_LOGD("InstallSandboxOperation of bundleName %{public}s, dipType is %{public}d", bundleName.c_str(), dlpType);
    return bundleInstallerProxy_->InstallSandboxApp(bundleName, dlpType, userId, appIndex);
}

ErrCode BundleTestTool::RunAsInstallSandboxCommand()
{
    int result = OHOS::ERR_OK;
    int option = -1;
    int counter = 0;
    std::string commandName = INSTALL_SANDBOX;
    std::string bundleName = "";
    int32_t userId = 100;
    int32_t dlpType = 0;
    while (true) {
        counter++;
        option = getopt_long(argc_, argv_, SHORT_OPTIONS_SANDBOX.c_str(), LONG_OPTIONS_SANDBOX, nullptr);
        APP_LOGD("option: %{public}d, optopt: %{public}d, optind: %{public}d", option, optopt, optind);
        if (optind < 0 || optind > argc_) {
            return OHOS::ERR_INVALID_VALUE;
        }
        if (option == -1 || option == '?') {
            result = !CheckSandboxErrorOption(option, counter, commandName) ? OHOS::ERR_INVALID_VALUE : result;
            break;
        } else if (option == 'u') {
            result = !CheckSandboxCorrectOption(option, commandName, userId, bundleName) ?
                OHOS::ERR_INVALID_VALUE : result;
        } else {
            result = !CheckSandboxCorrectOption(option, commandName, dlpType, bundleName) ?
                OHOS::ERR_INVALID_VALUE : result;
        }
    }

    if (result == OHOS::ERR_OK && bundleName == "") {
        resultReceiver_.append(HELP_MSG_NO_BUNDLE_NAME_OPTION);
        result = OHOS::ERR_INVALID_VALUE;
    } else {
        APP_LOGD("installSandbox app bundleName is %{public}s", bundleName.c_str());
    }

    if (result != OHOS::ERR_OK) {
        resultReceiver_.append(HELP_MSG_INSTALL_SANDBOX);
        return result;
    }

    int32_t appIndex = 0;
    auto ret = InstallSandboxOperation(bundleName, userId, dlpType, appIndex);
    if (ret == OHOS::ERR_OK) {
        resultReceiver_.append(STRING_INSTALL_SANDBOX_SUCCESSFULLY);
    } else {
        resultReceiver_.append(STRING_INSTALL_SANDBOX_FAILED + "errCode is "+ std::to_string(ret) + "\n");
    }
    return result;
}

ErrCode BundleTestTool::UninstallSandboxOperation(const std::string &bundleName,
    const int32_t appIndex, const int32_t userId) const
{
    APP_LOGD("UninstallSandboxOperation of bundleName %{public}s_%{public}d", bundleName.c_str(), appIndex);
    return bundleInstallerProxy_->UninstallSandboxApp(bundleName, appIndex, userId);
}

ErrCode BundleTestTool::RunAsUninstallSandboxCommand()
{
    int result = OHOS::ERR_OK;
    int option = -1;
    int counter = 0;
    std::string bundleName = "";
    std::string commandName = UNINSTALL_SANDBOX;
    int32_t userId = 100;
    int32_t appIndex = -1;
    while (true) {
        counter++;
        option = getopt_long(argc_, argv_, SHORT_OPTIONS_SANDBOX.c_str(), LONG_OPTIONS_SANDBOX, nullptr);
        APP_LOGD("option: %{public}d, optopt: %{public}d, optind: %{public}d", option, optopt, optind);
        if (optind < 0 || optind > argc_) {
            return OHOS::ERR_INVALID_VALUE;
        }
         
        if (option == -1 || option == '?') {
            result = !CheckSandboxErrorOption(option, counter, commandName) ? OHOS::ERR_INVALID_VALUE : result;
            break;
        } else if (option == 'u') {
            result = !CheckSandboxCorrectOption(option, commandName, userId, bundleName) ?
                OHOS::ERR_INVALID_VALUE : result;
        } else {
            result = !CheckSandboxCorrectOption(option, commandName, appIndex, bundleName) ?
                OHOS::ERR_INVALID_VALUE : result;
        }
    }

    if (result == OHOS::ERR_OK && bundleName == "") {
        resultReceiver_.append(HELP_MSG_NO_BUNDLE_NAME_OPTION);
        result = OHOS::ERR_INVALID_VALUE;
    } else {
        APP_LOGD("uninstallSandbox app bundleName is %{private}s", bundleName.c_str());
    }
    
    if (result != OHOS::ERR_OK) {
        resultReceiver_.append(HELP_MSG_UNINSTALL_SANDBOX);
        return result;
    }

    auto ret = UninstallSandboxOperation(bundleName, appIndex, userId);
    if (ret == ERR_OK) {
        resultReceiver_.append(STRING_UNINSTALL_SANDBOX_SUCCESSFULLY);
    } else {
        resultReceiver_.append(STRING_UNINSTALL_SANDBOX_FAILED + "errCode is " + std::to_string(ret) + "\n");
    }
    return result;
}

ErrCode BundleTestTool::DumpSandboxBundleInfo(const std::string &bundleName, const int32_t appIndex,
    const int32_t userId, std::string &dumpResults)
{
    APP_LOGD("DumpSandboxBundleInfo of bundleName %{public}s_%{public}d", bundleName.c_str(), appIndex);
    BundleInfo bundleInfo;
    BundleMgrClient client;
    auto dumpRet = client.GetSandboxBundleInfo(bundleName, appIndex, userId, bundleInfo);
    if (dumpRet == ERR_OK) {
        nlohmann::json jsonObject = bundleInfo;
        dumpResults= jsonObject.dump(Constants::DUMP_INDENT);
    }
    return dumpRet;
}

ErrCode BundleTestTool::RunAsDumpSandboxCommand()
{
    int result = OHOS::ERR_OK;
    int option = -1;
    int counter = 0;
    std::string bundleName = "";
    std::string commandName = DUMP_SANDBOX;
    int32_t userId = 100;
    int32_t appIndex = -1;
    while (true) {
        counter++;
        option = getopt_long(argc_, argv_, SHORT_OPTIONS_SANDBOX.c_str(), LONG_OPTIONS_SANDBOX, nullptr);
        APP_LOGD("option: %{public}d, optopt: %{public}d, optind: %{public}d", option, optopt, optind);
        if (optind < 0 || optind > argc_) {
            return OHOS::ERR_INVALID_VALUE;
        }
        if (option == -1 || option == '?') {
            result = !CheckSandboxErrorOption(option, counter, commandName) ? OHOS::ERR_INVALID_VALUE : result;
            break;
        } else if (option == 'u') {
            result = !CheckSandboxCorrectOption(option, commandName, userId, bundleName) ?
                OHOS::ERR_INVALID_VALUE : result;
        } else {
            result = !CheckSandboxCorrectOption(option, commandName, appIndex, bundleName) ?
                OHOS::ERR_INVALID_VALUE : result;
        }
    }

    if (result == OHOS::ERR_OK && bundleName == "") {
        resultReceiver_.append(HELP_MSG_NO_BUNDLE_NAME_OPTION);
        result = OHOS::ERR_INVALID_VALUE;
    } else {
        APP_LOGD("dumpSandbox app bundleName is %{public}s", bundleName.c_str());
    }
    
    if (result != OHOS::ERR_OK) {
        resultReceiver_.append(HELP_MSG_DUMP_SANDBOX);
        return result;
    }

    std::string dumpRes = "";
    ErrCode ret = DumpSandboxBundleInfo(bundleName, appIndex, userId, dumpRes);
    if (ret == ERR_OK) {
        resultReceiver_.append(dumpRes);
    } else {
        resultReceiver_.append(STRING_DUMP_SANDBOX_FAILED + "errCode is "+ std::to_string(ret) + "\n");
    }
    return result;
}
} // AppExecFwk
} // OHOS