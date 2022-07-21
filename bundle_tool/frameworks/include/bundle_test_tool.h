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

#ifndef FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_BUNDLE_TOOL_INCLUDE_BUNDLE_TEST_TOOL_H
#define FOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_BUNDLE_TOOL_INCLUDE_BUNDLE_TEST_TOOL_H

#include "shell_command.h"
#include "bundle_mgr_interface.h"
#include "bundle_installer_interface.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
static const std::string TOOL_NAME = "bundle_test_tool";
static const std::string HELP_MSG = "usage: bundle_test_tool <command> <options>\n"
                             "These are common bundle_test_tool commands list:\n"
                             "  help         list available commands\n"
                             "  setrm        set module isRemovable by given bundle name and module name\n"
                             "  getrm        obtain the value of isRemovable by given bundle name and module name\n";

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

const std::string STRING_SET_REMOVABLE_OK = "set removable is ok";
const std::string STRING_SET_REMOVABLE_NG = "error: failed to set removable";
const std::string STRING_GET_REMOVABLE_OK = "get removable is ok";
const std::string STRING_GET_REMOVABLE_NG = "error: failed to get removable";
const std::string STRING_REQUIRE_CORRECT_VALUE = "error: option requires a correct value.\n";
}
class BundleTestTool : public ShellCommand {
public:
    BundleTestTool(int argc, char *argv[]);
    ~BundleTestTool();

private:
    ErrCode CreateCommandMap() override;
    ErrCode CreateMessageMap() override;
    ErrCode Init() override;

    ErrCode RunAsHelpCommand();
    ErrCode RunAsCheckCommand();
    ErrCode CheckOperation(int userId, std::string deviceId, std::string bundleName,
        std::string moduleName, std::string abilityName);
    ErrCode RunAsSetRmCommand();
    ErrCode RunAsGetRmCommand();

    std::condition_variable cv_;
    std::mutex mutex_;

    sptr<IBundleMgr> bundleMgrProxy_;
    sptr<IBundleInstaller> bundleInstallerProxy_;

    bool CheckRmErrorOption(int option, int counter, std::string &name);
    bool CheckRmCorrectOption(int option, std::string &name, int &isRemovable, bool &setRemovable);
    bool SetIsRemovableOperation(const std::string &bundleName, const std::string &moduleName, int isRemovable) const;
    bool GetIsRemovableOperation(
        const std::string &bundleName, const std::string &moduleName, std::string &result) const;
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif  // FFOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_BUNDLE_TOOL_INCLUDE_BUNDLE_TEST_TOOL_H