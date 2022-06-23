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
class BundleTestTool : public ShellCommand {
public:
    BundleTestTool(int argc, char *argv[]);
    ~BundleTestTool();

private:
    ErrCode CreateCommandMap() override;
    ErrCode CreateMessageMap() override;
    ErrCode Init() override;

    ErrCode RunAsHelpCommand();

    sptr<IBundleMgr> bundleMgrProxy_;
    sptr<IBundleInstaller> bundleInstallerProxy_;
};
}  // namespace AppExecFwk
}  // namespace OHOS

#endif  // FFOUNDATION_BUNDLEMANAGER_BUNDLE_FRAMEWORK_BUNDLE_TOOL_INCLUDE_BUNDLE_TEST_TOOL_H