/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "aot/aot_executor.h"

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_extractor.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
const std::string ABC_RELATIVE_PATH = "ets/modules.abc";
const std::string HEX_PREFIX = "0x";
}

AOTExecutor& AOTExecutor::GetInstance()
{
    static AOTExecutor executor;
    return executor;
}

std::string AOTExecutor::DecToHex(uint32_t decimal) const
{
    APP_LOGD("DecToHex begin, decimal : %{public}u", decimal);
    std::stringstream ss;
    ss << std::hex << decimal;
    std::string hexString = HEX_PREFIX + ss.str();
    APP_LOGD("hex : %{public}s", hexString.c_str());
    return hexString;
}

bool AOTExecutor::CheckArgs(const AOTArgs &aotArgs) const
{
    if (aotArgs.compileMode.empty() || aotArgs.hapPath.empty() || aotArgs.outputPath.empty()) {
        APP_LOGE("aotArgs check failed");
        return false;
    }
    if (aotArgs.compileMode == Constants::COMPILE_PARTIAL && aotArgs.arkProfilePath.empty()) {
        APP_LOGE("partial mode, arkProfilePath can't be empty");
        return false;
    }
    return true;
}

bool AOTExecutor::GetAbcFileInfo(const std::string &hapPath, uint32_t &offset, uint32_t &length) const
{
    BundleExtractor extractor(hapPath);
    if (!extractor.Init()) {
        APP_LOGE("init BundleExtractor failed");
        return false;
    }
    if (!extractor.GetFileInfo(ABC_RELATIVE_PATH, offset, length)) {
        APP_LOGE("GetFileInfo failed");
        return false;
    }
    APP_LOGD("GetFileInfo success, offset : %{public}u, length : %{public}u", offset, length);
    return true;
}

ErrCode AOTExecutor::PrepareArgs(const AOTArgs &aotArgs, AOTArgs &completeArgs) const
{
    APP_LOGD("PrepareArgs begin");
    if (!CheckArgs(aotArgs)) {
        APP_LOGE("param check failed");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    uint32_t offset = 0;
    uint32_t length = 0;
    if (!GetAbcFileInfo(aotArgs.hapPath, offset, length)) {
        APP_LOGE("GetAbcFileInfo failed");
        return ERR_APPEXECFWK_INSTALLD_AOT_ABC_NOT_EXIST;
    }
    completeArgs = aotArgs;
    completeArgs.offset = offset;
    completeArgs.length = length;
    APP_LOGD("PrepareArgs success");
    return ERR_OK;
}

void AOTExecutor::ExecuteInChildProcess(const AOTArgs &aotArgs) const
{
    APP_LOGD("begin to execute AOT, args %{public}s", aotArgs.ToString().c_str());
    char path[] = "/system/bin/ark_aot_compiler";

    std::string s1 = "--target-compiler-mode=" + aotArgs.compileMode;
    char arg1[s1.length() + 1];
    strcpy(arg1, s1.c_str());

    std::string s2 = "--hap-path=" + aotArgs.hapPath;
    char arg2[s2.length() + 1];
    strcpy(arg2, s2.c_str());

    std::string s3 = "--compiler-pgo-profiler-path=" + aotArgs.arkProfilePath;
    char arg3[s3.length() + 1];
    strcpy(arg3, s3.c_str());

    std::string s4 = "--aot-file=" + aotArgs.outputPath + Constants::PATH_SEPARATOR + aotArgs.moduleName;
    char arg4[s4.length() + 1];
    strcpy(arg4, s4.c_str());

    std::string s5 = "--hap-abc-offset=" + DecToHex(aotArgs.offset);
    char arg5[s5.length() + 1];
    strcpy(arg5, s5.c_str());

    std::string s6 = "--hap-abc-size=" + DecToHex(aotArgs.length);
    char arg6[s6.length() + 1];
    strcpy(arg6, s6.c_str());

    std::string s7 = aotArgs.hapPath + "/" + ABC_RELATIVE_PATH;
    char arg7[s7.length() + 1];
    strcpy(arg7, s7.c_str());

    APP_LOGD("before execv, 1 : %{public}s, 2 : %{public}s, 3 : %{public}s, 4 : %{public}s, 5 : %{public}s, 6 : %{public}s, 7 : %{public}s",
        arg1, arg2, arg3, arg4, arg5, arg6, arg7);
    if (aotArgs.compileMode == Constants::COMPILE_PARTIAL) {
        char* const argv[] = {path, arg1, arg2, arg3, arg4, arg5, arg6, arg7, NULL};
        execv(path, argv);
    } else {
        char* const argv[] = {path, arg1, arg2, arg4, arg5, arg6, arg7, NULL};
        execv(path, argv);
    }
    APP_LOGE("execv failed : %{public}s", strerror(errno));
    exit(-1);
}

void AOTExecutor::ExecuteInParentProcess(pid_t childPid, ErrCode &ret) const
{
    int status;
    waitpid(childPid, &status, 0);
    if (WIFEXITED(status)) {
        int exit_status = WEXITSTATUS(status);
        APP_LOGD("child process exited with status: %{public}d", exit_status);
        ret = exit_status == 0 ? ERR_OK : ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED;
    } else if (WIFSIGNALED(status)) {
        int signal_number = WTERMSIG(status);
        APP_LOGW("child process terminated by signal: %{public}d", signal_number);
        ret = ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED;
    }
}

void AOTExecutor::ExecuteAOT(const AOTArgs &aotArgs, ErrCode &ret) const
{
    AOTArgs completeArgs;
    ret = PrepareArgs(aotArgs, completeArgs);
    if (ret != ERR_OK) {
        APP_LOGE("PrepareArgs failed");
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    APP_LOGD("begin to fork");
    pid_t pid = fork();
    if (pid == -1) {
        APP_LOGE("fork process failed : %{public}s", strerror(errno));
        ret = ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED;
    } else if (pid == 0) {
        ExecuteInChildProcess(completeArgs);
    } else {
        ExecuteInParentProcess(pid, ret);
    }
}
}  // namespace AppExecFwk
}  // namespace OHOS
