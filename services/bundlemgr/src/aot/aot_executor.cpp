/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <sstream>
#include <string>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_extractor.h"
#include "installd/installd_operator.h"
#include <nlohmann/json.hpp>

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* ABC_RELATIVE_PATH = "ets/modules.abc";
constexpr const char* HEX_PREFIX = "0x";
constexpr const char* BUNDLE_NAME = "bundleName";
constexpr const char* MODULE_NAME = "moduleName";
constexpr const char* PKG_PATH = "pkgPath";
constexpr const char* ABC_NAME = "abcName";
constexpr const char* ABC_OFFSET = "abcOffset";
constexpr const char* ABC_SIZE = "abcSize";
constexpr const char* PROCESS_UID = "processUid";
constexpr const char* BUNDLE_UID = "bundleUid";
constexpr const char* APP_IDENTIFIER = "appIdentifier";
constexpr const char* IS_ENCRYPTED_BUNDLE = "isEncryptedBundle";
constexpr const char* IS_SCREEN_OFF = "isScreenOff";
constexpr const char* PGO_DIR = "pgoDir";
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
    completeArgs = aotArgs;
    if (!GetAbcFileInfo(completeArgs.hapPath, completeArgs.offset, completeArgs.length)) {
        APP_LOGE("GetAbcFileInfo failed");
        return ERR_APPEXECFWK_INSTALLD_AOT_ABC_NOT_EXIST;
    }
    // handle hsp
    for (auto &hspInfo : completeArgs.hspVector) {
        (void)GetAbcFileInfo(hspInfo.hapPath, hspInfo.offset, hspInfo.length);
    }
    APP_LOGD("PrepareArgs success");
    return ERR_OK;
}

nlohmann::json AOTExecutor::GetSubjectInfo(const AOTArgs &aotArgs) const
{
    /* obtain the uid of current process */
    int32_t currentProcessUid = static_cast<int32_t>(getuid());

    std::filesystem::path filePath(aotArgs.arkProfilePath);
    nlohmann::json subject;
    subject[BUNDLE_NAME] = aotArgs.bundleName;
    subject[MODULE_NAME] = aotArgs.moduleName;
    subject[PKG_PATH] = aotArgs.hapPath;
    subject[ABC_NAME] = ABC_RELATIVE_PATH;
    subject[ABC_OFFSET] = DecToHex(aotArgs.offset);
    subject[ABC_SIZE] = DecToHex(aotArgs.length);
    subject[PROCESS_UID] = DecToHex(currentProcessUid);
    subject[BUNDLE_UID] = DecToHex(aotArgs.bundleUid);
    subject[APP_IDENTIFIER] = aotArgs.appIdentifier;
    subject[IS_ENCRYPTED_BUNDLE] = DecToHex(aotArgs.isEncryptedBundle);
    subject[IS_SCREEN_OFF] = DecToHex(aotArgs.isScreenOff);
    subject[PGO_DIR] = filePath.parent_path().string();
    return subject;
}

void AOTExecutor::ExecuteInChildProcess(const AOTArgs &aotArgs) const
{
    APP_LOGD("ExecuteInChildProcess, args : %{public}s", aotArgs.ToString().c_str());
    nlohmann::json subject = GetSubjectInfo(aotArgs);

    nlohmann::json objectArray = nlohmann::json::array();
    for (const auto &hspInfo : aotArgs.hspVector) {
        nlohmann::json object;
        object[BUNDLE_NAME] = hspInfo.bundleName;
        object[MODULE_NAME] = hspInfo.moduleName;
        object[PKG_PATH] = hspInfo.hapPath;
        object[ABC_NAME] = ABC_RELATIVE_PATH;
        object[ABC_OFFSET] = DecToHex(hspInfo.offset);
        object[ABC_SIZE] = DecToHex(hspInfo.length);
        objectArray.push_back(object);
    }

    std::vector<std::string> tmpVector = {
        "/system/bin/ark_aot_compiler",
        "--target-compiler-mode=" + aotArgs.compileMode,
        "--aot-file=" + aotArgs.outputPath + Constants::PATH_SEPARATOR + aotArgs.moduleName,
        "--compiler-pkg-info=" + subject.dump(),
        "--compiler-external-pkg-info=" + objectArray.dump(),
        "--compiler-opt-bc-range=" + aotArgs.optBCRangeList,
        "--compiler-device-state=" + std::to_string(aotArgs.isScreenOff)
    };
    tmpVector.emplace_back(aotArgs.hapPath + Constants::PATH_SEPARATOR + ABC_RELATIVE_PATH);

    std::vector<const char*> argv;
    argv.reserve(tmpVector.size() + 1);
    for (const auto &arg : tmpVector) {
        argv.emplace_back(arg.c_str());
    }
    argv.emplace_back(nullptr);
    APP_LOGD("argv size : %{public}zu", argv.size());
    for (const auto &arg : argv) {
        APP_LOGD("%{public}s", arg);
    }
    execv(argv[0], const_cast<char* const*>(argv.data()));
    APP_LOGE("execv failed : %{public}s", strerror(errno));
    exit(-1);
}

void AOTExecutor::ExecuteInParentProcess(const AOTArgs &aotArgs, pid_t childPid, ErrCode &ret)
{
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        InitState(aotArgs, childPid);
    }

    int status;
    int waitRet = waitpid(childPid, &status, 0);
    if (waitRet == -1) {
        APP_LOGE("waitpid failed");
        ret = ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED;
    } else if (WIFEXITED(status)) {
        int exit_status = WEXITSTATUS(status);
        APP_LOGI("child process exited with status: %{public}d", exit_status);
        ret = exit_status == 0 ? ERR_OK : ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED;
    } else if (WIFSIGNALED(status)) {
        int signal_number = WTERMSIG(status);
        APP_LOGW("child process terminated by signal: %{public}d", signal_number);
        ret = ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED;
    } else if (WIFSTOPPED(status)) {
        int signal_number = WSTOPSIG(status);
        APP_LOGW("child process was stopped by signal: %{public}d", signal_number);
        ret = ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED;
    } else if (WIFCONTINUED(status)) {
        APP_LOGW("child process was resumed");
        ret = ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED;
    } else {
        APP_LOGW("unknown");
        ret = ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED;
    }

    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        ResetState();
    }
}

void AOTExecutor::ExecuteAOT(const AOTArgs &aotArgs, ErrCode &ret)
{
    APP_LOGI("begin to execute AOT");
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        if (state_.running) {
            APP_LOGI("AOT is running, ignore");
            ret = ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED;
            return;
        }
    }

    AOTArgs completeArgs;
    ret = PrepareArgs(aotArgs, completeArgs);
    if (ret != ERR_OK) {
        APP_LOGE("PrepareArgs failed");
        return;
    }
    APP_LOGI("begin to fork");
    pid_t pid = fork();
    if (pid == -1) {
        APP_LOGE("fork process failed : %{public}s", strerror(errno));
        ret = ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED;
    } else if (pid == 0) {
        ExecuteInChildProcess(completeArgs);
    } else {
        ExecuteInParentProcess(aotArgs, pid, ret);
    }
}

ErrCode AOTExecutor::StopAOT()
{
    APP_LOGI("begin to stop AOT");
    std::lock_guard<std::mutex> lock(stateMutex_);
    if (!state_.running) {
        APP_LOGI("AOT not running, return directly");
        return ERR_OK;
    }
    if (state_.childPid <= 0) {
        APP_LOGE("invalid child pid");
        return ERR_APPEXECFWK_INSTALLD_STOP_AOT_FAILED;
    }
    APP_LOGI("begin to kill child process : %{public}d", state_.childPid);
    (void)kill(state_.childPid, SIGKILL);
    (void)InstalldOperator::DeleteDir(state_.outputPath);
    ResetState();
    return ERR_OK;
}

void AOTExecutor::InitState(const AOTArgs &aotArgs, pid_t childPid)
{
    state_.running = true;
    state_.childPid = childPid;
    state_.outputPath = aotArgs.outputPath;
}

void AOTExecutor::ResetState()
{
    state_.running = false;
    state_.childPid = -1;
    state_.outputPath.clear();
}
}  // namespace AppExecFwk
}  // namespace OHOS
