/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
#include <string>
#include <sys/wait.h>
#include <unistd.h>

#include "app_log_tag_wrapper.h"
#include "app_log_wrapper.h"
#include "bundle_constants.h"
#include "bundle_extractor.h"
#include "bundle_service_constants.h"
#if defined(CODE_SIGNATURE_ENABLE)
#include "aot_compiler_client.h"
#include "code_sign_utils.h"
#endif
#include "installd/installd_operator.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* ABC_RELATIVE_PATH = "ets/modules.abc";
constexpr const char* STATIC_ABC_RELATIVE_PATH = "ets/modules_static.abc";
constexpr uint8_t SHARED_BUNDLE_TYPE = 2; // Keep aligned with BundleType::SHARED.
#if defined(CODE_SIGNATURE_ENABLE)
constexpr int16_t ERR_AOT_COMPILER_SIGN_FAILED = 10004;
constexpr int16_t ERR_AOT_COMPILER_CALL_CRASH = 10008;
constexpr int16_t ERR_AOT_COMPILER_CALL_CANCELLED = 10009;
constexpr int16_t ERR_OK_AOT_FILE_EXIST = 10012;
#endif
}

AOTExecutor& AOTExecutor::GetInstance()
{
    static AOTExecutor executor;
    return executor;
}

bool AOTExecutor::CheckArgs(const AOTArgs &aotArgs) const
{
    if (aotArgs.hapPath.empty() || aotArgs.outputPath.empty()) {
        APP_LOGE("aotArgs check failed");
        return false;
    }
    return true;
}

std::string AOTExecutor::GetAbcRelativePath(const std::string &moduleArkTSMode) const
{
    if (moduleArkTSMode == Constants::ARKTS_MODE_DYNAMIC) {
        return ABC_RELATIVE_PATH;
    }
    if (moduleArkTSMode == Constants::ARKTS_MODE_STATIC || moduleArkTSMode == Constants::ARKTS_MODE_HYBRID) {
        return STATIC_ABC_RELATIVE_PATH;
    }
    APP_LOGW("invalid moduleArkTSMode : %{public}s", moduleArkTSMode.c_str());
    return Constants::EMPTY_STRING;
}

bool AOTExecutor::GetAbcFileInfo(const std::string &hapPath, const std::string &moduleArkTSMode,
    uint32_t &offset, uint32_t &length) const
{
    BundleExtractor extractor(hapPath);
    if (!extractor.Init()) {
        APP_LOGE("init BundleExtractor failed");
        return false;
    }
    std::string abcRelativePath = GetAbcRelativePath(moduleArkTSMode);
    if (abcRelativePath.empty()) {
        APP_LOGE("abcRelativePath empty");
        return false;
    }
    if (!extractor.GetFileInfo(abcRelativePath, offset, length)) {
        APP_LOGE("GetFileInfo failed");
        return false;
    }
    APP_LOGD("GetFileInfo success, offset : %{public}u, length : %{public}u", offset, length);
    return true;
}

ErrCode AOTExecutor::PrepareArgs(const AOTArgs &aotArgs, AOTArgs &completeArgs) const
{
    APP_LOGD("PrepareArgs begin");
    if (aotArgs.isSysComp) {
        APP_LOGD("sysComp, no need to prepare args");
        completeArgs = aotArgs;
        return ERR_OK;
    }
    if (!CheckArgs(aotArgs)) {
        APP_LOGE("param check failed");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    completeArgs = aotArgs;
    if (!GetAbcFileInfo(completeArgs.hapPath, completeArgs.moduleArkTSMode,
        completeArgs.offset, completeArgs.length)) {
        APP_LOGE("GetAbcFileInfo failed");
        return ERR_APPEXECFWK_INSTALLD_AOT_ABC_NOT_EXIST;
    }
    // handle hsp
    for (auto &hspInfo : completeArgs.hspVector) {
        (void)GetAbcFileInfo(hspInfo.hapPath, hspInfo.moduleArkTSMode, hspInfo.offset, hspInfo.length);
    }
    APP_LOGD("PrepareArgs success");
    return ERR_OK;
}

ErrCode AOTExecutor::PendSignAOT(const std::string &anFileName, const std::vector<uint8_t> &signData) const
{
    return EnforceCodeSign(anFileName, signData);
}

ErrCode AOTExecutor::EnforceCodeSign(const std::string &anFileName, const std::vector<uint8_t> &signData) const
{
#if defined(CODE_SIGNATURE_ENABLE)
    if (signData.empty()) {
        APP_LOGI("not enforce code sign if no aot file save");
        return ERR_OK;
    }
    uint32_t dataSize = static_cast<uint32_t>(signData.size());
    auto retCS =
        Security::CodeSign::CodeSignUtils::EnforceCodeSignForFile(anFileName, signData.data(), dataSize);
    if (retCS == VerifyErrCode::CS_ERR_ENABLE) {
        APP_LOGI("pending enforce code sign as screen not first unlock after reboot");
        return ERR_APPEXECFWK_INSTALLD_SIGN_AOT_DISABLE;
    }
    if (retCS != CommonErrCode::CS_SUCCESS) {
        APP_LOGE("fail to enable code signature for the aot file");
        return ERR_APPEXECFWK_INSTALLD_SIGN_AOT_FAILED;
    }
    APP_LOGI("sign aot file success");
    return ERR_OK;
#else
    APP_LOGE("code signature disable, ignore");
    return ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED;
#endif
}

bool AOTExecutor::MkdirWithAuth(const std::filesystem::path &basePath, const std::filesystem::path &targetPath,
    uid_t uid, gid_t gid, mode_t mode) const
{
    std::error_code ec;
    if (!std::filesystem::is_directory(basePath, ec)) {
        APP_LOGE_NOFUNC("invalid path:%{public}s,err:%{public}s", basePath.string().c_str(), ec.message().c_str());
        return false;
    }
    std::filesystem::path normalBase = basePath.lexically_normal();
    std::filesystem::path normalTarget = targetPath.lexically_normal();
    if (normalTarget == normalBase) {
        return true;
    }
    std::filesystem::path relativePath = normalTarget.lexically_relative(normalBase);
    if (relativePath.empty()) {
        APP_LOGE_NOFUNC("target not under base");
        return false;
    }
    std::filesystem::path currentPath(normalBase);
    for (const auto &part : relativePath) {
        if (part == ".") {
            continue;
        }
        if (part == "..") {
            APP_LOGE_NOFUNC("target out of base");
            return false;
        }
        currentPath /= part;
        const std::string dirStr = currentPath.string();
        std::error_code dirEc;
        if (std::filesystem::is_directory(currentPath, dirEc)) {
            continue;
        }
        if (!std::filesystem::create_directory(currentPath, dirEc)) {
            APP_LOGE_NOFUNC("create dir failed:%{public}s,err:%{public}s", dirStr.c_str(), dirEc.message().c_str());
            return false;
        }
        if (chown(dirStr.c_str(), uid, gid) != 0) {
            APP_LOGE_NOFUNC("chown failed:%{public}s, errno:%{public}d", dirStr.c_str(), errno);
            return false;
        }
        if (chmod(dirStr.c_str(), mode) != 0) {
            APP_LOGE_NOFUNC("chmod failed:%{public}s, errno:%{public}d", dirStr.c_str(), errno);
            return false;
        }
    }
    return true;
}

bool AOTExecutor::MkAOTOutputDir(const AOTArgs &aotArgs) const
{
    std::filesystem::path basePath;
    std::filesystem::path targetPath;
    mode_t dirMode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
    if (aotArgs.bundleType == SHARED_BUNDLE_TYPE) {
        basePath = ServiceConstants::HAP_ARK_CACHE_PATH;
        targetPath = aotArgs.outputPath;
        return MkdirWithAuth(basePath, targetPath, aotArgs.bundleUid, aotArgs.bundleGid, dirMode);
    }
    basePath = ServiceConstants::HAP_ARK_CACHE_PATH;
    targetPath = basePath / aotArgs.bundleName;
    return MkdirWithAuth(basePath, targetPath,
        static_cast<uid_t>(ServiceConstants::COMPILER_SERVICE_GID),
        static_cast<gid_t>(ServiceConstants::COMPILER_SERVICE_GID), dirMode);
}

#if defined(CODE_SIGNATURE_ENABLE)
ErrCode AOTExecutor::MapSysCompArgs(const AOTArgs &aotArgs, ArkCompiler::AotCompilerArgs &args) const
{
    APP_LOGI("MapSysCompArgs: %{public}s", aotArgs.ToString().c_str());
    args.isSysComp = true;
    args.sysCompPath = aotArgs.sysCompPath;
    args.abcPath = aotArgs.sysCompPath;
    args.anFileName = aotArgs.anFileName;
    uid_t uid = getuid();
    if (uid > UINT32_MAX) {
        APP_LOGE("invalid uid");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    args.processUid = static_cast<int32_t>(uid);
    return ERR_OK;
}

ErrCode AOTExecutor::MapBundleArgs(const AOTArgs &aotArgs, ArkCompiler::AotCompilerArgs &args) const
{
    APP_LOGD("MapBundleArgs: %{public}s", aotArgs.ToString().c_str());
    args.isSysComp = false;
    uid_t uid = getuid();
    if (uid > UINT32_MAX) {
        APP_LOGE("invalid uid");
        return ERR_APPEXECFWK_INSTALLD_PARAM_ERROR;
    }
    args.processUid = static_cast<int32_t>(uid);
    args.compileMode = aotArgs.compileMode;
    args.moduleArkTSMode = aotArgs.moduleArkTSMode;
    args.bundleName = aotArgs.bundleName;
    args.moduleName = aotArgs.moduleName;
    args.appIdentifier = aotArgs.appIdentifier;
    args.bundleUid = aotArgs.bundleUid;
    args.bundleGid = aotArgs.bundleGid;
    args.hapPath = aotArgs.hapPath;
    args.abcPath = aotArgs.hapPath + ServiceConstants::PATH_SEPARATOR + GetAbcRelativePath(aotArgs.moduleArkTSMode);
    args.anFileName = aotArgs.anFileName;
    args.outputPath = aotArgs.outputPath;
    args.optBCRangeList = aotArgs.optBCRangeList;
    args.isScreenOff = aotArgs.isScreenOff;
    args.isEncryptedBundle = aotArgs.isEncryptedBundle;
    args.isEnableBaselinePgo = aotArgs.isEnableBaselinePgo;
    args.pgoDir = std::filesystem::path(aotArgs.arkProfilePath).parent_path().string();
    args.bundleType = aotArgs.bundleType;
    args.triggerType = aotArgs.triggerType;
    args.hostBundleName = aotArgs.hostBundleName;
    for (const auto &hsp : aotArgs.hspVector) {
        ArkCompiler::HspModuleInfo hspInfo;
        hspInfo.bundleName = hsp.bundleName;
        hspInfo.moduleName = hsp.moduleName;
        hspInfo.hapPath = hsp.hapPath;
        hspInfo.moduleArkTSMode = hsp.moduleArkTSMode;
        args.hspModules.push_back(hspInfo);
    }
    return ERR_OK;
}
#endif

ErrCode AOTExecutor::HandleCompilerResult(ErrCode ret,
    const std::vector<uint8_t> &fileData, std::vector<uint8_t> &signData) const
{
#if defined(CODE_SIGNATURE_ENABLE)
    if (ret == ERR_AOT_COMPILER_SIGN_FAILED) {
        APP_LOGE("aot compiler local signature fail");
        return ERR_APPEXECFWK_INSTALLD_SIGN_AOT_FAILED;
    }
    if (ret == ERR_AOT_COMPILER_CALL_CRASH) {
        APP_LOGE("aot compiler crash");
        return ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_CRASH;
    }
    if (ret == ERR_AOT_COMPILER_CALL_CANCELLED) {
        APP_LOGE("aot compiler cancel");
        return ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_CANCELLED;
    }
    if (ret == ERR_OK_AOT_FILE_EXIST) {
        APP_LOGI("aot file already exists, skip compilation");
        return ERR_OK;
    }
    if (ret != ERR_OK) {
        APP_LOGE("aot compiler fail");
        return ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED;
    }
    signData = fileData;
    APP_LOGI("aot compiler success");
    return ERR_OK;
#else
    return ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED;
#endif
}

ErrCode AOTExecutor::StartAOTCompiler(const AOTArgs &aotArgs, std::vector<uint8_t> &signData)
{
#if defined(CODE_SIGNATURE_ENABLE)
    ArkCompiler::AotCompilerArgs args;
    ErrCode mapRet = ERR_OK;
    if (aotArgs.isSysComp) {
        mapRet = MapSysCompArgs(aotArgs, args);
        if (mapRet != ERR_OK) {
            APP_LOGE("MapSysCompArgs failed, ret=%{public}d", mapRet);
            return mapRet;
        }
    } else {
        mapRet = MapBundleArgs(aotArgs, args);
        if (mapRet != ERR_OK) {
            APP_LOGE("MapBundleArgs failed, ret=%{public}d", mapRet);
            return mapRet;
        }
        if (!MkAOTOutputDir(aotArgs)) {
            return ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED;
        }
    }
    APP_LOGI("start to aot compiler");
    std::vector<uint8_t> fileData;
    ErrCode ret = ArkCompiler::AotCompilerClient::GetInstance().AotCompiler(args, fileData);
    return HandleCompilerResult(ret, fileData, signData);
#else
    APP_LOGE("code signature disable, ignore");
    return ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED;
#endif
}

void AOTExecutor::ExecuteAOT(const AOTArgs &aotArgs, ErrCode &ret, std::vector<uint8_t> &pendSignData)
{
#if defined(CODE_SIGNATURE_ENABLE)
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
        APP_LOGE("prepareArgs fail");
        return;
    }
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        InitState(aotArgs);
    }
    APP_LOGI("begin to call aot compiler");
    std::vector<uint8_t> signData;
    ret = StartAOTCompiler(completeArgs, signData);
    if (ret == ERR_OK) {
        ret = EnforceCodeSign(completeArgs.anFileName, signData);
    }
    if (ret == ERR_APPEXECFWK_INSTALLD_SIGN_AOT_DISABLE) {
        pendSignData = signData;
    }
    APP_LOGI("aot compiler finish");
    {
        std::lock_guard<std::mutex> lock(stateMutex_);
        ResetState();
    }
#else
    APP_LOGE("code signature disable, ignore");
    ret = ERR_APPEXECFWK_INSTALLD_AOT_EXECUTE_FAILED;
#endif
}

ErrCode AOTExecutor::StopAOT()
{
#if defined(CODE_SIGNATURE_ENABLE)
    APP_LOGI("begin to stop AOT");
    std::lock_guard<std::mutex> lock(stateMutex_);
    if (!state_.running) {
        APP_LOGI("AOT not running, return directly");
        return ERR_OK;
    }
    int32_t ret = ArkCompiler::AotCompilerClient::GetInstance().StopAotCompiler();
    if (ret != ERR_OK) {
        APP_LOGE("stop aot compiler fail");
        return ERR_APPEXECFWK_INSTALLD_STOP_AOT_FAILED;
    }
    (void)InstalldOperator::DeleteDir(state_.outputPath);
    ResetState();
    return ERR_OK;
#else
    APP_LOGI("code signature disable, ignore");
    return ERR_OK;
#endif
}

void AOTExecutor::InitState(const AOTArgs &aotArgs)
{
    state_.running = true;
    state_.outputPath = aotArgs.outputPath;
}

void AOTExecutor::ResetState()
{
    state_.running = false;
    state_.outputPath.clear();
}
}  // namespace AppExecFwk
}  // namespace OHOS
