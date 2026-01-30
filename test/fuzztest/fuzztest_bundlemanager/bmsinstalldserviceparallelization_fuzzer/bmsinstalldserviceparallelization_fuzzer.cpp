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

#include <cstddef>
#include <cstdint>
#include <vector>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#define protected public
#include "installd_service.h"
#include "installd_host_impl.h"
#undef private
#undef protected
#include "securec.h"
#include "token_setproc.h"
#include "bmsinstalldserviceparallelization_fuzzer.h"
#include "bms_fuzztest_util.h"

using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
constexpr long long TOKEN_ID = 718336240uLL;
constexpr long long OFFSET = 32;
class OHOS::AppExecFwk::InstalldService* p_installdService = new OHOS::AppExecFwk::InstalldService();

enum IpcCode : std::int16_t {
    ON_START = 3001,
    ON_STOP = 3003,
    INIT = 3004,
    INIT_DIR = 3005,
    START = 3006,
    STOP = 3007,
    ON_ADD_SYSTEM_ABILITY = 3009,
    ON_IDLE = 3012,
    CREATE_BUNDLE_DIR = 3013,
    EXTRACT_MODULE_FILES = 3014,
    EXTRACT_FILES = 3015,
    EXTRACT_HNP_FILES = 3016,
    PROCESS_BUNDLE_INSTALL_NATIVE = 3017,
    PROCESS_BUNDLE_UNINSTALL_NATIVE = 3018,
    EXECUTE_AOT = 3023,
    PEND_SIGN_AOT = 3024,
    STOP_AOT = 3025,
    DELETE_UNINSTALL_TMP_DIRS = 3026,
    RENAME_MODULE_DIR = 3027,
    CREATE_BUNDLE_DATA_DIR = 3028,
    CREATE_BUNDLE_DATA_DIR_WITH_VECTOR = 3029,
    REMOVE_BUNDLE_DATA_DIR = 3030,
    REMOVE_MODULE_DATA_DIR = 3031,
    REMOVE_DIR = 3035,
};

sptr<IRemoteObject> GetMockRemoteObject()
{
    return nullptr;
}

// Helper functions to fill structs with fuzzed data
void FillExtractParam(FuzzedDataProvider &provider, ExtractParam &extractParam)
{
    extractParam.srcPath = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    extractParam.targetPath = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    extractParam.cpuAbi = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    extractParam.extractFileType = ExtractFileType::AN;
}

void FillInstallHnpParam(FuzzedDataProvider &provider, InstallHnpParam &installHnpParam)
{
    installHnpParam.userId = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    installHnpParam.hnpRootPath = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    installHnpParam.hapPath = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    installHnpParam.cpuAbi = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    installHnpParam.packageName = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    installHnpParam.appIdentifier = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    installHnpParam.hnpPaths = GenerateStringArray(provider);
}
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    if (SetSelfTokenID(TOKEN_ID | (1uLL << OHOS::OFFSET)) < 0) {
        return -1;
    }

    if (p_installdService == nullptr) {
        return -1;
    }

    OHOS::p_installdService->OnStart();
    return 0;
}

extern "C" int FuzzIInstalldService(FuzzedDataProvider &provider)
{
    if (p_installdService == nullptr) {
        return 0;
    }

    static const int ipcCodes[] = {
        IpcCode::ON_START, IpcCode::ON_STOP, IpcCode::INIT,
        IpcCode::INIT_DIR, IpcCode::START, IpcCode::STOP,
        IpcCode::ON_ADD_SYSTEM_ABILITY, IpcCode::ON_IDLE,
        IpcCode::CREATE_BUNDLE_DIR, IpcCode::EXTRACT_MODULE_FILES,
        IpcCode::EXTRACT_FILES, IpcCode::EXTRACT_HNP_FILES,
        IpcCode::PROCESS_BUNDLE_INSTALL_NATIVE, IpcCode::PROCESS_BUNDLE_UNINSTALL_NATIVE,
        IpcCode::EXECUTE_AOT, IpcCode::PEND_SIGN_AOT,
        IpcCode::STOP_AOT, IpcCode::DELETE_UNINSTALL_TMP_DIRS,
        IpcCode::RENAME_MODULE_DIR, IpcCode::CREATE_BUNDLE_DATA_DIR,
        IpcCode::CREATE_BUNDLE_DATA_DIR_WITH_VECTOR, IpcCode::REMOVE_BUNDLE_DATA_DIR, IpcCode::REMOVE_MODULE_DATA_DIR,
        IpcCode::REMOVE_DIR,
    };
    int code = provider.PickValueInArray(ipcCodes);

    switch (code) {
        case IpcCode::ON_START: {
            OHOS::p_installdService->OnStart();
            break;
        }
        case IpcCode::ON_STOP: {
            OHOS::p_installdService->OnStop();
            break;
        }
        case IpcCode::INIT: {
            OHOS::p_installdService->Init();
            break;
        }
        case IpcCode::INIT_DIR: {
            std::string path = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
            OHOS::p_installdService->InitDir(path);
            break;
        }
        case IpcCode::START: {
            OHOS::p_installdService->Start();
            break;
        }
        case IpcCode::STOP: {
            OHOS::p_installdService->Stop();
            break;
        }
        case IpcCode::ON_ADD_SYSTEM_ABILITY: {
            int32_t systemAbilityId = provider.ConsumeIntegral<int32_t>();
            std::string deviceId = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
            OHOS::p_installdService->OnAddSystemAbility(systemAbilityId, deviceId);
            break;
        }
        case IpcCode::ON_IDLE: {
            SystemAbilityOnDemandReason idleReason;
            OHOS::p_installdService->OnIdle(idleReason);
            break;
        }
        case IpcCode::CREATE_BUNDLE_DIR: {
            std::string bundleDir = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
            OHOS::p_installdService->hostImpl_->CreateBundleDir(bundleDir);
            break;
        }
        case IpcCode::EXTRACT_MODULE_FILES: {
            std::string srcModulePath = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
            std::string targetPath = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
            std::string targetSoPath = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
            std::string cpuAbi = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
            OHOS::p_installdService->hostImpl_->ExtractModuleFiles(srcModulePath, targetPath, targetSoPath, cpuAbi);
            break;
        }
        case IpcCode::EXTRACT_FILES: {
            ExtractParam extractParam;
            FillExtractParam(provider, extractParam);
            OHOS::p_installdService->hostImpl_->ExtractFiles(extractParam);
            break;
        }
        case IpcCode::EXTRACT_HNP_FILES: {
            std::map<std::string, std::string> hnpPackageMap;
            ExtractParam extractParam;
            OHOS::p_installdService->hostImpl_->ExtractHnpFiles(hnpPackageMap, extractParam);
            break;
        }
        case IpcCode::PROCESS_BUNDLE_INSTALL_NATIVE: {
            InstallHnpParam installHnpParam;
            FillInstallHnpParam(provider, installHnpParam);
            OHOS::p_installdService->hostImpl_->ProcessBundleInstallNative(installHnpParam);
            break;
        }
        case IpcCode::PROCESS_BUNDLE_UNINSTALL_NATIVE: {
            std::string userId = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
            std::string packageName = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
            OHOS::p_installdService->hostImpl_->ProcessBundleUnInstallNative(userId, packageName);
            break;
        }
        case IpcCode::EXECUTE_AOT: {
            AOTArgs aotArgs;
            std::vector<uint8_t> pendSignData;
            OHOS::p_installdService->hostImpl_->ExecuteAOT(aotArgs, pendSignData);
            break;
        }
        case IpcCode::PEND_SIGN_AOT: {
            std::string anFileName = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
            std::vector<uint8_t> signData;
            OHOS::p_installdService->hostImpl_->PendSignAOT(anFileName, signData);
            break;
        }
        case IpcCode::STOP_AOT: {
            OHOS::p_installdService->hostImpl_->StopAOT();
            break;
        }
        case IpcCode::DELETE_UNINSTALL_TMP_DIRS: {
            std::vector<std::string> dirs;
            OHOS::p_installdService->hostImpl_->DeleteUninstallTmpDirs(dirs);
            break;
        }
        case IpcCode::RENAME_MODULE_DIR: {
            std::string oldPath = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
            std::string newPath = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
            OHOS::p_installdService->hostImpl_->RenameModuleDir(oldPath, newPath);
            break;
        }
        case IpcCode::CREATE_BUNDLE_DATA_DIR: {
            CreateDirParam createDirParam;
            OHOS::p_installdService->hostImpl_->CreateBundleDataDir(createDirParam);
            break;
        }
        case IpcCode::CREATE_BUNDLE_DATA_DIR_WITH_VECTOR: {
            std::vector<CreateDirParam> createDirParams;
            OHOS::p_installdService->hostImpl_->CreateBundleDataDirWithVector(createDirParams);
            break;
        }
        case IpcCode::REMOVE_BUNDLE_DATA_DIR: {
            std::string bundleName = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
            int32_t userId = GenerateRandomUser(provider);
            OHOS::p_installdService->hostImpl_->RemoveBundleDataDir(bundleName, userId);
            break;
        }
        case IpcCode::REMOVE_MODULE_DATA_DIR: {
            std::string moduleDir = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
            int userid = provider.ConsumeIntegral<int>();
            OHOS::p_installdService->hostImpl_->RemoveModuleDataDir(moduleDir, userid);
            break;
        }
        case IpcCode::REMOVE_DIR: {
            std::string dir = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
            OHOS::p_installdService->hostImpl_->RemoveDir(dir);
            break;
        }
        default: {
            break;
        }
    }
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    FuzzIInstalldService(fdp);
    return 0;
}