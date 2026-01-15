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

#include <cstddef>
#include <cstdint>
#include <vector>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#define private public
#define protected public
#include "bundle_mgr_service.h"
#undef private
#undef protected
#include "securec.h"
#include "token_setproc.h"
#include "bmsbundlemgrserviceparallelization_fuzzer.h"
#include "bms_fuzztest_util.h"

using namespace OHOS;
using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
namespace OHOS {
constexpr long long TOKEN_ID = 718336240uLL;
constexpr long long OFFSET = 32;
class OHOS::AppExecFwk::BundleMgrService* p_bundleMgrdService = new OHOS::AppExecFwk::BundleMgrService();

enum IpcCode : std::int16_t {
    ON_START = 1,
    ON_STOP = 2,
    ON_DEVICE_LEVEL_CHANGED = 3,
    IS_SERVICE_READY = 4,
    INIT = 5,
    INIT_BMS_PARAM = 6,
    INIT_PREINSTALL_EXCEPTION_MGR = 7,
    INIT_BUNDLE_MGR_HOST = 8,
    INIT_BUNDLE_INSTALLER = 9,
    INIT_BUNDLE_DATA_MGR = 10,
    INIT_BUNDLE_USER_MGR = 11,
    INIT_VERIFY_MANAGER = 12,
    INIT_EXTEND_RESOURCE_MANAGER = 13,
    INIT_HIDUMP_HELPER = 14,
    INIT_FREE_INSTALL = 15,
    INIT_APP_CONTROL = 16,
    INIT_BUNDLE_MGR_EXT = 17,
    INIT_OVERLAY_MANAGER = 18,
    CREATE_BMS_SERVICE_DIR = 19,
    INIT_BUNDLE_RESOURCE_MGR = 20,
    GET_BUNDLE_INSTALLER = 21,
    REGISTER_DATA_MGR = 22,
    GET_DATA_MGR = 23,
    GET_AGING_MGR = 24,
    GET_CONNECT_ABILITY = 25,
    SELF_CLEAN = 26,
    GET_BUNDLE_USER_MGR = 27,
    GET_BUNDLE_DISTRIBUTED_MANAGER = 28,
    GET_VERIFY_MANAGER = 29,
    GET_EXTEND_RESOURCE_MANAGER = 30,
    GET_BMS_PARAM = 31,
    GET_PREINSTALL_EXCEPTION_MGR = 32,
    GET_DEFAULT_APP_PROXY = 33,
    GET_APP_CONTROL_PROXY = 34,
    GET_BUNDLE_MGR_EXT_PROXY = 35,
    GET_QUICK_FIX_MANAGER_PROXY = 36,
    GET_OVERLAY_MANAGER_PROXY = 37,
    GET_BUNDLE_RESOURCE_PROXY = 38,
    CHECK_ALL_USER = 39,
    REGISTER_SERVICE = 40,
    NOTIFY_BUNDLE_SCAN_STATUS = 41,
    ON_ADD_SYSTEM_ABILITY = 42,
    HIDUMP = 43,
    IS_BROKER_SERVICE_STARTED = 44,
    ON_EXTENSION = 45,
    GET_EXTEND__RESOURCE_MANAGER = 46,
};
}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    if (SetSelfTokenID(TOKEN_ID | (1uLL << OHOS::OFFSET)) < 0) {
        return -1;
    }

    if (p_bundleMgrdService == nullptr) {
        return -1;
    }

    OHOS::p_bundleMgrdService->OnStart();
    return 0;
}

extern "C" int FuzzIBundleMgrService(FuzzedDataProvider &provider)
{
    if (p_bundleMgrdService == nullptr) {
        return 0;
    }

    static const int ipcCodes[] = {
        IpcCode::ON_START, IpcCode::ON_STOP, IpcCode::ON_DEVICE_LEVEL_CHANGED,
        IpcCode::IS_SERVICE_READY, IpcCode::INIT, IpcCode::INIT_BMS_PARAM,
        IpcCode::INIT_PREINSTALL_EXCEPTION_MGR, IpcCode::INIT_BUNDLE_MGR_HOST,
        IpcCode::INIT_BUNDLE_INSTALLER, IpcCode::INIT_BUNDLE_DATA_MGR,
        IpcCode::INIT_BUNDLE_USER_MGR, IpcCode::INIT_VERIFY_MANAGER,
        IpcCode::INIT_EXTEND_RESOURCE_MANAGER, IpcCode::INIT_HIDUMP_HELPER,
        IpcCode::INIT_FREE_INSTALL, IpcCode::INIT_APP_CONTROL,
        IpcCode::INIT_BUNDLE_MGR_EXT, IpcCode::INIT_OVERLAY_MANAGER,
        IpcCode::CREATE_BMS_SERVICE_DIR, IpcCode::INIT_BUNDLE_RESOURCE_MGR,
        IpcCode::GET_BUNDLE_INSTALLER, IpcCode::REGISTER_DATA_MGR, IpcCode::GET_DATA_MGR,
        IpcCode::GET_AGING_MGR, IpcCode::GET_CONNECT_ABILITY,
        IpcCode::SELF_CLEAN, IpcCode::GET_BUNDLE_USER_MGR,
        IpcCode::GET_BUNDLE_DISTRIBUTED_MANAGER,
        IpcCode::GET_VERIFY_MANAGER, IpcCode::GET_BMS_PARAM,
        IpcCode::GET_PREINSTALL_EXCEPTION_MGR, IpcCode::GET_DEFAULT_APP_PROXY,
        IpcCode::GET_APP_CONTROL_PROXY, IpcCode::GET_BUNDLE_MGR_EXT_PROXY,
        IpcCode::GET_QUICK_FIX_MANAGER_PROXY, IpcCode::GET_OVERLAY_MANAGER_PROXY, IpcCode::GET_BUNDLE_RESOURCE_PROXY,
        IpcCode::CHECK_ALL_USER, IpcCode::REGISTER_SERVICE, IpcCode::NOTIFY_BUNDLE_SCAN_STATUS,
        IpcCode::ON_ADD_SYSTEM_ABILITY, IpcCode::HIDUMP,
        IpcCode::IS_BROKER_SERVICE_STARTED, IpcCode::ON_EXTENSION, IpcCode::GET_EXTEND__RESOURCE_MANAGER,
    };
    int code = provider.PickValueInArray(ipcCodes);

    switch (code) {
        case IpcCode::ON_START: {
            OHOS::p_bundleMgrdService->OnStart();
            break;
        }
        case IpcCode::ON_STOP: {
            OHOS::p_bundleMgrdService->OnStop();
            break;
        }
        case IpcCode::ON_DEVICE_LEVEL_CHANGED: {
            int32_t type = provider.ConsumeIntegral<int32_t>();
            int32_t level = provider.ConsumeIntegral<int32_t>();
            std::string action = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
            OHOS::p_bundleMgrdService->OnDeviceLevelChanged(type, level, action);
            break;
        }
        case IpcCode::IS_SERVICE_READY: {
            OHOS::p_bundleMgrdService->IsServiceReady();
            break;
        }
        case IpcCode::INIT: {
            OHOS::p_bundleMgrdService->Init();
            break;
        }
        case IpcCode::INIT_BMS_PARAM: {
            OHOS::p_bundleMgrdService->InitBmsParam();
            break;
        }
        case IpcCode::INIT_PREINSTALL_EXCEPTION_MGR: {
            OHOS::p_bundleMgrdService->InitPreInstallExceptionMgr();
            break;
        }
        case IpcCode::INIT_BUNDLE_MGR_HOST: {
            OHOS::p_bundleMgrdService->InitBundleMgrHost();
            break;
        }
        case IpcCode::INIT_BUNDLE_INSTALLER: {
            OHOS::p_bundleMgrdService->InitBundleInstaller();
            break;
        }
        case IpcCode::INIT_BUNDLE_DATA_MGR: {
            OHOS::p_bundleMgrdService->InitBundleDataMgr();
            break;
        }
        case IpcCode::INIT_BUNDLE_USER_MGR: {
            OHOS::p_bundleMgrdService->InitBundleUserMgr();
            break;
        }
        case IpcCode::INIT_VERIFY_MANAGER: {
            OHOS::p_bundleMgrdService->InitVerifyManager();
            break;
        }
        case IpcCode::INIT_EXTEND_RESOURCE_MANAGER: {
            OHOS::p_bundleMgrdService->InitExtendResourceManager();
            break;
        }
        case IpcCode::INIT_HIDUMP_HELPER: {
            OHOS::p_bundleMgrdService->InitHidumpHelper();
            break;
        }
        case IpcCode::INIT_FREE_INSTALL: {
            OHOS::p_bundleMgrdService->InitFreeInstall();
            break;
        }
        case IpcCode::INIT_APP_CONTROL: {
            OHOS::p_bundleMgrdService->InitAppControl();
            break;
        }
        case IpcCode::INIT_BUNDLE_MGR_EXT: {
            OHOS::p_bundleMgrdService->InitBundleMgrExt();
            break;
        }
        case IpcCode::INIT_OVERLAY_MANAGER: {
            OHOS::p_bundleMgrdService->InitOverlayManager();
            break;
        }
        case IpcCode::CREATE_BMS_SERVICE_DIR: {
            OHOS::p_bundleMgrdService->CreateBmsServiceDir();
            break;
        }
        case IpcCode::INIT_BUNDLE_RESOURCE_MGR: {
            OHOS::p_bundleMgrdService->InitBundleResourceMgr();
            break;
        }
        case IpcCode::GET_BUNDLE_INSTALLER: {
            OHOS::p_bundleMgrdService->GetBundleInstaller();
            break;
        }
        case IpcCode::REGISTER_DATA_MGR: {
            std::shared_ptr<BundleDataMgr> dataMgrImpl = DelayedSingleton<BundleMgrService>::GetInstance()->GetDataMgr();
            OHOS::p_bundleMgrdService->RegisterDataMgr(dataMgrImpl);
            break;
        }
        case IpcCode::GET_DATA_MGR: {
            OHOS::p_bundleMgrdService->GetDataMgr();
            break;
        }
        case IpcCode::GET_AGING_MGR: {
#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
            OHOS::p_bundleMgrdService->GetAgingMgr();
#endif
            break;
        }
        case IpcCode::GET_CONNECT_ABILITY: {
#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
            int32_t userId = provider.ConsumeIntegral<int32_t>();
            OHOS::p_bundleMgrdService->GetConnectAbility(userId);
#endif
            break;
        }
        case IpcCode::GET_BUNDLE_DISTRIBUTED_MANAGER: {
#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
            OHOS::p_bundleMgrdService->GetBundleDistributedManager();
#endif
            break;
        }
        case IpcCode::SELF_CLEAN: {
            OHOS::p_bundleMgrdService->SelfClean();
            break;
        }
        case IpcCode::GET_BUNDLE_USER_MGR: {
            OHOS::p_bundleMgrdService->GetBundleUserMgr();
            break;
        }
        case IpcCode::GET_VERIFY_MANAGER: {
            OHOS::p_bundleMgrdService->GetVerifyManager();
            break;
        }
        case IpcCode::GET_EXTEND__RESOURCE_MANAGER: {
            OHOS::p_bundleMgrdService->GetExtendResourceManager();
            break;
        }
        case IpcCode::GET_BMS_PARAM: {
            OHOS::p_bundleMgrdService->GetBmsParam();
            break;
        }
        case IpcCode::GET_PREINSTALL_EXCEPTION_MGR: {
            OHOS::p_bundleMgrdService->GetPreInstallExceptionMgr();
            break;
        }
        case IpcCode::GET_DEFAULT_APP_PROXY: {
#ifdef BUNDLE_FRAMEWORK_DEFAULT_APP
            OHOS::p_bundleMgrdService->GetDefaultAppProxy();
#endif
            break;
        }
        case IpcCode::GET_APP_CONTROL_PROXY: {
#ifdef BUNDLE_FRAMEWORK_APP_CONTROL
            OHOS::p_bundleMgrdService->GetAppControlProxy();
#endif
            break;
        }
        case IpcCode::GET_BUNDLE_MGR_EXT_PROXY: {
            OHOS::p_bundleMgrdService->GetBundleMgrExtProxy();
            break;
        }
        case IpcCode::GET_QUICK_FIX_MANAGER_PROXY: {
#ifdef BUNDLE_FRAMEWORK_QUICK_FIX
            OHOS::p_bundleMgrdService->GetQuickFixManagerProxy();
#endif
            break;
        }
        case IpcCode::GET_OVERLAY_MANAGER_PROXY: {
#ifdef BUNDLE_FRAMEWORK_OVERLAY_INSTALLATION
            OHOS::p_bundleMgrdService->GetOverlayManagerProxy();
#endif
            break;
        }
        case IpcCode::GET_BUNDLE_RESOURCE_PROXY: {
#ifdef BUNDLE_FRAMEWORK_BUNDLE_RESOURCE
            OHOS::p_bundleMgrdService->GetBundleResourceProxy();
#endif
            break;
        }
        case IpcCode::CHECK_ALL_USER: {
            OHOS::p_bundleMgrdService->CheckAllUser();
            break;
        }
        case IpcCode::REGISTER_SERVICE: {
            OHOS::p_bundleMgrdService->RegisterService();
            break;
        }
        case IpcCode::NOTIFY_BUNDLE_SCAN_STATUS: {
            OHOS::p_bundleMgrdService->NotifyBundleScanStatus();
            break;
        }
        case IpcCode::ON_ADD_SYSTEM_ABILITY: {
            int32_t systemAbilityId = provider.ConsumeIntegral<int32_t>();
            std::string deviceId = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
            OHOS::p_bundleMgrdService->OnAddSystemAbility(systemAbilityId, deviceId);
            break;
        }
        case IpcCode::HIDUMP: {
            std::vector<std::string> args = GenerateStringArray(provider);
            std::string result = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
            OHOS::p_bundleMgrdService->Hidump(args, result);
            break;
        }
        case IpcCode::IS_BROKER_SERVICE_STARTED: {
            OHOS::p_bundleMgrdService->IsBrokerServiceStarted();
            break;
        }
        case IpcCode::ON_EXTENSION: {
            std::string extension = provider.ConsumeRandomLengthString(STRING_MAX_LENGTH);
            MessageParcel datas;
            MessageParcel reply;
            OHOS::p_bundleMgrdService->OnExtension(extension, datas, reply);
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
    FuzzIBundleMgrService(fdp);
    return 0;
}