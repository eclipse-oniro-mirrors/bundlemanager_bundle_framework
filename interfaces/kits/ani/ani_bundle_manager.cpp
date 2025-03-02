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

#include <ani.h>
#include <cstring>
#include <iostream>
#include <string>
#include <unistd.h>
#include <vector>

#include "bundle_mgr_client.h"
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "common_fun_ani.h"
#include "common_func.h"
#include "ipc_skeleton.h"

using namespace OHOS;
using namespace AppExecFwk;

std::string AniStrToString(ani_env* env, ani_ref aniStr)
{
    ani_string str = reinterpret_cast<ani_string>(aniStr);
    if (str == nullptr) {
        std::cerr << "ani ParseString failed" << std::endl;
        return "";
    }

    ani_status status = ANI_ERROR;
    ani_size substrSize = -1;
    if ((status = env->String_GetUTF8Size(str, &substrSize)) != ANI_OK) {
        std::cerr << "String_GetUTF8Size failed" << std::endl;
        return "";
    }

    std::vector<char> buffer(substrSize + 1);
    ani_size nameSize;
    if ((status = env->String_GetUTF8SubString(str, 0U, substrSize, buffer.data(), buffer.size(), &nameSize)) !=
        ANI_OK) {
        std::cerr << "String_GetUTF8SubString failed" << std::endl;
        return "";
    }

    return std::string(buffer.data(), nameSize);
}

static ani_boolean IsApplicationEnabledSync(
    [[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object object, ani_string aniBundleName)
{
    bool isEnable = false;
    std::string bundleName = AniStrToString(env, aniBundleName);
    if (bundleName.empty()) {
        std::cerr << "BundleName is empty" << std::endl;
        return isEnable;
    }
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        std::cerr << "GetBundleMgr failed" << std::endl;
        return isEnable;
    }
    int32_t ret = iBundleMgr->IsApplicationEnabled(bundleName, isEnable);
    if (ret != ERR_OK) {
        std::cerr << "IsApplicationEnabled failed ret: " << ret << std::endl;
    }
    return isEnable;
}

static ani_object GetBundleInfoForSelfSync(
    [[maybe_unused]] ani_env* env, [[maybe_unused]] ani_object object, ani_int bundleFlags)
{
    auto iBundleMgr = CommonFunc::GetBundleMgr();
    if (iBundleMgr == nullptr) {
        std::cerr << "GetBundleMgr failed" << std::endl;
        return nullptr;
    }
    if (CommonFunc::CheckBundleFlagWithPermission(bundleFlags)) {
        std::cerr << "CheckBundleFlagWithPermission failed" << std::endl;
        return nullptr;
    }
    BundleInfo bundleInfo;
    int32_t ret = iBundleMgr->GetBundleInfoForSelf(bundleFlags, bundleInfo);
    if (ret != ERR_OK) {
        std::cerr << "GetBundleInfoForSelf failed ret: " << ret << " userId: " << getuid() << std::endl;
    }
    ani_object objectTemp = CommonFunAni::ConvertBundleInfo(env, bundleInfo);

    return objectTemp;
}

ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    ani_env* env;
    if (ANI_OK != vm->GetEnv(ANI_VERSION_1, &env)) {
        std::cerr << "Unsupported ANI_VERSION_1" << std::endl;
        return (ani_status)9;
    }

    static const char* className = "LBundleManager/BundleManager;";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        std::cerr << "Not found '" << className << "'" << std::endl;
        return (ani_status)2;
    }

    std::array methods = {
        ani_native_function {
            "IsApplicationEnabledSync", "Lstd/core/String;:Z", reinterpret_cast<void*>(IsApplicationEnabledSync) },
        ani_native_function { "GetBundleInfoForSelfSync", "I:LBundleInfo/BundleInfo;",
            reinterpret_cast<void*>(GetBundleInfoForSelfSync) },
    };

    if (ANI_OK != env->Class_BindNativeMethods(cls, methods.data(), methods.size())) {
        std::cerr << "Cannot bind native methods to '" << className << "'" << std::endl;
        return (ani_status)3;
    };

    *result = ANI_VERSION_1;
    return ANI_OK;
}
