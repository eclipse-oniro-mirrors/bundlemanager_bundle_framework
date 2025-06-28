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

#include "ani_signature_builder.h"
#include "ani_zip.h"
#include "common_func.h"

namespace OHOS {
namespace AppExecFwk {

namespace {
constexpr const char* NS_NAME_ZLIB = "@ohos.zlib.zlib";
constexpr const char* PARAM_NAME_IN_FILE = "inFile";
constexpr const char* PARAM_NAME_OUT_FILE = "outFile";
constexpr const char* PARAM_NAME_OPTIONS = "options";
constexpr const char* TYPE_STRING = "string";
} // namespace

using namespace arkts::ani_signature;

static void CompressFile(ani_env* env, ani_string aniInFile, ani_string aniOutFile, ani_object aniOptions)
{
    std::string inFile;
    if (!CommonFunAni::ParseString(env, aniInFile, inFile)) {
        APP_LOGE("parse aniInFile failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_IN_FILE, TYPE_STRING);
        return;
    }

    std::string outFile;
    if (!CommonFunAni::ParseString(env, aniOutFile, outFile)) {
        APP_LOGE("parse aniOutFile failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_OUT_FILE, TYPE_STRING);
        return;
    }

    LIBZIP::OPTIONS options;
    if (!LIBZIP::ANIParseOptions(env, aniOptions, options)) {
        APP_LOGE("options parse failed.");
        BusinessErrorAni::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_OPTIONS);
        return;
    }

    int32_t errCode = CommonFunc::ConvertErrCode(LIBZIP::ANICompressFileImpl(inFile, outFile, options));
    if (errCode != ERR_OK) {
        APP_LOGE("CompressFiles failed, ret %{public}d", errCode);
        BusinessErrorAni::ThrowCommonError(env, errCode, "", "");
    }
}

static void DecompressFile(ani_env* env, ani_string aniInFile, ani_string aniOutFile, ani_object aniOptions)
{
    std::string inFile;
    if (!CommonFunAni::ParseString(env, aniInFile, inFile)) {
        APP_LOGE("parse aniInFile failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_IN_FILE, TYPE_STRING);
        return;
    }

    std::string outFile;
    if (!CommonFunAni::ParseString(env, aniOutFile, outFile)) {
        APP_LOGE("parse aniOutFile failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_OUT_FILE, TYPE_STRING);
        return;
    }

    LIBZIP::OPTIONS options;
    if (!LIBZIP::ANIParseOptions(env, aniOptions, options)) {
        APP_LOGE("options parse failed.");
        BusinessErrorAni::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_OPTIONS);
        return;
    }

    int32_t errCode = CommonFunc::ConvertErrCode(LIBZIP::ANIDecompressFileImpl(inFile, outFile, options));
    if (errCode != ERR_OK) {
        APP_LOGE("DecompressFile failed, ret %{public}d", errCode);
        BusinessErrorAni::ThrowCommonError(env, errCode, "", "");
    }
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    APP_LOGI("ANI_Constructor zlib called");
    if (vm == nullptr) {
        APP_LOGE("vm is null");
        return ANI_ERROR;
    }
    if (result == nullptr) {
        APP_LOGE("result is null");
        return ANI_ERROR;
    }

    ani_env* env = nullptr;
    ani_status status = vm->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        APP_LOGE("Unsupported ANI_VERSION_1: %{public}d", status);
        return status;
    }
    if (env == nullptr) {
        APP_LOGE("env is null");
        return ANI_ERROR;
    }

    Namespace zlibNS = Builder::BuildNamespace(NS_NAME_ZLIB);
    ani_namespace kitNs = nullptr;
    status = env->FindNamespace(zlibNS.Descriptor().c_str(), &kitNs);
    if (status != ANI_OK) {
        APP_LOGE("FindNamespace: %{public}s fail with %{public}d", NS_NAME_ZLIB, status);
        return status;
    }

    std::array methods = {
        ani_native_function { "CompressFile", nullptr, reinterpret_cast<void*>(CompressFile) },
        ani_native_function { "DecompressFile", nullptr, reinterpret_cast<void*>(DecompressFile) },
    };

    status = env->Namespace_BindNativeFunctions(kitNs, methods.data(), methods.size());
    if (status != ANI_OK) {
        APP_LOGE("Namespace_BindNativeFunctions: %{public}s fail with %{public}d", NS_NAME_ZLIB, status);
        return status;
    }

    *result = ANI_VERSION_1;

    APP_LOGI("ANI_Constructor finished");

    return ANI_OK;
}
}
} // namespace AppExecFwk
} // namespace OHOS