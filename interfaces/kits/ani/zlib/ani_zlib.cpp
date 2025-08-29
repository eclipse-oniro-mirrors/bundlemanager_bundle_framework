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
#include "ani_zlib_callback_info.h"
#include "business_error_ani.h"
#include "checksum/ani_checksum.h"
#include "common_fun_ani.h"
#include "common_func.h"
#include "enum_util.h"
#include "gzip/ani_gzip.h"
#include "napi_business_error.h"
#include "napi_constants.h"
#include "zip.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* NS_NAME_ZLIB = "@ohos.zlib.zlib";
constexpr const char* PROPERTY_NAME_LEVEL = "level";
constexpr const char* PROPERTY_NAME_MEMLEVEL = "memLevel";
constexpr const char* PROPERTY_NAME_STRATEGY = "strategy";
constexpr const char* PROPERTY_NAME_PARALLEL = "parallel";
constexpr const char* TYPE_NAME_CHECKSUMINTERNAL = "ChecksumInternal";
constexpr const char* TYPE_NAME_GZIPINTERNAL = "GZipInternal";
constexpr const char* PARAM_NAME_IN_FILE = "inFile";
constexpr const char* PARAM_NAME_IN_FILES = "inFiles";
constexpr const char* PARAM_NAME_OUT_FILE = "outFile";
constexpr const char* PARAM_NAME_OPTIONS = "options";
} // namespace

using namespace arkts::ani_signature;

static bool ANIParseOptions(ani_env* env, ani_object object, LIBZIP::OPTIONS& options)
{
    APP_LOGD("ANIParseOptions entry");

    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(object);

    ani_enum_item enumItem = nullptr;
    // level?: CompressLevel
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTY_NAME_LEVEL, &enumItem)) {
        RETURN_FALSE_IF_FALSE(EnumUtils::EnumETSToNative(env, enumItem, options.level));
    }

    // memLevel?: MemLevel
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTY_NAME_MEMLEVEL, &enumItem)) {
        RETURN_FALSE_IF_FALSE(EnumUtils::EnumETSToNative(env, enumItem, options.memLevel));
    }

    // strategy?: CompressStrategy
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTY_NAME_STRATEGY, &enumItem)) {
        RETURN_FALSE_IF_FALSE(EnumUtils::EnumETSToNative(env, enumItem, options.strategy));
    }

    // parallel?: ParallelStrategy
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTY_NAME_PARALLEL, &enumItem)) {
        RETURN_FALSE_IF_FALSE(EnumUtils::EnumETSToNative(env, enumItem, options.parallel));
    }

    return true;
}

static void compressFileNative(ani_env* env, ani_string aniInFile, ani_string aniOutFile, ani_object aniOptions)
{
    APP_LOGD("compressFileNative entry");

    RETURN_IF_NULL(env);
    RETURN_IF_NULL(aniInFile);
    RETURN_IF_NULL(aniOutFile);
    RETURN_IF_NULL(aniOptions);

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
    if (!ANIParseOptions(env, aniOptions, options)) {
        APP_LOGE("options parse failed.");
        BusinessErrorAni::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_OPTIONS);
        return;
    }

    auto zlibCallbackInfo = std::make_shared<ANIZlibCallbackInfo>();
    LIBZIP::Zip(inFile, outFile, options, false, zlibCallbackInfo);
    const int32_t errCode = CommonFunc::ConvertErrCode(zlibCallbackInfo->GetResult());
    if (errCode != ERR_OK) {
        APP_LOGE("compressFileNative failed, ret %{public}d", errCode);
        BusinessErrorAni::ThrowCommonError(env, errCode, "", "");
    }
}

static void compressFilesNative(ani_env* env, ani_object aniInFiles, ani_string aniOutFile, ani_object aniOptions)
{
    APP_LOGD("compressFilesNative entry");

    RETURN_IF_NULL(env);
    RETURN_IF_NULL(aniInFiles);
    RETURN_IF_NULL(aniOutFile);
    RETURN_IF_NULL(aniOptions);

    std::vector<std::string> inFiles;
    if (aniInFiles == nullptr || !CommonFunAni::ParseStrArray(env, aniInFiles, inFiles) || inFiles.size() == 0) {
        APP_LOGE("inFiles parse failed.");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_IN_FILES, TYPE_ARRAY);
        return;
    }

    std::string outFile;
    if (!CommonFunAni::ParseString(env, aniOutFile, outFile)) {
        APP_LOGE("parse aniOutFile failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_OUT_FILE, TYPE_STRING);
        return;
    }

    LIBZIP::OPTIONS options;
    if (!ANIParseOptions(env, aniOptions, options)) {
        APP_LOGE("options parse failed.");
        BusinessErrorAni::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_OPTIONS);
        return;
    }

    auto zlibCallbackInfo = std::make_shared<ANIZlibCallbackInfo>();
    LIBZIP::Zips(inFiles, outFile, options, false, zlibCallbackInfo);
    const int32_t errCode = CommonFunc::ConvertErrCode(zlibCallbackInfo->GetResult());
    if (errCode != ERR_OK) {
        APP_LOGE("compressFilesNative failed, ret %{public}d", errCode);
        BusinessErrorAni::ThrowCommonError(env, errCode, "", "");
    }
}

static void decompressFileNative(ani_env* env, ani_string aniInFile, ani_string aniOutFile, ani_object aniOptions)
{
    APP_LOGD("decompressFileNative entry");

    RETURN_IF_NULL(env);
    RETURN_IF_NULL(aniInFile);
    RETURN_IF_NULL(aniOutFile);
    RETURN_IF_NULL(aniOptions);

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
    if (!ANIParseOptions(env, aniOptions, options)) {
        APP_LOGE("options parse failed.");
        BusinessErrorAni::ThrowError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_OPTIONS);
        return;
    }

    auto zlibCallbackInfo = std::make_shared<ANIZlibCallbackInfo>();
    LIBZIP::Unzip(inFile, outFile, options, zlibCallbackInfo);
    const int32_t errCode = CommonFunc::ConvertErrCode(zlibCallbackInfo->GetResult());
    if (errCode != ERR_OK) {
        APP_LOGE("decompressFileNative failed, ret %{public}d", errCode);
        BusinessErrorAni::ThrowCommonError(env, errCode, "", "");
    }
}

static ani_long getOriginalSizeNative(ani_env* env, ani_string aniCompressedFile)
{
    APP_LOGD("getOriginalSizeNative entry");

    if (env == nullptr) {
        APP_LOGE("env is null");
        return 0;
    }
    if (aniCompressedFile == nullptr) {
        APP_LOGE("aniCompressedFile is null");
        return 0;
    }

    std::string compressedFile;
    if (!CommonFunAni::ParseString(env, aniCompressedFile, compressedFile)) {
        APP_LOGE("parse aniCompressedFile failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_IN_FILE, TYPE_STRING);
        return 0;
    }

    int64_t originalSize = 0;
    const int32_t errCode = CommonFunc::ConvertErrCode(LIBZIP::GetOriginalSize(compressedFile, originalSize));
    if (errCode != ERR_OK) {
        APP_LOGE("getOriginalSizeNative failed, ret %{public}d", errCode);
        BusinessErrorAni::ThrowCommonError(env, errCode, "GetOriginalSize", "");
    }

    return originalSize;
}

static ani_object createChecksumNative(ani_env* env, ani_boolean)
{
    APP_LOGD("createChecksumNative entry");

    ani_object objChecksum = nullptr;
    Namespace zlibNS = Builder::BuildNamespace(NS_NAME_ZLIB);
    Type checksumType = Builder::BuildClass({ zlibNS.Name(), TYPE_NAME_CHECKSUMINTERNAL });
    ani_class clsChecksum = CommonFunAni::CreateClassByName(env, checksumType.Descriptor());
    if (clsChecksum != nullptr) {
        objChecksum = CommonFunAni::CreateNewObjectByClass(env, checksumType.Descriptor(), clsChecksum);
    }
    if (objChecksum == nullptr) {
        auto errorPair = LIBZIP::errCodeTable.at(EFAULT);
        BusinessErrorAni::ThrowError(env, errorPair.first, errorPair.second);
    }
    return objChecksum;
}

static ani_object createGZipNative(ani_env* env, ani_boolean)
{
    APP_LOGD("createGZipNative entry");

    ani_object objGZip = nullptr;
    Namespace zlibNS = Builder::BuildNamespace(NS_NAME_ZLIB);
    Type gzipType = Builder::BuildClass({ zlibNS.Name(), TYPE_NAME_GZIPINTERNAL });
    ani_class clsGZip = CommonFunAni::CreateClassByName(env, gzipType.Descriptor());
    if (clsGZip != nullptr) {
        objGZip = CommonFunAni::CreateNewObjectByClass(env, gzipType.Descriptor(), clsGZip);
    }
    if (objGZip == nullptr) {
        auto errorPair = LIBZIP::errCodeTable.at(EFAULT);
        BusinessErrorAni::ThrowError(env, errorPair.first, errorPair.second);
    }
    return objGZip;
}

static ani_status BindNSMethods(ani_env* env)
{
    APP_LOGD("BindNSMethods entry");

    Namespace zlibNS = Builder::BuildNamespace(NS_NAME_ZLIB);
    ani_namespace kitNs = nullptr;
    ani_status status = env->FindNamespace(zlibNS.Descriptor().c_str(), &kitNs);
    if (status != ANI_OK) {
        APP_LOGE("FindNamespace: %{public}s fail with %{public}d", NS_NAME_ZLIB, status);
        return status;
    }

    std::array methods = {
        ani_native_function { "compressFileNative", nullptr, reinterpret_cast<void*>(compressFileNative) },
        ani_native_function { "compressFilesNative", nullptr, reinterpret_cast<void*>(compressFilesNative) },
        ani_native_function { "decompressFileNative", nullptr, reinterpret_cast<void*>(decompressFileNative) },
        ani_native_function { "getOriginalSizeNative", nullptr, reinterpret_cast<void*>(getOriginalSizeNative) },
        ani_native_function { "createChecksumNative", nullptr, reinterpret_cast<void*>(createChecksumNative) },
        ani_native_function { "createGZipNative", nullptr, reinterpret_cast<void*>(createGZipNative) },
    };

    status = env->Namespace_BindNativeFunctions(kitNs, methods.data(), methods.size());
    if (status != ANI_OK) {
        APP_LOGE("Namespace_BindNativeFunctions: %{public}s fail with %{public}d", NS_NAME_ZLIB, status);
        return status;
    }

    return status;
}

static ani_status BindChecksumMethods(ani_env* env)
{
    APP_LOGD("BindChecksumMethods entry");

    Type checksumType = Builder::BuildClass({ NS_NAME_ZLIB, TYPE_NAME_CHECKSUMINTERNAL });
    ani_class clsChecksum = CommonFunAni::CreateClassByName(env, checksumType.Descriptor());
    if (clsChecksum == nullptr) {
        APP_LOGE("CreateClassByName: %{public}s fail", TYPE_NAME_CHECKSUMINTERNAL);
        return ANI_ERROR;
    }

    std::array methodsChecksum = {
        ani_native_function { "adler32Native", nullptr, reinterpret_cast<void*>(AniZLibChecksum::adler32Native) },
        ani_native_function {
            "adler32CombineNative", nullptr, reinterpret_cast<void*>(AniZLibChecksum::adler32CombineNative) },
        ani_native_function { "crc32Native", nullptr, reinterpret_cast<void*>(AniZLibChecksum::crc32Native) },
        ani_native_function {
            "crc32CombineNative", nullptr, reinterpret_cast<void*>(AniZLibChecksum::crc32CombineNative) },
        ani_native_function { "crc64Native", nullptr, reinterpret_cast<void*>(AniZLibChecksum::crc64Native) },
        ani_native_function {
            "getCrcTableNative", nullptr, reinterpret_cast<void*>(AniZLibChecksum::getCrcTableNative) },
        ani_native_function {
            "getCrc64TableNative", nullptr, reinterpret_cast<void*>(AniZLibChecksum::getCrc64TableNative) },
    };

    ani_status status = env->Class_BindNativeMethods(clsChecksum, methodsChecksum.data(), methodsChecksum.size());
    if (status != ANI_OK) {
        APP_LOGE("Class_BindNativeMethods: %{public}s fail with %{public}d", TYPE_NAME_CHECKSUMINTERNAL, status);
        return ANI_ERROR;
    }

    return status;
}

static ani_status BindGZipMethods(ani_env* env)
{
    APP_LOGD("BindGZipMethods entry");

    Type gzipType = Builder::BuildClass({ NS_NAME_ZLIB, TYPE_NAME_GZIPINTERNAL });
    ani_class clsGZip = CommonFunAni::CreateClassByName(env, gzipType.Descriptor());
    if (clsGZip == nullptr) {
        APP_LOGE("CreateClassByName: %{public}s fail", TYPE_NAME_GZIPINTERNAL);
        return ANI_ERROR;
    }

    std::array methodsGZip = {
        ani_native_function { "gzdopenNative", nullptr, reinterpret_cast<void*>(AniZLibGZip::gzdopenNative) },
        ani_native_function { "gzbufferNative", nullptr, reinterpret_cast<void*>(AniZLibGZip::gzbufferNative) },
        ani_native_function { "gzopenNative", nullptr, reinterpret_cast<void*>(AniZLibGZip::gzopenNative) },
        ani_native_function { "gzeofNative", nullptr, reinterpret_cast<void*>(AniZLibGZip::gzeofNative) },
        ani_native_function { "gzdirectNative", nullptr, reinterpret_cast<void*>(AniZLibGZip::gzdirectNative) },
        ani_native_function { "gzcloseNative", nullptr, reinterpret_cast<void*>(AniZLibGZip::gzcloseNative) },
        ani_native_function { "gzclearerrNative", nullptr, reinterpret_cast<void*>(AniZLibGZip::gzclearerrNative) },
        ani_native_function { "gzerrorNative", nullptr, reinterpret_cast<void*>(AniZLibGZip::gzerrorNative) },
        ani_native_function { "gzgetcNative", nullptr, reinterpret_cast<void*>(AniZLibGZip::gzgetcNative) },
        ani_native_function { "gzflushNative", nullptr, reinterpret_cast<void*>(AniZLibGZip::gzflushNative) },
        ani_native_function { "gzfwriteNative", nullptr, reinterpret_cast<void*>(AniZLibGZip::gzfwriteNative) },
        ani_native_function { "gzfreadNative", nullptr, reinterpret_cast<void*>(AniZLibGZip::gzfreadNative) },
        ani_native_function { "gzclosewNative", nullptr, reinterpret_cast<void*>(AniZLibGZip::gzclosewNative) },
        ani_native_function { "gzcloserNative", nullptr, reinterpret_cast<void*>(AniZLibGZip::gzcloserNative) },
        ani_native_function { "gzwriteNative", nullptr, reinterpret_cast<void*>(AniZLibGZip::gzwriteNative) },
        ani_native_function { "gzungetcNative", nullptr, reinterpret_cast<void*>(AniZLibGZip::gzungetcNative) },
        ani_native_function { "gztellNative", nullptr, reinterpret_cast<void*>(AniZLibGZip::gztellNative) },
        ani_native_function { "gzsetparamsNative", nullptr, reinterpret_cast<void*>(AniZLibGZip::gzsetparamsNative) },
        ani_native_function { "gzseekNative", nullptr, reinterpret_cast<void*>(AniZLibGZip::gzseekNative) },
        ani_native_function { "gzrewindNative", nullptr, reinterpret_cast<void*>(AniZLibGZip::gzrewindNative) },
        ani_native_function { "gzreadNative", nullptr, reinterpret_cast<void*>(AniZLibGZip::gzreadNative) },
        ani_native_function { "gzputsNative", nullptr, reinterpret_cast<void*>(AniZLibGZip::gzputsNative) },
        ani_native_function { "gzputcNative", nullptr, reinterpret_cast<void*>(AniZLibGZip::gzputcNative) },
        ani_native_function { "gzprintfNative", nullptr, reinterpret_cast<void*>(AniZLibGZip::gzprintfNative) },
        ani_native_function { "gzoffsetNative", nullptr, reinterpret_cast<void*>(AniZLibGZip::gzoffsetNative) },
        ani_native_function { "gzgetsNative", nullptr, reinterpret_cast<void*>(AniZLibGZip::gzgetsNative) },
    };

    ani_status status = env->Class_BindNativeMethods(clsGZip, methodsGZip.data(), methodsGZip.size());
    if (status != ANI_OK) {
        APP_LOGE("Class_BindNativeMethods: %{public}s fail with %{public}d", TYPE_NAME_GZIPINTERNAL, status);
        return ANI_ERROR;
    }

    return status;
}

extern "C" {
ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
{
    APP_LOGI("ANI_Constructor zlib called");
    ani_env* env;
    ani_status status = vm->GetEnv(ANI_VERSION_1, &env);
    if (status != ANI_OK) {
        APP_LOGE("Unsupported ANI_VERSION_1: %{public}d", status);
        return status;
    }

    status = BindNSMethods(env);
    if (status != ANI_OK) {
        APP_LOGE("BindNSMethods: %{public}d", status);
        return status;
    }

    status = BindChecksumMethods(env);
    if (status != ANI_OK) {
        APP_LOGE("BindChecksumMethods: %{public}d", status);
        return status;
    }

    status = BindGZipMethods(env);
    if (status != ANI_OK) {
        APP_LOGE("BindGZipMethods: %{public}d", status);
        return status;
    }

    *result = ANI_VERSION_1;

    APP_LOGI("ANI_Constructor finished");

    return ANI_OK;
}
}
} // namespace AppExecFwk
} // namespace OHOS