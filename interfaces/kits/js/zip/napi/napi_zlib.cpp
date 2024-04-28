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
#include "napi_zlib.h"

#include <cstring>
#include <uv.h>
#include <vector>

#include "app_log_wrapper.h"
#include "file_path.h"
#include "bundle_errors.h"
#include "business_error.h"
#include "common_func.h"
#include "napi/native_common.h"
#include "napi/native_node_api.h"
#include "napi_arg.h"
#include "napi_constants.h"
#include "napi_zlib_common.h"
#include "zip.h"
#include "zip_utils.h"
#include "zlib_callback_info.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {
namespace {
constexpr size_t ARGS_MAX_COUNT = 10;
constexpr int32_t PARAM3 = 3;
constexpr int32_t PARAM2 = 2;
const char* WRONG_PARAM = "wrong param type";
}

enum CompressFlushMode {
    NO_FLUSH = 0,
    PARTIAL_FLUSH,
    SYNC_FLUSH,
    FULL_FLUSH,
    FINISH,
    BLOCK,
    TREES
};

enum CompressMethod {
    DEFLATED = 8
};

#define COMPRESS_LEVE_CHECK(level, ret)                                                            \
    if (!(level == COMPRESS_LEVEL_NO_COMPRESSION || level == COMPRESS_LEVEL_DEFAULT_COMPRESSION || \
            level == COMPRESS_LEVEL_BEST_SPEED || level == COMPRESS_LEVEL_BEST_COMPRESSION)) {     \
        APP_LOGE("level parameter =[%{public}d] value is incorrect", (int)level);               \
        return ret;                                                                                \
    }

#define COMPRESS_STRATEGY_CHECK(strategy, false)                                                      \
    if (!(strategy == COMPRESS_STRATEGY_DEFAULT_STRATEGY || strategy == COMPRESS_STRATEGY_FILTERED || \
            strategy == COMPRESS_STRATEGY_HUFFMAN_ONLY || strategy == COMPRESS_STRATEGY_RLE ||        \
            strategy == COMPRESS_STRATEGY_FIXED)) {                                                   \
        APP_LOGE("strategy parameter= [%{public}d] value is incorrect", (int)strategy);            \
        return ret;                                                                                   \
    }

#define COMPRESS_MEM_CHECK(mem, false)                                                                            \
    if (!(mem == MEM_LEVEL_MIN_MEMLEVEL || mem == MEM_LEVEL_DEFAULT_MEMLEVEL || mem == MEM_LEVEL_MAX_MEMLEVEL)) { \
        APP_LOGE("memLevel parameter =[%{public}d] value is incorrect", (int)mem);                             \
        return ret;                                                                                               \
    }

void CompressExcute(napi_env env, AsyncZipCallbackInfo *asyncZipCallbackInfo);
void DecompressExcute(napi_env env, AsyncZipCallbackInfo *asyncZipCallbackInfo);
napi_value UnwrapZipParam(CallZipUnzipParam &param, napi_env env, napi_value *args, size_t argc);
napi_value UnwrapUnZipParam(CallZipUnzipParam &param, napi_env env, napi_value *args, size_t argc);
napi_value ZipFileWrap(napi_env env, napi_callback_info info, AsyncZipCallbackInfo *asyncZipCallbackInfo);
napi_value UnwrapStringParam(std::string &str, napi_env env, napi_value argv);
bool UnwrapOptionsParams(OPTIONS &options, napi_env env, napi_value arg);

/**
 * @brief FlushType data initialization.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param exports An empty object via the exports parameter as a convenience.
 *
 * @return The return value from Init is treated as the exports object for the module.
 */
napi_value FlushTypeInit(napi_env env, napi_value exports)
{
    APP_LOGD("%{public}s called.", __func__);
    const int FLUSH_TYPE_NO_FLUSH = 0;
    const int FLUSH_TYPE_PARTIAL_FLUSH = 1;
    const int FLUSH_TYPE_SYNC_FLUSH = 2;
    const int FLUSH_TYPE_FULL_FLUSH = 3;
    const int FLUSH_TYPE_FINISH = 4;
    const int FLUSH_TYPE_BLOCK = 5;
    const int FLUSH_TYPE_TREES = 6;

    napi_value flushType = nullptr;
    napi_create_object(env, &flushType);
    SetNamedProperty(env, flushType, "FLUSH_TYPE_NO_FLUSH", FLUSH_TYPE_NO_FLUSH);
    SetNamedProperty(env, flushType, "FLUSH_TYPE_PARTIAL_FLUSH", FLUSH_TYPE_PARTIAL_FLUSH);
    SetNamedProperty(env, flushType, "FLUSH_TYPE_SYNC_FLUSH", FLUSH_TYPE_SYNC_FLUSH);
    SetNamedProperty(env, flushType, "FLUSH_TYPE_FULL_FLUSH", FLUSH_TYPE_FULL_FLUSH);
    SetNamedProperty(env, flushType, "FLUSH_TYPE_FINISH", FLUSH_TYPE_FINISH);
    SetNamedProperty(env, flushType, "FLUSH_TYPE_BLOCK", FLUSH_TYPE_BLOCK);
    SetNamedProperty(env, flushType, "FLUSH_TYPE_TREES", FLUSH_TYPE_TREES);

    napi_property_descriptor properties[] = {
        DECLARE_NAPI_PROPERTY("FlushType", flushType),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(properties) / sizeof(properties[0]), properties));

    return exports;
}
/**
 * @brief CompressLevel data initialization.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param exports An empty object via the exports parameter as a convenience.
 *
 * @return The return value from Init is treated as the exports object for the module.
 */
napi_value CompressLevelInit(napi_env env, napi_value exports)
{
    APP_LOGD("%{public}s called.", __func__);
    const int COMPRESS_LEVEL_NO_COMPRESSION = 0;
    const int COMPRESS_LEVEL_BEST_SPEED = 1;
    const int COMPRESS_LEVEL_BEST_COMPRESSION = 9;
    const int COMPRESS_LEVEL_DEFAULT_COMPRESSION = -1;

    napi_value compressLevel = nullptr;
    napi_create_object(env, &compressLevel);
    SetNamedProperty(env, compressLevel, "COMPRESS_LEVEL_NO_COMPRESSION", COMPRESS_LEVEL_NO_COMPRESSION);
    SetNamedProperty(env, compressLevel, "COMPRESS_LEVEL_BEST_SPEED", COMPRESS_LEVEL_BEST_SPEED);
    SetNamedProperty(env, compressLevel, "COMPRESS_LEVEL_BEST_COMPRESSION", COMPRESS_LEVEL_BEST_COMPRESSION);
    SetNamedProperty(env, compressLevel, "COMPRESS_LEVEL_DEFAULT_COMPRESSION", COMPRESS_LEVEL_DEFAULT_COMPRESSION);

    napi_property_descriptor properties[] = {
        DECLARE_NAPI_PROPERTY("CompressLevel", compressLevel),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(properties) / sizeof(properties[0]), properties));

    return exports;
}
/**
 * @brief CompressFlushMode data initialization.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param exports An empty object via the exports parameter as a convenience.
 *
 * @return The return value from Init is treated as the exports object for the module.
 */
napi_value CompressFlushModeInit(napi_env env, napi_value exports)
{
    APP_LOGD("%{public}s called.", __func__);

    napi_value CompressFlushMode = nullptr;
    napi_create_object(env, &CompressFlushMode);
    SetNamedProperty(env, CompressFlushMode, "NO_FLUSH", NO_FLUSH);
    SetNamedProperty(env, CompressFlushMode, "PARTIAL_FLUSH", PARTIAL_FLUSH);
    SetNamedProperty(env, CompressFlushMode, "SYNC_FLUSH", SYNC_FLUSH);
    SetNamedProperty(env, CompressFlushMode, "FULL_FLUSH", FULL_FLUSH);
    SetNamedProperty(env, CompressFlushMode, "FINISH", FINISH);
    SetNamedProperty(env, CompressFlushMode, "BLOCK", BLOCK);
    SetNamedProperty(env, CompressFlushMode, "TREES", TREES);
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_PROPERTY("CompressFlushMode", CompressFlushMode),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(properties) / sizeof(properties[0]), properties));

    return exports;
}
/**
 * @brief CompressMethodInit data initialization.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param exports An empty object via the exports parameter as a convenience.
 *
 * @return The return value from Init is treated as the exports object for the module.
 */
napi_value CompressMethodInit(napi_env env, napi_value exports)
{
    APP_LOGD("%{public}s called.", __func__);

    napi_value CompressMethod = nullptr;
    napi_create_object(env, &CompressMethod);
    SetNamedProperty(env, CompressMethod, "DEFLATED", DEFLATED);
    napi_property_descriptor properties[] = {
        DECLARE_NAPI_PROPERTY("CompressMethod", CompressMethod),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(properties) / sizeof(properties[0]), properties));

    return exports;
}
/**
 * @brief CompressStrategy data initialization.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param exports An empty object via the exports parameter as a convenience.
 *
 * @return The return value from Init is treated as the exports object for the module.
 */
napi_value CompressStrategyInit(napi_env env, napi_value exports)
{
    APP_LOGD("%{public}s called.", __func__);
    const int COMPRESS_STRATEGY_DEFAULT_STRATEGY = 0;
    const int COMPRESS_STRATEGY_FILTERED = 1;
    const int COMPRESS_STRATEGY_HUFFMAN_ONLY = 2;
    const int COMPRESS_STRATEGY_RLE = 3;
    const int COMPRESS_STRATEGY_FIXED = 4;

    napi_value compressStrategy = nullptr;
    napi_create_object(env, &compressStrategy);
    SetNamedProperty(env, compressStrategy, "COMPRESS_STRATEGY_DEFAULT_STRATEGY", COMPRESS_STRATEGY_DEFAULT_STRATEGY);
    SetNamedProperty(env, compressStrategy, "COMPRESS_STRATEGY_FILTERED", COMPRESS_STRATEGY_FILTERED);
    SetNamedProperty(env, compressStrategy, "COMPRESS_STRATEGY_HUFFMAN_ONLY", COMPRESS_STRATEGY_HUFFMAN_ONLY);
    SetNamedProperty(env, compressStrategy, "COMPRESS_STRATEGY_RLE", COMPRESS_STRATEGY_RLE);
    SetNamedProperty(env, compressStrategy, "COMPRESS_STRATEGY_FIXED", COMPRESS_STRATEGY_FIXED);

    napi_property_descriptor properties[] = {
        DECLARE_NAPI_PROPERTY("CompressStrategy", compressStrategy),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(properties) / sizeof(properties[0]), properties));

    return exports;
}
/**
 * @brief MemLevel data initialization.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param exports An empty object via the exports parameter as a convenience.
 *
 * @return The return value from Init is treated as the exports object for the module.
 */
napi_value MemLevelInit(napi_env env, napi_value exports)
{
    APP_LOGD("%{public}s called.", __func__);
    const int MEM_LEVEL_MIN = 1;
    const int MEM_LEVEL_DEFAULT = 8;
    const int MEM_LEVEL_MAX = 9;

    napi_value memLevel = nullptr;
    napi_create_object(env, &memLevel);
    SetNamedProperty(env, memLevel, "MEM_LEVEL_MIN", MEM_LEVEL_MIN);
    SetNamedProperty(env, memLevel, "MEM_LEVEL_DEFAULT", MEM_LEVEL_DEFAULT);
    SetNamedProperty(env, memLevel, "MEM_LEVEL_MAX", MEM_LEVEL_MAX);

    napi_property_descriptor properties[] = {
        DECLARE_NAPI_PROPERTY("MemLevel", memLevel),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(properties) / sizeof(properties[0]), properties));

    return exports;
}
/**
 * @brief Errorcode data initialization.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param exports An empty object via the exports parameter as a convenience.
 *
 * @return The return value from Init is treated as the exports object for the module.
 */
napi_value ErrorCodeInit(napi_env env, napi_value exports)
{
    APP_LOGD("%{public}s called.", __func__);

    const int ERROR_CODE_OK = 0;
    const int ERROR_CODE_STREAM_END = 1;
    const int ERROR_CODE_NEED_DICT = 2;
    const int ERROR_CODE_ERRNO = -1;
    const int ERROR_CODE_STREAM_ERROR = -2;
    const int ERROR_CODE_DATA_ERROR = -3;
    const int ERROR_CODE_MEM_ERROR = -4;
    const int ERROR_CODE_BUF_ERROR = -5;
    const int ERROR_CODE_VERSION_ERROR = -6;

    napi_value errorCode = nullptr;
    napi_create_object(env, &errorCode);
    SetNamedProperty(env, errorCode, "ERROR_CODE_OK", ERROR_CODE_OK);
    SetNamedProperty(env, errorCode, "ERROR_CODE_STREAM_END", ERROR_CODE_STREAM_END);
    SetNamedProperty(env, errorCode, "ERROR_CODE_NEED_DICT", ERROR_CODE_NEED_DICT);
    SetNamedProperty(env, errorCode, "ERROR_CODE_ERRNO", ERROR_CODE_ERRNO);
    SetNamedProperty(env, errorCode, "ERROR_CODE_STREAM_ERROR", ERROR_CODE_STREAM_ERROR);
    SetNamedProperty(env, errorCode, "ERROR_CODE_DATA_ERROR", ERROR_CODE_DATA_ERROR);
    SetNamedProperty(env, errorCode, "ERROR_CODE_MEM_ERROR", ERROR_CODE_MEM_ERROR);
    SetNamedProperty(env, errorCode, "ERROR_CODE_BUF_ERROR", ERROR_CODE_BUF_ERROR);
    SetNamedProperty(env, errorCode, "ERROR_CODE_VERSION_ERROR", ERROR_CODE_VERSION_ERROR);

    napi_property_descriptor properties[] = {
        DECLARE_NAPI_PROPERTY("ErrorCode", errorCode),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(properties) / sizeof(properties[0]), properties));

    return exports;
}

/**
 * @brief FeatureAbility NAPI module registration.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param exports An empty object via the exports parameter as a convenience.
 *
 * @return The return value from Init is treated as the exports object for the module.
 */
napi_value ZlibInit(napi_env env, napi_value exports)
{
    APP_LOGD("%{public}s,called", __func__);

    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("zipFile", NAPI_ZipFile),
        DECLARE_NAPI_FUNCTION("unzipFile", NAPI_UnzipFile),
        DECLARE_NAPI_FUNCTION("compressFile", CompressFile),
        DECLARE_NAPI_FUNCTION("decompressFile", DecompressFile),
    };

    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(properties) / sizeof(properties[0]), properties));

    return exports;
}

AsyncZipCallbackInfo *CreateZipAsyncCallbackInfo(napi_env env)
{
    APP_LOGD("%{public}s called.", __func__);
    napi_status ret;
    napi_value global = 0;
    const napi_extended_error_info *errorInfo = nullptr;
    ret = napi_get_global(env, &global);
    if (ret != napi_ok) {
        napi_get_last_error_info(env, &errorInfo);
        if (errorInfo == nullptr) {
            APP_LOGE("%{public}s errorInfo is null", __func__);
            return nullptr;
        }
        APP_LOGE("%{public}s get_global=%{public}d err:%{public}s", __func__, ret, errorInfo->error_message);
    }

    AsyncZipCallbackInfo *asyncCallbackInfo = new (std::nothrow) AsyncZipCallbackInfo {
        .asyncWork = nullptr,
        .zlibCallbackInfo = nullptr,
    };
    if (asyncCallbackInfo == nullptr) {
        APP_LOGE("%{public}s asyncCallbackInfo is null", __func__);
        return nullptr;
    }
    APP_LOGD("%{public}s end.", __func__);
    return asyncCallbackInfo;
}

napi_value UnwrapStringParam(std::string &str, napi_env env, napi_value argv)
{
    APP_LOGD("%{public}s,called", __func__);
    // unwrap the param[0]
    napi_valuetype valueType = napi_valuetype::napi_undefined;
    napi_status rev = napi_typeof(env, argv, &valueType);
    if (rev != napi_ok) {
        return nullptr;
    }

    if (valueType != napi_valuetype::napi_string) {
        APP_LOGI("%{public}s called, Parameter type does not match", __func__);
        return nullptr;
    }

    size_t len;
    napi_status status = napi_get_value_string_utf8(env, argv, nullptr, 0, &len);
    if (status != napi_ok) {
        APP_LOGI("%{public}s called, Get locale tag length failed", __func__);
        return nullptr;
    }
    std::vector<char> buf(len + 1);
    status = napi_get_value_string_utf8(env, argv, buf.data(), len + 1, &len);
    if (status != napi_ok) {
        APP_LOGI("%{public}s called, Get locale tag failed", __func__);
        return nullptr;
    }
    str = std::string(buf.data());

    napi_value result;
    NAPI_CALL(env, napi_create_int32(env, 1, &result));
    return result;
}

bool UnwrapOptionsParams(OPTIONS &options, napi_env env, napi_value arg)
{
    if (!IsTypeForNapiValue(env, arg, napi_object)) {
        return false;
    }
    napi_valuetype jsValueType = napi_undefined;
    napi_value jsProNameList = nullptr;
    uint32_t jsProCount = 0;

    NAPI_CALL_BASE(env, napi_get_property_names(env, arg, &jsProNameList), false);
    NAPI_CALL_BASE(env, napi_get_array_length(env, jsProNameList, &jsProCount), false);

    napi_value jsProName = nullptr;
    napi_value jsProValue = nullptr;

    for (uint32_t index = 0; index < jsProCount; index++) {
        NAPI_CALL_BASE(env, napi_get_element(env, jsProNameList, index, &jsProName), false);
        std::string strProName = UnwrapStringFromJS(env, jsProName, std::string());
        APP_LOGD("%{public}s called. Property name=%{public}s.", __func__, strProName.c_str());
        NAPI_CALL_BASE(env, napi_get_named_property(env, arg, strProName.c_str(), &jsProValue), false);
        NAPI_CALL_BASE(env, napi_typeof(env, jsProValue, &jsValueType), false);

        int ret = 0;
        if (strProName == std::string("flush")) {
            if (UnwrapIntValue(env, jsProValue, ret)) {
                options.flush = static_cast<FLUSH_TYPE>(ret);
            }
        } else if (strProName == std::string("finishFlush")) {
            if (UnwrapIntValue(env, jsProValue, ret)) {
                options.finishFlush = static_cast<FLUSH_TYPE>(ret);
            }
        } else if (strProName == std::string("chunkSize")) {
            if (UnwrapIntValue(env, jsProValue, ret)) {
                options.chunkSize = ret;
            }
        } else if (strProName == std::string("level")) {
            if (UnwrapIntValue(env, jsProValue, ret)) {
                COMPRESS_LEVE_CHECK(ret, false)
                options.level = static_cast<COMPRESS_LEVEL>(ret);
            }
        } else if (strProName == std::string("memLevel")) {
            if (UnwrapIntValue(env, jsProValue, ret)) {
                COMPRESS_MEM_CHECK(ret, false)
                options.memLevel = static_cast<MEMORY_LEVEL>(ret);
            }
        } else if (strProName == std::string("strategy")) {
            if (UnwrapIntValue(env, jsProValue, ret)) {
                COMPRESS_STRATEGY_CHECK(ret, false)
                options.strategy = static_cast<COMPRESS_STRATEGY>(ret);
            }
        }
    }
    return true;
}

napi_value UnwrapZipParam(CallZipUnzipParam &param, napi_env env, napi_value *args, size_t argc)
{
    APP_LOGD("%{public}s,called", __func__);
    size_t argcPromise = 3;
    if (argc < argcPromise) {
        APP_LOGI("%{public}s called, param count is wrong", __func__);
        return nullptr;
    }

    // unwrap the param[0]
    if (UnwrapStringParam(param.src, env, args[0]) == nullptr) {
        APP_LOGI("%{public}s called, args[0] error", __func__);
        return nullptr;
    }

    // unwrap the param[1]
    if (UnwrapStringParam(param.dest, env, args[1]) == nullptr) {
        APP_LOGI("%{public}s called, args[1] error", __func__);
        return nullptr;
    }

    // unwrap the param[2]
    if (!UnwrapOptionsParams(param.options, env, args[2])) {
        APP_LOGI("%{public}s called, args[2] error", __func__);
        return nullptr;
    }
    // create reutrn
    napi_value ret = 0;
    NAPI_CALL_BASE(env, napi_create_int32(env, 0, &ret), nullptr);
    return ret;
}

napi_value UnwrapUnZipParam(CallZipUnzipParam &param, napi_env env, napi_value *args, size_t argc)
{
    APP_LOGD("%{public}s,called", __func__);
    size_t argcPromise = 3;
    if (argc < argcPromise) {
        return nullptr;
    }
    // unwrap the param[0]
    if (UnwrapStringParam(param.src, env, args[0]) == nullptr) {
        return nullptr;
    }

    // unwrap the param[1]
    if (UnwrapStringParam(param.dest, env, args[1]) == nullptr) {
        return nullptr;
    }

    // create reutrn
    napi_value ret = 0;
    NAPI_CALL_BASE(env, napi_create_int32(env, 0, &ret), nullptr);
    return ret;
}

/**
 * @brief Zlib NAPI method : zipFile.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param info The callback info passed into the callback function.
 *
 * @return The return value from NAPI C++ to JS for the module.
 */
napi_value NAPI_ZipFile(napi_env env, napi_callback_info info)
{
    APP_LOGD("%{public}s,called", __func__);
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    napi_value ret = 0;
    size_t argcAsync = 4;
    const size_t argcPromise = 3;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, nullptr, nullptr));
    if (argcAsync < argcPromise || argcAsync > ARGS_MAX_COUNT) {
        APP_LOGE("%{public}s, Wrong argument count.", __func__);
        return nullptr;
    }

    AsyncZipCallbackInfo *asyncZipCallbackInfo = CreateZipAsyncCallbackInfo(env);
    if (asyncZipCallbackInfo == nullptr) {
        return nullptr;
    }

    ret = ZipFileWrap(env, info, asyncZipCallbackInfo);
    return ret;
}

napi_value ZipFileWrap(napi_env env, napi_callback_info info, AsyncZipCallbackInfo *asyncZipCallbackInfo)
{
    APP_LOGD("%{public}s,called", __func__);
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    napi_value thisArg = nullptr;
    size_t argcAsync = 4;
    const size_t argcPromise = 3;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, &thisArg, nullptr));
    if (argcAsync < argcPromise || argcAsync > ARGS_MAX_COUNT) {
        APP_LOGE("%{public}s, Wrong argument count.", __func__);
        return nullptr;
    }
    if (thisArg == nullptr) {
        APP_LOGE("%{public}s, This argument is nullptr.", __func__);
        return nullptr;
    }
    napi_valuetype valueTypeOfThis = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, thisArg, &valueTypeOfThis), nullptr);
    if (valueTypeOfThis == napi_undefined) {
        APP_LOGE("%{public}s, Wrong this value.", __func__);
        return nullptr;
    }

    CallZipUnzipParam param;
    if (UnwrapZipParam(param, env, args, argcAsync) == nullptr) {
        APP_LOGE("%{public}s, call unwrapWant failed.", __func__);
        return nullptr;
    }
    napi_value promise = nullptr;
    std::unique_ptr<AsyncZipCallbackInfo> callbackPtr {asyncZipCallbackInfo};
    asyncZipCallbackInfo->param = param;
    if (argcAsync > PARAM3) {
        napi_valuetype valuetype = napi_undefined;
        NAPI_CALL_BASE(env, napi_typeof(env, args[PARAM3], &valuetype), nullptr);
        if (valuetype == napi_function) {
            napi_ref callbackRef = nullptr;
            napi_get_undefined(env,  &promise);
            napi_create_reference(env, args[PARAM3], 1, &callbackRef);
            asyncZipCallbackInfo->zlibCallbackInfo =
                std::make_shared<ZlibCallbackInfo>(env, callbackRef, nullptr, true);
        }
    } else {
        napi_deferred deferred;
        NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
        asyncZipCallbackInfo->zlibCallbackInfo = std::make_shared<ZlibCallbackInfo>(env, nullptr, deferred, false);
    }

    CompressExcute(env, asyncZipCallbackInfo);
    callbackPtr.release();
    return promise;
}

/**
 * @brief Zlib NAPI method : unzipFile.
 *
 * @param env The environment that the Node-API call is invoked under.
 * @param info The callback info passed into the callback function.
 *
 * @return The return value from NAPI C++ to JS for the module.
 */
napi_value NAPI_UnzipFile(napi_env env, napi_callback_info info)
{
    napi_value args[ARGS_MAX_COUNT] = {nullptr};
    size_t argcAsync = 4;
    size_t argcPromise = 3;
    NAPI_CALL(env, napi_get_cb_info(env, info, &argcAsync, args, nullptr, nullptr));
    if (argcAsync < argcPromise || argcAsync > ARGS_MAX_COUNT) {
        APP_LOGE("%{public}s, Wrong argument count.", __func__);
        return nullptr;
    }
    CallZipUnzipParam param;
    if (UnwrapUnZipParam(param, env, args, argcAsync) == nullptr) {
        APP_LOGE("%{public}s, call unwrap param failed.", __func__);
        return nullptr;
    }
    AsyncZipCallbackInfo *asyncZipCallbackInfo = CreateZipAsyncCallbackInfo(env);
    if (asyncZipCallbackInfo == nullptr) {
        return nullptr;
    }
    std::unique_ptr<AsyncZipCallbackInfo> callbackPtr {asyncZipCallbackInfo};
    asyncZipCallbackInfo->param = param;
    napi_value promise = nullptr;
    if (argcAsync > PARAM3) {
        napi_valuetype valuetype = napi_undefined;
        NAPI_CALL_BASE(env, napi_typeof(env, args[PARAM3], &valuetype), nullptr);
        if (valuetype == napi_function) {
            napi_ref callbackRef = nullptr;
            napi_get_undefined(env,  &promise);
            napi_create_reference(env, args[PARAM3], 1, &callbackRef);
            asyncZipCallbackInfo->zlibCallbackInfo =
                std::make_shared<ZlibCallbackInfo>(env, callbackRef, nullptr, true);
        }
    } else {
        napi_deferred deferred;
        NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
        asyncZipCallbackInfo->zlibCallbackInfo = std::make_shared<ZlibCallbackInfo>(env, nullptr, deferred, false);
    }
    DecompressExcute(env, asyncZipCallbackInfo);
    callbackPtr.release();
    return promise;
}

// interface for v9
bool InitParam(CallZipUnzipParam &param, napi_env env, NapiArg &args, bool isZipFile)
{
    if (args.GetMaxArgc() < PARAM2) {
        return false;
    }
    for (size_t i = 0; i < args.GetMaxArgc(); ++i) {
        napi_valuetype valueType = napi_undefined;
        napi_typeof(env, args[i], &valueType);
        if (i == ARGS_POS_ZERO) {
            if (UnwrapStringParam(param.src, env, args[i]) == nullptr) {
                return false;
            }
        } else if (i == ARGS_POS_ONE) {
            if (UnwrapStringParam(param.dest, env, args[i]) == nullptr) {
                return false;
            }
        } else if (i == ARGS_POS_TWO) {
            if (isZipFile && valueType != napi_function && !UnwrapOptionsParams(param.options, env, args[i])) {
                return false;
            }
        } else if (i == ARGS_POS_THREE) {
            if (valueType == napi_function) {
                break;
            }
        } else {
            return false;
        }
    }
    return true;
}

void CompressExcute(napi_env env, AsyncZipCallbackInfo *asyncZipCallbackInfo)
{
    if (asyncZipCallbackInfo == nullptr) {
        APP_LOGE("asyncZipCallbackInfo is nullptr");
        return;
    }
    std::unique_ptr<AsyncZipCallbackInfo> callbackPtr {asyncZipCallbackInfo};
    if (asyncZipCallbackInfo->zlibCallbackInfo == nullptr) {
        APP_LOGE("zlibCallbackInfo is nullptr");
        return;
    }

    Zip(asyncZipCallbackInfo->param.src, asyncZipCallbackInfo->param.dest, asyncZipCallbackInfo->param.options,
        false, asyncZipCallbackInfo->zlibCallbackInfo);
}

napi_value CompressFile(napi_env env, napi_callback_info info)
{
    APP_LOGD("napi begin CompressFile");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_THREE, ARGS_SIZE_FOUR)) {
        APP_LOGE("init args failed!");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, WRONG_PARAM);
        return nullptr;
    }
    CallZipUnzipParam param;
    if (!InitParam(param, env, args, true)) {
        APP_LOGE("Init Param failed!");
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, WRONG_PARAM);
        return nullptr;
    }
    AsyncZipCallbackInfo *asyncZipCallbackInfo = CreateZipAsyncCallbackInfo(env);
    if (asyncZipCallbackInfo == nullptr) {
        APP_LOGE("asyncZipCallbackInfo nullptr!");
        return nullptr;
    }
    asyncZipCallbackInfo->param = param;
    std::unique_ptr<AsyncZipCallbackInfo> callbackPtr {asyncZipCallbackInfo};
    asyncZipCallbackInfo->zlibCallbackInfo =
                std::make_shared<ZlibCallbackInfo>(env, nullptr, nullptr, false);
    asyncZipCallbackInfo->zlibCallbackInfo->SetDeliverErrCode(true);
    if (args.GetMaxArgc() > PARAM3) {
        napi_valuetype valuetype = napi_undefined;
        NAPI_CALL_BASE(env, napi_typeof(env, args[PARAM3], &valuetype), nullptr);
        if (valuetype == napi_function) {
            napi_ref callbackRef = nullptr;
            NAPI_CALL(env, napi_create_reference(env, args[PARAM3], NAPI_RETURN_ONE, &callbackRef));
            asyncZipCallbackInfo->zlibCallbackInfo->SetCallback(callbackRef);
            asyncZipCallbackInfo->zlibCallbackInfo->SetIsCallback(true);
        }
    }
    napi_value promise = nullptr;
    if (!asyncZipCallbackInfo->zlibCallbackInfo->GetIsCallback()) {
        napi_deferred deferred;
        NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
        asyncZipCallbackInfo->zlibCallbackInfo->SetDeferred(deferred);
    }
    CompressExcute(env, asyncZipCallbackInfo);
    callbackPtr.release();
    return promise;
}

void DecompressExcute(napi_env env, AsyncZipCallbackInfo *asyncZipCallbackInfo)
{
    if (asyncZipCallbackInfo == nullptr) {
        APP_LOGE("asyncZipCallbackInfo is nullptr");
        return;
    }
    std::unique_ptr<AsyncZipCallbackInfo> callbackPtr {asyncZipCallbackInfo};
    if (asyncZipCallbackInfo->zlibCallbackInfo == nullptr) {
        APP_LOGE("zlibCallbackInfo is nullptr");
        return;
    }
    Unzip(asyncZipCallbackInfo->param.src, asyncZipCallbackInfo->param.dest,
        asyncZipCallbackInfo->param.options, asyncZipCallbackInfo->zlibCallbackInfo);
}

napi_value DecompressFile(napi_env env, napi_callback_info info)
{
    APP_LOGD("napi begin CompressFile");
    NapiArg args(env, info);
    if (!args.Init(ARGS_SIZE_TWO, ARGS_SIZE_FOUR)) {
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, WRONG_PARAM);
        return nullptr;
    }
    CallZipUnzipParam param;
    if (!InitParam(param, env, args, true)) {
        BusinessError::ThrowError(env, ERROR_PARAM_CHECK_ERROR, WRONG_PARAM);
        return nullptr;
    }
    AsyncZipCallbackInfo *asyncZipCallbackInfo = CreateZipAsyncCallbackInfo(env);
    if (asyncZipCallbackInfo == nullptr) {
        return nullptr;
    }
    asyncZipCallbackInfo->param = param;
    std::unique_ptr<AsyncZipCallbackInfo> callbackPtr {asyncZipCallbackInfo};
    asyncZipCallbackInfo->zlibCallbackInfo =
                std::make_shared<ZlibCallbackInfo>(env, nullptr, nullptr, false);
    asyncZipCallbackInfo->zlibCallbackInfo->SetDeliverErrCode(true);
    for (size_t i = PARAM2; i < args.GetMaxArgc(); i++) {
        napi_valuetype valuetype = napi_undefined;
        NAPI_CALL_BASE(env, napi_typeof(env, args[i], &valuetype), nullptr);
        if (valuetype == napi_function) {
            napi_ref callbackRef = nullptr;
            NAPI_CALL(env, napi_create_reference(env, args[i], NAPI_RETURN_ONE, &callbackRef));
            asyncZipCallbackInfo->zlibCallbackInfo->SetCallback(callbackRef);
            asyncZipCallbackInfo->zlibCallbackInfo->SetIsCallback(true);
            break;
        }
    }
    napi_value promise = nullptr;
    if (!asyncZipCallbackInfo->zlibCallbackInfo->GetIsCallback()) {
        napi_deferred deferred;
        NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));
        asyncZipCallbackInfo->zlibCallbackInfo->SetDeferred(deferred);
    }
    DecompressExcute(env, asyncZipCallbackInfo);
    callbackPtr.release();
    return promise;
}

}  // namespace LIBZIP
}  // namespace AppExecFwk
}  // namespace OHOS
