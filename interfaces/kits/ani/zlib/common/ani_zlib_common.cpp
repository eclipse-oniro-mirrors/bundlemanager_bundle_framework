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
#include "ani_zlib_common.h"
#include "business_error_ani.h"
#include "common_fun_ani.h"
#include "enum_util.h"

namespace OHOS {
namespace AppExecFwk {
namespace AniZLibCommon {
namespace {
constexpr const char* CLASSNAME_ZSTREAM_INNER = "@ohos.zlib.zlib.ZStreamInner";
constexpr const char* CLASSNAME_ZIP_OUTPUT_INFO_INNER = "@ohos.zlib.zlib.ZipOutputInfoInner";
constexpr const char* CLASSNAME_DECOMPERSSION_OUTPUT_INFO_INNER = "@ohos.zlib.zlib.DecompressionOutputInfoInner";
constexpr const char* CLASSNAME_DICTIONARY_OUTPUT_INFO_INNER = "@ohos.zlib.zlib.DictionaryOutputInfoInner";
constexpr const char* CLASSNAME_DEFLATE_PENDING_OUTPUT_INFO_INNER = "@ohos.zlib.zlib.DeflatePendingOutputInfoInner";
constexpr const char* PROPERTY_NAME_LEVEL = "level";
constexpr const char* PROPERTY_NAME_MEMLEVEL = "memLevel";
constexpr const char* PROPERTY_NAME_STRATEGY = "strategy";
constexpr const char* PROPERTY_NAME_PARALLEL = "parallel";
constexpr const char* PROPERTYNAME_NEXTIN = "nextIn";
constexpr const char* PROPERTYNAME_AVAILABLE_IN = "availableIn";
constexpr const char* PROPERTYNAME_TOTAL_IN = "totalIn";
constexpr const char* PROPERTYNAME_NEXT_OUT = "nextOut";
constexpr const char* PROPERTYNAME_AVAILABLE_OUT = "availableOut";
constexpr const char* PROPERTYNAME_TOTAL_OUT = "totalOut";
constexpr const char* PROPERTYNAME_DATA_TYPE = "dataType";
constexpr const char* PROPERTYNAME_ADLER = "adler";
constexpr const char* PROPERTYNAME_STATUS = "status";
constexpr const char* PROPERTYNAME_DEST_LEN = "destLen";
constexpr const char* PROPERTYNAME_DEST_LENGTH = "destLength";
constexpr const char* PROPERTYNAME_SOURCE_LENGTH = "sourceLength";
constexpr const char* PROPERTYNAME_IS_TEXT = "isText";
constexpr const char* PROPERTYNAME_OS = "os";
constexpr const char* PROPERTYNAME_TIME = "time";
constexpr const char* PROPERTYNAME_XFLAGS = "xflags";
constexpr const char* PROPERTYNAME_EXTRA = "extra";
constexpr const char* PROPERTYNAME_EXTRA_LEN = "extraLen";
constexpr const char* PROPERTYNAME_NAME = "name";
constexpr const char* PROPERTYNAME_COMMENT = "comment";
constexpr const char* PROPERTYNAME_HCRC = "hcrc";
constexpr const char* PROPERTYNAME_DONE = "done";
constexpr const char* PROPERTYNAME_DICTIONARY_LENGTH = "dictionaryLength";
constexpr const char* PROPERTYNAME_PENDING = "pending";
constexpr const char* PROPERTYNAME_BITS = "bits";
} // namespace
using namespace arkts::ani_signature;

void ThrowZLibNapiError(ani_env* env, int posixError)
{
    auto errorPair = LIBZIP::errCodeTable.find(posixError) == LIBZIP::errCodeTable.end()
        ? LIBZIP::errCodeTable.at(ENOSTR) : LIBZIP::errCodeTable.at(posixError);
    BusinessErrorAni::ThrowError(env, errorPair.first, errorPair.second);
}

bool ParseOptions(ani_env* env, ani_object object, LIBZIP::OPTIONS& options)
{
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

bool ParseZStream(ani_env* env, ani_object object, LIBZIP::HasZStreamMember& hasZStreamMember, z_stream& result)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(object);

    // nextIn?: ArrayBuffer
    ani_arraybuffer arrayBuffer = nullptr;
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTYNAME_NEXTIN, &arrayBuffer)) {
        void *buf = nullptr;
        size_t bufLen = 0;
        RETURN_FALSE_IF_FALSE(ParseArrayBuffer(env, arrayBuffer, buf, bufLen, EINVAL));
        result.next_in = static_cast<Bytef *>(buf);
        hasZStreamMember.hasNextIn = true;
    }

    // availableIn?: int
    ani_int intValue = 0;
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTYNAME_AVAILABLE_IN, &intValue)) {
        result.avail_in = static_cast<uInt>(intValue);
        hasZStreamMember.hasAvailIn = true;
    }

    // totalIn?: long
    ani_long longValue = 0;
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTYNAME_TOTAL_IN, &longValue)) {
        result.total_in = static_cast<uLong>(longValue);
        hasZStreamMember.hasTotalIn = true;
    }

    // nextOut?: ArrayBuffer
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTYNAME_NEXT_OUT, &arrayBuffer)) {
        void *buf = nullptr;
        size_t bufLen = 0;
        RETURN_FALSE_IF_FALSE(ParseArrayBuffer(env, arrayBuffer, buf, bufLen, EINVAL));
        result.next_out = static_cast<Bytef *>(buf);
        hasZStreamMember.hasNextOut = true;
    }

    // availableOut?: int
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTYNAME_AVAILABLE_OUT, &intValue)) {
        result.avail_out = static_cast<uInt>(intValue);
        hasZStreamMember.hasAvailOut = true;
    }

    // totalOut?: long
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTYNAME_TOTAL_OUT, &longValue)) {
        result.total_out = static_cast<uLong>(longValue);
        hasZStreamMember.hasTotalOut = true;
    }

    // dataType?: int
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTYNAME_DATA_TYPE, &intValue)) {
        result.data_type = static_cast<int>(intValue);
        hasZStreamMember.hasDataType = true;
    }

    // adler?: long
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTYNAME_ADLER, &longValue)) {
        result.adler = static_cast<ulong>(longValue);
        hasZStreamMember.hasAdler = true;
    }

    return true;
}

bool ParseGzHeader(ani_env* env, ani_object object, gz_header& result)
{
    RETURN_FALSE_IF_NULL(env);
    RETURN_FALSE_IF_NULL(object);

    // isText?: boolean
    ani_boolean boolValue = false;
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTYNAME_IS_TEXT, &boolValue)) {
        result.text = CommonFunAni::AniBooleanToBool(boolValue);
    }

    // os?: int
    ani_int intValue = 0;
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTYNAME_OS, &intValue)) {
        result.os = static_cast<int>(intValue);
    }

    // time?: long
    ani_long longValue = 0;
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTYNAME_TIME, &longValue)) {
        result.time = static_cast<uLong>(longValue);
    }

    // xflags?: int
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTYNAME_XFLAGS, &intValue)) {
        result.xflags = static_cast<int>(intValue);
    }

    // extra?: ArrayBuffer
    ani_arraybuffer arrayBuffer = nullptr;
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTYNAME_EXTRA, &arrayBuffer)) {
        void *buf = nullptr;
        size_t bufLen = 0;
        RETURN_FALSE_IF_FALSE(ParseArrayBuffer(env, arrayBuffer, buf, bufLen, EINVAL));
        result.extra = static_cast<Bytef *>(buf);
    }

    // extraLen?: int
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTYNAME_EXTRA_LEN, &intValue)) {
        result.extra_len = static_cast<uInt>(intValue);
    }

    // name?: ArrayBuffer
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTYNAME_NAME, &arrayBuffer)) {
        void *buf = nullptr;
        size_t bufLen = 0;
        RETURN_FALSE_IF_FALSE(ParseArrayBuffer(env, arrayBuffer, buf, bufLen, EINVAL));
        result.name = static_cast<Bytef *>(buf);
    }

    // comment?: ArrayBuffer
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTYNAME_COMMENT, &arrayBuffer)) {
        void *buf = nullptr;
        size_t bufLen = 0;
        RETURN_FALSE_IF_FALSE(ParseArrayBuffer(env, arrayBuffer, buf, bufLen, EINVAL));
        result.comment = static_cast<Bytef *>(buf);
    }

    // hcrc?: boolean
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTYNAME_HCRC, &boolValue)) {
        result.hcrc = CommonFunAni::AniBooleanToBool(boolValue);
    }

    // done?: boolean
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTYNAME_DONE, &boolValue)) {
        result.done = CommonFunAni::AniBooleanToBool(boolValue);
    }

    return true;
}

ani_object ConvertZStream(ani_env* env, const z_streamp zStream)
{
    RETURN_NULL_IF_NULL(env);

    // availableIn?: int
    ani_object availableIn = CommonFunAni::BoxValue(env, static_cast<ani_int>(zStream->avail_in));
    RETURN_NULL_IF_FALSE(availableIn);

    // totalIn?: long
    ani_object totalIn = CommonFunAni::BoxValue(env, static_cast<ani_long>(zStream->total_in));
    RETURN_NULL_IF_FALSE(totalIn);

    // availableOut?: int
    ani_object availableOut = CommonFunAni::BoxValue(env, static_cast<ani_int>(zStream->avail_out));
    RETURN_NULL_IF_FALSE(availableOut);

    // totalOut?: long
    ani_object totalOut = CommonFunAni::BoxValue(env, static_cast<ani_long>(zStream->total_out));
    RETURN_NULL_IF_FALSE(totalOut);

    // dataType?: int
    ani_object dataType = CommonFunAni::BoxValue(env, static_cast<ani_int>(zStream->data_type));
    RETURN_NULL_IF_FALSE(dataType);

    // adler?: long
    ani_object adler = CommonFunAni::BoxValue(env, static_cast<ani_long>(zStream->adler));
    RETURN_NULL_IF_FALSE(adler);

    ani_value args[] = {
        { .r = availableIn },
        { .r = totalIn },
        { .r = availableOut },
        { .r = totalOut },
        { .r = dataType },
        { .r = adler },
    };
    static const std::string ctorSig =
        arkts::ani_signature::SignatureBuilder()
            .AddClass(CommonFunAniNS::CLASSNAME_INT)  // availableIn?: int
            .AddClass(CommonFunAniNS::CLASSNAME_LONG) // totalIn?: long
            .AddClass(CommonFunAniNS::CLASSNAME_INT)  // availableOut?: int
            .AddClass(CommonFunAniNS::CLASSNAME_LONG) // totalOut?: long
            .AddClass(CommonFunAniNS::CLASSNAME_INT)  // dataType?: int
            .AddClass(CommonFunAniNS::CLASSNAME_LONG) // adler?: long
            .BuildSignatureDescriptor();
    return CommonFunAni::CreateNewObjectByClassV2(env, CLASSNAME_ZSTREAM_INNER, ctorSig, args);
}

ani_object ConvertZipOutputInfo(ani_env* env, const int32_t errCode, const uLong destLen)
{
    RETURN_NULL_IF_NULL(env);

    ani_value args[] = {
        { .r = EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, errCode) },
        { .l = static_cast<ani_long>(destLen) },
    };
    static const std::string ctorSig =
        arkts::ani_signature::SignatureBuilder()
            .AddClass(CommonFunAniNS::CLASSNAME_ZLIB_RETURN_STATUS) // status: ReturnStatus
            .AddLong()                                              // destLen: long
            .BuildSignatureDescriptor();
    return CommonFunAni::CreateNewObjectByClassV2(env, CLASSNAME_ZIP_OUTPUT_INFO_INNER, ctorSig, args);
}

ani_object ConvertDecompressionOutputInfo(ani_env* env,
    const int32_t errCode, const uLong destLen, const ulong sourceLen)
{
    RETURN_NULL_IF_NULL(env);

    ani_value args[] = {
        { .r = EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, errCode) },
        { .l = static_cast<ani_long>(destLen) },
        { .l = static_cast<ani_long>(sourceLen) },
    };
    static const std::string ctorSig =
        arkts::ani_signature::SignatureBuilder()
            .AddClass(CommonFunAniNS::CLASSNAME_ZLIB_RETURN_STATUS) // status: ReturnStatus
            .AddLong()                                              // destLength: long
            .AddLong()                                              // sourceLength: long
            .BuildSignatureDescriptor();
    return CommonFunAni::CreateNewObjectByClassV2(env, CLASSNAME_DECOMPERSSION_OUTPUT_INFO_INNER, ctorSig, args);
}

ani_object ConvertDictionaryOutputInfo(ani_env* env, const int32_t errCode, const uInt dictionaryLen)
{
    RETURN_NULL_IF_NULL(env);

    ani_value args[] = {
        { .r = EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, errCode) },
        { .i = static_cast<ani_int>(dictionaryLen) },
    };
    static const std::string ctorSig =
        arkts::ani_signature::SignatureBuilder()
            .AddClass(CommonFunAniNS::CLASSNAME_ZLIB_RETURN_STATUS) // status: ReturnStatus
            .AddInt()                                               // dictionaryLength: int
            .BuildSignatureDescriptor();
    return CommonFunAni::CreateNewObjectByClassV2(env, CLASSNAME_DICTIONARY_OUTPUT_INFO_INNER, ctorSig, args);
}

ani_object ConvertDeflatePendingOutputInfo(ani_env* env,
    const int32_t errCode, const uint32_t pending, const int32_t bits)
{
    RETURN_NULL_IF_NULL(env);

    ani_value args[] = {
        { .r = EnumUtils::EnumNativeToETS_Zlib_ReturnStatus(env, errCode) },
        { .i = static_cast<ani_int>(pending) },
        { .i = static_cast<ani_int>(bits) },
    };
    static const std::string ctorSig =
        arkts::ani_signature::SignatureBuilder()
            .AddClass(CommonFunAniNS::CLASSNAME_ZLIB_RETURN_STATUS) // status: ReturnStatus
            .AddInt()                                               // pending: int
            .AddInt()                                               // bits: int
            .BuildSignatureDescriptor();
    return CommonFunAni::CreateNewObjectByClassV2(env, CLASSNAME_DEFLATE_PENDING_OUTPUT_INFO_INNER, ctorSig, args);
}
} // namespace AniZLibCommon
} // namespace AppExecFwk
} // namespace OHOS