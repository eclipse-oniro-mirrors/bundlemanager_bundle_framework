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
#include "common_fun_ani.h"
#include "common_func.h"
#include "enum_util.h"
#include "napi_constants.h"
#include "zip.h"
#include "zlib.h"

namespace OHOS {
namespace AppExecFwk {

namespace {
constexpr const char* NS_NAME_ZLIB = "@ohos.zlib.zlib";
constexpr const char* PROPERTY_NAME_LEVEL = "level";
constexpr const char* PROPERTY_NAME_MEMLEVEL = "memLevel";
constexpr const char* PROPERTY_NAME_STRATEGY = "strategy";
constexpr const char* TYPE_NAME_CHECKSUMINTERNAL = "ChecksumInternal";
constexpr const char* PARAM_NAME_IN_FILE = "inFile";
constexpr const char* PARAM_NAME_IN_FILES = "inFiles";
constexpr const char* PARAM_NAME_OUT_FILE = "outFile";
constexpr const char* PARAM_NAME_OPTIONS = "options";
constexpr const char* PARAM_NAME_BUF = "buf";
constexpr const char* PARAM_NAME_ADLER = "adler";
constexpr const char* PARAM_NAME_ADLER1 = "adler1";
constexpr const char* PARAM_NAME_ADLER2 = "adler2";
constexpr const char* PARAM_NAME_CRC = "crc";
constexpr const char* PARAM_NAME_CRC1 = "crc1";
constexpr const char* PARAM_NAME_CRC2 = "crc2";
constexpr const char* PARAM_NAME_LEN2 = "len2";
constexpr const char* TYPE_ARRAYBUFFER = "ArrayBuffer";
constexpr const size_t TABLE_SIZE = 256;
constexpr int32_t SHIFT_AMOUNT = 8;
constexpr uint64_t CRC64_TABLE[] = {
    0x0000000000000000, 0x3c3b78e888d80fe1, 0x7876f1d111b01fc2, 0x444d893999681023,
    0x750c207570b452a3, 0x4937589df86c5d42, 0x0d7ad1a461044d61, 0x3141a94ce9dc4280,
    0x6ff9833db2bcc861, 0x53c2fbd53a64c780, 0x178f72eca30cd7a3, 0x2bb40a042bd4d842,
    0x1af5a348c2089ac2, 0x26cedba04ad09523, 0x62835299d3b88500, 0x5eb82a715b608ae1,
    0x5a12c5ac36adfde5, 0x6629bd44be75f204, 0x2264347d271de227, 0x1e5f4c95afc5edc6,
    0x2f1ee5d94619af46, 0x13259d31cec1a0a7, 0x5768140857a9b084, 0x6b536ce0df71bf65,
    0x35eb469184113584, 0x09d03e790cc93a65, 0x4d9db74095a12a46, 0x71a6cfa81d7925a7,
    0x40e766e4f4a56727, 0x7cdc1e0c7c7d68c6, 0x38919735e51578e5, 0x04aaefdd6dcd7704,
    0x31c4488f3e8f96ed, 0x0dff3067b657990c, 0x49b2b95e2f3f892f, 0x7589c1b6a7e786ce,
    0x44c868fa4e3bc44e, 0x78f31012c6e3cbaf, 0x3cbe992b5f8bdb8c, 0x0085e1c3d753d46d,
    0x5e3dcbb28c335e8c, 0x6206b35a04eb516d, 0x264b3a639d83414e, 0x1a70428b155b4eaf,
    0x2b31ebc7fc870c2f, 0x170a932f745f03ce, 0x53471a16ed3713ed, 0x6f7c62fe65ef1c0c,
    0x6bd68d2308226b08, 0x57edf5cb80fa64e9, 0x13a07cf2199274ca, 0x2f9b041a914a7b2b,
    0x1edaad56789639ab, 0x22e1d5bef04e364a, 0x66ac5c8769262669, 0x5a97246fe1fe2988,
    0x042f0e1eba9ea369, 0x381476f63246ac88, 0x7c59ffcfab2ebcab, 0x4062872723f6b34a,
    0x71232e6bca2af1ca, 0x4d18568342f2fe2b, 0x0955dfbadb9aee08, 0x356ea7525342e1e9,
    0x6388911e7d1f2dda, 0x5fb3e9f6f5c7223b, 0x1bfe60cf6caf3218, 0x27c51827e4773df9,
    0x1684b16b0dab7f79, 0x2abfc98385737098, 0x6ef240ba1c1b60bb, 0x52c9385294c36f5a,
    0x0c711223cfa3e5bb, 0x304a6acb477bea5a, 0x7407e3f2de13fa79, 0x483c9b1a56cbf598,
    0x797d3256bf17b718, 0x45464abe37cfb8f9, 0x010bc387aea7a8da, 0x3d30bb6f267fa73b,
    0x399a54b24bb2d03f, 0x05a12c5ac36adfde, 0x41eca5635a02cffd, 0x7dd7dd8bd2dac01c,
    0x4c9674c73b06829c, 0x70ad0c2fb3de8d7d, 0x34e085162ab69d5e, 0x08dbfdfea26e92bf,
    0x5663d78ff90e185e, 0x6a58af6771d617bf, 0x2e15265ee8be079c, 0x122e5eb66066087d,
    0x236ff7fa89ba4afd, 0x1f548f120162451c, 0x5b19062b980a553f, 0x67227ec310d25ade,
    0x524cd9914390bb37, 0x6e77a179cb48b4d6, 0x2a3a28405220a4f5, 0x160150a8daf8ab14,
    0x2740f9e43324e994, 0x1b7b810cbbfce675, 0x5f3608352294f656, 0x630d70ddaa4cf9b7,
    0x3db55aacf12c7356, 0x018e224479f47cb7, 0x45c3ab7de09c6c94, 0x79f8d39568446375,
    0x48b97ad9819821f5, 0x7482023109402e14, 0x30cf8b0890283e37, 0x0cf4f3e018f031d6,
    0x085e1c3d753d46d2, 0x346564d5fde54933, 0x7028edec648d5910, 0x4c139504ec5556f1,
    0x7d523c4805891471, 0x416944a08d511b90, 0x0524cd9914390bb3, 0x391fb5719ce10452,
    0x67a79f00c7818eb3, 0x5b9ce7e84f598152, 0x1fd16ed1d6319171, 0x23ea16395ee99e90,
    0x12abbf75b735dc10, 0x2e90c79d3fedd3f1, 0x6add4ea4a685c3d2, 0x56e6364c2e5dcc33,
    0x42f0e1eba9ea3693, 0x7ecb990321323972, 0x3a86103ab85a2951, 0x06bd68d2308226b0,
    0x37fcc19ed95e6430, 0x0bc7b97651866bd1, 0x4f8a304fc8ee7bf2, 0x73b148a740367413,
    0x2d0962d61b56fef2, 0x11321a3e938ef113, 0x557f93070ae6e130, 0x6944ebef823eeed1,
    0x580542a36be2ac51, 0x643e3a4be33aa3b0, 0x2073b3727a52b393, 0x1c48cb9af28abc72,
    0x18e224479f47cb76, 0x24d95caf179fc497, 0x6094d5968ef7d4b4, 0x5cafad7e062fdb55,
    0x6dee0432eff399d5, 0x51d57cda672b9634, 0x1598f5e3fe438617, 0x29a38d0b769b89f6,
    0x771ba77a2dfb0317, 0x4b20df92a5230cf6, 0x0f6d56ab3c4b1cd5, 0x33562e43b4931334,
    0x0217870f5d4f51b4, 0x3e2cffe7d5975e55, 0x7a6176de4cff4e76, 0x465a0e36c4274197,
    0x7334a9649765a07e, 0x4f0fd18c1fbdaf9f, 0x0b4258b586d5bfbc, 0x3779205d0e0db05d,
    0x06388911e7d1f2dd, 0x3a03f1f96f09fd3c, 0x7e4e78c0f661ed1f, 0x427500287eb9e2fe,
    0x1ccd2a5925d9681f, 0x20f652b1ad0167fe, 0x64bbdb88346977dd, 0x5880a360bcb1783c,
    0x69c10a2c556d3abc, 0x55fa72c4ddb5355d, 0x11b7fbfd44dd257e, 0x2d8c8315cc052a9f,
    0x29266cc8a1c85d9b, 0x151d14202910527a, 0x51509d19b0784259, 0x6d6be5f138a04db8,
    0x5c2a4cbdd17c0f38, 0x6011345559a400d9, 0x245cbd6cc0cc10fa, 0x1867c58448141f1b,
    0x46dfeff5137495fa, 0x7ae4971d9bac9a1b, 0x3ea91e2402c48a38, 0x029266cc8a1c85d9,
    0x33d3cf8063c0c759, 0x0fe8b768eb18c8b8, 0x4ba53e517270d89b, 0x779e46b9faa8d77a,
    0x217870f5d4f51b49, 0x1d43081d5c2d14a8, 0x590e8124c545048b, 0x6535f9cc4d9d0b6a,
    0x54745080a44149ea, 0x684f28682c99460b, 0x2c02a151b5f15628, 0x1039d9b93d2959c9,
    0x4e81f3c86649d328, 0x72ba8b20ee91dcc9, 0x36f7021977f9ccea, 0x0acc7af1ff21c30b,
    0x3b8dd3bd16fd818b, 0x07b6ab559e258e6a, 0x43fb226c074d9e49, 0x7fc05a848f9591a8,
    0x7b6ab559e258e6ac, 0x4751cdb16a80e94d, 0x031c4488f3e8f96e, 0x3f273c607b30f68f,
    0x0e66952c92ecb40f, 0x325dedc41a34bbee, 0x761064fd835cabcd, 0x4a2b1c150b84a42c,
    0x1493366450e42ecd, 0x28a84e8cd83c212c, 0x6ce5c7b54154310f, 0x50debf5dc98c3eee,
    0x619f161120507c6e, 0x5da46ef9a888738f, 0x19e9e7c031e063ac, 0x25d29f28b9386c4d,
    0x10bc387aea7a8da4, 0x2c87409262a28245, 0x68cac9abfbca9266, 0x54f1b14373129d87,
    0x65b0180f9acedf07, 0x598b60e71216d0e6, 0x1dc6e9de8b7ec0c5, 0x21fd913603a6cf24,
    0x7f45bb4758c645c5, 0x437ec3afd01e4a24, 0x07334a9649765a07, 0x3b08327ec1ae55e6,
    0x0a499b3228721766, 0x3672e3daa0aa1887, 0x723f6ae339c208a4, 0x4e04120bb11a0745,
    0x4aaefdd6dcd77041, 0x7695853e540f7fa0, 0x32d80c07cd676f83, 0x0ee374ef45bf6062,
    0x3fa2dda3ac6322e2, 0x0399a54b24bb2d03, 0x47d42c72bdd33d20, 0x7bef549a350b32c1,
    0x25577eeb6e6bb820, 0x196c0603e6b3b7c1, 0x5d218f3a7fdba7e2, 0x611af7d2f703a803,
    0x505b5e9e1edfea83, 0x6c6026769607e562, 0x282daf4f0f6ff541, 0x1416d7a787b7faa0
};
} // namespace

using namespace arkts::ani_signature;

static uint64_t ComputeCrc64(uint64_t initCrc, const char *data, size_t length)
{
    uint64_t crc = initCrc;

    /* computation of the CRC */
    for (size_t i = 0; i < length; ++i) {
        crc = CRC64_TABLE[(crc ^ data[i]) & 0xFF] ^ (crc >> SHIFT_AMOUNT);
    }

    return crc;
}

template<typename tableType>
static ani_object ConvertCRCTable(ani_env* env, const tableType* table, const size_t tableSize)
{
    Type arrayType = Builder::BuildClass("escompat.Array");
    ani_class arrayCls = CommonFunAni::CreateClassByName(env, arrayType.Descriptor());
    RETURN_NULL_IF_NULL(arrayCls);

    ani_method arrayCtor = nullptr;
    ani_status status = env->Class_FindMethod(arrayCls, Builder::BuildConstructorName().c_str(),
        Builder::BuildSignatureDescriptor({ Builder::BuildInt() }).c_str(), &arrayCtor);
    if (status != ANI_OK) {
        APP_LOGE("Class_FindMethod Array failed %{public}d", status);
        return nullptr;
    }

    ani_object arrayObj = nullptr;
    status = env->Object_New(arrayCls, arrayCtor, &arrayObj, tableSize);
    if (status != ANI_OK) {
        APP_LOGE("Object_New Array failed %{public}d", status);
        return nullptr;
    }

    Type doubleType = Builder::BuildClass("std.core.Double");
    ani_class doubleClass = nullptr;
    status = env->FindClass(doubleType.Descriptor().c_str(), &doubleClass);
    if (status != ANI_OK) {
        APP_LOGE("FindClass Double failed %{public}d", status);
        return nullptr;
    }
    ani_method doubleCtor = nullptr;
    status = env->Class_FindMethod(doubleClass, Builder::BuildConstructorName().c_str(),
        Builder::BuildSignatureDescriptor({ Builder::BuildDouble() }).c_str(), &doubleCtor);
    if (status != ANI_OK) {
        APP_LOGE("Class_FindMethod Double ctor failed %{public}d", status);
        return nullptr;
    }
    std::string setSig = Builder::BuildSignatureDescriptor({ Builder::BuildInt(), Builder::BuildNull() });

    for (size_t i = 0; i < tableSize; ++i) {
        ani_object doubleObj = nullptr;
        status = env->Object_New(doubleClass, doubleCtor, &doubleObj, static_cast<double>(table[i]));
        if (status != ANI_OK) {
            APP_LOGE("Object_New Double failed %{public}d", status);
            return nullptr;
        }
        status = env->Object_CallMethodByName_Void(arrayObj, "$_set", setSig.c_str(), i, doubleObj);
        env->Reference_Delete(doubleObj);
        if (status != ANI_OK) {
            APP_LOGE("Object_CallMethodByName_Void failed %{public}d", status);
            return nullptr;
        }
    }

    return arrayObj;
}

static bool ANIParseOptions(ani_env* env, ani_object object, LIBZIP::OPTIONS& options)
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

    return true;
}

static void CompressFile(ani_env* env, ani_string aniInFile, ani_string aniOutFile, ani_object aniOptions)
{
    RETURN_IF_NULL(env);
    RETURN_IF_NULL(aniInFile);
    RETURN_IF_NULL(aniOutFile);
    RETURN_IF_NULL(aniOptions);

    std::string inFile = CommonFunAni::AniStrToString(env, aniInFile);
    if (inFile.empty()) {
        APP_LOGE("inFile is empty.");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_IN_FILE, TYPE_STRING);
        return;
    }

    std::string outFile = CommonFunAni::AniStrToString(env, aniOutFile);
    if (outFile.empty()) {
        APP_LOGE("outFile is empty.");
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
        APP_LOGE("CompressFile failed, ret %{public}d", errCode);
        BusinessErrorAni::ThrowCommonError(env, errCode, "", "");
    }
}

static void CompressFiles(ani_env* env, ani_object aniInFiles, ani_string aniOutFile, ani_object aniOptions)
{
    RETURN_IF_NULL(env);
    RETURN_IF_NULL(aniInFiles);
    RETURN_IF_NULL(aniOutFile);
    RETURN_IF_NULL(aniOptions);

    std::vector<std::string> inFiles;
    if (aniInFiles == nullptr || !CommonFunAni::ParseStrArray(env, aniInFiles, inFiles)) {
        APP_LOGE("inFiles parse failed.");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_IN_FILES, TYPE_ARRAY);
        return;
    }

    std::string outFile = CommonFunAni::AniStrToString(env, aniOutFile);
    if (outFile.empty()) {
        APP_LOGE("outFile is empty.");
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
        APP_LOGE("CompressFiles failed, ret %{public}d", errCode);
        BusinessErrorAni::ThrowCommonError(env, errCode, "", "");
    }
}

static void DecompressFile(ani_env* env, ani_string aniInFile, ani_string aniOutFile, ani_object aniOptions)
{
    RETURN_IF_NULL(env);
    RETURN_IF_NULL(aniInFile);
    RETURN_IF_NULL(aniOutFile);
    RETURN_IF_NULL(aniOptions);

    std::string inFile = CommonFunAni::AniStrToString(env, aniInFile);
    if (inFile.empty()) {
        APP_LOGE("inFile is empty.");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_IN_FILE, TYPE_STRING);
        return;
    }

    std::string outFile = CommonFunAni::AniStrToString(env, aniOutFile);
    if (outFile.empty()) {
        APP_LOGE("outFile is empty.");
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
        APP_LOGE("DecompressFile failed, ret %{public}d", errCode);
        BusinessErrorAni::ThrowCommonError(env, errCode, "", "");
    }
}

static ani_double GetOriginalSize(ani_env* env, ani_string aniCompressedFile)
{
    std::string compressedFile = CommonFunAni::AniStrToString(env, aniCompressedFile);
    if (compressedFile.empty()) {
        APP_LOGE("compressedFile is empty.");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_IN_FILE, TYPE_STRING);
        return 0;
    }

    int64_t originalSize = 0;
    const int32_t errCode = CommonFunc::ConvertErrCode(LIBZIP::GetOriginalSize(compressedFile, originalSize));
    if (errCode != ERR_OK) {
        APP_LOGE("GetOriginalSize failed, ret %{public}d", errCode);
        BusinessErrorAni::ThrowCommonError(env, errCode, "GetOriginalSize", "");
    }

    return originalSize;
}

static ani_object CreateChecksumSync(ani_env* env)
{
    Namespace zlibNS = Builder::BuildNamespace(NS_NAME_ZLIB);
    Type checksumType = Builder::BuildClass({ zlibNS.Name(), TYPE_NAME_CHECKSUMINTERNAL });
    ani_class clsChecksum = CommonFunAni::CreateClassByName(env, checksumType.Descriptor());
    RETURN_NULL_IF_NULL(clsChecksum);
    ani_object objChecksum = CommonFunAni::CreateNewObjectByClass(env, clsChecksum);
    return objChecksum;
}

static ani_double Adler32(
    ani_env* env, [[maybe_unused]] ani_object checksumObj, ani_double aniAdler, ani_arraybuffer buf)
{
    int64_t adler = 0;

    if (!CommonFunAni::TryCastDoubleTo(aniAdler, &adler)) {
        APP_LOGE("Cast aniAdler failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_ADLER, TYPE_NUMBER);
        return 0;
    }

    if (buf == nullptr) {
        APP_LOGE("buf is nullptr");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_BUF, TYPE_ARRAYBUFFER);
        return 0;
    }

    size_t bufferLength = 0;
    void* buffer = nullptr;
    ani_status status = env->ArrayBuffer_GetInfo(buf, &buffer, &bufferLength);
    if (status != ANI_OK) {
        APP_LOGE("ArrayBuffer_GetInfo failed: %{public}d", status);
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_BUF, TYPE_ARRAYBUFFER);
        return 0;
    }

    if (buffer == nullptr) {
        APP_LOGE("native buf is nullptr");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_BUF, TYPE_ARRAYBUFFER);
        return 0;
    }

    return adler32(static_cast<uLong>(adler), reinterpret_cast<Bytef*>(buffer), static_cast<uInt>(bufferLength));
}

static ani_double Adler32Combine(ani_env* env,
    [[maybe_unused]] ani_object checksumObj, ani_double aniAdler1, ani_double aniAdler2, ani_double aniLen2)
{
    int64_t adler1 = 0;
    int64_t adler2 = 0;
    int64_t len2 = 0;

    if (!CommonFunAni::TryCastDoubleTo(aniAdler1, &adler1)) {
        APP_LOGE("Cast aniAdler1 failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_ADLER1, TYPE_NUMBER);
        return 0;
    }

    if (!CommonFunAni::TryCastDoubleTo(aniAdler2, &adler2)) {
        APP_LOGE("Cast aniAdler2 failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_ADLER2, TYPE_NUMBER);
        return 0;
    }

    if (!CommonFunAni::TryCastDoubleTo(aniLen2, &len2)) {
        APP_LOGE("Cast aniLen2 failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_LEN2, TYPE_NUMBER);
        return 0;
    }

#ifdef Z_LARGE64
    return adler32_combine64(static_cast<uLong>(adler1), static_cast<uLong>(adler2), static_cast<z_off64_t>(len2));
#else
    return adler32_combine(static_cast<uLong>(adler1), static_cast<uLong>(adler2), static_cast<z_off64_t>(len2));
#endif
}

static ani_double Crc32(ani_env* env, [[maybe_unused]] ani_object checksumObj, ani_double aniCrc, ani_arraybuffer buf)
{
    int64_t crc = 0;

    if (!CommonFunAni::TryCastDoubleTo(aniCrc, &crc)) {
        APP_LOGE("Cast aniCrc failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_CRC, TYPE_NUMBER);
        return 0;
    }

    if (buf == nullptr) {
        APP_LOGE("buf is nullptr");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_BUF, TYPE_ARRAYBUFFER);
        return 0;
    }

    size_t bufferLength = 0;
    void* buffer = nullptr;
    ani_status status = env->ArrayBuffer_GetInfo(buf, &buffer, &bufferLength);
    if (status != ANI_OK) {
        APP_LOGE("ArrayBuffer_GetInfo failed: %{public}d", status);
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_BUF, TYPE_ARRAYBUFFER);
        return 0;
    }

    if (buffer == nullptr) {
        APP_LOGE("native buf is nullptr");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_BUF, TYPE_ARRAYBUFFER);
        return 0;
    }

    return crc32(static_cast<uLong>(crc), reinterpret_cast<Bytef*>(buffer), static_cast<uInt>(bufferLength));
}

static ani_double Crc32Combine(ani_env* env,
    [[maybe_unused]] ani_object checksumObj, ani_double aniCrc1, ani_double aniCrc2, ani_double aniLen2)
{
    int64_t crc1 = 0;
    int64_t crc2 = 0;
    int64_t len2 = 0;

    if (!CommonFunAni::TryCastDoubleTo(aniCrc1, &crc1)) {
        APP_LOGE("Cast aniCrc1 failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_CRC1, TYPE_NUMBER);
        return 0;
    }

    if (!CommonFunAni::TryCastDoubleTo(aniCrc2, &crc2)) {
        APP_LOGE("Cast aniCrc2 failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_CRC2, TYPE_NUMBER);
        return 0;
    }

    if (!CommonFunAni::TryCastDoubleTo(aniLen2, &len2)) {
        APP_LOGE("Cast aniLen2 failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_LEN2, TYPE_NUMBER);
        return 0;
    }

#ifdef Z_LARGE64
    return crc32_combine64(static_cast<uLong>(crc1), static_cast<uLong>(crc2), static_cast<z_off64_t>(len2));
#else
    return crc32_combine(static_cast<uLong>(crc1), static_cast<uLong>(crc2), static_cast<z_off64_t>(len2));
#endif
}

static ani_double Crc64(ani_env* env, [[maybe_unused]] ani_object checksumObj, ani_double aniCrc, ani_arraybuffer buf)
{
    uint64_t crc = 0;

    if (!CommonFunAni::TryCastDoubleTo(aniCrc, &crc)) {
        APP_LOGE("Cast aniCrc failed");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_CRC, TYPE_NUMBER);
        return 0;
    }

    if (buf == nullptr) {
        APP_LOGE("buf is nullptr");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_BUF, TYPE_ARRAYBUFFER);
        return 0;
    }

    size_t bufferLength = 0;
    void* buffer = nullptr;
    ani_status status = env->ArrayBuffer_GetInfo(buf, &buffer, &bufferLength);
    if (status != ANI_OK) {
        APP_LOGE("ArrayBuffer_GetInfo failed: %{public}d", status);
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_BUF, TYPE_ARRAYBUFFER);
        return 0;
    }

    if (buffer == nullptr) {
        APP_LOGE("native buf is nullptr");
        BusinessErrorAni::ThrowCommonError(env, ERROR_PARAM_CHECK_ERROR, PARAM_NAME_BUF, TYPE_ARRAYBUFFER);
        return 0;
    }

    return ComputeCrc64(crc, reinterpret_cast<char*>(buffer), bufferLength);
}

static ani_object GetCrcTable(ani_env* env, [[maybe_unused]] ani_object checksumObj)
{
    return ConvertCRCTable(env, get_crc_table(), TABLE_SIZE);
}

static ani_object GetCrc64Table(ani_env* env, [[maybe_unused]] ani_object checksumObj)
{
    return ConvertCRCTable(env, CRC64_TABLE, TABLE_SIZE);
}

static ani_status BindNSMethods(ani_env* env)
{
    Namespace zlibNS = Builder::BuildNamespace(NS_NAME_ZLIB);
    ani_namespace kitNs = nullptr;
    ani_status status = env->FindNamespace(zlibNS.Descriptor().c_str(), &kitNs);
    if (status != ANI_OK) {
        APP_LOGE("FindNamespace: %{public}s fail with %{public}d", NS_NAME_ZLIB, status);
        return status;
    }

    std::array methods = {
        ani_native_function { "CompressFile", nullptr, reinterpret_cast<void*>(CompressFile) },
        ani_native_function { "CompressFiles", nullptr, reinterpret_cast<void*>(CompressFiles) },
        ani_native_function { "DecompressFile", nullptr, reinterpret_cast<void*>(DecompressFile) },
        ani_native_function { "GetOriginalSize", nullptr, reinterpret_cast<void*>(GetOriginalSize) },
        ani_native_function { "createChecksumSync", nullptr, reinterpret_cast<void*>(CreateChecksumSync) },
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
    Type checksumType = Builder::BuildClass({ NS_NAME_ZLIB, TYPE_NAME_CHECKSUMINTERNAL });
    ani_class clsChecksum = CommonFunAni::CreateClassByName(env, checksumType.Descriptor());
    if (clsChecksum == nullptr) {
        APP_LOGE("CreateClassByName: %{public}s fail", TYPE_NAME_CHECKSUMINTERNAL);
        return ANI_ERROR;
    }

    std::array methodsChecksum = {
        ani_native_function { "Adler32", nullptr, reinterpret_cast<void*>(Adler32) },
        ani_native_function { "Adler32Combine", nullptr, reinterpret_cast<void*>(Adler32Combine) },
        ani_native_function { "Crc32", nullptr, reinterpret_cast<void*>(Crc32) },
        ani_native_function { "Crc32Combine", nullptr, reinterpret_cast<void*>(Crc32Combine) },
        ani_native_function { "Crc64", nullptr, reinterpret_cast<void*>(Crc64) },
        ani_native_function { "GetCrcTable", nullptr, reinterpret_cast<void*>(GetCrcTable) },
        ani_native_function { "GetCrc64Table", nullptr, reinterpret_cast<void*>(GetCrc64Table) },
    };

    ani_status status = env->Class_BindNativeMethods(clsChecksum, methodsChecksum.data(), methodsChecksum.size());
    if (status != ANI_OK) {
        APP_LOGE("Class_BindNativeMethods: %{public}s fail with %{public}d", TYPE_NAME_CHECKSUMINTERNAL, status);
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

    *result = ANI_VERSION_1;

    APP_LOGI("ANI_Constructor finished");

    return ANI_OK;
}
}
} // namespace AppExecFwk
} // namespace OHOS