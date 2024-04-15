/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "checksum_n_exporter.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <sstream>
#include <string>
#include <tuple>

#include "common/common_func.h"
#include "common/napi_async_work_callback.h"
#include "common/napi_async_work_promise.h"
#include "common/napi_class.h"
#include "common/napi_func_arg.h"
#include "common/napi_business_error.h"
#include "checksum_entity.h"
#include "zlib.h"

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {
using namespace std;

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

struct AsyncChecksumArg {
    uint64_t adler{0U};
    const z_crc_t* crcTable = nullptr;

    AsyncChecksumArg() = default;
    ~AsyncChecksumArg() = default;
};

static uint64_t ComputeCrc64(uint64_t initCrc, const char *data, size_t length)
{
    uint64_t crc = initCrc;

    /* computation of the CRC */
    for (size_t i = 0; i < length; ++i) {
        crc = CRC64_TABLE[(crc ^ data[i]) & 0xFF] ^ (crc >> SHIFT_AMOUNT);
    }

    return crc;
}

napi_value ChecksumNExporter::Constructor(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ZERO)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    unique_ptr<ChecksumEntity> checksumEntity = make_unique<ChecksumEntity>();
    if (!NapiClass::SetEntityFor<ChecksumEntity>(env, funcArg.GetThisVar(), move(checksumEntity))) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }
    return funcArg.GetThisVar();
}

bool ChecksumNExporter::Export()
{
    vector<napi_property_descriptor> props = {
        NapiValue::DeclareNapiFunction("adler32", Adler32),
        NapiValue::DeclareNapiFunction("adler32Combine", Adler32Combine),
        NapiValue::DeclareNapiFunction("adler32Combine64", Adler32Combine64),
        NapiValue::DeclareNapiFunction("crc32", Crc32),
        NapiValue::DeclareNapiFunction("crc32Combine", Crc32Combine),
        NapiValue::DeclareNapiFunction("crc32Combine64", Crc32Combine64),
        NapiValue::DeclareNapiFunction("getCrcTable", GetCrcTable),
        NapiValue::DeclareNapiFunction("getCrc64Table", GetCrc64Table),
        NapiValue::DeclareNapiFunction("crc64", Crc64),
    };

    string className = GetClassName();
    bool succ = false;
    napi_value cls = nullptr;
    tie(succ, cls) = NapiClass::DefineClass(exports_.env_, className, ChecksumNExporter::Constructor, move(props));
    if (!succ) {
        NapiBusinessError().ThrowErr(exports_.env_, EFAULT);
        return false;
    }
    succ = NapiClass::SaveClass(exports_.env_, className, cls);
    if (!succ) {
        NapiBusinessError().ThrowErr(exports_.env_, EFAULT);
        return false;
    }

    return exports_.AddProp(className, cls);
}

string ChecksumNExporter::GetClassName()
{
    return ChecksumNExporter::className_;
}

ChecksumNExporter::ChecksumNExporter(napi_env env, napi_value exports) : NapiExporter(env, exports)
{}

ChecksumNExporter::~ChecksumNExporter()
{}

napi_value ChecksumNExporter::Adler32(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::TWO, ArgumentCount::THREE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto checksumEntity = NapiClass::GetEntityOf<ChecksumEntity>(env, funcArg.GetThisVar());
    if (!checksumEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    void *buf = nullptr;
    size_t len = 0;
    uLong adler = 0U;
    tie(succ, adler, buf, len) = CommonFunc::GetAdler32Arg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncChecksumArg>();
    auto cbExec = [arg, adler, buf, len](napi_env env) -> NapiBusinessError {
        if (!arg) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->adler = adler32(static_cast<uLong>(adler), reinterpret_cast<Bytef *>(buf), static_cast<uInt>(len));
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt64(env, arg->adler)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::TWO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    } else {
        NapiValue cb(env, funcArg[ArgumentPosition::THIRD]);
        return NapiAsyncWorkCallback(env, thisVar, cb).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ChecksumNExporter::Adler32Combine(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::THREE, ArgumentCount::FOUR)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto checksumEntity = NapiClass::GetEntityOf<ChecksumEntity>(env, funcArg.GetThisVar());
    if (!checksumEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    size_t len = 0;
    uLong adler1 = 0U;
    uLong adler2 = 0U;
    tie(succ, adler1, adler2, len) = CommonFunc::GetAdler32CombineArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncChecksumArg>();
    auto cbExec = [arg, adler1, adler2, len](napi_env env) -> NapiBusinessError {
        if (!arg) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->adler = adler32_combine(static_cast<uLong>(adler1), static_cast<uLong>(adler2), static_cast<uInt>(len));
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt64(env, arg->adler)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::THREE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    } else {
        NapiValue cb(env, funcArg[ArgumentPosition::FOURTH]);
        return NapiAsyncWorkCallback(env, thisVar, cb).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ChecksumNExporter::Adler32Combine64(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::THREE, ArgumentCount::FOUR)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto checksumEntity = NapiClass::GetEntityOf<ChecksumEntity>(env, funcArg.GetThisVar());
    if (!checksumEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    size_t len = 0;
    uLong adler1 = 0U;
    uLong adler2 = 0U;
    tie(succ, adler1, adler2, len) = CommonFunc::GetAdler32CombineArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncChecksumArg>();
    auto cbExec = [arg, adler1, adler2, len](napi_env env) -> NapiBusinessError {
        if (!arg) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->adler = adler32_combine(static_cast<uLong>(adler1), static_cast<uLong>(adler2), static_cast<uInt>(len));
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt64(env, arg->adler)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::THREE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    } else {
        NapiValue cb(env, funcArg[ArgumentPosition::FOURTH]);
        return NapiAsyncWorkCallback(env, thisVar, cb).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ChecksumNExporter::Crc32(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::TWO, ArgumentCount::THREE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto checksumEntity = NapiClass::GetEntityOf<ChecksumEntity>(env, funcArg.GetThisVar());
    if (!checksumEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    void *buf = nullptr;
    size_t len = 0;
    uLong adler = 0U;
    tie(succ, adler, buf, len) = CommonFunc::GetAdler32Arg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncChecksumArg>();
    auto cbExec = [arg, adler, buf, len](napi_env env) -> NapiBusinessError {
        if (!arg) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->adler = crc32(static_cast<uLong>(adler), reinterpret_cast<Bytef *>(buf), static_cast<uInt>(len));
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt64(env, arg->adler)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::TWO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    } else {
        NapiValue cb(env, funcArg[ArgumentPosition::THIRD]);
        return NapiAsyncWorkCallback(env, thisVar, cb).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ChecksumNExporter::Crc32Combine(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::THREE, ArgumentCount::FOUR)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto checksumEntity = NapiClass::GetEntityOf<ChecksumEntity>(env, funcArg.GetThisVar());
    if (!checksumEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    size_t len = 0;
    uLong adler1 = 0U;
    uLong adler2 = 0U;
    tie(succ, adler1, adler2, len) = CommonFunc::GetAdler32CombineArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncChecksumArg>();
    auto cbExec = [arg, adler1, adler2, len](napi_env env) -> NapiBusinessError {
        if (!arg) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->adler = crc32_combine(static_cast<uLong>(adler1), static_cast<uLong>(adler2), static_cast<uInt>(len));
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt64(env, arg->adler)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::THREE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    } else {
        NapiValue cb(env, funcArg[ArgumentPosition::FOURTH]);
        return NapiAsyncWorkCallback(env, thisVar, cb).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ChecksumNExporter::Crc32Combine64(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::THREE, ArgumentCount::FOUR)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    /* To get entity */
    auto checksumEntity = NapiClass::GetEntityOf<ChecksumEntity>(env, funcArg.GetThisVar());
    if (!checksumEntity) {
        NapiBusinessError().ThrowErr(env, EFAULT);
        return nullptr;
    }

    bool succ = false;
    size_t len = 0;
    uLong adler1 = 0U;
    uLong adler2 = 0U;
    tie(succ, adler1, adler2, len) = CommonFunc::GetAdler32CombineArg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncChecksumArg>();
    auto cbExec = [arg, adler1, adler2, len](napi_env env) -> NapiBusinessError {
        if (!arg) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->adler = crc32_combine(static_cast<uLong>(adler1), static_cast<uLong>(adler2), static_cast<uInt>(len));
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateInt64(env, arg->adler)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::THREE) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    } else {
        NapiValue cb(env, funcArg[ArgumentPosition::FOURTH]);
        return NapiAsyncWorkCallback(env, thisVar, cb).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ChecksumNExporter::GetCrcTable(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ZERO, ArgumentCount::ONE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    size_t tableSize = 256;
    auto arg = make_shared<AsyncChecksumArg>();
    auto cbExec = [arg](napi_env env) -> NapiBusinessError {
        if (!arg) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->crcTable = get_crc_table();
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg, tableSize](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        std::vector<int64_t> crcVector(tableSize);
        for (size_t i = 0; i < tableSize; ++i) {
            crcVector[i] = static_cast<int64_t>(arg->crcTable[i]);
        }
        return {NapiValue::CreateInt64Array(env, crcVector)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ZERO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    } else {
        NapiValue cb(env, funcArg[ArgumentPosition::FIRST]);
        return NapiAsyncWorkCallback(env, thisVar, cb).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ChecksumNExporter::Crc64(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::TWO, ArgumentCount::THREE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    bool succ = false;
    void *buf = nullptr;
    size_t len = 0;
    uint64_t crc64 = 0U;
    tie(succ, crc64, buf, len) = CommonFunc::GetCrc64Arg(env, funcArg);
    if (!succ) {
        return nullptr;
    }

    auto arg = make_shared<AsyncChecksumArg>();
    auto cbExec = [arg, crc64, buf, len](napi_env env) -> NapiBusinessError {
        if (!arg) {
            return NapiBusinessError(EFAULT, true);
        }
        arg->adler = ComputeCrc64(crc64, reinterpret_cast<char *>(buf), len);
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        return {NapiValue::CreateUint64(env, arg->adler)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::TWO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    } else {
        NapiValue cb(env, funcArg[ArgumentPosition::THIRD]);
        return NapiAsyncWorkCallback(env, thisVar, cb).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}

napi_value ChecksumNExporter::GetCrc64Table(napi_env env, napi_callback_info info)
{
    NapiFuncArg funcArg(env, info);
    if (!funcArg.InitArgs(ArgumentCount::ZERO, ArgumentCount::ONE)) {
        NapiBusinessError().ThrowErr(env, EINVAL);
        return nullptr;
    }

    size_t tableSize = 256;
    auto arg = make_shared<AsyncChecksumArg>();
    auto cbExec = [](napi_env env) -> NapiBusinessError {
        return NapiBusinessError(ERRNO_NOERR);
    };

    auto cbCompl = [arg, tableSize](napi_env env, NapiBusinessError err) -> NapiValue {
        if (err) {
            return {env, err.GetNapiErr(env)};
        }
        if (!arg) {
            return {NapiValue::CreateUndefined(env)};
        }
        std::vector<uint64_t> crcVector(tableSize);
        for (size_t i = 0; i < tableSize; ++i) {
            crcVector[i] = static_cast<uint64_t>(CRC64_TABLE[i]);
        }
        return {NapiValue::CreateBigUint64Array(env, crcVector)};
    };

    NapiValue thisVar(env, funcArg.GetThisVar());
    if (funcArg.GetArgc() == ArgumentCount::ZERO) {
        return NapiAsyncWorkPromise(env, thisVar).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    } else {
        NapiValue cb(env, funcArg[ArgumentPosition::FIRST]);
        return NapiAsyncWorkCallback(env, thisVar, cb).Schedule(PROCEDURE_CHECKSUM_NAME, cbExec, cbCompl).val_;
    }

    return NapiValue::CreateUndefined(env).val_;
}
}  // namespace LIBZIP
}  // namespace AppExecFwk
}  // namespace OHOS