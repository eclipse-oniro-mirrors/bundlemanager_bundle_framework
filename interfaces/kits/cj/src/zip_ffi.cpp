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

#include "zip_ffi.h"
#include <string>
#include <vector>
#include "zip_utils.h"
#include "cj_zip.h"
#include "cj_common_ffi.h"
#include "common_func.h"
#include "app_log_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {

extern "C" {
    int32_t FfiCompressFile(CArrUI8 inFile, CArrUI8 outFile, RetOptions options)
    {
        APP_LOGI("begin to FfiCompressFile");
        std::vector<uint8_t> inBytesVec;
        for (int i = 0; i < inFile.len; i++) {
            inBytesVec.push_back(inFile.data[i]);
        }
        std::string strInFile(inBytesVec.begin(), inBytesVec.end());
        std::vector<uint8_t> outBytesVec;
        for (int i = 0; i < outFile.len; i++) {
            outBytesVec.push_back(outFile.data[i]);
        }
        std::string strOutFile(outBytesVec.begin(), outBytesVec.end());
        int32_t code = ERROR_CODE_ERRNO;
        OPTIONS cOptions;
        cOptions.level = static_cast<COMPRESS_LEVEL>(options.level);
        cOptions.memLevel = static_cast<MEMORY_LEVEL>(options.memLevel);
        cOptions.strategy = static_cast<COMPRESS_STRATEGY>(options.strategy);

        code = Zip(strInFile, strOutFile, cOptions);
        int32_t err = CommonFunc::ConvertErrCode(code);

        return err;
    }
    

    int32_t FfiDeCompressFileOptions(CArrUI8 inFile, CArrUI8 outFile, RetOptions options)
    {
        APP_LOGI("begin to FfiDeCompressFileOptions");
        std::vector<uint8_t> inBytesVec;
        for (int i = 0; i < inFile.len; i++) {
            inBytesVec.push_back(inFile.data[i]);
        }
        std::string strInFile(inBytesVec.begin(), inBytesVec.end());
        std::vector<uint8_t> outBytesVec;
        for (int i = 0; i < outFile.len; i++) {
            outBytesVec.push_back(outFile.data[i]);
        }
        std::string strOutFile(outBytesVec.begin(), outBytesVec.end());
        int32_t code = ERROR_CODE_ERRNO;
        OPTIONS cOptions;
        cOptions.level = static_cast<COMPRESS_LEVEL>(options.level);
        cOptions.memLevel = static_cast<MEMORY_LEVEL>(options.memLevel);
        cOptions.strategy = static_cast<COMPRESS_STRATEGY>(options.strategy);

        code = UnZip(strInFile, strOutFile, cOptions);
        int32_t err = CommonFunc::ConvertErrCode(code);

        return err;
    }

    int32_t FfiDeCompressFile(CArrUI8 inFile, CArrUI8 outFile)
    {
        APP_LOGI("begin to FfiDeCompressFileOptions");
        std::vector<uint8_t> inBytesVec;
        for (int i = 0; i < inFile.len; i++) {
            inBytesVec.push_back(inFile.data[i]);
        }
        std::string strInFile(inBytesVec.begin(), inBytesVec.end());
        std::vector<uint8_t> outBytesVec;
        for (int i = 0; i < outFile.len; i++) {
            outBytesVec.push_back(outFile.data[i]);
        }
        std::string strOutFile(outBytesVec.begin(), outBytesVec.end());
        int32_t code = ERROR_CODE_ERRNO;
        OPTIONS cOptions;

        code = UnZip(strInFile, strOutFile, cOptions);
        int32_t err = CommonFunc::ConvertErrCode(code);

        return err;
    }
}

} // LIBZIP
} // AppExecFwk
} // OHOS
