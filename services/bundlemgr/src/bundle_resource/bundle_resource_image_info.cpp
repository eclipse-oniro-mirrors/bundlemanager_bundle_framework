/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "bundle_resource_image_info.h"

#include <fstream>
#include <sstream>

#include "app_log_wrapper.h"
#ifdef BUNDLE_FRAMEWORK_GRAPHICS
#include "image_packer.h"
#endif

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr uint8_t BIT_SIX = 6;
constexpr uint8_t BIT_FOUR = 4;
constexpr uint8_t BIT_TWO = 2;
constexpr uint8_t BIT_ONE = 1;
constexpr int32_t LEN_THREE = 3;
const std::vector<char> g_codes = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};
#ifdef BUNDLE_FRAMEWORK_GRAPHICS
const std::string FORMAT = "image/png";
#endif
const std::string IMAGE_HEADER_INFO = "data:image/png;base64,";
}

#ifdef BUNDLE_FRAMEWORK_GRAPHICS
bool BundleResourceImageInfo::ConvertToString(
    const std::shared_ptr<Media::PixelMap> pixelMap, std::string &imageInfo)
{
    APP_LOGD("start");
    if (pixelMap == nullptr) {
        APP_LOGE("pixelMap is nullptr");
        return false;
    }
    Media::PackOption option;
    option.format = FORMAT;
    Media::ImagePacker packer;
    std::stringstream outputStream;
    auto errCode = packer.StartPacking(outputStream, option);
    if (errCode != 0) {
        APP_LOGE("StartPacking failed, code: %{public}d", static_cast<int32_t>(errCode));
        return false;
    }
    errCode = packer.AddImage(*pixelMap);
    if (errCode != 0) {
        APP_LOGE("AddImage failed, code: %{public}d", static_cast<int32_t>(errCode));
        return false;
    }
    int64_t packedSize = 0;
    errCode = packer.FinalizePacking(packedSize);
    if (errCode != 0) {
        APP_LOGE("FinalizePacking failed, code: %{public}d", static_cast<int32_t>(errCode));
        return false;
    }
    std::string originalString = outputStream.str();
    APP_LOGD("image size:%{public}d, packedSize:%{public}d originalString size:%{public}d",
        pixelMap->GetByteCount(), static_cast<int32_t>(packedSize), static_cast<int32_t>(originalString.length()));
    // to base64
    if (!EncodeBase64(originalString, imageInfo)) {
        APP_LOGE("EncodeBase64 failed");
        return false;
    }
    APP_LOGD("end");
    return true;
}

bool BundleResourceImageInfo::EncodeBase64(
    const std::string &originalData,
    std::string &dstData)
{
    APP_LOGD("start");
    if (originalData.empty()) {
        APP_LOGE("originalData is empty");
        return false;
    }
    int32_t srcLen = static_cast<int32_t>(originalData.length() - 1);
    std::string base64data = IMAGE_HEADER_INFO;
    int32_t i = 0;
    // encode in groups of every 3 bytes
    for (i = 0; i < srcLen - LEN_THREE; i += LEN_THREE) {
        unsigned char byte1 = static_cast<unsigned char>(originalData[i]);
        unsigned char byte2 = static_cast<unsigned char>(originalData[i + BIT_ONE]);
        unsigned char byte3 = static_cast<unsigned char>(originalData[i + BIT_TWO]);
        base64data += g_codes[byte1 >> BIT_TWO];
        base64data += g_codes[((byte1 & 0x3) << BIT_FOUR) | (byte2 >> BIT_FOUR)];
        base64data += g_codes[((byte2 & 0xF) << BIT_TWO) | (byte3 >> BIT_SIX)];
        base64data += g_codes[byte3 & 0x3F];
    }
    // Handle the case where there is one element left
    if (srcLen % LEN_THREE == 1) {
        unsigned char byte1 = static_cast<unsigned char>(originalData[i]);
        base64data += g_codes[byte1 >> BIT_TWO];
        base64data += g_codes[(byte1 & 0x3) << BIT_FOUR];
        base64data += '=';
        base64data += '=';
    } else {
        unsigned char byte1 = static_cast<unsigned char>(originalData[i]);
        unsigned char byte2 = static_cast<unsigned char>(originalData[i + BIT_ONE]);
        base64data += g_codes[byte1 >> BIT_TWO];
        base64data += g_codes[((byte1 & 0x3) << BIT_FOUR) | (byte2 >> BIT_FOUR)];
        base64data += g_codes[(byte2 & 0xF) << BIT_TWO];
        base64data += '=';
    }
    dstData = base64data;
    APP_LOGD("end");
    return true;
}
#endif

bool BundleResourceImageInfo::ConvertToBase64(
    const std::unique_ptr<uint8_t[]> originalData, const size_t length, std::string &imageInfo)
{
    APP_LOGD("start convert to base 64");
    if ((originalData == nullptr) || (length == 0)) {
        APP_LOGE("originalData is nullptr or length is 0");
        return false;
    }
    std::string base64data = IMAGE_HEADER_INFO;
    size_t i = 0;
    // encode in groups of every 3 bytes
    for (i = 0; i < length - LEN_THREE; i += LEN_THREE) {
        base64data += g_codes[originalData[i] >> BIT_TWO];
        base64data += g_codes[((originalData[i] & 0x3) << BIT_FOUR) | (originalData[i + BIT_ONE] >> BIT_FOUR)];
        base64data += g_codes[((originalData[i + BIT_ONE] & 0xF) << BIT_TWO) | (originalData[i + BIT_TWO] >> BIT_SIX)];
        base64data += g_codes[originalData[i + BIT_TWO] & 0x3F];
    }
    // Handle the case where there is one element left
    if (length % LEN_THREE == 1) {
        base64data += g_codes[originalData[i] >> BIT_TWO];
        base64data += g_codes[(originalData[i] & 0x3) << BIT_FOUR];
        base64data += '=';
        base64data += '=';
    } else {
        base64data += g_codes[originalData[i] >> BIT_TWO];
        base64data += g_codes[((originalData[i] & 0x3) << BIT_FOUR) | (originalData[i + BIT_ONE] >> BIT_FOUR)];
        base64data += g_codes[(originalData[i + BIT_ONE] & 0xF) << BIT_TWO];
        base64data += '=';
    }
    imageInfo = base64data;
    APP_LOGD("end");
    return true;
}
} // AppExecFwk
} // OHOS
