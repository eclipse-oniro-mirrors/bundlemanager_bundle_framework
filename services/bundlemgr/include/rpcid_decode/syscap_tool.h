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

#ifndef _SYSCAP_TOOL_H
#define _SYSCAP_TOOL_H

#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cplusplus */
#endif /* __cplusplus */

const int32_t SINGLE_FEAT_LENGTH = 32 * 8;
const int32_t SINGLE_SYSCAP_LENGTH = SINGLE_FEAT_LENGTH + 17; // 17, size of prefix "SystemCapability."

/**
 * @brief parse rpcid stream, get the syscap info.
 * @param contextBuffer Indicates the buffer of rpcid stream.
 * @param bufferLen Indicates the length of rpcid stream buffer.
 * @param syscapSetBuf Indicates the arrays of syscap string prased from rpcid.sc,
 * after useing, need to free if through FreeDecodeBuffer().
 * @param syscapSetLength Indicates the length of syscapSetBuf, the length of single syscap is SINGLE_SYSCAP_LENGTH.
 * @return Returns 0 if prase successfully; returns -1 otherwise.
 */
int32_t RPCIDStreamDecodeToBuffer(
    char *contextBuffer, uint32_t bufferLen, char **syscapSetBuf, uint32_t *syscapSetLength);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* _SYSCAP_TOOL_H */