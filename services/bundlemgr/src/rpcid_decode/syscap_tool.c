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

#include "syscap_tool.h"

#include <arpa/inet.h>
#include <securec.h>

#include "hilog/log_c.h"

const int32_t OK = 0;
const int32_t ERROR = -1;
const int32_t API_VERSION_TYPE = 1;
const int32_t APP_SYSCAP_TYPE = 2;
const int32_t SYSCAP_PREFIX_NAME_LEN = 18;
const char SYSCAP_PREFIX_NAME[] = "SystemCapability.";

typedef struct RequiredProductCompatibilityIDHead {
    uint16_t apiVersion : 15;
    uint16_t apiVersionType : 1;
} RPCIDHead;

int32_t RPCIDStreamDecodeToBuffer(
    char *contextBuffer, uint32_t bufferLen, char **syscapSetBuf, uint32_t *syscapSetLength)
{
    char *contextBufferTail = NULL;
    char *syscapBuf = NULL;
    uint32_t syscapBufLen;
    uint16_t sysCaptype;
    uint16_t sysCapLength;
    RPCIDHead *headPtr = NULL;
    char *sysCapArrayPtr = NULL;
    if (syscapSetBuf == NULL) {
        HILOG_ERROR(LOG_CORE, "syscapSetBuf is NULL\n");
        return ERROR;
    }
    *syscapSetBuf = NULL;
    if (syscapSetLength == NULL) {
        HILOG_ERROR(LOG_CORE, "syscapSetLength is NULL\n");
        return ERROR;
    }
    *syscapSetLength = 0;
    if (contextBuffer == NULL) {
        HILOG_ERROR(LOG_CORE, "input buffer is NULL\n");
        return ERROR;
    }

    contextBufferTail = contextBuffer + bufferLen;
    sysCapArrayPtr = contextBuffer + sizeof(RPCIDHead) + APP_SYSCAP_TYPE * sizeof(uint16_t);
    if (contextBufferTail <= sysCapArrayPtr) {
        HILOG_ERROR(LOG_CORE, "format error:sysCapArray head over to buffer\n");
        return ERROR;
    }

    headPtr = (RPCIDHead *)contextBuffer;
    if (headPtr->apiVersionType != API_VERSION_TYPE) {
        HILOG_ERROR(LOG_CORE, "format error:apiVersionType is invaild\n");
        return ERROR;
    }

    sysCaptype = ntohs(*(uint16_t *)(sysCapArrayPtr - APP_SYSCAP_TYPE * sizeof(uint16_t)));
    if (sysCaptype != APP_SYSCAP_TYPE) {
        HILOG_ERROR(LOG_CORE, "format error:sysCaptype is invaild\n");
        return ERROR;
    }

    sysCapLength = ntohs(*(uint16_t *)(sysCapArrayPtr - sizeof(uint16_t)));
    if (sysCapLength < 0) {
        HILOG_ERROR(LOG_CORE, "format error:sysCapLength is invalid\n");
        return ERROR;
    }
    if (contextBufferTail < sysCapArrayPtr + sysCapLength) {
        HILOG_ERROR(LOG_CORE, "format error:sysCapArray tail over to buffer\n");
        return ERROR;
    }

    if ((sysCapLength % SINGLE_FEAT_LENGTH) != 0) {
        HILOG_ERROR(LOG_CORE, "format error:sysCapLength is invalid\n");
        return ERROR;
    }

    syscapBufLen = sysCapLength / SINGLE_FEAT_LENGTH * SINGLE_SYSCAP_LENGTH;
    syscapBuf = (char *)malloc(syscapBufLen);
    if (syscapBuf == NULL) {
        HILOG_ERROR(LOG_CORE, "malloc syscapBuf failed, size = %u, errno = %{public}d\n", syscapBufLen, errno);
        return ERROR;
    }

    (void)memset_s(syscapBuf, syscapBufLen, 0, syscapBufLen);
    char *bufferPtr = syscapBuf;
    for (int32_t i = 0; i < ((int32_t)sysCapLength / SINGLE_FEAT_LENGTH); i++) {
        if (*(sysCapArrayPtr + (i + 1) * SINGLE_FEAT_LENGTH - 1) != '\0') {
            HILOG_ERROR(LOG_CORE, "prase failed, format is invaild, in line %{public}d\n", __LINE__);
            (void)free(syscapBuf);
            return ERROR;
        }

        errno_t ret = memcpy_s(bufferPtr, SINGLE_SYSCAP_LENGTH, SYSCAP_PREFIX_NAME, SYSCAP_PREFIX_NAME_LEN);
        if (ret != EOK) {
            HILOG_ERROR(LOG_CORE, "context of \"os\" array is invaild\n");
            (void)free(syscapBuf);
            return ERROR;
        }

        ret = strncat_s(bufferPtr, SINGLE_SYSCAP_LENGTH, sysCapArrayPtr + i * SINGLE_FEAT_LENGTH, SINGLE_FEAT_LENGTH);
        if (ret != EOK) {
            HILOG_ERROR(LOG_CORE, "strncat_s failed, (%{public}s, %{public}d, %{public}s, %{public}d)\n",
                bufferPtr, SINGLE_SYSCAP_LENGTH, sysCapArrayPtr + i * SINGLE_FEAT_LENGTH, SINGLE_FEAT_LENGTH);
            (void)free(syscapBuf);
            return ERROR;
        }

        bufferPtr += SINGLE_SYSCAP_LENGTH;
    }

    *syscapSetBuf = syscapBuf;
    *syscapSetLength = syscapBufLen;
    return OK;
}