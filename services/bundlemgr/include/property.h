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

#ifndef FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PROPERTY_H
#define FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PROPERTY_H

namespace OHOS {
namespace AppExecFwk {
#define BMS_DEFINE_PROPERTY_MEMBER_FILED(funcName, memberFiled, attribute, type)      \
    void Set##funcName(const type& defaultValue)                                      \
    {                                                                                 \
        memberFiled->attribute = defaultValue;                                        \
    }                                                                                 \
    type Get##funcName() const                                                        \
    {                                                                                 \
        return memberFiled->attribute;                                                \
    }

#define BMS_DEFINE_PROPERTY_MEMBER_FILED_SET(funcName, memberFiled, attribute, type)  \
    void Set##funcName(const type& defaultValue)                                      \
    {                                                                                 \
        memberFiled->attribute = defaultValue;                                        \
    }

#define BMS_DEFINE_PROPERTY_MEMBER_FILED_GET(funcName, memberFiled, attribute, type)  \
    type Get##funcName() const                                                        \
    {                                                                                 \
        return memberFiled->attribute;                                                \
    }

#define BMS_DEFINE_PROPERTY(funcName, attribute, type)                                \
    void Set##funcName(const type& defaultValue)                                      \
    {                                                                                 \
        attribute = defaultValue;                                                     \
    }                                                                                 \
    type Get##funcName() const                                                        \
    {                                                                                 \
        return attribute;                                                             \
    }

#define BMS_DEFINE_PROPERTY_SET(funcName, attribute, type)                            \
    void Set##funcName(const type& defaultValue)                                      \
    {                                                                                 \
        attribute = defaultValue;                                                     \
    }

#define BMS_DEFINE_PROPERTY_GET(funcName, attribute, type)                            \
    type Get##funcName() const                                                        \
    {                                                                                 \
        return attribute;                                                             \
    }
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // FOUNDATION_APPEXECFWK_SERVICES_BUNDLEMGR_INCLUDE_PROPERTY_H