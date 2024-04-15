/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
#include "distributed_device_profile_client.h"
#endif

namespace OHOS {
#ifdef BUNDLE_FRAMEWORK_FREE_INSTALL
namespace DistributedDeviceProfile {
int32_t DistributedDeviceProfileClient::PutAccessControlProfile(const AccessControlProfile& accessControlProfile)
{
    return 0;
}

int32_t DistributedDeviceProfileClient::UpdateAccessControlProfile(const AccessControlProfile& accessControlProfile)
{
    return 0;
}

int32_t DistributedDeviceProfileClient::GetTrustDeviceProfile(const std::string& deviceId,
    TrustDeviceProfile& trustDeviceProfile)
{
    return 0;
}

int32_t DistributedDeviceProfileClient::GetAllTrustDeviceProfile(std::vector<TrustDeviceProfile>& trustDeviceProfiles)
{
    return 0;
}

int32_t DistributedDeviceProfileClient::GetAccessControlProfile(std::map<std::string, std::string> params,
    std::vector<AccessControlProfile>& accessControlProfiles)
{
    return 0;
}

int32_t DistributedDeviceProfileClient::GetAllAccessControlProfile(
    std::vector<AccessControlProfile>& accessControlProfiles)
{
    return 0;
}

int32_t DistributedDeviceProfileClient::DeleteAccessControlProfile(int32_t accessControlId)
{
    return 0;
}

int32_t DistributedDeviceProfileClient::PutServiceProfile(const ServiceProfile& serviceProfile)
{
    return 0;
}

int32_t DistributedDeviceProfileClient::PutServiceProfileBatch(const std::vector<ServiceProfile>& serviceProfiles)
{
    return 0;
}

int32_t DistributedDeviceProfileClient::PutCharacteristicProfile(const CharacteristicProfile& characteristicProfile)
{
    return 0;
}

int32_t DistributedDeviceProfileClient::PutCharacteristicProfileBatch(
    const std::vector<CharacteristicProfile>& characteristicProfiles)
{
    return 0;
}

int32_t DistributedDeviceProfileClient::GetDeviceProfile(const std::string& deviceId, DeviceProfile& deviceProfile)
{
    if (deviceId != "") {
        return 0;
    }
    return -1;
}

int32_t DistributedDeviceProfileClient::GetServiceProfile(const std::string& deviceId, const std::string& serviceName,
    ServiceProfile& serviceProfile)
{
    return 0;
}

int32_t DistributedDeviceProfileClient::GetCharacteristicProfile(const std::string& deviceId,
    const std::string& serviceName, const std::string& characteristicId, CharacteristicProfile& characteristicProfile)
{
    return 0;
}

int32_t DistributedDeviceProfileClient::DeleteServiceProfile(const std::string& deviceId,
    const std::string& serviceName)
{
    return 0;
}

int32_t DistributedDeviceProfileClient::DeleteCharacteristicProfile(const std::string& deviceId,
    const std::string& serviceName, const std::string& characteristicKey)
{
    return 0;
}

int32_t DistributedDeviceProfileClient::SubscribeDeviceProfile(const SubscribeInfo& subscribeInfo)
{
    return 0;
}

int32_t DistributedDeviceProfileClient::UnSubscribeDeviceProfile(const SubscribeInfo& subscribeInfo)
{
    return 0;
}
}
#endif
}