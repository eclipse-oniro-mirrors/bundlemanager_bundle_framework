/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "bundle_mgr_proxy.h"

#include <numeric>
#include <set>
#include <unistd.h>

#include "ipc_types.h"
#include "parcel.h"
#include "string_ex.h"
#include "parcel_macro.h"

#include "app_log_wrapper.h"
#include "app_log_tag_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_constants.h"
#ifdef BUNDLE_FRAMEWORK_DEFAULT_APP
#include "default_app_proxy.h"
#endif
#include "hitrace_meter.h"
#include "json_util.h"
#ifdef BUNDLE_FRAMEWORK_QUICK_FIX
#include "quick_fix_manager_proxy.h"
#endif
#include "securec.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr size_t MAX_PARCEL_CAPACITY = 1024 * 1024 * 1024; // allow max 1GB resource size
constexpr size_t MAX_IPC_REWDATA_SIZE = 120 * 1024 * 1024; // max ipc size 120MB
const std::unordered_map<int32_t, int32_t> IPC_ERR_MAP = {
    {29201, ERR_APPEXECFWK_IPC_REPLY_ERROR},
    {29202, ERR_APPEXECFWK_IPC_REMOTE_FROZEN_ERROR},
    {29189, ERR_APPEXECFWK_IPC_REMOTE_DEAD_ERROR}
};

bool GetData(void *&buffer, size_t size, const void *data)
{
    if (data == nullptr) {
        APP_LOGE("GetData failed due to null data");
        return false;
    }
    if (size == 0 || size > MAX_PARCEL_CAPACITY) {
        APP_LOGE("GetData failed due to zero size");
        return false;
    }
    buffer = malloc(size);
    if (buffer == nullptr) {
        APP_LOGE("GetData failed due to malloc buffer failed");
        return false;
    }
    if (memcpy_s(buffer, size, data, size) != EOK) {
        free(buffer);
        APP_LOGE("GetData failed due to memcpy_s failed");
        return false;
    }
    return true;
}
} // namespace

BundleMgrProxy::BundleMgrProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<IBundleMgr>(impl)
{
    APP_LOGD("create bundle mgr proxy instance");
}

BundleMgrProxy::~BundleMgrProxy()
{
    APP_LOGD("destroy create bundle mgr proxy instance");
}

bool BundleMgrProxy::GetApplicationInfo(
    const std::string &appName, const ApplicationFlag flag, const int userId, ApplicationInfo &appInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    LOG_D(BMS_TAG_QUERY, "begin to GetApplicationInfo of %{public}s", appName.c_str());
    if (appName.empty()) {
        LOG_E(BMS_TAG_QUERY, "fail to GetApplicationInfo due to params empty");
        return false;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "fail to GetApplicationInfo due to write descriptor fail");
        return false;
    }
    if (!data.WriteString(appName)) {
        LOG_E(BMS_TAG_QUERY, "fail to GetApplicationInfo due to write appName fail");
        return false;
    }
    if (!data.WriteInt32(static_cast<int>(flag))) {
        LOG_E(BMS_TAG_QUERY, "fail to GetApplicationInfo due to write flag fail");
        return false;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_QUERY, "fail to GetApplicationInfo due to write userId fail");
        return false;
    }

    if (!GetParcelableInfo<ApplicationInfo>(BundleMgrInterfaceCode::GET_APPLICATION_INFO, data, appInfo)) {
        LOG_NOFUNC_E(BMS_TAG_QUERY, "fail to GetApplicationInfo from server");
        return false;
    }
    return true;
}

bool BundleMgrProxy::GetApplicationInfo(
    const std::string &appName, int32_t flags, int32_t userId, ApplicationInfo &appInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    LOG_D(BMS_TAG_QUERY, "begin to GetApplicationInfo of %{public}s", appName.c_str());
    if (appName.empty()) {
        LOG_E(BMS_TAG_QUERY, "fail to GetApplicationInfo due to params empty");
        return false;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "fail to GetApplicationInfo due to write MessageParcel fail");
        return false;
    }
    if (!data.WriteString(appName)) {
        LOG_E(BMS_TAG_QUERY, "fail to GetApplicationInfo due to write appName fail");
        return false;
    }
    if (!data.WriteInt32(flags)) {
        LOG_E(BMS_TAG_QUERY, "fail to GetApplicationInfo due to write flag fail");
        return false;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_QUERY, "fail to GetApplicationInfo due to write userId fail");
        return false;
    }

    if (!GetParcelableInfo<ApplicationInfo>(
        BundleMgrInterfaceCode::GET_APPLICATION_INFO_WITH_INT_FLAGS, data, appInfo)) {
        LOG_NOFUNC_E(BMS_TAG_QUERY, "fail to GetApplicationInfo from server");
        return false;
    }
    return true;
}

ErrCode BundleMgrProxy::GetApplicationInfoV9(
    const std::string &appName, int32_t flags, int32_t userId, ApplicationInfo &appInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    LOG_D(BMS_TAG_QUERY, "begin to GetApplicationInfoV9 of %{public}s", appName.c_str());
    if (appName.empty()) {
        LOG_E(BMS_TAG_QUERY, "fail to GetApplicationInfoV9 due to params empty");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "fail to GetApplicationInfoV9 due to write MessageParcel fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(appName)) {
        LOG_E(BMS_TAG_QUERY, "fail to GetApplicationInfoV9 due to write appName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(flags)) {
        LOG_E(BMS_TAG_QUERY, "fail to GetApplicationInfoV9 due to write flag fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_QUERY, "fail to GetApplicationInfoV9 due to write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    auto res = GetParcelableInfoWithErrCode<ApplicationInfo>(
        BundleMgrInterfaceCode::GET_APPLICATION_INFO_WITH_INT_FLAGS_V9, data, appInfo);
    if (res != ERR_OK) {
        LOG_NOFUNC_E(BMS_TAG_QUERY, "GetApplicationInfoV9 failed: %{public}d", res);
        return res;
    }
    return ERR_OK;
}

bool BundleMgrProxy::GetApplicationInfos(
    const ApplicationFlag flag, int userId, std::vector<ApplicationInfo> &appInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    LOG_D(BMS_TAG_QUERY, "begin to get GetApplicationInfos of specific userId id %{private}d", userId);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "fail to GetApplicationInfo due to write descriptor fail");
        return false;
    }
    if (!data.WriteInt32(static_cast<int>(flag))) {
        LOG_E(BMS_TAG_QUERY, "fail to GetApplicationInfo due to write flag fail");
        return false;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_QUERY, "fail to GetApplicationInfos due to write userId error");
        return false;
    }

    if (!GetVectorFromParcelIntelligent<ApplicationInfo>(
        BundleMgrInterfaceCode::GET_APPLICATION_INFOS, data, appInfos)) {
        LOG_E(BMS_TAG_QUERY, "fail to GetApplicationInfos from server");
        return false;
    }
    return true;
}

bool BundleMgrProxy::GetApplicationInfos(
    int32_t flags, int32_t userId, std::vector<ApplicationInfo> &appInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    LOG_D(BMS_TAG_QUERY, "begin to get GetApplicationInfos of specific userId id %{private}d", userId);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "fail to GetApplicationInfo due to write MessageParcel fail");
        return false;
    }
    if (!data.WriteInt32(flags)) {
        LOG_E(BMS_TAG_QUERY, "fail to GetApplicationInfo due to write flag fail");
        return false;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_QUERY, "fail to GetApplicationInfos due to write userId error");
        return false;
    }
    if (!GetVectorFromParcelIntelligent<ApplicationInfo>(
        BundleMgrInterfaceCode::GET_APPLICATION_INFOS_WITH_INT_FLAGS, data, appInfos)) {
        LOG_E(BMS_TAG_QUERY, "failed to GetApplicationInfos from server");
        return false;
    }
    return true;
}

ErrCode BundleMgrProxy::GetApplicationInfosV9(
    int32_t flags, int32_t userId, std::vector<ApplicationInfo> &appInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    LOG_D(BMS_TAG_QUERY, "begin to get GetApplicationInfosV9 of specific userId id %{private}d", userId);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "fail to GetApplicationInfosV9 due to write MessageParcel fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(flags)) {
        LOG_E(BMS_TAG_QUERY, "fail to GetApplicationInfosV9 due to write flag fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_QUERY, "fail to GetApplicationInfosV9 due to write userId error");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetVectorFromParcelIntelligentWithErrCode<ApplicationInfo>(
        BundleMgrInterfaceCode::GET_APPLICATION_INFOS_WITH_INT_FLAGS_V9, data, appInfos);
}

bool BundleMgrProxy::GetBundleInfo(
    const std::string &bundleName, const BundleFlag flag, BundleInfo &bundleInfo, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    LOG_D(BMS_TAG_QUERY, "begin to get bundle info of %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        LOG_E(BMS_TAG_QUERY, "fail to GetBundleInfo due to params empty");
        return false;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "fail to GetBundleInfo due to write InterfaceToken fail");
        return false;
    }
    if (!data.WriteString(bundleName)) {
        LOG_E(BMS_TAG_QUERY, "fail to GetBundleInfo due to write bundleName fail");
        return false;
    }
    if (!data.WriteInt32(static_cast<int>(flag))) {
        LOG_E(BMS_TAG_QUERY, "fail to GetBundleInfo due to write flag fail");
        return false;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_QUERY, "fail to GetBundleInfo due to write userId fail");
        return false;
    }

    return GetParcelInfoIntelligent<BundleInfo>(
        BundleMgrInterfaceCode::GET_BUNDLE_INFO, data, bundleInfo) == ERR_OK;
}

bool BundleMgrProxy::GetBundleInfo(
    const std::string &bundleName, int32_t flags, BundleInfo &bundleInfo, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    LOG_D(BMS_TAG_QUERY, "begin to get bundle info of %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        LOG_E(BMS_TAG_QUERY, "fail to GetBundleInfo due to params empty");
        return false;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "fail to GetBundleInfo due to write InterfaceToken fail");
        return false;
    }
    if (!data.WriteString(bundleName)) {
        LOG_E(BMS_TAG_QUERY, "fail to GetBundleInfo due to write bundleName fail");
        return false;
    }
    if (!data.WriteInt32(flags)) {
        LOG_E(BMS_TAG_QUERY, "fail to GetBundleInfo due to write flag fail");
        return false;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_QUERY, "fail to GetBundleInfo due to write userId fail");
        return false;
    }
    if (GetParcelInfoIntelligent<BundleInfo>(
        BundleMgrInterfaceCode::GET_BUNDLE_INFO_WITH_INT_FLAGS, data, bundleInfo)!= ERR_OK) {
        LOG_E(BMS_TAG_QUERY, "fail to GetBundleInfo from server");
        return false;
    }
    return true;
}

ErrCode BundleMgrProxy::GetBundleInfoV9(
    const std::string &bundleName, int32_t flags, BundleInfo &bundleInfo, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    LOG_D(BMS_TAG_QUERY, "begin to get bundle info of %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        LOG_NOFUNC_E(BMS_TAG_QUERY, "GetBundleInfoV9 fail params empty");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_NOFUNC_E(BMS_TAG_QUERY, "GetBundleInfoV9 write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        LOG_NOFUNC_E(BMS_TAG_QUERY, "GetBundleInfoV9 write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(flags)) {
        LOG_NOFUNC_E(BMS_TAG_QUERY, "GetBundleInfoV9 write flag fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_NOFUNC_E(BMS_TAG_QUERY, "GetBundleInfoV9 write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    auto res = GetParcelInfoIntelligent<BundleInfo>(
        BundleMgrInterfaceCode::GET_BUNDLE_INFO_WITH_INT_FLAGS_V9, data, bundleInfo);
    if (res != ERR_OK) {
        LOG_NOFUNC_E(BMS_TAG_QUERY, "GetBundleInfoV9 fail error: %{public}d", res);
        return res;
    }
    return ERR_OK;
}

ErrCode BundleMgrProxy::BatchGetBundleInfo(const std::vector<Want> &wants, int32_t flags,
    std::vector<BundleInfo> &bundleInfos, int32_t userId)
{
    std::vector<std::string> bundleNames;
    for (size_t i = 0; i < wants.size(); i++) {
        bundleNames.push_back(wants[i].GetElement().GetBundleName());
    }
    return BatchGetBundleInfo(bundleNames, flags, bundleInfos, userId);
}

ErrCode BundleMgrProxy::BatchGetBundleInfo(const std::vector<std::string> &bundleNames, int32_t flags,
    std::vector<BundleInfo> &bundleInfos, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to batch get bundle info, bundle name count=%{public}u",
        static_cast<unsigned int>(bundleNames.size()));
    if (bundleNames.empty()) {
        APP_LOGE("fail to BatchGetBundleInfo due to params empty");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    for (size_t i = 0; i < bundleNames.size(); i++) {
        APP_LOGD("begin to get bundle info of %{public}s", bundleNames[i].c_str());
        if (bundleNames[i].empty()) {
            APP_LOGE("fail to BatchGetBundleInfo due to bundleName %{public}zu empty", i);
            return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
        }
    }
    std::set<std::string> bundleNameSet(bundleNames.begin(), bundleNames.end());
    std::vector<std::string> newBundleNames(bundleNameSet.begin(), bundleNameSet.end());
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to BatchGetBundleInfo due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(newBundleNames.size())) {
        APP_LOGE("fail to BatchGetBundleInfo due to write bundle name count fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    for (size_t i = 0; i < newBundleNames.size(); i++) {
        if (!data.WriteString(newBundleNames[i])) {
            APP_LOGE("write bundleName %{public}zu failed", i);
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    if (!data.WriteInt32(flags)) {
        APP_LOGE("fail to BatchGetBundleInfo due to write flag fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to BatchGetBundleInfo due to write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetVectorFromParcelIntelligentWithErrCode<BundleInfo>(
        BundleMgrInterfaceCode::BATCH_GET_BUNDLE_INFO, data, bundleInfos);
}

ErrCode BundleMgrProxy::GetBundleInfoForSelf(int32_t flags, BundleInfo &bundleInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    LOG_D(BMS_TAG_QUERY, "begin to get bundle info for self");

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "fail to GetBundleInfoForSelf due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(flags)) {
        LOG_E(BMS_TAG_QUERY, "fail to GetBundleInfoForSelf due to write flag fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    auto res = GetParcelableInfoWithErrCode<BundleInfo>(
        BundleMgrInterfaceCode::GET_BUNDLE_INFO_FOR_SELF, data, bundleInfo);
    if (res != ERR_OK) {
        LOG_NOFUNC_E(BMS_TAG_QUERY, "GetBundleInfoForSelf failed err:%{public}d", res);
        return res;
    }
    return ERR_OK;
}

ErrCode BundleMgrProxy::GetDependentBundleInfo(const std::string &bundleName, BundleInfo &bundleInfo,
    GetDependentBundleInfoFlag flag)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to get dependent bundle info");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetDependentBundleInfo due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to GetDependentBundleInfo due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(flag))) {
        APP_LOGE("fail to GetDependentBundleInfo due to write flag fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto res = GetParcelableInfoWithErrCode<BundleInfo>(
        BundleMgrInterfaceCode::GET_DEPENDENT_BUNDLE_INFO, data, bundleInfo);
    if (res != ERR_OK) {
        APP_LOGE("fail to GetDependentBundleInfo from server, error code: %{public}d", res);
        return res;
    }
    return ERR_OK;
}

ErrCode BundleMgrProxy::GetBundlePackInfo(
    const std::string &bundleName, const BundlePackFlag flag, BundlePackInfo &bundlePackInfo, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to get bundle info of %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        APP_LOGE("fail to GetBundlePackInfo due to params empty");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetBundlePackInfo due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to GetBundlePackInfo due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(static_cast<int>(flag))) {
        APP_LOGE("fail to GetBundlePackInfo due to write flag fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to GetBundlePackInfo due to write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return GetParcelableInfoWithErrCode<BundlePackInfo>(BundleMgrInterfaceCode::GET_BUNDLE_PACK_INFO, data,
        bundlePackInfo);
}

ErrCode BundleMgrProxy::GetBundlePackInfo(
    const std::string &bundleName, int32_t flags, BundlePackInfo &bundlePackInfo, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to get bundle info of %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        APP_LOGE("fail to GetBundlePackInfo due to params empty");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetBundlePackInfo due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to GetBundlePackInfo due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(flags)) {
        APP_LOGE("fail to GetBundlePackInfo due to write flag fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to GetBundlePackInfo due to write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return GetParcelableInfoWithErrCode<BundlePackInfo>(
        BundleMgrInterfaceCode::GET_BUNDLE_PACK_INFO_WITH_INT_FLAGS, data, bundlePackInfo);
}

bool BundleMgrProxy::GetBundleInfos(
    const BundleFlag flag, std::vector<BundleInfo> &bundleInfos, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    LOG_D(BMS_TAG_QUERY, "begin to get bundle infos");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "fail to GetBundleInfos due to write InterfaceToken fail");
        return false;
    }
    if (!data.WriteInt32(static_cast<int>(flag))) {
        LOG_E(BMS_TAG_QUERY, "fail to GetBundleInfos due to write flag fail");
        return false;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_QUERY, "fail to GetBundleInfo due to write userId fail");
        return false;
    }
    if (!GetVectorFromParcelIntelligent<BundleInfo>(
        BundleMgrInterfaceCode::GET_BUNDLE_INFOS, data, bundleInfos)) {
        LOG_E(BMS_TAG_QUERY, "fail to GetBundleInfos from server");
        return false;
    }
    return true;
}

bool BundleMgrProxy::GetBundleInfos(
    int32_t flags, std::vector<BundleInfo> &bundleInfos, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    LOG_D(BMS_TAG_QUERY, "begin to get bundle infos");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "fail to GetBundleInfos due to write InterfaceToken fail");
        return false;
    }
    if (!data.WriteInt32(flags)) {
        LOG_E(BMS_TAG_QUERY, "fail to GetBundleInfos due to write flag fail");
        return false;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_QUERY, "fail to GetBundleInfo due to write userId fail");
        return false;
    }
    if (!GetVectorFromParcelIntelligent<BundleInfo>(
        BundleMgrInterfaceCode::GET_BUNDLE_INFOS_WITH_INT_FLAGS, data, bundleInfos)) {
        LOG_E(BMS_TAG_QUERY, "fail to GetBundleInfos from server");
        return false;
    }
    return true;
}

ErrCode BundleMgrProxy::GetBundleInfosV9(int32_t flags, std::vector<BundleInfo> &bundleInfos, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    LOG_NOFUNC_I(BMS_TAG_QUERY, "begin to get bundleinfos");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "fail to GetBundleInfosV9 due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(flags)) {
        LOG_E(BMS_TAG_QUERY, "fail to GetBundleInfosV9 due to write flag fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_QUERY, "fail to GetBundleInfosV9 due to write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    LOG_NOFUNC_I(BMS_TAG_QUERY, "get bundleinfos end");
    return GetVectorFromParcelIntelligentWithErrCode<BundleInfo>(
        BundleMgrInterfaceCode::GET_BUNDLE_INFOS_WITH_INT_FLAGS_V9, data, bundleInfos);
}

int BundleMgrProxy::GetUidByBundleName(const std::string &bundleName, const int userId)
{
    return GetUidByBundleName(bundleName, userId, 0);
}

int32_t BundleMgrProxy::GetUidByBundleName(const std::string &bundleName, const int32_t userId, int32_t appIndex)
{
    if (bundleName.empty()) {
        APP_LOGE("failed to GetUidByBundleName due to bundleName empty");
        return Constants::INVALID_UID;
    }
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to get uid of %{public}s, userId : %{public}d, appIndex : %{public}d", bundleName.c_str(),
        userId, appIndex);

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("failed to GetUidByBundleName due to write InterfaceToken fail");
        return Constants::INVALID_UID;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("failed to GetUidByBundleName due to write bundleName fail");
        return Constants::INVALID_UID;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("failed to GetUidByBundleName due to write uid fail");
        return Constants::INVALID_UID;
    }
    if (!data.WriteInt32(appIndex)) {
        APP_LOGE("failed to GetUidByBundleName due to write uid fail");
        return Constants::INVALID_UID;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_UID_BY_BUNDLE_NAME, data, reply)) {
        APP_LOGE("failed to GetUidByBundleName from server");
        return Constants::INVALID_UID;
    }
    int32_t uid = reply.ReadInt32();
    APP_LOGD("uid is %{public}d", uid);
    return uid;
}

int BundleMgrProxy::GetUidByDebugBundleName(const std::string &bundleName, const int userId)
{
    if (bundleName.empty()) {
        APP_LOGE("failed to GetUidByBundleName due to bundleName empty");
        return Constants::INVALID_UID;
    }
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to get uid of %{public}s, userId : %{public}d", bundleName.c_str(), userId);

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("failed to GetUidByBundleName due to write InterfaceToken fail");
        return Constants::INVALID_UID;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("failed to GetUidByBundleName due to write bundleName fail");
        return Constants::INVALID_UID;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("failed to GetUidByBundleName due to write uid fail");
        return Constants::INVALID_UID;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_UID_BY_DEBUG_BUNDLE_NAME, data, reply)) {
        APP_LOGE("failed to GetUidByBundleName from server");
        return Constants::INVALID_UID;
    }
    int32_t uid = reply.ReadInt32();
    APP_LOGD("uid is %{public}d", uid);
    return uid;
}

std::string BundleMgrProxy::GetAppIdByBundleName(const std::string &bundleName, const int userId)
{
    if (bundleName.empty()) {
        APP_LOGE("failed to GetAppIdByBundleName due to bundleName empty");
        return Constants::EMPTY_STRING;
    }
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to get appId of %{public}s", bundleName.c_str());

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("failed to GetAppIdByBundleName due to write InterfaceToken fail");
        return Constants::EMPTY_STRING;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("failed to GetAppIdByBundleName due to write bundleName fail");
        return Constants::EMPTY_STRING;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("failed to GetAppIdByBundleName due to write uid fail");
        return Constants::EMPTY_STRING;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_APPID_BY_BUNDLE_NAME, data, reply)) {
        APP_LOGE("failed to GetAppIdByBundleName from server");
        return Constants::EMPTY_STRING;
    }
    std::string appId = reply.ReadString();
    APP_LOGD("appId is %{private}s", appId.c_str());
    return appId;
}

bool BundleMgrProxy::GetBundleNameForUid(const int uid, std::string &bundleName)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to GetBundleNameForUid of %{public}d", uid);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetBundleNameForUid due to write InterfaceToken fail");
        return false;
    }
    if (!data.WriteInt32(uid)) {
        APP_LOGE("fail to GetBundleNameForUid due to write uid fail");
        return false;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_BUNDLE_NAME_FOR_UID, data, reply)) {
        APP_LOGE("fail to GetBundleNameForUid from server");
        return false;
    }
    if (!reply.ReadBool()) {
        if (uid > Constants::BASE_APP_UID) {
            APP_LOGE("reply result false");
        }
        return false;
    }
    bundleName = reply.ReadString();
    return true;
}

bool BundleMgrProxy::GetBundlesForUid(const int uid, std::vector<std::string> &bundleNames)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to GetBundlesForUid of %{public}d", uid);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetBundlesForUid due to write InterfaceToken fail");
        return false;
    }
    if (!data.WriteInt32(uid)) {
        APP_LOGE("fail to GetBundlesForUid due to write uid fail");
        return false;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_BUNDLES_FOR_UID, data, reply)) {
        APP_LOGE("fail to GetBundlesForUid from server");
        return false;
    }
    if (!reply.ReadBool()) {
        APP_LOGD("reply result false");
        return false;
    }
    if (!reply.ReadStringVector(&bundleNames)) {
        APP_LOGE("fail to GetBundlesForUid from reply");
        return false;
    }
    return true;
}

ErrCode BundleMgrProxy::GetNameForUid(const int uid, std::string &name)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to GetNameForUid of %{public}d", uid);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetNameForUid due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(uid)) {
        APP_LOGE("fail to GetNameForUid due to write uid fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    ErrCode ret = SendTransactCmdWithLogErrCode(BundleMgrInterfaceCode::GET_NAME_FOR_UID, data, reply);
    if (ret != ERR_OK) {
        APP_LOGE("fail to GetNameForUid from server, %{public}d", ret);
        return ret;
    }
    ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        return ret;
    }
    name = reply.ReadString();
    return ERR_OK;
}

ErrCode BundleMgrProxy::GetNameAndIndexForUid(const int32_t uid, std::string &bundleName, int32_t &appIndex)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to GetNameAndIndexForUid of %{public}d", uid);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetNameAndIndexForUid due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(uid)) {
        APP_LOGE("fail to GetNameAndIndexForUid due to write uid fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendTransactCmdWithLog(BundleMgrInterfaceCode::GET_NAME_AND_APPINDEX_FOR_UID, data, reply)) {
        APP_LOGE("fail to GetNameAndIndexForUid from server");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        return ret;
    }
    bundleName = reply.ReadString();
    appIndex = reply.ReadInt32();
    return ERR_OK;
}

ErrCode BundleMgrProxy::GetSimpleAppInfoForUid(
    const std::vector<std::int32_t> &uids, std::vector<SimpleAppInfo> &simpleAppInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to GetSimpleAppInfoForUid list");
    if (uids.empty()) {
        APP_LOGE("failed to GetSimpleAppInfoForUid list due to uids empty");
        return ERR_APPEXECFWK_INVALID_UID;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetSimpleAppInfoForUid list due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32Vector(uids)) {
        APP_LOGE("write uids count failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return GetParcelableInfosWithErrCode<SimpleAppInfo>(
        BundleMgrInterfaceCode::GET_SIMPLE_APP_INFO_FOR_UID, data, simpleAppInfo);
}

bool BundleMgrProxy::GetBundleGids(const std::string &bundleName, std::vector<int> &gids)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to GetBundleGids of %{public}s", bundleName.c_str());
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetBundleGids due to write InterfaceToken fail");
        return false;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to GetBundleGids due to write bundleName fail");
        return false;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_BUNDLE_GIDS, data, reply)) {
        APP_LOGE("fail to GetBundleGids from server");
        return false;
    }
    if (!reply.ReadBool()) {
        APP_LOGE("reply result false");
        return false;
    }
    if (!reply.ReadInt32Vector(&gids)) {
        APP_LOGE("fail to GetBundleGids from reply");
        return false;
    }
    return true;
}

bool BundleMgrProxy::GetBundleGidsByUid(const std::string &bundleName, const int &uid, std::vector<int> &gids)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to GetBundleGidsByUid of %{public}s", bundleName.c_str());
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetBundleGidsByUid due to write InterfaceToken fail");
        return false;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to GetBundleGidsByUid due to write bundleName fail");
        return false;
    }
    if (!data.WriteInt32(uid)) {
        APP_LOGE("fail to GetBundleGidsByUid due to write uid fail");
        return false;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_BUNDLE_GIDS_BY_UID, data, reply)) {
        APP_LOGE("fail to GetBundleGidsByUid from server");
        return false;
    }
    if (!reply.ReadBool()) {
        APP_LOGE("reply result false");
        return false;
    }
    if (!reply.ReadInt32Vector(&gids)) {
        APP_LOGE("fail to GetBundleGidsByUid from reply");
        return false;
    }
    return true;
}

std::string BundleMgrProxy::GetAppType(const std::string &bundleName)
{
    if (bundleName.empty()) {
        APP_LOGE("failed to GetAppType due to bundleName empty");
        return Constants::EMPTY_STRING;
    }
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to GetAppType of %{public}s", bundleName.c_str());

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("failed to GetAppType due to write InterfaceToken fail");
        return Constants::EMPTY_STRING;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("failed to GetAppType due to write bundleName fail");
        return Constants::EMPTY_STRING;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_APP_TYPE, data, reply)) {
        APP_LOGE("failed to GetAppType from server");
        return Constants::EMPTY_STRING;
    }
    std::string appType = reply.ReadString();
    APP_LOGD("appType is %{public}s", appType.c_str());
    return appType;
}

bool BundleMgrProxy::CheckIsSystemAppByUid(const int uid)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to CheckIsSystemAppByUid of %{public}d", uid);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to CheckIsSystemAppByUid due to write InterfaceToken fail");
        return false;
    }
    if (!data.WriteInt32(uid)) {
        APP_LOGE("fail to CheckIsSystemAppByUid due to write uid fail");
        return false;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::CHECK_IS_SYSTEM_APP_BY_UID, data, reply)) {
        APP_LOGE("fail to CheckIsSystemAppByUid from server");
        return false;
    }
    return reply.ReadBool();
}

bool BundleMgrProxy::GetBundleInfosByMetaData(const std::string &metaData, std::vector<BundleInfo> &bundleInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to GetBundleInfosByMetaData of %{public}s", metaData.c_str());
    if (metaData.empty()) {
        APP_LOGE("fail to GetBundleInfosByMetaData due to params empty");
        return false;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetBundleInfosByMetaData due to write InterfaceToken fail");
        return false;
    }
    if (!data.WriteString(metaData)) {
        APP_LOGE("fail to GetBundleInfosByMetaData due to write metaData fail");
        return false;
    }

    if (!GetParcelableInfos<BundleInfo>(BundleMgrInterfaceCode::GET_BUNDLE_INFOS_BY_METADATA, data, bundleInfos)) {
        APP_LOGE("fail to GetBundleInfosByMetaData from server");
        return false;
    }
    return true;
}

bool BundleMgrProxy::QueryAbilityInfo(const Want &want, AbilityInfo &abilityInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "QueryAbilityInfo write MessageParcel fail");
        return false;
    }
    if (!data.WriteParcelable(&want)) {
        LOG_E(BMS_TAG_QUERY, "QueryAbilityInfo write want fail");
        return false;
    }

    if (!GetParcelableInfo<AbilityInfo>(BundleMgrInterfaceCode::QUERY_ABILITY_INFO, data, abilityInfo)) {
        LOG_E(BMS_TAG_QUERY, "QueryAbilityInfo from server fail");
        return false;
    }
    return true;
}

bool BundleMgrProxy::QueryAbilityInfo(const Want &want, int32_t flags, int32_t userId,
    AbilityInfo &abilityInfo, const sptr<IRemoteObject> &callBack)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "QueryAbilityInfo write MessageParcel fail");
        return false;
    }
    if (!data.WriteParcelable(&want)) {
        LOG_E(BMS_TAG_QUERY, "QueryAbilityInfo write want fail");
        return false;
    }

    if (!data.WriteInt32(flags)) {
        LOG_E(BMS_TAG_QUERY, "QueryAbilityInfo write flags fail");
        return false;
    }

    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_QUERY, "QueryAbilityInfo write userId fail");
        return false;
    }

    if (!data.WriteRemoteObject(callBack)) {
        LOG_E(BMS_TAG_QUERY, "callBack write parcel fail");
        return false;
    }

    if (!GetParcelableInfo<AbilityInfo>(
        BundleMgrInterfaceCode::QUERY_ABILITY_INFO_WITH_CALLBACK, data, abilityInfo)) {
        LOG_E(BMS_TAG_QUERY, "QueryAbilityInfo from server fail");
        return false;
    }
    return true;
}

bool BundleMgrProxy::SilentInstall(const Want &want, int32_t userId, const sptr<IRemoteObject> &callBack)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to silent install");

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to SilentInstall due to write token");
        return false;
    }
    if (!data.WriteParcelable(&want)) {
        APP_LOGE("fail to SilentInstall due to write want");
        return false;
    }

    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to SilentInstall due to write userId");
        return false;
    }

    if (!data.WriteRemoteObject(callBack)) {
        APP_LOGE("fail to SilentInstall due to write callBack");
        return false;
    }

    MessageParcel reply;
    return SendTransactCmd(BundleMgrInterfaceCode::SILENT_INSTALL, data, reply);
}

void BundleMgrProxy::UpgradeAtomicService(const Want &want, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to UpgradeAtomicService due to write descriptor");
        return;
    }
    if (!data.WriteParcelable(&want)) {
        APP_LOGE("fail to UpgradeAtomicService due to write want");
        return;
    }

    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to UpgradeAtomicService due to write userId");
        return;
    }
    return;
}

bool BundleMgrProxy::QueryAbilityInfo(const Want &want, int32_t flags, int32_t userId, AbilityInfo &abilityInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "QueryAbilityInfo mutiparam write MessageParcel fail");
        return false;
    }
    if (!data.WriteParcelable(&want)) {
        LOG_E(BMS_TAG_QUERY, "QueryAbilityInfo mutiparam write want fail");
        return false;
    }
    if (!data.WriteInt32(flags)) {
        LOG_E(BMS_TAG_QUERY, "QueryAbilityInfo mutiparam write flags fail");
        return false;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_QUERY, "QueryAbilityInfo mutiparam write userId fail");
        return false;
    }

    if (!GetParcelableInfo<AbilityInfo>(BundleMgrInterfaceCode::QUERY_ABILITY_INFO_MUTI_PARAM, data, abilityInfo)) {
        LOG_E(BMS_TAG_QUERY, "QueryAbilityInfo mutiparam from server fail");
        return false;
    }
    return true;
}

bool BundleMgrProxy::QueryAbilityInfos(const Want &want, std::vector<AbilityInfo> &abilityInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "QueryAbilityInfos write MessageParcel fail");
        return false;
    }
    if (!data.WriteParcelable(&want)) {
        LOG_E(BMS_TAG_QUERY, "QueryAbilityInfos write want fail");
        return false;
    }

    if (!GetParcelableInfos<AbilityInfo>(BundleMgrInterfaceCode::QUERY_ABILITY_INFOS, data, abilityInfos)) {
        LOG_E(BMS_TAG_QUERY, "QueryAbilityInfos from server fail");
        return false;
    }
    return true;
}

bool BundleMgrProxy::QueryAbilityInfos(
    const Want &want, int32_t flags, int32_t userId, std::vector<AbilityInfo> &abilityInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "QueryAbilityInfos mutiparam write MessageParcel fail");
        return false;
    }
    if (!data.WriteParcelable(&want)) {
        LOG_E(BMS_TAG_QUERY, "QueryAbilityInfos mutiparam write want fail");
        return false;
    }
    if (!data.WriteInt32(flags)) {
        LOG_E(BMS_TAG_QUERY, "QueryAbilityInfos mutiparam write flags fail");
        return false;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_QUERY, "QueryAbilityInfos mutiparam write userId fail");
        return false;
    }
    if (!GetVectorFromParcelIntelligent<AbilityInfo>(
        BundleMgrInterfaceCode::QUERY_ABILITY_INFOS_MUTI_PARAM, data, abilityInfos)) {
        LOG_E(BMS_TAG_QUERY, "QueryAbilityInfos mutiparam from server fail");
        return false;
    }
    return true;
}

ErrCode BundleMgrProxy::QueryAbilityInfosV9(
    const Want &want, int32_t flags, int32_t userId, std::vector<AbilityInfo> &abilityInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "write interfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        LOG_E(BMS_TAG_QUERY, "write want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(flags)) {
        LOG_E(BMS_TAG_QUERY, "write flags failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_QUERY, "write userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetVectorFromParcelIntelligentWithErrCode<AbilityInfo>(
        BundleMgrInterfaceCode::QUERY_ABILITY_INFOS_V9, data, abilityInfos);
}

ErrCode BundleMgrProxy::BatchQueryAbilityInfos(
    const std::vector<Want> &wants, int32_t flags, int32_t userId, std::vector<AbilityInfo> &abilityInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("write interfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(wants.size())) {
        APP_LOGE("write wants count failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    for (size_t i = 0; i < wants.size(); i++) {
        if (!data.WriteParcelable(&wants[i])) {
            APP_LOGE("write want %{public}zu failed", i);
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    if (!data.WriteInt32(flags)) {
        APP_LOGE("write flags failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("write userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetVectorFromParcelIntelligentWithErrCode<AbilityInfo>(
        BundleMgrInterfaceCode::BATCH_QUERY_ABILITY_INFOS, data, abilityInfos);
}

ErrCode BundleMgrProxy::QueryLauncherAbilityInfos(
    const Want &want, int32_t userId, std::vector<AbilityInfo> &abilityInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "write interfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        LOG_E(BMS_TAG_QUERY, "write want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_QUERY, "write userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetVectorFromParcelIntelligentWithErrCode<AbilityInfo>(
        BundleMgrInterfaceCode::QUERY_LAUNCHER_ABILITY_INFO, data, abilityInfo);
}

ErrCode BundleMgrProxy::QueryLauncherAbilityInfosPublic(
    const std::string &bundleName, int32_t userId, std::vector<AbilityInfo> &abilityInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "write interfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        LOG_E(BMS_TAG_QUERY, "write bundleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_QUERY, "write userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetVectorFromParcelIntelligentWithErrCode<AbilityInfo>(
        BundleMgrInterfaceCode::QUERY_LAUNCHER_ABILITY_INFOS_PUBLIC, data, abilityInfo);
}

bool BundleMgrProxy::QueryAllAbilityInfos(const Want &want, int32_t userId, std::vector<AbilityInfo> &abilityInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "QueryAbilityInfo write MessageParcel fail");
        return false;
    }
    if (!data.WriteParcelable(&want)) {
        LOG_E(BMS_TAG_QUERY, "QueryAbilityInfos write want fail");
        return false;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_QUERY, "QueryAbilityInfos write userId fail");
        return false;
    }
    if (!GetVectorFromParcelIntelligent<AbilityInfo>(
        BundleMgrInterfaceCode::QUERY_ALL_ABILITY_INFOS, data, abilityInfos)) {
        LOG_E(BMS_TAG_QUERY, "QueryAbilityInfos from server fail");
        return false;
    }
    return true;
}

bool BundleMgrProxy::QueryAbilityInfoByUri(const std::string &abilityUri, AbilityInfo &abilityInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "QueryAbilityInfoByUri write MessageParcel fail");
        return false;
    }
    if (!data.WriteString(abilityUri)) {
        LOG_E(BMS_TAG_QUERY, "QueryAbilityInfoByUri write abilityUri fail");
        return false;
    }

    if (!GetParcelableInfo<AbilityInfo>(BundleMgrInterfaceCode::QUERY_ABILITY_INFO_BY_URI, data, abilityInfo)) {
        LOG_E(BMS_TAG_QUERY, "QueryAbilityInfoByUri from server fail");
        return false;
    }
    return true;
}

bool BundleMgrProxy::QueryAbilityInfosByUri(const std::string &abilityUri, std::vector<AbilityInfo> &abilityInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "QueryAbilityInfosByUri write MessageParcel fail");
        return false;
    }
    if (!data.WriteString(abilityUri)) {
        LOG_E(BMS_TAG_QUERY, "QueryAbilityInfosByUri write abilityUri fail");
        return false;
    }

    if (!GetParcelableInfos<AbilityInfo>(BundleMgrInterfaceCode::QUERY_ABILITY_INFOS_BY_URI, data, abilityInfos)) {
        LOG_E(BMS_TAG_QUERY, "QueryAbilityInfosByUri from server fail");
        return false;
    }
    return true;
}

bool BundleMgrProxy::QueryAbilityInfoByUri(
    const std::string &abilityUri, int32_t userId, AbilityInfo &abilityInfo)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "QueryAbilityInfoByUri write MessageParcel fail");
        return false;
    }
    if (!data.WriteString(abilityUri)) {
        LOG_E(BMS_TAG_QUERY, "QueryAbilityInfoByUri write abilityUri fail");
        return false;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_QUERY, "QueryAbilityInfo write userId fail");
        return false;
    }

    if (!GetParcelableInfo<AbilityInfo>(
        BundleMgrInterfaceCode::QUERY_ABILITY_INFO_BY_URI_FOR_USERID, data, abilityInfo)) {
        APP_LOGE("fail to QueryAbilityInfoByUri from server");
        return false;
    }
    return true;
}

bool BundleMgrProxy::QueryKeepAliveBundleInfos(std::vector<BundleInfo> &bundleInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to QueryKeepAliveBundleInfos");

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to QueryKeepAliveBundleInfos due to write InterfaceToken fail");
        return false;
    }

    if (!GetParcelableInfos<BundleInfo>(BundleMgrInterfaceCode::QUERY_KEEPALIVE_BUNDLE_INFOS, data, bundleInfos)) {
        APP_LOGE("fail to QueryKeepAliveBundleInfos from server");
        return false;
    }
    return true;
}

std::string BundleMgrProxy::GetAbilityLabel(const std::string &bundleName, const std::string &abilityName)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to GetAbilityLabel of %{public}s", bundleName.c_str());
    if (bundleName.empty() || abilityName.empty()) {
        APP_LOGE("fail to GetAbilityLabel due to params empty");
        return Constants::EMPTY_STRING;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetAbilityLabel due to write InterfaceToken fail");
        return Constants::EMPTY_STRING;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to GetAbilityLabel due to write bundleName fail");
        return Constants::EMPTY_STRING;
    }
    if (!data.WriteString(abilityName)) {
        APP_LOGE("fail to GetAbilityLabel due to write abilityName fail");
        return Constants::EMPTY_STRING;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_ABILITY_LABEL, data, reply)) {
        APP_LOGE("fail to GetAbilityLabel from server");
        return Constants::EMPTY_STRING;
    }
    return reply.ReadString();
}

ErrCode BundleMgrProxy::GetAbilityLabel(const std::string &bundleName, const std::string &moduleName,
    const std::string &abilityName, std::string &label)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGI("GetAbilityLabel begin %{public}s", bundleName.c_str());
    if (bundleName.empty() || moduleName.empty() || abilityName.empty()) {
        APP_LOGE("fail to GetAbilityLabel due to params empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetAbilityLabel due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to GetAbilityLabel due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(moduleName)) {
        APP_LOGE("fail to GetAbilityLabel due to write moduleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(abilityName)) {
        APP_LOGE("fail to GetAbilityLabel due to write abilityName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_ABILITY_LABEL_WITH_MODULE_NAME, data, reply)) {
        return ERR_BUNDLE_MANAGER_IPC_TRANSACTION;
    }
    int32_t errCode = reply.ReadInt32();
    if (errCode != ERR_OK) {
        return errCode;
    }
    label = reply.ReadString();
    return ERR_OK;
}

bool BundleMgrProxy::GetBundleArchiveInfo(const std::string &hapFilePath, const BundleFlag flag, BundleInfo &bundleInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to GetBundleArchiveInfo of %{private}s", hapFilePath.c_str());
    if (hapFilePath.empty()) {
        APP_LOGE("fail to GetBundleArchiveInfo due to params empty");
        return false;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetBundleArchiveInfo due to write InterfaceToken fail");
        return false;
    }
    if (!data.WriteString(hapFilePath)) {
        APP_LOGE("fail to GetBundleArchiveInfo due to write hapFilePath fail");
        return false;
    }
    if (!data.WriteInt32(static_cast<int>(flag))) {
        APP_LOGE("fail to GetBundleArchiveInfo due to write flag fail");
        return false;
    }

    if (!GetParcelableInfo<BundleInfo>(BundleMgrInterfaceCode::GET_BUNDLE_ARCHIVE_INFO, data, bundleInfo)) {
        APP_LOGE("fail to GetBundleArchiveInfo from server");
        return false;
    }
    return true;
}

bool BundleMgrProxy::GetBundleArchiveInfo(const std::string &hapFilePath, int32_t flags, BundleInfo &bundleInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to GetBundleArchiveInfo with int flags of %{private}s", hapFilePath.c_str());
    if (hapFilePath.empty()) {
        APP_LOGE("fail to GetBundleArchiveInfo due to params empty");
        return false;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetBundleArchiveInfo due to write InterfaceToken fail");
        return false;
    }
    if (!data.WriteString(hapFilePath)) {
        APP_LOGE("fail to GetBundleArchiveInfo due to write hapFilePath fail");
        return false;
    }
    if (!data.WriteInt32(flags)) {
        APP_LOGE("fail to GetBundleArchiveInfo due to write flags fail");
        return false;
    }

    if (!GetParcelableInfo<BundleInfo>(
        BundleMgrInterfaceCode::GET_BUNDLE_ARCHIVE_INFO_WITH_INT_FLAGS, data, bundleInfo)) {
        APP_LOGE("fail to GetBundleArchiveInfo from server");
        return false;
    }
    return true;
}

ErrCode BundleMgrProxy::GetBundleArchiveInfoV9(const std::string &hapFilePath, int32_t flags, BundleInfo &bundleInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to GetBundleArchiveInfoV9 with int flags of %{private}s", hapFilePath.c_str());
    if (hapFilePath.empty()) {
        APP_LOGE("fail to GetBundleArchiveInfoV9 due to params empty");
        return ERR_BUNDLE_MANAGER_INVALID_HAP_PATH;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetBundleArchiveInfoV9 due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(hapFilePath)) {
        APP_LOGE("fail to GetBundleArchiveInfoV9 due to write hapFilePath fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(flags)) {
        APP_LOGE("fail to GetBundleArchiveInfoV9 due to write flags fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetParcelableInfoWithErrCode<BundleInfo>(
        BundleMgrInterfaceCode::GET_BUNDLE_ARCHIVE_INFO_WITH_INT_FLAGS_V9, data, bundleInfo);
}

ErrCode BundleMgrProxy::GetBundleArchiveInfoExt(
    const std::string &hapFilePath, int32_t fd, int32_t flags, BundleInfo &bundleInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to GetBundleArchiveInfoV9 with int flags of %{private}s", hapFilePath.c_str());
    if (hapFilePath.empty()) {
        APP_LOGE("fail to GetBundleArchiveInfoV9 due to params empty");
        return ERR_BUNDLE_MANAGER_INVALID_HAP_PATH;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetBundleArchiveInfoV9 due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(hapFilePath)) {
        APP_LOGE("fail to GetBundleArchiveInfoV9 due to write hapFilePath fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteFileDescriptor(fd)) {
        APP_LOGE("fail to GetBundleArchiveInfo due to write FileDescriptor fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(flags)) {
        APP_LOGE("fail to GetBundleArchiveInfoV9 due to write flags fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetParcelableInfoWithErrCode<BundleInfo>(
        BundleMgrInterfaceCode::GET_BUNDLE_ARCHIVE_INFO_EXT, data, bundleInfo);
}

bool BundleMgrProxy::GetHapModuleInfo(const AbilityInfo &abilityInfo, HapModuleInfo &hapModuleInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to GetHapModuleInfo of %{public}s", abilityInfo.package.c_str());
    if (abilityInfo.bundleName.empty() || abilityInfo.package.empty()) {
        APP_LOGE("fail to GetHapModuleInfo due to params empty");
        return false;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetHapModuleInfo due to write InterfaceToken fail");
        return false;
    }
    if (!data.WriteParcelable(&abilityInfo)) {
        APP_LOGE("fail to GetHapModuleInfo due to write abilityInfo fail");
        return false;
    }

    if (!GetParcelableInfo<HapModuleInfo>(BundleMgrInterfaceCode::GET_HAP_MODULE_INFO, data, hapModuleInfo)) {
        APP_LOGE("fail to GetHapModuleInfo from server");
        return false;
    }
    return true;
}

bool BundleMgrProxy::GetHapModuleInfo(const AbilityInfo &abilityInfo, int32_t userId, HapModuleInfo &hapModuleInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to GetHapModuleInfo of %{public}s", abilityInfo.package.c_str());
    if (abilityInfo.bundleName.empty() || abilityInfo.package.empty()) {
        APP_LOGE("fail to GetHapModuleInfo due to params empty");
        return false;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetHapModuleInfo due to write InterfaceToken fail");
        return false;
    }
    if (!data.WriteParcelable(&abilityInfo)) {
        APP_LOGE("fail to GetHapModuleInfo due to write abilityInfo fail");
        return false;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to QueryAbilityInfo due to write want fail");
        return false;
    }

    if (!GetParcelableInfo<HapModuleInfo>(
        BundleMgrInterfaceCode::GET_HAP_MODULE_INFO_WITH_USERID, data, hapModuleInfo)) {
        APP_LOGE_NOFUNC("fail to GetHapModuleInfo from server");
        return false;
    }
    return true;
}

ErrCode BundleMgrProxy::GetLaunchWantForBundle(const std::string &bundleName, Want &want, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to GetLaunchWantForBundle of %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        APP_LOGE("fail to GetHapModuleInfo due to params empty");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetLaunchWantForBundle due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to GetLaunchWantForBundle due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to GetLaunchWantForBundle due to write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return GetParcelableInfoWithErrCode<Want>(
        BundleMgrInterfaceCode::GET_LAUNCH_WANT_FOR_BUNDLE, data, want);
}

ErrCode BundleMgrProxy::GetPermissionDef(const std::string &permissionName, PermissionDef &permissionDef)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to GetPermissionDef of %{public}s", permissionName.c_str());
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetPermissionDef due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(permissionName)) {
        APP_LOGE("fail to GetPermissionDef due to write permissionName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return GetParcelableInfoWithErrCode<PermissionDef>(
        BundleMgrInterfaceCode::GET_PERMISSION_DEF, data, permissionDef);
}

ErrCode BundleMgrProxy::CleanBundleCacheFilesAutomatic(uint64_t cacheSize)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);

    if (cacheSize == 0) {
        APP_LOGE("parameter error, cache size must be greater than 0");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to CleanBundleCacheFilesAutomatic due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteUint64(cacheSize)) {
        APP_LOGE("fail to CleanBundleCacheFilesAutomatic due to write cache size fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::AUTO_CLEAN_CACHE_BY_SIZE, data, reply)) {
        APP_LOGE("fail to CleanBundleCacheFilesAutomatic from server");
        return ERR_BUNDLE_MANAGER_IPC_TRANSACTION;
    }
    return reply.ReadInt32();
}

ErrCode BundleMgrProxy::CleanBundleCacheFiles(
    const std::string &bundleName, const sptr<ICleanCacheCallback> cleanCacheCallback, int32_t userId, int32_t appIndex)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to CleanBundleCacheFiles of %{public}s, userId:%{public}d, appIndex:%{public}d",
        bundleName.c_str(), userId, appIndex);
    if (bundleName.empty()) {
        APP_LOGE("fail to CleanBundleCacheFiles due to bundleName empty");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    if (cleanCacheCallback == nullptr) {
        APP_LOGE("fail to CleanBundleCacheFiles due to params error");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to CleanBundleCacheFiles due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to CleanBundleCacheFiles due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(cleanCacheCallback->AsObject())) {
        APP_LOGE("fail to CleanBundleCacheFiles, for write parcel failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to CleanBundleCacheFiles due to write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(appIndex)) {
        APP_LOGE("fail to CleanBundleDataFiles due to write appIndex fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::CLEAN_BUNDLE_CACHE_FILES, data, reply)) {
        APP_LOGE("fail to CleanBundleCacheFiles from server");
        return ERR_BUNDLE_MANAGER_IPC_TRANSACTION;
    }
    return reply.ReadInt32();
}

bool BundleMgrProxy::CleanBundleDataFiles(const std::string &bundleName, const int userId, const int appIndex)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to CleanBundleDataFiles of %{public}s, userId:%{public}d, appIndex:%{public}d",
        bundleName.c_str(), userId, appIndex);
    if (bundleName.empty()) {
        APP_LOGE("fail to CleanBundleDataFiles due to params empty");
        return false;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to CleanBundleDataFiles due to write InterfaceToken fail");
        return false;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to CleanBundleDataFiles due to write hapFilePath fail");
        return false;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to CleanBundleDataFiles due to write userId fail");
        return false;
    }
    if (!data.WriteInt32(appIndex)) {
        APP_LOGE("fail to CleanBundleDataFiles due to write appIndex fail");
        return false;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::CLEAN_BUNDLE_DATA_FILES, data, reply)) {
        APP_LOGE("fail to CleanBundleDataFiles from server");
        return false;
    }
    return reply.ReadBool();
}

bool BundleMgrProxy::RegisterBundleStatusCallback(const sptr<IBundleStatusCallback> &bundleStatusCallback)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to RegisterBundleStatusCallback");
    if (!bundleStatusCallback || bundleStatusCallback->GetBundleName().empty()) {
        APP_LOGE("fail to RegisterBundleStatusCallback");
        return false;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to RegisterBundleStatusCallback due to write InterfaceToken fail");
        return false;
    }
    if (!data.WriteString(bundleStatusCallback->GetBundleName())) {
        APP_LOGE("fail to RegisterBundleStatusCallback due to write bundleName fail");
        return false;
    }
    if (!data.WriteInt32(bundleStatusCallback->GetUserId())) {
        APP_LOGE("fail to RegisterBundleStatusCallback due to write userId fail");
        return false;
    }
    if (!data.WriteRemoteObject(bundleStatusCallback->AsObject())) {
        APP_LOGE("fail to RegisterBundleStatusCallback, for write parcel failed");
        return false;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::REGISTER_BUNDLE_STATUS_CALLBACK, data, reply)) {
        APP_LOGE("fail to RegisterBundleStatusCallback from server");
        return false;
    }
    return reply.ReadBool();
}

bool BundleMgrProxy::RegisterBundleEventCallback(const sptr<IBundleEventCallback> &bundleEventCallback)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to RegisterBundleEventCallback");
    if (!bundleEventCallback) {
        APP_LOGE("bundleEventCallback is null");
        return false;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to RegisterBundleEventCallback due to write InterfaceToken fail");
        return false;
    }
    if (!data.WriteRemoteObject(bundleEventCallback->AsObject())) {
        APP_LOGE("write BundleEventCallback failed");
        return false;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::REGISTER_BUNDLE_EVENT_CALLBACK, data, reply)) {
        APP_LOGE("fail to RegisterBundleEventCallback from server");
        return false;
    }
    return reply.ReadBool();
}

bool BundleMgrProxy::UnregisterBundleEventCallback(const sptr<IBundleEventCallback> &bundleEventCallback)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to UnregisterBundleEventCallback");
    if (!bundleEventCallback) {
        APP_LOGE("bundleEventCallback is null");
        return false;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to UnregisterBundleEventCallback due to write InterfaceToken fail");
        return false;
    }
    if (!data.WriteRemoteObject(bundleEventCallback->AsObject())) {
        APP_LOGE("fail to UnregisterBundleEventCallback, for write parcel failed");
        return false;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::UNREGISTER_BUNDLE_EVENT_CALLBACK, data, reply)) {
        APP_LOGE("fail to UnregisterBundleEventCallback from server");
        return false;
    }
    return reply.ReadBool();
}

bool BundleMgrProxy::ClearBundleStatusCallback(const sptr<IBundleStatusCallback> &bundleStatusCallback)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to ClearBundleStatusCallback");
    if (!bundleStatusCallback) {
        APP_LOGE("fail to ClearBundleStatusCallback, for bundleStatusCallback is nullptr");
        return false;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to ClearBundleStatusCallback due to write InterfaceToken fail");
        return false;
    }
    if (!data.WriteRemoteObject(bundleStatusCallback->AsObject())) {
        APP_LOGE("fail to ClearBundleStatusCallback, for write parcel failed");
        return false;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::CLEAR_BUNDLE_STATUS_CALLBACK, data, reply)) {
        APP_LOGE("fail to CleanBundleCacheFiles from server");
        return false;
    }
    return reply.ReadBool();
}

bool BundleMgrProxy::UnregisterBundleStatusCallback()
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to UnregisterBundleStatusCallback");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to UnregisterBundleStatusCallback due to write InterfaceToken fail");
        return false;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::UNREGISTER_BUNDLE_STATUS_CALLBACK, data, reply)) {
        APP_LOGE("fail to UnregisterBundleStatusCallback from server");
        return false;
    }
    return reply.ReadBool();
}

bool BundleMgrProxy::DumpInfos(
    const DumpFlag flag, const std::string &bundleName, int32_t userId, std::string &result)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to dump");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to dump due to write InterfaceToken fail");
        return false;
    }
    if (!data.WriteInt32(static_cast<int>(flag))) {
        APP_LOGE("fail to dump due to write flag fail");
        return false;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to dump due to write bundleName fail");
        return false;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to dump due to write userId fail");
        return false;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::DUMP_INFOS, data, reply)) {
        APP_LOGE("fail to dump from server");
        return false;
    }
    if (!reply.ReadBool()) {
        APP_LOGE("readParcelableInfo failed");
        return false;
    }
    std::vector<std::string> dumpInfos;
    if (!reply.ReadStringVector(&dumpInfos)) {
        APP_LOGE("fail to dump from reply");
        return false;
    }
    result = std::accumulate(dumpInfos.begin(), dumpInfos.end(), result);
    return true;
}

ErrCode BundleMgrProxy::IsModuleRemovable(const std::string &bundleName, const std::string &moduleName,
    bool &isRemovable)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to IsModuleRemovable of %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        APP_LOGE("fail to IsModuleRemovable due to bundleName empty");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    if (moduleName.empty()) {
        APP_LOGE("fail to IsModuleRemovable due to moduleName empty");
        return ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to IsModuleRemovable due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to IsModuleRemovable due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(moduleName)) {
        APP_LOGE("fail to IsModuleRemovable due to write moduleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::IS_MODULE_REMOVABLE, data, reply)) {
        APP_LOGE("fail to IsModuleRemovable from server");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode ret = reply.ReadInt32();
    if (ret == ERR_OK) {
        isRemovable = reply.ReadBool();
    }
    return ret;
}

bool BundleMgrProxy::SetModuleRemovable(const std::string &bundleName, const std::string &moduleName, bool isEnable)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to SetModuleRemovable of %{public}s", bundleName.c_str());
    if (bundleName.empty() || moduleName.empty()) {
        APP_LOGE("fail to SetModuleRemovable due to params empty");
        return false;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to SetModuleRemovable due to write InterfaceToken fail");
        return false;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to SetModuleRemovable due to write bundleName fail");
        return false;
    }

    if (!data.WriteString(moduleName)) {
        APP_LOGE("fail to SetModuleRemovable due to write moduleName fail");
        return false;
    }
    if (!data.WriteBool(isEnable)) {
        APP_LOGE("fail to SetModuleRemovable due to write isEnable fail");
        return false;
    }
    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::SET_MODULE_REMOVABLE, data, reply)) {
        APP_LOGE("fail to SetModuleRemovable from server");
        return false;
    }
    return reply.ReadBool();
}

bool BundleMgrProxy::GetModuleUpgradeFlag(const std::string &bundleName, const std::string &moduleName)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to GetModuleUpgradeFlag of %{public}s", bundleName.c_str());
    if (bundleName.empty() || moduleName.empty()) {
        APP_LOGE("fail to GetModuleUpgradeFlag due to params empty");
        return false;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetModuleUpgradeFlag due to write InterfaceToken fail");
        return false;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to GetModuleUpgradeFlag due to write bundleName fail");
        return false;
    }

    if (!data.WriteString(moduleName)) {
        APP_LOGE("fail to GetModuleUpgradeFlag due to write moduleName fail");
        return false;
    }
    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::IS_MODULE_NEED_UPDATE, data, reply)) {
        APP_LOGE("fail to GetModuleUpgradeFlag from server");
        return false;
    }
    return reply.ReadBool();
}

ErrCode BundleMgrProxy::SetModuleUpgradeFlag(const std::string &bundleName,
    const std::string &moduleName, int32_t upgradeFlag)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to SetModuleUpgradeFlag of %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        APP_LOGE("fail to SetModuleUpgradeFlag due to bundleName empty");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }
    if (moduleName.empty()) {
        APP_LOGE("fail to SetModuleUpgradeFlag due to moduleName empty");
        return ERR_BUNDLE_MANAGER_MODULE_NOT_EXIST;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to SetModuleUpgradeFlag due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to SetModuleUpgradeFlag due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(moduleName)) {
        APP_LOGE("fail to SetModuleUpgradeFlag due to write moduleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(upgradeFlag)) {
        APP_LOGE("fail to SetModuleUpgradeFlag due to write isEnable fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::SET_MODULE_NEED_UPDATE, data, reply)) {
        APP_LOGE("fail to SetModuleUpgradeFlag from server");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return reply.ReadInt32();
}

ErrCode BundleMgrProxy::IsApplicationEnabled(const std::string &bundleName, bool &isEnable)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to IsApplicationEnabled of %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        APP_LOGE("fail to IsApplicationEnabled due to params empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to IsApplicationEnabled due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to IsApplicationEnabled due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::IS_APPLICATION_ENABLED, data, reply)) {
        return ERR_BUNDLE_MANAGER_IPC_TRANSACTION;
    }
    int32_t ret = reply.ReadInt32();
    if (ret != NO_ERROR) {
        return ret;
    }
    isEnable = reply.ReadBool();
    return NO_ERROR;
}

ErrCode BundleMgrProxy::IsCloneApplicationEnabled(const std::string &bundleName, int32_t appIndex, bool &isEnable)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to IsCloneApplicationEnabled of %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        APP_LOGE("fail to IsCloneApplicationEnabled due to params empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to IsCloneApplicationEnabled due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to IsCloneApplicationEnabled due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(appIndex)) {
        APP_LOGE("fail to IsCloneApplicationEnabled due to write appIndex fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::IS_CLONE_APPLICATION_ENABLED, data, reply)) {
        return ERR_BUNDLE_MANAGER_IPC_TRANSACTION;
    }
    int32_t ret = reply.ReadInt32();
    if (ret != NO_ERROR) {
        return ret;
    }
    isEnable = reply.ReadBool();
    return NO_ERROR;
}

ErrCode BundleMgrProxy::SetApplicationEnabled(const std::string &bundleName, bool isEnable, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to SetApplicationEnabled of %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        APP_LOGE("fail to SetApplicationEnabled due to params empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to SetApplicationEnabled due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to SetApplicationEnabled due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(isEnable)) {
        APP_LOGE("fail to SetApplicationEnabled due to write isEnable fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to SetApplicationEnabled due to write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::SET_APPLICATION_ENABLED, data, reply)) {
        return ERR_BUNDLE_MANAGER_IPC_TRANSACTION;
    }
    return reply.ReadInt32();
}

ErrCode BundleMgrProxy::SetCloneApplicationEnabled(
    const std::string &bundleName, int32_t appIndex, bool isEnable, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to SetCloneApplicationEnabled of %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        APP_LOGE("fail to SetCloneApplicationEnabled due to params empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to SetCloneApplicationEnabled due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to SetCloneApplicationEnabled due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(appIndex)) {
        APP_LOGE("fail to SetCloneApplicationEnabled due to write appIndex fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(isEnable)) {
        APP_LOGE("fail to SetCloneApplicationEnabled due to write isEnable fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to SetCloneApplicationEnabled due to write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::SET_CLONE_APPLICATION_ENABLED, data, reply)) {
        return ERR_BUNDLE_MANAGER_IPC_TRANSACTION;
    }
    return reply.ReadInt32();
}

ErrCode BundleMgrProxy::IsAbilityEnabled(const AbilityInfo &abilityInfo, bool &isEnable)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to IsAbilityEnabled of %{public}s", abilityInfo.name.c_str());
    if (abilityInfo.bundleName.empty() || abilityInfo.name.empty()) {
        APP_LOGE("fail to IsAbilityEnabled due to params empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to IsAbilityEnabled due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&abilityInfo)) {
        APP_LOGE("fail to IsAbilityEnabled due to write abilityInfo fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::IS_ABILITY_ENABLED, data, reply)) {
        return ERR_BUNDLE_MANAGER_IPC_TRANSACTION;
    }
    int32_t ret = reply.ReadInt32();
    if (ret != NO_ERROR) {
        return ret;
    }
    isEnable = reply.ReadBool();
    return NO_ERROR;
}

ErrCode BundleMgrProxy::IsCloneAbilityEnabled(const AbilityInfo &abilityInfo, int32_t appIndex, bool &isEnable)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to IsCloneAbilityEnabled of %{public}s", abilityInfo.name.c_str());
    if (abilityInfo.bundleName.empty() || abilityInfo.name.empty()) {
        APP_LOGE("fail to IsCloneAbilityEnabled due to params empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to IsCloneAbilityEnabled due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&abilityInfo)) {
        APP_LOGE("fail to IsCloneAbilityEnabled due to write abilityInfo fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(appIndex)) {
        APP_LOGE("fail to IsCloneAbilityEnabled due to write appIndex fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::IS_CLONE_ABILITY_ENABLED, data, reply)) {
        return ERR_BUNDLE_MANAGER_IPC_TRANSACTION;
    }
    int32_t ret = reply.ReadInt32();
    if (ret != NO_ERROR) {
        return ret;
    }
    isEnable = reply.ReadBool();
    return NO_ERROR;
}

ErrCode BundleMgrProxy::SetAbilityEnabled(const AbilityInfo &abilityInfo, bool isEnabled, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to SetAbilityEnabled of %{public}s", abilityInfo.name.c_str());
    if (abilityInfo.bundleName.empty() || abilityInfo.name.empty()) {
        APP_LOGE("fail to SetAbilityEnabled due to params empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to SetAbilityEnabled due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&abilityInfo)) {
        APP_LOGE("fail to SetAbilityEnabled due to write abilityInfo fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(isEnabled)) {
        APP_LOGE("fail to SetAbilityEnabled due to write isEnabled fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to SetAbilityEnabled due to write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::SET_ABILITY_ENABLED, data, reply)) {
        return ERR_BUNDLE_MANAGER_IPC_TRANSACTION;
    }
    return reply.ReadInt32();
}

ErrCode BundleMgrProxy::SetCloneAbilityEnabled(
    const AbilityInfo &abilityInfo, int32_t appIndex, bool isEnabled, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to SetCloneAbilityEnabled of %{public}s", abilityInfo.name.c_str());
    if (abilityInfo.bundleName.empty() || abilityInfo.name.empty()) {
        APP_LOGE("fail to SetCloneAbilityEnabled due to params empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to SetCloneAbilityEnabled due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&abilityInfo)) {
        APP_LOGE("fail to SetCloneAbilityEnabled due to write abilityInfo fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(appIndex)) {
        APP_LOGE("fail to SetCloneAbilityEnabled due to write appIndex fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(isEnabled)) {
        APP_LOGE("fail to SetCloneAbilityEnabled due to write isEnabled fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to SetCloneAbilityEnabled due to write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::SET_CLONE_ABILITY_ENABLED, data, reply)) {
        return ERR_BUNDLE_MANAGER_IPC_TRANSACTION;
    }
    return reply.ReadInt32();
}

bool BundleMgrProxy::GetAbilityInfo(
    const std::string &bundleName, const std::string &abilityName, AbilityInfo &abilityInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    LOG_D(BMS_TAG_QUERY, "GetAbilityInfo bundleName:%{public}s abilityName:%{public}s",
        bundleName.c_str(), abilityName.c_str());
    if (bundleName.empty() || abilityName.empty()) {
        LOG_E(BMS_TAG_QUERY, "GetAbilityInfo failed params empty");
        return false;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "GetAbilityInfo write MessageParcel fail");
        return false;
    }
    if (!data.WriteString(bundleName)) {
        LOG_E(BMS_TAG_QUERY, "GetAbilityInfo write bundleName fail");
        return false;
    }
    if (!data.WriteString(abilityName)) {
        LOG_E(BMS_TAG_QUERY, "GetAbilityInfo write abilityName fail");
        return false;
    }

    if (!GetParcelableInfo<AbilityInfo>(BundleMgrInterfaceCode::GET_ABILITY_INFO, data, abilityInfo)) {
        LOG_E(BMS_TAG_QUERY, "GetAbilityInfo from server fail");
        return false;
    }
    return true;
}

bool BundleMgrProxy::GetAbilityInfo(
    const std::string &bundleName, const std::string &moduleName,
    const std::string &abilityName, AbilityInfo &abilityInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    LOG_D(BMS_TAG_QUERY, "GetAbilityInfo bundleName:%{public}s moduleName:%{public}s abilityName:%{public}s",
        bundleName.c_str(), moduleName.c_str(), abilityName.c_str());
    if (bundleName.empty() || moduleName.empty() || abilityName.empty()) {
        LOG_E(BMS_TAG_QUERY, "GetAbilityInfo failed params empty");
        return false;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "GetAbilityInfo write MessageParcel fail");
        return false;
    }
    if (!data.WriteString(bundleName)) {
        LOG_E(BMS_TAG_QUERY, "GetAbilityInfo write bundleName fail");
        return false;
    }
    if (!data.WriteString(moduleName)) {
        LOG_E(BMS_TAG_QUERY, "GetAbilityInfo write moduleName fail");
        return false;
    }
    if (!data.WriteString(abilityName)) {
        LOG_E(BMS_TAG_QUERY, "GetAbilityInfo write abilityName fail");
        return false;
    }

    if (!GetParcelableInfo<AbilityInfo>(
        BundleMgrInterfaceCode::GET_ABILITY_INFO_WITH_MODULE_NAME, data, abilityInfo)) {
        LOG_E(BMS_TAG_QUERY, "GetAbilityInfo from server fail");
        return false;
    }
    return true;
}

sptr<IBundleInstaller> BundleMgrProxy::GetBundleInstaller()
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to get bundle installer");
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetBundleInstaller due to write InterfaceToken fail");
        return nullptr;
    }
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_BUNDLE_INSTALLER, data, reply)) {
        return nullptr;
    }

    sptr<IRemoteObject> object = reply.ReadRemoteObject();
    if (object == nullptr) {
        APP_LOGE("read failed");
        return nullptr;
    }
    sptr<IBundleInstaller> installer = iface_cast<IBundleInstaller>(object);
    if (installer == nullptr) {
        APP_LOGE("bundle installer is nullptr");
    }

    APP_LOGD("get bundle installer success");
    return installer;
}

sptr<IBundleUserMgr> BundleMgrProxy::GetBundleUserMgr()
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to get bundle user mgr due to write InterfaceToken fail");
        return nullptr;
    }
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_BUNDLE_USER_MGR, data, reply)) {
        return nullptr;
    }

    sptr<IRemoteObject> object = reply.ReadRemoteObject();
    if (object == nullptr) {
        APP_LOGE("read failed");
        return nullptr;
    }
    sptr<IBundleUserMgr> bundleUserMgr = iface_cast<IBundleUserMgr>(object);
    if (bundleUserMgr == nullptr) {
        APP_LOGE("bundleUserMgr is nullptr");
    }

    return bundleUserMgr;
}

sptr<IVerifyManager> BundleMgrProxy::GetVerifyManager()
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to get VerifyManager due to write InterfaceToken fail");
        return nullptr;
    }
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_VERIFY_MANAGER, data, reply)) {
        return nullptr;
    }

    sptr<IRemoteObject> object = reply.ReadRemoteObject();
    if (object == nullptr) {
        APP_LOGE("read failed");
        return nullptr;
    }
    sptr<IVerifyManager> verifyManager = iface_cast<IVerifyManager>(object);
    if (verifyManager == nullptr) {
        APP_LOGE("VerifyManager is nullptr");
    }

    return verifyManager;
}

sptr<IExtendResourceManager> BundleMgrProxy::GetExtendResourceManager()
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to get GetExtendResourceManager due to write InterfaceToken fail");
        return nullptr;
    }
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_EXTEND_RESOURCE_MANAGER, data, reply)) {
        return nullptr;
    }

    sptr<IRemoteObject> object = reply.ReadRemoteObject();
    if (object == nullptr) {
        APP_LOGE("read failed");
        return nullptr;
    }
    sptr<IExtendResourceManager> extendResourceManager = iface_cast<IExtendResourceManager>(object);
    if (extendResourceManager == nullptr) {
        APP_LOGE("extendResourceManager is nullptr");
    }
    return extendResourceManager;
}

bool BundleMgrProxy::GetAllFormsInfo(std::vector<FormInfo> &formInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetAllFormsInfo due to write MessageParcel fail");
        return false;
    }

    if (!GetParcelableInfos<FormInfo>(BundleMgrInterfaceCode::GET_ALL_FORMS_INFO, data, formInfos)) {
        APP_LOGE("fail to GetAllFormsInfo from server");
        return false;
    }
    return true;
}

bool BundleMgrProxy::GetFormsInfoByApp(const std::string &bundleName, std::vector<FormInfo> &formInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (bundleName.empty()) {
        APP_LOGE("fail to GetFormsInfoByApp due to params empty");
        return false;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetFormsInfoByApp due to write MessageParcel fail");
        return false;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to GetFormsInfoByApp due to write bundleName fail");
        return false;
    }
    if (!GetParcelableInfos<FormInfo>(BundleMgrInterfaceCode::GET_FORMS_INFO_BY_APP, data, formInfos)) {
        APP_LOGE("fail to GetFormsInfoByApp from server");
        return false;
    }
    return true;
}

bool BundleMgrProxy::GetFormsInfoByModule(
    const std::string &bundleName, const std::string &moduleName, std::vector<FormInfo> &formInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (bundleName.empty() || moduleName.empty()) {
        APP_LOGE("fail to GetFormsByModule due to params empty");
        return false;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetFormsInfoByModule due to write MessageParcel fail");
        return false;
    }

    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to GetFormsInfoByModule due to write bundleName fail");
        return false;
    }

    if (!data.WriteString(moduleName)) {
        APP_LOGE("fail to GetFormsInfoByModule due to write moduleName fail");
        return false;
    }

    if (!GetParcelableInfos<FormInfo>(BundleMgrInterfaceCode::GET_FORMS_INFO_BY_MODULE, data, formInfos)) {
        APP_LOGE("fail to GetFormsInfoByModule from server");
        return false;
    }
    return true;
}

bool BundleMgrProxy::GetShortcutInfos(const std::string &bundleName, std::vector<ShortcutInfo> &shortcutInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (bundleName.empty()) {
        APP_LOGE("fail to GetShortcutInfos due to params empty");
        return false;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetShortcutInfos due to write MessageParcel fail");
        return false;
    }

    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to GetShortcutInfos due to write bundleName fail");
        return false;
    }

    if (!GetParcelableInfos<ShortcutInfo>(BundleMgrInterfaceCode::GET_SHORTCUT_INFO, data, shortcutInfos)) {
        APP_LOGE("fail to GetShortcutInfos from server");
        return false;
    }
    return true;
}

ErrCode BundleMgrProxy::GetShortcutInfoV9(const std::string &bundleName,
    std::vector<ShortcutInfo> &shortcutInfos, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (bundleName.empty()) {
        APP_LOGE("fail to GetShortcutInfos due to params empty");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetShortcutInfos due to write MessageParcel fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to GetShortcutInfos due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to GetShortcutInfos due to write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetParcelableInfosWithErrCode<ShortcutInfo>(
        BundleMgrInterfaceCode::GET_SHORTCUT_INFO_V9, data, shortcutInfos);
}

bool BundleMgrProxy::GetAllCommonEventInfo(const std::string &eventKey, std::vector<CommonEventInfo> &commonEventInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (eventKey.empty()) {
        APP_LOGE("fail to GetAllCommonEventInfo due to eventKey empty");
        return false;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetAllCommonEventInfo due to write MessageParcel fail");
        return false;
    }

    if (!data.WriteString(eventKey)) {
        APP_LOGE("fail to GetAllCommonEventInfo due to write eventKey fail");
        return false;
    }

    if (!GetParcelableInfos<CommonEventInfo>(
        BundleMgrInterfaceCode::GET_ALL_COMMON_EVENT_INFO, data, commonEventInfos)) {
        APP_LOGE("fail to GetAllCommonEventInfo from server");
        return false;
    }
    return true;
}

bool BundleMgrProxy::GetDistributedBundleInfo(const std::string &networkId, const std::string &bundleName,
    DistributedBundleInfo &distributedBundleInfo)
{
    APP_LOGD("begin to GetDistributedBundleInfo of %{public}s", bundleName.c_str());
    if (networkId.empty() || bundleName.empty()) {
        APP_LOGE("fail to GetDistributedBundleInfo due to params empty");
        return false;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetDistributedBundleInfo due to write MessageParcel fail");
        return false;
    }

    if (!data.WriteString(networkId)) {
        APP_LOGE("fail to GetDistributedBundleInfo due to write networkId fail");
        return false;
    }

    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to GetDistributedBundleInfo due to write bundleName fail");
        return false;
    }
    MessageParcel reply;
    if (!GetParcelableInfo<DistributedBundleInfo>(
            BundleMgrInterfaceCode::GET_DISTRIBUTE_BUNDLE_INFO, data, distributedBundleInfo)) {
        APP_LOGE("fail to GetDistributedBundleInfo from server");
        return false;
    }
    return true;
}

std::string BundleMgrProxy::GetAppPrivilegeLevel(const std::string &bundleName, int32_t userId)
{
    APP_LOGD("begin to GetAppPrivilegeLevel of %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        APP_LOGE("fail to GetAppPrivilegeLevel due to params empty");
        return Constants::EMPTY_STRING;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetAppPrivilegeLevel due to write InterfaceToken fail");
        return Constants::EMPTY_STRING;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to GetAppPrivilegeLevel due to write bundleName fail");
        return Constants::EMPTY_STRING;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to GetAppPrivilegeLevel due to write userId fail");
        return Constants::EMPTY_STRING;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_APPLICATION_PRIVILEGE_LEVEL, data, reply)) {
        APP_LOGE("fail to GetAppPrivilegeLevel from server");
        return Constants::EMPTY_STRING;
    }
    return reply.ReadString();
}

bool BundleMgrProxy::QueryExtensionAbilityInfos(const Want &want, const int32_t &flag, const int32_t &userId,
    std::vector<ExtensionAbilityInfo> &extensionInfos)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "QueryExtensionAbilityInfos write InterfaceToken fail");
        return false;
    }
    if (!data.WriteParcelable(&want)) {
        LOG_E(BMS_TAG_QUERY, "QueryExtensionAbilityInfos write want fail");
        return false;
    }
    if (!data.WriteInt32(flag)) {
        LOG_E(BMS_TAG_QUERY, "QueryExtensionAbilityInfos write flag fail");
        return false;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_QUERY, "QueryExtensionAbilityInfos write userId fail");
        return false;
    }

    if (!GetParcelableInfos(BundleMgrInterfaceCode::QUERY_EXTENSION_INFO_WITHOUT_TYPE, data, extensionInfos)) {
        LOG_E(BMS_TAG_QUERY, "fail to obtain extensionInfos");
        return false;
    }
    return true;
}

ErrCode BundleMgrProxy::QueryExtensionAbilityInfosV9(const Want &want, int32_t flags, int32_t userId,
    std::vector<ExtensionAbilityInfo> &extensionInfos)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "QueryExtensionAbilityInfosV9 write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        LOG_E(BMS_TAG_QUERY, "QueryExtensionAbilityInfosV9 write want fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(flags)) {
        LOG_E(BMS_TAG_QUERY, "QueryExtensionAbilityInfosV9 write flag fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_QUERY, "QueryExtensionAbilityInfosV9 write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetParcelableInfosWithErrCode(
        BundleMgrInterfaceCode::QUERY_EXTENSION_INFO_WITHOUT_TYPE_V9, data, extensionInfos);
}

bool BundleMgrProxy::QueryExtensionAbilityInfos(const Want &want, const ExtensionAbilityType &extensionType,
    const int32_t &flag, const int32_t &userId, std::vector<ExtensionAbilityInfo> &extensionInfos)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "QueryExtensionAbilityInfos write InterfaceToken fail");
        return false;
    }
    if (!data.WriteParcelable(&want)) {
        LOG_E(BMS_TAG_QUERY, "QueryExtensionAbilityInfos write want fail");
        return false;
    }
    if (!data.WriteInt32(static_cast<int32_t>(extensionType))) {
        LOG_E(BMS_TAG_QUERY, "QueryExtensionAbilityInfos write type fail");
        return false;
    }
    if (!data.WriteInt32(flag)) {
        LOG_E(BMS_TAG_QUERY, "QueryExtensionAbilityInfos write flag fail");
        return false;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_QUERY, "QueryExtensionAbilityInfos write userId fail");
        return false;
    }

    if (!GetParcelableInfos(BundleMgrInterfaceCode::QUERY_EXTENSION_INFO, data, extensionInfos)) {
        LOG_E(BMS_TAG_QUERY, "fail to obtain extensionInfos");
        return false;
    }
    return true;
}

ErrCode BundleMgrProxy::QueryExtensionAbilityInfosV9(const Want &want, const ExtensionAbilityType &extensionType,
    int32_t flags, int32_t userId, std::vector<ExtensionAbilityInfo> &extensionInfos)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "QueryExtensionAbilityInfosV9 write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        LOG_E(BMS_TAG_QUERY, "QueryExtensionAbilityInfosV9 write want fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(static_cast<int32_t>(extensionType))) {
        LOG_E(BMS_TAG_QUERY, "QueryExtensionAbilityInfosV9 write type fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(flags)) {
        LOG_E(BMS_TAG_QUERY, "QueryExtensionAbilityInfosV9 write flag fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_QUERY, "QueryExtensionAbilityInfosV9 write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetParcelableInfosWithErrCode(BundleMgrInterfaceCode::QUERY_EXTENSION_INFO_V9, data, extensionInfos);
}

bool BundleMgrProxy::QueryExtensionAbilityInfos(const ExtensionAbilityType &extensionType, const int32_t &userId,
    std::vector<ExtensionAbilityInfo> &extensionInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "QueryExtensionAbilityInfos write InterfaceToken fail");
        return false;
    }
    if (!data.WriteInt32(static_cast<int32_t>(extensionType))) {
        LOG_E(BMS_TAG_QUERY, "QueryExtensionAbilityInfos write type fail");
        return false;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_QUERY, "QueryExtensionAbilityInfos write userId fail");
        return false;
    }

    if (!GetParcelableInfos(BundleMgrInterfaceCode::QUERY_EXTENSION_INFO_BY_TYPE, data, extensionInfos)) {
        LOG_E(BMS_TAG_QUERY, "fail to obtain extensionInfos");
        return false;
    }
    return true;
}

bool BundleMgrProxy::VerifyCallingPermission(const std::string &permission)
{
    APP_LOGD("VerifyCallingPermission begin");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to VerifyCallingPermission due to write InterfaceToken fail");
        return false;
    }

    if (!data.WriteString(permission)) {
        APP_LOGE("fail to VerifyCallingPermission due to write bundleName fail");
        return false;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::VERIFY_CALLING_PERMISSION, data, reply)) {
        APP_LOGE("fail to sendRequest");
        return false;
    }
    return reply.ReadBool();
}

bool BundleMgrProxy::QueryExtensionAbilityInfoByUri(const std::string &uri, int32_t userId,
    ExtensionAbilityInfo &extensionAbilityInfo)
{
    LOG_D(BMS_TAG_QUERY, "begin to QueryExtensionAbilityInfoByUri");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (uri.empty()) {
        LOG_E(BMS_TAG_QUERY, "uri is empty");
        return false;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "QueryExtensionAbilityInfoByUri write MessageParcel fail");
        return false;
    }
    if (!data.WriteString(uri)) {
        LOG_E(BMS_TAG_QUERY, "QueryExtensionAbilityInfoByUri write uri fail");
        return false;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_QUERY, "QueryExtensionAbilityInfoByUri write userId fail");
        return false;
    }

    if (!GetParcelableInfo<ExtensionAbilityInfo>(
        BundleMgrInterfaceCode::QUERY_EXTENSION_ABILITY_INFO_BY_URI, data, extensionAbilityInfo)) {
        LOG_E(BMS_TAG_QUERY, "failed to QueryExtensionAbilityInfoByUri from server");
        return false;
    }
    return true;
}

bool BundleMgrProxy::ImplicitQueryInfoByPriority(const Want &want, int32_t flags, int32_t userId,
    AbilityInfo &abilityInfo, ExtensionAbilityInfo &extensionInfo)
{
    LOG_D(BMS_TAG_QUERY, "begin to ImplicitQueryInfoByPriority");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "ImplicitQueryInfoByPriority write MessageParcel fail");
        return false;
    }
    if (!data.WriteParcelable(&want)) {
        LOG_E(BMS_TAG_QUERY, "ImplicitQueryInfoByPriority write want fail");
        return false;
    }
    if (!data.WriteInt32(flags)) {
        LOG_E(BMS_TAG_QUERY, "ImplicitQueryInfoByPriority write flags fail");
        return false;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_QUERY, "ImplicitQueryInfoByPriority write userId error");
        return false;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::IMPLICIT_QUERY_INFO_BY_PRIORITY, data, reply)) {
        APP_LOGE("fail to ImplicitQueryInfoByPriority from server");
        return false;
    }

    if (!reply.ReadBool()) {
        LOG_E(BMS_TAG_QUERY, "reply result false");
        return false;
    }

    std::unique_ptr<AbilityInfo> abilityInfoPtr(reply.ReadParcelable<AbilityInfo>());
    if (abilityInfoPtr == nullptr) {
        LOG_E(BMS_TAG_QUERY, "read AbilityInfo failed");
        return false;
    }
    abilityInfo = *abilityInfoPtr;

    std::unique_ptr<ExtensionAbilityInfo> extensionInfoPtr(reply.ReadParcelable<ExtensionAbilityInfo>());
    if (extensionInfoPtr == nullptr) {
        LOG_E(BMS_TAG_QUERY, "read ExtensionAbilityInfo failed");
        return false;
    }
    extensionInfo = *extensionInfoPtr;
    return true;
}

bool BundleMgrProxy::ImplicitQueryInfos(const Want &want, int32_t flags, int32_t userId, bool withDefault,
    std::vector<AbilityInfo> &abilityInfos, std::vector<ExtensionAbilityInfo> &extensionInfos, bool &findDefaultApp)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "WriteInterfaceToken failed");
        return false;
    }
    if (!data.WriteParcelable(&want)) {
        LOG_E(BMS_TAG_QUERY, "WriteParcelable want failed");
        return false;
    }
    if (!data.WriteInt32(flags)) {
        LOG_E(BMS_TAG_QUERY, "WriteInt32 flags failed");
        return false;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_QUERY, "WriteInt32 userId failed");
        return false;
    }
    if (!data.WriteBool(withDefault)) {
        LOG_E(BMS_TAG_QUERY, "WriteBool withDefault failed");
        return false;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::IMPLICIT_QUERY_INFOS, data, reply)) {
        return false;
    }
    if (!reply.ReadBool()) {
        LOG_E(BMS_TAG_QUERY, "reply result false");
        return false;
    }
    int32_t abilityInfoSize = reply.ReadInt32();
    for (int32_t i = 0; i < abilityInfoSize; i++) {
        std::unique_ptr<AbilityInfo> abilityInfoPtr(reply.ReadParcelable<AbilityInfo>());
        if (abilityInfoPtr == nullptr) {
            LOG_E(BMS_TAG_QUERY, "Read Parcelable abilityInfos failed");
            return false;
        }
        abilityInfos.emplace_back(*abilityInfoPtr);
    }
    int32_t extensionInfoSize = reply.ReadInt32();
    for (int32_t i = 0; i < extensionInfoSize; i++) {
        std::unique_ptr<ExtensionAbilityInfo> extensionInfoPtr(reply.ReadParcelable<ExtensionAbilityInfo>());
        if (extensionInfoPtr == nullptr) {
            LOG_E(BMS_TAG_QUERY, "Read Parcelable extensionInfos failed");
            return false;
        }
        extensionInfos.emplace_back(*extensionInfoPtr);
    }
    findDefaultApp = reply.ReadBool();

    return true;
}

ErrCode BundleMgrProxy::GetSandboxBundleInfo(const std::string &bundleName, int32_t appIndex, int32_t userId,
    BundleInfo &info)
{
    APP_LOGD("begin to GetSandboxBundleInfo");
    if (bundleName.empty() || appIndex <= Constants::INITIAL_SANDBOX_APP_INDEX) {
        APP_LOGE("GetSandboxBundleInfo params are invalid");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_PARAM_ERROR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("failed to GetSandboxBundleInfo due to write MessageParcel fail");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("failed to GetSandboxBundleInfo due to write bundleName fail");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(appIndex)) {
        APP_LOGE("failed to GetSandboxBundleInfo due to write appIndex fail");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_WRITE_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("failed to GetSandboxBundleInfo due to write userId fail");
        return ERR_APPEXECFWK_SANDBOX_INSTALL_WRITE_PARCEL_ERROR;
    }

    return GetParcelableInfoWithErrCode<BundleInfo>(BundleMgrInterfaceCode::GET_SANDBOX_APP_BUNDLE_INFO, data, info);
}

bool BundleMgrProxy::GetAllDependentModuleNames(const std::string &bundleName, const std::string &moduleName,
    std::vector<std::string> &dependentModuleNames)
{
    APP_LOGD("begin to GetAllDependentModuleNames");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (bundleName.empty() || moduleName.empty()) {
        APP_LOGE("bundleName or moduleName is empty");
        return false;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("failed to GetAllDependentModuleNames due to write MessageParcel fail");
        return false;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("failed to GetAllDependentModuleNames due to write bundleName fail");
        return false;
    }
    if (!data.WriteString(moduleName)) {
        APP_LOGE("failed to GetAllDependentModuleNames due to write moduleName fail");
        return false;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_ALL_DEPENDENT_MODULE_NAMES, data, reply)) {
        APP_LOGE("fail to GetAllDependentModuleNames from server");
        return false;
    }
    if (!reply.ReadBool()) {
        APP_LOGE("reply result false");
        return false;
    }
    if (!reply.ReadStringVector(&dependentModuleNames)) {
        APP_LOGE("fail to GetAllDependentModuleNames from reply");
        return false;
    }
    return true;
}

bool BundleMgrProxy::ObtainCallingBundleName(std::string &bundleName)
{
    APP_LOGD("begin to ObtainCallingBundleName");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("failed to ObtainCallingBundleName due to write MessageParcel fail");
        return false;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::QUERY_CALLING_BUNDLE_NAME, data, reply)) {
        APP_LOGE("fail to ObtainCallingBundleName from server");
        return false;
    }
    if (!reply.ReadBool()) {
        APP_LOGE("reply result false");
        return false;
    }
    bundleName = reply.ReadString();
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        return false;
    }
    return true;
}

bool BundleMgrProxy::GetBundleStats(const std::string &bundleName, int32_t userId,
    std::vector<int64_t> &bundleStats, int32_t appIndex, uint32_t statFlag)
{
    APP_LOGI("begin %{public}s", bundleName.c_str());
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("failed to GetBundleStats due to write MessageParcel fail");
        return false;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to GetBundleStats due to write bundleName fail");
        return false;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to GetBundleStats due to write userId fail");
        return false;
    }
    if (!data.WriteInt32(appIndex)) {
        APP_LOGE("fail to GetBundleStats due to write appIndex fail");
        return false;
    }
    if (!data.WriteUint32(statFlag)) {
        APP_LOGE("fail to GetBundleStats due to write statFlag fail");
        return false;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_BUNDLE_STATS, data, reply)) {
        APP_LOGE("fail to GetBundleStats from server");
        return false;
    }
    if (!reply.ReadBool()) {
        APP_LOGE("reply result false");
        return false;
    }
    if (!reply.ReadInt64Vector(&bundleStats)) {
        APP_LOGE("fail to GetBundleStats from reply");
        return false;
    }
    APP_LOGI("end %{public}s", bundleName.c_str());
    return true;
}

bool BundleMgrProxy::GetAllBundleStats(int32_t userId, std::vector<int64_t> &bundleStats)
{
    APP_LOGI("GetAllBundleStats start");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("failed to GetAllBundleStats due to write MessageParcel fail");
        return false;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to GetAllBundleStats due to write userId fail");
        return false;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_ALL_BUNDLE_STATS, data, reply)) {
        APP_LOGE("fail to GetAllBundleStats from server");
        return false;
    }
    if (!reply.ReadBool()) {
        APP_LOGE("reply result false");
        return false;
    }
    if (!reply.ReadInt64Vector(&bundleStats)) {
        APP_LOGE("fail to GetAllBundleStats from reply");
        return false;
    }
    APP_LOGI("GetAllBundleStats end");
    return true;
}

bool BundleMgrProxy::CheckAbilityEnableInstall(
    const Want &want, int32_t missionId, int32_t userId, const sptr<IRemoteObject> &callback)
{
    APP_LOGD("begin to CheckAbilityEnableInstall");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("failed to CheckAbilityEnableInstall due to write MessageParcel fail");
        return false;
    }

    if (!data.WriteParcelable(&want)) {
        APP_LOGE("fail to CheckAbilityEnableInstall due to write want fail");
        return false;
    }

    if (!data.WriteInt32(missionId)) {
        APP_LOGE("fail to CheckAbilityEnableInstall due to write missionId fail");
        return false;
    }

    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to CheckAbilityEnableInstall due to write userId fail");
        return false;
    }

    if (!data.WriteRemoteObject(callback)) {
        APP_LOGE("fail to callback, for write parcel");
        return false;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::CHECK_ABILITY_ENABLE_INSTALL, data, reply)) {
        return false;
    }
    return reply.ReadBool();
}

std::string BundleMgrProxy::GetStringById(const std::string &bundleName, const std::string &moduleName,
    uint32_t resId, int32_t userId, const std::string &localeInfo)
{
    APP_LOGD("begin to GetStringById");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (bundleName.empty() || moduleName.empty()) {
        APP_LOGE("fail to GetStringById due to params empty");
        return Constants::EMPTY_STRING;
    }
    APP_LOGD("GetStringById bundleName: %{public}s, moduleName: %{public}s, resId:%{public}d",
        bundleName.c_str(), moduleName.c_str(), resId);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetStringById due to write InterfaceToken fail");
        return Constants::EMPTY_STRING;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to GetStringById due to write bundleName fail");
        return Constants::EMPTY_STRING;
    }
    if (!data.WriteString(moduleName)) {
        APP_LOGE("fail to GetStringById due to write moduleName fail");
        return Constants::EMPTY_STRING;
    }
    if (!data.WriteUint32(resId)) {
        APP_LOGE("fail to GetStringById due to write resId fail");
        return Constants::EMPTY_STRING;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to GetStringById due to write userId fail");
        return Constants::EMPTY_STRING;
    }
    if (!data.WriteString(localeInfo)) {
        APP_LOGE("fail to GetStringById due to write localeInfo fail");
        return Constants::EMPTY_STRING;
    }
    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_STRING_BY_ID, data, reply)) {
        APP_LOGE("fail to GetStringById from server");
        return Constants::EMPTY_STRING;
    }
    return reply.ReadString();
}

std::string BundleMgrProxy::GetIconById(
    const std::string &bundleName, const std::string &moduleName, uint32_t resId, uint32_t density, int32_t userId)
{
    APP_LOGD("begin to GetIconById");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (bundleName.empty() || moduleName.empty()) {
        APP_LOGE("fail to GetIconById due to params empty");
        return Constants::EMPTY_STRING;
    }
    APP_LOGD("GetIconById bundleName: %{public}s, moduleName: %{public}s, resId:%{public}d",
        bundleName.c_str(), moduleName.c_str(), resId);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetIconById due to write InterfaceToken fail");
        return Constants::EMPTY_STRING;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to GetIconById due to write bundleName fail");
        return Constants::EMPTY_STRING;
    }

    if (!data.WriteString(moduleName)) {
        APP_LOGE("fail to GetIconById due to write moduleName fail");
        return Constants::EMPTY_STRING;
    }
    if (!data.WriteUint32(resId)) {
        APP_LOGE("fail to GetIconById due to write resId fail");
        return Constants::EMPTY_STRING;
    }
    if (!data.WriteUint32(density)) {
        APP_LOGE("fail to GetIconById due to write density fail");
        return Constants::EMPTY_STRING;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to GetIconById due to write userId fail");
        return Constants::EMPTY_STRING;
    }
    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_ICON_BY_ID, data, reply)) {
        APP_LOGE("fail to GetIconById from server");
        return Constants::EMPTY_STRING;
    }
    return reply.ReadString();
}

#ifdef BUNDLE_FRAMEWORK_DEFAULT_APP
sptr<IDefaultApp> BundleMgrProxy::GetDefaultAppProxy()
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to get default app proxy due to write InterfaceToken failed");
        return nullptr;
    }
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_DEFAULT_APP_PROXY, data, reply)) {
        return nullptr;
    }

    sptr<IRemoteObject> object = reply.ReadRemoteObject();
    if (object == nullptr) {
        APP_LOGE("reply failed");
        return nullptr;
    }
    sptr<IDefaultApp> defaultAppProxy = iface_cast<IDefaultApp>(object);
    if (defaultAppProxy == nullptr) {
        APP_LOGE("defaultAppProxy is nullptr");
    }

    return defaultAppProxy;
}
#endif

#ifdef BUNDLE_FRAMEWORK_APP_CONTROL
sptr<IAppControlMgr> BundleMgrProxy::GetAppControlProxy()
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to get app control proxy due to write InterfaceToken failed");
        return nullptr;
    }
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_APP_CONTROL_PROXY, data, reply)) {
        return nullptr;
    }

    sptr<IRemoteObject> object = reply.ReadRemoteObject();
    if (object == nullptr) {
        APP_LOGE("reply failed");
        return nullptr;
    }
    sptr<IAppControlMgr> appControlProxy = iface_cast<IAppControlMgr>(object);
    if (appControlProxy == nullptr) {
        APP_LOGE("appControlProxy is nullptr");
    }

    return appControlProxy;
}
#endif

ErrCode BundleMgrProxy::GetSandboxAbilityInfo(const Want &want, int32_t appIndex, int32_t flags, int32_t userId,
    AbilityInfo &info)
{
    APP_LOGD("begin to GetSandboxAbilityInfo");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (appIndex <= Constants::INITIAL_SANDBOX_APP_INDEX || appIndex > Constants::MAX_SANDBOX_APP_INDEX) {
        APP_LOGE("GetSandboxAbilityInfo params are invalid");
        return ERR_APPEXECFWK_SANDBOX_QUERY_INTERNAL_ERROR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        APP_LOGE("WriteParcelable want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(appIndex)) {
        APP_LOGE("failed to GetSandboxAbilityInfo due to write appIndex fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(flags)) {
        APP_LOGE("failed to GetSandboxAbilityInfo due to write flags fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("failed to GetSandboxAbilityInfo due to write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return GetParcelableInfoWithErrCode<AbilityInfo>(
        BundleMgrInterfaceCode::GET_SANDBOX_APP_ABILITY_INFO, data, info);
}

ErrCode BundleMgrProxy::GetSandboxExtAbilityInfos(const Want &want, int32_t appIndex, int32_t flags, int32_t userId,
    std::vector<ExtensionAbilityInfo> &infos)
{
    APP_LOGD("begin to GetSandboxExtAbilityInfos");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (appIndex <= Constants::INITIAL_SANDBOX_APP_INDEX || appIndex > Constants::MAX_SANDBOX_APP_INDEX) {
        APP_LOGE("appIndex is invalid,: %{public}d,", appIndex);
        return ERR_APPEXECFWK_SANDBOX_QUERY_INTERNAL_ERROR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        APP_LOGE("WriteParcelable want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(appIndex)) {
        APP_LOGE("failed to GetSandboxExtAbilityInfos due to write appIndex fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(flags)) {
        APP_LOGE("failed to GetSandboxExtAbilityInfos due to write flags fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("failed to GetSandboxExtAbilityInfos due to write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return GetParcelableInfosWithErrCode<ExtensionAbilityInfo>(
        BundleMgrInterfaceCode::GET_SANDBOX_APP_EXTENSION_INFOS, data, infos);
}

ErrCode BundleMgrProxy::GetSandboxHapModuleInfo(const AbilityInfo &abilityInfo, int32_t appIndex, int32_t userId,
    HapModuleInfo &info)
{
    APP_LOGD("begin to GetSandboxHapModuleInfo");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (appIndex <= Constants::INITIAL_SANDBOX_APP_INDEX || appIndex > Constants::MAX_SANDBOX_APP_INDEX) {
        APP_LOGE("GetSandboxHapModuleInfo params are invalid");
        return ERR_APPEXECFWK_SANDBOX_QUERY_INTERNAL_ERROR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("WriteInterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&abilityInfo)) {
        APP_LOGE("WriteParcelable want failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(appIndex)) {
        APP_LOGE("failed to GetSandboxHapModuleInfo due to write flags fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("failed to GetSandboxHapModuleInfo due to write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return GetParcelableInfoWithErrCode<HapModuleInfo>(BundleMgrInterfaceCode::GET_SANDBOX_MODULE_INFO, data, info);
}

ErrCode BundleMgrProxy::GetMediaData(const std::string &bundleName, const std::string &moduleName,
    const std::string &abilityName, std::unique_ptr<uint8_t[]> &mediaDataPtr, size_t &len, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to get media data of %{public}s, %{public}s", bundleName.c_str(), abilityName.c_str());
    if (bundleName.empty() || abilityName.empty()) {
        APP_LOGE("fail to GetMediaData due to params empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetMediaData due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to GetMediaData due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(abilityName)) {
        APP_LOGE("fail to GetMediaData due to write abilityName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(moduleName)) {
        APP_LOGE("fail to GetMediaData due to write abilityName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to GetMediaData due to write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_MEDIA_DATA, data, reply)) {
        APP_LOGE("SendTransactCmd result false");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        APP_LOGE("host return error : %{public}d", ret);
        return ret;
    }
    return GetMediaDataFromAshMem(reply, mediaDataPtr, len);
}

ErrCode BundleMgrProxy::GetMediaDataFromAshMem(
    MessageParcel &reply, std::unique_ptr<uint8_t[]> &mediaDataPtr, size_t &len)
{
    sptr<Ashmem> ashMem = reply.ReadAshmem();
    if (ashMem == nullptr) {
        APP_LOGE("Ashmem is nullptr");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!ashMem->MapReadOnlyAshmem()) {
        APP_LOGE("MapReadOnlyAshmem failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t ashMemSize = ashMem->GetAshmemSize();
    int32_t offset = 0;
    const uint8_t* ashDataPtr = reinterpret_cast<const uint8_t*>(ashMem->ReadFromAshmem(ashMemSize, offset));
    if (ashDataPtr == nullptr) {
        APP_LOGE("ashDataPtr is nullptr");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    len = static_cast<size_t>(ashMemSize);
    mediaDataPtr = std::make_unique<uint8_t[]>(len);
    if (memcpy_s(mediaDataPtr.get(), len, ashDataPtr, len) != 0) {
        mediaDataPtr.reset();
        len = 0;
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

sptr<IQuickFixManager> BundleMgrProxy::GetQuickFixManagerProxy()
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to get quick fix manager proxy due to write InterfaceToken failed");
        return nullptr;
    }
    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_QUICK_FIX_MANAGER_PROXY, data, reply)) {
        return nullptr;
    }

    sptr<IRemoteObject> object = reply.ReadRemoteObject();
    if (object == nullptr) {
        APP_LOGE("reply failed");
        return nullptr;
    }
    sptr<IQuickFixManager> quickFixManagerProxy = iface_cast<IQuickFixManager>(object);
    if (quickFixManagerProxy == nullptr) {
        APP_LOGE("quickFixManagerProxy is nullptr");
    }

    return quickFixManagerProxy;
}

ErrCode BundleMgrProxy::SetDebugMode(bool isDebug)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to get bundle manager proxy due to write InterfaceToken failed");
        return ERR_BUNDLEMANAGER_SET_DEBUG_MODE_PARCEL_ERROR;
    }
    if (!data.WriteBool(isDebug)) {
        APP_LOGE("fail to SetDebugMode due to write bundleName fail");
        return ERR_BUNDLEMANAGER_SET_DEBUG_MODE_PARCEL_ERROR;
    }
    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::SET_DEBUG_MODE, data, reply)) {
        return ERR_BUNDLEMANAGER_SET_DEBUG_MODE_SEND_REQUEST_ERROR;
    }

    return reply.ReadInt32();
}

bool BundleMgrProxy::VerifySystemApi(int32_t beginApiVersion)
{
    APP_LOGD("begin to verify system app");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to VerifySystemApi due to write InterfaceToken fail");
        return false;
    }

    if (!data.WriteInt32(beginApiVersion)) {
        APP_LOGE("fail to VerifySystemApi due to write apiVersion fail");
        return false;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::VERIFY_SYSTEM_API, data, reply)) {
        APP_LOGE("fail to sendRequest");
        return false;
    }
    return reply.ReadBool();
}

bool BundleMgrProxy::ProcessPreload(const Want &want)
{
    APP_LOGD("BundleMgrProxy::ProcessPreload is called");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to ProcessPreload due to write InterfaceToken fail");
        return false;
    }
    if (!data.WriteParcelable(&want)) {
        APP_LOGE("fail to ProcessPreload due to write want fail");
        return false;
    }
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    auto remoteObj = Remote();
    if (remoteObj == nullptr) {
        APP_LOGE("remote is null");
        return false;
    }
    auto res = remoteObj->SendRequest(
        static_cast<uint32_t>(BundleMgrInterfaceCode::PROCESS_PRELOAD), data, reply, option);
    if (res != ERR_OK) {
        APP_LOGE("SendRequest fail, error: %{public}d", res);
        return false;
    }
    return reply.ReadBool();
}

sptr<IOverlayManager> BundleMgrProxy::GetOverlayManagerProxy()
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to get bundle manager proxy due to write InterfaceToken failed");
        return nullptr;
    }
    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_OVERLAY_MANAGER_PROXY, data, reply)) {
        return nullptr;
    }

    sptr<IRemoteObject> object = reply.ReadRemoteObject();
    if (object == nullptr) {
        APP_LOGE("reply failed");
        return nullptr;
    }
    sptr<IOverlayManager> overlayManagerProxy = iface_cast<IOverlayManager>(object);
    if (overlayManagerProxy == nullptr) {
        APP_LOGE("overlayManagerProxy is nullptr");
    }

    return overlayManagerProxy;
}

ErrCode BundleMgrProxy::GetAppProvisionInfo(const std::string &bundleName, int32_t userId,
    AppProvisionInfo &appProvisionInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to get AppProvisionInfo of %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        APP_LOGE("fail to GetAppProvisionInfo due to params empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetAppProvisionInfo due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to GetAppProvisionInfo due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to GetAppProvisionInfo due to write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetParcelableInfoWithErrCode<AppProvisionInfo>(BundleMgrInterfaceCode::GET_APP_PROVISION_INFO,
        data, appProvisionInfo);
}

ErrCode BundleMgrProxy::GetBaseSharedBundleInfos(const std::string &bundleName,
    std::vector<BaseSharedBundleInfo> &baseSharedBundleInfos, GetDependentBundleInfoFlag flag)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to get base shared package infos");
    if (bundleName.empty()) {
        APP_LOGE("fail to GetBaseSharedBundleInfos due to bundleName empty");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetBaseSharedBundleInfos due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to GetBaseSharedBundleInfos due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteUint32(static_cast<uint32_t>(flag))) {
        APP_LOGE("fail to GetBaseSharedBundleInfos due to write flag fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetParcelableInfosWithErrCode<BaseSharedBundleInfo>(BundleMgrInterfaceCode::GET_BASE_SHARED_BUNDLE_INFOS,
        data, baseSharedBundleInfos);
}

ErrCode BundleMgrProxy::GetAllSharedBundleInfo(std::vector<SharedBundleInfo> &sharedBundles)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to GetAllSharedBundleInfo");

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetAllSharedBundleInfo due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetParcelableInfosWithErrCode<SharedBundleInfo>(BundleMgrInterfaceCode::GET_ALL_SHARED_BUNDLE_INFO,
        data, sharedBundles);
}

ErrCode BundleMgrProxy::GetSharedBundleInfo(const std::string &bundleName, const std::string &moduleName,
    std::vector<SharedBundleInfo> &sharedBundles)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to GetSharedBundleInfo");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetSharedBundleInfo due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to GetSharedBundleInfo due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(moduleName)) {
        APP_LOGE("fail to GetSharedBundleInfo due to write moduleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetParcelableInfosWithErrCode<SharedBundleInfo>(BundleMgrInterfaceCode::GET_SHARED_BUNDLE_INFO,
        data, sharedBundles);
}

ErrCode BundleMgrProxy::GetSharedBundleInfoBySelf(const std::string &bundleName, SharedBundleInfo &sharedBundleInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to GetSharedBundleInfoBySelf");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetSharedBundleInfoBySelf due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to GetSharedBundleInfoBySelf due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetParcelableInfoWithErrCode<SharedBundleInfo>(BundleMgrInterfaceCode::GET_SHARED_BUNDLE_INFO_BY_SELF,
        data, sharedBundleInfo);
}

ErrCode BundleMgrProxy::GetSharedDependencies(const std::string &bundleName, const std::string &moduleName,
    std::vector<Dependency> &dependencies)
{
    APP_LOGD("begin to GetSharedDependencies");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (bundleName.empty() || moduleName.empty()) {
        APP_LOGE("bundleName or moduleName is empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetSharedDependencies due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to GetSharedDependencies due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(moduleName)) {
        APP_LOGE("fail to GetSharedDependencies due to write moduleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetParcelableInfosWithErrCode<Dependency>(
        BundleMgrInterfaceCode::GET_SHARED_DEPENDENCIES, data, dependencies);
}

ErrCode BundleMgrProxy::GetProxyDataInfos(const std::string &bundleName, const std::string &moduleName,
    std::vector<ProxyData> &proxyDatas, int32_t userId)
{
    APP_LOGD("begin to GetProxyDataInfos");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetProxyDataInfos due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to GetProxyDataInfos due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(moduleName)) {
        APP_LOGE("fail to GetProxyDataInfos due to write moduleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to GetProxyDataInfos due to write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetParcelableInfosWithErrCode<ProxyData>(BundleMgrInterfaceCode::GET_PROXY_DATA_INFOS, data, proxyDatas);
}

ErrCode BundleMgrProxy::GetAllProxyDataInfos(std::vector<ProxyData> &proxyDatas, int32_t userId)
{
    APP_LOGD("begin to GetAllProxyDatas");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetAllProxyDatas due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to GetProxyDataInfos due to write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetParcelableInfosWithErrCode<ProxyData>(
        BundleMgrInterfaceCode::GET_ALL_PROXY_DATA_INFOS, data, proxyDatas);
}

ErrCode BundleMgrProxy::GetSpecifiedDistributionType(const std::string &bundleName,
    std::string &specifiedDistributionType)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (bundleName.empty()) {
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetSpecifiedDistributionType due to write InterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to GetSpecifiedDistributionType due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_SPECIFIED_DISTRIBUTED_TYPE, data, reply)) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto ret = reply.ReadInt32();
    if (ret == ERR_OK) {
        specifiedDistributionType = reply.ReadString();
    }
    return ret;
}

ErrCode BundleMgrProxy::GetAdditionalInfo(const std::string &bundleName,
    std::string &additionalInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (bundleName.empty()) {
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetAdditionalInfo due to write InterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to GetAdditionalInfo due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_ADDITIONAL_INFO, data, reply)) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto ret = reply.ReadInt32();
    if (ret == ERR_OK) {
        additionalInfo = reply.ReadString();
    }
    return ret;
}

ErrCode BundleMgrProxy::GetAdditionalInfoForAllUser(const std::string &bundleName,
    std::string &additionalInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (bundleName.empty()) {
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetAdditionalInfo due to write InterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to GetAdditionalInfo due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_ADDITIONAL_INFO_FOR_ALL_USER, data, reply)) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto ret = reply.ReadInt32();
    if (ret == ERR_OK) {
        additionalInfo = reply.ReadString();
    }
    return ret;
}

ErrCode BundleMgrProxy::SetExtNameOrMIMEToApp(const std::string &bundleName, const std::string &moduleName,
    const std::string &abilityName, const std::string &extName, const std::string &mimeType)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (bundleName.empty() || moduleName.empty() || abilityName.empty()) {
        APP_LOGE("bundleName, moduleName or abilityName is empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    if (extName.empty() && mimeType.empty()) {
        APP_LOGE("extName and mimeType are empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to SetExtNameOrMIMEToApp due to write InterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to SetExtNameOrMIMEToApp due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(moduleName)) {
        APP_LOGE("fail to SetExtNameOrMIMEToApp due to write moduleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(abilityName)) {
        APP_LOGE("fail to SetExtNameOrMIMEToApp due to write abilityName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(extName)) {
        APP_LOGE("fail to SetExtNameOrMIMEToApp due to write extName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(mimeType)) {
        APP_LOGE("fail to SetExtNameOrMIMEToApp due to write mimeType fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::SET_EXT_NAME_OR_MIME_TO_APP, data, reply)) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto ret = reply.ReadInt32();
    return ret;
}

ErrCode BundleMgrProxy::DelExtNameOrMIMEToApp(const std::string &bundleName, const std::string &moduleName,
    const std::string &abilityName, const std::string &extName, const std::string &mimeType)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (bundleName.empty() || moduleName.empty() || abilityName.empty()) {
        APP_LOGE("bundleName, moduleName or abilityName is empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    if (extName.empty() && mimeType.empty()) {
        APP_LOGE("extName and mimeType are empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to DelExtNameOrMIMEToApp due to write InterfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to DelExtNameOrMIMEToApp due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(moduleName)) {
        APP_LOGE("fail to DelExtNameOrMIMEToApp due to write moduleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(abilityName)) {
        APP_LOGE("fail to DelExtNameOrMIMEToApp due to write abilityName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(extName)) {
        APP_LOGE("fail to DelExtNameOrMIMEToApp due to write extName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(mimeType)) {
        APP_LOGE("fail to DelExtNameOrMIMEToApp due to write mimeType fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::DEL_EXT_NAME_OR_MIME_TO_APP, data, reply)) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto ret = reply.ReadInt32();
    return ret;
}

bool BundleMgrProxy::QueryDataGroupInfos(const std::string &bundleName,
    int32_t userId, std::vector<DataGroupInfo> &infos)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        return false;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to QueryDataGroupInfos due to write InterfaceToken failed");
        return false;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to QueryDataGroupInfos due to write dataGroupId fail");
        return false;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to QueryDataGroupInfos due to write userId fail");
        return false;
    }

    if (!GetParcelableInfos<DataGroupInfo>(BundleMgrInterfaceCode::QUERY_DATA_GROUP_INFOS, data, infos)) {
        APP_LOGE("failed to QueryDataGroupInfos from server");
        return false;
    }
    return true;
}

bool BundleMgrProxy::GetGroupDir(const std::string &dataGroupId, std::string &dir)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (dataGroupId.empty()) {
        APP_LOGE("dataGroupId is empty");
        return false;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetGroupDir due to write InterfaceToken failed");
        return false;
    }
    if (!data.WriteString(dataGroupId)) {
        APP_LOGE("fail to GetGroupDir due to write dataGroupId fail");
        return false;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_PREFERENCE_DIR_BY_GROUP_ID, data, reply)) {
        APP_LOGE("fail to GetGroupDir from server");
        return false;
    }
    if (!reply.ReadBool()) {
        APP_LOGE("reply result false");
        return false;
    }
    dir = reply.ReadString();
    return true;
}

bool BundleMgrProxy::QueryAppGalleryBundleName(std::string &bundleName)
{
    APP_LOGD("QueryAppGalleryBundleName in bundle proxy start");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to QueryAppGalleryBundleName due to write InterfaceToken failed");
        return false;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::QUERY_APPGALLERY_BUNDLE_NAME, data, reply)) {
        APP_LOGE("fail to QueryAppGalleryBundleName from server");
        return false;
    }
    if (!reply.ReadBool()) {
        APP_LOGE("reply result false");
        return false;
    }
    bundleName = reply.ReadString();
    if (bundleName.length() > Constants::MAX_BUNDLE_NAME) {
        APP_LOGE("reply result false");
        return false;
    }
    APP_LOGD("bundleName is %{public}s", bundleName.c_str());
    return true;
}

ErrCode BundleMgrProxy::QueryExtensionAbilityInfosWithTypeName(const Want &want, const std::string &extensionTypeName,
    const int32_t flag, const int32_t userId, std::vector<ExtensionAbilityInfo> &extensionInfos)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "Write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&want)) {
        LOG_E(BMS_TAG_QUERY, "Write want fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(extensionTypeName)) {
        LOG_E(BMS_TAG_QUERY, "Write type fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(flag)) {
        LOG_E(BMS_TAG_QUERY, "Write flag fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_QUERY, "Write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetParcelableInfosWithErrCode(BundleMgrInterfaceCode::QUERY_EXTENSION_ABILITY_INFO_WITH_TYPE_NAME,
        data, extensionInfos);
}

ErrCode BundleMgrProxy::QueryExtensionAbilityInfosOnlyWithTypeName(const std::string &extensionTypeName,
    const uint32_t flag, const int32_t userId, std::vector<ExtensionAbilityInfo> &extensionInfos)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("Write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(extensionTypeName)) {
        APP_LOGE("Write type fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteUint32(flag)) {
        APP_LOGE("Write flag fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("Write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetVectorFromParcelIntelligentWithErrCode(
        BundleMgrInterfaceCode::QUERY_EXTENSION_ABILITY_INFO_ONLY_WITH_TYPE_NAME, data,
        extensionInfos);
}

ErrCode BundleMgrProxy::ResetAOTCompileStatus(const std::string &bundleName, const std::string &moduleName,
    int32_t triggerMode)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("ResetAOTCompileStatus begin, bundleName : %{public}s, moduleName : %{public}s, triggerMode : %{public}d",
        bundleName.c_str(), moduleName.c_str(), triggerMode);
    if (bundleName.empty() || moduleName.empty()) {
        APP_LOGE("invalid param");
        return ERR_BUNDLE_MANAGER_INVALID_PARAMETER;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("write interfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("write bundleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(moduleName)) {
        APP_LOGE("write moduleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(triggerMode)) {
        APP_LOGE("write triggerMode failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::RESET_AOT_COMPILE_STATUS, data, reply)) {
        APP_LOGE("SendTransactCmd failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return reply.ReadInt32();
}

ErrCode BundleMgrProxy::GetJsonProfile(ProfileType profileType, const std::string &bundleName,
    const std::string &moduleName, std::string &profile, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to GetJsonProfile");
    if (bundleName.empty()) {
        APP_LOGE("bundleName is empty");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetJsonProfile due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(profileType)) {
        APP_LOGE("fail to GetJsonProfile due to write flags fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to GetJsonProfile due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(moduleName)) {
        APP_LOGE("fail to GetJsonProfile due to write moduleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to GetBundleInfo due to write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return GetBigString(BundleMgrInterfaceCode::GET_JSON_PROFILE, data, profile);
}

sptr<IBundleResource> BundleMgrProxy::GetBundleResourceProxy()
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("write InterfaceToken failed");
        return nullptr;
    }
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_BUNDLE_RESOURCE_PROXY, data, reply)) {
        return nullptr;
    }

    sptr<IRemoteObject> object = reply.ReadRemoteObject();
    if (object == nullptr) {
        APP_LOGE("reply failed");
        return nullptr;
    }
    sptr<IBundleResource> bundleResourceProxy = iface_cast<IBundleResource>(object);
    if (bundleResourceProxy == nullptr) {
        APP_LOGE("bundleResourceProxy is nullptr");
    }

    return bundleResourceProxy;
}

ErrCode BundleMgrProxy::GetRecoverableApplicationInfo(
    std::vector<RecoverableApplicationInfo> &recoverableApplications)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to GetRecoverableApplicationInfo");

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetRecoverableApplicationInfo due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetParcelableInfosWithErrCode<RecoverableApplicationInfo>(
        BundleMgrInterfaceCode::GET_RECOVERABLE_APPLICATION_INFO, data, recoverableApplications);
}

ErrCode BundleMgrProxy::GetUninstalledBundleInfo(const std::string bundleName, BundleInfo &bundleInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to GetUninstalledBundleInfo of %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        APP_LOGE("fail to GetUninstalledBundleInfo due to params empty");
        return ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetUninstalledBundleInfo due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to GetUninstalledBundleInfo due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    auto res = GetParcelableInfoWithErrCode<BundleInfo>(
        BundleMgrInterfaceCode::GET_UNINSTALLED_BUNDLE_INFO, data, bundleInfo);
    if (res != ERR_OK) {
        APP_LOGE_NOFUNC("GetUninstalledBundleInfo failed: %{public}d", res);
        return res;
    }
    return ERR_OK;
}

ErrCode BundleMgrProxy::SetAdditionalInfo(const std::string &bundleName, const std::string &additionalInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("Called. BundleName : %{public}s", bundleName.c_str());
    if (bundleName.empty()) {
        APP_LOGE("Invalid param");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("Write interfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("Write bundleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(additionalInfo)) {
        APP_LOGE("Write additionalInfo failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::SET_ADDITIONAL_INFO, data, reply)) {
        APP_LOGE("Call failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return reply.ReadInt32();
}

ErrCode BundleMgrProxy::CreateBundleDataDir(int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("CreateBundleDataDir Called. userId: %{public}d", userId);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("Write interfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to CreateBundleDataDir due to write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::CREATE_BUNDLE_DATA_DIR, data, reply)) {
        APP_LOGE("Call failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return reply.ReadInt32();
}

ErrCode BundleMgrProxy::CreateBundleDataDirWithEl(int32_t userId, DataDirEl dirEl)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("Called. userId: %{public}d el: %{public}d", userId, static_cast<uint8_t>(dirEl));
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("Write interfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to CreateBundleDataDirWithEl due to write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteUint8(static_cast<uint8_t>(dirEl))) {
        APP_LOGE("fail to CreateBundleDataDirWithEl due to write dirEl fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::CREATE_BUNDLE_DATA_DIR_WITH_EL, data, reply)) {
        APP_LOGE("Call failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return reply.ReadInt32();
}

ErrCode BundleMgrProxy::MigrateData(const std::vector<std::string> &sourcePaths, const std::string &destinationPath)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("MigrateData Called");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("Write interfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteStringVector(sourcePaths)) {
        APP_LOGE("fail to MigrateData due to write sourcePaths fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(destinationPath)) {
        APP_LOGE("fail to MigrateData due to write destinationPath fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::MIGRATE_DATA, data, reply)) {
        APP_LOGE("Call failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return reply.ReadInt32();
}

ErrCode BundleMgrProxy::GetOdid(std::string &odid)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("GetOdid Called");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("Write interfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_ODID, data, reply)) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto ret = reply.ReadInt32();
    if (ret == ERR_OK) {
        odid = reply.ReadString();
    }
    APP_LOGD("GetOdid ret: %{public}d, odid: %{private}s", ret, odid.c_str());
    return ret;
}

ErrCode BundleMgrProxy::GetAllBundleInfoByDeveloperId(const std::string &developerId,
    std::vector<BundleInfo> &bundleInfos, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGI("begin GetAllBundleInfoByDeveloperId, developerId: %{public}s, userId :%{public}d",
        developerId.c_str(), userId);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetAllBundleInfoByDeveloperId due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(developerId)) {
        APP_LOGE("failed to GetAllBundleInfoByDeveloperId due to write developerId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to GetAllBundleInfoByDeveloperId due to write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetVectorFromParcelIntelligentWithErrCode<BundleInfo>(
        BundleMgrInterfaceCode::GET_ALL_BUNDLE_INFO_BY_DEVELOPER_ID, data, bundleInfos);
}

ErrCode BundleMgrProxy::GetDeveloperIds(const std::string &appDistributionType,
    std::vector<std::string> &developerIdList, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGI("begin to GetDeveloperIds of %{public}s", appDistributionType.c_str());
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetDeveloperIds due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(appDistributionType)) {
        APP_LOGE("failed to GetDeveloperIds due to write appDistributionType fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to GetDeveloperIds due to write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_DEVELOPER_IDS, data, reply)) {
        APP_LOGE("SendTransactCmd failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode res = reply.ReadInt32();
    if (res != ERR_OK) {
        APP_LOGE("host reply err %{public}d", res);
        return res;
    }
    if (!reply.ReadStringVector(&developerIdList)) {
        APP_LOGE("fail to GetDeveloperIds from reply");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

template<typename T>
bool BundleMgrProxy::GetParcelableInfo(BundleMgrInterfaceCode code, MessageParcel &data, T &parcelableInfo)
{
    MessageParcel reply;
    if (!SendTransactCmd(code, data, reply)) {
        return false;
    }

    if (!reply.ReadBool()) {
        APP_LOGE_NOFUNC("GetParcelableInfo reply false");
        return false;
    }

    std::unique_ptr<T> info(reply.ReadParcelable<T>());
    if (info == nullptr) {
        APP_LOGE("readParcelableInfo failed");
        return false;
    }
    parcelableInfo = *info;
    APP_LOGD("get parcelable info success");
    return true;
}

template <typename T>
ErrCode BundleMgrProxy::GetParcelableInfoWithErrCode(
    BundleMgrInterfaceCode code, MessageParcel &data, T &parcelableInfo)
{
    MessageParcel reply;
    if (!SendTransactCmd(code, data, reply)) {
        APP_LOGE("SendTransactCmd failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    ErrCode res = reply.ReadInt32();
    if (res == ERR_OK) {
        std::unique_ptr<T> info(reply.ReadParcelable<T>());
        if (info == nullptr) {
            APP_LOGE("readParcelableInfo failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        parcelableInfo = *info;
    }

    APP_LOGD("GetParcelableInfoWithErrCode ErrCode : %{public}d", res);
    return res;
}

template<typename T>
bool BundleMgrProxy::GetParcelableInfos(
    BundleMgrInterfaceCode code, MessageParcel &data, std::vector<T> &parcelableInfos)
{
    MessageParcel reply;
    if (!SendTransactCmd(code, data, reply)) {
        return false;
    }

    if (!reply.ReadBool()) {
        APP_LOGE("readParcelableInfo failed");
        return false;
    }

    int32_t infoSize = reply.ReadInt32();
    CONTAINER_SECURITY_VERIFY(reply, infoSize, &parcelableInfos);
    for (int32_t i = 0; i < infoSize; i++) {
        std::unique_ptr<T> info(reply.ReadParcelable<T>());
        if (info == nullptr) {
            APP_LOGE("Read Parcelable infos failed");
            return false;
        }
        parcelableInfos.emplace_back(*info);
    }
    APP_LOGD("get parcelable infos success");
    return true;
}

template<typename T>
ErrCode BundleMgrProxy::GetParcelableInfosWithErrCode(BundleMgrInterfaceCode code, MessageParcel &data,
    std::vector<T> &parcelableInfos)
{
    MessageParcel reply;
    if (!SendTransactCmd(code, data, reply)) {
        APP_LOGE("SendTransactCmd failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    ErrCode res = reply.ReadInt32();
    if (res == ERR_OK) {
        int32_t infoSize = reply.ReadInt32();
        CONTAINER_SECURITY_VERIFY(reply, infoSize, &parcelableInfos);
        for (int32_t i = 0; i < infoSize; i++) {
            std::unique_ptr<T> info(reply.ReadParcelable<T>());
            if (info == nullptr) {
                APP_LOGE("Read Parcelable infos failed");
                return ERR_APPEXECFWK_PARCEL_ERROR;
            }
            parcelableInfos.emplace_back(*info);
        }
        APP_LOGD("get parcelable infos success");
    }
    APP_LOGD("GetParcelableInfosWithErrCode ErrCode : %{public}d", res);
    return res;
}

template<typename T>
ErrCode BundleMgrProxy::GetParcelInfoIntelligent(
    BundleMgrInterfaceCode code, MessageParcel &data, T &parcelInfo)
{
    MessageParcel reply;
    ErrCode ret = SendTransactCmdWithErrCode(code, data, reply);
    if (ret != ERR_OK) {
        APP_LOGE("SendTransactCmd failed");
        return ret;
    }
    ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        APP_LOGE_NOFUNC("reply ErrCode: %{public}d", ret);
        return ret;
    }
    size_t dataSize = reply.ReadUint32();
    void *buffer = nullptr;
    if (!GetData(buffer, dataSize, reply.ReadRawData(dataSize))) {
        APP_LOGE("GetData failed dataSize : %{public}zu", dataSize);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel tmpParcel;
    if (!tmpParcel.ParseFrom(reinterpret_cast<uintptr_t>(buffer), dataSize)) {
        APP_LOGE("ParseFrom failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    std::unique_ptr<T> info(tmpParcel.ReadParcelable<T>());
    if (info == nullptr) {
        APP_LOGE("ReadParcelable failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    parcelInfo = *info;
    return ERR_OK;
}

template<typename T>
bool BundleMgrProxy::GetVectorFromParcelIntelligent(
    BundleMgrInterfaceCode code, MessageParcel &data, std::vector<T> &parcelableInfos)
{
    APP_LOGD("GetParcelableInfos start");
    MessageParcel reply;
    if (!SendTransactCmd(code, data, reply)) {
        return false;
    }

    if (!reply.ReadBool()) {
        APP_LOGE("readParcelableInfo failed");
        return false;
    }

    if (InnerGetVectorFromParcelIntelligent<T>(reply, parcelableInfos) != ERR_OK) {
        APP_LOGE("InnerGetVectorFromParcelIntelligent failed");
        return false;
    }

    return true;
}

template<typename T>
ErrCode BundleMgrProxy::GetVectorFromParcelIntelligentWithErrCode(
    BundleMgrInterfaceCode code, MessageParcel &data, std::vector<T> &parcelableInfos)
{
    MessageParcel reply;
    if (!SendTransactCmd(code, data, reply)) {
        APP_LOGE("SendTransactCmd failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    ErrCode res = reply.ReadInt32();
    if (res != ERR_OK) {
        return res;
    }

    return InnerGetVectorFromParcelIntelligent<T>(reply, parcelableInfos);
}

template<typename T>
ErrCode BundleMgrProxy::InnerGetVectorFromParcelIntelligent(
    MessageParcel &reply, std::vector<T> &parcelableInfos)
{
    size_t dataSize = static_cast<size_t>(reply.ReadInt32());
    if (dataSize == 0) {
        APP_LOGW("Parcel no data");
        return ERR_OK;
    }

    void *buffer = nullptr;
    if (dataSize > MAX_IPC_REWDATA_SIZE) {
        APP_LOGI("dataSize is too large, use ashmem");
        if (GetParcelInfoFromAshMem(reply, buffer) != ERR_OK) {
            APP_LOGE("read data from ashmem fail, length %{public}zu", dataSize);
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    } else {
        if (!GetData(buffer, dataSize, reply.ReadRawData(dataSize))) {
            APP_LOGE("Fail read raw data length %{public}zu", dataSize);
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }

    MessageParcel tempParcel;
    if (!tempParcel.ParseFrom(reinterpret_cast<uintptr_t>(buffer), dataSize)) {
        APP_LOGE("Fail to ParseFrom");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    int32_t infoSize = tempParcel.ReadInt32();
    CONTAINER_SECURITY_VERIFY(tempParcel, infoSize, &parcelableInfos);
    for (int32_t i = 0; i < infoSize; i++) {
        std::unique_ptr<T> info(tempParcel.ReadParcelable<T>());
        if (info == nullptr) {
            APP_LOGE("Read Parcelable infos failed");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
        parcelableInfos.emplace_back(*info);
    }

    return ERR_OK;
}

bool BundleMgrProxy::SendTransactCmd(BundleMgrInterfaceCode code, MessageParcel &data, MessageParcel &reply)
{
    MessageOption option(MessageOption::TF_SYNC);

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        APP_LOGE("fail send transact cmd %{public}d due remote object", code);
        return false;
    }
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != NO_ERROR) {
        APP_LOGE("receive error transact code %{public}d in transact cmd %{public}d", result, code);
        return false;
    }
    return true;
}

ErrCode BundleMgrProxy::SendTransactCmdWithErrCode(BundleMgrInterfaceCode code, MessageParcel &data,
    MessageParcel &reply)
{
    MessageOption option(MessageOption::TF_SYNC);

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        APP_LOGE("fail send transact cmd %{public}d due remote object", code);
        return ERR_APPEXECFWK_NULL_PTR;
    }
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != NO_ERROR) {
        APP_LOGE("receive error transact code %{public}d in transact cmd %{public}d", result, code);
        if (IPC_ERR_MAP.find(result) != IPC_ERR_MAP.end()) {
            return IPC_ERR_MAP.at(result);
        }
        return result;
    }
    return ERR_OK;
}

ErrCode BundleMgrProxy::SendTransactCmdWithLogErrCode(BundleMgrInterfaceCode code, MessageParcel &data,
    MessageParcel &reply)
{
    MessageOption option(MessageOption::TF_SYNC);

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        APP_LOGE("fail send transact cmd %{public}d due remote object", code);
        return ERR_APPEXECFWK_NULL_PTR;
    }
    int32_t sptrRefCount = remote->GetSptrRefCount();
    int32_t wptrRefCount = remote->GetWptrRefCount();
    if (sptrRefCount <= 0 || wptrRefCount <= 0) {
        APP_LOGI("SendRequest before sptrRefCount: %{public}d wptrRefCount: %{public}d",
            sptrRefCount, wptrRefCount);
    }
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != NO_ERROR) {
        APP_LOGE("receive error transact code %{public}d in transact cmd %{public}d", result, code);
        if (IPC_ERR_MAP.find(result) != IPC_ERR_MAP.end()) {
            return IPC_ERR_MAP.at(result);
        }
        return result;
    }
    return ERR_OK;
}

bool BundleMgrProxy::SendTransactCmdWithLog(BundleMgrInterfaceCode code, MessageParcel &data,
    MessageParcel &reply)
{
    MessageOption option(MessageOption::TF_SYNC);

    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        APP_LOGE("fail send transact cmd %{public}d due remote object", code);
        return false;
    }
    int32_t sptrRefCount = remote->GetSptrRefCount();
    int32_t wptrRefCount = remote->GetWptrRefCount();
    if (sptrRefCount <= 0 || wptrRefCount <= 0) {
        APP_LOGI("SendRequest before sptrRefCount: %{public}d wptrRefCount: %{public}d",
            sptrRefCount, wptrRefCount);
    }
    int32_t result = remote->SendRequest(static_cast<uint32_t>(code), data, reply, option);
    if (result != NO_ERROR) {
        APP_LOGE("receive error transact code %{public}d in transact cmd %{public}d", result, code);
        return false;
    }
    return true;
}

bool ParseStr(const char *buf, const int itemLen, int index, std::string &result)
{
    APP_LOGD("ParseStr itemLen:%{public}d index:%{public}d", itemLen, index);
    if (buf == nullptr || itemLen <= 0 || index < 0) {
        APP_LOGE("param invalid");
        return false;
    }

    char item[itemLen + 1];
    if (strncpy_s(item, sizeof(item), buf + index, itemLen) != 0) {
        APP_LOGE("ParseStr failed due to strncpy_s error");
        return false;
    }

    std::string str(item, 0, itemLen);
    result = str;
    return true;
}

template<typename T>
ErrCode BundleMgrProxy::GetParcelInfo(BundleMgrInterfaceCode code, MessageParcel &data, T &parcelInfo)
{
    MessageParcel reply;
    if (!SendTransactCmd(code, data, reply)) {
        APP_LOGE("SendTransactCmd failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        APP_LOGE("host reply err : %{public}d", ret);
        return ret;
    }
    return InnerGetParcelInfo<T>(reply, parcelInfo);
}

template<typename T>
ErrCode BundleMgrProxy::InnerGetParcelInfo(MessageParcel &reply, T &parcelInfo)
{
    size_t dataSize = reply.ReadUint32();
    void *buffer = nullptr;
    if (!GetData(buffer, dataSize, reply.ReadRawData(dataSize))) {
        APP_LOGE("GetData failed, dataSize : %{public}zu", dataSize);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel tmpParcel;
    if (!tmpParcel.ParseFrom(reinterpret_cast<uintptr_t>(buffer), dataSize)) {
        APP_LOGE("ParseFrom failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    std::unique_ptr<T> info(tmpParcel.ReadParcelable<T>());
    if (info == nullptr) {
        APP_LOGE("ReadParcelable failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    parcelInfo = *info;
    APP_LOGD("InnerGetParcelInfo success");
    return ERR_OK;
}

template<typename T>
ErrCode BundleMgrProxy::WriteParcelInfoIntelligent(const T &parcelInfo, MessageParcel &reply) const
{
    Parcel tempParcel;
    (void)tempParcel.SetMaxCapacity(Constants::MAX_PARCEL_CAPACITY);
    if (!tempParcel.WriteParcelable(&parcelInfo)) {
        APP_LOGE("Write parcelable failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    size_t dataSize = tempParcel.GetDataSize();
    if (!reply.WriteUint32(dataSize)) {
        APP_LOGE("Write parcel size failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!reply.WriteRawData(reinterpret_cast<uint8_t *>(tempParcel.GetData()), dataSize)) {
        APP_LOGE("Write parcel raw data failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrProxy::GetBigString(BundleMgrInterfaceCode code, MessageParcel &data, std::string &result)
{
    MessageParcel reply;
    if (!SendTransactCmd(code, data, reply)) {
        APP_LOGE("SendTransactCmd failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        APP_LOGD("host reply err %{public}d", ret);
        return ret;
    }
    return InnerGetBigString(reply, result);
}

ErrCode BundleMgrProxy::InnerGetBigString(MessageParcel &reply, std::string &result)
{
    size_t dataSize = reply.ReadUint32();
    if (dataSize == 0) {
        APP_LOGE("Invalid data size");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    const char *data = reinterpret_cast<const char *>(reply.ReadRawData(dataSize));
    if (!data) {
        APP_LOGE("Fail read raw data length %{public}zu", dataSize);
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    result = data;
    APP_LOGD("InnerGetBigString success");
    return ERR_OK;
}

ErrCode BundleMgrProxy::CompileProcessAOT(const std::string &bundleName, const std::string &compileMode,
    bool isAllBundle, std::vector<std::string> &compileResults)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to compile");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to compile due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to compile due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(compileMode)) {
        APP_LOGE("fail to compile due to write compileMode fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(isAllBundle)) {
        APP_LOGE("fail to compile due to write isAllBundle fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::COMPILE_PROCESSAOT, data, reply)) {
        APP_LOGE("fail to compile from server");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        if (!reply.ReadStringVector(&compileResults)) {
            APP_LOGE("fail to get compile results from reply");
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    return ret;
}

ErrCode BundleMgrProxy::CompileReset(const std::string &bundleName, bool isAllBundle)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to reset");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to reset due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to reset due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(isAllBundle)) {
        APP_LOGE("fail to reset due to write isAllBundle fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::COMPILE_RESET, data, reply)) {
        APP_LOGE("fail to reset from server");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrProxy::CopyAp(const std::string &bundleName, bool isAllBundle, std::vector<std::string> &results)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to CopyAp");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to CopyAp due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to CopyAp due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(isAllBundle)) {
        APP_LOGE("fail to CopyAp due to write isAllBundle fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::COPY_AP, data, reply)) {
        APP_LOGE("fail to CopyAp from server");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode res = reply.ReadInt32();
    if (res != ERR_OK) {
        APP_LOGE("host reply err: %{public}d", res);
        return res;
    }
    if (!reply.ReadStringVector(&results)) {
        APP_LOGE("fail to CopyAp from reply");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    APP_LOGD("end to CopyAp");
    return ERR_OK;
}

ErrCode BundleMgrProxy::CanOpenLink(
    const std::string &link, bool &canOpen)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("write interfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(link)) {
        APP_LOGE("write link failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::CAN_OPEN_LINK, data, reply)) {
        APP_LOGE("SendTransactCmd failed");
        return ERR_BUNDLE_MANAGER_IPC_TRANSACTION;
    }
    ErrCode res = reply.ReadInt32();
    if (res != ERR_OK) {
        APP_LOGE("host reply err: %{public}d", res);
        return res;
    }
    canOpen = reply.ReadBool();
    return ERR_OK;
}

ErrCode BundleMgrProxy::GetAllPreinstalledApplicationInfos(
    std::vector<PreinstalledApplicationInfo> &preinstalledApplicationInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("Called");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("Fail to reset due to WriteInterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetParcelableInfosWithErrCode<PreinstalledApplicationInfo>(
        BundleMgrInterfaceCode::GET_PREINSTALLED_APPLICATION_INFO, data, preinstalledApplicationInfos);
}

ErrCode BundleMgrProxy::SwitchUninstallState(const std::string &bundleName, const bool &state,
    bool isNeedSendNotify)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("write interfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("write bundleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(state)) {
        APP_LOGE("write state failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(isNeedSendNotify)) {
        APP_LOGE("write isNeedSendNotify failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::SWITCH_UNINSTALL_STATE, data, reply)) {
        APP_LOGE("SendTransactCmd failed");
        return ERR_BUNDLE_MANAGER_IPC_TRANSACTION;
    }
    return reply.ReadInt32();
}

ErrCode BundleMgrProxy::QueryAbilityInfoByContinueType(const std::string &bundleName,
    const std::string &continueType,  AbilityInfo &abilityInfo, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to QueryAbilityInfoByContinueType due to write interfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("fail to QueryAbilityInfoByContinueType due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(continueType)) {
        APP_LOGE("fail to QueryAbilityInfoByContinueType due to write continueType fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to QueryAbilityInfoByContinueType due to write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetParcelableInfoWithErrCode<AbilityInfo>(
        BundleMgrInterfaceCode::QUERY_ABILITY_INFO_BY_CONTINUE_TYPE, data, abilityInfo);
}

ErrCode BundleMgrProxy::QueryCloneAbilityInfo(const ElementName &element,
    int32_t flags, int32_t appIndex, AbilityInfo &abilityInfo, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "write interfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&element)) {
        LOG_E(BMS_TAG_QUERY, "write element fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(flags)) {
        LOG_E(BMS_TAG_QUERY, "write flags failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(appIndex)) {
        LOG_E(BMS_TAG_QUERY, "write appIndex failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_QUERY, "write userId failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetParcelableInfoWithErrCode<AbilityInfo>(
        BundleMgrInterfaceCode::GET_CLONE_ABILITY_INFO, data, abilityInfo);
}

ErrCode BundleMgrProxy::GetCloneBundleInfo(const std::string &bundleName, int32_t flags, int32_t appIndex,
    BundleInfo &bundleInfo, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to GetCloneBundleInfo of %{public}s", bundleName.c_str());
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetCloneBundleInfo due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("failed to GetCloneBundleInfo due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(flags)) {
        APP_LOGE("fail to GetCloneBundleInfo due to write flag fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(appIndex)) {
        APP_LOGE("fail to GetCloneBundleInfo due to write appIndex fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to GetCloneBundleInfo due to write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return GetParcelableInfoWithErrCode<BundleInfo>(
        BundleMgrInterfaceCode::GET_CLONE_BUNDLE_INFO, data, bundleInfo);
}

ErrCode BundleMgrProxy::GetCloneAppIndexes(const std::string &bundleName, std::vector<int32_t> &appIndexes,
    int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to GetCloneAppIndexes of %{public}s", bundleName.c_str());
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("fail to GetCloneAppIndexes due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("failed to GetCloneAppIndexes due to write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("fail to GetCloneAppIndexes due to write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_CLONE_APP_INDEXES, data, reply)) {
        APP_LOGE("fail to GetCloneAppIndexes from server");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    ErrCode ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        return ret;
    }
    if (!reply.ReadInt32Vector(&appIndexes)) {
        APP_LOGE("fail to GetCloneAppIndexes from reply");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ret;
}

ErrCode BundleMgrProxy::GetLaunchWant(Want &want)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to GetLaunchWant");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return GetParcelableInfoWithErrCode<Want>(BundleMgrInterfaceCode::GET_LAUNCH_WANT, data, want);
}

ErrCode BundleMgrProxy::QueryCloneExtensionAbilityInfoWithAppIndex(const ElementName &elementName,
    int32_t flags, int32_t appIndex, ExtensionAbilityInfo &extensionAbilityInfo, int32_t userId)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "QueryExtensionAbilityInfo write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteParcelable(&elementName)) {
        LOG_E(BMS_TAG_QUERY, "QueryExtensionAbilityInfo write elementName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(flags)) {
        LOG_E(BMS_TAG_QUERY, "QueryExtensionAbilityInfo write flag fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(appIndex)) {
        LOG_E(BMS_TAG_QUERY, "QueryExtensionAbilityInfo write appIndex fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_QUERY, "QueryExtensionAbilityInfo write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    return GetParcelableInfoWithErrCode<ExtensionAbilityInfo>(
        BundleMgrInterfaceCode::QUERY_CLONE_EXTENSION_ABILITY_INFO_WITH_APP_INDEX, data, extensionAbilityInfo);
}

ErrCode BundleMgrProxy::GetSignatureInfoByBundleName(const std::string &bundleName, SignatureInfo &signatureInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin %{public}s", bundleName.c_str());
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetParcelInfoIntelligent<SignatureInfo>(BundleMgrInterfaceCode::GET_SIGNATURE_INFO, data, signatureInfo);
}

ErrCode BundleMgrProxy::GetSignatureInfoByUid(const int32_t uid, SignatureInfo &signatureInfo)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin %{public}d", uid);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(uid)) {
        APP_LOGE("write uid fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetParcelInfoIntelligent<SignatureInfo>(
        BundleMgrInterfaceCode::GET_SIGNATURE_INFO_BY_UID, data, signatureInfo);
}

ErrCode BundleMgrProxy::UpdateAppEncryptedStatus(const std::string &bundleName, bool isExisted, int32_t appIndex)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("UpdateAppEncryptedStatus write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteBool(isExisted)) {
        APP_LOGE("write isExisted failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(appIndex)) {
        APP_LOGE("write appIndex fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::UPDATE_APP_ENCRYPTED_KEY_STATUS, data, reply)) {
        APP_LOGE("SendTransactCmd failed");
        return ERR_BUNDLE_MANAGER_IPC_TRANSACTION;
    }
    return reply.ReadInt32();
}

ErrCode BundleMgrProxy::AddDesktopShortcutInfo(const ShortcutInfo &shortcutInfo, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("AddDesktopShortcutInfo write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto ret = WriteParcelInfoIntelligent(shortcutInfo, data);
    if (ret != ERR_OK) {
        APP_LOGE("AddDesktopShortcutInfo write ParcelInfo fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("AddDesktopShortcutInfo write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::ADD_DESKTOP_SHORTCUT_INFO, data, reply)) {
        APP_LOGE("SendTransactCmd failed");
        return ERR_BUNDLE_MANAGER_IPC_TRANSACTION;
    }
    return reply.ReadInt32();
}

ErrCode BundleMgrProxy::DeleteDesktopShortcutInfo(const ShortcutInfo &shortcutInfo, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("DeleteDesktopShortcutInfo write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto ret = WriteParcelInfoIntelligent(shortcutInfo, data);
    if (ret != ERR_OK) {
        APP_LOGE("DeleteDesktopShortcutInfo write ParcelInfo fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("DeleteDesktopShortcutInfo write userId fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::DELETE_DESKTOP_SHORTCUT_INFO, data, reply)) {
        APP_LOGE("SendTransactCmd failed");
        return ERR_BUNDLE_MANAGER_IPC_TRANSACTION;
    }
    return reply.ReadInt32();
}

ErrCode BundleMgrProxy::GetAllDesktopShortcutInfo(int32_t userId, std::vector<ShortcutInfo> &shortcutInfos)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("GetAllDesktopShortcutInfo write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("GetAllDesktopShortcutInfo write bundleName fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetVectorFromParcelIntelligentWithErrCode<ShortcutInfo>(
        BundleMgrInterfaceCode::GET_ALL_DESKTOP_SHORTCUT_INFO, data, shortcutInfos);
}

ErrCode BundleMgrProxy::GetOdidByBundleName(const std::string &bundleName, std::string &odid)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("GetOdidByBundleName Called");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("Write interfaceToken failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("Write bundleName failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_ODID_BY_BUNDLENAME, data, reply)) {
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto ret = reply.ReadInt32();
    if (ret == ERR_OK) {
        odid = reply.ReadString();
    }
    APP_LOGD("GetOdidByBundleName ret: %{public}d, odid: %{private}s", ret, odid.c_str());
    return ret;
}

bool BundleMgrProxy::GetBundleInfosForContinuation(
    int32_t flags, std::vector<BundleInfo> &bundleInfos, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    LOG_D(BMS_TAG_QUERY, "begin to get bundle infos");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "fail to GetBundleInfosForContinuation due to write InterfaceToken fail");
        return false;
    }
    if (!data.WriteInt32(flags)) {
        LOG_E(BMS_TAG_QUERY, "fail to GetBundleInfosForContinuation due to write flag fail");
        return false;
    }
    if (!data.WriteInt32(userId)) {
        LOG_E(BMS_TAG_QUERY, "fail to GetBundleInfo due to write userId fail");
        return false;
    }
    if (!GetVectorFromParcelIntelligent<BundleInfo>(
            BundleMgrInterfaceCode::GET_BUNDLE_INFOS_FOR_CONTINUATION, data, bundleInfos)) {
        LOG_E(BMS_TAG_QUERY, "fail to GetBundleInfosForContinuation from server");
        return false;
    }
    return true;
}

ErrCode BundleMgrProxy::GetContinueBundleNames(
    const std::string &continueBundleName, std::vector<std::string> &bundleNames, int32_t userId)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("Write interface token fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(continueBundleName)) {
        APP_LOGE("Write bundle name fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("Write user id fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_CONTINUE_BUNDLE_NAMES, data, reply)) {
        APP_LOGE("Fail to GetContinueBundleNames from server");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    auto ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        APP_LOGE("Reply err : %{public}d", ret);
        return ret;
    }
    if (!reply.ReadStringVector(&bundleNames)) {
        APP_LOGE("Fail to GetContinueBundleNames from reply");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}

ErrCode BundleMgrProxy::IsBundleInstalled(const std::string &bundleName, int32_t userId,
    int32_t appIndex, bool &isInstalled)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("Write interface token fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("Write bundle name fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("Write user id fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(appIndex)) {
        APP_LOGE("Write appIndex id fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::IS_BUNDLE_INSTALLED, data, reply)) {
        APP_LOGE("Fail to IsBundleInstalled from server");
        return ERR_BUNDLE_MANAGER_IPC_TRANSACTION;
    }
    auto ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        APP_LOGE("IsBundleInstalled err: %{public}d", ret);
        return ret;
    }
    isInstalled = reply.ReadBool();
    return ERR_OK;
}

ErrCode BundleMgrProxy::GetCompatibleDeviceType(const std::string &bundleName, std::string &deviceType)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("Write interface token fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("Write bundle name fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_COMPATIBLED_DEVICE_TYPE, data, reply)) {
        APP_LOGE("Fail to IsBundleInstalled from server");
        return ERR_BUNDLE_MANAGER_IPC_TRANSACTION;
    }
    auto ret = reply.ReadInt32();
    if (ret == ERR_OK) {
        deviceType = reply.ReadString();
    }
    APP_LOGD("GetCompatibleDeviceType: ret: %{public}d, device type: %{public}s", ret, deviceType.c_str());
    return ret;
}

ErrCode BundleMgrProxy::GetBundleNameByAppId(const std::string &appId, std::string &bundleName)
{
    APP_LOGD("GetBundleNameByAppId: appId: %{private}s", appId.c_str());
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (appId.empty()) {
        APP_LOGE("appId empty");
        return ERR_APPEXECFWK_INSTALL_PARAM_ERROR;
    }
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("Write interface token fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(appId)) {
        APP_LOGE("Write app id fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_BUNDLE_NAME_BY_APP_ID_OR_APP_IDENTIFIER, data, reply)) {
        APP_LOGE("Fail to get bundleName from server");
        return ERR_BUNDLE_MANAGER_IPC_TRANSACTION;
    }
    auto ret = reply.ReadInt32();
    if (ret == ERR_OK) {
        bundleName = reply.ReadString();
    }
    APP_LOGD("GetBundleNameByAppId: ret: %{public}d, bundleName: %{public}s", ret, bundleName.c_str());
    return ret;
}

ErrCode BundleMgrProxy::GetDirByBundleNameAndAppIndex(const std::string &bundleName, const int32_t appIndex,
    std::string &dataDir)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("Write interface token fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteString(bundleName)) {
        APP_LOGE("Write bundle name fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(appIndex)) {
        APP_LOGE("Write appIndex id fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_DIR_BY_BUNDLENAME_AND_APPINDEX, data, reply)) {
        APP_LOGE("Fail to GetDir from server");
        return ERR_BUNDLE_MANAGER_IPC_TRANSACTION;
    }
    auto ret = reply.ReadInt32();
    if (ret == ERR_OK) {
        dataDir = reply.ReadString();
    }
    APP_LOGD("GetDirByBundleNameAndAppIndex: ret: %{public}d, dataDir: %{public}s", ret, dataDir.c_str());
    return ret;
}

ErrCode BundleMgrProxy::GetAllBundleCacheStat(const sptr<IProcessCacheCallback> processCacheCallback)
{
    APP_LOGI("GetAllBundleCacheStat start");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (processCacheCallback == nullptr) {
        APP_LOGE("fail to CleanBundleCacheFiles due to params error");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("failed to GetAllBundleCacheStat due to write MessageParcel fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(processCacheCallback->AsObject())) {
        APP_LOGE("fail to GetAllBundleCacheStat, for write parcel failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    
    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::GET_ALL_BUNDLE_CACHE, data, reply)) {
        APP_LOGE("fail to GetAllBundleCacheStat from server");
        return ERR_BUNDLE_MANAGER_IPC_TRANSACTION;
    }
    ErrCode res = reply.ReadInt32();
    if (res != ERR_OK) {
        APP_LOGE("fail to GetAllBundleCacheStat from reply: %{public}d", res);
        return res;
    }
    return ERR_OK;
}

ErrCode BundleMgrProxy::CleanAllBundleCache(const sptr<IProcessCacheCallback> processCacheCallback)
{
    APP_LOGI("CleanAllBundleCache start");
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    if (processCacheCallback == nullptr) {
        APP_LOGE("fail to CleanBundleCacheFiles due to params error");
        return ERR_BUNDLE_MANAGER_PARAM_ERROR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("failed to CleanAllBundleCache due to write MessageParcel fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteRemoteObject(processCacheCallback->AsObject())) {
        APP_LOGE("fail to CleanAllBundleCache, for write parcel failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    
    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::CLEAN_ALL_BUNDLE_CACHE, data, reply)) {
        APP_LOGE("fail to CleanAllBundleCache from server");
        return ERR_BUNDLE_MANAGER_IPC_TRANSACTION;
    }
    ErrCode res = reply.ReadInt32();
    if (res != ERR_OK) {
        APP_LOGE("fail to CleanAllBundleCache from reply: %{public}d", res);
        return res;
    }
    return ERR_OK;
}

ErrCode BundleMgrProxy::SetAppDistributionTypes(std::set<AppDistributionTypeEnum> &appDistributionTypeEnums)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    APP_LOGD("begin to set appDistributionTypes");
    if (appDistributionTypeEnums.size() <= 0) {
        LOG_E(BMS_TAG_QUERY, "fail to SetAppDistributionTypes due size not satisfied");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        LOG_E(BMS_TAG_QUERY, "fail to SetAppDistributionTypes due to write InterfaceToken fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(appDistributionTypeEnums.size())) {
        APP_LOGE("fail to SetAppDistributionTypes due to write count fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    for (AppDistributionTypeEnum item : appDistributionTypeEnums) {
        int32_t itemSize =  static_cast<int>(item);
        if (!data.WriteInt32(itemSize)) {
            APP_LOGE("write appDistributionType %{public}d failed", itemSize);
            return ERR_APPEXECFWK_PARCEL_ERROR;
        }
    }
    MessageParcel reply;
    if (!SendTransactCmd(BundleMgrInterfaceCode::SET_APP_DISTRIBUTION_TYPES, data, reply)) {
        APP_LOGE("fail to CleanAllBundleCache from server");
        return ERR_BUNDLE_MANAGER_IPC_TRANSACTION;
    }
    ErrCode res = reply.ReadInt32();
    if (res != ERR_OK) {
        APP_LOGE("fail to SetAppDistributionTypes from reply: %{public}d", res);
        return res;
    }
    return ERR_OK;
}

ErrCode BundleMgrProxy::GetAllBundleDirs(int32_t userId, std::vector<BundleDir> &bundleDirs)
{
    HITRACE_METER_NAME(HITRACE_TAG_APP, __PRETTY_FUNCTION__);
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        APP_LOGE("Write interface token fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (!data.WriteInt32(userId)) {
        APP_LOGE("Write user id fail");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return GetVectorFromParcelIntelligentWithErrCode<BundleDir>(
        BundleMgrInterfaceCode::GET_ALL_BUNDLE_DIRS, data, bundleDirs);
}

ErrCode BundleMgrProxy::GetParcelInfoFromAshMem(MessageParcel &reply, void *&data)
{
    sptr<Ashmem> ashMem = reply.ReadAshmem();
    if (ashMem == nullptr) {
        APP_LOGE("Ashmem is nullptr");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }

    if (!ashMem->MapReadOnlyAshmem()) {
        APP_LOGE("MapReadOnlyAshmem failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    int32_t ashMemSize = ashMem->GetAshmemSize();
    int32_t offset = 0;
    const void* ashDataPtr = ashMem->ReadFromAshmem(ashMemSize, offset);
    if (ashDataPtr == nullptr) {
        APP_LOGE("ashDataPtr is nullptr");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if ((ashMemSize == 0) || ashMemSize > static_cast<int32_t>(MAX_PARCEL_CAPACITY)) {
        APP_LOGE("failed due to wrong size");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    data = malloc(ashMemSize);
    if (data == nullptr) {
        APP_LOGE("failed due to malloc data failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    if (memcpy_s(data, ashMemSize, ashDataPtr, ashMemSize) != EOK) {
        free(data);
        APP_LOGE("failed due to memcpy_s failed");
        return ERR_APPEXECFWK_PARCEL_ERROR;
    }
    return ERR_OK;
}
}  // namespace AppExecFwk
}  // namespace OHOS
