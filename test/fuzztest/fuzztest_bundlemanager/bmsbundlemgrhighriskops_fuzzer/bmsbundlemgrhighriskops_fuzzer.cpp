/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#define private public
#include "bmsbundlemgrhighriskops_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "bundlemgr/bundle_mgr_host.h"
#include "message_parcel.h"
#include "want.h"
#include "element_name.h"
#include "ability_info.h"
#include "ipc_object_stub.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;
using namespace OHOS::AAFwk;
namespace OHOS {
constexpr uint32_t CODE_MAX = 274;

// ====== 15high-riskmethod: real read orderprecise Parcel construction ======
// field read order verified one by one against bundle_mgr_host.cpp

 // 1. HandleSetBundleFirstLaunch: ReadString(bundleName), ReadInt32(userId), ReadInt32(appIndex),
// ReadBool(isBundleFirstLaunched)
void FuzzSetBundleFirstLaunch(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteUserId(data, fdp);                            // userId
    WriteInt32Field(data, fdp);                     // appIndex
    WriteBoolField(data, fdp);                                   // isBundleFirstLaunched
    FinishParcel(data);
    host.HandleSetBundleFirstLaunch(data, reply);
}

// 2. HandleSetApplicationEnabled: ReadString(bundleName), ReadBool(isEnable), ReadInt32(userId), ReadBool(killProcess)
void FuzzSetApplicationEnabled(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteBoolField(data, fdp);                                   // isEnable
    WriteUserId(data, fdp);                            // userId
    WriteBoolField(data, fdp);                                   // killProcess
    FinishParcel(data);
    host.HandleSetApplicationEnabled(data, reply);
}

// 3. HandleSetAbilityEnabled: ReadParcelable<AbilityInfo>, ReadBool(isEnabled), ReadInt32(userId)
void FuzzSetAbilityEnabled(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    AbilityInfo abilityInfo;
    GenerateAbilityInfo(fdp, abilityInfo);
    data.WriteParcelable(&abilityInfo);                                   // AbilityInfo
    WriteBoolField(data, fdp);                                   // isEnabled
    WriteUserId(data, fdp);                            // userId
    FinishParcel(data);
    host.HandleSetAbilityEnabled(data, reply);
}

// 4. HandleGetUidByDebugBundleName: ReadString(bundleName), ReadInt32(userId)
void FuzzGetUidByDebugBundleName(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp, ATTACK_CERT_BYPASS);     // bundleName (security related)
    WriteUserId(data, fdp);                            // userId
    FinishParcel(data);
    host.HandleGetUidByDebugBundleName(data, reply);
}

// 5. HandleGetSandboxBundleInfo: ReadString(bundleName), ReadInt32(appIndex), ReadInt32(userId)
void FuzzGetSandboxBundleInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteInt32Field(data, fdp);                     // appIndex
    WriteUserId(data, fdp);                            // userId
    FinishParcel(data);
    host.HandleGetSandboxBundleInfo(data, reply);
}

// 6. HandleSilentInstall: ReadParcelable<Want>, ReadInt32(userId), ReadRemoteObject(object)
void FuzzSilentInstall(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    Want want;
    want.SetBundle(GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL));
    want.SetAction(GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL));
    want.SetElementName(GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL),
        fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    data.WriteParcelable(&want);                                          // Want
    WriteUserId(data, fdp);                            // userId
    WriteRemoteObject(data);                                      // object
    FinishParcel(data);
    host.HandleSilentInstall(data, reply);
}

// 7. HandleSetDebugMode: ReadBool(enable)
void FuzzSetDebugMode(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteBoolField(data, fdp);                                   // enable
    FinishParcel(data);
    host.HandleSetDebugMode(data, reply);
}

// 8. HandleGetAppProvisionInfo: ReadString(bundleName), ReadInt32(userId)
void FuzzGetAppProvisionInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp, ATTACK_CERT_BYPASS);     // bundleName (provision security)
    WriteUserId(data, fdp);                            // userId
    FinishParcel(data);
    host.HandleGetAppProvisionInfo(data, reply);
}

// 9. HandleMigrateData: ReadStringVector(sourcePaths), ReadString(destinationPath)
void FuzzMigrateData(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    std::vector<std::string> sourcePaths = GenerateStringArray(fdp);
    data.WriteStringVector(sourcePaths);                                 // sourcePaths
    WriteStringField(data, fdp);  // destinationPath
    FinishParcel(data);
    host.HandleMigrateData(data, reply);
}

// 10. HandleCreateBundleDataDir: ReadInt32(userId)
void FuzzCreateBundleDataDir(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteUserId(data, fdp);                            // userId
    FinishParcel(data);
    host.HandleCreateBundleDataDir(data, reply);
}

// 11. HandleCreateBundleDataDirWithEl: ReadInt32(userId), ReadUint8(dirEl)
void FuzzCreateBundleDataDirWithEl(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteUserId(data, fdp);                            // userId
    WriteUint8Field(data, fdp);                 // dirEl (DataDirEl)
    FinishParcel(data);
    host.HandleCreateBundleDataDirWithEl(data, reply);
}

// 12. HandleSwitchUninstallState: ReadString(bundleName), ReadBool(state), ReadBool(isNeedSendNotify)
void FuzzSwitchUninstallState(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteBoolField(data, fdp);                                   // state
    WriteBoolField(data, fdp);                                   // isNeedSendNotify
    FinishParcel(data);
    host.HandleSwitchUninstallState(data, reply);
}

// 13. HandleSwitchUninstallStateByUserId: ReadString(bundleName), ReadBool(state), ReadInt32(userId)
void FuzzSwitchUninstallStateByUserId(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteBoolField(data, fdp);                                   // state
    WriteUserId(data, fdp);                            // userId
    FinishParcel(data);
    host.HandleSwitchUninstallStateByUserId(data, reply);
}

 // 14. HandleQueryCloneAbilityInfo: ReadParcelable<ElementName>, ReadInt32(flags), ReadInt32(appIndex),
// ReadInt32(userId)
void FuzzQueryCloneAbilityInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    ElementName elementName;
    elementName.SetBundleName(GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL));
    elementName.SetModuleName(fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    elementName.SetAbilityName(fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    data.WriteParcelable(&elementName);                                   // ElementName
    WriteInt32Field(data, fdp);                     // flags
    WriteInt32Field(data, fdp);                     // appIndex
    WriteUserId(data, fdp);                            // userId
    FinishParcel(data);
    host.HandleQueryCloneAbilityInfo(data, reply);
}

// 15. HandleUpdateAppEncryptedStatus: ReadString(name), ReadBool(isExisted), ReadInt32(appIndex)
void FuzzUpdateAppEncryptedStatus(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp, ATTACK_CERT_BYPASS);     // name (encryptionstate)
    WriteBoolField(data, fdp);                                   // isExisted
    WriteInt32Field(data, fdp);                     // appIndex
    FinishParcel(data);
    host.HandleUpdateAppEncryptedStatus(data, reply);
}

// ====== additional high-risk methods (10) ======

 // 16. HandleSetCloneApplicationEnabled: ReadString(bundleName), ReadInt32(appIndex), ReadBool(isEnable),
// ReadInt32(userId), ReadBool(killProcess)
void FuzzSetCloneApplicationEnabled(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteInt32Field(data, fdp);                     // appIndex
    WriteBoolField(data, fdp);                                   // isEnable
    WriteUserId(data, fdp);                            // userId
    WriteBoolField(data, fdp);                                   // killProcess
    FinishParcel(data);
    host.HandleSetCloneApplicationEnabled(data, reply);
}

 // 17. HandleSetCloneAbilityEnabled: ReadParcelable<AbilityInfo>, ReadInt32(appIndex), ReadBool(isEnabled),
// ReadInt32(userId)
void FuzzSetCloneAbilityEnabled(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    AbilityInfo abilityInfo;
    GenerateAbilityInfo(fdp, abilityInfo);
    data.WriteParcelable(&abilityInfo);                                   // AbilityInfo
    WriteInt32Field(data, fdp);                     // appIndex
    WriteBoolField(data, fdp);                                   // isEnabled
    WriteUserId(data, fdp);                            // userId
    FinishParcel(data);
    host.HandleSetCloneAbilityEnabled(data, reply);
}

// 18. HandleGetCloneBundleInfo: ReadString(bundleName), ReadInt32(flags), ReadInt32(appIndex), ReadInt32(userId)
void FuzzGetCloneBundleInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteInt32Field(data, fdp);                     // flags
    WriteInt32Field(data, fdp);                     // appIndex
    WriteUserId(data, fdp);                            // userId
    FinishParcel(data);
    host.HandleGetCloneBundleInfo(data, reply);
}

// 19. HandleGetCloneAppIndexes: ReadString(bundleName), ReadInt32(userId)
void FuzzGetCloneAppIndexes(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteUserId(data, fdp);                            // userId
    FinishParcel(data);
    host.HandleGetCloneAppIndexes(data, reply);
}

// 20. HandleGetAllAppProvisionInfo: ReadInt32(userId)
void FuzzGetAllAppProvisionInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteUserId(data, fdp);                            // userId
    FinishParcel(data);
    host.HandleGetAllAppProvisionInfo(data, reply);
}

// 21. HandleGetProvisionMetadata: ReadString(bundleName), ReadInt32(userId)
void FuzzGetProvisionMetadata(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp, ATTACK_CERT_BYPASS);     // bundleName (provision)
    WriteUserId(data, fdp);                            // userId
    FinishParcel(data);
    host.HandleGetProvisionMetadata(data, reply);
}

// 22. HandleCreateNewBundleDir: ReadInt32(userId), ReadString(moduleName)
void FuzzCreateNewBundleDir(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteUserId(data, fdp);                            // userId
    WriteStringField(data, fdp);  // moduleName
    FinishParcel(data);
    host.HandleCreateNewBundleDir(data, reply);
}

// 23. HandleIsBundleInstalled: ReadString(bundleName), ReadInt32(userId), ReadInt32(appIndex)
void FuzzIsBundleInstalled(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteUserId(data, fdp);                            // userId
    WriteInt32Field(data, fdp);                     // appIndex
    FinishParcel(data);
    host.HandleIsBundleInstalled(data, reply);
}

// 24. HandleGetInstalledBundleList: ReadUint32(flags), ReadInt32(userId)
void FuzzGetInstalledBundleList(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteUint32Field(data, fdp);                   // flags
    WriteUserId(data, fdp);                            // userId
    FinishParcel(data);
    host.HandleGetInstalledBundleList(data, reply);
}

// 25. HandleGetBundleInstallStatus: ReadString(bundleName), ReadInt32(userId)
void FuzzGetBundleInstallStatus(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteUserId(data, fdp);                            // userId
    FinishParcel(data);
    host.HandleGetBundleInstallStatus(data, reply);
}

// ====== additional high-risk methods batch 2 (5) ======

// 26. HandleSetAppClonePreference: ReadString(bundleName), ReadInt32(userId), ReadParcelable<AppClonePreference>
void FuzzSetAppClonePreference(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteUserId(data, fdp);                            // userId
    FinishParcel(data);
    host.HandleSetAppClonePreference(data, reply);
}

// 27. HandleGetAppClonePreference: ReadString(bundleName), ReadInt32(userId)
void FuzzGetAppClonePreference(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteUserId(data, fdp);                            // userId
    FinishParcel(data);
    host.HandleGetAppClonePreference(data, reply);
}

// 28. HandleGetCliSandboxAppIndexes: ReadString(bundleName), ReadInt32(userId)
void FuzzGetCliSandboxAppIndexes(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteUserId(data, fdp);                            // userId
    FinishParcel(data);
    host.HandleGetCliSandboxAppIndexes(data, reply);
}

 // 29. HandleQuerySandboxCloneAbilityInfo: ReadString(creatorBundleName), ReadParcelable<ElementName>,
// ReadString(moduleName), ReadInt32(flags), ReadInt32(appIndex)
void FuzzQuerySandboxCloneAbilityInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // creatorBundleName
    ElementName elementName;
    elementName.SetBundleName(GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL));
    elementName.SetModuleName(fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    elementName.SetAbilityName(fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    data.WriteParcelable(&elementName);                                   // ElementName
    WritePlainString(data, fdp);  // moduleName
    WriteInt32Field(data, fdp);                     // flags
    WriteInt32Field(data, fdp);                     // appIndex
    FinishParcel(data);
    host.HandleQuerySandboxCloneAbilityInfo(data, reply);
}

// ====== additional high-risk methods batch 3 (14) ======

// 29. HandleSetModuleRemovable: ReadString(bundleName), ReadString(moduleName), ReadBool(isEnable)
void FuzzSetModuleRemovable(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WritePlainString(data, fdp);  // moduleName
    WriteBoolField(data, fdp);                                   // isEnable
    FinishParcel(data);
    host.HandleSetModuleRemovable(data, reply);
}

// 30. HandleSetAdditionalInfo: ReadString(bundleName), ReadString(additionalInfo)
void FuzzSetAdditionalInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteStringField(data, fdp, ATTACK_CERT_BYPASS);     // additionalInfo
    FinishParcel(data);
    host.HandleSetAdditionalInfo(data, reply);
}

 // 31. HandleCleanBundleCacheFiles: ReadString(bundleName), ReadRemoteObject(object), ReadInt32(userId),
// ReadInt32(appIndex)
void FuzzCleanBundleCacheFiles(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteRemoteObject(data);                                      // object
    WriteUserId(data, fdp);                            // userId
    WriteInt32Field(data, fdp);                     // appIndex
    FinishParcel(data);
    host.HandleCleanBundleCacheFiles(data, reply);
}

// 32. HandleCleanBundleDataFiles: ReadString(bundleName), ReadInt32(userId), ReadInt32(appIndex), ReadInt32(callerUid)
void FuzzCleanBundleDataFiles(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteUserId(data, fdp);                            // userId
    WriteInt32Field(data, fdp);                     // appIndex
    WriteInt32Field(data, fdp);                     // callerUid
    FinishParcel(data);
    host.HandleCleanBundleDataFiles(data, reply);
}

// 33. HandleCleanAllBundleCache: ReadRemoteObject(object)
void FuzzCleanAllBundleCache(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteRemoteObject(data);                                      // object
    FinishParcel(data);
    host.HandleCleanAllBundleCache(data, reply);
}

// 34. HandleGetAbilityInfo: ReadString(bundleName), ReadString(abilityName)
void FuzzGetAbilityInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WritePlainString(data, fdp);  // abilityName
    FinishParcel(data);
    host.HandleGetAbilityInfo(data, reply);
}

// 35. HandleGetAbilityInfos: ReadString(uri), ReadUint32(flags)
void FuzzGetAbilityInfos(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // uri
    WriteUint32Field(data, fdp);                   // flags
    FinishParcel(data);
    host.HandleGetAbilityInfos(data, reply);
}

// 36. HandleAddDesktopShortcutInfo: ReadParcelable<ShortcutInfo>, ReadInt32(userId)
void FuzzAddDesktopShortcutInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    ShortcutInfo shortcutInfo;
    GenerateShortcutInfo(fdp, shortcutInfo);
    data.WriteParcelable(&shortcutInfo);                                   // ShortcutInfo
    WriteUserId(data, fdp);                            // userId
    FinishParcel(data);
    host.HandleAddDesktopShortcutInfo(data, reply);
}

// 37. HandleDeleteDesktopShortcutInfo: ReadParcelable<ShortcutInfo>, ReadInt32(userId)
void FuzzDeleteDesktopShortcutInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    ShortcutInfo shortcutInfo;
    GenerateShortcutInfo(fdp, shortcutInfo);
    data.WriteParcelable(&shortcutInfo);                                   // ShortcutInfo
    WriteUserId(data, fdp);                            // userId
    FinishParcel(data);
    host.HandleDeleteDesktopShortcutInfo(data, reply);
}

// 38. HandleCompileProcessAOT: ReadString(bundleName), ReadString(compileMode), ReadBool(isAllBundle)
void FuzzCompileProcessAOT(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WritePlainString(data, fdp);  // compileMode
    WriteBoolField(data, fdp);                                   // isAllBundle
    FinishParcel(data);
    host.HandleCompileProcessAOT(data, reply);
}

// 39. HandleCompileReset: ReadString(bundleName), ReadBool(isAllBundle)
void FuzzCompileReset(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteBoolField(data, fdp);                                   // isAllBundle
    FinishParcel(data);
    host.HandleCompileReset(data, reply);
}

// 40. HandleQueryAbilityInfo: ReadParcelable<Want>
void FuzzQueryAbilityInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteWant(data, fdp);                                          // Want
    FinishParcel(data);
    host.HandleQueryAbilityInfo(data, reply);
}

// 41. HandleCheckIsSystemAppByUid: ReadInt32(uid)
void FuzzCheckIsSystemAppByUid(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteInt32Field(data, fdp);  // uid (0=root, 1000=system, 9999=invalid)
    FinishParcel(data);
    host.HandleCheckIsSystemAppByUid(data, reply);
}

// 42. HandleDumpInfos: ReadInt32(flag), ReadString(bundleName), ReadInt32(userId)
void FuzzDumpInfos(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteInt32Field(data, fdp);                     // flag (DumpFlag)
    WriteStringField(data, fdp);  // bundleName
    WriteUserId(data, fdp);                            // userId
    FinishParcel(data);
    host.HandleDumpInfos(data, reply);
}

// ====== additional high-risk methods batch 4 (12) ======

// 43. HandleGetSandboxAbilityInfo: ReadParcelable<Want>, ReadInt32(appIndex), ReadInt32(flag), ReadInt32(userId)
void FuzzGetSandboxAbilityInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    Want want;
    want.SetBundle(GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL));
    data.WriteParcelable(&want);                                          // Want
    WriteInt32Field(data, fdp);                     // appIndex
    WriteInt32Field(data, fdp);                     // flag
    WriteUserId(data, fdp);                            // userId
    FinishParcel(data);
    host.HandleGetSandboxAbilityInfo(data, reply);
}

// 44. HandleGetSandboxExtAbilityInfos: ReadParcelable<Want>, ReadInt32(appIndex), ReadInt32(flag), ReadInt32(userId)
void FuzzGetSandboxExtAbilityInfos(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    Want want;
    want.SetBundle(GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL));
    data.WriteParcelable(&want);                                          // Want
    WriteInt32Field(data, fdp);                     // appIndex
    WriteInt32Field(data, fdp);                     // flag
    WriteUserId(data, fdp);                            // userId
    FinishParcel(data);
    host.HandleGetSandboxExtAbilityInfos(data, reply);
}

// 45. HandleGetSandboxHapModuleInfo: ReadParcelable<AbilityInfo>, ReadInt32(appIndex), ReadInt32(userId)
void FuzzGetSandboxHapModuleInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    AbilityInfo abilityInfo;
    GenerateAbilityInfo(fdp, abilityInfo);
    data.WriteParcelable(&abilityInfo);                                   // AbilityInfo
    WriteInt32Field(data, fdp);                     // appIndex
    WriteUserId(data, fdp);                            // userId
    FinishParcel(data);
    host.HandleGetSandboxHapModuleInfo(data, reply);
}

// 46. HandleSetAppDistributionTypes: ReadInt32(typesCount), loop ReadInt32(type)
void FuzzSetAppDistributionTypes(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    int32_t typesCount = fdp.ConsumeIntegral<int32_t>() % MAX_TYPE_COUNT;
    data.WriteInt32(typesCount);                                         // typesCount
    for (int32_t i = 0; i < typesCount; i++) {
        WriteInt32Field(data, fdp);                // type
    }
    FinishParcel(data);
    host.HandleSetAppDistributionTypes(data, reply);
}

// 47. HandleBatchGetAdditionalInfo: ReadInt32(bundleNameCount), loop ReadString(bundleName)
void FuzzBatchGetAdditionalInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    int32_t count = fdp.ConsumeIntegral<int32_t>() % MAX_TYPE_COUNT;
    data.WriteInt32(count);                                             // bundleNameCount
    for (int32_t i = 0; i < count; i++) {
        WriteStringField(data, fdp);  // bundleName
    }
    FinishParcel(data);
    host.HandleBatchGetAdditionalInfo(data, reply);
}

// 48. HandleBatchGetBundleInfo: ReadInt32(bundleNameCount), loop ReadString(bundleName)
void FuzzBatchGetBundleInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    int32_t count = fdp.ConsumeIntegral<int32_t>() % MAX_TYPE_COUNT;
    data.WriteInt32(count);                                             // bundleNameCount
    for (int32_t i = 0; i < count; i++) {
        WriteStringField(data, fdp);  // bundleName
    }
    FinishParcel(data);
    host.HandleBatchGetBundleInfo(data, reply);
}

// 49. HandleBatchQueryAbilityInfos: ReadInt32(wantCount), loop ReadParcelable<Want>
void FuzzBatchQueryAbilityInfos(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    int32_t wantCount = fdp.ConsumeIntegral<int32_t>() % MAX_WANT_COUNT;
    data.WriteInt32(wantCount);                                          // wantCount
    for (int32_t i = 0; i < wantCount; i++) {
        Want want;
        want.SetBundle(GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL));
        data.WriteParcelable(&want);                                      // Want
    }
    FinishParcel(data);
    host.HandleBatchQueryAbilityInfos(data, reply);
}

// 50. HandleCanOpenLink: ReadString(link)
void FuzzCanOpenLink(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // link
    FinishParcel(data);
    host.HandleCanOpenLink(data, reply);
}

// 51. HandleCopyAp: ReadString(bundleName), ReadBool(isAllBundle)
void FuzzCopyAp(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteBoolField(data, fdp);                                   // isAllBundle
    FinishParcel(data);
    host.HandleCopyAp(data, reply);
}

 // 52. HandleDelExtNameOrMIMEToApp: ReadString(bundleName), ReadString(moduleName), ReadString(abilityName),
// ReadString(extName), ReadString(mimeType)
void FuzzDelExtNameOrMIMEToApp(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WritePlainString(data, fdp);  // moduleName
    WritePlainString(data, fdp);  // abilityName
    WriteStringField(data, fdp);  // extName
    WritePlainString(data, fdp);  // mimeType
    FinishParcel(data);
    host.HandleDelExtNameOrMIMEToApp(data, reply);
}

// 53. HandleCleanBundleCacheFilesAutomatic: ReadUint64(cacheSize)
void FuzzCleanBundleCacheFilesAutomatic(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteUint64Field(data, fdp);                   // cacheSize
    FinishParcel(data);
    host.HandleCleanBundleCacheFilesAutomatic(data, reply);
}

// 54. HandleCleanBundlePartialCacheAutomatic: ReadParcelable<CleanCacheInfo>
void FuzzCleanBundlePartialCacheAutomatic(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    CleanCacheInfo cleanCacheInfo;
    GenerateCleanCacheInfo(fdp, cleanCacheInfo);
    data.WriteParcelable(&cleanCacheInfo);  // CleanCacheInfo
    FinishParcel(data);
    host.HandleCleanBundlePartialCacheAutomatic(data, reply);
}

// 55. HandleSetApplicationDisableForbidden: ReadString(bundleName), ReadInt32(userId), ReadInt32(appIndex),
// ReadBool(forbidden)
void FuzzSetApplicationDisableForbidden(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteUserId(data, fdp);                            // userId
    WriteInt32Field(data, fdp);                     // appIndex
    WriteBoolField(data, fdp);                                   // forbidden
    FinishParcel(data);
    host.HandleSetApplicationDisableForbidden(data, reply);
}

// 56. HandleRecoverBackupBundleData: ReadString(bundleName), ReadInt32(userId), ReadInt32(appIndex)
void FuzzRecoverBackupBundleData(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteUserId(data, fdp);                            // userId
    WriteInt32Field(data, fdp);                     // appIndex
    FinishParcel(data);
    host.HandleRecoverBackupBundleData(data, reply);
}

// 57. HandleRemoveBackupBundleData: ReadString(bundleName), ReadInt32(userId), ReadInt32(appIndex)
void FuzzRemoveBackupBundleData(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteUserId(data, fdp);                            // userId
    WriteInt32Field(data, fdp);                     // appIndex
    FinishParcel(data);
    host.HandleRemoveBackupBundleData(data, reply);
}

// ====== additional high-risk methods batch 5 (17) ======

// 58. HandleGetSandboxDataDir: ReadString(bundleName), ReadInt32(appIndex)
void FuzzGetSandboxDataDir(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteInt32Field(data, fdp);  // appIndex
    FinishParcel(data);
    host.HandleGetSandboxDataDir(data, reply);
}

// 59. HandleGetSignatureInfoByUid: ReadInt32(uid)
void FuzzGetSignatureInfoByUid(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteInt32Field(data, fdp);  // uid
    FinishParcel(data);
    host.HandleGetSignatureInfoByUid(data, reply);
}

// 60. HandleIsDebuggableApplication: ReadString(bundleName)
void FuzzIsDebuggableApplication(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    FinishParcel(data);
    host.HandleIsDebuggableApplication(data, reply);
}

// 61. HandleResetAllAOT: no params (empty Parcel)
void FuzzResetAllAOT(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    FinishParcel(data);
    host.HandleResetAllAOT(data, reply);
}

// 62. HandleSetShortcutVisibleForSelf: ReadString(shortcutId), ReadBool(visible)
void FuzzSetShortcutVisibleForSelf(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // shortcutId
    WriteBoolField(data, fdp);  // visible
    FinishParcel(data);
    host.HandleSetShortcutVisibleForSelf(data, reply);
}

// 63. HandleIsApplicationDisableForbidden: ReadString(bundleName), ReadInt32(userId), ReadInt32(appIndex)
void FuzzIsApplicationDisableForbidden(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteUserId(data, fdp);  // userId
    WriteInt32Field(data, fdp);  // appIndex
    FinishParcel(data);
    host.HandleIsApplicationDisableForbidden(data, reply);
}

// 64. HandleCleanBundleCacheFilesForSelf: ReadRemoteObject(object)
void FuzzCleanBundleCacheFilesForSelf(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteRemoteObject(data);  // object
    FinishParcel(data);
    host.HandleCleanBundleCacheFilesForSelf(data, reply);
}

// 65. HandleRegisterBundleEventCallback: ReadRemoteObject(object)
void FuzzRegisterBundleEventCallback(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteRemoteObject(data);  // object
    FinishParcel(data);
    host.HandleRegisterBundleEventCallback(data, reply);
}

// 66. HandleRegisterPluginEventCallback: ReadRemoteObject(object)
void FuzzRegisterPluginEventCallback(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteRemoteObject(data);  // object
    FinishParcel(data);
    host.HandleRegisterPluginEventCallback(data, reply);
}

// 67. HandleUnregisterBundleEventCallback: ReadRemoteObject(object)
void FuzzUnregisterBundleEventCallback(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteRemoteObject(data);  // object
    FinishParcel(data);
    host.HandleUnregisterBundleEventCallback(data, reply);
}

// 68. HandleUnregisterPluginEventCallback: ReadRemoteObject(object)
void FuzzUnregisterPluginEventCallback(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteRemoteObject(data);  // object
    FinishParcel(data);
    host.HandleUnregisterPluginEventCallback(data, reply);
}

// 69. HandleDeleteDynamicShortcutInfos: ReadString(bundleName), ReadInt32(appIndex), ReadInt32(userId),
// ReadStringVector(ids)
void FuzzDeleteDynamicShortcutInfos(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteInt32Field(data, fdp);  // appIndex
    WriteUserId(data, fdp);  // userId
    WriteStringVectorField(data, fdp);  // ids
    FinishParcel(data);
    host.HandleDeleteDynamicShortcutInfos(data, reply);
}

// 70. HandleSetAbilityFileTypesForSelf: ReadString(moduleName), ReadString(abilityName), ReadStringVector(fileTypes)
void FuzzSetAbilityFileTypesForSelf(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // moduleName
    WritePlainString(data, fdp);  // abilityName
    WriteStringVectorField(data, fdp);  // fileTypes
    FinishParcel(data);
    host.HandleSetAbilityFileTypesForSelf(data, reply);
}

// 71. HandleUpdateDesktopShortcutInfo: ReadParcelInfoIntelligent<ShortcutInfo>(Uint32(size)+RawData+ParseFrom+
// ReadParcelable), ReadInt32(userId)
void FuzzUpdateDesktopShortcutInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    // Build ShortcutInfo into tempParcel, then wrap with Uint32(size)+RawData to mirror ReadParcelInfoIntelligent
    MessageParcel tempParcel;
    ShortcutInfo shortcutInfo;
    GenerateShortcutInfo(fdp, shortcutInfo);
    tempParcel.WriteParcelable(&shortcutInfo);  // ShortcutInfo (inside tempParcel)
    size_t dataSize = tempParcel.GetDataSize();
    data.WriteUint32(dataSize);  // size header read by ReadParcelInfoIntelligent
    // RawData payload parsed by ParseFrom
    data.WriteRawData(reinterpret_cast<const void*>(tempParcel.GetData()), dataSize);
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleUpdateDesktopShortcutInfo(data, reply);
}

// 72. HandleAddDynamicShortcutInfos: GetVectorParcelInfoIntelligent<vector<ShortcutInfo>>(Uint32(size)+RawData+
// ParseFrom+Int32(count)+parcelables), ReadInt32(userId)
void FuzzAddDynamicShortcutInfos(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    // Build vector of ShortcutInfo into tempParcel: Int32(count)+WriteParcelable*N, wrap with Uint32+RawData
    MessageParcel tempParcel;
    int32_t infoSize = fdp.ConsumeIntegralInRange<int32_t>(1, MAX_TYPE_COUNT);  // 1..8 in MAX_SHORTCUT_INFO_SIZE
    tempParcel.WriteInt32(infoSize);  // infoSize read by GetVectorParcelInfoIntelligent
    for (int32_t i = 0; i < infoSize; i++) {
        ShortcutInfo shortcutInfo;
        GenerateShortcutInfo(fdp, shortcutInfo);
        tempParcel.WriteParcelable(&shortcutInfo);  // ShortcutInfo item
    }
    size_t dataSize = tempParcel.GetDataSize();
    data.WriteUint32(dataSize);  // size header read by GetVectorParcelInfoIntelligent
    // RawData payload parsed by ParseFrom
    data.WriteRawData(reinterpret_cast<const void*>(tempParcel.GetData()), dataSize);
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleAddDynamicShortcutInfos(data, reply);
}

// 73. HandleSetShortcutsEnabled: GetVectorParcelInfoIntelligent<vector<ShortcutInfo>>(Uint32(size)+RawData+ParseFrom+
// Int32(count)+parcelables), ReadBool(isEnabled)
void FuzzSetShortcutsEnabled(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    // Build vector of ShortcutInfo into tempParcel: Int32(count)+WriteParcelable*N, wrap with Uint32+RawData
    MessageParcel tempParcel;
    int32_t infoSize = fdp.ConsumeIntegralInRange<int32_t>(1, MAX_TYPE_COUNT);  // 1..8 in MAX_SHORTCUT_INFO_SIZE
    tempParcel.WriteInt32(infoSize);  // infoSize read by GetVectorParcelInfoIntelligent
    for (int32_t i = 0; i < infoSize; i++) {
        ShortcutInfo shortcutInfo;
        GenerateShortcutInfo(fdp, shortcutInfo);
        tempParcel.WriteParcelable(&shortcutInfo);  // ShortcutInfo item
    }
    size_t dataSize = tempParcel.GetDataSize();
    data.WriteUint32(dataSize);  // size header read by GetVectorParcelInfoIntelligent
    // RawData payload parsed by ParseFrom
    data.WriteRawData(reinterpret_cast<const void*>(tempParcel.GetData()), dataSize);
    WriteBoolField(data, fdp);  // isEnabled
    FinishParcel(data);
    host.HandleSetShortcutsEnabled(data, reply);
}

// 74. HandleStartAppDetailAbility: no params (empty Parcel)
void FuzzStartAppDetailAbility(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    FinishParcel(data);
    host.HandleStartAppDetailAbility(data, reply);
}

// ====== P2 query methods batch (Get/Query/Is/Batch/Verify/Process/Obtain/Upgrade/Implicit/Reset) ======

// 76. HandleGetApplicationInfo: ReadString(name), ReadInt32(flag), ReadInt32(userId)
void FuzzGetApplicationInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // name
    WriteInt32Field(data, fdp);  // flag (ApplicationFlag)
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetApplicationInfo(data, reply);
}

// 77. HandleGetApplicationInfoWithIntFlags: ReadString(name), ReadInt32(flags), ReadInt32(userId)
void FuzzGetApplicationInfoWithIntFlags(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // name
    WriteInt32Field(data, fdp);  // flags
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetApplicationInfoWithIntFlags(data, reply);
}

// 78. HandleGetApplicationInfoWithIntFlagsV9: ReadString(name), ReadInt32(flags), ReadInt32(userId)
void FuzzGetApplicationInfoWithIntFlagsV9(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // name
    WriteInt32Field(data, fdp);  // flags
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetApplicationInfoWithIntFlagsV9(data, reply);
}

// 79. HandleGetApplicationInfos: ReadInt32(flag), ReadInt32(userId)
void FuzzGetApplicationInfos(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteInt32Field(data, fdp);  // flag (ApplicationFlag)
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetApplicationInfos(data, reply);
}

// 80. HandleGetApplicationInfosWithIntFlags: ReadInt32(flags), ReadInt32(userId)
void FuzzGetApplicationInfosWithIntFlags(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteInt32Field(data, fdp);  // flags
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetApplicationInfosWithIntFlags(data, reply);
}

// 81. HandleGetApplicationInfosWithIntFlagsV9: ReadInt32(flags), ReadInt32(userId)
void FuzzGetApplicationInfosWithIntFlagsV9(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteInt32Field(data, fdp);  // flags
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetApplicationInfosWithIntFlagsV9(data, reply);
}

// 82. HandleGetBundleInfo: ReadString(name), ReadInt32(flag), ReadInt32(userId)
void FuzzGetBundleInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // name
    WriteInt32Field(data, fdp);  // flag (BundleFlag)
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetBundleInfo(data, reply);
}

// 83. HandleGetBundleInfoWithIntFlags: ReadString(name), ReadInt32(flags), ReadInt32(userId)
void FuzzGetBundleInfoWithIntFlags(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // name
    WriteInt32Field(data, fdp);  // flags
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetBundleInfoWithIntFlags(data, reply);
}

// 84. HandleGetBundleInfoWithIntFlagsV9: ReadString(name), ReadInt32(flags), ReadInt32(userId)
void FuzzGetBundleInfoWithIntFlagsV9(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // name
    WriteInt32Field(data, fdp);  // flags
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetBundleInfoWithIntFlagsV9(data, reply);
}

// 85. HandleGetBundlePackInfo: ReadString(name), ReadInt32(flag), ReadInt32(userId)
void FuzzGetBundlePackInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // name
    WriteInt32Field(data, fdp);  // flag (BundlePackFlag)
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetBundlePackInfo(data, reply);
}

// 86. HandleGetBundlePackInfoWithIntFlags: ReadString(name), ReadInt32(flags), ReadInt32(userId)
void FuzzGetBundlePackInfoWithIntFlags(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // name
    WriteInt32Field(data, fdp);  // flags
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetBundlePackInfoWithIntFlags(data, reply);
}

// 87. HandleGetBundleInfos: ReadInt32(flag), ReadInt32(userId)
void FuzzGetBundleInfos(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteInt32Field(data, fdp);  // flag (BundleFlag)
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetBundleInfos(data, reply);
}

// 88. HandleGetBundleInfosWithIntFlags: ReadInt32(flags), ReadInt32(userId)
void FuzzGetBundleInfosWithIntFlags(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteInt32Field(data, fdp);  // flags
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetBundleInfosWithIntFlags(data, reply);
}

// 89. HandleGetBundleInfosWithIntFlagsV9: ReadInt32(flags), ReadInt32(userId)
void FuzzGetBundleInfosWithIntFlagsV9(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteInt32Field(data, fdp);  // flags
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetBundleInfosWithIntFlagsV9(data, reply);
}

// 90. HandleGetBundleNameForUid: ReadInt32(uid)
void FuzzGetBundleNameForUid(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteInt32Field(data, fdp);  // uid
    FinishParcel(data);
    host.HandleGetBundleNameForUid(data, reply);
}

// 91. HandleGetBundlesForUid: ReadInt32(uid)
void FuzzGetBundlesForUid(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteInt32Field(data, fdp);  // uid
    FinishParcel(data);
    host.HandleGetBundlesForUid(data, reply);
}

// 92. HandleGetNameForUid: ReadInt32(uid)
void FuzzGetNameForUid(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteInt32Field(data, fdp);  // uid
    FinishParcel(data);
    host.HandleGetNameForUid(data, reply);
}

// 93. HandleGetNameAndIndexForUid: ReadInt32(uid)
void FuzzGetNameAndIndexForUid(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteInt32Field(data, fdp);  // uid
    FinishParcel(data);
    host.HandleGetNameAndIndexForUid(data, reply);
}

// 94. HandleGetAppIdentifierAndAppIndex: ReadUint32(accessTokenId)
void FuzzGetAppIdentifierAndAppIndex(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteUint32Field(data, fdp);  // accessTokenId
    FinishParcel(data);
    host.HandleGetAppIdentifierAndAppIndex(data, reply);
}

// 95. HandleGetBundleGids: ReadString(name)
void FuzzGetBundleGids(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // name
    FinishParcel(data);
    host.HandleGetBundleGids(data, reply);
}

// 96. HandleGetBundleGidsByUid: ReadString(name), ReadInt32(uid)
void FuzzGetBundleGidsByUid(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // name
    WriteInt32Field(data, fdp);  // uid
    FinishParcel(data);
    host.HandleGetBundleGidsByUid(data, reply);
}

// 97. HandleGetBundleInfosByMetaData: ReadString(metaData)
void FuzzGetBundleInfosByMetaData(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // metaData
    FinishParcel(data);
    host.HandleGetBundleInfosByMetaData(data, reply);
}

// 98. HandleQueryAbilityInfoMutiparam: ReadParcelable<Want>, ReadInt32(flags), ReadInt32(userId)
void FuzzQueryAbilityInfoMutiparam(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteWant(data, fdp);  // Want
    WriteInt32Field(data, fdp);  // flags
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleQueryAbilityInfoMutiparam(data, reply);
}

// 99. HandleQueryAbilityInfos: ReadParcelable<Want>
void FuzzQueryAbilityInfos(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteWant(data, fdp);  // Want
    FinishParcel(data);
    host.HandleQueryAbilityInfos(data, reply);
}

// 100. HandleQueryAbilityInfosMutiparam: ReadParcelable<Want>, ReadInt32(flags), ReadInt32(userId)
void FuzzQueryAbilityInfosMutiparam(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteWant(data, fdp);  // Want
    WriteInt32Field(data, fdp);  // flags
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleQueryAbilityInfosMutiparam(data, reply);
}

// 101. HandleQueryAbilityInfosV9: ReadParcelable<Want>, ReadInt32(flags), ReadInt32(userId)
void FuzzQueryAbilityInfosV9(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteWant(data, fdp);  // Want
    WriteInt32Field(data, fdp);  // flags
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleQueryAbilityInfosV9(data, reply);
}

// 102. HandleQueryLauncherAbilityInfos: ReadParcelable<Want>, ReadInt32(userId)
void FuzzQueryLauncherAbilityInfos(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteWant(data, fdp);  // Want
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleQueryLauncherAbilityInfos(data, reply);
}

// 103. HandleGetLauncherAbilityInfoSync: ReadString(bundleName), ReadInt32(userId)
void FuzzGetLauncherAbilityInfoSync(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetLauncherAbilityInfoSync(data, reply);
}

// 104. HandleQueryAllAbilityInfos: ReadParcelable<Want>, ReadInt32(userId)
void FuzzQueryAllAbilityInfos(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteWant(data, fdp);  // Want
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleQueryAllAbilityInfos(data, reply);
}

// 105. HandleQueryAbilityInfoByUri: ReadString(abilityUri)
void FuzzQueryAbilityInfoByUri(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // abilityUri
    FinishParcel(data);
    host.HandleQueryAbilityInfoByUri(data, reply);
}

// 106. HandleQueryAbilityInfosByUri: ReadString(abilityUri)
void FuzzQueryAbilityInfosByUri(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // abilityUri
    FinishParcel(data);
    host.HandleQueryAbilityInfosByUri(data, reply);
}

// 107. HandleQueryAbilityInfoByUriForUserId: ReadString(abilityUri), ReadInt32(userId)
void FuzzQueryAbilityInfoByUriForUserId(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // abilityUri
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleQueryAbilityInfoByUriForUserId(data, reply);
}

// 108. HandleQueryKeepAliveBundleInfos: no params (empty Parcel)
void FuzzQueryKeepAliveBundleInfos(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    FinishParcel(data);
    host.HandleQueryKeepAliveBundleInfos(data, reply);
}

// 109. HandleGetAbilityLabel: ReadString(bundleName), ReadString(abilityName)
void FuzzGetAbilityLabel(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WritePlainString(data, fdp);  // abilityName
    FinishParcel(data);
    host.HandleGetAbilityLabel(data, reply);
}

// 110. HandleGetAbilityLabelWithModuleName: ReadString(bundleName), ReadString(moduleName), ReadString(abilityName)
void FuzzGetAbilityLabelWithModuleName(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WritePlainString(data, fdp);  // moduleName
    WritePlainString(data, fdp);  // abilityName
    FinishParcel(data);
    host.HandleGetAbilityLabelWithModuleName(data, reply);
}

// 111. HandleGetApplicationLabel: ReadString(bundleName), ReadInt32(appIndex)
void FuzzGetApplicationLabel(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteInt32Field(data, fdp);  // appIndex
    FinishParcel(data);
    host.HandleGetApplicationLabel(data, reply);
}

// 112. HandleGetBundleArchiveInfo: ReadString(hapFilePath), ReadInt32(flag)
void FuzzGetBundleArchiveInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp, ATTACK_PATH_TRAVERSAL);  // hapFilePath (path-sensitive)
    WriteInt32Field(data, fdp);  // flag (BundleFlag)
    FinishParcel(data);
    host.HandleGetBundleArchiveInfo(data, reply);
}

// 113. HandleGetBundleArchiveInfoWithIntFlags: ReadString(hapFilePath), ReadInt32(flags)
void FuzzGetBundleArchiveInfoWithIntFlags(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp, ATTACK_PATH_TRAVERSAL);  // hapFilePath (path-sensitive)
    WriteInt32Field(data, fdp);  // flags
    FinishParcel(data);
    host.HandleGetBundleArchiveInfoWithIntFlags(data, reply);
}

// 114. HandleGetBundleArchiveInfoWithIntFlagsV9: ReadString(hapFilePath), ReadInt32(flags)
void FuzzGetBundleArchiveInfoWithIntFlagsV9(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp, ATTACK_PATH_TRAVERSAL);  // hapFilePath (path-sensitive)
    WriteInt32Field(data, fdp);  // flags
    FinishParcel(data);
    host.HandleGetBundleArchiveInfoWithIntFlagsV9(data, reply);
}

// 115. HandleGetHapModuleInfo: ReadParcelable<AbilityInfo>
void FuzzGetHapModuleInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    AbilityInfo abilityInfo;
    GenerateAbilityInfo(fdp, abilityInfo);
    data.WriteParcelable(&abilityInfo);  // AbilityInfo
    FinishParcel(data);
    host.HandleGetHapModuleInfo(data, reply);
}

// 116. HandleGetHapModuleInfoWithUserId: ReadParcelable<AbilityInfo>, ReadInt32(userId)
void FuzzGetHapModuleInfoWithUserId(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    AbilityInfo abilityInfo;
    GenerateAbilityInfo(fdp, abilityInfo);
    data.WriteParcelable(&abilityInfo);  // AbilityInfo
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetHapModuleInfoWithUserId(data, reply);
}

// 117. HandleGetLaunchWantForBundle: ReadString(bundleName), ReadInt32(userId), ReadBool(isSync)
void FuzzGetLaunchWantForBundle(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteUserId(data, fdp);  // userId
    WriteBoolField(data, fdp);  // isSync
    FinishParcel(data);
    host.HandleGetLaunchWantForBundle(data, reply);
}

// 118. HandleGetPermissionDef: ReadString(permissionName)
void FuzzGetPermissionDef(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp, ATTACK_SELINUX);  // permissionName (security related)
    FinishParcel(data);
    host.HandleGetPermissionDef(data, reply);
}

// 119. HandleCleanBundleCacheFilesAutomaticByType: ReadUint64(cacheSize), ReadInt8(cleanType)
void FuzzCleanBundleCacheFilesAutomaticByType(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteUint64Field(data, fdp);  // cacheSize
    data.WriteInt8(fdp.ConsumeIntegral<int8_t>());  // cleanType (CleanType)
    FinishParcel(data);
    host.HandleCleanBundleCacheFilesAutomaticByType(data, reply);
}

// 120. HandleRegisterBundleStatusCallback: ReadString(bundleName), ReadInt32(userId), ReadRemoteObject(object)
void FuzzRegisterBundleStatusCallback(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteUserId(data, fdp);  // userId
    WriteRemoteObject(data);  // object
    FinishParcel(data);
    host.HandleRegisterBundleStatusCallback(data, reply);
}

// 121. HandleClearBundleStatusCallback: ReadRemoteObject(object)
void FuzzClearBundleStatusCallback(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteRemoteObject(data);  // object
    FinishParcel(data);
    host.HandleClearBundleStatusCallback(data, reply);
}

// 122. HandleUnregisterBundleStatusCallback: no params (empty Parcel)
void FuzzUnregisterBundleStatusCallback(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    FinishParcel(data);
    host.HandleUnregisterBundleStatusCallback(data, reply);
}

// 123. HandleIsApplicationEnabled: ReadString(bundleName)
void FuzzIsApplicationEnabled(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    FinishParcel(data);
    host.HandleIsApplicationEnabled(data, reply);
}

// 124. HandleIsAbilityEnabled: ReadParcelable<AbilityInfo>
void FuzzIsAbilityEnabled(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    AbilityInfo abilityInfo;
    GenerateAbilityInfo(fdp, abilityInfo);
    data.WriteParcelable(&abilityInfo);  // AbilityInfo
    FinishParcel(data);
    host.HandleIsAbilityEnabled(data, reply);
}

// 125. HandleIsCloneApplicationEnabled: ReadString(bundleName), ReadInt32(appIndex)
void FuzzIsCloneApplicationEnabled(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteInt32Field(data, fdp);  // appIndex
    FinishParcel(data);
    host.HandleIsCloneApplicationEnabled(data, reply);
}

// 126. HandleIsCloneAbilityEnabled: ReadParcelable<AbilityInfo>, ReadInt32(appIndex)
void FuzzIsCloneAbilityEnabled(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    AbilityInfo abilityInfo;
    GenerateAbilityInfo(fdp, abilityInfo);
    data.WriteParcelable(&abilityInfo);  // AbilityInfo
    WriteInt32Field(data, fdp);  // appIndex
    FinishParcel(data);
    host.HandleIsCloneAbilityEnabled(data, reply);
}

// 127. HandleIsModuleRemovable: ReadString(bundleName), ReadString(moduleName)
void FuzzIsModuleRemovable(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WritePlainString(data, fdp);  // moduleName
    FinishParcel(data);
    host.HandleIsModuleRemovable(data, reply);
}

// 128. HandleGetAbilityInfoWithModuleName: ReadString(bundleName), ReadString(moduleName), ReadString(abilityName)
void FuzzGetAbilityInfoWithModuleName(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WritePlainString(data, fdp);  // moduleName
    WritePlainString(data, fdp);  // abilityName
    FinishParcel(data);
    host.HandleGetAbilityInfoWithModuleName(data, reply);
}

// 129. HandleGetBundleInstaller: no params (empty Parcel)
void FuzzGetBundleInstaller(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    FinishParcel(data);
    host.HandleGetBundleInstaller(data, reply);
}

// 130. HandleGetLocalPluginInstaller: no params (empty Parcel)
void FuzzGetLocalPluginInstaller(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    FinishParcel(data);
    host.HandleGetLocalPluginInstaller(data, reply);
}

// 131. HandleGetBundleUserMgr: no params (empty Parcel)
void FuzzGetBundleUserMgr(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    FinishParcel(data);
    host.HandleGetBundleUserMgr(data, reply);
}

// 132. HandleGetVerifyManager: no params (empty Parcel)
void FuzzGetVerifyManager(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    FinishParcel(data);
    host.HandleGetVerifyManager(data, reply);
}

// 133. HandleGetExtendResourceManager: no params (empty Parcel)
void FuzzGetExtendResourceManager(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    FinishParcel(data);
    host.HandleGetExtendResourceManager(data, reply);
}

// 134. HandleGetAllFormsInfo: no params (empty Parcel)
void FuzzGetAllFormsInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    FinishParcel(data);
    host.HandleGetAllFormsInfo(data, reply);
}

// 135. HandleGetFormsInfoByApp: ReadString(bundlename)
void FuzzGetFormsInfoByApp(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundlename
    FinishParcel(data);
    host.HandleGetFormsInfoByApp(data, reply);
}

// 136. HandleGetFormsInfoByModule: ReadString(bundlename), ReadString(modulename)
void FuzzGetFormsInfoByModule(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundlename
    WritePlainString(data, fdp);  // modulename
    FinishParcel(data);
    host.HandleGetFormsInfoByModule(data, reply);
}

// 137. HandleGetShortcutInfos: ReadString(bundlename)
void FuzzGetShortcutInfos(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundlename
    FinishParcel(data);
    host.HandleGetShortcutInfos(data, reply);
}

// 138. HandleGetShortcutInfoV9: ReadString(bundlename), ReadInt32(userId)
void FuzzGetShortcutInfoV9(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundlename
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetShortcutInfoV9(data, reply);
}

// 139. HandleGetShortcutInfoByAppIndex: ReadString(bundlename), ReadInt32(appIndex)
void FuzzGetShortcutInfoByAppIndex(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundlename
    WriteInt32Field(data, fdp);  // appIndex
    FinishParcel(data);
    host.HandleGetShortcutInfoByAppIndex(data, reply);
}

// 140. HandleGetAllCommonEventInfo: ReadString(eventKey)
void FuzzGetAllCommonEventInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // eventKey
    FinishParcel(data);
    host.HandleGetAllCommonEventInfo(data, reply);
}

// 141. HandleGetDistributedBundleInfo: ReadString(networkId), ReadString(bundleName)
void FuzzGetDistributedBundleInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // networkId
    WriteStringField(data, fdp);  // bundleName
    FinishParcel(data);
    host.HandleGetDistributedBundleInfo(data, reply);
}

// 142. HandleGetAppPrivilegeLevel: ReadString(bundleName), ReadInt32(userId)
void FuzzGetAppPrivilegeLevel(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetAppPrivilegeLevel(data, reply);
}

// 143. HandleVerifyCallingPermission: ReadString(permission)
void FuzzVerifyCallingPermission(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp, ATTACK_SELINUX);  // permission (security related)
    FinishParcel(data);
    host.HandleVerifyCallingPermission(data, reply);
}

// 144. HandleQueryExtensionAbilityInfoByUri: ReadString(uri), ReadInt32(userId)
void FuzzQueryExtensionAbilityInfoByUri(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // uri
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleQueryExtensionAbilityInfoByUri(data, reply);
}

// 145. HandleQueryExtensionAbilityInfoByUriOptimal: ReadString(uri), ReadInt32(userId)
void FuzzQueryExtensionAbilityInfoByUriOptimal(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // uri
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleQueryExtensionAbilityInfoByUriOptimal(data, reply);
}

// 146. HandleGetAppIdByBundleName: ReadString(bundleName), ReadInt32(userId)
void FuzzGetAppIdByBundleName(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetAppIdByBundleName(data, reply);
}

// 147. HandleGetAppType: ReadString(bundleName)
void FuzzGetAppType(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    FinishParcel(data);
    host.HandleGetAppType(data, reply);
}

// 148. HandleGetUidByBundleName: ReadString(bundleName), ReadInt32(userId), ReadInt32(appIndex)
void FuzzGetUidByBundleName(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteUserId(data, fdp);  // userId
    WriteInt32Field(data, fdp);  // appIndex
    FinishParcel(data);
    host.HandleGetUidByBundleName(data, reply);
}

// 149. HandleGetModuleUpgradeFlag: ReadString(bundleName), ReadString(moduleName)
void FuzzGetModuleUpgradeFlag(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WritePlainString(data, fdp);  // moduleName
    FinishParcel(data);
    host.HandleGetModuleUpgradeFlag(data, reply);
}

// 150. HandleSetModuleUpgradeFlag: ReadString(bundleName), ReadString(moduleName), ReadInt32(upgradeFlag)
void FuzzSetModuleUpgradeFlag(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WritePlainString(data, fdp);  // moduleName
    WriteInt32Field(data, fdp);  // upgradeFlag
    FinishParcel(data);
    host.HandleSetModuleUpgradeFlag(data, reply);
}

// 151. HandleImplicitQueryInfoByPriority: ReadParcelable<Want>, ReadInt32(flags), ReadInt32(userId)
void FuzzImplicitQueryInfoByPriority(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteWant(data, fdp);  // Want
    WriteInt32Field(data, fdp);  // flags
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleImplicitQueryInfoByPriority(data, reply);
}

// 152. HandleImplicitQueryInfos: ReadParcelable<Want>, ReadInt32(flags), ReadInt32(userId), ReadBool(withDefault),
// ReadBool(findDefaultApp)
void FuzzImplicitQueryInfos(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteWant(data, fdp);  // Want
    WriteInt32Field(data, fdp);  // flags
    WriteUserId(data, fdp);  // userId
    WriteBoolField(data, fdp);  // withDefault
    WriteBoolField(data, fdp);  // findDefaultApp
    FinishParcel(data);
    host.HandleImplicitQueryInfos(data, reply);
}

// 153. HandleGetAllDependentModuleNames: ReadString(bundleName), ReadString(moduleName)
void FuzzGetAllDependentModuleNames(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WritePlainString(data, fdp);  // moduleName
    FinishParcel(data);
    host.HandleGetAllDependentModuleNames(data, reply);
}

// 154. HandleObtainCallingBundleName: no params (empty Parcel)
void FuzzObtainCallingBundleName(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    FinishParcel(data);
    host.HandleObtainCallingBundleName(data, reply);
}

// 155. HandleCheckAbilityEnableInstall: ReadParcelable<Want>, ReadInt32(missionId), ReadInt32(userId),
// ReadRemoteObject(object)
void FuzzCheckAbilityEnableInstall(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteWant(data, fdp);  // Want
    WriteInt32Field(data, fdp);  // missionId
    WriteUserId(data, fdp);  // userId
    WriteRemoteObject(data);  // object
    FinishParcel(data);
    host.HandleCheckAbilityEnableInstall(data, reply);
}

// 156. HandleGetStringById: ReadString(bundleName), ReadString(moduleName), ReadUint32(resId), ReadInt32(userId),
// ReadString(localeInfo)
void FuzzGetStringById(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WritePlainString(data, fdp);  // moduleName
    WriteUint32Field(data, fdp);  // resId
    WriteUserId(data, fdp);  // userId
    WritePlainString(data, fdp);  // localeInfo
    FinishParcel(data);
    host.HandleGetStringById(data, reply);
}

// 157. HandleGetIconById: ReadString(bundleName), ReadString(moduleName), ReadUint32(resId), ReadUint32(density),
// ReadInt32(userId)
void FuzzGetIconById(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WritePlainString(data, fdp);  // moduleName
    WriteUint32Field(data, fdp);  // resId
    WriteUint32Field(data, fdp);  // density
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetIconById(data, reply);
}

// 158. HandleGetBundleMgrExtProxy: no params (empty Parcel)
void FuzzGetBundleMgrExtProxy(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    FinishParcel(data);
    host.HandleGetBundleMgrExtProxy(data, reply);
}

// 159. HandleGetBundleInfoForSelf: ReadInt32(flags)
void FuzzGetBundleInfoForSelf(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteInt32Field(data, fdp);  // flags
    FinishParcel(data);
    host.HandleGetBundleInfoForSelf(data, reply);
}

// 160. HandleVerifySystemApi: ReadInt32(beginApiVersion)
void FuzzVerifySystemApi(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteInt32Field(data, fdp);  // beginApiVersion
    FinishParcel(data);
    host.HandleVerifySystemApi(data, reply);
}

// 161. HandleGetOverlayManagerProxy: no params (empty Parcel)
void FuzzGetOverlayManagerProxy(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    FinishParcel(data);
    host.HandleGetOverlayManagerProxy(data, reply);
}

// 162. HandleProcessPreload: ReadParcelable<Want>
void FuzzProcessPreload(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteWant(data, fdp);  // Want
    FinishParcel(data);
    host.HandleProcessPreload(data, reply);
}

// 163. HandleUpgradeAtomicService: ReadParcelable<Want>, ReadInt32(userId)
void FuzzUpgradeAtomicService(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteWant(data, fdp);  // Want
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleUpgradeAtomicService(data, reply);
}

// 164. HandleGetBaseSharedBundleInfos: ReadString(bundleName), ReadUint32(flag)
void FuzzGetBaseSharedBundleInfos(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteUint32Field(data, fdp);  // flag (GetDependentBundleInfoFlag)
    FinishParcel(data);
    host.HandleGetBaseSharedBundleInfos(data, reply);
}

// 165. HandleGetAllSharedBundleInfo: no params (empty Parcel)
void FuzzGetAllSharedBundleInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    FinishParcel(data);
    host.HandleGetAllSharedBundleInfo(data, reply);
}

// 166. HandleGetSharedBundleInfo: ReadString(bundleName), ReadString(moduleName)
void FuzzGetSharedBundleInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WritePlainString(data, fdp);  // moduleName
    FinishParcel(data);
    host.HandleGetSharedBundleInfo(data, reply);
}

// 167. HandleGetSharedBundleInfoBySelf: ReadString(bundleName)
void FuzzGetSharedBundleInfoBySelf(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    FinishParcel(data);
    host.HandleGetSharedBundleInfoBySelf(data, reply);
}

// 168. HandleGetSharedDependencies: ReadString(bundleName), ReadString(moduleName)
void FuzzGetSharedDependencies(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WritePlainString(data, fdp);  // moduleName
    FinishParcel(data);
    host.HandleGetSharedDependencies(data, reply);
}

// 169. HandleGetDependentBundleInfo: ReadString(name), ReadUint32(flag)
void FuzzGetDependentBundleInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // name
    WriteUint32Field(data, fdp);  // flag (GetDependentBundleInfoFlag)
    FinishParcel(data);
    host.HandleGetDependentBundleInfo(data, reply);
}

// 170. HandleGetProxyDataInfos: ReadString(bundleName), ReadString(moduleName), ReadInt32(userId)
void FuzzGetProxyDataInfos(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WritePlainString(data, fdp);  // moduleName
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetProxyDataInfos(data, reply);
}

// 171. HandleGetAllProxyDataInfos: ReadInt32(userId)
void FuzzGetAllProxyDataInfos(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetAllProxyDataInfos(data, reply);
}

// 172. HandleGetSpecifiedDistributionType: ReadString(bundleName)
void FuzzGetSpecifiedDistributionType(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    FinishParcel(data);
    host.HandleGetSpecifiedDistributionType(data, reply);
}

// 173. HandleGetAdditionalInfo: ReadString(bundleName)
void FuzzGetAdditionalInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    FinishParcel(data);
    host.HandleGetAdditionalInfo(data, reply);
}

// 174. HandleGetAdditionalInfoForAllUser: ReadString(bundleName)
void FuzzGetAdditionalInfoForAllUser(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    FinishParcel(data);
    host.HandleGetAdditionalInfoForAllUser(data, reply);
}

// 175. HandleSetExtNameOrMIMEToApp: ReadString(bundleName), ReadString(moduleName), ReadString(abilityName),
// ReadString(extName), ReadString(mimeType)
void FuzzSetExtNameOrMIMEToApp(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WritePlainString(data, fdp);  // moduleName
    WritePlainString(data, fdp);  // abilityName
    WriteStringField(data, fdp);  // extName
    WritePlainString(data, fdp);  // mimeType
    FinishParcel(data);
    host.HandleSetExtNameOrMIMEToApp(data, reply);
}

// 176. HandleQueryDataGroupInfos: ReadString(bundleName), ReadInt32(userId)
void FuzzQueryDataGroupInfos(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleQueryDataGroupInfos(data, reply);
}

// 177. HandleGetPreferenceDirByGroupId: ReadString(dataGroupId)
void FuzzGetPreferenceDirByGroupId(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // dataGroupId
    FinishParcel(data);
    host.HandleGetPreferenceDirByGroupId(data, reply);
}

// 178. HandleQueryAppGalleryBundleName: no params (empty Parcel)
void FuzzQueryAppGalleryBundleName(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    FinishParcel(data);
    host.HandleQueryAppGalleryBundleName(data, reply);
}

// 179. HandleQueryExtensionAbilityInfosWithTypeName: ReadParcelable<Want>, ReadString(extensionTypeName),
// ReadInt32(flags), ReadInt32(userId)
void FuzzQueryExtensionAbilityInfosWithTypeName(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteWant(data, fdp);  // Want
    WriteStringField(data, fdp);  // extensionTypeName
    WriteInt32Field(data, fdp);  // flags
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleQueryExtensionAbilityInfosWithTypeName(data, reply);
}

// 180. HandleQueryExtensionAbilityInfosOnlyWithTypeName: ReadString(extensionTypeName), ReadUint32(flags),
// ReadInt32(userId)
void FuzzQueryExtensionAbilityInfosOnlyWithTypeName(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // extensionTypeName
    WriteUint32Field(data, fdp);  // flags
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleQueryExtensionAbilityInfosOnlyWithTypeName(data, reply);
}

// 181. HandleResetAOTCompileStatus: ReadString(bundleName), ReadString(moduleName), ReadInt32(triggerMode)
void FuzzResetAOTCompileStatus(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WritePlainString(data, fdp);  // moduleName
    WriteInt32Field(data, fdp);  // triggerMode
    FinishParcel(data);
    host.HandleResetAOTCompileStatus(data, reply);
}

// 182. HandleGetJsonProfile: ReadInt32(profileType), ReadString(bundleName), ReadString(moduleName), ReadInt32(userId)
void FuzzGetJsonProfile(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteInt32Field(data, fdp);  // profileType (ProfileType)
    WriteStringField(data, fdp);  // bundleName
    WritePlainString(data, fdp);  // moduleName
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetJsonProfile(data, reply);
}

// 183. HandleGetBundleResourceProxy: no params (empty Parcel)
void FuzzGetBundleResourceProxy(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    FinishParcel(data);
    host.HandleGetBundleResourceProxy(data, reply);
}

// 184. HandleGetSkillManagerProxy: no params (empty Parcel)
void FuzzGetSkillManagerProxy(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    FinishParcel(data);
    host.HandleGetSkillManagerProxy(data, reply);
}

// 185. HandleGetRecoverableApplicationInfo: no params (empty Parcel)
void FuzzGetRecoverableApplicationInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    FinishParcel(data);
    host.HandleGetRecoverableApplicationInfo(data, reply);
}

// 186. HandleGetUninstalledBundleInfo: ReadString(name)
void FuzzGetUninstalledBundleInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // name
    FinishParcel(data);
    host.HandleGetUninstalledBundleInfo(data, reply);
}

// 187. HandleGetOdid: no params (empty Parcel)
void FuzzGetOdid(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    FinishParcel(data);
    host.HandleGetOdid(data, reply);
}

// 188. HandleGetAllPreinstalledApplicationInfos: no params (empty Parcel)
void FuzzGetAllPreinstalledApplicationInfos(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    FinishParcel(data);
    host.HandleGetAllPreinstalledApplicationInfos(data, reply);
}

// 189. HandleGetAllNewPreinstalledApplicationInfos: no params (empty Parcel)
void FuzzGetAllNewPreinstalledApplicationInfos(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    FinishParcel(data);
    host.HandleGetAllNewPreinstalledApplicationInfos(data, reply);
}

// 190. HandleGetAllBundleInfoByDeveloperId: ReadString(developerId), ReadInt32(userId)
void FuzzGetAllBundleInfoByDeveloperId(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // developerId
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetAllBundleInfoByDeveloperId(data, reply);
}

// 191. HandleGetDeveloperIds: ReadString(appDistributionType), ReadInt32(userId)
void FuzzGetDeveloperIds(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // appDistributionType
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetDeveloperIds(data, reply);
}

// 192. HandleQueryAbilityInfoByContinueType: ReadString(bundleName), ReadString(continueType), ReadInt32(userId)
void FuzzQueryAbilityInfoByContinueType(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WritePlainString(data, fdp);  // continueType
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleQueryAbilityInfoByContinueType(data, reply);
}

// 193. HandleGetLaunchWant: no params (empty Parcel)
void FuzzGetLaunchWant(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    FinishParcel(data);
    host.HandleGetLaunchWant(data, reply);
}

// 194. HandleQueryCloneExtensionAbilityInfoWithAppIndex: ReadParcelable<ElementName>, ReadInt32(flag),
// ReadInt32(appIndex), ReadInt32(userId)
void FuzzQueryCloneExtensionAbilityInfoWithAppIndex(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    ElementName elementName;
    elementName.SetBundleName(GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL));
    elementName.SetModuleName(fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    elementName.SetAbilityName(fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    data.WriteParcelable(&elementName);  // ElementName
    WriteInt32Field(data, fdp);  // flag
    WriteInt32Field(data, fdp);  // appIndex
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleQueryCloneExtensionAbilityInfoWithAppIndex(data, reply);
}

// 195. HandleGetSignatureInfoByBundleName: ReadString(name)
void FuzzGetSignatureInfoByBundleName(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp, ATTACK_CERT_BYPASS);  // name (signature security)
    FinishParcel(data);
    host.HandleGetSignatureInfoByBundleName(data, reply);
}

// 196. HandleGetOdidByBundleName: ReadString(bundleName)
void FuzzGetOdidByBundleName(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    FinishParcel(data);
    host.HandleGetOdidByBundleName(data, reply);
}

// 197. HandleGetOdidResetCount: ReadString(bundleName)
void FuzzGetOdidResetCount(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    FinishParcel(data);
    host.HandleGetOdidResetCount(data, reply);
}

// 198. HandleGetAllDesktopShortcutInfo: ReadInt32(userId)
void FuzzGetAllDesktopShortcutInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetAllDesktopShortcutInfo(data, reply);
}

// 199. HandleGetBundleInfosForContinuation: ReadInt32(flags), ReadInt32(userId)
void FuzzGetBundleInfosForContinuation(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteInt32Field(data, fdp);  // flags
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetBundleInfosForContinuation(data, reply);
}

// 200. HandleGetContinueBundleNames: ReadString(continueBundleName), ReadInt32(userId)
void FuzzGetContinueBundleNames(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // continueBundleName
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetContinueBundleNames(data, reply);
}

// 201. HandleGetCompatibleDeviceTypeNative: no params (empty Parcel)
void FuzzGetCompatibleDeviceTypeNative(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    FinishParcel(data);
    host.HandleGetCompatibleDeviceTypeNative(data, reply);
}

// 202. HandleGetCompatibleDeviceType: ReadString(bundleName)
void FuzzGetCompatibleDeviceType(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    FinishParcel(data);
    host.HandleGetCompatibleDeviceType(data, reply);
}

// 203. HandleGetBundleNameByAppId: ReadString(appId)
void FuzzGetBundleNameByAppId(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp, ATTACK_CERT_BYPASS);  // appId (security related)
    FinishParcel(data);
    host.HandleGetBundleNameByAppId(data, reply);
}

// 204. HandleGetAllPluginInfo: ReadString(hostBundleName), ReadInt32(userId)
void FuzzGetAllPluginInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // hostBundleName
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetAllPluginInfo(data, reply);
}

// 205. HandleGetPluginInfosForSelf: no params (empty Parcel)
void FuzzGetPluginInfosForSelf(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    FinishParcel(data);
    host.HandleGetPluginInfosForSelf(data, reply);
}

// 206. HandleGetDirByBundleNameAndAppIndex: ReadString(bundleName), ReadInt32(appIndex)
void FuzzGetDirByBundleNameAndAppIndex(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteInt32Field(data, fdp);  // appIndex
    FinishParcel(data);
    host.HandleGetDirByBundleNameAndAppIndex(data, reply);
}

// 207. HandleGetAllBundleDirs: ReadInt32(userId)
void FuzzGetAllBundleDirs(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetAllBundleDirs(data, reply);
}

// 208. HandleGetAllBundleCacheStat: ReadRemoteObject(object)
void FuzzGetAllBundleCacheStat(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteRemoteObject(data);  // object
    FinishParcel(data);
    host.HandleGetAllBundleCacheStat(data, reply);
}

// 209. HandleGetPluginAbilityInfo: ReadString(hostBundleName), ReadString(pluginBundleName),
// ReadString(pluginModuleName), ReadString(pluginAbilityName), ReadInt32(userId)
void FuzzGetPluginAbilityInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // hostBundleName
    WriteStringField(data, fdp);  // pluginBundleName
    WritePlainString(data, fdp);  // pluginModuleName
    WritePlainString(data, fdp);  // pluginAbilityName
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetPluginAbilityInfo(data, reply);
}

// 210. HandleGetPluginHapModuleInfo: ReadString(hostBundleName), ReadString(pluginBundleName),
// ReadString(pluginModuleName), ReadInt32(userId)
void FuzzGetPluginHapModuleInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // hostBundleName
    WriteStringField(data, fdp);  // pluginBundleName
    WritePlainString(data, fdp);  // pluginModuleName
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetPluginHapModuleInfo(data, reply);
}

// 211. HandleGreatOrEqualTargetAPIVersion: ReadInt32(platformVersion), ReadInt32(minorVersion),
// ReadInt32(patchVersion)
void FuzzGreatOrEqualTargetAPIVersion(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteInt32Field(data, fdp);  // platformVersion
    WriteInt32Field(data, fdp);  // minorVersion
    WriteInt32Field(data, fdp);  // patchVersion
    FinishParcel(data);
    host.HandleGreatOrEqualTargetAPIVersion(data, reply);
}

// 212. HandleGetAllShortcutInfoForSelf: no params (empty Parcel)
void FuzzGetAllShortcutInfoForSelf(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    FinishParcel(data);
    host.HandleGetAllShortcutInfoForSelf(data, reply);
}

// 213. HandleGetAlternateIcons: no params (empty Parcel)
void FuzzGetAlternateIcons(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    FinishParcel(data);
    host.HandleGetAlternateIcons(data, reply);
}

// 214. HandleGetPluginInfo: ReadString(hostBundleName), ReadString(pluginBundleName), ReadInt32(userId)
void FuzzGetPluginInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // hostBundleName
    WriteStringField(data, fdp);  // pluginBundleName
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetPluginInfo(data, reply);
}

// 215. HandleGetTestRunner: ReadString(bundleName), ReadString(moduleName)
void FuzzGetTestRunner(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WritePlainString(data, fdp);  // moduleName
    FinishParcel(data);
    host.HandleGetTestRunner(data, reply);
}

// 216. HandleGetAllBundleNames: ReadUint32(flags), ReadInt32(userId), ReadBool(withExtBundle)
void FuzzGetAllBundleNames(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteUint32Field(data, fdp);  // flags
    WriteUserId(data, fdp);  // userId
    WriteBoolField(data, fdp);  // withExtBundle
    FinishParcel(data);
    host.HandleGetAllBundleNames(data, reply);
}

// 217. HandleGetAbilityResourceInfo: ReadString(fileType)
void FuzzGetAbilityResourceInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // fileType
    FinishParcel(data);
    host.HandleGetAbilityResourceInfo(data, reply);
}

// 218. HandleGetPluginBundlePathForSelf: ReadString(pluginBundleName)
void FuzzGetPluginBundlePathForSelf(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // pluginBundleName
    FinishParcel(data);
    host.HandleGetPluginBundlePathForSelf(data, reply);
}

// 219. HandleGetBundleInfoForException: ReadString(name), ReadInt32(userId), ReadUint32(catchSoNum),
// ReadUint64(catchSoMaxSize)
void FuzzGetBundleInfoForException(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // name
    WriteUserId(data, fdp);  // userId
    WriteUint32Field(data, fdp);  // catchSoNum
    WriteUint64Field(data, fdp);  // catchSoMaxSize
    FinishParcel(data);
    host.HandleGetBundleInfoForException(data, reply);
}

// 220. HandleGetAllJsonProfile: ReadInt32(profileType), ReadInt32(userId)
void FuzzGetAllJsonProfile(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteInt32Field(data, fdp);  // profileType (ProfileType)
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetAllJsonProfile(data, reply);
}

// 221. HandleBatchGetCompatibleDeviceType: ReadInt32(bundleNameCount), loop ReadString(bundleName)
void FuzzBatchGetCompatibleDeviceType(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    int32_t count = fdp.ConsumeIntegral<int32_t>() % MAX_TYPE_COUNT;
    data.WriteInt32(count);  // bundleNameCount
    for (int32_t i = 0; i < count; i++) {
        WriteStringField(data, fdp);  // bundleName
    }
    FinishParcel(data);
    host.HandleBatchGetCompatibleDeviceType(data, reply);
}

// 222. HandleGetAssetGroupsInfo: ReadInt32(uid)
void FuzzGetAssetGroupsInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteInt32Field(data, fdp);  // uid
    FinishParcel(data);
    host.HandleGetAssetGroupsInfo(data, reply);
}

// 223. HandleGetPluginExtensionInfo: ReadString(hostBundleName), ReadParcelable<Want>, ReadInt32(userId)
void FuzzGetPluginExtensionInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // hostBundleName
    WriteWant(data, fdp);  // Want
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetPluginExtensionInfo(data, reply);
}

// 224. HandleGetAllLocalPluginInfoForSelf: no params (empty Parcel)
void FuzzGetAllLocalPluginInfoForSelf(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    FinishParcel(data);
    host.HandleGetAllLocalPluginInfoForSelf(data, reply);
}

// 225. HandleGetStringByIdList: ReadString(bundleName), ReadString(moduleName), ReadUInt32Vector(resIdList),
// ReadInt32(userId), ReadString(localeInfo). Simplified: empty resIdList (vector construction skipped)
void FuzzGetStringByIdList(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WritePlainString(data, fdp);  // moduleName
    data.WriteUInt32Vector({});  // resIdList (simplified empty vector)
    WriteUserId(data, fdp);  // userId
    WritePlainString(data, fdp);  // localeInfo
    FinishParcel(data);
    host.HandleGetStringByIdList(data, reply);
}

// 226. HandleGetAllAppInstallExtendedInfo: no params (empty Parcel)
void FuzzGetAllAppInstallExtendedInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    FinishParcel(data);
    host.HandleGetAllAppInstallExtendedInfo(data, reply);
}

// 227. HandleQueryExtAbilityInfosByType: ReadInt32(type), ReadInt32(userId)
void FuzzQueryExtAbilityInfosByType(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteInt32Field(data, fdp);  // type (ExtensionAbilityType)
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleQueryExtAbilityInfosByType(data, reply);
}

// 228. HandleQueryExtAbilityInfosWithoutType: ReadParcelable<Want>, ReadInt32(flag), ReadInt32(userId)
void FuzzQueryExtAbilityInfosWithoutType(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteWant(data, fdp);  // Want
    WriteInt32Field(data, fdp);  // flag
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleQueryExtAbilityInfosWithoutType(data, reply);
}

// 229. HandleQueryExtAbilityInfosWithoutTypeV9: ReadParcelable<Want>, ReadInt32(flags), ReadInt32(userId)
void FuzzQueryExtAbilityInfosWithoutTypeV9(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteWant(data, fdp);  // Want
    WriteInt32Field(data, fdp);  // flags
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleQueryExtAbilityInfosWithoutTypeV9(data, reply);
}

// 230. HandleQueryExtAbilityInfos: ReadParcelable<Want>, ReadInt32(type), ReadInt32(flag), ReadInt32(userId)
void FuzzQueryExtAbilityInfos(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteWant(data, fdp);  // Want
    WriteInt32Field(data, fdp);  // type (ExtensionAbilityType)
    WriteInt32Field(data, fdp);  // flag
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleQueryExtAbilityInfos(data, reply);
}

// 231. HandleQueryExtAbilityInfosV9: ReadParcelable<Want>, ReadInt32(type), ReadInt32(flags), ReadInt32(userId)
void FuzzQueryExtAbilityInfosV9(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteWant(data, fdp);  // Want
    WriteInt32Field(data, fdp);  // type (ExtensionAbilityType)
    WriteInt32Field(data, fdp);  // flags
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleQueryExtAbilityInfosV9(data, reply);
}

// 232. HandleGetTopNLargestItemsInAppDataDir: ReadString(bundleName), ReadInt32(appIndex), ReadInt32(userId),
// ReadRemoteObject(object)
void FuzzGetTopNLargestItemsInAppDataDir(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteInt32Field(data, fdp);  // appIndex
    WriteUserId(data, fdp);  // userId
    WriteRemoteObject(data);  // object
    FinishParcel(data);
    host.HandleGetTopNLargestItemsInAppDataDir(data, reply);
}

// 233. HandleGetAllBundleStats: ReadInt32(userId)
void FuzzGetAllBundleStats(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetAllBundleStats(data, reply);
}

// 234. HandleGetBundleInodeCount: ReadString(bundleName), ReadInt32(appIndex), ReadInt32(userId)
void FuzzGetBundleInodeCount(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteInt32Field(data, fdp);  // appIndex
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetBundleInodeCount(data, reply);
}

// 235. HandleGetMediaData: ReadString(bundleName), ReadString(abilityName), ReadString(moduleName), ReadInt32(userId)
void FuzzGetMediaData(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WritePlainString(data, fdp);  // abilityName
    WritePlainString(data, fdp);  // moduleName
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetMediaData(data, reply);
}

// 236. HandleGetBundleStats: ReadString(bundleName), ReadInt32(userId), ReadInt32(appIndex), ReadUint32(statFlag)
void FuzzGetBundleStats(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteUserId(data, fdp);  // userId
    WriteInt32Field(data, fdp);  // appIndex
    WriteUint32Field(data, fdp);  // statFlag
    FinishParcel(data);
    host.HandleGetBundleStats(data, reply);
}

// 237. HandleBatchGetBundleStats: ReadInt32(count)+ReadStringVector(bundleNames), ReadInt32(userId)
void FuzzBatchGetBundleStats(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    int32_t count = fdp.ConsumeIntegral<int32_t>() % MAX_TYPE_COUNT;
    data.WriteInt32(count);  // bundleNamesSize (preceding count)
    std::vector<std::string> bundleNames = GenerateStringArray(fdp);
    data.WriteStringVector(bundleNames);  // bundleNames
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleBatchGetBundleStats(data, reply);
}

// 238. HandleQueryAbilityInfoWithCallback: ReadParcelable<Want>, ReadInt32(flags), ReadInt32(userId),
// ReadRemoteObject(object)
void FuzzQueryAbilityInfoWithCallback(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteWant(data, fdp);  // Want
    WriteInt32Field(data, fdp);  // flags
    WriteUserId(data, fdp);  // userId
    WriteRemoteObject(data);  // object
    FinishParcel(data);
    host.HandleQueryAbilityInfoWithCallback(data, reply);
}

// 239. HandleGetApiTargetVersionByUid: ReadInt32(uid)
void FuzzGetApiTargetVersionByUid(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteInt32Field(data, fdp);  // uid
    FinishParcel(data);
    host.HandleGetApiTargetVersionByUid(data, reply);
}

// 240. HandleGetQuickFixManagerProxy: no params (empty Parcel)
void FuzzGetQuickFixManagerProxy(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    FinishParcel(data);
    host.HandleGetQuickFixManagerProxy(data, reply);
}

// 241. HandleBatchGetSpecifiedDistributionType: ReadInt32(bundleNameCount), loop ReadString(bundleName)
void FuzzBatchGetSpecifiedDistributionType(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    int32_t count = fdp.ConsumeIntegral<int32_t>() % MAX_TYPE_COUNT;
    data.WriteInt32(count);  // bundleNameCount
    for (int32_t i = 0; i < count; i++) {
        WriteStringField(data, fdp);  // bundleName
    }
    FinishParcel(data);
    host.HandleBatchGetSpecifiedDistributionType(data, reply);
}

// 242. HandleGetAppControlProxy: 无参数
void FuzzGetAppControlProxy(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    (void)fdp;
    FinishParcel(data);
    host.HandleGetAppControlProxy(data, reply);
}

// 243. HandleGetDefaultAppProxy: 无参数
void FuzzGetDefaultAppProxy(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    (void)fdp;
    FinishParcel(data);
    host.HandleGetDefaultAppProxy(data, reply);
}

// 244. HandleGetCloneBundleInfoExt: ReadString(bundleName), ReadUint32(flags), ReadInt32(appIndex), ReadInt32(userId)
void FuzzGetCloneBundleInfoExt(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteUint32Field(data, fdp);  // flags
    WriteInt32Field(data, fdp);  // appIndex
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetCloneBundleInfoExt(data, reply);
}

// 245. HandleGetMainAndCloneBundleInfo: ReadString(bundleName), ReadUint32(flags), ReadInt32(userId)
void FuzzGetMainAndCloneBundleInfo(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteUint32Field(data, fdp);  // flags
    WriteUserId(data, fdp);  // userId
    FinishParcel(data);
    host.HandleGetMainAndCloneBundleInfo(data, reply);
}

// 246. HandleGetShortcutInfoByAbility: ReadString(bundleName), ReadString(moduleName), ReadString(abilityName),
// ReadInt32(userId), ReadInt32(appIndex)
void FuzzGetShortcutInfoByAbility(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // bundleName
    WriteStringField(data, fdp);  // moduleName
    WriteStringField(data, fdp);  // abilityName
    WriteUserId(data, fdp);  // userId
    WriteInt32Field(data, fdp);  // appIndex
    FinishParcel(data);
    host.HandleGetShortcutInfoByAbility(data, reply);
}

// 247. HandleGetSimpleAppInfoForUid: ReadInt32Vector(uids)
void FuzzGetSimpleAppInfoForUid(BundleMgrHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<BundleMgrHost>(data);
    MessageParcel reply;
    int32_t uidCount = fdp.ConsumeIntegral<int32_t>() % MAX_TYPE_COUNT;
    std::vector<int32_t> uids;
    for (int32_t i = 0; i < uidCount; i++) {
        uids.push_back(fdp.ConsumeIntegral<int32_t>());
    }
    data.WriteInt32Vector(uids);  // uids
    FinishParcel(data);
    host.HandleGetSimpleAppInfoForUid(data, reply);
}

enum BundleMgrMethod {
    FUZZSETBUNDLEFIRSTLAUNCH = 0,
    FUZZSETAPPLICATIONENABLED,
    FUZZSETABILITYENABLED,
    FUZZGETUIDBYDEBUGBUNDLENAME,
    FUZZGETSANDBOXBUNDLEINFO,
    FUZZSILENTINSTALL,
    FUZZSETDEBUGMODE,
    FUZZGETAPPPROVISIONINFO,
    FUZZMIGRATEDATA,
    FUZZCREATEBUNDLEDATADIR,
    FUZZCREATEBUNDLEDATADIRWITHEL,
    FUZZSWITCHUNINSTALLSTATE,
    FUZZSWITCHUNINSTALLSTATEBYUSERID,
    FUZZQUERYCLONEABILITYINFO,
    FUZZUPDATEAPPENCRYPTEDSTATUS,
    FUZZSETCLONEAPPLICATIONENABLED,
    FUZZSETCLONEABILITYENABLED,
    FUZZGETCLONEBUNDLEINFO,
    FUZZGETCLONEAPPINDEXES,
    FUZZGETALLAPPPROVISIONINFO,
    FUZZGETPROVISIONMETADATA,
    FUZZCREATENEWBUNDLEDIR,
    FUZZISBUNDLEINSTALLED,
    FUZZGETINSTALLEDBUNDLELIST,
    FUZZGETBUNDLEINSTALLSTATUS,
    FUZZSETAPPCLONEPREFERENCE,
    FUZZGETAPPCLONEPREFERENCE,
    FUZZGETCLISANDBOXAPPINDEXES,
    FUZZQUERYSANDBOXCLONEABILITYINFO,
    FUZZSETMODULEREMOVABLE,
    FUZZSETADDITIONALINFO,
    FUZZCLEANBUNDLECACHEFILES,
    FUZZCLEANBUNDLEDATAFILES,
    FUZZCLEANALLBUNDLECACHE,
    FUZZGETABILITYINFO,
    FUZZGETABILITYINFOS,
    FUZZADDDESKTOPSHORTCUTINFO,
    FUZZDELETEDESKTOPSHORTCUTINFO,
    FUZZCOMPILEPROCESSAOT,
    FUZZCOMPILERESET,
    FUZZQUERYABILITYINFO,
    FUZZCHECKISSYSTEMAPPBYUID,
    FUZZDUMPINFOS,
    FUZZGETSANDBOXABILITYINFO,
    FUZZGETSANDBOXEXTABILITYINFOS,
    FUZZGETSANDBOXHAPMODULEINFO,
    FUZZSETAPPDISTRIBUTIONTYPES,
    FUZZBATCHGETADDITIONALINFO,
    FUZZBATCHGETBUNDLEINFO,
    FUZZBATCHQUERYABILITYINFOS,
    FUZZCANOPENLINK,
    FUZZCOPYAP,
    FUZZDELEXTNAMEORMIMETOAPP,
    FUZZCLEANBUNDLECACHEFILESAUTOMATIC,
    FUZZCLEANBUNDLEPARTIALCACHEAUTOMATIC,
    FUZZSETAPPLICATIONDISABLEFORBIDDEN,
    FUZZRECOVERBACKUPBUNDLEDATA,
    FUZZREMOVEBACKUPBUNDLEDATA,
    FUZZGETSANDBOXDATADIR,
    FUZZGETSIGNATUREINFOBYUID,
    FUZZISDEBUGGABLEAPPLICATION,
    FUZZRESETALLAOT,
    FUZZSETSHORTCUTVISIBLEFORSELF,
    FUZZISAPPLICATIONDISABLEFORBIDDEN,
    FUZZCLEANBUNDLECACHEFILESFORSELF,
    FUZZREGISTERBUNDLEEVENTCALLBACK,
    FUZZREGISTERPLUGINEVENTCALLBACK,
    FUZZUNREGISTERBUNDLEEVENTCALLBACK,
    FUZZUNREGISTERPLUGINEVENTCALLBACK,
    FUZZDELETEDYNAMICSHORTCUTINFOS,
    FUZZSETABILITYFILETYPESFORSELF,
    FUZZUPDATEDESKTOPSHORTCUTINFO,
    FUZZADDDYNAMICSHORTCUTINFOS,
    FUZZSETSHORTCUTSENABLED,
    FUZZSTARTAPPDETAILABILITY,
    FUZZGETAPPLICATIONINFO,
    FUZZGETAPPLICATIONINFOWITHINTFLAGS,
    FUZZGETAPPLICATIONINFOWITHINTFLAGSV9,
    FUZZGETAPPLICATIONINFOS,
    FUZZGETAPPLICATIONINFOSWITHINTFLAGS,
    FUZZGETAPPLICATIONINFOSWITHINTFLAGSV9,
    FUZZGETBUNDLEINFO,
    FUZZGETBUNDLEINFOWITHINTFLAGS,
    FUZZGETBUNDLEINFOWITHINTFLAGSV9,
    FUZZGETBUNDLEPACKINFO,
    FUZZGETBUNDLEPACKINFOWITHINTFLAGS,
    FUZZGETBUNDLEINFOS,
    FUZZGETBUNDLEINFOSWITHINTFLAGS,
    FUZZGETBUNDLEINFOSWITHINTFLAGSV9,
    FUZZGETBUNDLENAMEFORUID,
    FUZZGETBUNDLESFORUID,
    FUZZGETNAMEFORUID,
    FUZZGETNAMEANDINDEXFORUID,
    FUZZGETAPPIDENTIFIERANDAPPINDEX,
    FUZZGETBUNDLEGIDS,
    FUZZGETBUNDLEGIDSBYUID,
    FUZZGETBUNDLEINFOSBYMETADATA,
    FUZZQUERYABILITYINFOMUTIPARAM,
    FUZZQUERYABILITYINFOS,
    FUZZQUERYABILITYINFOSMUTIPARAM,
    FUZZQUERYABILITYINFOSV9,
    FUZZQUERYLAUNCHERABILITYINFOS,
    FUZZGETLAUNCHERABILITYINFOSYNC,
    FUZZQUERYALLABILITYINFOS,
    FUZZQUERYABILITYINFOBYURI,
    FUZZQUERYABILITYINFOSBYURI,
    FUZZQUERYABILITYINFOBYURIFORUSERID,
    FUZZQUERYKEEPALIVEBUNDLEINFOS,
    FUZZGETABILITYLABEL,
    FUZZGETABILITYLABELWITHMODULENAME,
    FUZZGETAPPLICATIONLABEL,
    FUZZGETBUNDLEARCHIVEINFO,
    FUZZGETBUNDLEARCHIVEINFOWITHINTFLAGS,
    FUZZGETBUNDLEARCHIVEINFOWITHINTFLAGSV9,
    FUZZGETHAPMODULEINFO,
    FUZZGETHAPMODULEINFOWITHUSERID,
    FUZZGETLAUNCHWANTFORBUNDLE,
    FUZZGETPERMISSIONDEF,
    FUZZCLEANBUNDLECACHEFILESAUTOMATICBYTYPE,
    FUZZREGISTERBUNDLESTATUSCALLBACK,
    FUZZCLEARBUNDLESTATUSCALLBACK,
    FUZZUNREGISTERBUNDLESTATUSCALLBACK,
    FUZZISAPPLICATIONENABLED,
    FUZZISABILITYENABLED,
    FUZZISCLONEAPPLICATIONENABLED,
    FUZZISCLONEABILITYENABLED,
    FUZZISMODULEREMOVABLE,
    FUZZGETABILITYINFOWITHMODULENAME,
    FUZZGETBUNDLEINSTALLER,
    FUZZGETLOCALPLUGININSTALLER,
    FUZZGETBUNDLEUSERMGR,
    FUZZGETVERIFYMANAGER,
    FUZZGETEXTENDRESOURCEMANAGER,
    FUZZGETALLFORMSINFO,
    FUZZGETFORMSINFOBYAPP,
    FUZZGETFORMSINFOBYMODULE,
    FUZZGETSHORTCUTINFOS,
    FUZZGETSHORTCUTINFOV9,
    FUZZGETSHORTCUTINFOBYAPPINDEX,
    FUZZGETALLCOMMONEVENTINFO,
    FUZZGETDISTRIBUTEDBUNDLEINFO,
    FUZZGETAPPPRIVILEGELEVEL,
    FUZZVERIFYCALLINGPERMISSION,
    FUZZQUERYEXTENSIONABILITYINFOBYURI,
    FUZZQUERYEXTENSIONABILITYINFOBYURIOPTIMAL,
    FUZZGETAPPIDBYBUNDLENAME,
    FUZZGETAPPTYPE,
    FUZZGETUIDBYBUNDLENAME,
    FUZZGETMODULEUPGRADEFLAG,
    FUZZSETMODULEUPGRADEFLAG,
    FUZZIMPLICITQUERYINFOBYPRIORITY,
    FUZZIMPLICITQUERYINFOS,
    FUZZGETALLDEPENDENTMODULENAMES,
    FUZZOBTAINCALLINGBUNDLENAME,
    FUZZCHECKABILITYENABLEINSTALL,
    FUZZGETSTRINGBYID,
    FUZZGETICONBYID,
    FUZZGETBUNDLEMGREXTPROXY,
    FUZZGETBUNDLEINFOFORSELF,
    FUZZVERIFYSYSTEMAPI,
    FUZZGETOVERLAYMANAGERPROXY,
    FUZZPROCESSPRELOAD,
    FUZZUPGRADEATOMICSERVICE,
    FUZZGETBASESHAREDBUNDLEINFOS,
    FUZZGETALLSHAREDBUNDLEINFO,
    FUZZGETSHAREDBUNDLEINFO,
    FUZZGETSHAREDBUNDLEINFOBYSELF,
    FUZZGETSHAREDDEPENDENCIES,
    FUZZGETDEPENDENTBUNDLEINFO,
    FUZZGETPROXYDATAINFOS,
    FUZZGETALLPROXYDATAINFOS,
    FUZZGETSPECIFIEDDISTRIBUTIONTYPE,
    FUZZGETADDITIONALINFO,
    FUZZGETADDITIONALINFOFORALLUSER,
    FUZZSETEXTNAMEORMIMETOAPP,
    FUZZQUERYDATAGROUPINFOS,
    FUZZGETPREFERENCEDIRBYGROUPID,
    FUZZQUERYAPPGALLERYBUNDLENAME,
    FUZZQUERYEXTENSIONABILITYINFOSWITHTYPENAME,
    FUZZQUERYEXTENSIONABILITYINFOSONLYWITHTYPENAME,
    FUZZRESETAOTCOMPILESTATUS,
    FUZZGETJSONPROFILE,
    FUZZGETBUNDLERESOURCEPROXY,
    FUZZGETSKILLMANAGERPROXY,
    FUZZGETRECOVERABLEAPPLICATIONINFO,
    FUZZGETUNINSTALLEDBUNDLEINFO,
    FUZZGETODID,
    FUZZGETALLPREINSTALLEDAPPLICATIONINFOS,
    FUZZGETALLNEWPREINSTALLEDAPPLICATIONINFOS,
    FUZZGETALLBUNDLEINFOBYDEVELOPERID,
    FUZZGETDEVELOPERIDS,
    FUZZQUERYABILITYINFOBYCONTINUETYPE,
    FUZZGETLAUNCHWANT,
    FUZZQUERYCLONEEXTENSIONABILITYINFOWITHAPPINDEX,
    FUZZGETSIGNATUREINFOBYBUNDLENAME,
    FUZZGETODIDBYBUNDLENAME,
    FUZZGETODIDRESETCOUNT,
    FUZZGETALLDESKTOPSHORTCUTINFO,
    FUZZGETBUNDLEINFOSFORCONTINUATION,
    FUZZGETCONTINUEBUNDLENAMES,
    FUZZGETCOMPATIBLEDEVICETYPENATIVE,
    FUZZGETCOMPATIBLEDEVICETYPE,
    FUZZGETBUNDLENAMEBYAPPID,
    FUZZGETALLPLUGININFO,
    FUZZGETPLUGININFOSFORSELF,
    FUZZGETDIRBYBUNDLENAMEANDAPPINDEX,
    FUZZGETALLBUNDLEDIRS,
    FUZZGETALLBUNDLECACHESTAT,
    FUZZGETPLUGINABILITYINFO,
    FUZZGETPLUGINHAPMODULEINFO,
    FUZZGREATOREQUALTARGETAPIVERSION,
    FUZZGETALLSHORTCUTINFOFORSELF,
    FUZZGETALTERNATEICONS,
    FUZZGETPLUGININFO,
    FUZZGETTESTRUNNER,
    FUZZGETALLBUNDLENAMES,
    FUZZGETABILITYRESOURCEINFO,
    FUZZGETPLUGINBUNDLEPATHFORSELF,
    FUZZGETBUNDLEINFOFOREXCEPTION,
    FUZZGETALLJSONPROFILE,
    FUZZBATCHGETCOMPATIBLEDEVICETYPE,
    FUZZGETASSETGROUPSINFO,
    FUZZGETPLUGINEXTENSIONINFO,
    FUZZGETALLLOCALPLUGININFOFORSELF,
    FUZZGETSTRINGBYIDLIST,
    FUZZGETALLAPPINSTALLEDEXTENDEDINFO,
    FUZZQUERYEXTABILITYINFOSBYTYPE,
    FUZZQUERYEXTABILITYINFOSWITHOUTTYPE,
    FUZZQUERYEXTABILITYINFOSWITHOUTTYPEV9,
    FUZZQUERYEXTABILITYINFOS,
    FUZZQUERYEXTABILITYINFOSV9,
    FUZZGETTOPNLARGESTITEMSINAPPDATADIR,
    FUZZGETALLBUNDLESTATS,
    FUZZGETBUNDLEINODECOUNT,
    FUZZGETMEDIADATA,
    FUZZGETBUNDLESTATS,
    FUZZBATCHGETBUNDLESTATS,
    FUZZQUERYABILITYINFOWITHCALLBACK,
    FUZZGETAPITARGETVERSIONBYUID,
    FUZZGETQUICKFIXMANAGERPROXY,
    FUZZBATCHGETSPECIFIEDDISTRIBUTIONTYPE,
    FUZZGETAPPCONTROLPROXY,
    FUZZGETDEFAULTAPPPROXY,
    FUZZGETCLONEBUNDLEINFOEXT,
    FUZZGETMAINANDCLONEBUNDLEINFO,
    FUZZGETSHORTCUTINFOBYABILITY,
    FUZZGETSIMPLEAPPINFOFORUID,
    BUNDLE_MGR_METHOD_MAX,
};

// ====== comprehensive fuzz entry ======
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return false;
    }

    FuzzedDataProvider fdp(data, size);
    static BundleMgrHost bundleMgrHost;

    // Layer 1: Stub loop
    FuzzIpcStubLoop(bundleMgrHost, data, size, CODE_MAX);

    // Layer 2: method layer - 158 high-risk + P2 query codes precise construction by real field order
    uint8_t methodSelector = fdp.ConsumeIntegral<uint8_t>();
    switch (methodSelector % BUNDLE_MGR_METHOD_MAX) {
        case FUZZSETBUNDLEFIRSTLAUNCH: FuzzSetBundleFirstLaunch(bundleMgrHost, fdp);       break;
        case FUZZSETAPPLICATIONENABLED: FuzzSetApplicationEnabled(bundleMgrHost, fdp);      break;
        case FUZZSETABILITYENABLED: FuzzSetAbilityEnabled(bundleMgrHost, fdp);           break;
        case FUZZGETUIDBYDEBUGBUNDLENAME: FuzzGetUidByDebugBundleName(bundleMgrHost, fdp);    break;
        case FUZZGETSANDBOXBUNDLEINFO: FuzzGetSandboxBundleInfo(bundleMgrHost, fdp);       break;
        case FUZZSILENTINSTALL: FuzzSilentInstall(bundleMgrHost, fdp);              break;
        case FUZZSETDEBUGMODE: FuzzSetDebugMode(bundleMgrHost, fdp);               break;
        case FUZZGETAPPPROVISIONINFO: FuzzGetAppProvisionInfo(bundleMgrHost, fdp);        break;
        case FUZZMIGRATEDATA: FuzzMigrateData(bundleMgrHost, fdp);                break;
        case FUZZCREATEBUNDLEDATADIR: FuzzCreateBundleDataDir(bundleMgrHost, fdp);       break;
        case FUZZCREATEBUNDLEDATADIRWITHEL: FuzzCreateBundleDataDirWithEl(bundleMgrHost, fdp); break;
        case FUZZSWITCHUNINSTALLSTATE: FuzzSwitchUninstallState(bundleMgrHost, fdp);       break;
        case FUZZSWITCHUNINSTALLSTATEBYUSERID: FuzzSwitchUninstallStateByUserId(bundleMgrHost, fdp); break;
        case FUZZQUERYCLONEABILITYINFO: FuzzQueryCloneAbilityInfo(bundleMgrHost, fdp);      break;
        case FUZZUPDATEAPPENCRYPTEDSTATUS: FuzzUpdateAppEncryptedStatus(bundleMgrHost, fdp);  break;
        case FUZZSETCLONEAPPLICATIONENABLED: FuzzSetCloneApplicationEnabled(bundleMgrHost, fdp); break;
        case FUZZSETCLONEABILITYENABLED: FuzzSetCloneAbilityEnabled(bundleMgrHost, fdp);    break;
        case FUZZGETCLONEBUNDLEINFO: FuzzGetCloneBundleInfo(bundleMgrHost, fdp);        break;
        case FUZZGETCLONEAPPINDEXES: FuzzGetCloneAppIndexes(bundleMgrHost, fdp);       break;
        case FUZZGETALLAPPPROVISIONINFO: FuzzGetAllAppProvisionInfo(bundleMgrHost, fdp);   break;
        case FUZZGETPROVISIONMETADATA: FuzzGetProvisionMetadata(bundleMgrHost, fdp);     break;
        case FUZZCREATENEWBUNDLEDIR: FuzzCreateNewBundleDir(bundleMgrHost, fdp);       break;
        case FUZZISBUNDLEINSTALLED: FuzzIsBundleInstalled(bundleMgrHost, fdp);        break;
        case FUZZGETINSTALLEDBUNDLELIST: FuzzGetInstalledBundleList(bundleMgrHost, fdp);   break;
        case FUZZGETBUNDLEINSTALLSTATUS: FuzzGetBundleInstallStatus(bundleMgrHost, fdp);   break;
        case FUZZSETAPPCLONEPREFERENCE: FuzzSetAppClonePreference(bundleMgrHost, fdp);   break;
        case FUZZGETAPPCLONEPREFERENCE: FuzzGetAppClonePreference(bundleMgrHost, fdp);   break;
        case FUZZGETCLISANDBOXAPPINDEXES: FuzzGetCliSandboxAppIndexes(bundleMgrHost, fdp); break;
        case FUZZQUERYSANDBOXCLONEABILITYINFO: FuzzQuerySandboxCloneAbilityInfo(bundleMgrHost, fdp); break;
        case FUZZSETMODULEREMOVABLE: FuzzSetModuleRemovable(bundleMgrHost, fdp);      break;
        case FUZZSETADDITIONALINFO: FuzzSetAdditionalInfo(bundleMgrHost, fdp);       break;
        case FUZZCLEANBUNDLECACHEFILES: FuzzCleanBundleCacheFiles(bundleMgrHost, fdp);  break;
        case FUZZCLEANBUNDLEDATAFILES: FuzzCleanBundleDataFiles(bundleMgrHost, fdp);    break;
        case FUZZCLEANALLBUNDLECACHE: FuzzCleanAllBundleCache(bundleMgrHost, fdp);     break;
        case FUZZGETABILITYINFO: FuzzGetAbilityInfo(bundleMgrHost, fdp);          break;
        case FUZZGETABILITYINFOS: FuzzGetAbilityInfos(bundleMgrHost, fdp);         break;
        case FUZZADDDESKTOPSHORTCUTINFO: FuzzAddDesktopShortcutInfo(bundleMgrHost, fdp);  break;
        case FUZZDELETEDESKTOPSHORTCUTINFO: FuzzDeleteDesktopShortcutInfo(bundleMgrHost, fdp); break;
        case FUZZCOMPILEPROCESSAOT: FuzzCompileProcessAOT(bundleMgrHost, fdp);       break;
        case FUZZCOMPILERESET: FuzzCompileReset(bundleMgrHost, fdp);            break;
        case FUZZQUERYABILITYINFO: FuzzQueryAbilityInfo(bundleMgrHost, fdp);       break;
        case FUZZCHECKISSYSTEMAPPBYUID: FuzzCheckIsSystemAppByUid(bundleMgrHost, fdp);   break;
        case FUZZDUMPINFOS: FuzzDumpInfos(bundleMgrHost, fdp);              break;
        case FUZZGETSANDBOXABILITYINFO: FuzzGetSandboxAbilityInfo(bundleMgrHost, fdp);  break;
        case FUZZGETSANDBOXEXTABILITYINFOS: FuzzGetSandboxExtAbilityInfos(bundleMgrHost, fdp); break;
        case FUZZGETSANDBOXHAPMODULEINFO: FuzzGetSandboxHapModuleInfo(bundleMgrHost, fdp); break;
        case FUZZSETAPPDISTRIBUTIONTYPES: FuzzSetAppDistributionTypes(bundleMgrHost, fdp); break;
        case FUZZBATCHGETADDITIONALINFO: FuzzBatchGetAdditionalInfo(bundleMgrHost, fdp); break;
        case FUZZBATCHGETBUNDLEINFO: FuzzBatchGetBundleInfo(bundleMgrHost, fdp);    break;
        case FUZZBATCHQUERYABILITYINFOS: FuzzBatchQueryAbilityInfos(bundleMgrHost, fdp); break;
        case FUZZCANOPENLINK: FuzzCanOpenLink(bundleMgrHost, fdp);          break;
        case FUZZCOPYAP: FuzzCopyAp(bundleMgrHost, fdp);              break;
        case FUZZDELEXTNAMEORMIMETOAPP: FuzzDelExtNameOrMIMEToApp(bundleMgrHost, fdp); break;
        case FUZZCLEANBUNDLECACHEFILESAUTOMATIC: FuzzCleanBundleCacheFilesAutomatic(bundleMgrHost, fdp); break;
        case FUZZCLEANBUNDLEPARTIALCACHEAUTOMATIC: FuzzCleanBundlePartialCacheAutomatic(bundleMgrHost, fdp); break;
        case FUZZSETAPPLICATIONDISABLEFORBIDDEN: FuzzSetApplicationDisableForbidden(bundleMgrHost, fdp); break;
        case FUZZRECOVERBACKUPBUNDLEDATA: FuzzRecoverBackupBundleData(bundleMgrHost, fdp); break;
        case FUZZREMOVEBACKUPBUNDLEDATA: FuzzRemoveBackupBundleData(bundleMgrHost, fdp); break;
        case FUZZGETSANDBOXDATADIR: FuzzGetSandboxDataDir(bundleMgrHost, fdp); break;
        case FUZZGETSIGNATUREINFOBYUID: FuzzGetSignatureInfoByUid(bundleMgrHost, fdp); break;
        case FUZZISDEBUGGABLEAPPLICATION: FuzzIsDebuggableApplication(bundleMgrHost, fdp); break;
        case FUZZRESETALLAOT: FuzzResetAllAOT(bundleMgrHost, fdp); break;
        case FUZZSETSHORTCUTVISIBLEFORSELF: FuzzSetShortcutVisibleForSelf(bundleMgrHost, fdp); break;
        case FUZZISAPPLICATIONDISABLEFORBIDDEN: FuzzIsApplicationDisableForbidden(bundleMgrHost, fdp); break;
        case FUZZCLEANBUNDLECACHEFILESFORSELF: FuzzCleanBundleCacheFilesForSelf(bundleMgrHost, fdp); break;
        case FUZZREGISTERBUNDLEEVENTCALLBACK: FuzzRegisterBundleEventCallback(bundleMgrHost, fdp); break;
        case FUZZREGISTERPLUGINEVENTCALLBACK: FuzzRegisterPluginEventCallback(bundleMgrHost, fdp); break;
        case FUZZUNREGISTERBUNDLEEVENTCALLBACK: FuzzUnregisterBundleEventCallback(bundleMgrHost, fdp); break;
        case FUZZUNREGISTERPLUGINEVENTCALLBACK: FuzzUnregisterPluginEventCallback(bundleMgrHost, fdp); break;
        case FUZZDELETEDYNAMICSHORTCUTINFOS: FuzzDeleteDynamicShortcutInfos(bundleMgrHost, fdp); break;
        case FUZZSETABILITYFILETYPESFORSELF: FuzzSetAbilityFileTypesForSelf(bundleMgrHost, fdp); break;
        case FUZZUPDATEDESKTOPSHORTCUTINFO: FuzzUpdateDesktopShortcutInfo(bundleMgrHost, fdp); break;
        case FUZZADDDYNAMICSHORTCUTINFOS: FuzzAddDynamicShortcutInfos(bundleMgrHost, fdp); break;
        case FUZZSETSHORTCUTSENABLED: FuzzSetShortcutsEnabled(bundleMgrHost, fdp); break;
        case FUZZSTARTAPPDETAILABILITY: FuzzStartAppDetailAbility(bundleMgrHost, fdp); break;
        case FUZZGETAPPLICATIONINFO: FuzzGetApplicationInfo(bundleMgrHost, fdp); break;
        case FUZZGETAPPLICATIONINFOWITHINTFLAGS: FuzzGetApplicationInfoWithIntFlags(bundleMgrHost, fdp); break;
        case FUZZGETAPPLICATIONINFOWITHINTFLAGSV9: FuzzGetApplicationInfoWithIntFlagsV9(bundleMgrHost, fdp); break;
        case FUZZGETAPPLICATIONINFOS: FuzzGetApplicationInfos(bundleMgrHost, fdp); break;
        case FUZZGETAPPLICATIONINFOSWITHINTFLAGS: FuzzGetApplicationInfosWithIntFlags(bundleMgrHost, fdp); break;
        case FUZZGETAPPLICATIONINFOSWITHINTFLAGSV9: FuzzGetApplicationInfosWithIntFlagsV9(bundleMgrHost, fdp); break;
        case FUZZGETBUNDLEINFO: FuzzGetBundleInfo(bundleMgrHost, fdp); break;
        case FUZZGETBUNDLEINFOWITHINTFLAGS: FuzzGetBundleInfoWithIntFlags(bundleMgrHost, fdp); break;
        case FUZZGETBUNDLEINFOWITHINTFLAGSV9: FuzzGetBundleInfoWithIntFlagsV9(bundleMgrHost, fdp); break;
        case FUZZGETBUNDLEPACKINFO: FuzzGetBundlePackInfo(bundleMgrHost, fdp); break;
        case FUZZGETBUNDLEPACKINFOWITHINTFLAGS: FuzzGetBundlePackInfoWithIntFlags(bundleMgrHost, fdp); break;
        case FUZZGETBUNDLEINFOS: FuzzGetBundleInfos(bundleMgrHost, fdp); break;
        case FUZZGETBUNDLEINFOSWITHINTFLAGS: FuzzGetBundleInfosWithIntFlags(bundleMgrHost, fdp); break;
        case FUZZGETBUNDLEINFOSWITHINTFLAGSV9: FuzzGetBundleInfosWithIntFlagsV9(bundleMgrHost, fdp); break;
        case FUZZGETBUNDLENAMEFORUID: FuzzGetBundleNameForUid(bundleMgrHost, fdp); break;
        case FUZZGETBUNDLESFORUID: FuzzGetBundlesForUid(bundleMgrHost, fdp); break;
        case FUZZGETNAMEFORUID: FuzzGetNameForUid(bundleMgrHost, fdp); break;
        case FUZZGETNAMEANDINDEXFORUID: FuzzGetNameAndIndexForUid(bundleMgrHost, fdp); break;
        case FUZZGETAPPIDENTIFIERANDAPPINDEX: FuzzGetAppIdentifierAndAppIndex(bundleMgrHost, fdp); break;
        case FUZZGETBUNDLEGIDS: FuzzGetBundleGids(bundleMgrHost, fdp); break;
        case FUZZGETBUNDLEGIDSBYUID: FuzzGetBundleGidsByUid(bundleMgrHost, fdp); break;
        case FUZZGETBUNDLEINFOSBYMETADATA: FuzzGetBundleInfosByMetaData(bundleMgrHost, fdp); break;
        case FUZZQUERYABILITYINFOMUTIPARAM: FuzzQueryAbilityInfoMutiparam(bundleMgrHost, fdp); break;
        case FUZZQUERYABILITYINFOS: FuzzQueryAbilityInfos(bundleMgrHost, fdp); break;
        case FUZZQUERYABILITYINFOSMUTIPARAM: FuzzQueryAbilityInfosMutiparam(bundleMgrHost, fdp); break;
        case FUZZQUERYABILITYINFOSV9: FuzzQueryAbilityInfosV9(bundleMgrHost, fdp); break;
        case FUZZQUERYLAUNCHERABILITYINFOS: FuzzQueryLauncherAbilityInfos(bundleMgrHost, fdp); break;
        case FUZZGETLAUNCHERABILITYINFOSYNC: FuzzGetLauncherAbilityInfoSync(bundleMgrHost, fdp); break;
        case FUZZQUERYALLABILITYINFOS: FuzzQueryAllAbilityInfos(bundleMgrHost, fdp); break;
        case FUZZQUERYABILITYINFOBYURI: FuzzQueryAbilityInfoByUri(bundleMgrHost, fdp); break;
        case FUZZQUERYABILITYINFOSBYURI: FuzzQueryAbilityInfosByUri(bundleMgrHost, fdp); break;
        case FUZZQUERYABILITYINFOBYURIFORUSERID: FuzzQueryAbilityInfoByUriForUserId(bundleMgrHost, fdp); break;
        case FUZZQUERYKEEPALIVEBUNDLEINFOS: FuzzQueryKeepAliveBundleInfos(bundleMgrHost, fdp); break;
        case FUZZGETABILITYLABEL: FuzzGetAbilityLabel(bundleMgrHost, fdp); break;
        case FUZZGETABILITYLABELWITHMODULENAME: FuzzGetAbilityLabelWithModuleName(bundleMgrHost, fdp); break;
        case FUZZGETAPPLICATIONLABEL: FuzzGetApplicationLabel(bundleMgrHost, fdp); break;
        case FUZZGETBUNDLEARCHIVEINFO: FuzzGetBundleArchiveInfo(bundleMgrHost, fdp); break;
        case FUZZGETBUNDLEARCHIVEINFOWITHINTFLAGS: FuzzGetBundleArchiveInfoWithIntFlags(bundleMgrHost, fdp); break;
        case FUZZGETBUNDLEARCHIVEINFOWITHINTFLAGSV9: FuzzGetBundleArchiveInfoWithIntFlagsV9(bundleMgrHost, fdp); break;
        case FUZZGETHAPMODULEINFO: FuzzGetHapModuleInfo(bundleMgrHost, fdp); break;
        case FUZZGETHAPMODULEINFOWITHUSERID: FuzzGetHapModuleInfoWithUserId(bundleMgrHost, fdp); break;
        case FUZZGETLAUNCHWANTFORBUNDLE: FuzzGetLaunchWantForBundle(bundleMgrHost, fdp); break;
        case FUZZGETPERMISSIONDEF: FuzzGetPermissionDef(bundleMgrHost, fdp); break;
        case FUZZCLEANBUNDLECACHEFILESAUTOMATICBYTYPE:
            FuzzCleanBundleCacheFilesAutomaticByType(bundleMgrHost, fdp); break;
        case FUZZREGISTERBUNDLESTATUSCALLBACK: FuzzRegisterBundleStatusCallback(bundleMgrHost, fdp); break;
        case FUZZCLEARBUNDLESTATUSCALLBACK: FuzzClearBundleStatusCallback(bundleMgrHost, fdp); break;
        case FUZZUNREGISTERBUNDLESTATUSCALLBACK: FuzzUnregisterBundleStatusCallback(bundleMgrHost, fdp); break;
        case FUZZISAPPLICATIONENABLED: FuzzIsApplicationEnabled(bundleMgrHost, fdp); break;
        case FUZZISABILITYENABLED: FuzzIsAbilityEnabled(bundleMgrHost, fdp); break;
        case FUZZISCLONEAPPLICATIONENABLED: FuzzIsCloneApplicationEnabled(bundleMgrHost, fdp); break;
        case FUZZISCLONEABILITYENABLED: FuzzIsCloneAbilityEnabled(bundleMgrHost, fdp); break;
        case FUZZISMODULEREMOVABLE: FuzzIsModuleRemovable(bundleMgrHost, fdp); break;
        case FUZZGETABILITYINFOWITHMODULENAME: FuzzGetAbilityInfoWithModuleName(bundleMgrHost, fdp); break;
        case FUZZGETBUNDLEINSTALLER: FuzzGetBundleInstaller(bundleMgrHost, fdp); break;
        case FUZZGETLOCALPLUGININSTALLER: FuzzGetLocalPluginInstaller(bundleMgrHost, fdp); break;
        case FUZZGETBUNDLEUSERMGR: FuzzGetBundleUserMgr(bundleMgrHost, fdp); break;
        case FUZZGETVERIFYMANAGER: FuzzGetVerifyManager(bundleMgrHost, fdp); break;
        case FUZZGETEXTENDRESOURCEMANAGER: FuzzGetExtendResourceManager(bundleMgrHost, fdp); break;
        case FUZZGETALLFORMSINFO: FuzzGetAllFormsInfo(bundleMgrHost, fdp); break;
        case FUZZGETFORMSINFOBYAPP: FuzzGetFormsInfoByApp(bundleMgrHost, fdp); break;
        case FUZZGETFORMSINFOBYMODULE: FuzzGetFormsInfoByModule(bundleMgrHost, fdp); break;
        case FUZZGETSHORTCUTINFOS: FuzzGetShortcutInfos(bundleMgrHost, fdp); break;
        case FUZZGETSHORTCUTINFOV9: FuzzGetShortcutInfoV9(bundleMgrHost, fdp); break;
        case FUZZGETSHORTCUTINFOBYAPPINDEX: FuzzGetShortcutInfoByAppIndex(bundleMgrHost, fdp); break;
        case FUZZGETALLCOMMONEVENTINFO: FuzzGetAllCommonEventInfo(bundleMgrHost, fdp); break;
        case FUZZGETDISTRIBUTEDBUNDLEINFO: FuzzGetDistributedBundleInfo(bundleMgrHost, fdp); break;
        case FUZZGETAPPPRIVILEGELEVEL: FuzzGetAppPrivilegeLevel(bundleMgrHost, fdp); break;
        case FUZZVERIFYCALLINGPERMISSION: FuzzVerifyCallingPermission(bundleMgrHost, fdp); break;
        case FUZZQUERYEXTENSIONABILITYINFOBYURI: FuzzQueryExtensionAbilityInfoByUri(bundleMgrHost, fdp); break;
        case FUZZQUERYEXTENSIONABILITYINFOBYURIOPTIMAL:
            FuzzQueryExtensionAbilityInfoByUriOptimal(bundleMgrHost, fdp); break;
        case FUZZGETAPPIDBYBUNDLENAME: FuzzGetAppIdByBundleName(bundleMgrHost, fdp); break;
        case FUZZGETAPPTYPE: FuzzGetAppType(bundleMgrHost, fdp); break;
        case FUZZGETUIDBYBUNDLENAME: FuzzGetUidByBundleName(bundleMgrHost, fdp); break;
        case FUZZGETMODULEUPGRADEFLAG: FuzzGetModuleUpgradeFlag(bundleMgrHost, fdp); break;
        case FUZZSETMODULEUPGRADEFLAG: FuzzSetModuleUpgradeFlag(bundleMgrHost, fdp); break;
        case FUZZIMPLICITQUERYINFOBYPRIORITY: FuzzImplicitQueryInfoByPriority(bundleMgrHost, fdp); break;
        case FUZZIMPLICITQUERYINFOS: FuzzImplicitQueryInfos(bundleMgrHost, fdp); break;
        case FUZZGETALLDEPENDENTMODULENAMES: FuzzGetAllDependentModuleNames(bundleMgrHost, fdp); break;
        case FUZZOBTAINCALLINGBUNDLENAME: FuzzObtainCallingBundleName(bundleMgrHost, fdp); break;
        case FUZZCHECKABILITYENABLEINSTALL: FuzzCheckAbilityEnableInstall(bundleMgrHost, fdp); break;
        case FUZZGETSTRINGBYID: FuzzGetStringById(bundleMgrHost, fdp); break;
        case FUZZGETICONBYID: FuzzGetIconById(bundleMgrHost, fdp); break;
        case FUZZGETBUNDLEMGREXTPROXY: FuzzGetBundleMgrExtProxy(bundleMgrHost, fdp); break;
        case FUZZGETBUNDLEINFOFORSELF: FuzzGetBundleInfoForSelf(bundleMgrHost, fdp); break;
        case FUZZVERIFYSYSTEMAPI: FuzzVerifySystemApi(bundleMgrHost, fdp); break;
        case FUZZGETOVERLAYMANAGERPROXY: FuzzGetOverlayManagerProxy(bundleMgrHost, fdp); break;
        case FUZZPROCESSPRELOAD: FuzzProcessPreload(bundleMgrHost, fdp); break;
        case FUZZUPGRADEATOMICSERVICE: FuzzUpgradeAtomicService(bundleMgrHost, fdp); break;
        case FUZZGETBASESHAREDBUNDLEINFOS: FuzzGetBaseSharedBundleInfos(bundleMgrHost, fdp); break;
        case FUZZGETALLSHAREDBUNDLEINFO: FuzzGetAllSharedBundleInfo(bundleMgrHost, fdp); break;
        case FUZZGETSHAREDBUNDLEINFO: FuzzGetSharedBundleInfo(bundleMgrHost, fdp); break;
        case FUZZGETSHAREDBUNDLEINFOBYSELF: FuzzGetSharedBundleInfoBySelf(bundleMgrHost, fdp); break;
        case FUZZGETSHAREDDEPENDENCIES: FuzzGetSharedDependencies(bundleMgrHost, fdp); break;
        case FUZZGETDEPENDENTBUNDLEINFO: FuzzGetDependentBundleInfo(bundleMgrHost, fdp); break;
        case FUZZGETPROXYDATAINFOS: FuzzGetProxyDataInfos(bundleMgrHost, fdp); break;
        case FUZZGETALLPROXYDATAINFOS: FuzzGetAllProxyDataInfos(bundleMgrHost, fdp); break;
        case FUZZGETSPECIFIEDDISTRIBUTIONTYPE: FuzzGetSpecifiedDistributionType(bundleMgrHost, fdp); break;
        case FUZZGETADDITIONALINFO: FuzzGetAdditionalInfo(bundleMgrHost, fdp); break;
        case FUZZGETADDITIONALINFOFORALLUSER: FuzzGetAdditionalInfoForAllUser(bundleMgrHost, fdp); break;
        case FUZZSETEXTNAMEORMIMETOAPP: FuzzSetExtNameOrMIMEToApp(bundleMgrHost, fdp); break;
        case FUZZQUERYDATAGROUPINFOS: FuzzQueryDataGroupInfos(bundleMgrHost, fdp); break;
        case FUZZGETPREFERENCEDIRBYGROUPID: FuzzGetPreferenceDirByGroupId(bundleMgrHost, fdp); break;
        case FUZZQUERYAPPGALLERYBUNDLENAME: FuzzQueryAppGalleryBundleName(bundleMgrHost, fdp); break;
        case FUZZQUERYEXTENSIONABILITYINFOSWITHTYPENAME:
            FuzzQueryExtensionAbilityInfosWithTypeName(bundleMgrHost, fdp); break;
        case FUZZQUERYEXTENSIONABILITYINFOSONLYWITHTYPENAME:
            FuzzQueryExtensionAbilityInfosOnlyWithTypeName(bundleMgrHost, fdp); break;
        case FUZZRESETAOTCOMPILESTATUS: FuzzResetAOTCompileStatus(bundleMgrHost, fdp); break;
        case FUZZGETJSONPROFILE: FuzzGetJsonProfile(bundleMgrHost, fdp); break;
        case FUZZGETBUNDLERESOURCEPROXY: FuzzGetBundleResourceProxy(bundleMgrHost, fdp); break;
        case FUZZGETSKILLMANAGERPROXY: FuzzGetSkillManagerProxy(bundleMgrHost, fdp); break;
        case FUZZGETRECOVERABLEAPPLICATIONINFO: FuzzGetRecoverableApplicationInfo(bundleMgrHost, fdp); break;
        case FUZZGETUNINSTALLEDBUNDLEINFO: FuzzGetUninstalledBundleInfo(bundleMgrHost, fdp); break;
        case FUZZGETODID: FuzzGetOdid(bundleMgrHost, fdp); break;
        case FUZZGETALLPREINSTALLEDAPPLICATIONINFOS: FuzzGetAllPreinstalledApplicationInfos(bundleMgrHost, fdp); break;
        case FUZZGETALLNEWPREINSTALLEDAPPLICATIONINFOS:
            FuzzGetAllNewPreinstalledApplicationInfos(bundleMgrHost, fdp); break;
        case FUZZGETALLBUNDLEINFOBYDEVELOPERID: FuzzGetAllBundleInfoByDeveloperId(bundleMgrHost, fdp); break;
        case FUZZGETDEVELOPERIDS: FuzzGetDeveloperIds(bundleMgrHost, fdp); break;
        case FUZZQUERYABILITYINFOBYCONTINUETYPE: FuzzQueryAbilityInfoByContinueType(bundleMgrHost, fdp); break;
        case FUZZGETLAUNCHWANT: FuzzGetLaunchWant(bundleMgrHost, fdp); break;
        case FUZZQUERYCLONEEXTENSIONABILITYINFOWITHAPPINDEX:
            FuzzQueryCloneExtensionAbilityInfoWithAppIndex(bundleMgrHost, fdp); break;
        case FUZZGETSIGNATUREINFOBYBUNDLENAME: FuzzGetSignatureInfoByBundleName(bundleMgrHost, fdp); break;
        case FUZZGETODIDBYBUNDLENAME: FuzzGetOdidByBundleName(bundleMgrHost, fdp); break;
        case FUZZGETODIDRESETCOUNT: FuzzGetOdidResetCount(bundleMgrHost, fdp); break;
        case FUZZGETALLDESKTOPSHORTCUTINFO: FuzzGetAllDesktopShortcutInfo(bundleMgrHost, fdp); break;
        case FUZZGETBUNDLEINFOSFORCONTINUATION: FuzzGetBundleInfosForContinuation(bundleMgrHost, fdp); break;
        case FUZZGETCONTINUEBUNDLENAMES: FuzzGetContinueBundleNames(bundleMgrHost, fdp); break;
        case FUZZGETCOMPATIBLEDEVICETYPENATIVE: FuzzGetCompatibleDeviceTypeNative(bundleMgrHost, fdp); break;
        case FUZZGETCOMPATIBLEDEVICETYPE: FuzzGetCompatibleDeviceType(bundleMgrHost, fdp); break;
        case FUZZGETBUNDLENAMEBYAPPID: FuzzGetBundleNameByAppId(bundleMgrHost, fdp); break;
        case FUZZGETALLPLUGININFO: FuzzGetAllPluginInfo(bundleMgrHost, fdp); break;
        case FUZZGETPLUGININFOSFORSELF: FuzzGetPluginInfosForSelf(bundleMgrHost, fdp); break;
        case FUZZGETDIRBYBUNDLENAMEANDAPPINDEX: FuzzGetDirByBundleNameAndAppIndex(bundleMgrHost, fdp); break;
        case FUZZGETALLBUNDLEDIRS: FuzzGetAllBundleDirs(bundleMgrHost, fdp); break;
        case FUZZGETALLBUNDLECACHESTAT: FuzzGetAllBundleCacheStat(bundleMgrHost, fdp); break;
        case FUZZGETPLUGINABILITYINFO: FuzzGetPluginAbilityInfo(bundleMgrHost, fdp); break;
        case FUZZGETPLUGINHAPMODULEINFO: FuzzGetPluginHapModuleInfo(bundleMgrHost, fdp); break;
        case FUZZGREATOREQUALTARGETAPIVERSION: FuzzGreatOrEqualTargetAPIVersion(bundleMgrHost, fdp); break;
        case FUZZGETALLSHORTCUTINFOFORSELF: FuzzGetAllShortcutInfoForSelf(bundleMgrHost, fdp); break;
        case FUZZGETALTERNATEICONS: FuzzGetAlternateIcons(bundleMgrHost, fdp); break;
        case FUZZGETPLUGININFO: FuzzGetPluginInfo(bundleMgrHost, fdp); break;
        case FUZZGETTESTRUNNER: FuzzGetTestRunner(bundleMgrHost, fdp); break;
        case FUZZGETALLBUNDLENAMES: FuzzGetAllBundleNames(bundleMgrHost, fdp); break;
        case FUZZGETABILITYRESOURCEINFO: FuzzGetAbilityResourceInfo(bundleMgrHost, fdp); break;
        case FUZZGETPLUGINBUNDLEPATHFORSELF: FuzzGetPluginBundlePathForSelf(bundleMgrHost, fdp); break;
        case FUZZGETBUNDLEINFOFOREXCEPTION: FuzzGetBundleInfoForException(bundleMgrHost, fdp); break;
        case FUZZGETALLJSONPROFILE: FuzzGetAllJsonProfile(bundleMgrHost, fdp); break;
        case FUZZBATCHGETCOMPATIBLEDEVICETYPE: FuzzBatchGetCompatibleDeviceType(bundleMgrHost, fdp); break;
        case FUZZGETASSETGROUPSINFO: FuzzGetAssetGroupsInfo(bundleMgrHost, fdp); break;
        case FUZZGETPLUGINEXTENSIONINFO: FuzzGetPluginExtensionInfo(bundleMgrHost, fdp); break;
        case FUZZGETALLLOCALPLUGININFOFORSELF: FuzzGetAllLocalPluginInfoForSelf(bundleMgrHost, fdp); break;
        case FUZZGETSTRINGBYIDLIST: FuzzGetStringByIdList(bundleMgrHost, fdp); break;
        case FUZZGETALLAPPINSTALLEDEXTENDEDINFO: FuzzGetAllAppInstallExtendedInfo(bundleMgrHost, fdp); break;
        case FUZZQUERYEXTABILITYINFOSBYTYPE: FuzzQueryExtAbilityInfosByType(bundleMgrHost, fdp); break;
        case FUZZQUERYEXTABILITYINFOSWITHOUTTYPE: FuzzQueryExtAbilityInfosWithoutType(bundleMgrHost, fdp); break;
        case FUZZQUERYEXTABILITYINFOSWITHOUTTYPEV9: FuzzQueryExtAbilityInfosWithoutTypeV9(bundleMgrHost, fdp); break;
        case FUZZQUERYEXTABILITYINFOS: FuzzQueryExtAbilityInfos(bundleMgrHost, fdp); break;
        case FUZZQUERYEXTABILITYINFOSV9: FuzzQueryExtAbilityInfosV9(bundleMgrHost, fdp); break;
        case FUZZGETTOPNLARGESTITEMSINAPPDATADIR: FuzzGetTopNLargestItemsInAppDataDir(bundleMgrHost, fdp); break;
        case FUZZGETALLBUNDLESTATS: FuzzGetAllBundleStats(bundleMgrHost, fdp); break;
        case FUZZGETBUNDLEINODECOUNT: FuzzGetBundleInodeCount(bundleMgrHost, fdp); break;
        case FUZZGETMEDIADATA: FuzzGetMediaData(bundleMgrHost, fdp); break;
        case FUZZGETBUNDLESTATS: FuzzGetBundleStats(bundleMgrHost, fdp); break;
        case FUZZBATCHGETBUNDLESTATS: FuzzBatchGetBundleStats(bundleMgrHost, fdp); break;
        case FUZZQUERYABILITYINFOWITHCALLBACK: FuzzQueryAbilityInfoWithCallback(bundleMgrHost, fdp); break;
        case FUZZGETAPITARGETVERSIONBYUID: FuzzGetApiTargetVersionByUid(bundleMgrHost, fdp); break;
        case FUZZGETQUICKFIXMANAGERPROXY: FuzzGetQuickFixManagerProxy(bundleMgrHost, fdp); break;
        case FUZZBATCHGETSPECIFIEDDISTRIBUTIONTYPE: FuzzBatchGetSpecifiedDistributionType(bundleMgrHost, fdp); break;
        case FUZZGETAPPCONTROLPROXY: FuzzGetAppControlProxy(bundleMgrHost, fdp); break;
        case FUZZGETDEFAULTAPPPROXY: FuzzGetDefaultAppProxy(bundleMgrHost, fdp); break;
        case FUZZGETCLONEBUNDLEINFOEXT: FuzzGetCloneBundleInfoExt(bundleMgrHost, fdp); break;
        case FUZZGETMAINANDCLONEBUNDLEINFO: FuzzGetMainAndCloneBundleInfo(bundleMgrHost, fdp); break;
        case FUZZGETSHORTCUTINFOBYABILITY: FuzzGetShortcutInfoByAbility(bundleMgrHost, fdp); break;
        case FUZZGETSIMPLEAPPINFOFORUID: FuzzGetSimpleAppInfoForUid(bundleMgrHost, fdp); break;
    }
    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
