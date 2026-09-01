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
#include "bmsinstalldprivilegedops_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "ipc/installd_host.h"
#include "create_dir_param.h"
#include "bms_installd_fuzztest_util.h"
#include "message_parcel.h"
#include "securec.h"
#include "bms_fuzztest_util.h"

using namespace OHOS::AppExecFwk;
using namespace OHOS::AppExecFwk::BMSFuzzTestUtil;

namespace OHOS {
constexpr uint32_t CODE_MAX = 128;

// Enum for profileBlock overflow type selection
enum ProfileBlockOverflow {
    OVERFLOW_BOUNDARY = 0,      // maxProfileBlockLength - 1
    OVERFLOW_EXACT_MAX,         // equals maxProfileBlockLength
    OVERFLOW_INTEGER_MAX,       // UINT32_MAX
    OVERFLOW_KEEP_ORIGINAL,     // keep GenerateCodeSignatureParam value
};
constexpr int32_t MAX_CERT_PATH_NUM = 10;

// ====== precise Parcel construction by real read order (verified against installd_host.cpp)======

// HandleCreateBundleDir: ReadString16(bundleName), ReadInt32(scene), ReadString16(bundleDir) [✅ correct]
void FuzzCreateBundleDir(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp);  // bundleName
    WriteInt32Field(data, fdp);                              // scene
    WriteString16Field(data, fdp); // bundleDir
    FinishParcel(data);
    host.HandleCreateBundleDir(data, reply);
}

// HandleRemoveDir: ReadString16(removedDir), ReadInt32(scene), ReadString16(bundleName), ReadBool(async)
// [fix] originally missing bundleName and async twofields
void FuzzRemoveDir(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp);  // removedDir
    WriteInt32Field(data, fdp);                              // scene
    WriteString16Field(data, fdp); // bundleName [fix]
    WriteBoolField(data, fdp);                                             // async     [fix]
    FinishParcel(data);
    host.HandleRemoveDir(data, reply);
}

// HandleExtractModuleFiles: ReadString16(srcModulePath), ReadString16(targetPath),
// ReadString16(targetSoPath), ReadString16(cpuAbi), ReadBool(needFakeDecompression), ReadBool(isSystemApp)
// [fix] originally extra bundleName and async twofields，realmethodnotthistwofields
void FuzzExtractModuleFiles(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    // [fix] removeextra bundleName and async，srcModulePath isfirstfields
    WriteString16Field(data, fdp, ATTACK_ARCHIVE);               // srcModulePath
    WriteString16Field(data, fdp);        // targetPath
    WriteString16Field(data, fdp);        // targetSoPath
    WriteParcelString16(data, fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));         // cpuAbi
    WriteBoolField(data, fdp);                                                     // needFakeDecompression
    WriteBoolField(data, fdp);                                                     // isSystemApp
    FinishParcel(data);
    host.HandleExtractModuleFiles(data, reply);
}

// HandleMoveFile: ReadString16(oldPath), ReadString16(newPath), ReadInt32(scene), ReadString16(bundleName)
// [fix] originally missing scene and bundleName twofields
void FuzzMoveFile(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp);  // oldPath
    WriteString16Field(data, fdp);  // newPath
    WriteInt32Field(data, fdp);                              // scene      [fix]
    WriteString16Field(data, fdp); // bundleName [fix]
    FinishParcel(data);
    host.HandleMoveFile(data, reply);
}

// HandleCopyFile: ReadString16(oldPath), ReadString16(newPath), ReadInt32(scene), ReadString16(signatureFilePath)
// [fix] originally missing signatureFilePath fields
void FuzzCopyFile(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp);  // oldPath
    WriteString16Field(data, fdp);  // newPath
    WriteInt32Field(data, fdp);                              // scene
    // [fix] supplement signatureFilePath fields，makeusesignature bypass attack vector
    WriteString16Field(data, fdp, ATTACK_CERT_BYPASS);   // signatureFilePath
    FinishParcel(data);
    host.HandleCopyFile(data, reply);
}

// HandleMkdir: ReadString16(dir), ReadInt32(mode), ReadInt32(uid),
// ReadInt32(gid), ReadParcelable<CreateDirParam>
// [fix] originally wrong: dir + isRealPath, real: dir + mode + uid + gid + CreateDirParam
void FuzzMkdir(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp);  // dir
    WriteInt32Field(data, fdp);                              // mode  [fix]
    WriteInt32Field(data, fdp);                              // uid   [fix]
    WriteInt32Field(data, fdp);                              // gid   [fix]
    // [fix] construct CreateDirParam Parcelable andwrite
    CreateDirParam dirParam;
    GenerateCreateDirParam(fdp, dirParam);
    data.WriteParcelable(&dirParam);                                                // CreateDirParam [fix]
    FinishParcel(data);
    host.HandleMkdir(data, reply);
}

// HandleSetDirApl: ReadString16(dataDir), ReadString16(bundleName), ReadString16(apl),
// ReadBool(isPreInstallApp), ReadBool(debug), ReadInt32(uid)
// [fix] originallywrong order(dir,apl,dataDir)andmissing isPreInstallApp, debug, uid threefields
void FuzzSetDirApl(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    // [fix] by real order：dataDir, bundleName, apl, isPreInstallApp, debug, uid
    WriteString16Field(data, fdp);  // dataDir       [fix]
    WriteString16Field(data, fdp); // bundleName    [fix]
    WriteString16Field(data, fdp, ATTACK_SELINUX);        // apl           [fix]
    WriteBoolField(data, fdp);                                             // isPreInstallApp [fix]
    WriteBoolField(data, fdp);                                             // debug         [fix]
    WriteInt32Field(data, fdp);                              // uid           [fix]
    FinishParcel(data);
    host.HandleSetDirApl(data, reply);
}

// HandleDeleteCertAndRemoveKey: ReadInt32(pathSize), loopReadString16(certPath), ReadInt32(userId)
// [fix] originallycompletely wrong(certPath,userId)，real order: read count then loop read path array
void FuzzDeleteCert(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    // [fix] real read order：pathSize + looppathSizeReadString16(certPath)
    int32_t pathSize = fdp.ConsumeIntegral<int32_t>() % MAX_CERT_PATH_NUM + 1;  // pathSize [fix]
    data.WriteInt32(pathSize);
    for (int32_t i = 0; i < pathSize; i++) {
        // signature bypass attack vector: malicious cert path
        WriteString16Field(data, fdp, ATTACK_CERT_BYPASS);  // certPath [fix]
    }
    WriteInt32Field(data, fdp);                              // userId   [fix]
    FinishParcel(data);
    host.HandleDeleteCertAndRemoveKey(data, reply);
}

// ====== add: signature verification3code ======

// HandVerifyCodeSignature: ReadParcelable<CodeSignatureParam>
// Inject malicious profileBlockLength to trigger WriteBuffer overflow in Marshalling:
// CodeSignatureParam::Marshalling calls parcel.WriteBuffer(profileBlock.get(), profileBlockLength)
// If profileBlock has 64 bytes but profileBlockLength=1048575 -> out-of-bounds read during Marshalling
void FuzzVerifyCodeSignature(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    CodeSignatureParam param;
    GenerateCodeSignatureParam(fdp, param);
    // Overwrite profileBlockLength with malicious value larger than actual profileBlock buffer
    // This triggers WriteBuffer(profileBlock.get(), profileBlockLength) out-of-bounds read in Marshalling
    uint8_t overflowType = fdp.ConsumeIntegral<uint8_t>() % OVERFLOW_TYPE_COUNT;
    constexpr uint32_t maxProfileBlockLength = PROFILE_BLOCK_MAX_SIZE;  // 1M
    switch (overflowType) {
        case OVERFLOW_BOUNDARY:  // boundary: maxProfileBlockLength - 1, passes < MAX check but buffer is small
            param.profileBlockLength = maxProfileBlockLength - 1;
            param.profileBlock = std::shared_ptr<unsigned char[]>(new unsigned char[SMALL_BUFFER_SIZE]());
            break;
        case OVERFLOW_EXACT_MAX:  // exact boundary: equals MAX, skips read
            param.profileBlockLength = maxProfileBlockLength;
            break;
        case OVERFLOW_INTEGER_MAX:  // integer overflow: UINT32_MAX
            param.profileBlockLength = UINT32_MAX_VAL;
            param.profileBlock = std::shared_ptr<unsigned char[]>(new unsigned char[SMALL_BUFFER_SIZE]());
            break;
        default: // keep GenerateCodeSignatureParam's original value
            break;
    }
    data.WriteParcelable(&param);  // Marshalling triggers WriteBuffer overflow
    FinishParcel(data);
    host.HandVerifyCodeSignature(data, reply);
}

// HandVerifyCodeSignatureForHap: ReadParcelable<CodeSignatureParam>
// Same WriteBuffer overflow trigger via Marshalling path
void FuzzVerifyCodeSignatureForHap(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    CodeSignatureParam param;
    GenerateCodeSignatureParam(fdp, param);
    // Same malicious profileBlockLength injection for Marshalling WriteBuffer overflow
    uint8_t overflowType = fdp.ConsumeIntegral<uint8_t>() % OVERFLOW_TYPE_COUNT;
    constexpr uint32_t maxProfileBlockLength = PROFILE_BLOCK_MAX_SIZE;
    switch (overflowType) {
        case OVERFLOW_BOUNDARY:
            param.profileBlockLength = maxProfileBlockLength - 1;
            param.profileBlock = std::shared_ptr<unsigned char[]>(new unsigned char[SMALL_BUFFER_SIZE]());
            break;
        case OVERFLOW_EXACT_MAX:
            param.profileBlockLength = maxProfileBlockLength;
            break;
        case OVERFLOW_INTEGER_MAX:
            param.profileBlockLength = UINT32_MAX_VAL;
            param.profileBlock = std::shared_ptr<unsigned char[]>(new unsigned char[SMALL_BUFFER_SIZE]());
            break;
        default:
            break;
    }
    data.WriteParcelable(&param);  // Marshalling triggers WriteBuffer overflow
    FinishParcel(data);
    host.HandVerifyCodeSignatureForHap(data, reply);
}

// HandDeliverySignProfile: ReadString16(bundleName), ReadInt32(profileBlockLength), ReadRawData(profileBlockLength)
void FuzzDeliverySignProfile(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp);  // bundleName
    int32_t profileBlockLength =
        fdp.ConsumeIntegral<int32_t>() % PROFILE_BLOCK_MAX_SIZE + 1;
    data.WriteInt32(profileBlockLength);
    std::vector<uint8_t> profileBlock(profileBlockLength);
    for (int32_t i = 0; i < profileBlockLength; i++) {
        profileBlock[i] = fdp.ConsumeIntegral<uint8_t>();
    }
    data.WriteRawData(profileBlock.data(), profileBlockLength);                    // profileBlock
    FinishParcel(data);
    host.HandDeliverySignProfile(data, reply);
}

// ====== add: encryptionoperation3code ======

// HandleCheckEncryption: ReadParcelable<CheckEncryptionParam>
void FuzzCheckEncryption(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    CheckEncryptionParam param;
    GenerateCheckEncryptionParam(fdp, param);
    data.WriteParcelable(&param);
    FinishParcel(data);
    host.HandleCheckEncryption(data, reply);
}

// HandleSetEncryptionDir: ReadParcelable<EncryptionParam>, ReadString(keyId)
void FuzzSetEncryptionDir(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    EncryptionParam param;
    GenerateEncryptionParam(fdp, param);
    data.WriteParcelable(&param);
    // keyId — makeusesignature bypass attack vector
    WriteStringField(data, fdp, ATTACK_CERT_BYPASS);              // keyId
    FinishParcel(data);
    host.HandleSetEncryptionDir(data, reply);
}

// HandleDeleteEncryptionKeyId: ReadParcelable<EncryptionParam>
void FuzzDeleteEncryptionKeyId(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    EncryptionParam param;
    GenerateEncryptionParam(fdp, param);
    data.WriteParcelable(&param);
    FinishParcel(data);
    host.HandleDeleteEncryptionKeyId(data, reply);
}

// ====== add: certoperation1code ======

// HandleAddCertAndEnableKey: ReadString16(certPath), ReadUint32(dataSize), ReadBuffer(data, dataSize)
void FuzzAddCertAndEnableKey(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp, ATTACK_CERT_BYPASS);  // certPath
    uint32_t dataSize = fdp.ConsumeIntegral<uint32_t>() % (CERT_CAPACITY_MAX_SIZE / 128) + 1;             // dataSize
    data.WriteUint32(dataSize);
    std::vector<uint8_t> certData(dataSize);
    for (uint32_t i = 0; i < dataSize; i++) {
        certData[i] = fdp.ConsumeIntegral<uint8_t>();
    }
    data.WriteBuffer(certData.data(), dataSize);                                // certData
    FinishParcel(data);
    host.HandleAddCertAndEnableKey(data, reply);
}

// ====== add: strcpy_s overflow verification ======
// trigger 4 strcpy_s overflow paths in installd_operator.cpp:
//   strcpy_s(hapInfo.packageName, sizeof(hapInfo.packageName), param.packageName.c_str())
//   strcpy_s(hapInfo.hapPath, sizeof(hapInfo.hapPath), param.hapPath.c_str())
//   strcpy_s(hapInfo.abi, sizeof(hapInfo.abi), param.cpuAbi.c_str())
//   strcpy_s(hapInfo.appIdentifier, sizeof(hapInfo.appIdentifier), param.appIdentifier.c_str())
void FuzzStrcpyOverflow(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    // constructmaliciousHapInfo payloadtrigger4strcpy_soverflow
    std::string packageName;
    std::string hapPath;
    std::string cpuAbi;
    std::string appIdentifier;
    GenMaliciousHapInfoPayload(fdp, packageName, hapPath, cpuAbi, appIdentifier);
    // passHandleProcessBundleInstallNativetriggerstrcpy_spath
    // ReadString16(packageName), ReadString16(hapPath), ReadString16(cpuAbi), ReadString16(appIdentifier)
    WriteParcelString16(data, packageName);
    WriteParcelString16(data, hapPath);
    WriteParcelString16(data, cpuAbi);
    WriteParcelString16(data, appIdentifier);
    FinishParcel(data);
    host.HandleProcessBundleInstallNative(data, reply);
}

// ====== additional high-risk methods (20) ======

// CleanBundleDataDir: ReadString16(bundleDir), ReadString16(bundleName), ReadInt32(userId)
void FuzzCleanBundleDataDir(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp);  // bundleDir
    WriteString16Field(data, fdp); // bundleName
    WriteUserId(data, fdp);                                     // userId
    FinishParcel(data);
    host.HandleCleanBundleDataDir(data, reply);
}

// CleanBundleDirs: ReadUint32(dirSize), ReadStringVector(dirs), ReadBool(keepParent)
void FuzzCleanBundleDirs(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    uint32_t dirSize = fdp.ConsumeIntegral<uint32_t>() % MAX_DIR_COUNT;
    data.WriteUint32(dirSize);                                                    // dirSize
    WriteStringVectorField(data, fdp);                                                 // dirs
    WriteBoolField(data, fdp);                                            // keepParent
    FinishParcel(data);
    host.HandleCleanBundleDirs(data, reply);
}

// ClearDir: ReadString(dir), ReadInt32(scene)
void FuzzClearDir(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // dir
    WriteInt32Field(data, fdp);                     // scene
    FinishParcel(data);
    host.HandleClearDir(data, reply);
}

// CopyDir: ReadString(srcDir), ReadString(destDir), ReadString16(bundleName), ReadInt32(scene)
void FuzzCopyDir(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);          // srcDir
    WriteStringField(data, fdp);          // destDir
    WriteString16Field(data, fdp); // bundleName
    WriteInt32Field(data, fdp);                             // scene
    FinishParcel(data);
    host.HandleCopyDir(data, reply);
}

// RenameFile: ReadString16(oldPath), ReadString16(newPath)
void FuzzRenameFile(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp);  // oldPath
    WriteString16Field(data, fdp);  // newPath
    FinishParcel(data);
    host.HandleRenameFile(data, reply);
}

// RenameModuleDir: ReadString16(oldPath), ReadString16(newPath), ReadString16(bundleName), ReadInt32(scene)
void FuzzRenameModuleDir(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp);  // oldPath
    WriteString16Field(data, fdp);  // newPath
    WriteString16Field(data, fdp); // bundleName
    WriteInt32Field(data, fdp);                             // scene
    FinishParcel(data);
    host.HandleRenameModuleDir(data, reply);
}

// MoveHapToCodeDir: ReadString16(originPath), ReadString16(targetPath)
void FuzzMoveHapToCodeDir(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp);  // originPath
    WriteString16Field(data, fdp);  // targetPath
    FinishParcel(data);
    host.HandleMoveHapToCodeDir(data, reply);
}

// ApplyDiffPatch: ReadString16(oldSoPath), ReadString16(diffFilePath), ReadString16(newSoPath), ReadInt32(uid)
void FuzzApplyDiffPatch(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp);  // oldSoPath
    WriteString16Field(data, fdp, ATTACK_CERT_BYPASS);    // diffFilePath
    WriteString16Field(data, fdp);  // newSoPath
    WriteInt32Field(data, fdp);                             // uid
    FinishParcel(data);
    host.HandleApplyDiffPatch(data, reply);
}

// ExtractDiffFiles: ReadString16(filePath), ReadString16(targetPath), ReadString16(cpuAbi)
void FuzzExtractDiffFiles(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp, ATTACK_ARCHIVE);         // filePath
    WriteString16Field(data, fdp);  // targetPath
    WriteParcelString16(data, fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));  // cpuAbi
    FinishParcel(data);
    host.HandleExtractDiffFiles(data, reply);
}

// RemoveExtensionDir: ReadInt32(userId), ReadInt32(extensionBundleDirSize), ReadStringVector(extensionBundleDirs)
void FuzzRemoveExtensionDir(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteUserId(data, fdp);                                    // userId
    int32_t dirSize = fdp.ConsumeIntegral<int32_t>() % MAX_DIR_COUNT;
    data.WriteInt32(dirSize);                                                    // extensionBundleDirSize
    WriteStringVectorField(data, fdp);                                 // extensionBundleDirs
    FinishParcel(data);
    host.HandleRemoveExtensionDir(data, reply);
}

// RemoveBundleDataDir: ReadString16(bundleName), ReadInt32(userId), ReadBool(isAtomicService), ReadBool(async)
void FuzzRemoveBundleDataDir(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp);  // bundleName
    WriteUserId(data, fdp);                                     // userId
    WriteBoolField(data, fdp);                                            // isAtomicService
    WriteBoolField(data, fdp);                                            // async
    FinishParcel(data);
    host.HandleRemoveBundleDataDir(data, reply);
}

// IsExistDir: ReadString16(path)
void FuzzIsExistDir(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp);  // path
    FinishParcel(data);
    host.HandleIsExistDir(data, reply);
}

// IsExistFile: ReadString16(path)
void FuzzIsExistFile(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp);  // path
    FinishParcel(data);
    host.HandleIsExistFile(data, reply);
}

// ScanDir: ReadString16(dir), ReadInt32(scanMode), ReadInt32(resultMode)
void FuzzScanDir(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp);  // dir
    WriteInt32Field(data, fdp);                             // scanMode
    WriteInt32Field(data, fdp);                             // resultMode
    FinishParcel(data);
    host.HandleScanDir(data, reply);
}

// GetBundleCachePath: ReadString16(dir)
void FuzzGetBundleCachePath(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp);  // dir
    FinishParcel(data);
    host.HandleGetBundleCachePath(data, reply);
}

// GetDiskUsage: ReadString16(dir), ReadBool(isRealPath)
void FuzzGetDiskUsage(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp);  // dir
    WriteBoolField(data, fdp);                                            // isRealPath
    FinishParcel(data);
    host.HandleGetDiskUsage(data, reply);
}

// MigrateData: ReadInt32(size), ReadStringVector(sourcePaths), ReadString16(destinationPath)
void FuzzMigrateDataInstalld(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    int32_t size = fdp.ConsumeIntegral<int32_t>() % MAX_DIR_COUNT;
    data.WriteInt32(size);                                                       // size
    WriteStringVectorField(data, fdp);                                          // sourcePaths
    WriteString16Field(data, fdp); // destinationPath
    FinishParcel(data);
    host.HandleMigrateData(data, reply);
}

// DeleteOldCacheFiles: ReadInt32(pathSize), ReadStringVector(paths)
void FuzzDeleteOldCacheFiles(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    int32_t pathSize = fdp.ConsumeIntegral<int32_t>() % MAX_DIR_COUNT;
    data.WriteInt32(pathSize);                                                   // pathSize
    WriteStringVectorField(data, fdp);                                               // paths
    FinishParcel(data);
    host.HandleDeleteOldCacheFiles(data, reply);
}

// CreateDataGroupDirs: ReadUint32(dataGroupSize), loop ReadParcelable<CreateDirParam>
void FuzzCreateDataGroupDirs(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    uint32_t dataGroupSize = fdp.ConsumeIntegral<uint32_t>() % MAX_GROUP_COUNT;
    data.WriteUint32(dataGroupSize);                                             // dataGroupSize
    for (uint32_t i = 0; i < dataGroupSize; i++) {
        CreateDirParam dirParam;
        GenerateCreateDirParam(fdp, dirParam);
        data.WriteParcelable(&dirParam);
    }
    FinishParcel(data);
    host.HandleCreateDataGroupDirs(data, reply);
}

// SetDirsApl: ReadParcelable<CreateDirParam>, ReadBool(isExtensionDir)
void FuzzSetDirsApl(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    CreateDirParam dirParam;
    GenerateCreateDirParam(fdp, dirParam);
    data.WriteParcelable(&dirParam);                                              // CreateDirParam
    WriteBoolField(data, fdp);                                           // isExtensionDir
    FinishParcel(data);
    host.HandleSetDirsApl(data, reply);
}

// ====== additional high-risk methods batch 2 (23) ======

// CleanBundleDataDirByName: ReadString16(bundleName), ReadInt32(userid), ReadInt32(appIndex), ReadBool(isAtomicService)
void FuzzCleanBundleDataDirByName(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp);  // bundleName
    WriteUserId(data, fdp);                                     // userid
    WriteInt32Field(data, fdp);                              // appIndex
    WriteBoolField(data, fdp);                                            // isAtomicService
    FinishParcel(data);
    host.HandleCleanBundleDataDirByName(data, reply);
}

// HashSoFile: ReadString(soPath), ReadUint32(catchSoNum), ReadUint64(catchSoMaxSize), ReadStringVector(soName)
void FuzzHashSoFile(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);  // soPath
    WriteUint32Field(data, fdp);                   // catchSoNum
    WriteUint64Field(data, fdp);                  // catchSoMaxSize
    WriteStringVectorField(data, fdp);                                       // soName
    FinishParcel(data);
    host.HandleHashSoFile(data, reply);
}

// HashFiles: ReadInt32(size), loop ReadString16(files)
void FuzzHashFiles(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    int32_t size = fdp.ConsumeIntegral<int32_t>() % MAX_DIR_COUNT;
    data.WriteInt32(size);                                               // size
    WriteStringVectorField(data, fdp);                                        // files
    FinishParcel(data);
    host.HandleHashFiles(data, reply);
}

// GetFileStat: ReadString16(file), ReadInt32(scene)
void FuzzGetFileStat(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp);  // file
    WriteInt32Field(data, fdp);                              // scene
    FinishParcel(data);
    host.HandleGetFileStat(data, reply);
}

// IsDirEmpty: ReadString16(dir)
void FuzzIsDirEmpty(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp);  // dir
    FinishParcel(data);
    host.HandleIsDirEmpty(data, reply);
}

// IsExistApFile: ReadString16(path)
void FuzzIsExistApFile(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp);  // path
    FinishParcel(data);
    host.HandleIsExistApFile(data, reply);
}

// IsExistExtensionDir: ReadInt32(userId), ReadString16(extensionBundleDir)
void FuzzIsExistExtensionDir(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteUserId(data, fdp);                                     // userId
    WriteString16Field(data, fdp); // extensionBundleDir
    FinishParcel(data);
    host.HandleIsExistExtensionDir(data, reply);
}

// SetFileConForce: ReadUint32(pathSize), loop ReadString16(paths), ReadParcelable<CreateDirParam>
void FuzzSetFileConForce(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    uint32_t pathSize = fdp.ConsumeIntegral<uint32_t>() % MAX_PATH_COUNT;
    data.WriteUint32(pathSize);                                                  // pathSize
    for (uint32_t i = 0; i < pathSize; i++) {
        WriteString16Field(data, fdp);  // path
    }
    CreateDirParam dirParam;
    GenerateCreateDirParam(fdp, dirParam);
    data.WriteParcelable(&dirParam);                                              // CreateDirParam
    FinishParcel(data);
    host.HandleSetFileConForce(data, reply);
}

// StopAOT: no params
void FuzzStopAOT(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    FinishParcel(data);
    host.HandleStopAOT(data, reply);
}

// PendSignAOT: ReadString16(anFileName), ReadUInt8Vector(signData)
void FuzzPendSignAOT(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp, ATTACK_CERT_BYPASS);  // anFileName
    std::vector<uint8_t> signData(fdp.ConsumeIntegral<uint32_t>() % MAX_SIGN_DATA_SIZE);
    for (auto& b : signData) { b = fdp.ConsumeIntegral<uint8_t>(); }
    data.WriteUInt8Vector(signData);                                              // signData
    FinishParcel(data);
    host.HandlePendSignAOT(data, reply);
}

// LoadInstalls: no params
void FuzzLoadInstalls(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    FinishParcel(data);
    host.HandleLoadInstalls(data, reply);
}

// CheckExternalSourcePluginSwitch: no params
void FuzzCheckExternalSourcePluginSwitch(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    FinishParcel(data);
    host.HandleCheckExternalSourcePluginSwitch(data, reply);
}

// DeleteUninstallTmpDirs: ReadUint32(size), loop ReadString(dirs)
void FuzzDeleteUninstallTmpDirs(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    uint32_t size = fdp.ConsumeIntegral<uint32_t>() % MAX_DIR_COUNT;
    data.WriteUint32(size);                                                      // size
    WriteStringVectorField(data, fdp);                                                 // dirs
    FinishParcel(data);
    host.HandleDeleteUninstallTmpDirs(data, reply);
}

// ChangeFileStat: ReadString16(file), ReadParcelable<FileStat>, ReadInt32(scene)
void FuzzChangeFileStat(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp);  // file
    WriteInt32Field(data, fdp);                              // scene (simplified, skip FileStat Parcelable)
    FinishParcel(data);
    host.HandleChangeFileStat(data, reply);
}

// GetBundleStats: ReadString16(bundleName), ReadInt32(userId), ReadInt32(uidSize), loop ReadInt32(uids)
void FuzzGetBundleStats(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp);  // bundleName
    WriteUserId(data, fdp);                                     // userId
    int32_t uidSize = fdp.ConsumeIntegral<int32_t>() % MAX_UID_COUNT;
    data.WriteInt32(uidSize);                                                     // uidSize
    for (int32_t i = 0; i < uidSize; i++) {
        WriteInt32Field(data, fdp);                          // uid
    }
    FinishParcel(data);
    host.HandleGetBundleStats(data, reply);
}

// GetAllBundleStats: ReadInt32(uidSize), loop ReadInt32(uids)
void FuzzGetAllBundleStats(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    int32_t uidSize = fdp.ConsumeIntegral<int32_t>() % MAX_UID_COUNT;
    data.WriteInt32(uidSize);                                                     // uidSize
    for (int32_t i = 0; i < uidSize; i++) {
        WriteInt32Field(data, fdp);                          // uid
    }
    FinishParcel(data);
    host.HandleGetAllBundleStats(data, reply);
}

// StopSetFileCon: ReadParcelable<CreateDirParam>, ReadInt32(reason)
void FuzzStopSetFileCon(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    CreateDirParam dirParam;
    GenerateCreateDirParam(fdp, dirParam);
    data.WriteParcelable(&dirParam);                                              // CreateDirParam
    WriteInt32Field(data, fdp);                             // reason
    FinishParcel(data);
    host.HandleStopSetFileCon(data, reply);
}

// AddUserDirDeleteDfx: ReadInt32(userId)
void FuzzAddUserDirDeleteDfx(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteUserId(data, fdp);                                    // userId
    FinishParcel(data);
    host.HandleAddUserDirDeleteDfx(data, reply);
}

// GetTopNLargestItemsInAppDataDir: ReadString16(bundleName), ReadInt32(appIndex), ReadInt32(userId), ReadInt32(timeout)
void FuzzGetTopNLargestItems(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp);  // bundleName
    WriteInt32Field(data, fdp);                              // appIndex
    WriteUserId(data, fdp);                                    // userId
    WriteInt32Field(data, fdp);                              // timeout
    FinishParcel(data);
    host.HandleGetTopNLargestItemsInAppDataDir(data, reply);
}

// ExtractHnpFiles: ReadInt32(mapSize), loop ReadString16(package)+ReadString16(type), ReadParcelable<ExtractParam>
void FuzzExtractHnpFiles(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    int32_t mapSize = fdp.ConsumeIntegral<int32_t>() % MAX_GROUP_COUNT;
    data.WriteInt32(mapSize);                                                    // mapSize
    for (int32_t i = 0; i < mapSize; i++) {
        WriteParcelString16(data, fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));  // package
        WriteParcelString16(data, fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));  // type
    }
    FinishParcel(data);
    host.HandleExtractHnpFiles(data, reply);
}

// CheckHspPluginCertValidity: ReadString16(bundleName), ReadInt32(sessionId)
void FuzzCheckHspPluginCertValidity(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp, ATTACK_CERT_BYPASS);  // bundleName
    WriteInt32Field(data, fdp);                           // sessionId
    FinishParcel(data);
    host.HandleCheckHspPluginCertValidity(data, reply);
}

// SetArkStartupCacheDirApl: ReadString16(bundleName), ReadString16(apl), ReadInt32(uid)
void FuzzSetArkStartupCacheApl(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp);  // bundleName
    WriteString16Field(data, fdp, ATTACK_SELINUX);         // apl
    WriteInt32Field(data, fdp);                              // uid
    FinishParcel(data);
    host.HandleSetArkStartupCacheApl(data, reply);
}

// HandObtainQuickFixFileDir: ReadString16(dir)
void FuzzObtainQuickFixDir(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp);  // dir
    FinishParcel(data);
    host.HandObtainQuickFixFileDir(data, reply);
}

// ====== additional high-risk methods batch 3 (19) ======

// CreateBundleDataDir: ReadParcelable<CreateDirParam>
void FuzzCreateBundleDataDir2(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    CreateDirParam dirParam;
    GenerateCreateDirParam(fdp, dirParam);
    data.WriteParcelable(&dirParam);
    FinishParcel(data);
    host.HandleCreateBundleDataDir(data, reply);
}

// CreateExtensionDataDir: ReadParcelable<CreateDirParam>
void FuzzCreateExtensionDataDir2(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    CreateDirParam dirParam;
    GenerateCreateDirParam(fdp, dirParam);
    data.WriteParcelable(&dirParam);
    FinishParcel(data);
    host.HandleCreateExtensionDataDir(data, reply);
}

// DeleteDataGroupDirs: ReadUint32(uuidSize), loop ReadString(uuid)
void FuzzDeleteDataGroupDirs(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    uint32_t uuidSize = fdp.ConsumeIntegral<uint32_t>() % MAX_GROUP_COUNT;
    data.WriteUint32(uuidSize);
    for (uint32_t i = 0; i < uuidSize; i++) {
        WriteStringField(data, fdp, ATTACK_CERT_BYPASS);
    }
    FinishParcel(data);
    host.HandleDeleteDataGroupDirs(data, reply);
}

// ExecuteAOT: ReadParcelable<AOTArgs>
void FuzzExecuteAOT(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    AOTArgs aotArgs;
    GenerateAOTArgs(fdp, aotArgs);
    data.WriteParcelable(&aotArgs);                                        // AOTArgs
    FinishParcel(data);
    host.HandleExecuteAOT(data, reply);
}

// ExtractFiles: ReadParcelable<ExtractParam>
void FuzzExtractFiles(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    ExtractParam param;
    GenerateExtractParam(fdp, param);
    data.WriteParcelable(&param);                                          // ExtractParam
    FinishParcel(data);
    host.HandleExtractFiles(data, reply);
}

// ExtractSkillsPackage: ReadParcelable<SkillsPackageParam>
void FuzzExtractSkillsPackage(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    SkillsPackageParam param;
    GenerateSkillsPackageParam(fdp, param);
    data.WriteParcelable(&param);                                          // SkillsPackageParam
    FinishParcel(data);
    host.HandleExtractSkillsPackage(data, reply);
}

// ProcessBinFiles: ReadParcelable<VerifyBinParam>
void FuzzProcessBinFiles(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    VerifyBinParam param;
    GenerateVerifyBinParam(fdp, param);
    data.WriteParcelable(&param);                                          // VerifyBinParam
    FinishParcel(data);
    host.HandleProcessBinFiles(data, reply);
}

// BatchGetBundleStats: ReadInt32(size), loop ReadString16(bundleName)
void FuzzBatchGetBundleStats(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    int32_t size = fdp.ConsumeIntegral<int32_t>() % MAX_PATH_COUNT;
    data.WriteInt32(size);
    for (int32_t i = 0; i < size; i++) {
        WriteString16Field(data, fdp);
    }
    FinishParcel(data);
    host.HandleBatchGetBundleStats(data, reply);
}

// GetDiskUsageFromPath: ReadUint32(cachePathSize), loop ReadString(cachePaths)
void FuzzGetDiskUsageFromPath(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    uint32_t cachePathSize = fdp.ConsumeIntegral<uint32_t>() % MAX_PATH_COUNT;
    data.WriteUint32(cachePathSize);
    WriteStringVectorField(data, fdp);
    FinishParcel(data);
    host.HandleGetDiskUsageFromPath(data, reply);
}

// ProcessBundleUnInstallNative: ReadString16(userId), ReadString16(packageName)
void FuzzProcessBundleUnInstallNative(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteParcelString16(data, fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));   // userId
    WriteString16Field(data, fdp);   // packageName
    FinishParcel(data);
    host.HandleProcessBundleUnInstallNative(data, reply);
}

// RemoveModuleDataDir: ReadString16(moduleName), ReadInt32(userId)
void FuzzRemoveModuleDataDir(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp);  // moduleName
    WriteUserId(data, fdp);                                     // userId
    FinishParcel(data);
    host.HandleRemoveModuleDataDir(data, reply);
}

// RestoreconPath: ReadString(path), ReadString16(bundleName), ReadInt32(scene)
void FuzzRestoreconPath(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteStringField(data, fdp);          // path
    WriteString16Field(data, fdp); // bundleName
    WriteInt32Field(data, fdp);                              // scene
    FinishParcel(data);
    host.HandleRestoreconPath(data, reply);
}

// ResetBmsDBSecurity: no params
void FuzzResetBmsDBSecurity(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    FinishParcel(data);
    host.HandleResetBmsDBSecurity(data, reply);
}

// GetExtensionSandboxTypeList: no params
void FuzzGetExtensionSandboxTypeList(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    FinishParcel(data);
    host.HandleGetExtensionSandboxTypeList(data, reply);
}

// GetBundleInodeCount: ReadInt32(uid)
void FuzzGetBundleInodeCount(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteInt32Field(data, fdp);                              // uid
    FinishParcel(data);
    host.HandleGetBundleInodeCount(data, reply);
}

// HandCopyFiles: ReadString16(sourceDir), ReadString16(destinationDir), ReadString16(bundleName), ReadInt32(scene)
void FuzzCopyFiles(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp);  // sourceDir
    WriteString16Field(data, fdp);  // destinationDir
    WriteString16Field(data, fdp); // bundleName
    WriteInt32Field(data, fdp);                              // scene
    FinishParcel(data);
    host.HandCopyFiles(data, reply);
}

// HandExtractDriverSoFiles: ReadString16(srcPath), ReadInt32(size), loop ReadString16+ReadString16
void FuzzExtractDriverSoFiles(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp);  // srcPath
    int32_t size = fdp.ConsumeIntegral<int32_t>() % MAX_GROUP_COUNT;
    data.WriteInt32(size);
    for (int32_t i = 0; i < size; i++) {
        WriteParcelString16(data, fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
        WriteParcelString16(data, fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));
    }
    FinishParcel(data);
    host.HandExtractDriverSoFiles(data, reply);
}

// HandMoveFiles: ReadString16(srcDir), ReadString16(desDir), ReadString16(bundleName), ReadInt32(scene)
void FuzzMoveFiles(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp);  // srcDir
    WriteString16Field(data, fdp);  // desDir
    WriteString16Field(data, fdp); // bundleName
    WriteInt32Field(data, fdp);                              // scene
    FinishParcel(data);
    host.HandMoveFiles(data, reply);
}

// HandRemoveSignProfile: ReadString16(bundleName)
void FuzzRemoveSignProfile(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp, ATTACK_CERT_BYPASS);  // bundleName
    FinishParcel(data);
    host.HandRemoveSignProfile(data, reply);
}

// ====== additional high-risk methods batch 4 (4) ======

 // HandExtractEncryptedSoFiles: ReadString16(hapPath), ReadString16(realSoFilesPath), ReadString16(cpuAbi),
// ReadString16(tmpSoPath)
void FuzzExtractEncryptedSoFiles(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp, ATTACK_ARCHIVE);         // hapPath
    WriteString16Field(data, fdp);  // realSoFilesPath
    WriteParcelString16(data, fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));  // cpuAbi
    WriteString16Field(data, fdp);  // tmpSoPath
    FinishParcel(data);
    host.HandExtractEncryptedSoFiles(data, reply);
}

// HandGetNativeLibraryFileNames: ReadString16(filePath), ReadString16(cupAbi)
void FuzzGetNativeLibraryFileNames(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp);  // filePath
    WriteParcelString16(data, fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH));  // cupAbi
    FinishParcel(data);
    host.HandGetNativeLibraryFileNames(data, reply);
}

// HandleCreateBundleDataDirWithVector: ReadInt32(createDirParamSize), loop ReadParcelable<CreateDirParam>
void FuzzCreateBundleDataDirWithVector(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    int32_t createDirParamSize = fdp.ConsumeIntegral<int32_t>() % MAX_GROUP_COUNT;
    data.WriteInt32(createDirParamSize);                                       // createDirParamSize
    for (int32_t i = 0; i < createDirParamSize; i++) {
        CreateDirParam dirParam;
        GenerateCreateDirParam(fdp, dirParam);
        data.WriteParcelable(&dirParam);
    }
    FinishParcel(data);
    host.HandleCreateBundleDataDirWithVector(data, reply);
}

// HandleGetCacheDiskUsageFromPath: ReadUint32(cachePathSize), loop ReadString(cachePaths)
void FuzzGetCacheDiskUsageFromPath(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    uint32_t cachePathSize = fdp.ConsumeIntegral<uint32_t>() % MAX_PATH_COUNT;
    data.WriteUint32(cachePathSize);                                           // cachePathSize
    WriteStringVectorField(data, fdp);                                        // cachePaths
    FinishParcel(data);
    host.HandleGetCacheDiskUsageFromPath(data, reply);
}

// ProcessBundleInstallNative: ReadParcelable<InstallHnpParam> - precise field construction
void FuzzProcessBundleInstallNative(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    InstallHnpParam param;
    GenerateInstallHnpParam(fdp, param);
    data.WriteParcelable(&param);                                         // InstallHnpParam
    FinishParcel(data);
    host.HandleProcessBundleInstallNative(data, reply);
}

// HandleExtractQuickFixSoFile: ReadString16(bundleName), ReadString16(hqfFilePath),
// ReadString16(nativeLibraryPath), ReadString16(cpuAbi), ReadBool(isReplace),
// ReadInt32(versionCode), ReadString16(targetPathSuffix)
void FuzzExtractQuickFixSoFile(InstalldHost& host, FuzzedDataProvider& fdp)
{
    MessageParcel data;
    PrepareParcel<InstalldHost>(data);
    MessageParcel reply;
    WriteString16Field(data, fdp);                            // bundleName
    WriteString16Field(data, fdp, ATTACK_ARCHIVE);           // hqfFilePath
    WriteString16Field(data, fdp);                            // nativeLibraryPath
    WriteString16Field(data, fdp);                            // cpuAbi
    WriteBoolField(data, fdp);                                // isReplace
    WriteInt32Field(data, fdp);                               // versionCode
    WriteString16Field(data, fdp);                            // targetPathSuffix
    FinishParcel(data);
    host.HandleExtractQuickFixSoFile(data, reply);
}

enum InstalldMethod {
    FUZZCREATEBUNDLEDIR = 0,
    FUZZREMOVEDIR,
    FUZZEXTRACTMODULEFILES,
    FUZZMOVEFILE,
    FUZZCOPYFILE,
    FUZZMKDIR,
    FUZZSETDIRAPL,
    FUZZDELETECERT,
    FUZZVERIFYCODESIGNATURE,
    FUZZVERIFYCODESIGNATUREFORHAP,
    FUZZDELIVERYSIGNPROFILE,
    FUZZCHECKENCRYPTION,
    FUZZSETENCRYPTIONDIR,
    FUZZDELETEENCRYPTIONKEYID,
    FUZZADDCERTANDENABLEKEY,
    FUZZSTRCPYOVERFLOW,
    FUZZCLEANBUNDLEDATADIR,
    FUZZCLEANBUNDLEDIRS,
    FUZZCLEARDIR,
    FUZZCOPYDIR,
    FUZZRENAMEFILE,
    FUZZRENAMEMODULEDIR,
    FUZZMOVEHAPTOCODEDIR,
    FUZZAPPLYDIFFPATCH,
    FUZZEXTRACTDIFFFILES,
    FUZZREMOVEEXTENSIONDIR,
    FUZZREMOVEBUNDLEDATADIR,
    FUZZISEXISTDIR,
    FUZZISEXISTFILE,
    FUZZSCANDIR,
    FUZZGETBUNDLECACHEPATH,
    FUZZGETDISKUSAGE,
    FUZZMIGRATEDATAINSTALLD,
    FUZZDELETEOLDCACHEFILES,
    FUZZCREATEDATAGROUPDIRS,
    FUZZSETDIRSAPL,
    FUZZCLEANBUNDLEDATADIRBYNAME,
    FUZZHASHSOFILE,
    FUZZHASHFILES,
    FUZZGETFILESTAT,
    FUZZISDIREMPTY,
    FUZZISEXISTAPFILE,
    FUZZISEXISTEXTENSIONDIR,
    FUZZSETFILECONFORCE,
    FUZZSTOPAOT,
    FUZZPENDSIGNAOT,
    FUZZLOADINSTALLS,
    FUZZCHECKEXTERNALSOURCEPLUGINSWITCH,
    FUZZDELETEUNINSTALLTMPDIRS,
    FUZZCHANGEFILESTAT,
    FUZZGETBUNDLESTATS,
    FUZZGETALLBUNDLESTATS,
    FUZZSTOPSETFILECON,
    FUZZADDUSERDIRDELETEDFX,
    FUZZGETTOPNLARGESTITEMS,
    FUZZEXTRACTHNPFILES,
    FUZZCHECKHSPPLUGINCERTVALIDITY,
    FUZZSETARKSTARTUPCACHEAPL,
    FUZZOBTAINQUICKFIXDIR,
    FUZZCREATEBUNDLEDATADIR2,
    FUZZCREATEEXTENSIONDATADIR2,
    FUZZDELETEDATAGROUPDIRS,
    FUZZEXECUTEAOT,
    FUZZEXTRACTFILES,
    FUZZEXTRACTSKILLSPACKAGE,
    FUZZBATCHGETBUNDLESTATS,
    FUZZGETDISKUSAGEFROMPATH,
    FUZZPROCESSBINFILES,
    FUZZPROCESSBUNDLEUNINSTALLNATIVE,
    FUZZREMOVEMODULEDATADIR,
    FUZZRESTORECONPATH,
    FUZZRESETBMSDBSECURITY,
    FUZZGETEXTENSIONSANDBOXTYPELIST,
    FUZZGETBUNDLEINODECOUNT,
    FUZZCOPYFILES,
    FUZZEXTRACTDRIVERSOFILES,
    FUZZMOVEFILES,
    FUZZREMOVESIGNPROFILE,
    FUZZEXTRACTENCRYPTEDSOFILES,
    FUZZGETNATIVELIBRARYFILENAMES,
    FUZZCREATEBUNDLEDATADIRWITHVECTOR,
    FUZZGETCACHEDISKUSAGEFROMPATH,
    FUZZPROCESSBUNDLEINSTALLNATIVE,
    FUZZEXTRACTQUICKFIXSOFILE,
    INSTALLD_METHOD_MAX,
};

// ====== comprehensive fuzz entry ======
bool DoSomethingInterestingWithMyAPI(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return false;
    }

    FuzzedDataProvider fdp(data, size);
    static InstalldHost installdHost;

    // Layer 1: Stub layer
    FuzzIpcStubLoop(installdHost, data, size, CODE_MAX);

    // Layer 2: method layer - 83 methods with precise Parcel construction
    uint8_t methodSelector = fdp.ConsumeIntegral<uint8_t>();
    switch (methodSelector % INSTALLD_METHOD_MAX) {
        case FUZZCREATEBUNDLEDIR: FuzzCreateBundleDir(installdHost, fdp);          break;
        case FUZZREMOVEDIR: FuzzRemoveDir(installdHost, fdp);                break;
        case FUZZEXTRACTMODULEFILES: FuzzExtractModuleFiles(installdHost, fdp);       break;
        case FUZZMOVEFILE: FuzzMoveFile(installdHost, fdp);                 break;
        case FUZZCOPYFILE: FuzzCopyFile(installdHost, fdp);                break;
        case FUZZMKDIR: FuzzMkdir(installdHost, fdp);                   break;
        case FUZZSETDIRAPL: FuzzSetDirApl(installdHost, fdp);               break;
        case FUZZDELETECERT: FuzzDeleteCert(installdHost, fdp);              break;
        case FUZZVERIFYCODESIGNATURE: FuzzVerifyCodeSignature(installdHost, fdp);     break;
        case FUZZVERIFYCODESIGNATUREFORHAP: FuzzVerifyCodeSignatureForHap(installdHost, fdp); break;
        case FUZZDELIVERYSIGNPROFILE: FuzzDeliverySignProfile(installdHost, fdp);     break;
        case FUZZCHECKENCRYPTION: FuzzCheckEncryption(installdHost, fdp);        break;
        case FUZZSETENCRYPTIONDIR: FuzzSetEncryptionDir(installdHost, fdp);       break;
        case FUZZDELETEENCRYPTIONKEYID: FuzzDeleteEncryptionKeyId(installdHost, fdp); break;
        case FUZZADDCERTANDENABLEKEY: FuzzAddCertAndEnableKey(installdHost, fdp);   break;
        case FUZZSTRCPYOVERFLOW: FuzzStrcpyOverflow(installdHost, fdp);        break;
        case FUZZCLEANBUNDLEDATADIR: FuzzCleanBundleDataDir(installdHost, fdp);    break;
        case FUZZCLEANBUNDLEDIRS: FuzzCleanBundleDirs(installdHost, fdp);       break;
        case FUZZCLEARDIR: FuzzClearDir(installdHost, fdp);              break;
        case FUZZCOPYDIR: FuzzCopyDir(installdHost, fdp);              break;
        case FUZZRENAMEFILE: FuzzRenameFile(installdHost, fdp);            break;
        case FUZZRENAMEMODULEDIR: FuzzRenameModuleDir(installdHost, fdp);       break;
        case FUZZMOVEHAPTOCODEDIR: FuzzMoveHapToCodeDir(installdHost, fdp);     break;
        case FUZZAPPLYDIFFPATCH: FuzzApplyDiffPatch(installdHost, fdp);       break;
        case FUZZEXTRACTDIFFFILES: FuzzExtractDiffFiles(installdHost, fdp);     break;
        case FUZZREMOVEEXTENSIONDIR: FuzzRemoveExtensionDir(installdHost, fdp);   break;
        case FUZZREMOVEBUNDLEDATADIR: FuzzRemoveBundleDataDir(installdHost, fdp);  break;
        case FUZZISEXISTDIR: FuzzIsExistDir(installdHost, fdp);           break;
        case FUZZISEXISTFILE: FuzzIsExistFile(installdHost, fdp);         break;
        case FUZZSCANDIR: FuzzScanDir(installdHost, fdp);             break;
        case FUZZGETBUNDLECACHEPATH: FuzzGetBundleCachePath(installdHost, fdp);   break;
        case FUZZGETDISKUSAGE: FuzzGetDiskUsage(installdHost, fdp);        break;
        case FUZZMIGRATEDATAINSTALLD: FuzzMigrateDataInstalld(installdHost, fdp); break;
        case FUZZDELETEOLDCACHEFILES: FuzzDeleteOldCacheFiles(installdHost, fdp); break;
        case FUZZCREATEDATAGROUPDIRS: FuzzCreateDataGroupDirs(installdHost, fdp); break;
        case FUZZSETDIRSAPL: FuzzSetDirsApl(installdHost, fdp);         break;
        case FUZZCLEANBUNDLEDATADIRBYNAME: FuzzCleanBundleDataDirByName(installdHost, fdp); break;
        case FUZZHASHSOFILE: FuzzHashSoFile(installdHost, fdp);          break;
        case FUZZHASHFILES: FuzzHashFiles(installdHost, fdp);          break;
        case FUZZGETFILESTAT: FuzzGetFileStat(installdHost, fdp);         break;
        case FUZZISDIREMPTY: FuzzIsDirEmpty(installdHost, fdp);         break;
        case FUZZISEXISTAPFILE: FuzzIsExistApFile(installdHost, fdp);     break;
        case FUZZISEXISTEXTENSIONDIR: FuzzIsExistExtensionDir(installdHost, fdp); break;
        case FUZZSETFILECONFORCE: FuzzSetFileConForce(installdHost, fdp);   break;
        case FUZZSTOPAOT: FuzzStopAOT(installdHost, fdp);            break;
        case FUZZPENDSIGNAOT: FuzzPendSignAOT(installdHost, fdp);      break;
        case FUZZLOADINSTALLS: FuzzLoadInstalls(installdHost, fdp);     break;
        case FUZZCHECKEXTERNALSOURCEPLUGINSWITCH: FuzzCheckExternalSourcePluginSwitch(installdHost, fdp); break;
        case FUZZDELETEUNINSTALLTMPDIRS: FuzzDeleteUninstallTmpDirs(installdHost, fdp); break;
        case FUZZCHANGEFILESTAT: FuzzChangeFileStat(installdHost, fdp);    break;
        case FUZZGETBUNDLESTATS: FuzzGetBundleStats(installdHost, fdp);    break;
        case FUZZGETALLBUNDLESTATS: FuzzGetAllBundleStats(installdHost, fdp); break;
        case FUZZSTOPSETFILECON: FuzzStopSetFileCon(installdHost, fdp);   break;
        case FUZZADDUSERDIRDELETEDFX: FuzzAddUserDirDeleteDfx(installdHost, fdp); break;
        case FUZZGETTOPNLARGESTITEMS: FuzzGetTopNLargestItems(installdHost, fdp); break;
        case FUZZEXTRACTHNPFILES: FuzzExtractHnpFiles(installdHost, fdp);  break;
        case FUZZCHECKHSPPLUGINCERTVALIDITY: FuzzCheckHspPluginCertValidity(installdHost, fdp); break;
        case FUZZSETARKSTARTUPCACHEAPL: FuzzSetArkStartupCacheApl(installdHost, fdp); break;
        case FUZZOBTAINQUICKFIXDIR: FuzzObtainQuickFixDir(installdHost, fdp); break;
        case FUZZCREATEBUNDLEDATADIR2: FuzzCreateBundleDataDir2(installdHost, fdp);    break;
        case FUZZCREATEEXTENSIONDATADIR2: FuzzCreateExtensionDataDir2(installdHost, fdp); break;
        case FUZZDELETEDATAGROUPDIRS: FuzzDeleteDataGroupDirs(installdHost, fdp);    break;
        case FUZZEXECUTEAOT: FuzzExecuteAOT(installdHost, fdp);       break;
        case FUZZEXTRACTFILES: FuzzExtractFiles(installdHost, fdp);     break;
        case FUZZEXTRACTSKILLSPACKAGE: FuzzExtractSkillsPackage(installdHost, fdp); break;
        case FUZZBATCHGETBUNDLESTATS: FuzzBatchGetBundleStats(installdHost, fdp);  break;
        case FUZZGETDISKUSAGEFROMPATH: FuzzGetDiskUsageFromPath(installdHost, fdp); break;
        case FUZZPROCESSBINFILES: FuzzProcessBinFiles(installdHost, fdp);   break;
        case FUZZPROCESSBUNDLEUNINSTALLNATIVE: FuzzProcessBundleUnInstallNative(installdHost, fdp); break;
        case FUZZREMOVEMODULEDATADIR: FuzzRemoveModuleDataDir(installdHost, fdp);   break;
        case FUZZRESTORECONPATH: FuzzRestoreconPath(installdHost, fdp);    break;
        case FUZZRESETBMSDBSECURITY: FuzzResetBmsDBSecurity(installdHost, fdp);  break;
        case FUZZGETEXTENSIONSANDBOXTYPELIST: FuzzGetExtensionSandboxTypeList(installdHost, fdp); break;
        case FUZZGETBUNDLEINODECOUNT: FuzzGetBundleInodeCount(installdHost, fdp); break;
        case FUZZCOPYFILES: FuzzCopyFiles(installdHost, fdp);          break;
        case FUZZEXTRACTDRIVERSOFILES: FuzzExtractDriverSoFiles(installdHost, fdp); break;
        case FUZZMOVEFILES: FuzzMoveFiles(installdHost, fdp);          break;
        case FUZZREMOVESIGNPROFILE: FuzzRemoveSignProfile(installdHost, fdp); break;
        case FUZZEXTRACTENCRYPTEDSOFILES: FuzzExtractEncryptedSoFiles(installdHost, fdp); break;
        case FUZZGETNATIVELIBRARYFILENAMES: FuzzGetNativeLibraryFileNames(installdHost, fdp); break;
        case FUZZCREATEBUNDLEDATADIRWITHVECTOR: FuzzCreateBundleDataDirWithVector(installdHost, fdp); break;
        case FUZZGETCACHEDISKUSAGEFROMPATH: FuzzGetCacheDiskUsageFromPath(installdHost, fdp); break;
        case FUZZPROCESSBUNDLEINSTALLNATIVE: FuzzProcessBundleInstallNative(installdHost, fdp); break;
        case FUZZEXTRACTQUICKFIXSOFILE: FuzzExtractQuickFixSoFile(installdHost, fdp); break;
    }
    return true;
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyAPI(data, size);
    return 0;
}
