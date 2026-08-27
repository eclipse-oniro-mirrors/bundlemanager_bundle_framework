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

#ifndef BMS_INSTALLD_FUZZTEST_UTIL_H
#define BMS_INSTALLD_FUZZTEST_UTIL_H

#include "aot/aot_args.h"
#include "bms_fuzztest_util.h"
#include "check_encryption_param.h"
#include "code_signature_param.h"
#include "create_dir_param.h"
#include "encryption_param.h"
#include "extract_param.h"
#include "install_hnp_param.h"
#include "skills_package_param.h"
#include "verify_bin_param.h"

namespace OHOS {
namespace AppExecFwk {
namespace BMSFuzzTestUtil {
// InstallHnpParam: 7 fields, native install parameter
inline void GenerateInstallHnpParam(FuzzedDataProvider& fdp, InstallHnpParam& p)
{
    p.userId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    p.hnpRootPath = GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL);
    p.hapPath = GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL);
    p.cpuAbi = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    p.packageName = GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL);
    p.appIdentifier = GenAttackAwareString(fdp, ATTACK_CERT_BYPASS);
    p.hnpPaths = GenerateStringArray(fdp);
}

// CreateDirParam: full field coverage with attack vector injection
// Used by HandleMkdir/HandleCreateBundleDataDir/HandleCreateDataGroupDirs/etc.
inline void GenerateCreateDirParam(FuzzedDataProvider& fdp, CreateDirParam& d)
{
    d.bundleName = GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL);
    d.apl = GenAttackAwareString(fdp, ATTACK_SELINUX);
    d.uuid = GenAttackAwareString(fdp, ATTACK_CERT_BYPASS);
    d.userId = GenerateRandomUser(fdp);
    d.uid = fdp.ConsumeIntegral<int32_t>();
    d.gid = fdp.ConsumeIntegral<int32_t>();
    d.appIndex = fdp.ConsumeIntegral<int32_t>();
    d.dlpType = fdp.ConsumeIntegral<int32_t>();
    d.isPreInstallApp = fdp.ConsumeBool();
    d.debug = fdp.ConsumeBool();
    d.isDlpSandbox = fdp.ConsumeBool();
    d.isExtensionDir = fdp.ConsumeBool();
    d.isContainsEl5Dir = fdp.ConsumeBool();
    d.hasInputMethodExtension = fdp.ConsumeBool();
    d.createDirFlag = static_cast<CreateDirFlag>(fdp.ConsumeIntegral<uint8_t>() % CREATE_DIR_FLAG_COUNT);
    d.dataDirEl = static_cast<DataDirEl>(fdp.ConsumeIntegral<uint8_t>() % DATA_DIR_EL_COUNT);
    d.bundleDirScene = static_cast<BundleDirScene>(fdp.ConsumeIntegral<int32_t>());
}

// ExtractParam: 7 fields
inline void GenerateExtractParam(FuzzedDataProvider& fdp, ExtractParam& p)
{
    p.bundleName = GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL);
    p.srcPath = GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL);
    p.targetPath = GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL);
    p.cpuAbi = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    p.needRemoveOld = fdp.ConsumeBool();
    p.needFakeDecompression = fdp.ConsumeBool();
    p.isSystemApp = fdp.ConsumeBool();
}

// SkillsPackageParam: 5 fields + vector
inline void GenerateSkillsPackageParam(FuzzedDataProvider& fdp, SkillsPackageParam& p)
{
    p.bundleName = GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL);
    p.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    p.extractModuleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    p.hspPath = GenAttackAwareString(fdp, ATTACK_ARCHIVE);
    p.skillNameList = GenerateStringArray(fdp);
}

// VerifyBinParam: 4 fields
inline void GenerateVerifyBinParam(FuzzedDataProvider& fdp, VerifyBinParam& p)
{
    p.bundleName = GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL);
    p.appIdentifier = GenAttackAwareString(fdp, ATTACK_CERT_BYPASS);
    p.userId = GenerateRandomUser(fdp);
    p.binFilePaths = GenerateStringArray(fdp);
}

// HspInfo: 7 fields
inline void GenerateHspInfo(FuzzedDataProvider& fdp, HspInfo& h)
{
    h.versionCode = fdp.ConsumeIntegral<uint32_t>();
    h.offset = fdp.ConsumeIntegral<uint32_t>();
    h.length = fdp.ConsumeIntegral<uint32_t>();
    h.bundleName = GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL);
    h.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    h.hapPath = GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL);
    h.moduleArkTSMode = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
}

// AOTArgs: 7 fields
inline void GenerateAOTArgs(FuzzedDataProvider& fdp, AOTArgs& a)
{
    a.bundleType = fdp.ConsumeIntegral<uint8_t>();
    a.triggerType = fdp.ConsumeIntegral<uint8_t>();
    a.staticAndHybridModuleCnt = fdp.ConsumeIntegral<uint32_t>();
    a.offset = fdp.ConsumeIntegral<uint32_t>();
    a.length = fdp.ConsumeIntegral<uint32_t>();
    a.isEncryptedBundle = fdp.ConsumeIntegral<uint32_t>();
    a.isScreenOff = fdp.ConsumeIntegral<uint32_t>();
    a.isEnableBaselinePgo = fdp.ConsumeIntegral<uint32_t>();
    a.bundleUid = fdp.ConsumeIntegral<int32_t>();
    a.bundleGid = fdp.ConsumeIntegral<int32_t>();
    a.bundleName = GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL);
    a.moduleName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    a.compileMode = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    a.hapPath = GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL);
    a.coreLibPath = GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL);
    a.outputPath = GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL);
    a.arkProfilePath = GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL);
    a.anFileName = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    a.appIdentifier = GenAttackAwareString(fdp, ATTACK_CERT_BYPASS);
    a.hostBundleName = GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL);
    a.optBCRangeList = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    a.moduleArkTSMode = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    a.hspVector.clear();
    size_t hspSize = fdp.ConsumeIntegralInRange<size_t>(0, ARRAY_MAX_LENGTH);
    a.hspVector.reserve(hspSize);
    for (size_t i = 0; i < hspSize; ++i) {
        HspInfo h;
        GenerateHspInfo(fdp, h);
        a.hspVector.emplace_back(std::move(h));
    }
    a.isSysComp = fdp.ConsumeBool();
    a.sysCompPath = GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL);
}

// CodeSignatureParam: 15fields，signature verification core struct
inline void GenerateCodeSignatureParam(FuzzedDataProvider& fdp, CodeSignatureParam& p)
{
    p.isEnterpriseBundle = fdp.ConsumeBool();
    p.isEnterpriseResigned = fdp.ConsumeBool();
    p.isPreInstalledBundle = fdp.ConsumeBool();
    p.isCompileSdkOpenHarmony = fdp.ConsumeBool();
    p.isInternaltestingBundle = fdp.ConsumeBool();
    p.isCompressNativeLibrary = fdp.ConsumeBool();
    p.isPlugin = fdp.ConsumeBool();
    p.isDeveloperDistribution = fdp.ConsumeBool();
    p.bundleName = GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL);
    p.modulePath = GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL);
    p.cpuAbi = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    p.targetSoPath = GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL);
    p.signatureFileDir = GenAttackAwareString(fdp, ATTACK_CERT_BYPASS);
    p.appIdentifier = GenAttackAwareString(fdp, ATTACK_CERT_BYPASS);
    p.pluginId = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    p.profileBlockLength = fdp.ConsumeIntegral<uint32_t>() % PROFILE_BLOCK_MAX_SIZE;
}

// CheckEncryptionParam: 9fields，encryption check core struct
inline void GenerateCheckEncryptionParam(FuzzedDataProvider& fdp, CheckEncryptionParam& p)
{
    p.installBundleType = static_cast<InstallBundleType>(fdp.ConsumeIntegral<uint8_t>() % CODE_MAX_FOUR);
    p.isCompressNativeLibrary = fdp.ConsumeBool();
    p.versionCode = fdp.ConsumeIntegral<uint32_t>();
    p.appIdentifier = GenAttackAwareString(fdp, ATTACK_CERT_BYPASS);
    p.bundleName = GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL);
    p.modulePath = GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL);
    p.cpuAbi = fdp.ConsumeRandomLengthString(STRING_MAX_LENGTH);
    p.targetSoPath = GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL);
    p.bundleId = fdp.ConsumeIntegral<int32_t>();
}

// EncryptionParam: 4fields，encryption dir operation core struct
inline void GenerateEncryptionParam(FuzzedDataProvider& fdp, EncryptionParam& p)
{
    p.bundleName = GenAttackAwareString(fdp, ATTACK_PATH_TRAVERSAL);
    p.groupId = GenAttackAwareString(fdp, ATTACK_CERT_BYPASS);
    p.uid = fdp.ConsumeIntegral<int32_t>();
    p.userId = GenerateRandomUser(fdp);
}

}  // namespace BMSFuzzTestUtil
}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // BMS_INSTALLD_FUZZTEST_UTIL_H
