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

#include "pre_compress_handler.h"

#include <cerrno>
#include <cinttypes>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

#include "app_log_tag_wrapper.h"
#include "bundle_service_constants.h"
#include "bundle_util.h"
#include "directory_ex.h"
#include "inner_bundle_info.h"
#include "installd_client.h"
#include "scope_guard.h"
#include "zstd_wrapper.h"

namespace OHOS {
namespace AppExecFwk {
namespace {
constexpr const char* ARCHIVE_SUFFIX = ".zst";
constexpr const char* DECOMPRESS_DIR_TEMPLATE = "pre_compress_XXXXXX";
constexpr mode_t SECURITY_DIR_MODE = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
constexpr int64_t ONE_GB = 1024 * 1024 * 1024;
constexpr int64_t MAX_DECOMPRESSED_SIZE = ONE_GB * 4;
constexpr mode_t DECOMPRESSED_FILE_MODE = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

struct DecompressContext {
    std::string realSrcPath;
    int32_t srcFd = -1;
    int32_t dstFd = -1;
    std::vector<char> inBuf;
    std::vector<char> outBuf;
    ssize_t inLen = 0;
    int64_t sizeCap = 0;
    int64_t written = 0;
    size_t lastRet = 0;
};

std::string GetDecompressedFileName(const std::string &archiveName)
{
    if (!BundleUtil::EndWith(archiveName, ARCHIVE_SUFFIX)) {
        return "";
    }
    std::string fileName = archiveName.substr(0, archiveName.size() - std::strlen(ARCHIVE_SUFFIX));
    if (!BundleUtil::CheckFileType(fileName, ServiceConstants::INSTALL_FILE_SUFFIX) &&
        !BundleUtil::CheckFileType(fileName, ServiceConstants::HSP_FILE_SUFFIX)) {
        return "";
    }
    return fileName;
}

bool WriteAll(int32_t fd, const char *buf, size_t len)
{
    size_t written = 0;
    while (written < len) {
        ssize_t ret = TEMP_FAILURE_RETRY(write(fd, buf + written, len - written));
        if (ret < 0) {
            LOG_NOFUNC_E(BMS_TAG_INSTALLER, "write decompressed data failed");
            return false;
        }
        written += static_cast<size_t>(ret);
    }
    return true;
}

ErrCode CheckDecompressPath(const std::string &srcPath, const std::string &dstPath, std::string &realSrcPath)
{
    if (srcPath.find(ServiceConstants::RELATIVE_PATH) != std::string::npos ||
        dstPath.find(ServiceConstants::RELATIVE_PATH) != std::string::npos) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "relative path is not allowed");
        return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
    }
    if (!PathToRealPath(srcPath, realSrcPath)) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "src path %{public}s is not real path", srcPath.c_str());
        return ERR_APPEXECFWK_INSTALL_FILE_PATH_IS_NOT_REAL;
    }
    if (realSrcPath.compare(0, std::strlen(ServiceConstants::PRELOAD_APP_DIR),
        ServiceConstants::PRELOAD_APP_DIR) != 0) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "%{public}s is outside the preload dir", realSrcPath.c_str());
        return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
    }
    return ERR_OK;
}

ErrCode CheckDecompressedSize(const DecompressContext &ctx)
{
    unsigned long long contentSize =
        ZstdWrapper::GetInstance().GetFrameContentSize(ctx.inBuf.data(), static_cast<size_t>(ctx.inLen));
    if (contentSize == ZSTD_CONTENT_SIZE_ERROR) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "%{public}s is not a valid zstd frame", ctx.realSrcPath.c_str());
        return ERR_APPEXECFWK_INSTALL_DECOMPRESS_APP_FAILED;
    }
    if (contentSize != ZSTD_CONTENT_SIZE_UNKNOWN && contentSize > static_cast<unsigned long long>(ctx.sizeCap)) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "%{public}s decompressed size %{public}llu exceeds cap %{public}" PRId64,
            ctx.realSrcPath.c_str(), contentSize, ctx.sizeCap);
        return ERR_APPEXECFWK_INSTALL_INVALID_HAP_SIZE;
    }
    return ERR_OK;
}

ErrCode DecompressChunk(ZstdDStream *zds, DecompressContext &ctx)
{
    ZstdWrapper &zstd = ZstdWrapper::GetInstance();
    ZstdInBuffer input { ctx.inBuf.data(), static_cast<size_t>(ctx.inLen), 0 };
    while (input.pos < input.size) {
        ZstdOutBuffer output { ctx.outBuf.data(), ctx.outBuf.size(), 0 };
        ctx.lastRet = zstd.DecompressStream(zds, &output, &input);
        if (zstd.IsError(ctx.lastRet)) {
            LOG_NOFUNC_E(BMS_TAG_INSTALLER, "decompress %{public}s failed : %{public}s",
                ctx.realSrcPath.c_str(), zstd.GetErrorName(ctx.lastRet));
            return ERR_APPEXECFWK_INSTALL_DECOMPRESS_APP_FAILED;
        }
        ctx.written += static_cast<int64_t>(output.pos);
        if (ctx.written > ctx.sizeCap) {
            LOG_NOFUNC_E(BMS_TAG_INSTALLER, "%{public}s decompressed size exceeds cap %{public}" PRId64,
                ctx.realSrcPath.c_str(), ctx.sizeCap);
            return ERR_APPEXECFWK_INSTALL_INVALID_HAP_SIZE;
        }
        if (!WriteAll(ctx.dstFd, ctx.outBuf.data(), output.pos)) {
            return ERR_APPEXECFWK_INSTALL_DECOMPRESS_APP_FAILED;
        }
    }
    return ERR_OK;
}

ErrCode DecompressAllChunks(DecompressContext &ctx)
{
    auto zds = ZstdWrapper::GetInstance().CreateDStream();
    if (zds == nullptr) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "create zstd dstream failed");
        return ERR_APPEXECFWK_INSTALL_DECOMPRESS_APP_FAILED;
    }

    while (ctx.inLen > 0) {
        ErrCode result = DecompressChunk(zds.get(), ctx);
        if (result != ERR_OK) {
            return result;
        }
        ctx.inLen = TEMP_FAILURE_RETRY(read(ctx.srcFd, ctx.inBuf.data(), ctx.inBuf.size()));
    }
    if (ctx.inLen < 0) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "read %{public}s failed", ctx.realSrcPath.c_str());
        return ERR_APPEXECFWK_INSTALL_ACCESS_FILE_FAILED;
    }
    if (ctx.lastRet != 0) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "%{public}s ends with an incomplete zstd frame", ctx.realSrcPath.c_str());
        return ERR_APPEXECFWK_INSTALL_DECOMPRESS_APP_FAILED;
    }
    return ERR_OK;
}

ErrCode WriteDecompressedFile(DecompressContext &ctx, const std::string &dstPath)
{
    ctx.dstFd = open(dstPath.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, DECOMPRESSED_FILE_MODE);
    if (ctx.dstFd < 0) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "create %{public}s failed", dstPath.c_str());
        return ERR_APPEXECFWK_INSTALL_ACCESS_FILE_FAILED;
    }
    fdsan_exchange_owner_tag(ctx.dstFd, 0, BMS_FDSAN_TEMP_TAG);
    ScopeGuard dstFdGuard([&ctx] { fdsan_close_with_tag(ctx.dstFd, BMS_FDSAN_TEMP_TAG); });
    return DecompressAllChunks(ctx);
}

ErrCode DecompressFile(const std::string &srcPath, const std::string &dstPath, int64_t &totalSize)
{
    DecompressContext ctx;
    ctx.sizeCap = MAX_DECOMPRESSED_SIZE - totalSize;
    ErrCode result = CheckDecompressPath(srcPath, dstPath, ctx.realSrcPath);
    if (result != ERR_OK) {
        return result;
    }

    ctx.srcFd = open(ctx.realSrcPath.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (ctx.srcFd < 0) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "open %{public}s failed", ctx.realSrcPath.c_str());
        return ERR_APPEXECFWK_INSTALL_ACCESS_FILE_FAILED;
    }
    fdsan_exchange_owner_tag(ctx.srcFd, 0, BMS_FDSAN_TEMP_TAG);
    ScopeGuard srcFdGuard([&ctx] { fdsan_close_with_tag(ctx.srcFd, BMS_FDSAN_TEMP_TAG); });

    ZstdWrapper &zstd = ZstdWrapper::GetInstance();
    ctx.inBuf.resize(zstd.DStreamInSize());
    ctx.outBuf.resize(zstd.DStreamOutSize());
    ctx.inLen = TEMP_FAILURE_RETRY(read(ctx.srcFd, ctx.inBuf.data(), ctx.inBuf.size()));
    if (ctx.inLen <= 0) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "read %{public}s failed", ctx.realSrcPath.c_str());
        return ERR_APPEXECFWK_INSTALL_ACCESS_FILE_FAILED;
    }
    result = CheckDecompressedSize(ctx);
    if (result != ERR_OK) {
        return result;
    }
    result = WriteDecompressedFile(ctx, dstPath);
    totalSize += ctx.written;
    return result;
}

std::string CreateDecompressTempDir()
{
    // the decompressed haps are consumed by installd and the code signature check, so stage them in the
    // security dir as CopyHapsToSecurityDir does, never in stream_install which holds caller written files
    std::string securityDir = std::string(ServiceConstants::HAP_COPY_PATH) + ServiceConstants::PATH_SEPARATOR +
        ServiceConstants::SECURITY_STREAM_INSTALL_PATH;
    CreateDirParam createDirParam;
    createDirParam.bundleDirScene = BundleDirScene::SERVICE_BMS_SECURITY_STREAM_INSTALL_DIR;
    ErrCode ret = InstalldClient::GetInstance()->Mkdir(securityDir, SECURITY_DIR_MODE,
        Constants::FOUNDATION_UID, ServiceConstants::BMS_GID, createDirParam);
    if (ret != ERR_OK) {
        LOG_NOFUNC_W(BMS_TAG_INSTALLER, "installd mkdir %{public}s failed %{public}d", securityDir.c_str(), ret);
    }
    std::string tempDir = securityDir + ServiceConstants::PATH_SEPARATOR + DECOMPRESS_DIR_TEMPLATE;
    if (mkdtemp(tempDir.data()) == nullptr) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "mkdtemp %{public}s failed errno:%{public}d", tempDir.c_str(), errno);
        return "";
    }
    if (BundleUtil::CreateTempDir(tempDir).empty()) {
        BundleUtil::DeleteDir(tempDir);
        return "";
    }
    return tempDir + ServiceConstants::PATH_SEPARATOR;
}

ErrCode DecompressArchives(const std::vector<std::string> &archives, std::vector<std::string> &hapPaths,
    std::vector<std::string> &toDeletePaths, std::unordered_map<std::string, std::string> &sourceMap)
{
    auto lease = ZstdWrapper::GetInstance().Acquire();
    if (lease == nullptr) {
        return ERR_APPEXECFWK_INSTALL_DECOMPRESS_APP_FAILED;
    }
    std::string tempDir = CreateDecompressTempDir();
    if (tempDir.empty()) {
        return ERR_APPEXECFWK_INSTALL_COPY_HAP_FAILED;
    }
    toDeletePaths.emplace_back(tempDir);

    int64_t totalSize = 0;
    for (const auto &archive : archives) {
        std::string fileName =
            GetDecompressedFileName(archive.substr(archive.rfind(ServiceConstants::FILE_SEPARATOR_CHAR) + 1));
        if (fileName.empty()) {
            LOG_NOFUNC_E(BMS_TAG_INSTALLER, "invalid compressed archive name %{public}s", archive.c_str());
            return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
        }
        std::string hapPath = tempDir + fileName;
        ErrCode result = DecompressFile(archive, hapPath, totalSize);
        if (result != ERR_OK) {
            return result;
        }
        hapPaths.emplace_back(hapPath);
        std::string realHapPath;
        sourceMap[PathToRealPath(hapPath, realHapPath) ? realHapPath : hapPath] = archive;
    }
    LOG_NOFUNC_I(BMS_TAG_INSTALLER, "decompressed %{public}zu preinstall archives", hapPaths.size());
    return ERR_OK;
}
}  // namespace

bool PreCompressHandler::IsCompressedArchive(const std::string &path)
{
    return !GetDecompressedFileName(path).empty();
}

ErrCode PreCompressHandler::GetCompressedArchivesFromBundlePath(
    const std::string &currentBundlePath, std::vector<std::string> &archiveList)
{
    DIR* dir = opendir(currentBundlePath.c_str());
    if (dir == nullptr) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "open bundle dir:%{public}s failed", currentBundlePath.c_str());
        return ERR_APPEXECFWK_INSTALL_OPENDIR_FAILED;
    }
    ScopeGuard dirGuard([dir] { closedir(dir); });

    std::string bundlePath = currentBundlePath;
    if (bundlePath.back() != ServiceConstants::FILE_SEPARATOR_CHAR) {
        bundlePath.append(ServiceConstants::PATH_SEPARATOR);
    }
    struct dirent *entry = nullptr;
    while ((entry = readdir(dir)) != nullptr) {
        const std::string filePath = bundlePath + entry->d_name;
        if (BundleUtil::EndWith(filePath, ServiceConstants::INSTALL_FILE_SUFFIX) ||
            BundleUtil::EndWith(filePath, ServiceConstants::HSP_FILE_SUFFIX)) {
            LOG_NOFUNC_E(BMS_TAG_INSTALLER, "%{public}s is not compressed, mixed packages are not allowed",
                filePath.c_str());
            return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
        }
        if (!IsCompressedArchive(filePath)) {
            continue;
        }
        std::string realPath;
        if (!PathToRealPath(filePath, realPath)) {
            LOG_NOFUNC_E(BMS_TAG_INSTALLER, "find invalid archive path %{public}s", filePath.c_str());
            continue;
        }
        archiveList.emplace_back(realPath);
    }
    return ERR_OK;
}

ErrCode PreCompressHandler::PrepareCompressedPaths(const std::vector<std::string> &inPaths,
    std::vector<std::string> &outPaths, std::vector<std::string> &toDeletePaths,
    std::unordered_map<std::string, std::string> &sourceMap)
{
    std::vector<std::string> archives;
    for (const auto &path : inPaths) {
        if (!BundleUtil::IsExistDirNoLog(path)) {
            archives.emplace_back(path);
            continue;
        }
        ErrCode result = GetCompressedArchivesFromBundlePath(path, archives);
        if (result != ERR_OK) {
            return result;
        }
    }
    if (archives.empty()) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "no compressed archive found in the preload paths");
        return ERR_APPEXECFWK_INSTALL_FILE_PATH_INVALID;
    }
    return DecompressArchives(archives, outPaths, toDeletePaths, sourceMap);
}

bool PreCompressHandler::PrepareScanPaths(const std::string &scanPath, bool isCompressed,
    std::vector<std::string> &realPaths, std::vector<std::string> &tempDirs,
    std::unordered_map<std::string, std::string> &sourceMap)
{
    std::vector<std::string> scanPathVec { scanPath };
    ErrCode result = isCompressed ? PrepareCompressedPaths(scanPathVec, realPaths, tempDirs, sourceMap) :
        BundleUtil::CheckFilePath(scanPathVec, realPaths);
    if (result != ERR_OK) {
        LOG_NOFUNC_E(BMS_TAG_DEFAULT, "prepare scan path %{public}s failed %{public}d", scanPath.c_str(), result);
        return false;
    }
    return !realPaths.empty();
}

void PreCompressHandler::RekeyInfosToSource(const std::unordered_map<std::string, std::string> &sourceMap,
    std::unordered_map<std::string, InnerBundleInfo> &infos)
{
    for (const auto &[tempPath, sourcePath] : sourceMap) {
        auto node = infos.extract(tempPath);
        if (node.empty()) {
            continue;
        }
        node.key() = sourcePath;
        infos.insert(std::move(node));
    }
}

ErrCode PreCompressHandler::StageAgConfigFile(const std::unordered_map<std::string, std::string> &sourceMap,
    std::string &stagedPath)
{
    if (sourceMap.empty()) {
        return ERR_OK;
    }
    const auto &[tempPath, archivePath] = *sourceMap.begin();
    std::string configPath = archivePath.substr(0, archivePath.rfind(ServiceConstants::FILE_SEPARATOR_CHAR) + 1) +
        ServiceConstants::AG_CONFIG_FILE;
    if (!BundleUtil::IsExistFileNoLog(configPath)) {
        return ERR_OK;
    }
    std::string targetPath = tempPath.substr(0, tempPath.rfind(ServiceConstants::FILE_SEPARATOR_CHAR) + 1) +
        ServiceConstants::AG_CONFIG_FILE;
    if (!BundleUtil::CopyFileFast(configPath, targetPath)) {
        LOG_NOFUNC_E(BMS_TAG_INSTALLER, "copy %{public}s failed", configPath.c_str());
        return ERR_APPEXECFWK_INSTALL_COPY_HAP_FAILED;
    }
    stagedPath = targetPath;
    return ERR_OK;
}

ScopedDecompressedHap::ScopedDecompressedHap(const std::string &path)
{
    if (!PreCompressHandler::IsCompressedArchive(path)) {
        hapPath_ = path;
        valid_ = true;
        return;
    }
    std::vector<std::string> hapPaths;
    std::unordered_map<std::string, std::string> sourceMap;
    if (PreCompressHandler::PrepareCompressedPaths({path}, hapPaths, toDeletePaths_, sourceMap) != ERR_OK) {
        return;
    }
    hapPath_ = hapPaths.front();
    valid_ = true;
}

ScopedDecompressedHap::~ScopedDecompressedHap()
{
    BundleUtil::DeleteTempDirs(toDeletePaths_);
}
}  // namespace AppExecFwk
}  // namespace OHOS
