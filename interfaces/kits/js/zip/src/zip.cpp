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
#include "zip.h"

#include <fcntl.h>
#include <list>
#include <stdio.h>
#include <string>
#include <unistd.h>
#include <vector>

#include "app_log_wrapper.h"
#include "appexecfwk_errors.h"
#include "bundle_errors.h"
#include "directory_ex.h"
#include "event_handler.h"
#include "file_path.h"
#include "zip_internal.h"
#include "zip_reader.h"
#include "zip_writer.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {
namespace {
using FilterCallback = std::function<bool(const FilePath &)>;
using DirectoryCreator = std::function<bool(FilePath &, FilePath &)>;
using WriterFactory = std::function<std::unique_ptr<WriterDelegate>(FilePath &, FilePath &)>;

const std::string SEPARATOR = "/";
const char HIDDEN_SEPARATOR = '.';
const std::string ZIP = ".zip";

struct UnzipParam {
    FilterCallback filterCB = nullptr;
    bool logSkippedFiles = false;
};
bool IsHiddenFile(const FilePath &filePath)
{
    FilePath localFilePath = filePath;
    if (!localFilePath.Value().empty()) {
        return localFilePath.Value().c_str()[0] == HIDDEN_SEPARATOR;
    } else {
        return false;
    }
}
bool ExcludeNoFilesFilter(const FilePath &filePath)
{
    return true;
}

bool ExcludeHiddenFilesFilter(const FilePath &filePath)
{
    return !IsHiddenFile(filePath);
}

std::vector<FileAccessor::DirectoryContentEntry> ListDirectoryContent(const FilePath &filePath, bool& isSuccess)
{
    FilePath curPath = filePath;
    std::vector<FileAccessor::DirectoryContentEntry> fileDirectoryVector;
    std::vector<std::string> filelist;
    isSuccess = FilePath::GetZipAllDirFiles(curPath.Value(), filelist);
    if (isSuccess) {
        APP_LOGD("ListDirectoryContent filelist =====filelist.size=%{public}zu====", filelist.size());
        for (size_t i = 0; i < filelist.size(); i++) {
            std::string str(filelist[i]);
            if (!str.empty()) {
                fileDirectoryVector.push_back(
                    FileAccessor::DirectoryContentEntry(FilePath(str), FilePath::DirectoryExists(FilePath(str))));
            }
        }
    }
    return fileDirectoryVector;
}

// Creates a directory at |extractDir|/|entryPath|, including any parents.
bool CreateDirectory(FilePath &extractDir, FilePath &entryPath)
{
    std::string path = extractDir.Value();
    if (EndsWith(path, SEPARATOR)) {
        return FilePath::CreateDirectory(FilePath(extractDir.Value() + entryPath.Value()));
    } else {
        return FilePath::CreateDirectory(FilePath(extractDir.Value() + "/" + entryPath.Value()));
    }
}

// Creates a WriterDelegate that can write a file at |extractDir|/|entryPath|.
std::unique_ptr<WriterDelegate> CreateFilePathWriterDelegate(FilePath &extractDir, FilePath entryPath)
{
    if (EndsWith(extractDir.Value(), SEPARATOR)) {
        return std::make_unique<FilePathWriterDelegate>(FilePath(extractDir.Value() + entryPath.Value()));
    } else {
        return std::make_unique<FilePathWriterDelegate>(FilePath(extractDir.Value() + "/" + entryPath.Value()));
    }
}
}  // namespace

ZipParams::ZipParams(const std::vector<FilePath>& srcDir, const FilePath& destFile)
    : srcDir_(srcDir), destFile_(destFile)
{}

// Does not take ownership of |fd|.
ZipParams::ZipParams(const std::vector<FilePath> &srcDir, int destFd) : srcDir_(srcDir), destFd_(destFd)
{}

FilePath FilePathEndIsSeparator(FilePath paramPath)
{
    bool endIsSeparator = EndsWith(paramPath.Value(), SEPARATOR);
    if (FilePath::IsDir(paramPath)) {
        if (!endIsSeparator) {
            paramPath.AppendSeparator();
        }
    }
    return paramPath;
}

bool Zip(const ZipParams &params, const OPTIONS &options)
{
    const std::vector<std::pair<FilePath, FilePath>> *filesToAdd = &params.GetFilesTozip();
    std::vector<std::pair<FilePath, FilePath>> allRelativeFiles;
    FilePath srcDir = params.SrcDir().front();
    FilePath paramPath = FilePathEndIsSeparator(srcDir);
    if (filesToAdd->empty()) {
        filesToAdd = &allRelativeFiles;
        std::list<FileAccessor::DirectoryContentEntry> entries;
        if (EndsWith(paramPath.Value(), SEPARATOR)) {
            entries.push_back(FileAccessor::DirectoryContentEntry(srcDir, true));
            FilterCallback filterCallback = params.GetFilterCallback();
            for (auto iter = entries.begin(); iter != entries.end(); ++iter) {
                if (iter != entries.begin() && ((!params.GetIncludeHiddenFiles() && IsHiddenFile(iter->path)) ||
                    (filterCallback && !filterCallback(iter->path)))) {
                    continue;
                }
                if (iter != entries.begin()) {
                    FilePath relativePath;
                    FilePath paramsSrcPath = srcDir;
                    if (paramsSrcPath.AppendRelativePath(iter->path, &relativePath)) {
                        allRelativeFiles.push_back(std::make_pair(relativePath, iter->path));
                    }
                }
                if (iter->isDirectory) {
                    bool isSuccess = false;
                    std::vector<FileAccessor::DirectoryContentEntry> subEntries =
                        ListDirectoryContent(iter->path, isSuccess);
                    entries.insert(entries.end(), subEntries.begin(), subEntries.end());
                }
            }
        } else {
            allRelativeFiles.push_back(std::make_pair(paramPath.BaseName(), paramPath));
        }
    }
    std::unique_ptr<ZipWriter> zipWriter = nullptr;
    if (params.DestFd() != kInvalidPlatformFile) {
        zipWriter = std::make_unique<ZipWriter>(ZipWriter::InitZipFileWithFd(params.DestFd()));
    } else {
        zipWriter = std::make_unique<ZipWriter>(ZipWriter::InitZipFileWithFile(params.DestFile()));
    }
    if (zipWriter == nullptr) {
        APP_LOGE("Init zipWriter failed!");
        return false;
    }
    return zipWriter->WriteEntries(*filesToAdd, options);
}

void GetZipsAllRelativeFilesInner(const ZipParams &params, const FilePath &iterPath,
    std::list<FileAccessor::DirectoryContentEntry> &entries,
    std::vector<std::pair<FilePath, FilePath>> &allRelativeFiles)
{
    FilterCallback filterCallback = params.GetFilterCallback();
    for (auto iter = entries.begin(); iter != entries.end(); ++iter) {
        if (iter != entries.begin() && ((!params.GetIncludeHiddenFiles() && IsHiddenFile(iter->path)) ||
            (filterCallback && !filterCallback(iter->path)))) {
            continue;
        }
        if (iter != entries.begin()) {
            FilePath relativePath;
            FilePath paramsSrcPath = iterPath;
            if (paramsSrcPath.AppendRelativePath(iter->path, &relativePath)) {
                allRelativeFiles.push_back(std::make_pair(relativePath, iter->path));
            }
        }
        if (iter->isDirectory) {
            bool isSuccess = false;
            std::vector<FileAccessor::DirectoryContentEntry> subEntries = ListDirectoryContent(iter->path, isSuccess);
            entries.insert(entries.end(), subEntries.begin(), subEntries.end());
        }
    }
}

void GetZipsAllRelativeFiles(const ZipParams &params, std::vector<std::pair<FilePath, FilePath>> &allRelativeFiles,
    std::vector<FilePath> &srcFiles)
{
    std::list<FileAccessor::DirectoryContentEntry> entries;
    for (auto iterPath = srcFiles.begin(); iterPath != srcFiles.end(); ++iterPath) {
        FilePath paramPath = FilePathEndIsSeparator(*iterPath);
        if (!EndsWith(paramPath.Value(), SEPARATOR)) {
            allRelativeFiles.push_back(std::make_pair(paramPath.BaseName(), paramPath));
            continue;
        }
        entries.clear();
        entries.push_back(FileAccessor::DirectoryContentEntry(*iterPath, true));
        GetZipsAllRelativeFilesInner(params, *iterPath, entries, allRelativeFiles);
    }
}

bool Zips(const ZipParams &params, const OPTIONS &options)
{
    const std::vector<std::pair<FilePath, FilePath>> *filesToAdd = &params.GetFilesTozip();
    std::vector<std::pair<FilePath, FilePath>> allRelativeFiles;
    std::vector<FilePath> srcFiles = params.SrcDir();
    if (filesToAdd->empty()) {
        filesToAdd = &allRelativeFiles;
        GetZipsAllRelativeFiles(params, allRelativeFiles, srcFiles);
    }
    std::unique_ptr<ZipWriter> zipWriter = nullptr;
    if (params.DestFd() != kInvalidPlatformFile) {
        zipWriter = std::make_unique<ZipWriter>(ZipWriter::InitZipFileWithFd(params.DestFd()));
    } else {
        zipWriter = std::make_unique<ZipWriter>(ZipWriter::InitZipFileWithFile(params.DestFile()));
    }
    if (zipWriter == nullptr) {
        APP_LOGE("Init zipWriter failed!");
        return false;
    }
    return zipWriter->WriteEntries(*filesToAdd, options);
}

ErrCode UnzipWithFilterAndWriters(const PlatformFile &srcFile, FilePath &destDir, WriterFactory writerFactory,
    DirectoryCreator directoryCreator, UnzipParam &unzipParam)
{
    APP_LOGD("%{public}s called, destDir=%{private}s", __func__, destDir.Value().c_str());
    ZipReader reader;
    if (!reader.OpenFromPlatformFile(srcFile)) {
        APP_LOGI("%{public}s called, Failed to open srcFile.", __func__);
        return ERR_ZLIB_SRC_FILE_FORMAT_ERROR;
    }
    while (reader.HasMore()) {
        if (!reader.OpenCurrentEntryInZip()) {
            APP_LOGI("%{public}s called, Failed to open the current file in zip.", __func__);
            return ERR_ZLIB_SERVICE_DISABLED;
        }
        const FilePath &constEntryPath = reader.CurrentEntryInfo()->GetFilePath();
        FilePath entryPath = constEntryPath;
        if (reader.CurrentEntryInfo()->IsUnsafe()) {
            APP_LOGI("%{public}s called, Found an unsafe file in zip.", __func__);
            return ERR_ZLIB_SERVICE_DISABLED;
        }
        // callback
        if (unzipParam.filterCB(entryPath)) {
            if (reader.CurrentEntryInfo()->IsDirectory()) {
                if (!directoryCreator(destDir, entryPath)) {
                    APP_LOGI("!!!directory_creator(%{private}s) Failed!!!.", entryPath.Value().c_str());
                    return ERR_ZLIB_DEST_FILE_DISABLED;
                }
            } else {
                std::unique_ptr<WriterDelegate> writer = writerFactory(destDir, entryPath);
                if (!reader.ExtractCurrentEntry(writer.get(), std::numeric_limits<uint64_t>::max())) {
                    APP_LOGI("%{public}s called, Failed to extract.", __func__);
                    return ERR_ZLIB_SERVICE_DISABLED;
                }
            }
        } else if (unzipParam.logSkippedFiles) {
            APP_LOGI("%{public}s called, Skipped file.", __func__);
        }

        if (!reader.AdvanceToNextEntry()) {
            APP_LOGI("%{public}s called, Failed to advance to the next file.", __func__);
            return ERR_ZLIB_SERVICE_DISABLED;
        }
    }
    return ERR_OK;
}

ErrCode UnzipWithFilterCallback(
    const FilePath &srcFile, const FilePath &destDir, const OPTIONS &options, UnzipParam &unzipParam)
{
    FilePath src = srcFile;
    if (!FilePathCheckValid(src.Value())) {
        APP_LOGI("%{public}s called, FilePathCheckValid returnValue is false.", __func__);
        return ERR_ZLIB_SRC_FILE_DISABLED;
    }

    FilePath dest = destDir;

    APP_LOGD("%{public}s called,  srcFile=%{private}s, destFile=%{private}s",
        __func__,
        src.Value().c_str(),
        dest.Value().c_str());

    if (!FilePath::PathIsValid(srcFile)) {
        APP_LOGI("%{public}s called,PathIsValid return value is false.", __func__);
        return ERR_ZLIB_SRC_FILE_DISABLED;
    }

    PlatformFile zipFd = open(src.Value().c_str(), S_IREAD, O_CREAT);
    if (zipFd == kInvalidPlatformFile) {
        APP_LOGI("%{public}s called, Failed to open.", __func__);
        return ERR_ZLIB_SRC_FILE_DISABLED;
    }
    ErrCode ret = UnzipWithFilterAndWriters(zipFd,
        dest,
        std::bind(&CreateFilePathWriterDelegate, std::placeholders::_1, std::placeholders::_2),
        std::bind(&CreateDirectory, std::placeholders::_1, std::placeholders::_2),
        unzipParam);
    close(zipFd);
    return ret;
}

bool Unzip(const std::string &srcFile, const std::string &destFile, OPTIONS options,
    std::shared_ptr<ZlibCallbackInfo> zlibCallbackInfo)
{
    if (zlibCallbackInfo == nullptr) {
        APP_LOGE("zlibCallbackInfo is nullptr!");
        return false;
    }
    FilePath srcFileDir(srcFile);
    FilePath destDir(destFile);
    if (destDir.Value().size() == 0) {
        zlibCallbackInfo->OnZipUnZipFinish(ERR_ZLIB_DEST_FILE_DISABLED);
        return false;
    }
    if (srcFileDir.Value().size() == 0) {
        APP_LOGI("%{public}s called fail, srcFile isn't Exist.", __func__);
        zlibCallbackInfo->OnZipUnZipFinish(ERR_ZLIB_SRC_FILE_DISABLED);
        return false;
    }
    if (!FilePath::PathIsValid(srcFileDir)) {
        APP_LOGI("%{public}s called fail, srcFile isn't Exist.", __func__);
        zlibCallbackInfo->OnZipUnZipFinish(ERR_ZLIB_SRC_FILE_DISABLED);
        return false;
    }
    if (FilePath::DirectoryExists(destDir)) {
        if (!FilePath::PathIsWriteable(destDir)) {
            APP_LOGI("%{public}s called, FilePath::PathIsWriteable(destDir) fail.", __func__);
            zlibCallbackInfo->OnZipUnZipFinish(ERR_ZLIB_DEST_FILE_DISABLED);
            return false;
        }
    } else {
        APP_LOGI("%{public}s called fail, destDir isn't path.", __func__);
        zlibCallbackInfo->OnZipUnZipFinish(ERR_ZLIB_DEST_FILE_DISABLED);
        return false;
    }
    auto innerTask = [srcFileDir, destDir, options, zlibCallbackInfo]() {
        UnzipParam unzipParam {
            .filterCB = ExcludeNoFilesFilter,
            .logSkippedFiles = true
        };
        ErrCode err = UnzipWithFilterCallback(srcFileDir, destDir, options, unzipParam);
        if (zlibCallbackInfo != nullptr) {
            zlibCallbackInfo->OnZipUnZipFinish(err);
        }
    };
    PostTask(innerTask);
    return true;
}

ErrCode ZipWithFilterCallback(const FilePath &srcDir, const FilePath &destFile,
    const OPTIONS &options, FilterCallback filterCB)
{
    FilePath destPath = destFile;
    if (!FilePath::DirectoryExists(destPath.DirName())) {
        APP_LOGE("The destPath not exist.");
        return ERR_ZLIB_DEST_FILE_DISABLED;
    }
    if (!FilePath::PathIsWriteable(destPath.DirName())) {
        APP_LOGE("The destPath not writeable.");
        return ERR_ZLIB_DEST_FILE_DISABLED;
    }

    if (!FilePath::PathIsValid(srcDir)) {
        APP_LOGI("%{public}s called fail, srcDir isn't Exist.", __func__);
        return ERR_ZLIB_SRC_FILE_DISABLED;
    } else {
        if (!FilePath::PathIsReadable(srcDir)) {
            APP_LOGI("%{public}s called fail, srcDir not readable.", __func__);
            return ERR_ZLIB_SRC_FILE_DISABLED;
        }
    }

    std::vector<FilePath> srcFile = {srcDir};
    ZipParams params(srcFile, FilePath(destPath.CheckDestDirTail()));
    params.SetFilterCallback(filterCB);
    bool result = Zip(params, options);
    if (result) {
        return ERR_OK;
    } else {
        return ERR_ZLIB_SERVICE_DISABLED;
    }
}

ErrCode ZipsWithFilterCallback(const std::vector<FilePath> &srcFiles, const FilePath &destFile,
    const OPTIONS &options, FilterCallback filterCB)
{
    FilePath destPath = destFile;
    if (!FilePath::DirectoryExists(destPath.DirName())) {
        APP_LOGE("The destPath not exist.");
        return ERR_ZLIB_DEST_FILE_DISABLED;
    }
    if (!FilePath::PathIsWriteable(destPath.DirName())) {
        APP_LOGE("The destPath not writeable.");
        return ERR_ZLIB_DEST_FILE_DISABLED;
    }

    for (auto iter = srcFiles.begin(); iter != srcFiles.end(); ++iter) {
        if (!FilePath::PathIsValid(*iter)) {
            APP_LOGI("%{public}s called fail, srcDir isn't Exist.", __func__);
            return ERR_ZLIB_SRC_FILE_DISABLED;
        } else {
            if (!FilePath::PathIsReadable(*iter)) {
                APP_LOGI("%{public}s called fail, srcDir not readable.", __func__);
                return ERR_ZLIB_SRC_FILE_DISABLED;
            }
        }
    }

    ZipParams params(srcFiles, FilePath(destPath.CheckDestDirTail()));
    params.SetFilterCallback(filterCB);
    bool result = Zips(params, options);
    if (result) {
        return ERR_OK;
    } else {
        return ERR_ZLIB_SERVICE_DISABLED;
    }
}

bool Zip(const std::string &srcPath, const std::string &destPath, const OPTIONS &options,
    bool includeHiddenFiles, std::shared_ptr<ZlibCallbackInfo> zlibCallbackInfo)
{
    if (zlibCallbackInfo == nullptr) {
        return false;
    }
    FilePath srcDir(srcPath);
    FilePath destFile(destPath);
    APP_LOGD("%{public}s called,  srcDir=%{private}s, destFile=%{private}s", __func__,
        srcDir.Value().c_str(), destFile.Value().c_str());

    if (srcDir.Value().size() == 0) {
        zlibCallbackInfo->OnZipUnZipFinish(ERR_ZLIB_SRC_FILE_DISABLED);
        return false;
    }
    if (destFile.Value().size() == 0) {
        zlibCallbackInfo->OnZipUnZipFinish(ERR_ZLIB_DEST_FILE_DISABLED);
        return false;
    }

    auto innerTask = [srcDir, destFile, includeHiddenFiles, zlibCallbackInfo, options]() {
        if (includeHiddenFiles) {
            ErrCode err = ZipWithFilterCallback(srcDir, destFile, options, ExcludeNoFilesFilter);
            if (zlibCallbackInfo != nullptr) {
                zlibCallbackInfo->OnZipUnZipFinish(err);
            }
        } else {
            ErrCode err = ZipWithFilterCallback(srcDir, destFile, options, ExcludeHiddenFilesFilter);
            if (zlibCallbackInfo != nullptr) {
                zlibCallbackInfo->OnZipUnZipFinish(err);
            }
        }
    };

    PostTask(innerTask);
    return true;
}

bool ZipFileIsValid(const std::string &srcFile)
{
    if (srcFile.size() == 0) {
        APP_LOGE("srcFile len is 0.");
        return false;
    }
    if (!FilePathCheckValid(srcFile)) {
        APP_LOGE("FilePathCheckValid return false.");
        return false;
    }
    FilePath srcFileDir(srcFile);
    if (!FilePath::PathIsValid(srcFileDir)) {
        APP_LOGE("PathIsValid return false.");
        return false;
    }
    if (!FilePath::PathIsReadable(srcFileDir)) {
        APP_LOGE("PathIsReadable return false.");
        return false;
    }
    return true;
}

ErrCode GetOriginalSize(PlatformFile zipFd, int64_t &originalSize)
{
    ZipReader reader;
    if (!reader.OpenFromPlatformFile(zipFd)) {
        APP_LOGE("Failed to open, not ZIP format or damaged.");
        return ERR_ZLIB_SRC_FILE_FORMAT_ERROR;
    }
    int64_t totalSize = 0;
    while (reader.HasMore()) {
        if (!reader.OpenCurrentEntryInZip()) {
            APP_LOGE("Failed to open the current file in zip.");
            return ERR_ZLIB_SERVICE_DISABLED;
        }
        const FilePath &constEntryPath = reader.CurrentEntryInfo()->GetFilePath();
        FilePath entryPath = constEntryPath;
        if (reader.CurrentEntryInfo()->IsUnsafe()) {
            APP_LOGE("Found an unsafe file in zip.");
            return ERR_ZLIB_SERVICE_DISABLED;
        }
        totalSize += reader.CurrentEntryInfo()->GetOriginalSize();
        if (!reader.AdvanceToNextEntry()) {
            APP_LOGE("Failed to advance to the next file.");
            return ERR_ZLIB_SERVICE_DISABLED;
        }
    }
    originalSize = totalSize;
    return ERR_OK;
}

ErrCode GetOriginalSize(const std::string &srcFile, int64_t &originalSize)
{
    if (!ZipFileIsValid(srcFile)) {
        return ERR_ZLIB_SRC_FILE_DISABLED;
    }
    PlatformFile zipFd = open(srcFile.c_str(), S_IREAD, O_CREAT);
    if (zipFd == kInvalidPlatformFile) {
        APP_LOGE("Failed to open file, errno: %{public}d, %{public}s", errno, strerror(errno));
        return ERR_ZLIB_SRC_FILE_DISABLED;
    }
    ErrCode ret = GetOriginalSize(zipFd, originalSize);
    close(zipFd);
    return ret;
}

bool Zips(const std::vector<std::string> &srcFiles, const std::string &destPath, const OPTIONS &options,
    bool includeHiddenFiles, std::shared_ptr<ZlibCallbackInfo> zlibCallbackInfo)
{
    if (zlibCallbackInfo == nullptr) {
        return false;
    }

    std::vector<FilePath> srcFilesPath;
    for (auto iter = srcFiles.begin(); iter != srcFiles.end(); ++iter) {
        FilePath srcFile(*iter);
        if (srcFile.Value().size() == 0) {
            zlibCallbackInfo->OnZipUnZipFinish(ERR_ZLIB_SRC_FILE_DISABLED);
            return false;
        }
        srcFilesPath.push_back(srcFile);
    }
    FilePath destFile(destPath);
    if (destFile.Value().size() == 0) {
        zlibCallbackInfo->OnZipUnZipFinish(ERR_ZLIB_DEST_FILE_DISABLED);
        return false;
    }

    auto innerTask = [srcFilesPath, destFile, includeHiddenFiles, zlibCallbackInfo, options]() {
        if (includeHiddenFiles) {
            ErrCode err = ZipsWithFilterCallback(srcFilesPath, destFile, options, ExcludeNoFilesFilter);
            if (zlibCallbackInfo != nullptr) {
                zlibCallbackInfo->OnZipUnZipFinish(err);
            }
        } else {
            ErrCode err = ZipsWithFilterCallback(srcFilesPath, destFile, options, ExcludeHiddenFilesFilter);
            if (zlibCallbackInfo != nullptr) {
                zlibCallbackInfo->OnZipUnZipFinish(err);
            }
        }
    };

    PostTask(innerTask);
    return true;
}
}  // namespace LIBZIP
}  // namespace AppExecFwk
}  // namespace OHOS
