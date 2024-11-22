/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "zip_writer.h"
#include "file_path.h"
#include "bundle_error.h"
#include "cj_common_ffi.h"
#include "zip_utils.h"
#include "zip.h"
#include "zip_reader.h"
#include <unistd.h>
#include "app_log_wrapper.h"

using namespace OHOS::CJSystemapi::BundleManager;

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {

ZipParams::ZipParams(const std::vector<FilePath>& srcDir, const FilePath& destFile)
    : srcDir_(srcDir), destFile_(destFile)
{}

ZipParams::ZipParams(const std::vector<FilePath> &srcDir, int destFd) : srcDir_(srcDir), destFd_(destFd)
{}

using FilterCallback = std::function<bool(const FilePath &)>;
using DirectoryCreator = std::function<bool(FilePath &, FilePath &)>;
using WriterFactory = std::function<std::unique_ptr<WriterDelegate>(FilePath &, FilePath &)>;

struct UnzipParam {
    FilterCallback filterCB = nullptr;
    bool logSkippedFiles = false;
};

const std::string SEPARATOR = "/";
const char HIDDEN_SEPARATOR = '.';
const std::string ZIP = ".zip";

bool IsHiddenFile(const FilePath &filePath)
{
    FilePath localFilePath = filePath;
    if (!localFilePath.Value().empty()) {
        return localFilePath.Value().c_str()[0] == HIDDEN_SEPARATOR;
    } else {
        return false;
    }
}

bool ExcludeHiddenFilesFilter(const FilePath &filePath)
{
    return !IsHiddenFile(filePath);
}

bool ExcludeNoFilesFilter(const FilePath &filePath)
{
    return true;
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

bool CreateDirectory(FilePath &extractDir, FilePath &entryPath)
{
    std::string path = extractDir.Value();
    if (EndsWith(path, SEPARATOR)) {
        return FilePath::CreateDirectory(FilePath(extractDir.Value() + entryPath.Value()));
    } else {
        return FilePath::CreateDirectory(FilePath(extractDir.Value() + "/" + entryPath.Value()));
    }
}

std::unique_ptr<WriterDelegate> CreateFilePathWriterDelegate(FilePath &extractDir, FilePath entryPath)
{
    if (EndsWith(extractDir.Value(), SEPARATOR)) {
        return std::make_unique<FilePathWriterDelegate>(FilePath(extractDir.Value() + entryPath.Value()));
    } else {
        return std::make_unique<FilePathWriterDelegate>(FilePath(extractDir.Value() + "/" + entryPath.Value()));
    }
}

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
        APP_LOGE("Init zipWriter failed");
        return false;
    }
    return zipWriter->WriteEntries(*filesToAdd, options);
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
        return ERR_ZLIB_DEST_FILE_DISABLED;
    }
}

int32_t Zip(const std::string &srcPath, const std::string &destPath, const OPTIONS &options)
{
    FilePath srcDir(srcPath);
    FilePath destFile(destPath);

    if (srcDir.Value().size() == 0) {
        return ERR_ZLIB_SRC_FILE_DISABLED;
    }
    if (destFile.Value().size() == 0) {
        return ERR_ZLIB_DEST_FILE_DISABLED;
    }

    int32_t code = ZipWithFilterCallback(srcDir, destFile, options, ExcludeHiddenFilesFilter);
    return code;
}

ErrCode UnzipWithFilterAndWriters(const PlatformFile &srcFile, FilePath &destDir, WriterFactory writerFactory,
    DirectoryCreator directoryCreator, UnzipParam &unzipParam)
{
    APP_LOGI("destDir=%{private}s", destDir.Value().c_str());
    ZipReader reader;
    if (!reader.OpenFromPlatformFile(srcFile)) {
        APP_LOGI("Failed to open srcFile");
        return ERR_ZLIB_SRC_FILE_FORMAT_ERROR;
    }
    while (reader.HasMore()) {
        if (!reader.OpenCurrentEntryInZip()) {
            APP_LOGI("Failed to open the current file in zip");
            return ERR_ZLIB_SRC_FILE_FORMAT_ERROR;
        }
        const FilePath &constEntryPath = reader.CurrentEntryInfo()->GetFilePath();
        FilePath entryPath = constEntryPath;
        if (reader.CurrentEntryInfo()->IsUnsafe()) {
            APP_LOGI("Found an unsafe file in zip");
            return ERR_ZLIB_SRC_FILE_FORMAT_ERROR;
        }
        if (unzipParam.filterCB(entryPath)) {
            if (reader.CurrentEntryInfo()->IsDirectory()) {
                if (!directoryCreator(destDir, entryPath)) {
                    APP_LOGI("directory_creator(%{private}s) Failed", entryPath.Value().c_str());
                    return ERR_ZLIB_DEST_FILE_DISABLED;
                }
            } else {
                std::unique_ptr<WriterDelegate> writer = writerFactory(destDir, entryPath);
                if (!writer->PrepareOutput()) {
                    APP_LOGE("PrepareOutput err");
                    return ERR_ZLIB_DEST_FILE_DISABLED;
                }
                if (!reader.ExtractCurrentEntry(writer.get(), std::numeric_limits<uint64_t>::max())) {
                    APP_LOGI("Failed to extract");
                    return ERR_ZLIB_SRC_FILE_FORMAT_ERROR;
                }
            }
        } else if (unzipParam.logSkippedFiles) {
            APP_LOGI("Skipped file");
        }

        if (!reader.AdvanceToNextEntry()) {
            APP_LOGI("Failed to advance to the next file");
            return ERR_ZLIB_SRC_FILE_FORMAT_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode UnzipWithFilterCallback(
    const FilePath &srcFile, const FilePath &destDir, const OPTIONS &options, UnzipParam &unzipParam)
{
    FilePath src = srcFile;
    if (!FilePathCheckValid(src.Value())) {
        APP_LOGI("FilePathCheckValid returnValue is false");
        return ERR_ZLIB_SRC_FILE_DISABLED;
    }

    FilePath dest = destDir;

    APP_LOGI("srcFile=%{private}s, destFile=%{private}s", src.Value().c_str(), dest.Value().c_str());

    if (!FilePath::PathIsValid(srcFile)) {
        APP_LOGI("PathIsValid return value is false");
        return ERR_ZLIB_SRC_FILE_DISABLED;
    }

    PlatformFile zipFd = open(src.Value().c_str(), S_IREAD, O_CREAT);
    if (zipFd == kInvalidPlatformFile) {
        APP_LOGI("Failed to open");
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

int32_t UnZip(const std::string &srcFile, const std::string &destFile, OPTIONS options)
{
    FilePath srcFileDir(srcFile);
    FilePath destDir(destFile);
    if (destDir.Value().size() == 0) {
        return ERR_ZLIB_DEST_FILE_DISABLED;
    }
    if (srcFileDir.Value().size() == 0) {
        APP_LOGI("srcFile isn't Exist");
        return ERR_ZLIB_SRC_FILE_DISABLED;
    }
    if (!FilePath::PathIsValid(srcFileDir)) {
        APP_LOGI("srcFile invalid");
        return ERR_ZLIB_SRC_FILE_DISABLED;
    }
    if (FilePath::DirectoryExists(destDir)) {
        if (!FilePath::PathIsWriteable(destDir)) {
            APP_LOGI("FilePath::PathIsWriteable(destDir) fail");
            return ERR_ZLIB_DEST_FILE_DISABLED;
        }
    } else {
        APP_LOGI("destDir isn't path");
        return ERR_ZLIB_DEST_FILE_DISABLED;
    }
    UnzipParam unzipParam {
        .filterCB = ExcludeNoFilesFilter,
        .logSkippedFiles = true
    };
    ErrCode ret = UnzipWithFilterCallback(srcFileDir, destDir, options, unzipParam);
    return ret;
}
}
}
}