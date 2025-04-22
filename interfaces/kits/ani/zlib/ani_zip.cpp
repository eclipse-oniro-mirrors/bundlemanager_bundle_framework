/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "ani_zip.h"
#include "zip.h"
#include "zip_reader.h"
#include "zip_writer.h"

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {
constexpr const char* PROPERTY_NAME_LEVEL = "level";
constexpr const char* PROPERTY_NAME_MEMLEVEL = "memLevel";
constexpr const char* PROPERTY_NAME_STRATEGY = "strategy";
constexpr const char* SEPARATOR = "/";
constexpr const char HIDDEN_SEPARATOR = '.';

using FilterCallback = std::function<bool(const FilePath&)>;
using DirectoryCreator = std::function<bool(FilePath&, FilePath&)>;
using WriterFactory = std::function<std::unique_ptr<WriterDelegate>(FilePath&, FilePath&)>;

struct ANIUnzipParam {
    FilterCallback filterCB = nullptr;
    bool logSkippedFiles = false;
};

bool ANIParseOptions(ani_env* env, ani_object object, LIBZIP::OPTIONS& options)
{
    RETURN_FALSE_IF_NULL(env);

    if (object == nullptr) {
        return true; // allow null
    }

    options.level = LIBZIP::COMPRESS_LEVEL::COMPRESS_LEVEL_DEFAULT_COMPRESSION;
    options.memLevel = LIBZIP::MEMORY_LEVEL::MEM_LEVEL_DEFAULT_MEMLEVEL;
    options.strategy = LIBZIP::COMPRESS_STRATEGY::COMPRESS_STRATEGY_DEFAULT_STRATEGY;

    ani_boolean isUndefined;
    ani_status status = env->Reference_IsUndefined(object, &isUndefined);
    if (status != ANI_OK) {
        APP_LOGI("Reference_IsUndefined failed %{public}d", status);
        return false;
    }

    if (isUndefined) {
        return true; // allow undefined
    }

    ani_enum_item enumItem = nullptr;
    // level?: CompressLevel
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTY_NAME_LEVEL, &enumItem)) {
        RETURN_FALSE_IF_FALSE(EnumUtils::EnumETSToNative(env, enumItem, options.level));
    }

    // memLevel?: MemLevel
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTY_NAME_MEMLEVEL, &enumItem)) {
        RETURN_FALSE_IF_FALSE(EnumUtils::EnumETSToNative(env, enumItem, options.memLevel));
    }

    // strategy?: CompressStrategy
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTY_NAME_STRATEGY, &enumItem)) {
        RETURN_FALSE_IF_FALSE(EnumUtils::EnumETSToNative(env, enumItem, options.strategy));
    }

    return true;
}

bool ANIIsHiddenFile(const FilePath& filePath)
{
    FilePath localFilePath = filePath;
    if (!localFilePath.Value().empty()) {
        return localFilePath.Value()[0] == HIDDEN_SEPARATOR;
    }

    return false;
}

bool ANIExcludeNoFilesFilter(const FilePath& filePath)
{
    return true;
}

bool ANIExcludeHiddenFilesFilter(const FilePath& filePath)
{
    return !ANIIsHiddenFile(filePath);
}

std::vector<FileAccessor::DirectoryContentEntry> ANIListDirectoryContent(const FilePath& filePath, bool& isSuccess)
{
    FilePath curPath = filePath;
    std::vector<FileAccessor::DirectoryContentEntry> fileDirectoryVector;
    std::vector<std::string> filelist;
    isSuccess = FilePath::GetZipAllDirFiles(curPath.Value(), filelist);
    if (isSuccess) {
        APP_LOGD("f.size=%{public}zu", filelist.size());
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

bool ANICreateDirectory(FilePath& extractDir, FilePath& entryPath)
{
    std::string path = extractDir.Value();
    if (EndsWith(path, SEPARATOR)) {
        APP_LOGE("ANICreateDirectory: %{public}s", FilePath(extractDir.Value() + entryPath.Value()).Value().c_str());
        return FilePath::CreateDirectory(FilePath(extractDir.Value() + entryPath.Value()));
    } else {
        APP_LOGE(
            "ANICreateDirectory: %{public}s", FilePath(extractDir.Value() + "/" + entryPath.Value()).Value().c_str());
        return FilePath::CreateDirectory(FilePath(extractDir.Value() + "/" + entryPath.Value()));
    }
}

std::unique_ptr<WriterDelegate> ANICreateFilePathWriterDelegate(FilePath& extractDir, FilePath entryPath)
{
    if (EndsWith(extractDir.Value(), SEPARATOR)) {
        APP_LOGE("ANICreateFilePathWriterDelegate: %{public}s",
            FilePath(extractDir.Value() + entryPath.Value()).Value().c_str());
        return std::make_unique<FilePathWriterDelegate>(FilePath(extractDir.Value() + entryPath.Value()));
    } else {
        APP_LOGE("ANICreateFilePathWriterDelegate: %{public}s",
            FilePath(extractDir.Value() + "/" + entryPath.Value()).Value().c_str());
        return std::make_unique<FilePathWriterDelegate>(FilePath(extractDir.Value() + "/" + entryPath.Value()));
    }
}

ZipParams::ZipParams(const std::vector<FilePath>& srcDir, const FilePath& destFile)
    : srcDir_(srcDir), destFile_(destFile)
{}

// Does not take ownership of |fd|.
ZipParams::ZipParams(const std::vector<FilePath>& srcDir, int destFd) : srcDir_(srcDir), destFd_(destFd) {}

FilePath ANIFilePathEndIsSeparator(FilePath paramPath)
{
    bool endIsSeparator = EndsWith(paramPath.Value(), SEPARATOR);
    if (FilePath::IsDir(paramPath)) {
        if (!endIsSeparator) {
            paramPath.AppendSeparator();
        }
    }
    return paramPath;
}

ErrCode ANIUnzipWithFilterAndWriters(const PlatformFile& srcFile, FilePath& destDir, WriterFactory writerFactory,
    DirectoryCreator directoryCreator, ANIUnzipParam& unzipParam)
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
        const FilePath& constEntryPath = reader.CurrentEntryInfo()->GetFilePath();
        FilePath entryPath = constEntryPath;
        if (reader.CurrentEntryInfo()->IsUnsafe()) {
            APP_LOGI("Found an unsafe file in zip");
            return ERR_ZLIB_SRC_FILE_FORMAT_ERROR;
        }
        if (!unzipParam.filterCB(entryPath)) {
            if (unzipParam.logSkippedFiles) {
                APP_LOGI("Skipped file");
            }
            if (!reader.AdvanceToNextEntry()) {
                APP_LOGI("Failed to advance to the next file");
                return ERR_ZLIB_SRC_FILE_FORMAT_ERROR;
            }
            continue;
        }

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

        if (!reader.AdvanceToNextEntry()) {
            APP_LOGI("Failed to advance to the next file");
            return ERR_ZLIB_SRC_FILE_FORMAT_ERROR;
        }
    }
    return ERR_OK;
}

ErrCode ANIUnzipWithFilterAndWritersParallel(const FilePath& srcFile, FilePath& destDir, WriterFactory writerFactory,
    DirectoryCreator directoryCreator, ANIUnzipParam& unzipParam)
{
    ZipParallelReader reader;
    FilePath src = srcFile;

    if (!reader.Open(src)) {
        APP_LOGI("Failed to open srcFile");
        return ERR_ZLIB_SRC_FILE_FORMAT_ERROR;
    }
    ErrCode ret = ERR_OK;
    for (int32_t i = 0; i < reader.num_entries(); i++) {
        if (!reader.OpenCurrentEntryInZip()) {
            APP_LOGI("Failed to open the current file in zip");
            return ERR_ZLIB_SRC_FILE_FORMAT_ERROR;
        }
        const FilePath& constEntryPath = reader.CurrentEntryInfo()->GetFilePath();
        if (reader.CurrentEntryInfo()->IsUnsafe()) {
            APP_LOGI("Found an unsafe file in zip");
            return ERR_ZLIB_SRC_FILE_FORMAT_ERROR;
        }
        unz_file_pos position = {};
        if (!reader.GetCurrentEntryPos(position)) {
            return ERR_ZLIB_SRC_FILE_FORMAT_ERROR;
        }
        bool isDirectory = reader.CurrentEntryInfo()->IsDirectory();
        ffrt::submit(
            [&, position, isDirectory, constEntryPath]() {
                if (ret != ERR_OK) {
                    return;
                }
                int resourceId = sched_getcpu();
                unzFile zipFile = reader.GetZipHandler(resourceId);
                if (!reader.GotoEntry(zipFile, position)) {
                    APP_LOGI("Failed to go to entry");
                    ret = ERR_ZLIB_SRC_FILE_FORMAT_ERROR;
                    return;
                }
                FilePath entryPath = constEntryPath;
                if (unzipParam.filterCB(entryPath)) {
                    if (isDirectory) {
                        if (!directoryCreator(destDir, entryPath)) {
                            APP_LOGI("directory_creator(%{private}s) Failed", entryPath.Value().c_str());
                            reader.ReleaseZipHandler(resourceId);
                            ret = ERR_ZLIB_DEST_FILE_DISABLED;
                            return;
                        }
                    } else {
                        std::unique_ptr<WriterDelegate> writer = writerFactory(destDir, entryPath);
                        if (!writer->PrepareOutput()) {
                            APP_LOGE("PrepareOutput err");
                            reader.ReleaseZipHandler(resourceId);
                            ret = ERR_ZLIB_DEST_FILE_DISABLED;
                            return;
                        }
                        if (!reader.ExtractEntry(writer.get(), zipFile, std::numeric_limits<uint64_t>::max())) {
                            APP_LOGI("Failed to extract");
                            reader.ReleaseZipHandler(resourceId);
                            ret = ERR_ZLIB_SRC_FILE_FORMAT_ERROR;
                            return;
                        }
                    }
                } else if (unzipParam.logSkippedFiles) {
                    APP_LOGI("Skipped file");
                }
                reader.ReleaseZipHandler(resourceId);
            },
            {}, {});
        if (!reader.AdvanceToNextEntry()) {
            APP_LOGI("Failed to advance to the next file");
            return ERR_ZLIB_SRC_FILE_FORMAT_ERROR;
        }
    }
    ffrt::wait();
    return ERR_OK;
}

ErrCode ANIUnzipWithFilterCallback(
    const FilePath& srcFile, const FilePath& destDir, const OPTIONS& options, ANIUnzipParam& unzipParam)
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

    ErrCode ret = ERR_OK;
    if (options.parallel == PARALLEL_STRATEGY_PARALLEL_DECOMPRESSION) {
        ret = ANIUnzipWithFilterAndWritersParallel(src, dest,
            std::bind(&ANICreateFilePathWriterDelegate, std::placeholders::_1, std::placeholders::_2),
            std::bind(&ANICreateDirectory, std::placeholders::_1, std::placeholders::_2), unzipParam);
    } else {
        PlatformFile zipFd = open(src.Value().c_str(), S_IREAD, O_CREAT);
        if (zipFd == kInvalidPlatformFile) {
            APP_LOGE("Failed to open");
            return ERR_ZLIB_SRC_FILE_DISABLED;
        }
        ret = ANIUnzipWithFilterAndWriters(zipFd, dest,
            std::bind(&ANICreateFilePathWriterDelegate, std::placeholders::_1, std::placeholders::_2),
            std::bind(&ANICreateDirectory, std::placeholders::_1, std::placeholders::_2), unzipParam);
        close(zipFd);
    }
    return ret;
}

ErrCode ANIDecompressFileImpl(const std::string& inFile, const std::string& outFile, const LIBZIP::OPTIONS& options)
{
    LIBZIP::FilePath srcFileDir(inFile);
    LIBZIP::FilePath destDir(outFile);
    if ((destDir.Value().size() == 0) || LIBZIP::FilePath::HasRelativePathBaseOnAPIVersion(outFile)) {
        return ERR_ZLIB_DEST_FILE_DISABLED;
    }
    if ((srcFileDir.Value().size() == 0) || LIBZIP::FilePath::HasRelativePathBaseOnAPIVersion(inFile)) {
        APP_LOGI("srcFile doesn't Exist");
        return ERR_ZLIB_SRC_FILE_DISABLED;
    }
    if (!LIBZIP::FilePath::PathIsValid(srcFileDir)) {
        APP_LOGI("srcFile invalid");
        return ERR_ZLIB_SRC_FILE_DISABLED;
    }
    if (LIBZIP::FilePath::DirectoryExists(destDir)) {
        if (!LIBZIP::FilePath::PathIsWriteable(destDir)) {
            APP_LOGI("FilePath::PathIsWriteable(destDir) fail");
            return ERR_ZLIB_DEST_FILE_DISABLED;
        }
    } else {
        APP_LOGI("destDir isn't path");
        return ERR_ZLIB_DEST_FILE_DISABLED;
    }

    ANIUnzipParam unzipParam { .filterCB = ANIExcludeNoFilesFilter, .logSkippedFiles = true };
    return ANIUnzipWithFilterCallback(srcFileDir, destDir, options, unzipParam);
}

bool ANIZip(const ZipParams& params, const OPTIONS& options)
{
    const std::vector<std::pair<FilePath, FilePath>>* filesToAdd = &params.GetFilesTozip();
    std::vector<std::pair<FilePath, FilePath>> allRelativeFiles;
    FilePath srcDir = params.SrcDir().front();
    FilePath paramPath = ANIFilePathEndIsSeparator(srcDir);
    if (filesToAdd->empty()) {
        filesToAdd = &allRelativeFiles;
        std::list<FileAccessor::DirectoryContentEntry> entries;
        if (EndsWith(paramPath.Value(), SEPARATOR)) {
            entries.push_back(FileAccessor::DirectoryContentEntry(srcDir, true));
            FilterCallback filterCallback = params.GetFilterCallback();
            for (auto iter = entries.begin(); iter != entries.end(); ++iter) {
                if (iter != entries.begin() && ((!params.GetIncludeHiddenFiles() && ANIIsHiddenFile(iter->path)) ||
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
                        ANIListDirectoryContent(iter->path, isSuccess);
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

ErrCode ANIZipWithFilterCallback(
    const FilePath& srcDir, const FilePath& destFile, const OPTIONS& options, FilterCallback filterCB)
{
    FilePath destPath = destFile;
    if (!FilePath::DirectoryExists(destPath.DirName())) {
        APP_LOGE("The destPath not exist");
        return ERR_ZLIB_DEST_FILE_DISABLED;
    }
    if (!FilePath::PathIsWriteable(destPath.DirName())) {
        APP_LOGE("The destPath not writeable");
        return ERR_ZLIB_DEST_FILE_DISABLED;
    }

    if (!FilePath::PathIsValid(srcDir)) {
        APP_LOGI("srcDir isn't Exist");
        return ERR_ZLIB_SRC_FILE_DISABLED;
    } else if (!FilePath::PathIsReadable(srcDir)) {
        APP_LOGI("srcDir not readable");
        return ERR_ZLIB_SRC_FILE_DISABLED;
    }

    std::vector<FilePath> srcFile = { srcDir };
    ZipParams params(srcFile, FilePath(destPath.CheckDestDirTail()));
    params.SetFilterCallback(filterCB);
    return ANIZip(params, options) ? ERR_OK : ERR_ZLIB_DEST_FILE_DISABLED;
}

ErrCode ANICompressFileImpl(const std::string& inFile, const std::string& outFile, const LIBZIP::OPTIONS& options)
{
    LIBZIP::FilePath srcFileDir(inFile);
    LIBZIP::FilePath destDir(outFile);
    if ((destDir.Value().size() == 0) || LIBZIP::FilePath::HasRelativePathBaseOnAPIVersion(outFile)) {
        return ERR_ZLIB_DEST_FILE_DISABLED;
    }
    if ((srcFileDir.Value().size() == 0) || LIBZIP::FilePath::HasRelativePathBaseOnAPIVersion(inFile)) {
        return ERR_ZLIB_SRC_FILE_DISABLED;
    }

    return ANIZipWithFilterCallback(srcFileDir, destDir, options, ANIExcludeHiddenFilesFilter);
}
} // namespace LIBZIP
} // namespace AppExecFwk
} // namespace OHOS