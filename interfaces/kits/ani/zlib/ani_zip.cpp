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

namespace OHOS {
namespace AppExecFwk {
namespace LIBZIP {
namespace {
constexpr const char* PROPERTY_NAME_LEVEL = "level";
constexpr const char* PROPERTY_NAME_MEMLEVEL = "memLevel";
constexpr const char* PROPERTY_NAME_STRATEGY = "strategy";
constexpr const char* SEPARATOR = "/";
} // namespace

using FilterCallback = std::function<bool(const FilePath&)>;
using DirectoryCreator = std::function<bool(FilePath&, FilePath&)>;
using WriterFactory = std::function<std::unique_ptr<WriterDelegate>(FilePath&, FilePath&)>;

struct UnzipParam {
    FilterCallback filterCB = nullptr;
    bool logSkippedFiles = false;
};

bool ParseOptions(ani_env* env, ani_object object, LIBZIP::OPTIONS& options)
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
    } else {
    }

    // memLevel?: MemLevel
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTY_NAME_MEMLEVEL, &enumItem)) {
        RETURN_FALSE_IF_FALSE(EnumUtils::EnumETSToNative(env, enumItem, options.memLevel));
    } else {
    }

    // strategy?: CompressStrategy
    if (CommonFunAni::CallGetterOptional(env, object, PROPERTY_NAME_STRATEGY, &enumItem)) {
        RETURN_FALSE_IF_FALSE(EnumUtils::EnumETSToNative(env, enumItem, options.strategy));
    } else {
    }

    return true;
}

bool CreateDirectory(FilePath& extractDir, FilePath& entryPath)
{
    std::string path = extractDir.Value();
    if (EndsWith(path, SEPARATOR)) {
        return FilePath::CreateDirectory(FilePath(extractDir.Value() + entryPath.Value()));
    } else {
        return FilePath::CreateDirectory(FilePath(extractDir.Value() + "/" + entryPath.Value()));
    }
}

std::unique_ptr<WriterDelegate> CreateFilePathWriterDelegate(FilePath& extractDir, FilePath entryPath)
{
    if (EndsWith(extractDir.Value(), SEPARATOR)) {
        return std::make_unique<FilePathWriterDelegate>(FilePath(extractDir.Value() + entryPath.Value()));
    } else {
        return std::make_unique<FilePathWriterDelegate>(FilePath(extractDir.Value() + "/" + entryPath.Value()));
    }
}

ErrCode UnzipWithFilterAndWriters(const PlatformFile& srcFile, FilePath& destDir, WriterFactory writerFactory,
    DirectoryCreator directoryCreator, UnzipParam& unzipParam)
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

ErrCode UnzipWithFilterCallback(const FilePath& srcFile,
    const FilePath& destDir, const OPTIONS& options, UnzipParam& unzipParam)
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
    ErrCode ret = UnzipWithFilterAndWriters(zipFd, dest,
        std::bind(&CreateFilePathWriterDelegate, std::placeholders::_1, std::placeholders::_2),
        std::bind(&CreateDirectory, std::placeholders::_1, std::placeholders::_2), unzipParam);
    close(zipFd);
    return ret;
}

ErrCode DecompressFileImpl(const std::string& inFile, const std::string& outFile, const LIBZIP::OPTIONS& options)
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
    if (!LIBZIP::FilePathCheckValid(srcFileDir.Value())) {
        APP_LOGI("FilePathCheckValid srcFileDir fail");
        return ERR_ZLIB_SRC_FILE_DISABLED;
    }

    UnzipParam unzipParam { .filterCB = ExcludeNoFilesFilter, .logSkippedFiles = true };
    return UnzipWithFilterCallback(srcFileDir, destDir, options, unzipParam);
}
} // namespace LIBZIP
} // namespace AppExecFwk
} // namespace OHOS