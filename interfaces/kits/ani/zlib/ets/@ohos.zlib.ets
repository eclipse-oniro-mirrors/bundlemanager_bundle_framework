/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"),
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

/**
 * @file
 * @kit BasicServicesKit
 */

import { AsyncCallback, BusinessError } from '@ohos.base';

/**
 * @namespace zlib
 * @syscap SystemCapability.BundleManager.Zlib
 * @since 7
 */
/**
 * @namespace zlib
 * @syscap SystemCapability.BundleManager.Zlib
 * @atomicservice
 * @since 11
 */
/**
 * @namespace zlib
 * @syscap SystemCapability.BundleManager.Zlib
 * @crossplatform
 * @atomicservice
 * @since 12
 */
export default namespace zlib {

  loadLibrary("ani_zlib.z");

  /**
   * CompressLevel
   *
   * @enum { number }
   * @syscap SystemCapability.BundleManager.Zlib
   * @since 7
   */
  /**
   * CompressLevel
   *
   * @enum { number }
   * @syscap SystemCapability.BundleManager.Zlib
   * @crossplatform
   * @atomicservice
   * @since 11
   */
   enum CompressLevel {
    /**
     * Indicates the no compression mode.
     *
     * @syscap SystemCapability.BundleManager.Zlib
     * @since 7
     */
    /**
     * Indicates the no compression mode.
     *
     * @syscap SystemCapability.BundleManager.Zlib
     * @crossplatform
     * @atomicservice
     * @since 11
     */
    COMPRESS_LEVEL_NO_COMPRESSION = 0,
    /**
     * Indicates the best speed mode.
     *
     * @syscap SystemCapability.BundleManager.Zlib
     * @since 7
     */
    /**
     * Indicates the best speed mode.
     *
     * @syscap SystemCapability.BundleManager.Zlib
     * @crossplatform
     * @atomicservice
     * @since 11
     */
    COMPRESS_LEVEL_BEST_SPEED = 1,
    /**
     * Indicates the best compression mode.
     *
     * @syscap SystemCapability.BundleManager.Zlib
     * @since 7
     */
    /**
     * Indicates the best compression mode.
     *
     * @syscap SystemCapability.BundleManager.Zlib
     * @crossplatform
     * @atomicservice
     * @since 11
     */
    COMPRESS_LEVEL_BEST_COMPRESSION = 9,
    /**
     * Indicates the default compression mode.
     *
     * @syscap SystemCapability.BundleManager.Zlib
     * @since 7
     */
    /**
     * Indicates the default compression mode.
     *
     * @syscap SystemCapability.BundleManager.Zlib
     * @crossplatform
     * @atomicservice
     * @since 11
     */
    COMPRESS_LEVEL_DEFAULT_COMPRESSION = -1
  }

  /**
   * CompressStrategy
   *
   * @enum { number }
   * @syscap SystemCapability.BundleManager.Zlib
   * @since 7
   */
  /**
   * CompressStrategy
   *
   * @enum { number }
   * @syscap SystemCapability.BundleManager.Zlib
   * @crossplatform
   * @atomicservice
   * @since 11
   */
   enum CompressStrategy {
    /**
     * Indicates the default strategy.
     *
     * @syscap SystemCapability.BundleManager.Zlib
     * @since 7
     */
    /**
     * Indicates the default strategy.
     *
     * @syscap SystemCapability.BundleManager.Zlib
     * @crossplatform
     * @atomicservice
     * @since 11
     */
    COMPRESS_STRATEGY_DEFAULT_STRATEGY = 0,
    /**
     * Indicates the filtered strategy.
     *
     * @syscap SystemCapability.BundleManager.Zlib
     * @since 7
     */
    /**
     * Indicates the filtered strategy.
     *
     * @syscap SystemCapability.BundleManager.Zlib
     * @crossplatform
     * @atomicservice
     * @since 11
     */
    COMPRESS_STRATEGY_FILTERED = 1,
    /**
     * Indicates the huffman-only strategy.
     *
     * @syscap SystemCapability.BundleManager.Zlib
     * @since 7
     */
    /**
     * Indicates the huffman-only strategy.
     *
     * @syscap SystemCapability.BundleManager.Zlib
     * @crossplatform
     * @atomicservice
     * @since 11
     */
    COMPRESS_STRATEGY_HUFFMAN_ONLY = 2,
    /**
     * Indicates the RLE strategy.
     *
     * @syscap SystemCapability.BundleManager.Zlib
     * @since 7
     */
    /**
     * Indicates the RLE strategy.
     *
     * @syscap SystemCapability.BundleManager.Zlib
     * @crossplatform
     * @atomicservice
     * @since 11
     */
    COMPRESS_STRATEGY_RLE = 3,
    /**
     * Indicates the fixed strategy.
     *
     * @syscap SystemCapability.BundleManager.Zlib
     * @since 7
     */
    /**
     * Indicates the fixed strategy.
     *
     * @syscap SystemCapability.BundleManager.Zlib
     * @crossplatform
     * @atomicservice
     * @since 11
     */
    COMPRESS_STRATEGY_FIXED = 4
  }

  /**
   * MemLevel
   *
   * @enum { number }
   * @syscap SystemCapability.BundleManager.Zlib
   * @since 7
   */
  /**
   * MemLevel
   *
   * @enum { number }
   * @syscap SystemCapability.BundleManager.Zlib
   * @crossplatform
   * @atomicservice
   * @since 11
   */
   enum MemLevel {
    /**
     * Uses the least amount of memory.
     *
     * @syscap SystemCapability.BundleManager.Zlib
     * @since 7
     */
    /**
     * Uses the least amount of memory.
     *
     * @syscap SystemCapability.BundleManager.Zlib
     * @crossplatform
     * @atomicservice
     * @since 11
     */
    MEM_LEVEL_MIN = 1,
    /**
     * Uses the maximum amount of memory.
     *
     * @syscap SystemCapability.BundleManager.Zlib
     * @since 7
     */
    /**
     * Uses the maximum amount of memory.
     *
     * @syscap SystemCapability.BundleManager.Zlib
     * @crossplatform
     * @atomicservice
     * @since 11
     */
    MEM_LEVEL_MAX = 9,
    /**
     * Uses the default amount of memory.
     *
     * @syscap SystemCapability.BundleManager.Zlib
     * @since 7
     */
    /**
     * Uses the default amount of memory.
     *
     * @syscap SystemCapability.BundleManager.Zlib
     * @crossplatform
     * @atomicservice
     * @since 11
     */
    MEM_LEVEL_DEFAULT = 8
  }

  export interface Options {
    /**
     * Indicates the compress level.
     *
     * @syscap SystemCapability.BundleManager.Zlib
     * @since 7
     */
    /**
     * Indicates the compress level.
     *
     * @type { ?CompressLevel }
     * @syscap SystemCapability.BundleManager.Zlib
     * @crossplatform
     * @atomicservice
     * @since 11
     */
    level?: CompressLevel;
    /**
     * Indicates the memory level.
     *
     * @syscap SystemCapability.BundleManager.Zlib
     * @since 7
     */
    /**
     * Indicates the memory level.
     *
     * @type { ?MemLevel }
     * @syscap SystemCapability.BundleManager.Zlib
     * @crossplatform
     * @atomicservice
     * @since 11
     */
    memLevel?: MemLevel;
    /**
     * Indicates the compress strategy.
     *
     * @syscap SystemCapability.BundleManager.Zlib
     * @since 7
     */
    /**
     * Indicates the compress strategy.
     *
     * @type { ?CompressStrategy }
     * @syscap SystemCapability.BundleManager.Zlib
     * @crossplatform
     * @atomicservice
     * @since 11
     */
    strategy?: CompressStrategy;
  }

  class OptionsInner implements Options {
    level?: CompressLevel | undefined = CompressLevel.COMPRESS_LEVEL_DEFAULT_COMPRESSION;
    memLevel?: MemLevel | undefined = MemLevel.MEM_LEVEL_DEFAULT;
    strategy?: CompressStrategy | undefined = CompressStrategy.COMPRESS_STRATEGY_DEFAULT_STRATEGY;
  }

  /**
   * Decompress the specified file.
   *
   * @param { string } inFile - Indicates the path of the file to be decompressed.
   * @param { string } outFile - Indicates the path of the output decompressed file.
   * @param { Options } options - Indicates the options of decompressing file.
   * @param { AsyncCallback<void> } callback - The callback of decompressing file result.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified; 2. Incorrect parameter types.
   * @throws { BusinessError } 900001 - The input source file is invalid.
   * @throws { BusinessError } 900002 - The input destination file is invalid.
   * @syscap SystemCapability.BundleManager.Zlib
   * @since 9
   */
  /**
   * Decompress the specified file.
   *
   * @param { string } inFile - Indicates the path of the file to be decompressed.
   * @param { string } outFile - Indicates the path of the output decompressed file.
   * @param { Options } options - Indicates the options of decompressing file.
   * @param { AsyncCallback<void> } callback - The callback of decompressing file result.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified; 2. Incorrect parameter types.
   * @throws { BusinessError } 900001 - The input source file is invalid.
   * @throws { BusinessError } 900002 - The input destination file is invalid.
   * @throws { BusinessError } 900003 - The input source file is not in ZIP format or is damaged.
   * @syscap SystemCapability.BundleManager.Zlib
   * @since 10
   */
  /**
   * Decompress the specified file.
   *
   * @param { string } inFile - Indicates the path of the file to be decompressed.
   * @param { string } outFile - Indicates the path of the output decompressed file.
   * @param { Options } options - Indicates the options of decompressing file.
   * @param { AsyncCallback<void> } callback - The callback of decompressing file result.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified; 2. Incorrect parameter types.
   * @throws { BusinessError } 900001 - The input source file is invalid.
   * @throws { BusinessError } 900002 - The input destination file is invalid.
   * @throws { BusinessError } 900003 - The input source file is not in ZIP format or is damaged.
   * @syscap SystemCapability.BundleManager.Zlib
   * @crossplatform
   * @atomicservice
   * @since 11
   */
  export function decompressFile(inFile: string, outFile: string, options: Options, callback: AsyncCallback<void>) {
    let execFun = (): NullishType => {
      zlib.DecompressFile(inFile, outFile, options);
    };
    let p1 = taskpool.execute(execFun);
    p1.then(() => {
        let r: BusinessError = { code: 0, name: "error", message: "error", data: undefined };
        callback(r, undefined);
    }, (err: Object): void => {
    });
  }

  /**
   * Decompress the specified file.
   *
   * @param { string } inFile - Indicates the path of the file to be decompressed.
   * @param { string } outFile - Indicates the path of the output decompressed file.
   * @param { AsyncCallback<void> } callback - The callback of decompressing file result.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified; 2. Incorrect parameter types.
   * @throws { BusinessError } 900001 - The input source file is invalid.
   * @throws { BusinessError } 900002 - The input destination file is invalid.
   * @throws { BusinessError } 900003 - The input source file is not in ZIP format or is damaged.
   * @syscap SystemCapability.BundleManager.Zlib
   * @since 10
   */
  /**
   * Decompress the specified file.
   *
   * @param { string } inFile - Indicates the path of the file to be decompressed.
   * @param { string } outFile - Indicates the path of the output decompressed file.
   * @param { AsyncCallback<void> } callback - The callback of decompressing file result.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified; 2. Incorrect parameter types.
   * @throws { BusinessError } 900001 - The input source file is invalid.
   * @throws { BusinessError } 900002 - The input destination file is invalid.
   * @throws { BusinessError } 900003 - The input source file is not in ZIP format or is damaged.
   * @syscap SystemCapability.BundleManager.Zlib
   * @crossplatform
   * @atomicservice
   * @since 11
   */
  export function decompressFile(inFile: string, outFile: string, callback: AsyncCallback<void>): void {
    let execFun = (): NullishType => {
      zlib.DecompressFile(inFile, outFile, undefined);
    };
    let p1 = taskpool.execute(execFun);
    p1.then(() => {
        let r: BusinessError = { code: 0, name: "error", message: "error", data: undefined };
        callback(r, undefined);
    }, (err: Object): void => {
    });
  }

  /**
   * Decompress the specified file.
   *
   * @param { string } inFile - Indicates the path of the file to be decompressed.
   * @param { string } outFile - Indicates the path of the output decompressing file.
   * @param { Options } options - Indicates the options of decompressing file.
   * @returns { Promise<void> } Returns the result of decompressing file.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified; 2. Incorrect parameter types.
   * @throws { BusinessError } 900001 - The input source file is invalid.
   * @throws { BusinessError } 900002 - The input destination file is invalid.
   * @syscap SystemCapability.BundleManager.Zlib
   * @since 9
   */
  /**
   * Decompress the specified file.
   *
   * @param { string } inFile - Indicates the path of the file to be decompressed.
   * @param { string } outFile - Indicates the path of the output decompressing file.
   * @param { Options } options - Indicates the options of decompressing file.
   * @returns { Promise<void> } Returns the result of decompressing file.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified; 2. Incorrect parameter types.
   * @throws { BusinessError } 900001 - The input source file is invalid.
   * @throws { BusinessError } 900002 - The input destination file is invalid.
   * @throws { BusinessError } 900003 - The input source file is not in ZIP format or is damaged.
   * @syscap SystemCapability.BundleManager.Zlib
   * @since 10
   */
  /**
   * Decompress the specified file.
   *
   * @param { string } inFile - Indicates the path of the file to be decompressed.
   * @param { string } outFile - Indicates the path of the output decompressing file.
   * @param { Options } options - Indicates the options of decompressing file.
   * @returns { Promise<void> } Returns the result of decompressing file.
   * @throws { BusinessError } 401 - Parameter error. Possible causes: 1. Mandatory parameters are left unspecified; 2. Incorrect parameter types.
   * @throws { BusinessError } 900001 - The input source file is invalid.
   * @throws { BusinessError } 900002 - The input destination file is invalid.
   * @throws { BusinessError } 900003 - The input source file is not in ZIP format or is damaged.
   * @syscap SystemCapability.BundleManager.Zlib
   * @crossplatform
   * @atomicservice
   * @since 11
   */
  export function decompressFile(inFile: string, outFile: string, options?: Options): Promise<void> {
    let p: Promise<void> = new Promise<void>((resolve: (v:undefined) => void, reject: (error: Object) => void) : void => {
      let execFun = (): NullishType => {
        zlib.DecompressFile(inFile, outFile, options);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(undefined);
      }, (err: Object): void => {
        let be = err as BusinessError<void>;
        reject(be);
      });
    });
    return p;
  }

  export native function DecompressFile(inFile: string, outFile: string, options?: Options): void;
}