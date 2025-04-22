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

export default namespace zlib {

  loadLibrary("ani_zlib.z");

  export enum CompressLevel {
    COMPRESS_LEVEL_NO_COMPRESSION = 0,
    COMPRESS_LEVEL_BEST_SPEED = 1,
    COMPRESS_LEVEL_BEST_COMPRESSION = 9,
    COMPRESS_LEVEL_DEFAULT_COMPRESSION = -1
  }

  export enum CompressStrategy {
    COMPRESS_STRATEGY_DEFAULT_STRATEGY = 0,
    COMPRESS_STRATEGY_FILTERED = 1,
    COMPRESS_STRATEGY_HUFFMAN_ONLY = 2,
    COMPRESS_STRATEGY_RLE = 3,
    COMPRESS_STRATEGY_FIXED = 4
  }

  export enum MemLevel {
    MEM_LEVEL_MIN = 1,
    MEM_LEVEL_MAX = 9,
    MEM_LEVEL_DEFAULT = 8
  }

  export interface Options {
    level?: CompressLevel;
    memLevel?: MemLevel;
    strategy?: CompressStrategy;
  }

  class OptionsInner implements Options {
    level?: CompressLevel | undefined = CompressLevel.COMPRESS_LEVEL_DEFAULT_COMPRESSION;
    memLevel?: MemLevel | undefined = MemLevel.MEM_LEVEL_DEFAULT;
    strategy?: CompressStrategy | undefined = CompressStrategy.COMPRESS_STRATEGY_DEFAULT_STRATEGY;
  }

  export function compressFile(inFile: string, outFile: string, options: Options, callback: AsyncCallback<void>): void {
    let execFun = (): void => {
      zlib.CompressFile(inFile, outFile, options);
    };
    let p1 = taskpool.execute(execFun);
    p1.then(() => {
      let r = new BusinessError();
      callback(r, undefined);
    }).catch((err: BusinessError): void => {
      callback(err, undefined);
    });
  }

  export function compressFile(inFile: string, outFile: string, options: Options): Promise<void> {
    let p: Promise<void> = new Promise<void>((resolve: (v:undefined) => void, reject: (error: Object) => void) : void => {
      let execFun = (): void => {
        zlib.CompressFile(inFile, outFile, options);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(undefined);
      }, (err: BusinessError): void => {
        reject(err);
      });
    });
    return p;
  }

  export native function CompressFile(inFile: string, outFile: string, options?: Options): void;

  export function decompressFile(inFile: string, outFile: string, options: Options, callback: AsyncCallback<void>): void {
    let execFun = (): void => {
      zlib.DecompressFile(inFile, outFile, options);
    };
    let p1 = taskpool.execute(execFun);
    p1.then(() => {
      let r = new BusinessError();
      callback(r, undefined);
    }).catch((err: BusinessError): void => {
      callback(err, undefined);
    });
  }

  export function decompressFile(inFile: string, outFile: string, callback: AsyncCallback<void>): void {
    let execFun = (): void => {
      zlib.DecompressFile(inFile, outFile, undefined);
    };
    let p1 = taskpool.execute(execFun);
    p1.then(() => {
      let r = new BusinessError();
      callback(r, undefined);
    }).catch((err: BusinessError): void => {
      callback(err, undefined);
    });
  }

  export function decompressFile(inFile: string, outFile: string, options?: Options): Promise<void> {
    let p: Promise<void> = new Promise<void>((resolve: (v:undefined) => void, reject: (error: Object) => void) : void => {
      let execFun = (): void => {
        zlib.DecompressFile(inFile, outFile, options);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(undefined);
      }, (err: BusinessError): void => {
        reject(err);
      });
    });
    return p;
  }

  export native function DecompressFile(inFile: string, outFile: string, options?: Options): void;
}