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

  loadLibraryWithPermissionCheck("ani_zlib.z", "@ohos.zlib");

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

  export enum ParallelStrategy {
    PARALLEL_STRATEGY_SEQUENTIAL = 0,
    PARALLEL_STRATEGY_PARALLEL_DECOMPRESSION = 1
  }

  export enum PathSeparatorStrategy {
    PATH_SEPARATOR_STRATEGY_DEFAULT = 0,
    PATH_SEPARATOR_STRATEGY_REPLACE_BACKSLASH = 1
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
    parallel?: ParallelStrategy;
    pathSeparatorStrategy?: PathSeparatorStrategy;
  }

  class OptionsInner implements Options {
    level?: CompressLevel | undefined;
    memLevel?: MemLevel | undefined;
    strategy?: CompressStrategy | undefined;
    parallel?: ParallelStrategy | undefined;
    pathSeparatorStrategy?: PathSeparatorStrategy | undefined;
  }

  export function compressFile(inFile: string, outFile: string, options: Options, callback: AsyncCallback<void>): void {
    let execFun = (): void => {
      zlib.CompressFile(inFile, outFile, options);
    };
    let p1 = taskpool.execute(execFun);
    p1.then(() => {
      callback(null, undefined);
    }).catch((err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  export function compressFile(inFile: string, outFile: string, options: Options): Promise<void> {
    let p: Promise<void> = new Promise<void>((resolve: (v:undefined) => void, reject: (error: Error) => void) : void => {
      let execFun = (): void => {
        zlib.CompressFile(inFile, outFile, options);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(undefined);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  export native function CompressFile(inFile: string, outFile: string, options: Options): void;

  export function decompressFile(inFile: string, outFile: string, options: Options, callback: AsyncCallback<void>): void {
    let execFun = (): void => {
      zlib.DecompressFile(inFile, outFile, options);
    };
    let p1 = taskpool.execute(execFun);
    p1.then(() => {
      callback(null, undefined);
    }).catch((err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  export function decompressFile(inFile: string, outFile: string, callback: AsyncCallback<void>): void {
    let execFun = (): void => {
      zlib.DecompressFile(inFile, outFile, new OptionsInner());
    };
    let p1 = taskpool.execute(execFun);
    p1.then(() => {
      callback(null, undefined);
    }).catch((err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  export function decompressFile(inFile: string, outFile: string, options?: Options): Promise<void> {
    let optionsParam = options ?? new OptionsInner();
    let p: Promise<void> = new Promise<void>((resolve: (v:undefined) => void, reject: (error: Error) => void) : void => {
      let execFun = (): void => {
        zlib.DecompressFile(inFile, outFile, optionsParam);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(undefined);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  export native function DecompressFile(inFile: string, outFile: string, options?: Options): void;

  export interface Checksum {
    adler32(adler: number, buf: ArrayBuffer): Promise<number>;
    adler32Combine(adler1: number, adler2: number, len2: number): Promise<number>;
    crc32(crc: number, buf: ArrayBuffer): Promise<number>;
    crc32Combine(crc1: number, crc2: number, len2: number): Promise<number>;
    crc64(crc: number, buf: ArrayBuffer): Promise<number>;
    getCrcTable(): Promise<Array<number>>;
    getCrc64Table(): Promise<Array<number>>;
  }

  export class ChecksumInternal implements Checksum {
    public native Adler32(adler: number, buf: ArrayBuffer): number;
    public native Adler32Combine(adler1: number, adler2: number, len2: number): number;
    public native Crc32(crc: number, buf: ArrayBuffer): number;
    public native Crc32Combine(crc1: number, crc2: number, len2: number): number;
    public native Crc64(crc: number, buf: ArrayBuffer): number;
    public native GetCrcTable(): Array<number>;
    public native GetCrc64Table(): Array<number>;

    public adler32(adler: number, buf: ArrayBuffer): Promise<number> {
      let p: Promise<number> = new Promise<number>((resolve: (v:number) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): number => {
          return this.Adler32(adler, buf);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let result: number = e as number;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public adler32Combine(adler1: number, adler2: number, len2: number): Promise<number> {
      let p: Promise<number> = new Promise<number>((resolve: (v:number) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): number => {
          return this.Adler32Combine(adler1, adler2, len2);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let result: number = e as number;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public crc32(crc: number, buf: ArrayBuffer): Promise<number> {
      let p: Promise<number> = new Promise<number>((resolve: (v:number) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): number => {
          return this.Crc32(crc, buf);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let result: number = e as number;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public crc32Combine(crc1: number, crc2: number, len2: number): Promise<number> {
      let p: Promise<number> = new Promise<number>((resolve: (v:number) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): number => {
          return this.Crc32Combine(crc1, crc2, len2);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let result: number = e as number;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public crc64(crc: number, buf: ArrayBuffer): Promise<number> {
      let p: Promise<number> = new Promise<number>((resolve: (v:number) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): number => {
          return this.Crc64(crc, buf);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let result: number = e as number;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public getCrcTable(): Promise<Array<number>> {
      let p: Promise<Array<number>> = new Promise<Array<number>>((resolve: (v:Array<number>) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): Array<number> => {
          return this.GetCrcTable();
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let resultArray: Array<number> = e as Array<number>;
          resolve(resultArray);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public getCrc64Table(): Promise<Array<number>> {
      let p: Promise<Array<number>> = new Promise<Array<number>>((resolve: (v:Array<number>) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): Array<number> => {
          return this.GetCrc64Table();
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let resultArray: Array<number> = e as Array<number>;
          resolve(resultArray);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }
  }

  export native function CompressFiles(inFiles: Array<string>, outFile: string, options: Options): void;

  export function compressFiles(inFiles: Array<string>, outFile: string, options: Options): Promise<void> {
    let p: Promise<void> = new Promise<void>((resolve: (v:PromiseLike<void>) => void, reject: (error: Error) => void) : void => {
      let execFun = (): void => {
        zlib.CompressFiles(inFiles, outFile, options);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((): void => {
        resolve(Promise.resolve());
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  export native function GetOriginalSize(compressedFile: string): number;

  export function getOriginalSize(compressedFile: string): Promise<number> {
    let p: Promise<number> = new Promise<number>((resolve: (v:number) => void, reject: (error: BusinessError) => void) : void => {
      let execFun = (): number => {
        return zlib.GetOriginalSize(compressedFile);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let result: number = e as number;
        resolve(result);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  export native function createChecksumSync(): Checksum;

  export function createChecksum(): Promise<Checksum> {
    let p: Promise<Checksum> = new Promise<Checksum>((resolve: (v:Checksum) => void, reject: (error: BusinessError) => void) : void => {
      let execFun = (): Checksum => {
        return zlib.createChecksumSync();
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let result: Checksum = e as Checksum;
        resolve(result);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }
}