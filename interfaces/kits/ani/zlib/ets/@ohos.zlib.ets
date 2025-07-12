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
    }).catch((err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  export function compressFile(inFile: string, outFile: string, options: Options): Promise<void> {
    let p: Promise<void> = new Promise<void>((resolve: (v:PromiseLike<void>) => void, reject: (error: Error) => void) : void => {
      let execFun = (): void => {
        zlib.CompressFile(inFile, outFile, options);
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

  export native function CompressFile(inFile: string, outFile: string, options: Options): void;

  export function decompressFile(inFile: string, outFile: string, options: Options, callback: AsyncCallback<void>): void {
    let execFun = (): void => {
      zlib.DecompressFile(inFile, outFile, options);
    };
    let p1 = taskpool.execute(execFun);
    p1.then(() => {
      let r = new BusinessError();
      callback(r, undefined);
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
      let r = new BusinessError();
      callback(r, undefined);
    }).catch((err: Error): void => {
      callback(err as BusinessError, undefined);
    });
  }

  export function decompressFile(inFile: string, outFile: string, options?: Options): Promise<void> {
    let optionsParam = options ?? new OptionsInner();
    let p: Promise<void> = new Promise<void>((resolve: (v:PromiseLike<void>) => void, reject: (error: Error) => void) : void => {
      let execFun = (): void => {
        zlib.DecompressFile(inFile, outFile, optionsParam);
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

  export native function DecompressFile(inFile: string, outFile: string, options?: Options): void;

  export interface Checksum {
    adler32(adler: long, buf: ArrayBuffer): Promise<long>;
    adler32Combine(adler1: long, adler2: long, len2: long): Promise<long>;
    crc32(crc: long, buf: ArrayBuffer): Promise<long>;
    crc32Combine(crc1: long, crc2: long, len2: long): Promise<long>;
    crc64(crc: long, buf: ArrayBuffer): Promise<long>;
    getCrcTable(): Promise<Array<long>>;
    getCrc64Table(): Promise<Array<long>>;
  }

  export class ChecksumInternal implements Checksum {
    public native Adler32(adler: long, buf: ArrayBuffer): long;
    public native Adler32Combine(adler1: long, adler2: long, len2: long): long;
    public native Crc32(crc: long, buf: ArrayBuffer): long;
    public native Crc32Combine(crc1: long, crc2: long, len2: long): long;
    public native Crc64(crc: long, buf: ArrayBuffer): long;
    public native GetCrcTable(): Array<long>;
    public native GetCrc64Table(): Array<long>;

    public adler32(adler: long, buf: ArrayBuffer): Promise<long> {
      let p: Promise<long> = new Promise<long>((resolve: (v:long) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): long => {
          return this.Adler32(adler, buf);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let result: long = e as long;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public adler32Combine(adler1: long, adler2: long, len2: long): Promise<long> {
      let p: Promise<long> = new Promise<long>((resolve: (v:long) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): long => {
          return this.Adler32Combine(adler1, adler2, len2);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let result: long = e as long;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public crc32(crc: long, buf: ArrayBuffer): Promise<long> {
      let p: Promise<long> = new Promise<long>((resolve: (v:long) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): long => {
          return this.Crc32(crc, buf);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let result: long = e as long;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public crc32Combine(crc1: long, crc2: long, len2: long): Promise<long> {
      let p: Promise<long> = new Promise<long>((resolve: (v:long) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): long => {
          return this.Crc32Combine(crc1, crc2, len2);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let result: long = e as long;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public crc64(crc: long, buf: ArrayBuffer): Promise<long> {
      let p: Promise<long> = new Promise<long>((resolve: (v:long) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): long => {
          return this.Crc64(crc, buf);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let result: long = e as long;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public getCrcTable(): Promise<Array<long>> {
      let p: Promise<Array<long>> = new Promise<Array<long>>((resolve: (v:Array<long>) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): Array<long> => {
          return this.GetCrcTable();
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let resultArray: Array<long> = e as Array<long>;
          resolve(resultArray);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public getCrc64Table(): Promise<Array<long>> {
      let p: Promise<Array<long>> = new Promise<Array<long>>((resolve: (v:Array<long>) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): Array<long> => {
          return this.GetCrc64Table();
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let resultArray: Array<long> = e as Array<long>;
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

  export native function GetOriginalSize(compressedFile: string): long;

  export function getOriginalSize(compressedFile: string): Promise<long> {
    let p: Promise<long> = new Promise<long>((resolve: (v:long) => void, reject: (error: BusinessError) => void) : void => {
      let execFun = (): long => {
        return zlib.GetOriginalSize(compressedFile);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let result: long = e as long;
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