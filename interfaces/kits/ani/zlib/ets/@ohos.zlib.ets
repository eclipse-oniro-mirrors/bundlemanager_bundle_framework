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

  export enum CompressFlushMode {
    NO_FLUSH = 0,
    PARTIAL_FLUSH = 1,
    SYNC_FLUSH = 2,
    FULL_FLUSH = 3,
    FINISH = 4,
    BLOCK = 5,
    TREES = 6
  }

  export enum ReturnStatus {
    OK = 0,
    STREAM_END = 1,
    NEED_DICT = 2,
  }

  export enum CompressMethod {
    DEFLATED = 8,
  }

  export enum OffsetReferencePoint {
    SEEK_SET = 0,
    SEEK_CUR = 1,
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

  export interface GzErrorOutputInfo {
    status: ReturnStatus;
    statusMsg: string;
  }

  class GzErrorOutputInfoInner implements GzErrorOutputInfo {
    status: ReturnStatus = ReturnStatus.OK;
    statusMsg: string;
  }
  
  export function compressFile(inFile: string, outFile: string, options: Options, callback: AsyncCallback<void>): void {
    let execFun = (): void => {
      zlib.compressFileNative(inFile, outFile, options);
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
        zlib.compressFileNative(inFile, outFile, options);
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

  export native function compressFileNative(inFile: string, outFile: string, options: Options): void;

  export function decompressFile(inFile: string, outFile: string, options: Options, callback: AsyncCallback<void>): void {
    let execFun = (): void => {
      zlib.decompressFileNative(inFile, outFile, options);
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
      zlib.decompressFileNative(inFile, outFile, new OptionsInner());
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
        zlib.decompressFileNative(inFile, outFile, optionsParam);
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

  export native function decompressFileNative(inFile: string, outFile: string, options?: Options): void;

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
    public native adler32Native(adler: long, buf: ArrayBuffer): long;
    public native adler32CombineNative(adler1: long, adler2: long, len2: long): long;
    public native crc32Native(crc: long, buf: ArrayBuffer): long;
    public native crc32CombineNative(crc1: long, crc2: long, len2: long): long;
    public native crc64Native(crc: long, buf: ArrayBuffer): long;
    public native getCrcTableNative(): Array<long>;
    public native getCrc64TableNative(): Array<long>;

    public adler32(adler: long, buf: ArrayBuffer): Promise<long> {
      let p: Promise<long> = new Promise<long>((resolve: (v:long) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): long => {
          return this.adler32Native(adler, buf);
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
          return this.adler32CombineNative(adler1, adler2, len2);
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
          return this.crc32Native(crc, buf);
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
          return this.crc32CombineNative(crc1, crc2, len2);
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
          return this.crc64Native(crc, buf);
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
          return this.getCrcTableNative();
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
          return this.getCrc64TableNative();
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

  export interface GZip {
    gzdopen(fd: int, mode: string): Promise<void>;
    gzbuffer(size: long): Promise<int>;
    gzopen(path: string, mode: string): Promise<void>;
    gzeof(): Promise<int>;
    gzdirect(): Promise<int>;
    gzclose(): Promise<ReturnStatus>;
    gzclearerr(): Promise<void>;
    gzerror(): Promise<GzErrorOutputInfo>;
    gzgetc(): Promise<int>;
    gzflush(flush: CompressFlushMode): Promise<ReturnStatus>;
    gzfwrite(buf: ArrayBuffer, size: long, nitems: long): Promise<long>
    gzfread(buf: ArrayBuffer, size: long, nitems: long): Promise<long>;
    gzclosew(): Promise<ReturnStatus>;
    gzcloser(): Promise<ReturnStatus>;
    gzwrite(buf: ArrayBuffer, len: long): Promise<long>;
    gzungetc(c: int): Promise<int>;
    gztell(): Promise<long>;
    gzsetparams(level: CompressLevel, strategy: CompressStrategy): Promise<ReturnStatus>;
    gzseek(offset: long, whence: OffsetReferencePoint): Promise<long>;
    gzrewind(): Promise<ReturnStatus>;
    gzread(buf: ArrayBuffer): Promise<long>;
    gzputs(str: string): Promise<int>;
    gzputc(c: int): Promise<int>;
    gzprintf(format: string, ...args: Array<string | number>): Promise<int>;
    gzoffset(): Promise<long>;
    gzgets(buf: ArrayBuffer): Promise<string>;
  }

  export class GZipInternal implements GZip {
    nativeGZFile : long = 0;
    
    public native gzdopenNative(fd: int, mode: string): void;
    public native gzbufferNative(size: long): int;
    public native gzopenNative(path: string, mode: string): void;
    public native gzeofNative(): int;
    public native gzdirectNative(): int;
    public native gzcloseNative(): ReturnStatus;
    public native gzclearerrNative(): void;
    public native gzerrorNative(): GzErrorOutputInfo;
    public native gzgetcNative(): int;
    public native gzflushNative(flush: CompressFlushMode): ReturnStatus;
    public native gzfwriteNative(buf: ArrayBuffer, size: long, nitems: long): long;
    public native gzfreadNative(buf: ArrayBuffer, size: long, nitems: long): long;
    public native gzclosewNative(): ReturnStatus;
    public native gzcloserNative(): ReturnStatus;
    public native gzwriteNative(buf: ArrayBuffer, len: long): long;
    public native gzungetcNative(c: int): int;
    public native gztellNative(): long;
    public native gzsetparamsNative(level: CompressLevel, strategy: CompressStrategy): ReturnStatus;
    public native gzseekNative(offset: long, whence: OffsetReferencePoint): long;
    public native gzrewindNative(): ReturnStatus;
    public native gzreadNative(buf: ArrayBuffer): long;
    public native gzputsNative(str: string): int;
    public native gzputcNative(c: int): int;
    public native gzprintfNative(format: string, ...args: Array<string | number>): int;
    public native gzoffsetNative(): long;
    public native gzgetsNative(buf: ArrayBuffer): string;

    public gzdopen(fd: int, mode: string): Promise<void> {
      let p: Promise<void> = new Promise<void>((resolve: (v:PromiseLike<void>) => void, reject: (error: Error) => void) : void => {
        let execFun = (): void => {
          this.gzdopenNative(fd, mode);
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

    public gzbuffer(size: long): Promise<int> {
      let p: Promise<int> = new Promise<int>((resolve: (v:int) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): int => {
          return this.gzbufferNative(size);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let result: int = e as int;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public gzopen(path: string, mode: string): Promise<void> {
      let p: Promise<void> = new Promise<void>((resolve: (v:PromiseLike<void>) => void, reject: (error: Error) => void) : void => {
        let execFun = (): void => {
          this.gzopenNative(path, mode);
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

    public gzeof(): Promise<int> {
      let p: Promise<int> = new Promise<int>((resolve: (v:int) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): int => {
          return this.gzeofNative();
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let result: int = e as int;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public gzdirect(): Promise<int> {
      let p: Promise<int> = new Promise<int>((resolve: (v:int) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): int => {
          return this.gzdirectNative();
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let result: int = e as int;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public gzclose(): Promise<ReturnStatus> {
      let p: Promise<ReturnStatus> = new Promise<ReturnStatus>((resolve: (v:ReturnStatus) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): ReturnStatus => {
          return this.gzcloseNative();
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let result: ReturnStatus = e as ReturnStatus;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public gzclearerr(): Promise<void> {
      let p: Promise<void> = new Promise<void>((resolve: (v:PromiseLike<void>) => void, reject: (error: Error) => void) : void => {
        let execFun = (): void => {
          this.gzclearerrNative();
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

    public gzerror(): Promise<GzErrorOutputInfo> {
      let p: Promise<GzErrorOutputInfo> = new Promise<GzErrorOutputInfo>((resolve: (v:GzErrorOutputInfo) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): GzErrorOutputInfo => {
          return this.gzerrorNative();
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let result: GzErrorOutputInfo = e as GzErrorOutputInfo;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public gzgetc(): Promise<int> {
      let p: Promise<int> = new Promise<int>((resolve: (v:int) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): int => {
          return this.gzgetcNative();
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let result: int = e as int;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public gzflush(flush: CompressFlushMode): Promise<ReturnStatus> {
      let p: Promise<ReturnStatus> = new Promise<ReturnStatus>((resolve: (v:ReturnStatus) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): ReturnStatus => {
          return this.gzflushNative(flush);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let result: ReturnStatus = e as ReturnStatus;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public gzfwrite(buf: ArrayBuffer, size: long, nitems: long): Promise<long> {
      let p: Promise<long> = new Promise<long>((resolve: (v:long) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): long => {
          return this.gzfwriteNative(buf, size, nitems);
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

    public gzfread(buf: ArrayBuffer, size: long, nitems: long): Promise<long> {
      let p: Promise<long> = new Promise<long>((resolve: (v:long) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): long => {
          return this.gzfreadNative(buf, size, nitems);
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

    public gzclosew(): Promise<ReturnStatus> {
      let p: Promise<ReturnStatus> = new Promise<ReturnStatus>((resolve: (v:ReturnStatus) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): ReturnStatus => {
          return this.gzclosewNative();
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let result: ReturnStatus = e as ReturnStatus;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public gzcloser(): Promise<ReturnStatus> {
      let p: Promise<ReturnStatus> = new Promise<ReturnStatus>((resolve: (v:ReturnStatus) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): ReturnStatus => {
          return this.gzcloserNative();
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let result: ReturnStatus = e as ReturnStatus;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public gzwrite(buf: ArrayBuffer, len: long): Promise<long> {
      let p: Promise<long> = new Promise<long>((resolve: (v:long) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): long => {
          return this.gzwriteNative(buf, len);
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

    public gzungetc(c: int): Promise<int> {
      let p: Promise<int> = new Promise<int>((resolve: (v:int) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): int => {
          return this.gzungetcNative(c);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let result: int = e as int;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public gztell(): Promise<long> {
      let p: Promise<long> = new Promise<long>((resolve: (v:long) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): long => {
          return this.gztellNative();
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

    public gzsetparams(level: CompressLevel, strategy: CompressStrategy): Promise<ReturnStatus> {
      let p: Promise<ReturnStatus> = new Promise<ReturnStatus>((resolve: (v:ReturnStatus) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): ReturnStatus => {
          return this.gzsetparamsNative(level, strategy);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let result: ReturnStatus = e as ReturnStatus;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public gzseek(offset: long, whence: OffsetReferencePoint): Promise<long> {
      let p: Promise<long> = new Promise<long>((resolve: (v:long) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): long => {
          return this.gzseekNative(offset, whence);
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

    public gzrewind(): Promise<ReturnStatus> {
      let p: Promise<ReturnStatus> = new Promise<ReturnStatus>((resolve: (v:ReturnStatus) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): ReturnStatus => {
          return this.gzrewindNative();
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let result: ReturnStatus = e as ReturnStatus;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public gzread(buf: ArrayBuffer): Promise<long> {
      let p: Promise<long> = new Promise<long>((resolve: (v:long) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): long => {
          return this.gzreadNative(buf);
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

    public gzputs(str: string): Promise<int> {
      let p: Promise<int> = new Promise<int>((resolve: (v:int) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): int => {
          return this.gzputsNative(str);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let result: int = e as int;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public gzputc(c: int): Promise<int> {
      let p: Promise<int> = new Promise<int>((resolve: (v:int) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): int => {
          return this.gzputcNative(c);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let result: int = e as int;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public gzprintf(format: string, ...args: Array<string | number>): Promise<int> {
      let p: Promise<int> = new Promise<int>((resolve: (v:int) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): int => {
          return this.gzprintfNative(format, ...args);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let result: int = e as int;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public gzoffset(): Promise<long> {
      let p: Promise<long> = new Promise<long>((resolve: (v:long) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): long => {
          return this.gzoffsetNative();
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

    public gzgets(buf: ArrayBuffer): Promise<string> {
      let p: Promise<string> = new Promise<string>((resolve: (v:string) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): string => {
          return this.gzgetsNative(buf);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let result: string = e as string;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }
  }

  export native function compressFilesNative(inFiles: Array<string>, outFile: string, options: Options): void;

  export function compressFiles(inFiles: Array<string>, outFile: string, options: Options): Promise<void> {
    let p: Promise<void> = new Promise<void>((resolve: (v:PromiseLike<void>) => void, reject: (error: Error) => void) : void => {
      let execFun = (): void => {
        zlib.compressFilesNative(inFiles, outFile, options);
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

  export native function getOriginalSizeNative(compressedFile: string): long;

  export function getOriginalSize(compressedFile: string): Promise<long> {
    let p: Promise<long> = new Promise<long>((resolve: (v:long) => void, reject: (error: BusinessError) => void) : void => {
      let execFun = (): long => {
        return zlib.getOriginalSizeNative(compressedFile);
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

  export native function createChecksumNative(isSync: boolean): Checksum;

  export function createChecksum(): Promise<Checksum> {
    let p: Promise<Checksum> = new Promise<Checksum>((resolve: (v:Checksum) => void, reject: (error: BusinessError) => void) : void => {
      let execFun = (): Checksum => {
        return zlib.createChecksumNative(false);
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

  function createChecksumSync(): Checksum {
    return zlib.createChecksumNative(true);
  }

  export native function createGZipNative(isSync: boolean): GZip;

  function createGZip(): Promise<GZip> {
    let p: Promise<GZip> = new Promise<GZip>((resolve: (v:GZip) => void, reject: (error: BusinessError) => void) : void => {
      let execFun = (): GZip => {
        return zlib.createGZipNative(false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let result: GZip = e as GZip;
        resolve(result);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  function createGZipSync(): GZip {
    return zlib.createGZipNative(true);
  }
}
