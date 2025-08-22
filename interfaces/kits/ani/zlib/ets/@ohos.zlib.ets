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

import { AsyncCallback, BusinessError, RecordData } from '@ohos.base';

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

  export enum ParallelStrategy {
    PARALLEL_STRATEGY_SEQUENTIAL = 0,
    PARALLEL_STRATEGY_PARALLEL_DECOMPRESSION = 1
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
    ERRNO = -1,
    STREAM_ERROR = -2,
    DATA_ERROR = -3,
    MEM_ERROR = -4,
    BUF_ERROR = -5
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
    parallel?: ParallelStrategy;
  }

  class OptionsInner implements Options {
    level?: CompressLevel | undefined;
    memLevel?: MemLevel | undefined;
    strategy?: CompressStrategy | undefined;
    parallel?: ParallelStrategy | undefined;
  }

  export interface GzErrorOutputInfo {
    status: ReturnStatus;
    statusMsg: string;
  }

  class GzErrorOutputInfoInner implements GzErrorOutputInfo {
    status: ReturnStatus = ReturnStatus.OK;
    statusMsg: string;

    constructor() { }
    constructor(status: ReturnStatus, statusMsg: string) {
        this.status = status;
        this.statusMsg = statusMsg;
    }
  }

  export interface ZStream {
    nextIn?: ArrayBuffer;
    availableIn?: int;
    totalIn?: long;
    nextOut?: ArrayBuffer;
    availableOut?: int;
    totalOut?: long;
    dataType?: int;
    adler?: long;
  }

  class ZStreamInner implements ZStream {
    nextIn?: ArrayBuffer | undefined;
    availableIn?: int | undefined;
    totalIn?: long | undefined;
    nextOut?: ArrayBuffer | undefined;
    availableOut?: int | undefined;
    totalOut?: long | undefined;
    dataType?: int | undefined;
    adler?: long | undefined;

    constructor(availableIn?: int,
      totalIn?: long,
      availableOut?: int,
      totalOut?: long,
      dataType?: int,
      adler?: long) {
        this.availableIn = availableIn;
        this.totalIn = totalIn;
        this.availableOut = availableOut;
        this.totalOut = totalOut;
        this.dataType = dataType;
        this.adler = adler;
    }
  }

  export interface ZipOutputInfo {
    status: ReturnStatus;
    destLen: long;
  }

  class ZipOutputInfoInner implements ZipOutputInfo {
    status: ReturnStatus = ReturnStatus.OK;
    destLen: long;

    constructor() { }
    constructor(status: ReturnStatus, destLen: long) {
        this.status = status;
        this.destLen = destLen;
    }
  }

  export interface DecompressionOutputInfo {
    status: ReturnStatus;
    destLength: long;
    sourceLength: long;
  }

  class DecompressionOutputInfoInner implements DecompressionOutputInfo {
    status: ReturnStatus = ReturnStatus.OK;
    destLength: long;
    sourceLength: long;

    constructor() { }
    constructor(status: ReturnStatus, destLength: long, sourceLength: long) {
        this.status = status;
        this.destLength = destLength;
        this.sourceLength = sourceLength;
    }
  }

  export interface GzHeader {
    isText?: boolean;
    os?: int;
    time?: long;
    xflags?: int;
    extra?: ArrayBuffer;
    extraLen?: int;
    name?: ArrayBuffer;
    comment?: ArrayBuffer;
    hcrc?: boolean;
    done?: boolean;
  }

  class GzHeaderInner implements GzHeader {
    isText?: boolean | undefined;
    os?: int | undefined;
    time?: long | undefined;
    xflags?: int | undefined;
    extra?: ArrayBuffer | undefined;
    extraLen?: int | undefined;
    name?: ArrayBuffer | undefined;
    comment?: ArrayBuffer | undefined;
    hcrc?: boolean | undefined;
    done?: boolean | undefined;
  }

  export interface DictionaryOutputInfo {
    status: ReturnStatus;
    dictionaryLength: int;
  }

  class DictionaryOutputInfoInner implements DictionaryOutputInfo {
    status: ReturnStatus = ReturnStatus.OK;
    dictionaryLength: int;

    constructor() { }
    constructor(status: ReturnStatus, dictionaryLength: int) {
        this.status = status;
        this.dictionaryLength = dictionaryLength;
    }
  }

  export interface DeflatePendingOutputInfo {
    status: ReturnStatus;
    pending: int;
    bits: int;
  }

  class DeflatePendingOutputInfoInner implements DeflatePendingOutputInfo {
    status: ReturnStatus = ReturnStatus.OK;
    pending: int;
    bits: int;

    constructor() { }
    constructor(status: ReturnStatus, pending: int, bits: int) {
        this.status = status;
        this.pending = pending;
        this.bits = bits;
    }
  }

  type InflateBackInputCallback = (inDesc: RecordData) => ArrayBuffer;
  type InflateBackOutputCallback = (outDesc: RecordData, buf: ArrayBuffer, length: int) => int;

  export function compressFile(inFile: string, outFile: string, options: Options, callback: AsyncCallback<void>): void {
    let execFun = (): void => {
      zlib.compressFileNative(inFile, outFile, options);
    };
    let p1 = taskpool.execute(execFun);
    p1.then(() => {
      callback(null, undefined);
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
      callback(null, undefined);
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
      callback(null, undefined);
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
    @JSONStringifyIgnore
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

  export interface Zip {
    getZStream(): Promise<ZStream | undefined>;
    zlibVersion(): Promise<string>;
    zlibCompileFlags(): Promise<int>;
    compress(dest: ArrayBuffer, source: ArrayBuffer, sourceLen?: long): Promise<ZipOutputInfo>;
    compress2(dest: ArrayBuffer, source: ArrayBuffer, level: CompressLevel, sourceLen?: long): Promise<ZipOutputInfo>;
    compressBound(sourceLen: int): Promise<int>;
    uncompress(dest: ArrayBuffer, source: ArrayBuffer, sourceLen?: long): Promise<ZipOutputInfo>;
    uncompress2(dest: ArrayBuffer, source: ArrayBuffer, sourceLen?: long): Promise<DecompressionOutputInfo>;
    inflateValidate(strm: ZStream, check: int): Promise<ReturnStatus>;
    inflateSyncPoint(strm: ZStream): Promise<ReturnStatus>;
    inflateSync(strm: ZStream): Promise<ReturnStatus>;
    inflateSetDictionary(strm: ZStream, dictionary: ArrayBuffer): Promise<ReturnStatus>;
    inflateResetKeep(strm: ZStream): Promise<ReturnStatus>;
    inflateReset2(strm: ZStream, windowBits: int): Promise<ReturnStatus>;
    inflateReset(strm: ZStream): Promise<ReturnStatus>;
    inflatePrime(strm: ZStream, bits: int, value: int): Promise<ReturnStatus>;
    inflateMark(strm: ZStream): Promise<int>;
    inflateInit2(strm: ZStream, windowBits: int): Promise<ReturnStatus>;
    inflateInit(strm: ZStream): Promise<ReturnStatus>;
    inflateGetHeader(strm: ZStream, header: GzHeader): Promise<ReturnStatus>;
    inflateGetDictionary(strm: ZStream, dictionary: ArrayBuffer): Promise<DictionaryOutputInfo>;
    inflateEnd(strm: ZStream): Promise<ReturnStatus>;
    inflateCopy(source: Zip): Promise<ReturnStatus>;
    inflateCodesUsed(strm: ZStream): Promise<long>;
    inflateBackInit(strm: ZStream, windowBits: long, window: ArrayBuffer): Promise<ReturnStatus>;
    inflateBackEnd(strm: ZStream): Promise<ReturnStatus>;
    inflateBack(strm: ZStream, backIn: InflateBackInputCallback, inDesc: RecordData, backOut: InflateBackOutputCallback, outDesc: RecordData): Promise<ReturnStatus>;
    inflate(strm: ZStream, flush: CompressFlushMode): Promise<ReturnStatus>;
    deflateInit(strm: ZStream, level: CompressLevel): Promise<ReturnStatus>;
    deflateInit2(strm: ZStream, level: CompressLevel, method: CompressMethod, windowBits: int, memLevel: MemLevel, strategy: CompressStrategy): Promise<ReturnStatus>;
    deflate(strm: ZStream, flush: CompressFlushMode): Promise<ReturnStatus>;
    deflateEnd(strm: ZStream): Promise<ReturnStatus>;
    deflateBound(strm: ZStream, sourceLength: long): Promise<int>;
    deflateSetHeader(strm: ZStream, head: GzHeader): Promise<ReturnStatus>;
    deflateCopy(source: Zip): Promise<ReturnStatus>;
    deflateSetDictionary(strm: ZStream, dictionary: ArrayBuffer): Promise<ReturnStatus>;
    deflateGetDictionary(strm: ZStream, dictionary: ArrayBuffer): Promise<DictionaryOutputInfo>;
    deflateTune(strm: ZStream, goodLength: int, maxLazy: int, niceLength: int, maxChain: int): Promise<ReturnStatus>;
    deflateReset(strm: ZStream): Promise<ReturnStatus>;
    deflateResetKeep(strm: ZStream): Promise<ReturnStatus>;
    deflatePending(strm: ZStream): Promise<DeflatePendingOutputInfo>;
    deflateParams(strm: ZStream, level: CompressLevel, strategy: CompressStrategy): Promise<ReturnStatus>;
    deflatePrime(strm: ZStream, bits: int, value: int): Promise<ReturnStatus>;
  }

  class ZipCleaner {
    public ptr: long = 0;

    constructor(ptr: long) {
      this.ptr = ptr;
    }

    public native zipClean(): void;
  }

  export function callback(zipCleaner: ZipCleaner): void {
    zipCleaner.zipClean();
  }

  let destroyRegister = new FinalizationRegistry<ZipCleaner>(callback);
  let unregisterToken = new object();

  export class ZipInternal implements Zip {
    @JSONStringifyIgnore
    nativeZStream: long = 0;
    @JSONStringifyIgnore
    private zipCleaner: ZipCleaner | null = null;

    registerZipCleaner(): void {
      if (this.nativeZStream == 0) {
        return;
      }
      this.zipCleaner = new ZipCleaner(this.nativeZStream);
      destroyRegister.register(this, this.zipCleaner!, unregisterToken);
    }

    unregisterZipCleaner(): void {
      destroyRegister.unregister(unregisterToken);
    }

    public native getZStreamNative(): ZStream | undefined;
    public native zlibVersionNative(): string;
    public native zlibCompileFlagsNative(): int;
    public native compressNative(dest: ArrayBuffer, source: ArrayBuffer): ZipOutputInfo;
    public native compressWithSourceLenNative(dest: ArrayBuffer, source: ArrayBuffer, sourceLen: long): ZipOutputInfo;
    public native compress2Native(dest: ArrayBuffer, source: ArrayBuffer, level: CompressLevel): ZipOutputInfo;
    public native compress2WithSourceLenNative(dest: ArrayBuffer, source: ArrayBuffer, level: CompressLevel, sourceLen: long): ZipOutputInfo;
    public native compressBoundNative(sourceLen: int): int;
    public native uncompressNative(dest: ArrayBuffer, source: ArrayBuffer): ZipOutputInfo;
    public native uncompressWithSourceLenNative(dest: ArrayBuffer, source: ArrayBuffer, sourceLen: long): ZipOutputInfo;
    public native uncompress2Native(dest: ArrayBuffer, source: ArrayBuffer): DecompressionOutputInfo;
    public native uncompress2WithSourceLenNative(dest: ArrayBuffer, source: ArrayBuffer, sourceLen: long): DecompressionOutputInfo;
    public native inflateValidateNative(strm: ZStream, check: int): ReturnStatus;
    public native inflateSyncPointNative(strm: ZStream): ReturnStatus;
    public native inflateSyncNative(strm: ZStream): ReturnStatus;
    public native inflateSetDictionaryNative(strm: ZStream, dictionary: ArrayBuffer): ReturnStatus;
    public native inflateResetKeepNative(strm: ZStream): ReturnStatus;
    public native inflateReset2Native(strm: ZStream, windowBits: int): ReturnStatus;
    public native inflateResetNative(strm: ZStream): ReturnStatus;
    public native inflatePrimeNative(strm: ZStream, bits: int, value: int): ReturnStatus;
    public native inflateMarkNative(strm: ZStream): int;
    public native inflateInit2Native(strm: ZStream, windowBits: int): ReturnStatus;
    public native inflateInitNative(strm: ZStream): ReturnStatus;
    public native inflateGetHeaderNative(strm: ZStream, header: GzHeader): ReturnStatus;
    public native inflateGetDictionaryNative(strm: ZStream, dictionary: ArrayBuffer): DictionaryOutputInfo;
    public native inflateEndNative(strm: ZStream): ReturnStatus;
    public native inflateCopyNative(source: Zip): ReturnStatus;
    public native inflateCodesUsedNative(strm: ZStream): long;
    public native inflateBackInitNative(strm: ZStream, windowBits: long, window: ArrayBuffer): ReturnStatus;
    public native inflateBackEndNative(strm: ZStream): ReturnStatus;
    public native inflateBackNative(strm: ZStream, backIn: InflateBackInputCallback, inDesc: RecordData, backOut: InflateBackOutputCallback, outDesc: RecordData): ReturnStatus;
    public native inflateNative(strm: ZStream, flush: CompressFlushMode): ReturnStatus;
    public native deflateInitNative(strm: ZStream, level: CompressLevel): ReturnStatus;
    public native deflateInit2Native(strm: ZStream, level: CompressLevel, method: CompressMethod, windowBits: int, memLevel: MemLevel, strategy: CompressStrategy): ReturnStatus;
    public native deflateNative(strm: ZStream, flush: CompressFlushMode): ReturnStatus;
    public native deflateEndNative(strm: ZStream): ReturnStatus;
    public native deflateBoundNative(strm: ZStream, sourceLength: long): int;
    public native deflateSetHeaderNative(strm: ZStream, head: GzHeader): ReturnStatus;
    public native deflateCopyNative(source: Zip): ReturnStatus;
    public native deflateSetDictionaryNative(strm: ZStream, dictionary: ArrayBuffer): ReturnStatus;
    public native deflateGetDictionaryNative(strm: ZStream, dictionary: ArrayBuffer): DictionaryOutputInfo;
    public native deflateTuneNative(strm: ZStream, goodLength: int, maxLazy: int, niceLength: int, maxChain: int): ReturnStatus;
    public native deflateResetNative(strm: ZStream): ReturnStatus;
    public native deflateResetKeepNative(strm: ZStream): ReturnStatus;
    public native deflatePendingNative(strm: ZStream): DeflatePendingOutputInfo;
    public native deflateParamsNative(strm: ZStream, level: CompressLevel, strategy: CompressStrategy): ReturnStatus;
    public native deflatePrimeNative(strm: ZStream, bits: int, value: int): ReturnStatus;

    public getZStream(): Promise<ZStream | undefined> {
      let p = new Promise<ZStream | undefined>((resolve: (v: ZStream | undefined) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ZStream | undefined => {
          return this.getZStreamNative();
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          if (e) {
            let result: ZStream = e as ZStream;
            resolve(result);
          } else {
            resolve(undefined);
          }
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public zlibVersion(): Promise<string> {
      let p = new Promise<string>((resolve: (v: string) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): string => {
          return this.zlibVersionNative();
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

    public zlibCompileFlags(): Promise<int> {
      let p = new Promise<int>((resolve: (v: int) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): int => {
          return this.zlibCompileFlagsNative();
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

    public compress(dest: ArrayBuffer, source: ArrayBuffer, sourceLen?: long): Promise<ZipOutputInfo> {
      let p = new Promise<ZipOutputInfo>((resolve: (v: ZipOutputInfo) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ZipOutputInfo => {
          return sourceLen === undefined ? this.compressNative(dest, source) :
                                           this.compressWithSourceLenNative(dest, source, sourceLen);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let result: ZipOutputInfo = e as ZipOutputInfo;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public compress2(dest: ArrayBuffer, source: ArrayBuffer, level: CompressLevel, sourceLen?: long,): Promise<ZipOutputInfo> {
      let p = new Promise<ZipOutputInfo>((resolve: (v: ZipOutputInfo) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ZipOutputInfo => {
          return sourceLen === undefined ? this.compress2Native(dest, source, level) :
                                           this.compress2WithSourceLenNative(dest, source, level, sourceLen);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let result: ZipOutputInfo = e as ZipOutputInfo;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public compressBound(sourceLen: int): Promise<int> {
      let p = new Promise<int>((resolve: (v: int) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): int => {
          return this.compressBoundNative(sourceLen);
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

    public uncompress(dest: ArrayBuffer, source: ArrayBuffer, sourceLen?: long): Promise<ZipOutputInfo> {
      let p = new Promise<ZipOutputInfo>((resolve: (v: ZipOutputInfo) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ZipOutputInfo => {
          return sourceLen === undefined ? this.uncompressNative(dest, source) :
                                           this.uncompressWithSourceLenNative(dest, source, sourceLen);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let result: ZipOutputInfo = e as ZipOutputInfo;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public uncompress2(dest: ArrayBuffer, source: ArrayBuffer, sourceLen?: long): Promise<DecompressionOutputInfo> {
      let p = new Promise<DecompressionOutputInfo>((resolve: (v: DecompressionOutputInfo) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): DecompressionOutputInfo => {
          return sourceLen === undefined ? this.uncompress2Native(dest, source) :
                                           this.uncompress2WithSourceLenNative(dest, source, sourceLen);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let result: DecompressionOutputInfo = e as DecompressionOutputInfo;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public inflateValidate(strm: ZStream, check: int): Promise<ReturnStatus> {
      let p = new Promise<ReturnStatus>((resolve: (v: ReturnStatus) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ReturnStatus => {
          return this.inflateValidateNative(strm, check);
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

    public inflateSyncPoint(strm: ZStream): Promise<ReturnStatus> {
      let p = new Promise<ReturnStatus>((resolve: (v: ReturnStatus) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ReturnStatus => {
          return this.inflateSyncPointNative(strm);
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

    public inflateSync(strm: ZStream): Promise<ReturnStatus> {
      let p = new Promise<ReturnStatus>((resolve: (v: ReturnStatus) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ReturnStatus => {
          return this.inflateSyncNative(strm);
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

    public inflateSetDictionary(strm: ZStream, dictionary: ArrayBuffer): Promise<ReturnStatus> {
      let p = new Promise<ReturnStatus>((resolve: (v: ReturnStatus) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ReturnStatus => {
          return this.inflateSetDictionaryNative(strm, dictionary);
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

    public inflateResetKeep(strm: ZStream): Promise<ReturnStatus> {
      let p = new Promise<ReturnStatus>((resolve: (v: ReturnStatus) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ReturnStatus => {
          return this.inflateResetKeepNative(strm);
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

    public inflateReset2(strm: ZStream, windowBits: int): Promise<ReturnStatus> {
      let p = new Promise<ReturnStatus>((resolve: (v: ReturnStatus) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ReturnStatus => {
          return this.inflateReset2Native(strm, windowBits);
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

    public inflateReset(strm: ZStream): Promise<ReturnStatus> {
      let p = new Promise<ReturnStatus>((resolve: (v: ReturnStatus) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ReturnStatus => {
          return this.inflateResetNative(strm);
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

    public inflatePrime(strm: ZStream, bits: int, value: int): Promise<ReturnStatus> {
      let p = new Promise<ReturnStatus>((resolve: (v: ReturnStatus) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ReturnStatus => {
          return this.inflatePrimeNative(strm, bits, value);
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

    public inflateMark(strm: ZStream): Promise<int> {
      let p = new Promise<int>((resolve: (v: int) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): int => {
          return this.inflateMarkNative(strm);
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

    public inflateInit2(strm: ZStream, windowBits: int): Promise<ReturnStatus> {
      let p = new Promise<ReturnStatus>((resolve: (v: ReturnStatus) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ReturnStatus => {
          return this.inflateInit2Native(strm, windowBits);
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

    public inflateInit(strm: ZStream): Promise<ReturnStatus> {
      let p = new Promise<ReturnStatus>((resolve: (v: ReturnStatus) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ReturnStatus => {
          return this.inflateInitNative(strm);
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

    public inflateGetHeader(strm: ZStream, header: GzHeader): Promise<ReturnStatus> {
      let p = new Promise<ReturnStatus>((resolve: (v: ReturnStatus) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ReturnStatus => {
          return this.inflateGetHeaderNative(strm, header);
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

    public inflateGetDictionary(strm: ZStream, dictionary: ArrayBuffer): Promise<DictionaryOutputInfo> {
      let p = new Promise<DictionaryOutputInfo>((resolve: (v: DictionaryOutputInfo) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): DictionaryOutputInfo => {
          return this.inflateGetDictionaryNative(strm, dictionary);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let result: DictionaryOutputInfo = e as DictionaryOutputInfo;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public inflateEnd(strm: ZStream): Promise<ReturnStatus> {
      let p = new Promise<ReturnStatus>((resolve: (v: ReturnStatus) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ReturnStatus => {
          return this.inflateEndNative(strm);
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

    public inflateCopy(source: Zip): Promise<ReturnStatus> {
      let p = new Promise<ReturnStatus>((resolve: (v: ReturnStatus) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ReturnStatus => {
          return this.inflateCopyNative(source);
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

    public inflateCodesUsed(strm: ZStream): Promise<long> {
      let p = new Promise<long>((resolve: (v: long) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): long => {
          return this.inflateCodesUsedNative(strm);
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

    public inflateBackInit(strm: ZStream, windowBits: long, window: ArrayBuffer): Promise<ReturnStatus> {
      let p = new Promise<ReturnStatus>((resolve: (v: ReturnStatus) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ReturnStatus => {
          return this.inflateBackInitNative(strm, windowBits, window);
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

    public inflateBackEnd(strm: ZStream): Promise<ReturnStatus> {
      let p = new Promise<ReturnStatus>((resolve: (v: ReturnStatus) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ReturnStatus => {
          return this.inflateBackEndNative(strm);
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

    public inflateBack(strm: ZStream, backIn: InflateBackInputCallback, inDesc: RecordData, backOut: InflateBackOutputCallback, outDesc: RecordData): Promise<ReturnStatus> {
      let p = new Promise<ReturnStatus>((resolve: (v: ReturnStatus) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ReturnStatus => {
          return this.inflateBackNative(strm, backIn, inDesc, backOut, outDesc);
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

    public inflate(strm: ZStream, flush: CompressFlushMode): Promise<ReturnStatus> {
      let p = new Promise<ReturnStatus>((resolve: (v: ReturnStatus) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ReturnStatus => {
          return this.inflateNative(strm, flush);
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

    public deflateInit(strm: ZStream, level: CompressLevel): Promise<ReturnStatus> {
      let p = new Promise<ReturnStatus>((resolve: (v: ReturnStatus) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ReturnStatus => {
          return this.deflateInitNative(strm, level);
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

    public deflateInit2(strm: ZStream, level: CompressLevel, method: CompressMethod, windowBits: int, memLevel: MemLevel, strategy: CompressStrategy): Promise<ReturnStatus> {
      let p = new Promise<ReturnStatus>((resolve: (v: ReturnStatus) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ReturnStatus => {
          return this.deflateInit2Native(strm, level, method, windowBits, memLevel, strategy);
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

    public deflate(strm: ZStream, flush: CompressFlushMode): Promise<ReturnStatus> {
      let p = new Promise<ReturnStatus>((resolve: (v: ReturnStatus) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ReturnStatus => {
          return this.deflateNative(strm, flush);
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

    public deflateEnd(strm: ZStream): Promise<ReturnStatus> {
      let p = new Promise<ReturnStatus>((resolve: (v: ReturnStatus) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ReturnStatus => {
          return this.deflateEndNative(strm);
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

    public deflateBound(strm: ZStream, sourceLength: long): Promise<int> {
      let p = new Promise<int>((resolve: (v: int) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): int => {
          return this.deflateBoundNative(strm, sourceLength);
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

    public deflateSetHeader(strm: ZStream, head: GzHeader): Promise<ReturnStatus> {
      let p = new Promise<ReturnStatus>((resolve: (v: ReturnStatus) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ReturnStatus => {
          return this.deflateSetHeaderNative(strm, head);
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

    public deflateCopy(source: Zip): Promise<ReturnStatus> {
      let p = new Promise<ReturnStatus>((resolve: (v: ReturnStatus) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ReturnStatus => {
          return this.deflateCopyNative(source);
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

    public deflateSetDictionary(strm: ZStream, dictionary: ArrayBuffer): Promise<ReturnStatus> {
      let p = new Promise<ReturnStatus>((resolve: (v: ReturnStatus) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ReturnStatus => {
          return this.deflateSetDictionaryNative(strm, dictionary);
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

    public deflateGetDictionary(strm: ZStream, dictionary: ArrayBuffer): Promise<DictionaryOutputInfo> {
      let p = new Promise<DictionaryOutputInfo>((resolve: (v: DictionaryOutputInfo) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): DictionaryOutputInfo => {
          return this.deflateGetDictionaryNative(strm, dictionary);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let result: DictionaryOutputInfo = e as DictionaryOutputInfo;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public deflateTune(strm: ZStream, goodLength: int, maxLazy: int, niceLength: int, maxChain: int): Promise<ReturnStatus> {
      let p = new Promise<ReturnStatus>((resolve: (v: ReturnStatus) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ReturnStatus => {
          return this.deflateTuneNative(strm, goodLength, maxLazy, niceLength, maxChain);
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

    public deflateReset(strm: ZStream): Promise<ReturnStatus> {
      let p = new Promise<ReturnStatus>((resolve: (v: ReturnStatus) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ReturnStatus => {
          return this.deflateResetNative(strm);
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

    public deflateResetKeep(strm: ZStream): Promise<ReturnStatus> {
      let p = new Promise<ReturnStatus>((resolve: (v: ReturnStatus) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ReturnStatus => {
          return this.deflateResetKeepNative(strm);
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

    public deflatePending(strm: ZStream): Promise<DeflatePendingOutputInfo> {
      let p = new Promise<DeflatePendingOutputInfo>((resolve: (v: DeflatePendingOutputInfo) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): DeflatePendingOutputInfo => {
          return this.deflatePendingNative(strm);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: NullishType) => {
          let result: DeflatePendingOutputInfo = e as DeflatePendingOutputInfo;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public deflateParams(strm: ZStream, level: CompressLevel, strategy: CompressStrategy): Promise<ReturnStatus> {
      let p = new Promise<ReturnStatus>((resolve: (v: ReturnStatus) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ReturnStatus => {
          return this.deflateParamsNative(strm, level, strategy);
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

    public deflatePrime(strm: ZStream, bits: int, value: int): Promise<ReturnStatus> {
      let p = new Promise<ReturnStatus>((resolve: (v: ReturnStatus) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ReturnStatus => {
          return this.deflatePrimeNative(strm, bits, value);
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

  export native function createZipNative(isSync: boolean): Zip;

  function createZip(): Promise<Zip> {
    let p: Promise<Zip> = new Promise<Zip>((resolve: (v:Zip) => void, reject: (error: BusinessError) => void) : void => {
      let execFun = (): Zip => {
        return zlib.createZipNative(false);
      };
      let p1 = taskpool.execute(execFun);
      p1.then((e: NullishType) => {
        let result: Zip = e as Zip;
        resolve(result);
      }, (err: Error): void => {
        reject(err as BusinessError);
      });
    });
    return p;
  }

  function createZipSync(): Zip {
    return zlib.createZipNative(true);
  }
}
