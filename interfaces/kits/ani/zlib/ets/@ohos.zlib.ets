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

  const MIN_ASCII: int = 0;
  const MAX_ASCII: int = 255;
  const MIN_WINDOWBITS: long = 8;
  const MAX_WINDOWBITS: long = 15;
  const MIN_BITS: int = 0;
  const MAX_BITS: int = 16;
  const ERROR_PARAM_CHECK_ERROR: int = 401;
  const PARAM_CHECK_FAILED: string = 'The parameter check failed';
  function createBusinessError(code: int, message: string) {
    let err = new BusinessError();
    err.code = code;
    err.name = 'Error';
    err.message = message;
    return err;
  }

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
    private native adler32Native(adler: long, buf: ArrayBuffer): long;
    private native adler32CombineNative(adler1: long, adler2: long, len2: long): long;
    private native crc32Native(crc: long, buf: ArrayBuffer): long;
    private native crc32CombineNative(crc1: long, crc2: long, len2: long): long;
    private native crc64Native(crc: long, buf: ArrayBuffer): long;
    private native getCrcTableNative(): Array<long>;
    private native getCrc64TableNative(): Array<long>;

    public adler32(adler: long, buf: ArrayBuffer): Promise<long> {
      let p: Promise<long> = new Promise<long>((resolve: (v:long) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): long => {
          return this.adler32Native(adler, buf);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: Any) => {
          let result: long = e as long;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public adler32Combine(adler1: long, adler2: long, len2: long): Promise<long> {
      if (len2 < 0) {
        throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_CHECK_FAILED);
      }
      let p: Promise<long> = new Promise<long>((resolve: (v:long) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): long => {
          return this.adler32CombineNative(adler1, adler2, len2);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
          let result: long = e as long;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public crc32Combine(crc1: long, crc2: long, len2: long): Promise<long> {
      if (len2 < 0) {
        throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_CHECK_FAILED);
      }
      let p: Promise<long> = new Promise<long>((resolve: (v:long) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): long => {
          return this.crc32CombineNative(crc1, crc2, len2);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
    private nativeGZFile : long = 0;

    private native gzdopenNative(fd: int, mode: string): void;
    private native gzbufferNative(size: long): int;
    private native gzopenNative(path: string, mode: string): void;
    private native gzeofNative(): int;
    private native gzdirectNative(): int;
    private native gzcloseNative(): ReturnStatus;
    private native gzclearerrNative(): void;
    private native gzerrorNative(): GzErrorOutputInfo;
    private native gzgetcNative(): int;
    private native gzflushNative(flush: CompressFlushMode): ReturnStatus;
    private native gzfwriteNative(buf: ArrayBuffer, size: long, nitems: long): long;
    private native gzfreadNative(buf: ArrayBuffer, size: long, nitems: long): long;
    private native gzclosewNative(): ReturnStatus;
    private native gzcloserNative(): ReturnStatus;
    private native gzwriteNative(buf: ArrayBuffer, len: long): long;
    private native gzungetcNative(c: int): int;
    private native gztellNative(): long;
    private native gzsetparamsNative(level: CompressLevel, strategy: CompressStrategy): ReturnStatus;
    private native gzseekNative(offset: long, whence: OffsetReferencePoint): long;
    private native gzrewindNative(): ReturnStatus;
    private native gzreadNative(buf: ArrayBuffer): long;
    private native gzputsNative(str: string): int;
    private native gzputcNative(c: int): int;
    private native gzprintfNative(format: string, ...args: Array<string | number>): int;
    private native gzoffsetNative(): long;
    private native gzgetsNative(buf: ArrayBuffer): string;

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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
          let result: ReturnStatus = e as ReturnStatus;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public gzfwrite(buf: ArrayBuffer, size: long, nitems: long): Promise<long> {
      if (buf.byteLength == 0 || size < 0 || nitems < 0 || BigInt(buf.byteLength) < BigInt(size) * BigInt(nitems)) {
        throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_CHECK_FAILED);
      }
      let p: Promise<long> = new Promise<long>((resolve: (v:long) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): long => {
          return this.gzfwriteNative(buf, size, nitems);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: Any) => {
          let result: long = e as long;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public gzfread(buf: ArrayBuffer, size: long, nitems: long): Promise<long> {
      if (buf.byteLength == 0 || size < 0 || nitems < 0 || BigInt(buf.byteLength) < BigInt(size) * BigInt(nitems)) {
        throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_CHECK_FAILED);
      }
      let p: Promise<long> = new Promise<long>((resolve: (v:long) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): long => {
          return this.gzfreadNative(buf, size, nitems);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
          let result: ReturnStatus = e as ReturnStatus;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public gzwrite(buf: ArrayBuffer, len: long): Promise<long> {
      if (buf.byteLength == 0 || len > (buf.byteLength as long)) {
        throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_CHECK_FAILED);
      }
      let p: Promise<long> = new Promise<long>((resolve: (v:long) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): long => {
          return this.gzwriteNative(buf, len);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: Any) => {
          let result: long = e as long;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public gzungetc(c: int): Promise<int> {
      if (c < MIN_ASCII || c > MAX_ASCII) {
        throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_CHECK_FAILED);
      }
      let p: Promise<int> = new Promise<int>((resolve: (v:int) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): int => {
          return this.gzungetcNative(c);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
          let result: ReturnStatus = e as ReturnStatus;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public gzread(buf: ArrayBuffer): Promise<long> {
      if (buf.byteLength == 0) {
        throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_CHECK_FAILED);
      }
      let p: Promise<long> = new Promise<long>((resolve: (v:long) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): long => {
          return this.gzreadNative(buf);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
          let result: int = e as int;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public gzputc(c: int): Promise<int> {
      if (c < MIN_ASCII || c > MAX_ASCII) {
        throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_CHECK_FAILED);
      }
      let p: Promise<int> = new Promise<int>((resolve: (v:int) => void, reject: (error: BusinessError) => void) : void => {
        let execFun = (): int => {
          return this.gzputcNative(c);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
    private ptr: long = 0;

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
    private nativeZStream: long = 0;
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

    private native getZStreamNative(): ZStream | undefined;
    private native zlibVersionNative(): string;
    private native zlibCompileFlagsNative(): int;
    private native compressNative(dest: ArrayBuffer, source: ArrayBuffer): ZipOutputInfo;
    private native compressWithSourceLenNative(dest: ArrayBuffer, source: ArrayBuffer, sourceLen: long): ZipOutputInfo;
    private native compress2Native(dest: ArrayBuffer, source: ArrayBuffer, level: CompressLevel): ZipOutputInfo;
    private native compress2WithSourceLenNative(dest: ArrayBuffer, source: ArrayBuffer, level: CompressLevel, sourceLen: long): ZipOutputInfo;
    private native compressBoundNative(sourceLen: int): int;
    private native uncompressNative(dest: ArrayBuffer, source: ArrayBuffer): ZipOutputInfo;
    private native uncompressWithSourceLenNative(dest: ArrayBuffer, source: ArrayBuffer, sourceLen: long): ZipOutputInfo;
    private native uncompress2Native(dest: ArrayBuffer, source: ArrayBuffer): DecompressionOutputInfo;
    private native uncompress2WithSourceLenNative(dest: ArrayBuffer, source: ArrayBuffer, sourceLen: long): DecompressionOutputInfo;
    private native inflateValidateNative(strm: ZStream, check: int): ReturnStatus;
    private native inflateSyncPointNative(strm: ZStream): ReturnStatus;
    private native inflateSyncNative(strm: ZStream): ReturnStatus;
    private native inflateSetDictionaryNative(strm: ZStream, dictionary: ArrayBuffer): ReturnStatus;
    private native inflateResetKeepNative(strm: ZStream): ReturnStatus;
    private native inflateReset2Native(strm: ZStream, windowBits: int): ReturnStatus;
    private native inflateResetNative(strm: ZStream): ReturnStatus;
    private native inflatePrimeNative(strm: ZStream, bits: int, value: int): ReturnStatus;
    private native inflateMarkNative(strm: ZStream): int;
    private native inflateInit2Native(strm: ZStream, windowBits: int): ReturnStatus;
    private native inflateInitNative(strm: ZStream): ReturnStatus;
    private native inflateGetHeaderNative(strm: ZStream, header: GzHeader): ReturnStatus;
    private native inflateGetDictionaryNative(strm: ZStream, dictionary: ArrayBuffer): DictionaryOutputInfo;
    private native inflateEndNative(strm: ZStream): ReturnStatus;
    private native inflateCopyNative(source: Zip): ReturnStatus;
    private native inflateCodesUsedNative(strm: ZStream): long;
    private native inflateBackInitNative(strm: ZStream, windowBits: long, window: ArrayBuffer): ReturnStatus;
    private native inflateBackEndNative(strm: ZStream): ReturnStatus;
    private native inflateBackNative(strm: ZStream, backIn: InflateBackInputCallback, inDesc: RecordData, backOut: InflateBackOutputCallback, outDesc: RecordData): ReturnStatus;
    private native inflateNative(strm: ZStream, flush: CompressFlushMode): ReturnStatus;
    private native deflateInitNative(strm: ZStream, level: CompressLevel): ReturnStatus;
    private native deflateInit2Native(strm: ZStream, level: CompressLevel, method: CompressMethod, windowBits: int, memLevel: MemLevel, strategy: CompressStrategy): ReturnStatus;
    private native deflateNative(strm: ZStream, flush: CompressFlushMode): ReturnStatus;
    private native deflateEndNative(strm: ZStream): ReturnStatus;
    private native deflateBoundNative(strm: ZStream, sourceLength: long): int;
    private native deflateSetHeaderNative(strm: ZStream, head: GzHeader): ReturnStatus;
    private native deflateCopyNative(source: Zip): ReturnStatus;
    private native deflateSetDictionaryNative(strm: ZStream, dictionary: ArrayBuffer): ReturnStatus;
    private native deflateGetDictionaryNative(strm: ZStream, dictionary: ArrayBuffer): DictionaryOutputInfo;
    private native deflateTuneNative(strm: ZStream, goodLength: int, maxLazy: int, niceLength: int, maxChain: int): ReturnStatus;
    private native deflateResetNative(strm: ZStream): ReturnStatus;
    private native deflateResetKeepNative(strm: ZStream): ReturnStatus;
    private native deflatePendingNative(strm: ZStream): DeflatePendingOutputInfo;
    private native deflateParamsNative(strm: ZStream, level: CompressLevel, strategy: CompressStrategy): ReturnStatus;
    private native deflatePrimeNative(strm: ZStream, bits: int, value: int): ReturnStatus;

    public getZStream(): Promise<ZStream | undefined> {
      let p = new Promise<ZStream | undefined>((resolve: (v: ZStream | undefined) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ZStream | undefined => {
          return this.getZStreamNative();
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
          let result: int = e as int;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public compress(dest: ArrayBuffer, source: ArrayBuffer, sourceLen?: long): Promise<ZipOutputInfo> {
      if (sourceLen !== undefined && sourceLen < 0) {
        throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_CHECK_FAILED);
      }
      let p = new Promise<ZipOutputInfo>((resolve: (v: ZipOutputInfo) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ZipOutputInfo => {
          return sourceLen === undefined ? this.compressNative(dest, source) :
                                           this.compressWithSourceLenNative(dest, source, sourceLen);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: Any) => {
          let result: ZipOutputInfo = e as ZipOutputInfo;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public compress2(dest: ArrayBuffer, source: ArrayBuffer, level: CompressLevel, sourceLen?: long,): Promise<ZipOutputInfo> {
      if (sourceLen !== undefined && sourceLen < 0) {
        throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_CHECK_FAILED);
      }
      let p = new Promise<ZipOutputInfo>((resolve: (v: ZipOutputInfo) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ZipOutputInfo => {
          return sourceLen === undefined ? this.compress2Native(dest, source, level) :
                                           this.compress2WithSourceLenNative(dest, source, level, sourceLen);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: Any) => {
          let result: ZipOutputInfo = e as ZipOutputInfo;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public compressBound(sourceLen: int): Promise<int> {
      if (sourceLen < 0) {
        throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_CHECK_FAILED);
      }
      let p = new Promise<int>((resolve: (v: int) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): int => {
          return this.compressBoundNative(sourceLen);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: Any) => {
          let result: int = e as int;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public uncompress(dest: ArrayBuffer, source: ArrayBuffer, sourceLen?: long): Promise<ZipOutputInfo> {
      if (sourceLen !== undefined && sourceLen < 0) {
        throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_CHECK_FAILED);
      }
      let p = new Promise<ZipOutputInfo>((resolve: (v: ZipOutputInfo) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ZipOutputInfo => {
          return sourceLen === undefined ? this.uncompressNative(dest, source) :
                                           this.uncompressWithSourceLenNative(dest, source, sourceLen);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: Any) => {
          let result: ZipOutputInfo = e as ZipOutputInfo;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public uncompress2(dest: ArrayBuffer, source: ArrayBuffer, sourceLen?: long): Promise<DecompressionOutputInfo> {
      if (sourceLen !== undefined && sourceLen < 0) {
        throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_CHECK_FAILED);
      }
      let p = new Promise<DecompressionOutputInfo>((resolve: (v: DecompressionOutputInfo) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): DecompressionOutputInfo => {
          return sourceLen === undefined ? this.uncompress2Native(dest, source) :
                                           this.uncompress2WithSourceLenNative(dest, source, sourceLen);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
          let result: long = e as long;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public inflateBackInit(strm: ZStream, windowBits: long, window: ArrayBuffer): Promise<ReturnStatus> {
      if (windowBits < MIN_WINDOWBITS || windowBits > MAX_WINDOWBITS) {
        throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_CHECK_FAILED);
      }
      let p = new Promise<ReturnStatus>((resolve: (v: ReturnStatus) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ReturnStatus => {
          return this.inflateBackInitNative(strm, windowBits, window);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
          let result: ReturnStatus = e as ReturnStatus;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public deflateBound(strm: ZStream, sourceLength: long): Promise<int> {
      if (sourceLength < 0) {
        throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_CHECK_FAILED);
      }
      let p = new Promise<int>((resolve: (v: int) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): int => {
          return this.deflateBoundNative(strm, sourceLength);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
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
        p1.then((e: Any) => {
          let result: ReturnStatus = e as ReturnStatus;
          resolve(result);
        }, (err: Error): void => {
          reject(err as BusinessError);
        });
      });
      return p;
    }

    public deflatePrime(strm: ZStream, bits: int, value: int): Promise<ReturnStatus> {
      if (bits < MIN_BITS || bits > MAX_BITS) {
        throw createBusinessError(ERROR_PARAM_CHECK_ERROR, PARAM_CHECK_FAILED);
      }
      let p = new Promise<ReturnStatus>((resolve: (v: ReturnStatus) => void, reject: (error: BusinessError) => void): void => {
        let execFun = (): ReturnStatus => {
          return this.deflatePrimeNative(strm, bits, value);
        };
        let p1 = taskpool.execute(execFun);
        p1.then((e: Any) => {
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
      p1.then((e: Any) => {
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
      p1.then((e: Any) => {
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
      p1.then((e: Any) => {
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
      p1.then((e: Any) => {
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
