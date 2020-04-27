import * as crypto from 'crypto';
import { TimeUnitInSeconds } from './types';

export type BufferLike = string | ArrayBuffer | Buffer | Uint8Array;
export type JSONDumpable =
  | null
  | number
  | boolean
  | string
  | JSONDumpable[]
  | { [K: string]: JSONDumpable };
export const enum ActAuthJanSignType {
  V1 = 1,
  V2,
}

export default class ActAuthJan {
  static SIGNTYPE = new Set([ActAuthJanSignType.V1, ActAuthJanSignType.V2]);

  static getHashvalue(
    signtype: ActAuthJanSignType,
    key: string,
    expireat: number = ActAuthJan.expireat(),
    meta: BufferLike = Buffer.alloc(0),
    condition: BufferLike = '',
    noAssert?: boolean,
  ): string {
    if (noAssert) {
      signtype &= 0x3f;
      expireat &= 0x3ffffffff;
    } else {
      if (signtype < 1 || !Number.isInteger(signtype))
        throw new Error(`Sign type mark MUST BE a positive integer, got \`${signtype}\`.`);
      if (expireat < 1 || !Number.isInteger(expireat))
        throw new Error(`Expiry time MUST BE a positive integer, got \`${expireat}\`.`);
      if (signtype > 0x3f)
        throw new Error(`Sign type mark MUST BE less than 63, got \`${signtype}\`.`);
      if (expireat > 0x3ffffffff)
        throw new Error(`Expiry time MUST BE less than 2 ^ 34, got \`${expireat}\`.`);
    }
    const premeta = Buffer.alloc(5);
    premeta.writeUIntBE(expireat * 0x40 + signtype, 0, 5);
    const metabuf = Buffer.concat([
      new Uint8Array(premeta),
      new Uint8Array(ActAuthJan.toBuffer(meta)),
    ]);
    return crypto
      .createHmac('sha256', key)
      .update(metabuf)
      .update(ActAuthJan.toBuffer(condition))
      .digest('base64');
  }

  static getV1Hashvalue(key: string, id: BufferLike, expireat?: number): string {
    return ActAuthJan.getHashvalue(ActAuthJanSignType.V1, key, expireat, id);
  }

  static getV2Hashvalue(
    key: string,
    policy: JSONDumpable,
    expireat?: number,
    body?: BufferLike,
  ): string {
    policy = JSON.stringify(policy);
    return ActAuthJan.getHashvalue(ActAuthJanSignType.V2, key, expireat, policy, body);
  }

  static createSign(
    signtype: ActAuthJanSignType,
    key: string,
    expireat: number = ActAuthJan.expireat(),
    meta: BufferLike = Buffer.alloc(0),
    condition: BufferLike = '',
    noAssert?: boolean,
  ): string {
    if (noAssert) {
      signtype &= 0x3f;
      expireat &= 0x3ffffffff;
    } else {
      if (signtype < 1 || !Number.isInteger(signtype))
        throw new Error(`Sign type mark MUST BE a positive integer, got \`${signtype}\`.`);
      if (expireat < 1 || !Number.isInteger(expireat))
        throw new Error(`Expiry time MUST BE a positive integer, got \`${expireat}\`.`);
      if (signtype > 0x3f)
        throw new Error(`Sign type mark MUST BE less than 63, got \`${signtype}\`.`);
      if (expireat > 0x3ffffffff)
        throw new Error(`Expiry time MUST BE less than 2 ^ 34, got \`${expireat}\`.`);
    }
    const premeta = Buffer.alloc(5);
    premeta.writeUIntBE(expireat * 0x40 + signtype, 0, 5);
    const metabuf = Buffer.concat([
      new Uint8Array(premeta),
      new Uint8Array(ActAuthJan.toBuffer(meta)),
    ]);
    return crypto
      .createHmac('sha256', key)
      .update(metabuf)
      .update(ActAuthJan.toBuffer(condition))
      .digest('base64')
      .concat(metabuf.toString('base64'));
  }

  static createV1Sign(key: string, id: BufferLike, expireat?: number): string {
    return ActAuthJan.createSign(ActAuthJanSignType.V1, key, expireat, id);
  }

  static createV2Sign(
    key: string,
    policy: JSONDumpable,
    expireat?: number,
    body?: BufferLike,
  ): string {
    policy = JSON.stringify(policy);
    return ActAuthJan.createSign(ActAuthJanSignType.V2, key, expireat, policy, body);
  }

  static parseSign(sign: string) {
    const [hashvalue, metastr] = sign.trim().split('=', 2);
    if (!hashvalue || hashvalue.length !== 43 || !metastr || metastr.length < 7) return;
    const metabuf = Buffer.from(metastr, 'base64');
    const mark = metabuf.readUIntBE(0, 5);
    const signtype = (mark % 0x40) as ActAuthJanSignType;
    const expireat = Math.trunc((mark - signtype) / 0x40);
    return {
      signtype,
      expireat,
      meta: metabuf.slice(5),
      hashvalue: hashvalue.concat('='),
    };
  }

  static parseV1Sign(sign: string) {
    return ActAuthJan._parseV1Sign(ActAuthJan.parseSign(sign));
  }

  static parseV2Sign<T = unknown>(sign: string) {
    return ActAuthJan._parseV2Sign<T>(ActAuthJan.parseSign(sign));
  }

  static parseAnySign<T = unknown>(sign: string) {
    const parsed = ActAuthJan.parseSign(sign);
    switch (parsed?.signtype) {
      case ActAuthJanSignType.V1:
        return ActAuthJan._parseV1Sign(parsed);
      case ActAuthJanSignType.V2:
        return ActAuthJan._parseV2Sign<T>(parsed);
      default:
        return;
    }
  }

  protected static toBuffer = Buffer.from as (input: BufferLike) => Buffer;

  protected static expireat() {
    return Math.trunc(Date.now() / 1000 + 2 * TimeUnitInSeconds.Hour);
  }

  protected static _parseV1Sign(parsed: ReturnType<typeof ActAuthJan['parseSign']>) {
    if (!parsed || parsed.signtype !== ActAuthJanSignType.V1) return;
    const { signtype, expireat, hashvalue } = parsed;
    return { signtype, expireat, id: parsed.meta, hashvalue };
  }

  protected static _parseV2Sign<T>(
    parsed: ReturnType<typeof ActAuthJan['parseSign']>,
  ): void | { signtype: ActAuthJanSignType; expireat: number; policy?: T; hashvalue: string } {
    if (!parsed || parsed.signtype !== ActAuthJanSignType.V2) return;
    const { signtype, expireat, hashvalue } = parsed;
    const policy = parsed.meta.toString();
    if (!policy) return { signtype, expireat, hashvalue };
    try {
      return { signtype, expireat, policy: JSON.parse(policy), hashvalue };
    } catch {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      return { signtype, expireat, policy: policy as any, hashvalue };
    }
  }
}
