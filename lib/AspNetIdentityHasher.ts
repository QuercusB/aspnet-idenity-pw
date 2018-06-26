import { HashOptions } from './AspNetIdentityHasher';
import * as crypto from "crypto";

export type HashOptions = {
  version?: 'v2' | 'v3',
  algorithm?: 'sha1' | 'sha256' | 'sha512',
  iterations?: number,
  salt?: Buffer
}

export class AspNetIdentityHasher {

  public static defaultHashOptions = {
    version: 'v3',
    algorithm: 'sha256',
    iterations: 10000
  }

  public hash(password: string, 
    options: HashOptions = <any>AspNetIdentityHasher.defaultHashOptions): Promise<Buffer> {

    const version = options.version || AspNetIdentityHasher.defaultHashOptions.version;
    let algorithm = options.algorithm || AspNetIdentityHasher.defaultHashOptions.algorithm;
    let iterations = options.iterations || AspNetIdentityHasher.defaultHashOptions.iterations;
    const salt = options.salt || crypto.randomBytes(16);

    if (version === 'v2') {
      algorithm = 'sha1';
      iterations = 1000;
    }
    
    return new Promise((resolve, reject) => {
      crypto.pbkdf2(password, salt, iterations, 32, algorithm, 
        (err, key) => {
          if (err)
            reject(err);
          const result = new Uint8Array(1 + (version === 'v3' ? 4 + 4 + 4 : 0) + salt.length + key.length);
          switch (version) {
            case 'v2':
              result[0] = 0;
              break;  
            case 'v3':
              result[0] = 1;
              switch (algorithm) {
                case 'sha1':
                  this.writeUInt32(result, 1, 0);
                  break;
                case 'sha256':
                  this.writeUInt32(result, 1, 1);
                  break;
                case 'sha512':
                  this.writeUInt32(result, 1, 2);
                  break;
              }
              this.writeUInt32(result, 1 + 4, iterations || 1);
              this.writeUInt32(result, 1 + 4 + 4, salt.length);
              break;
          }
          salt.copy(result, result.length - key.length - salt.length, 0);
          key.copy(result, result.length - key.length, 0);
          resolve(new Buffer(result.buffer));
        })
    });
  }

  public async hash64(password: string, 
    options: HashOptions = <any>AspNetIdentityHasher.defaultHashOptions): Promise<string> {
    const hash = await this.hash(password, options);
    return hash.toString('base64');
  }

  public async verify(password: string, passwordHash: string | Buffer): Promise<boolean> {
    if (typeof passwordHash === 'string')
      passwordHash = new Buffer(passwordHash, 'base64');
    const options: HashOptions = {};
    switch (passwordHash[0]) {
      case 0:
        options.version = 'v2';
        if (passwordHash.length != 1 + 16 + 32)
          throw new Error('Invalid password hash - length of IdentityV2 should be exactly 49 bytes');
        break;
      case 1:
        options.version = 'v3';
        if (passwordHash.length != 1 + 4 + 4 + 4 + 16 + 32)
          throw new Error('Invalid password hash - length of IdentityV3 should be exactly 61 bytes');
        switch (this.readUInt32(passwordHash, 1)) {
          case 0:
            options.algorithm = 'sha1';
            break;
          case 1:
            options.algorithm = 'sha256';
            break;
          case 2:
            options.algorithm = 'sha512';
            break;
          default:
            throw new Error('Invalid password hash - algorithm in IdentityV3 is unknown');
        }
        options.iterations = this.readUInt32(passwordHash, 5);
        if (this.readUInt32(passwordHash, 9) != 16)
          throw new Error('Invalid password hash - expected salt length to equal 16 bytes');
        break;
      default:
        throw new Error('Invalid password hash - unknown identity version');
    }
    options.salt = new Buffer(16);
    passwordHash.copy(options.salt, 0, passwordHash.length - 48);
    const hash = await this.hash(password, options);
    return passwordHash.equals(hash);
  }

  private writeUInt32(array: Uint8Array, offset: number, value: number) {
    array[offset] = (value & 0xFF000000) >> 24;
    array[offset+1] = (value & 0xFF0000) >> 16;
    array[offset+2] = (value & 0xFF00) >> 8;
    array[offset+3] = value & 0xFF;
  }

  private readUInt32(buffer: Buffer, offset: number) {
    let result = 0;
    for (var i = 0; i < 4; i++)
      result = (result << 8) + buffer[offset + i];
    return result;
  }
}
