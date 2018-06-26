/// <reference types="node" />
import { HashOptions } from './AspNetIdentityHasher';
export declare type HashOptions = {
    version?: 'v2' | 'v3';
    algorithm?: 'sha1' | 'sha256' | 'sha512';
    iterations?: number;
    salt?: Buffer;
};
export declare class AspNetIdentityHasher {
    static defaultHashOptions: {
        version: string;
        algorithm: string;
        iterations: number;
    };
    hash(password: string, options?: HashOptions): Promise<Buffer>;
    hash64(password: string, options?: HashOptions): Promise<string>;
    verify(password: string, passwordHash: string | Buffer): Promise<boolean>;
    private writeUInt32;
    private readUInt32;
}
