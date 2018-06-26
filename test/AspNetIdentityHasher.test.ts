import * as td from 'testdouble';
import * as crypto from 'crypto';
import { AspNetIdentityHasher } from './../lib/AspNetIdentityHasher';
import * as chai from 'chai';
const expect = chai.expect;

describe('Password generation', () => {

  afterEach(() => {
    td.reset();
  })

  const hasher = new AspNetIdentityHasher();

  describe('hash', () => {

    it('should generate some password hash', async () => {
      const hash = await hasher.hash('Just a password');
      expect(hash).to.be.instanceof(Buffer);
    });

    it('should generate IdentityV3 password hash', async () => {
      const hash = (await hasher.hash('Swordfish', {
        version: 'v3',
        algorithm: 'sha256',
        iterations: 10000,
        salt: new Buffer('5421a7c5dfa8927f2bacbd8dee42dffd', 'hex')
      })).toString('hex');
      expect(hash).to.eql(
        '010000000100002710000000105421a7c5dfa8927f2bacbd8dee42dffdeaf302221ab20f063f498e407311a7c597b9c1686726cdf1d50c60ecd389bf7b');
    })

    it('should get salt from crypto.randomBytes if none specified', async () => {
      let randomBytesArgs;
      td.replace(crypto, "randomBytes", (...args) => {
        randomBytesArgs = args;
        return new Buffer('94805eba7d33f8fe386e692b39fce563', 'hex');
      });

      const hash = (await hasher.hash('Very nice password')).toString('hex');

      expect(randomBytesArgs).to.eql([16])
      expect(hash).to.eql(
        '0100000001000027100000001094805eba7d33f8fe386e692b39fce5638f894a694cd4572abb2e2855c86ada2b41c86d7471a1d56b6c0ed1e63348bcf6');
    })

    for (const algorithm of ['sha1', 'sha512']) {
      it(`should pass algorithm ${algorithm} as digest to crypto.pbkdf2 if specified`, async () => {
        let pbkdf2_digest;
        td.replace(crypto, 'pbkdf2', (password, salt, iterations, keyLen, digest, callback) => {
          pbkdf2_digest = digest;
          callback(null, new Buffer(''));
        })

        await hasher.hash('Sample', { algorithm: <any>algorithm });

        expect(pbkdf2_digest).to.eql(algorithm);
      })
    }

    it('should pass iterations count to crypto.pbkdf2', async () => {
      let pbkdf2_iterations;
      td.replace(crypto, 'pbkdf2', (password, salt, iterations, keyLen, digest, callback) => {
        pbkdf2_iterations = iterations;
        callback(null, new Buffer(''));
      })

      await hasher.hash('Sample', { iterations: 5521 });

      expect(pbkdf2_iterations).to.eql(5521);
    })

    for (const algorithm of [{ algorithm: 'sha1', id: 0 }, { algorithm: 'sha256', id: 1 }, { algorithm: 'sha512', id: 2 } ]) {
      it(`should save ${algorithm.algorithm}'id in 2-5 result bytes`, async () => {
        const hash = await hasher.hash('Sample', { algorithm: <any>algorithm.algorithm });
        const idBuffer = new Buffer(4);
        hash.copy(idBuffer, 0, 1);
        expect(idBuffer.toString('hex')).to.eql(`0000000${algorithm.id}`);
      })
    }

    it('uses 1000 iterations and sha1 for IdentityV2 hash', async () => {
      let pbkdf2args;
      td.replace(crypto, 'pbkdf2', (password, salt, iterations, keyLen, digest, callback) => {
        pbkdf2args = { password, salt, iterations, keyLen, digest };
        callback(null, new Buffer(''));
      })

      await hasher.hash('Some password', { version: 'v2' })

      expect(pbkdf2args.iterations).to.eql(1000);
      expect(pbkdf2args.digest).to.eql('sha1');
      expect(pbkdf2args.keyLen).to.eql(32);
    })

    it('encoded IdentityV2 hash with correct layout', async () => {
      const hash = (await hasher.hash('Swordfish', {
        version: 'v2',
        salt: new Buffer('5421a7c5dfa8927f2bacbd8dee42dffd', 'hex')
      })).toString('hex');
      expect(hash).to.eql(
        '005421a7c5dfa8927f2bacbd8dee42dffd1c19942452d218fe1661a60f5ee71469afa776658519422352186d14f1dca997');
    })
  })

  describe('hash64', () => {

    it('should return base64 encoded string for hash64 call', async () => {
      const hash64 = await hasher.hash64('Swordfish', {
        salt: new Buffer('5421a7c5dfa8927f2bacbd8dee42dffd', 'hex')
      });
      expect(hash64).to.eql(
        'AQAAAAEAACcQAAAAEFQhp8XfqJJ/K6y9je5C3/3q8wIiGrIPBj9JjkBzEafFl7nBaGcmzfHVDGDs04m/ew==');
    })
  })

  describe('verify', () => {

    it('fetches hash parameter out of hashed password, hashes given password and compares the result', async () => {
      const hashedPassword = new Buffer(
        '010000000200002710000000105421a7c5dfa8927f2bacbd8dee42dffdeaf302221ab20f063f498e407311a7c597b9c1686726cdf1d50c60ecd389bf7b', 'hex');
      const hashedPasswordSalt = new Buffer(16);
      hashedPassword.copy(hashedPasswordSalt, 0, 1 + 4 + 4 + 4);
      const password = 'Does not matter';
      
      let hashArgs;
      td.replace(hasher, 'hash', (...args) => {
        hashArgs = args;
        return Promise.resolve(hashedPassword); // returing same password as hash result
      })

      const result = await hasher.verify(password, hashedPassword);

      expect(hashArgs).to.eql([ password, {
        version: 'v3',
        iterations: 10000,
        algorithm: 'sha512',
        salt: hashedPasswordSalt
      }])
      expect(result).to.eql(true);
    })

    it('can verify IdentityV2 password as well', async () => {
      const hashedPassword = new Buffer(
        '005421a7c5dfa8927f2bacbd8dee42dffdeaf302221ab20f063f498e407311a7c597b9c1686726cdf1d50c60ecd389bf7b', 'hex');
      const hashedPasswordSalt = new Buffer(16);
      hashedPassword.copy(hashedPasswordSalt, 0, 1);
      const password = 'Does not matter';
      
      let hashArgs;
      td.replace(hasher, 'hash', (...args) => {
        hashArgs = args;
        return Promise.resolve(new Buffer(0)); // returing same password as hash result
      })

      const result = await hasher.verify(password, hashedPassword);

      expect(hashArgs).to.eql([ password, {
        version: 'v2',
        salt: hashedPasswordSalt
      }])
      expect(result).to.eql(false);
    })

    it('treats given string as base64 - decodes it and checks as byte buffer', async () => {
      const result = await hasher.verify('Swordfish', 'AQAAAAEAACcQAAAAEFQhp8XfqJJ/K6y9je5C3/3q8wIiGrIPBj9JjkBzEafFl7nBaGcmzfHVDGDs04m/ew==');
      
      expect(result).to.eql(true);
    })
  })
})
