"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var _this = this;
Object.defineProperty(exports, "__esModule", { value: true });
var td = require("testdouble");
var crypto = require("crypto");
var AspNetIdentityHasher_1 = require("./../lib/AspNetIdentityHasher");
var chai = require("chai");
var expect = chai.expect;
describe('Password generation', function () {
    afterEach(function () {
        td.reset();
    });
    var hasher = new AspNetIdentityHasher_1.AspNetIdentityHasher();
    describe('hash', function () {
        it('should generate some password hash', function () { return __awaiter(_this, void 0, void 0, function () {
            var hash;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, hasher.hash('Just a password')];
                    case 1:
                        hash = _a.sent();
                        expect(hash).to.be.instanceof(Buffer);
                        return [2 /*return*/];
                }
            });
        }); });
        it('should generate IdentityV3 password hash', function () { return __awaiter(_this, void 0, void 0, function () {
            var hash;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, hasher.hash('Swordfish', {
                            version: 'v3',
                            algorithm: 'sha256',
                            iterations: 10000,
                            salt: new Buffer('5421a7c5dfa8927f2bacbd8dee42dffd', 'hex')
                        })];
                    case 1:
                        hash = (_a.sent()).toString('hex');
                        expect(hash).to.eql('010000000100002710000000105421a7c5dfa8927f2bacbd8dee42dffdeaf302221ab20f063f498e407311a7c597b9c1686726cdf1d50c60ecd389bf7b');
                        return [2 /*return*/];
                }
            });
        }); });
        it('should get salt from crypto.randomBytes if none specified', function () { return __awaiter(_this, void 0, void 0, function () {
            var randomBytesArgs, hash;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        td.replace(crypto, "randomBytes", function () {
                            var args = [];
                            for (var _i = 0; _i < arguments.length; _i++) {
                                args[_i] = arguments[_i];
                            }
                            randomBytesArgs = args;
                            return new Buffer('94805eba7d33f8fe386e692b39fce563', 'hex');
                        });
                        return [4 /*yield*/, hasher.hash('Very nice password')];
                    case 1:
                        hash = (_a.sent()).toString('hex');
                        expect(randomBytesArgs).to.eql([16]);
                        expect(hash).to.eql('0100000001000027100000001094805eba7d33f8fe386e692b39fce5638f894a694cd4572abb2e2855c86ada2b41c86d7471a1d56b6c0ed1e63348bcf6');
                        return [2 /*return*/];
                }
            });
        }); });
        var _loop_1 = function (algorithm) {
            it("should pass algorithm " + algorithm + " as digest to crypto.pbkdf2 if specified", function () { return __awaiter(_this, void 0, void 0, function () {
                var pbkdf2_digest;
                return __generator(this, function (_a) {
                    switch (_a.label) {
                        case 0:
                            td.replace(crypto, 'pbkdf2', function (password, salt, iterations, keyLen, digest, callback) {
                                pbkdf2_digest = digest;
                                callback(null, new Buffer(''));
                            });
                            return [4 /*yield*/, hasher.hash('Sample', { algorithm: algorithm })];
                        case 1:
                            _a.sent();
                            expect(pbkdf2_digest).to.eql(algorithm);
                            return [2 /*return*/];
                    }
                });
            }); });
        };
        for (var _i = 0, _a = ['sha1', 'sha512']; _i < _a.length; _i++) {
            var algorithm = _a[_i];
            _loop_1(algorithm);
        }
        it('should pass iterations count to crypto.pbkdf2', function () { return __awaiter(_this, void 0, void 0, function () {
            var pbkdf2_iterations;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        td.replace(crypto, 'pbkdf2', function (password, salt, iterations, keyLen, digest, callback) {
                            pbkdf2_iterations = iterations;
                            callback(null, new Buffer(''));
                        });
                        return [4 /*yield*/, hasher.hash('Sample', { iterations: 5521 })];
                    case 1:
                        _a.sent();
                        expect(pbkdf2_iterations).to.eql(5521);
                        return [2 /*return*/];
                }
            });
        }); });
        var _loop_2 = function (algorithm) {
            it("should save " + algorithm.algorithm + "'id in 2-5 result bytes", function () { return __awaiter(_this, void 0, void 0, function () {
                var hash, idBuffer;
                return __generator(this, function (_a) {
                    switch (_a.label) {
                        case 0: return [4 /*yield*/, hasher.hash('Sample', { algorithm: algorithm.algorithm })];
                        case 1:
                            hash = _a.sent();
                            idBuffer = new Buffer(4);
                            hash.copy(idBuffer, 0, 1);
                            expect(idBuffer.toString('hex')).to.eql("0000000" + algorithm.id);
                            return [2 /*return*/];
                    }
                });
            }); });
        };
        for (var _b = 0, _c = [{ algorithm: 'sha1', id: 0 }, { algorithm: 'sha256', id: 1 }, { algorithm: 'sha512', id: 2 }]; _b < _c.length; _b++) {
            var algorithm = _c[_b];
            _loop_2(algorithm);
        }
        it('uses 1000 iterations and sha1 for IdentityV2 hash', function () { return __awaiter(_this, void 0, void 0, function () {
            var pbkdf2args;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        td.replace(crypto, 'pbkdf2', function (password, salt, iterations, keyLen, digest, callback) {
                            pbkdf2args = { password: password, salt: salt, iterations: iterations, keyLen: keyLen, digest: digest };
                            callback(null, new Buffer(''));
                        });
                        return [4 /*yield*/, hasher.hash('Some password', { version: 'v2' })];
                    case 1:
                        _a.sent();
                        expect(pbkdf2args.iterations).to.eql(1000);
                        expect(pbkdf2args.digest).to.eql('sha1');
                        expect(pbkdf2args.keyLen).to.eql(32);
                        return [2 /*return*/];
                }
            });
        }); });
        it('encoded IdentityV2 hash with correct layout', function () { return __awaiter(_this, void 0, void 0, function () {
            var hash;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, hasher.hash('Swordfish', {
                            version: 'v2',
                            salt: new Buffer('5421a7c5dfa8927f2bacbd8dee42dffd', 'hex')
                        })];
                    case 1:
                        hash = (_a.sent()).toString('hex');
                        expect(hash).to.eql('005421a7c5dfa8927f2bacbd8dee42dffd1c19942452d218fe1661a60f5ee71469afa776658519422352186d14f1dca997');
                        return [2 /*return*/];
                }
            });
        }); });
    });
    describe('hash64', function () {
        it('should return base64 encoded string for hash64 call', function () { return __awaiter(_this, void 0, void 0, function () {
            var hash64;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, hasher.hash64('Swordfish', {
                            salt: new Buffer('5421a7c5dfa8927f2bacbd8dee42dffd', 'hex')
                        })];
                    case 1:
                        hash64 = _a.sent();
                        expect(hash64).to.eql('AQAAAAEAACcQAAAAEFQhp8XfqJJ/K6y9je5C3/3q8wIiGrIPBj9JjkBzEafFl7nBaGcmzfHVDGDs04m/ew==');
                        return [2 /*return*/];
                }
            });
        }); });
    });
    describe('verify', function () {
        it('fetches hash parameter out of hashed password, hashes given password and compares the result', function () { return __awaiter(_this, void 0, void 0, function () {
            var hashedPassword, hashedPasswordSalt, password, hashArgs, result;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        hashedPassword = new Buffer('010000000200002710000000105421a7c5dfa8927f2bacbd8dee42dffdeaf302221ab20f063f498e407311a7c597b9c1686726cdf1d50c60ecd389bf7b', 'hex');
                        hashedPasswordSalt = new Buffer(16);
                        hashedPassword.copy(hashedPasswordSalt, 0, 1 + 4 + 4 + 4);
                        password = 'Does not matter';
                        td.replace(hasher, 'hash', function () {
                            var args = [];
                            for (var _i = 0; _i < arguments.length; _i++) {
                                args[_i] = arguments[_i];
                            }
                            hashArgs = args;
                            return Promise.resolve(hashedPassword); // returing same password as hash result
                        });
                        return [4 /*yield*/, hasher.verify(password, hashedPassword)];
                    case 1:
                        result = _a.sent();
                        expect(hashArgs).to.eql([password, {
                                version: 'v3',
                                iterations: 10000,
                                algorithm: 'sha512',
                                salt: hashedPasswordSalt
                            }]);
                        expect(result).to.eql(true);
                        return [2 /*return*/];
                }
            });
        }); });
        it('can verify IdentityV2 password as well', function () { return __awaiter(_this, void 0, void 0, function () {
            var hashedPassword, hashedPasswordSalt, password, hashArgs, result;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        hashedPassword = new Buffer('005421a7c5dfa8927f2bacbd8dee42dffdeaf302221ab20f063f498e407311a7c597b9c1686726cdf1d50c60ecd389bf7b', 'hex');
                        hashedPasswordSalt = new Buffer(16);
                        hashedPassword.copy(hashedPasswordSalt, 0, 1);
                        password = 'Does not matter';
                        td.replace(hasher, 'hash', function () {
                            var args = [];
                            for (var _i = 0; _i < arguments.length; _i++) {
                                args[_i] = arguments[_i];
                            }
                            hashArgs = args;
                            return Promise.resolve(new Buffer(0)); // returing same password as hash result
                        });
                        return [4 /*yield*/, hasher.verify(password, hashedPassword)];
                    case 1:
                        result = _a.sent();
                        expect(hashArgs).to.eql([password, {
                                version: 'v2',
                                salt: hashedPasswordSalt
                            }]);
                        expect(result).to.eql(false);
                        return [2 /*return*/];
                }
            });
        }); });
        it('treats given string as base64 - decodes it and checks as byte buffer', function () { return __awaiter(_this, void 0, void 0, function () {
            var result;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, hasher.verify('Swordfish', 'AQAAAAEAACcQAAAAEFQhp8XfqJJ/K6y9je5C3/3q8wIiGrIPBj9JjkBzEafFl7nBaGcmzfHVDGDs04m/ew==')];
                    case 1:
                        result = _a.sent();
                        expect(result).to.eql(true);
                        return [2 /*return*/];
                }
            });
        }); });
    });
});
