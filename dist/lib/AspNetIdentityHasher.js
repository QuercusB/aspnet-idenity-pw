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
Object.defineProperty(exports, "__esModule", { value: true });
var crypto = require("crypto");
var AspNetIdentityHasher = /** @class */ (function () {
    function AspNetIdentityHasher() {
    }
    AspNetIdentityHasher.prototype.hash = function (password, options) {
        var _this = this;
        if (options === void 0) { options = AspNetIdentityHasher.defaultHashOptions; }
        var version = options.version || AspNetIdentityHasher.defaultHashOptions.version;
        var algorithm = options.algorithm || AspNetIdentityHasher.defaultHashOptions.algorithm;
        var iterations = options.iterations || AspNetIdentityHasher.defaultHashOptions.iterations;
        var salt = options.salt || crypto.randomBytes(16);
        if (version === 'v2') {
            algorithm = 'sha1';
            iterations = 1000;
        }
        return new Promise(function (resolve, reject) {
            crypto.pbkdf2(password, salt, iterations, 32, algorithm, function (err, key) {
                if (err)
                    reject(err);
                var result = new Uint8Array(1 + (version === 'v3' ? 4 + 4 + 4 : 0) + salt.length + key.length);
                switch (version) {
                    case 'v2':
                        result[0] = 0;
                        break;
                    case 'v3':
                        result[0] = 1;
                        switch (algorithm) {
                            case 'sha1':
                                _this.writeUInt32(result, 1, 0);
                                break;
                            case 'sha256':
                                _this.writeUInt32(result, 1, 1);
                                break;
                            case 'sha512':
                                _this.writeUInt32(result, 1, 2);
                                break;
                        }
                        _this.writeUInt32(result, 1 + 4, iterations || 1);
                        _this.writeUInt32(result, 1 + 4 + 4, salt.length);
                        break;
                }
                salt.copy(result, result.length - key.length - salt.length, 0);
                key.copy(result, result.length - key.length, 0);
                resolve(new Buffer(result.buffer));
            });
        });
    };
    AspNetIdentityHasher.prototype.hash64 = function (password, options) {
        if (options === void 0) { options = AspNetIdentityHasher.defaultHashOptions; }
        return __awaiter(this, void 0, void 0, function () {
            var hash;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.hash(password, options)];
                    case 1:
                        hash = _a.sent();
                        return [2 /*return*/, hash.toString('base64')];
                }
            });
        });
    };
    AspNetIdentityHasher.prototype.verify = function (password, passwordHash) {
        return __awaiter(this, void 0, void 0, function () {
            var options, hash;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        if (typeof passwordHash === 'string')
                            passwordHash = new Buffer(passwordHash, 'base64');
                        options = {};
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
                        return [4 /*yield*/, this.hash(password, options)];
                    case 1:
                        hash = _a.sent();
                        return [2 /*return*/, passwordHash.equals(hash)];
                }
            });
        });
    };
    AspNetIdentityHasher.prototype.writeUInt32 = function (array, offset, value) {
        array[offset] = (value & 0xFF000000) >> 24;
        array[offset + 1] = (value & 0xFF0000) >> 16;
        array[offset + 2] = (value & 0xFF00) >> 8;
        array[offset + 3] = value & 0xFF;
    };
    AspNetIdentityHasher.prototype.readUInt32 = function (buffer, offset) {
        var result = 0;
        for (var i = 0; i < 4; i++)
            result = (result << 8) + buffer[offset + i];
        return result;
    };
    AspNetIdentityHasher.defaultHashOptions = {
        version: 'v3',
        algorithm: 'sha256',
        iterations: 10000
    };
    return AspNetIdentityHasher;
}());
exports.AspNetIdentityHasher = AspNetIdentityHasher;
