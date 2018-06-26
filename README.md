# aspnet-identity-v3-pw

[![Build Status](https://travis-ci.org/QuercusB/aspnet-identityv3.svg?branch=master)](https://travis-ci.org/QuercusB/aspnet-identityv3)
[![Coverage Status](https://coveralls.io/repos/github/QuercusB/aspnet-identityv3/badge.svg?branch=master)](https://coveralls.io/github/QuercusB/aspnet-identityv3?branch=master)

## Description

Typescript library to generate & validate ASP.NET Identity V2 & V3 passwords.
To be used for connecting node.js application to ASP.NET managed database in case you need to separate authorization out of ASP.NET application.

## Install

This is a [Node.js](https://nodejs.org/en/) module available through the
[npm registry](https://www.npmjs.com/). Installation is done using the
[`npm install` command](https://docs.npmjs.com/getting-started/installing-npm-packages-locally): 

```sh
$ npm install aspnet-identityv3 --save
```

## Typescript

### Generate hash for the password

```typescript
import aspnet_hasher from 'aspnet-identityv3';

const hash = await aspnet_hasher.hash('Some password'); // hash: Buffer

const hashStr = await aspnet_hasher.hash64('Some password'); // hash: Base64 encoded string
```

### Verify password over hashed

```typescript
import aspnet_hasher from 'aspnet-identityv3';

await aspnet_hasher.verify('Swordfish', new Buffer('005421a7c5dfa8927f2bacbd8dee42dffd1c19942452d218fe1661a60f5ee71469afa776658519422352186d14f1dca997', 'hex'))

// you can either pass Buffer or base64 encoded string

await aspnet_hasher.verify('Swordfish', 'AQAAAAEAACcQAAAAEFQhp8XfqJJ/K6y9je5C3/3q8wIiGrIPBj9JjkBzEafFl7nBaGcmzfHVDGDs04m/ew==')
```