//
//  PrimitivesSpec.m
//  SimpleSecrets
//
//  Created by Tim Shadel on 5/11/13.
//  Copyright (c) 2013 Tim Shadel. All rights reserved.
//

#import "Kiwi.h"
#import "Primitives.h"
#import "hexString.h"

NSData * makeData(const int, const size_t);
NSData * hexStringToData(char *);

SPEC_BEGIN(PrimitivesSpec)

describe(@"primitive crypto functions", ^{

    describe(@"nonce", ^{
        it(@"should return 16 random bytes", ^{
            NSData *first = [Primitives nonce];
            NSData *second = [Primitives nonce];
            [first shouldNotBeNil];
            [[first should] equal:first];
            [second shouldNotBeNil];
            [[first shouldNot] equal:second];
        });
    });

    describe(@"deriveSenderHmacKeyFromMasterKey:", ^{
        it(@"should require a 256-bit master key", ^{
            NSData *smallKey = makeData(0x33, 31);
            NSData *exactKey = makeData(0x33, 32);
            NSData *largeKey = makeData(0x33, 33);

            NSData *smallHmac = [Primitives deriveSenderHmacKeyFromMasterKey:smallKey];
            NSData *exactHmac = [Primitives deriveSenderHmacKeyFromMasterKey:exactKey];
            NSData *largeHmac = [Primitives deriveSenderHmacKeyFromMasterKey:largeKey];
            
            [smallHmac shouldBeNil];
            [exactHmac shouldNotBeNil];
            [largeHmac shouldBeNil];
        });

        it(@"should require a 256-bit master key", ^{
            NSData *masterKey = makeData(0xbc, 32);
            NSData *hmacKey = [Primitives deriveSenderHmacKeyFromMasterKey:masterKey];
            NSData *expectedHmac = hexStringToData("1e2e2725f135463f05c268ffd1c1687dbc9dd7da65405697471052236b3b3088");
            [hmacKey shouldNotBeNil];
            [[theValue([hmacKey length]) should] equal:theValue(32)];
            [[hmacKey should] equal:expectedHmac];
        });

    });
    
    describe(@"deriveSenderCipherKeyFromMasterKey:", ^{
        it(@"should derive a 256-bit encryption key from a 256-bit master key", ^{
            NSData *masterKey = makeData(0xbc, 32);
            NSData *cipherKey = [Primitives deriveSenderCipherKeyFromMasterKey:masterKey];
            NSData *expectedCipher = hexStringToData("327b5f32d7ff0beeb0a7224166186e5f1fc2ba681092214a25b1465d1f17d837");
            [cipherKey shouldNotBeNil];
            [[theValue([cipherKey length]) should] equal:theValue(32)];
            [[cipherKey should] equal:expectedCipher];
        });
    });

    describe(@"deriveReceiverHmacKeyFromMasterKey:", ^{
        it(@"should require a 256-bit master key", ^{
            NSData *masterKey = makeData(0xbc, 32);
            NSData *hmacKey = [Primitives deriveReceiverHmacKeyFromMasterKey:masterKey];
            NSData *expectedHmac = hexStringToData("375f52dff2a263f2d0e0df11d252d25ba18b2f9abae1f0cbf299bab8d8c4904d");
            [hmacKey shouldNotBeNil];
            [[theValue([hmacKey length]) should] equal:theValue(32)];
            [[hmacKey should] equal:expectedHmac];
        });
    });
    
    describe(@"deriveReceiverCipherKeyFromMasterKey:", ^{
        it(@"should derive a 256-bit encryption key from a 256-bit master key", ^{
            NSData *masterKey = makeData(0xbc, 32);
            NSData *cipherKey = [Primitives deriveReceiverCipherKeyFromMasterKey:masterKey];
            NSData *expectedCipher = hexStringToData("c7e2a9660369f243aed71b0de0c49ee69719d20261778fdf39991a456566ef22");
            [cipherKey shouldNotBeNil];
            [[theValue([cipherKey length]) should] equal:theValue(32)];
            [[cipherKey should] equal:expectedCipher];
        });
    });

    describe(@"encrypt()", ^{
        it(@"should encrypt data using a 256-bit key", ^{
            NSData *key = makeData(0xcd, 32);
            NSData *data = makeData(0x11, 25);
            
            NSData *binmessage = [Primitives encryptData:data withKey:key];
            NSData *iv = [binmessage subdataWithRange:NSMakeRange(0,16)];
            NSData *ciphertext = [binmessage subdataWithRange:NSMakeRange(16, binmessage.length - 16)];

            [[theValue(iv.length) should] equal:theValue(16)];
            [[theValue(ciphertext.length) should] equal:theValue(32)];
            // Try to decipher it...
            NSData *recovered = [Primitives decryptData:ciphertext withKey:key andIV:iv];
            [[recovered should] equal:data];
        });
        
        it(@"should return a Buffer of (iv || ciphertext)", ^{
            NSData *key = makeData(0xcd, 32);
            NSData *data = makeData(0x11, 25);
            
            NSData *binmessage = [Primitives encryptData:data withKey:key];
            [binmessage shouldNotBeNil];
            [[binmessage should] beKindOfClass:[NSMutableData class]];
            // 16-byte IV, 32 bytes to encrypt the 25 data bytes
            [[theValue([binmessage length]) should] equal:theValue(48)];
        });
    });
    
    describe(@"decrypt()", ^{
        it(@"should decrypt data using a 256-bit key", ^{
            NSData *key = makeData(0xcd, 32);
            NSData *plaintext = makeData(0x11, 25);
            NSData *iv = hexStringToData("d4a5794c81015dde3b9b0648f2b9f5b9");
            NSData *ciphertext = hexStringToData("cb7f804ec83617144aa261f24af07023a91a3864601a666edea98938f2702dbc");
            
            NSData *recovered = [Primitives decryptData:ciphertext withKey:key andIV:iv];
            [recovered shouldNotBeNil];
            [[recovered should] beKindOfClass:[NSMutableData class]];
            // 16-byte IV, 32 bytes to encrypt the 25 data bytes
            [[theValue([recovered length]) should] equal:theValue(25)];
            [[recovered should] equal:plaintext];
        });
    });
    
    describe(@"identify()", ^{
        it(@"should calculate an id for a key", ^{
            NSData *key = makeData(0xab, 32);
            NSData *ident = [Primitives identify:key];
            NSData *expectedIdent = hexStringToData("0d081b0889d7");
            
            [ident shouldNotBeNil];
            [[ident should] beKindOfClass:[NSMutableData class]];
            [[theValue([ident length]) should] equal:theValue(6)];
            [[ident should] equal:expectedIdent];
        });
    });
    
    describe(@"mac()", ^{
        it(@"should create a message authentication code", ^{
            NSData *key = makeData(0x9f, 32);
            NSData *data = makeData(0x11, 25);
            NSData *mac = [Primitives macForData:data withKey:key];
            NSData *expectedMac = hexStringToData("adf1793fdef44c54a2c01513c0c7e4e71411600410edbde61558db12d0a01c65");
            
            [mac shouldNotBeNil];
            [[mac should] beKindOfClass:[NSMutableData class]];
            [[theValue([mac length]) should] equal:theValue(32)];
            [[mac should] equal:expectedMac];
        });
    });
    
    describe(@"compare()", ^{
        it(@"should correctly distinguish data equality", ^{
            NSData *a = makeData(0x11, 25);
            NSData *b = makeData(0x12, 25);
            NSData *c = makeData(0x11, 25);
            
            [[theValue([Primitives compare:a to:a]) should] beTrue];
            [[theValue([Primitives compare:a to:b]) should] beFalse];
            [[theValue([Primitives compare:a to:c]) should] beTrue];
        });
        
//        // This works fine locally, but has tons of variation on build server
//        it.skip('should take just as long to compare different data as identical data', function() {
//            NSData *a = makeData(0xff, 250000);
//            NSData *b = makeData(0x00, 250000);
//            NSData *c = makeData(0xff, 250000);
//            
//            var benchAA = benchmark(primitives.compare, a, a);
//            var benchAB = benchmark(primitives.compare, a, b);
//            var benchAC = benchmark(primitives.compare, a, c);
//            
//            var naiveAA = benchmark(naiveEquals, a, a);
//            var naiveAB = benchmark(naiveEquals, a, b);
//            var naiveAC = benchmark(naiveEquals, a, c);
//            
//            // All constant-time comparisons should be roughly equal in time
//            expect(difference(benchAA, benchAB)).to.be.greaterThan(0.95);
//            expect(difference(benchAA, benchAC)).to.be.greaterThan(0.95);
//            expect(difference(benchAB, benchAC)).to.be.greaterThan(0.95);
//            
//            // Naive comparisons of the same item with itself, or with obviously
//            // different items should be ridiculously fast
//            expect(difference(benchAA, naiveAA)).to.be.lessThan(0.01);
//            expect(difference(benchAB, naiveAB)).to.be.lessThan(0.01);
//            
//            // It should take just about as long to compare identical arrays as the constant time compare
//            expect(difference(benchAC, naiveAC)).to.be.greaterThan(0.90);
//            
//            function naiveEquals(a, b) {
//                if (a === b) return true;
//                for (var i = 0; i < a.length; i++) {
//                    if (a[i] !== b[i]) {
//                        return false;
//                    }
//                }
//                return true;
//            }
//            
//            function benchmark(fn, a, b) {
//                var time = process.hrtime();
//                for (var i = 0; i < 100; i++) {
//                    fn(a, b);
//                };
//                var diff = process.hrtime(time);
//                return diff[0] * 1e9 + diff[1];
//            }
//            
//            function difference(first, second) {
//                var smaller = Math.min(first, second);
//                var larger = Math.max(first, second);
//                return (smaller / larger);
//            }
//            
//        });

    });

    
    describe(@"binify()", ^{
        it(@"should return a binary version of the string", ^{
            NSData *binary = [Primitives binify:@"cartinir9_-"];
            NSData *expected = hexStringToData("71aaed8a78abf7ff");
            [binary shouldNotBeNil];
            [[binary should] equal:expected];
        });
    });
    
    describe(@"stringify()", ^{
        it(@"should return a base64url string", ^{
            NSData *buf = makeData(0x32, 10);
            NSString *str = [Primitives stringify:buf];
            [[theValue(str.length) should] equal:theValue(14)];
            [[str should] matchPattern:@"^[a-zA-Z0-9_-]+$"];
        });
    });
    
    describe(@"serialize()", ^{
        it(@"should return a Buffer", ^{
            NSData *bin = [Primitives serialize:@"abcd"];
            [[theValue(bin.length) should] equal:theValue(5)];
        });
    });
    
    describe(@"deserialize()", ^{
        it(@"should return a native primitive or object", ^{
            [[[Primitives deserialize:[Primitives serialize:[NSNumber numberWithInt:1]]] should] equal:theValue(1)];
            [[[Primitives deserialize:[Primitives serialize:@"abcd"]] should] equal:@"abcd"];
            [[[Primitives deserialize:[Primitives serialize:@[]]] should] equal:@[]];
            [[[Primitives deserialize:[Primitives serialize:@{}]] should] equal:@{}];
            [[[Primitives deserialize:[Primitives serialize:[NSNull null]]] should] equal:[NSNull null]];
            [[[Primitives deserialize:[Primitives serialize:@YES]] should] beYes];
            [[Primitives deserialize:[Primitives serialize:nil]] shouldBeNil];
        });
    });
    
    describe(@"zero()", ^{
        
        it(@"should overwrite all buffer contents with zeros", ^{
            NSMutableData *b = [hexStringToData("7468697320697320736f6d65") mutableCopy];
            NSData *z = hexStringToData("000000000000000000000000");
            
            [[b shouldNot] equal:z];
            [Primitives zero:b,nil];
            [[b should] equal:z];
        });
        
        it(@"should zero multiple buffers", ^{
            NSMutableData *b = [hexStringToData("7468697320697320736f6d65") mutableCopy];
            NSMutableData *c = [hexStringToData("697320736f6d657468697320") mutableCopy];
            NSData *z = hexStringToData("000000000000000000000000");
            
            // different contents
            [[b shouldNot] equal:z];
            [[c shouldNot] equal:z];
            [Primitives zero:b,c,nil];
            [[b should] equal:z];
            [[c should] equal:z];
        });
        
    });

    
});

SPEC_END

NSData * makeData(const int value, const size_t length)
{
    uint8_t bytes[length];
    memset(bytes, value, sizeof(bytes));
    NSData *data = [NSData dataWithBytes:bytes length:sizeof(bytes)];
    memset(bytes, 0, sizeof(bytes));
    return data;
}

NSData * hexStringToData(char *hex)
{
    return [NSData dataWithBytes:hexStringToBytes(hex) length:strlen(hex)/2];
}