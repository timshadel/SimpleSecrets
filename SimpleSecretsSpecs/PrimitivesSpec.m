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