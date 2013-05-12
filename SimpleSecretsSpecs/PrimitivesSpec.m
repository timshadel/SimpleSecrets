//
//  PrimitivesSpec.m
//  SimpleSecrets
//
//  Created by Tim Shadel on 5/11/13.
//  Copyright (c) 2013 Tim Shadel. All rights reserved.
//

#import "Kiwi.h"
#import "Primitives.h"

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

    describe(@"derive_sender_hmac", ^{
        it(@"should require a 256-bit master key", ^{
            uint8_t small[31];
            uint8_t exact[32];
            uint8_t large[33];
            memset(small, 0x33, sizeof(small));
            memset(exact, 0x33, sizeof(exact));
            memset(large, 0x33, sizeof(large));
            NSData *smallKey = [NSData dataWithBytes:small length:sizeof(small)];
            NSData *exactKey = [NSData dataWithBytes:exact length:sizeof(exact)];
            NSData *largeKey = [NSData dataWithBytes:large length:sizeof(large)];

            NSData *smallHmac = [Primitives deriveSenderHmacKeyFromMasterKey:smallKey];
            NSData *exactHmac = [Primitives deriveSenderHmacKeyFromMasterKey:exactKey];
            NSData *largeHmac = [Primitives deriveSenderHmacKeyFromMasterKey:largeKey];
            
            [smallHmac shouldBeNil];
            [exactHmac shouldNotBeNil];
            [largeHmac shouldBeNil];
        });

        it(@"should require a 256-bit master key", ^{
            uint8_t masterBytes[32];
            memset(masterBytes, 0xbc, sizeof(masterBytes));
            NSData *masterKey = [NSData dataWithBytes:masterBytes length:sizeof(masterBytes)];
            memset(masterBytes, 0, sizeof(masterBytes));
            NSData *hmacKey = [Primitives deriveSenderHmacKeyFromMasterKey:masterKey];
            [hmacKey shouldNotBeNil];
            [[theValue([hmacKey length]) should] equal:theValue(32)];
            uint8_t hmacKeyBytes[32] = { 0x1e, 0x2e, 0x27, 0x25, 0xf1, 0x35, 0x46, 0x3f, 0x05, 0xc2, 0x68, 0xff, 0xd1, 0xc1, 0x68, 0x7d, 0xbc, 0x9d, 0xd7, 0xda, 0x65, 0x40, 0x56, 0x97, 0x47, 0x10, 0x52, 0x23, 0x6b, 0x3b, 0x30, 0x88 };
            [[hmacKey should] equal:[NSData dataWithBytes:hmacKeyBytes length:32]];
        });

    });
    
//    it 'should derive a 256-bit hmac key from a 256-bit master key' do
//        master_key = 'bc'.hex_to_bin(32)
//        
//        hmac_key = Primitives.derive_sender_hmac(master_key);
//    expect(hmac_key.size).to eq(32)
//    expect(hmac_key).to eq('1e2e2725f135463f05c268ffd1c1687dbc9dd7da65405697471052236b3b3088'.hex_to_bin);
//    end
//    end
});

SPEC_END