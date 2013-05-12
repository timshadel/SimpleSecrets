//
//  Primitives.m
//  SimpleSecrets
//
//  Created by Tim Shadel on 5/11/13.
//  Copyright (c) 2013 Tim Shadel. All rights reserved.
//

#import "Primitives.h"
#import <Security/SecRandom.h>
#import <CommonCrypto/CommonDigest.h>

@implementation Primitives

+ (NSData *)nonce
{
    static size_t count = 16;
    uint8_t bytes[count];
    memset(bytes, 0, sizeof(bytes));
    int errCode = SecRandomCopyBytes(kSecRandomDefault, count, bytes);
    if (-1 == errCode) {
        memset(bytes, 0, sizeof(bytes));
        return nil;
    }
    NSData *nonce = [NSData dataWithBytes:bytes length:count];
    memset(bytes, 0, sizeof(bytes));
    return nonce;
}

+ (NSData *)deriveKeyFromMasterKey:(NSData *)masterKey andRole:(char *)role
{
    if ([masterKey length] != 32) {
        return nil;
    }
    
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
    CC_SHA256_Update(&ctx, [masterKey bytes], [masterKey length]);
    CC_SHA256_Update(&ctx, role, strlen(role));

    uint8_t keyBytes[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(keyBytes, &ctx);
    NSData *key = [NSData dataWithBytes:keyBytes length:sizeof(keyBytes)];
    memset(keyBytes, 0, sizeof(keyBytes));
    
    return key;
}

+ (NSData *)deriveSenderHmacKeyFromMasterKey:(NSData *)masterKey
{
    return [self deriveKeyFromMasterKey:masterKey andRole:"simple-crypto/sender-hmac-key"];
}

+ (NSData *)deriveSenderCipherKeyFromMasterKey:(NSData *)masterKey
{
    return [self deriveKeyFromMasterKey:masterKey andRole:"simple-crypto/sender-cipher-key"];
}

+ (NSData *)deriveReceiverHmacKeyFromMasterKey:(NSData *)masterKey
{
    return [self deriveKeyFromMasterKey:masterKey andRole:"simple-crypto/receiver-hmac-key"];
}

+ (NSData *)deriveReceiverCipherKeyFromMasterKey:(NSData *)masterKey
{
    return [self deriveKeyFromMasterKey:masterKey andRole:"simple-crypto/receiver-cipher-key"];
}

@end
