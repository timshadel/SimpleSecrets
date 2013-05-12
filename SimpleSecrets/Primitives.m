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
#import <CommonCrypto/CommonCryptor.h>

static NSUInteger kNonceLength = 16;
static NSUInteger kIVLength = 16;
static NSUInteger kKeyLength = 32;

static uint8_t zeros[2048] = { 0 };

@implementation Primitives

+ (NSMutableData *)nonce
{
    return [self mutableRandomDataWithLength:kNonceLength];
}

+ (NSMutableData *)mutableRandomDataWithLength:(NSUInteger)length
{
    NSMutableData *random = [NSMutableData dataWithBytes:zeros length:length];
    int errCode = SecRandomCopyBytes(kSecRandomDefault, random.length, random.mutableBytes);
    if (-1 == errCode) {
        memset(random.mutableBytes, 0, random.length);
        return nil;
    }
    return random;
}

+ (NSMutableData *)deriveKeyFromMasterKey:(NSData *)masterKey andRole:(char *)role
{
    if ([masterKey length] != kKeyLength) {
        return nil;
    }

    NSMutableData *key = [NSMutableData dataWithBytes:zeros length:kKeyLength];
    
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
    CC_SHA256_Update(&ctx, [masterKey bytes], [masterKey length]);
    CC_SHA256_Update(&ctx, role, strlen(role));
    CC_SHA256_Final(key.mutableBytes, &ctx);
    
    return key;
}

+ (NSMutableData *)deriveSenderHmacKeyFromMasterKey:(NSData *)masterKey
{
    return [self deriveKeyFromMasterKey:masterKey andRole:"simple-crypto/sender-hmac-key"];
}

+ (NSMutableData *)deriveSenderCipherKeyFromMasterKey:(NSData *)masterKey
{
    return [self deriveKeyFromMasterKey:masterKey andRole:"simple-crypto/sender-cipher-key"];
}

+ (NSMutableData *)deriveReceiverHmacKeyFromMasterKey:(NSData *)masterKey
{
    return [self deriveKeyFromMasterKey:masterKey andRole:"simple-crypto/receiver-hmac-key"];
}

+ (NSMutableData *)deriveReceiverCipherKeyFromMasterKey:(NSData *)masterKey
{
    return [self deriveKeyFromMasterKey:masterKey andRole:"simple-crypto/receiver-cipher-key"];
}

+ (NSMutableData *)encryptData:(NSData *)data withKey:(NSData *)key
{
    // iv + cipher output
    NSUInteger length = (16 + ceil(data.length * 1.0f / 16) * 16);
    NSMutableData *cipherData = [NSMutableData dataWithBytes:zeros length:length];
    size_t cipherDataLength = 0;
    NSMutableData *iv = [self mutableRandomDataWithLength:kIVLength];
    [cipherData replaceBytesInRange:NSMakeRange(0, kIVLength) withBytes:iv.bytes];

    CCCryptorStatus
    result = CCCrypt(kCCEncrypt, // operation
                     kCCAlgorithmAES128, // Algorithm
                     kCCOptionPKCS7Padding, // options
                     key.bytes, // key
                     key.length, // keylength
                     iv.bytes,// iv
                     data.bytes, // dataIn
                     data.length, // dataInLength,
                     cipherData.mutableBytes+16, // dataOut
                     cipherData.length-16, // dataOutAvailable
                     &cipherDataLength); // dataOutMoved

    [iv replaceBytesInRange:NSMakeRange(0, kIVLength) withBytes:zeros];
    if (result == kCCSuccess) {
		//the returned NSData takes ownership of the buffer and will free it on deallocation
		return cipherData;
	}
    return nil;
}

@end
