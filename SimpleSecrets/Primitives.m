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
#import <CommonCrypto/CommonHMAC.h>

static NSUInteger kNonceLength = 16;
static NSUInteger kIVLength = 16;
static NSUInteger kKeyLength = 32;
static NSUInteger kHashLength = 32;
static NSUInteger kIdentLength = 6;

@implementation Primitives

+ (NSMutableData *)nonce
{
    return [self mutableRandomDataWithLength:kNonceLength];
}

+ (NSMutableData *)mutableRandomDataWithLength:(NSUInteger)length
{
    NSMutableData *random = [NSMutableData dataWithLength:length];
    int errCode = SecRandomCopyBytes(kSecRandomDefault, random.length, random.mutableBytes);
    if (-1 == errCode) {
        memset(random.mutableBytes, 0, random.length);
        return nil;
    }
    return random;
}

+ (NSMutableData *)deriveKeyFromMasterKey:(NSData *)masterKey andRole:(char *)role
{
    if (masterKey.length != kKeyLength) {
        return nil;
    }

    NSMutableData *key = [NSMutableData dataWithLength:kKeyLength];
    
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
    CC_SHA256_Update(&ctx, masterKey.bytes, masterKey.length);
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
    if (key.length != kKeyLength) {
        return nil;
    }
    
    // iv + cipher output
    NSUInteger length = (16 + ceil(data.length * 1.0f / 16) * 16);
    NSMutableData *cipherData = [NSMutableData dataWithLength:length];
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

    [iv resetBytesInRange:NSMakeRange(0, kIVLength)];
    if (result == kCCSuccess) {
		//the returned NSData takes ownership of the buffer and will free it on deallocation
		return cipherData;
	}
    return nil;
}

+ (NSMutableData *)decryptData:(NSData *)data withKey:(NSData *)key andIV:(NSData *)iv
{
    if (key.length != kKeyLength || iv.length != kIVLength) {
        return nil;
    }
    
    NSMutableData *plaintext = [NSMutableData dataWithLength:data.length];
    size_t dataLength = 0;
    
    CCCryptorStatus
    result = CCCrypt(kCCDecrypt, // operation
                     kCCAlgorithmAES128, // Algorithm
                     kCCOptionPKCS7Padding, // options
                     key.bytes, // key
                     key.length, // keylength
                     iv.bytes,// iv
                     data.bytes, // dataIn
                     data.length, // dataInLength,
                     plaintext.mutableBytes, // dataOut
                     plaintext.length, // dataOutAvailable
                     &dataLength); // dataOutMoved
    
    [plaintext setLength:dataLength];
    if (result == kCCSuccess) {
		//the returned NSData takes ownership of the buffer and will free it on deallocation
		return plaintext;
	}
    return nil;
}

+ (NSMutableData *)identify:(NSData *)data
{
    if (data.length > UCHAR_MAX) {
        return nil;
    }

    NSMutableData *ident = [NSMutableData dataWithLength:kHashLength];
    unsigned char length = (unsigned char)data.length;
    
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
    CC_SHA256_Update(&ctx, &length, sizeof(unsigned char));
    CC_SHA256_Update(&ctx, data.bytes, data.length);
    CC_SHA256_Final(ident.mutableBytes, &ctx);
    [ident resetBytesInRange:NSMakeRange(kIdentLength, length-kIdentLength)];
    [ident setLength:kIdentLength];
    
    return ident;
}

+ (NSMutableData *)macForData:(NSData *)data withKey:(NSData *)key
{
    if (key.length != kKeyLength) {
        return nil;
    }
    
    NSMutableData *mac = [NSMutableData dataWithLength:kHashLength];
    
    CCHmac(kCCHmacAlgSHA256,
           key.bytes,
           key.length,
           data.bytes,
           data.length,
           mac.mutableBytes);

    return mac;
}

+ (BOOL)compare:(NSData *)a to:(NSData *)b
{
    if (a.length != b.length) return NO;
    
    uint8_t *abytes = (uint8_t *)a.bytes;
    uint8_t *bbytes = (uint8_t *)b.bytes;

    char result = 0;
    for (NSUInteger i = 0; i < a.length; i++) {
        result |= abytes[i] ^ bbytes[i];
    }

    return result == 0;
}

@end
