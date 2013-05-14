//
//  Primitives.h
//  SimpleSecrets
//
//  Created by Tim Shadel on 5/11/13.
//  Copyright (c) 2013 Tim Shadel. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface Primitives : NSObject

+ (NSMutableData *)nonce;
+ (NSMutableData *)deriveSenderHmacKeyFromMasterKey:(NSData *)masterKey;
+ (NSMutableData *)deriveSenderCipherKeyFromMasterKey:(NSData *)masterKey;
+ (NSMutableData *)deriveReceiverHmacKeyFromMasterKey:(NSData *)masterKey;
+ (NSMutableData *)deriveReceiverCipherKeyFromMasterKey:(NSData *)masterKey;

+ (NSMutableData *)encryptData:(NSData *)data withKey:(NSData *)key;
+ (NSMutableData *)decryptData:(NSData *)data withKey:(NSData *)key andIV:(NSData *)iv;

+ (NSMutableData *)identify:(NSData *)data;
+ (NSMutableData *)macForData:(NSData *)data withKey:(NSData *)key;

+ (BOOL)compare:(NSData *)a to:(NSData *)b;
+ (NSData *)binify:(NSString *)websafe;
+ (NSString *)stringify:(NSData *)binary;

+ (NSData *)serialize:(id)object;
+ (id)deserialize:(NSData *)buffer;


@end
