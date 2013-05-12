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

@end
