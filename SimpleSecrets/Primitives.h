//
//  Primitives.h
//  SimpleSecrets
//
//  Created by Tim Shadel on 5/11/13.
//  Copyright (c) 2013 Tim Shadel. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface Primitives : NSObject

+ (NSData *)nonce;
+ (NSData *)deriveSenderHmacKeyFromMasterKey:(NSData *)masterKey;
+ (NSData *)deriveSenderCipherKeyFromMasterKey:(NSData *)masterKey;
+ (NSData *)deriveReceiverHmacKeyFromMasterKey:(NSData *)masterKey;
+ (NSData *)deriveReceiverCipherKeyFromMasterKey:(NSData *)masterKey;

@end
