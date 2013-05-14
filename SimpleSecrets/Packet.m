//
//  Packet.m
//  SimpleSecrets
//
//  Created by Tim Shadel on 5/14/13.
//  Copyright (c) 2013 Tim Shadel. All rights reserved.
//

#import "Packet.h"
#import "Primitives.h"


NSMutableData * buildBody(id);
NSMutableData * bodyToData(NSData *);
NSMutableData * encryptBody(NSData *, NSData *);
NSMutableData * decryptBody(NSData *, NSData *);
NSMutableData * authenticate(NSData *, NSData *, NSData *);
NSMutableData * verify(NSData *, NSData *, NSData *);


@interface Packet ()
@property (nonatomic, strong) NSMutableData *masterKey;
@property (nonatomic, strong) NSMutableData *keyId;
@end

@implementation Packet

- (id)initWithKey:(NSData *)key
{
    self = [super init];
    if (self) {
        self.masterKey = [key mutableCopy];
        self.keyId = [Primitives identify:self.masterKey];
    }
    return self;
}

- (NSString *)pack:(id)object
{
    NSMutableData *body = buildBody(object);
    NSMutableData *encrypted = encryptBody(body, self.masterKey);
    NSMutableData *packet = authenticate(encrypted, self.masterKey, self.keyId);
    NSString *websafe = [Primitives stringify:packet];
    
    [Primitives zero:body, encrypted, packet, nil];
    return websafe;
}

- (id)unpack:(NSString *)websafe
{
    NSMutableData *packet = [Primitives binify:websafe];
    NSMutableData *cipherdata = verify(packet, self.masterKey, self.keyId);
    NSMutableData *body = nil;
    NSMutableData *data = nil;
    
    if (cipherdata) {
        body = decryptBody(cipherdata, self.masterKey);
        data = bodyToData(body);
        [Primitives zero:body, cipherdata, nil];
    }

    [Primitives zero:packet, nil];
    return data;
}

@end


NSMutableData * buildBody(id data) {
    NSMutableData *nonce = [Primitives nonce];
    NSData *bindata = [Primitives serialize:data];
    NSMutableData *body = [NSMutableData dataWithCapacity:(nonce.length+bindata.length)];
    [body appendData:nonce];
    [body appendData:bindata];
    
    [Primitives zero:nonce, bindata, nil];
    return body;
}

NSMutableData * bodyToData(NSData *body) {
    NSMutableData *nonce = [NSMutableData dataWithBytes:body.bytes length:16];
    NSMutableData *bindata = [NSMutableData dataWithBytes:(body.bytes+16) length:(body.length-16)];
    NSMutableData *data = [Primitives deserialize:bindata];
    
    [Primitives zero:nonce, bindata, nil];
    return data;
}

NSMutableData * encryptBody(NSData *body, NSData *master) {
    NSMutableData *key = [Primitives deriveSenderCipherKeyFromMasterKey:master];
    NSMutableData *cipherdata = [Primitives encryptData:body withKey:master];
    
    [Primitives zero:key, nil];
    return cipherdata;
}

NSMutableData * decryptBody(NSData *cipherdata, NSData *master) {
    NSMutableData *key = [Primitives deriveSenderCipherKeyFromMasterKey:master];
    NSMutableData *iv = [NSMutableData dataWithBytes:cipherdata.bytes length:16];
    NSMutableData *encrypted = [NSMutableData dataWithBytes:(cipherdata.bytes+16) length:(cipherdata.length-16)];
    NSMutableData *body = [Primitives decryptData:encrypted withKey:key andIV:iv];
    
    [Primitives zero:key, iv, encrypted, nil];
    return body;
}

NSMutableData * authenticate(NSData *data, NSData *master, NSData *keyId) {
    // Authenticate the (keyId || iv || ciphertext); bundle it all together
    NSMutableData *hmacKey = [Primitives deriveSenderHmacKeyFromMasterKey:master];
    NSMutableData *auth = [NSMutableData dataWithCapacity:(keyId.length+data.length)];
    [auth appendData:keyId];
    [auth appendData:data];
    NSMutableData *mac = [Primitives macForData:auth withKey:hmacKey];
    NSMutableData *packet = [NSMutableData dataWithCapacity:(keyId.length+data.length+mac.length)];
    [packet appendData:keyId];
    [packet appendData:data];
    [packet appendData:mac];
    
    [Primitives zero:hmacKey, mac, auth];
    return packet;
}

NSMutableData * verify(NSData *packet, NSData *master, NSData *keyId) {
    // Authenticate the (keyId || iv || ciphertext); bundle it all together
    NSMutableData *packetKeyId = [NSMutableData dataWithBytes:packet.bytes length:6];
    
    if (![Primitives compare:packetKeyId to:keyId]) {
        return nil;
    }
    
    NSMutableData *auth = [NSMutableData dataWithBytes:packet.bytes length:(packet.length-32)];
    NSMutableData *packetMac = [NSMutableData dataWithBytes:(packet.bytes+packet.length-32) length:32];
    
    NSMutableData *hmacKey = [Primitives deriveSenderHmacKeyFromMasterKey:master];
    NSMutableData *mac = [Primitives macForData:auth withKey:hmacKey];
    BOOL valid = [Primitives compare:packetMac to:mac];
    
    NSMutableData *data = valid ? [NSMutableData dataWithBytes:packet.bytes+6 length:(packet.length-32-6)] : nil;
    
    [Primitives zero:hmacKey, mac, auth, packetKeyId, packetMac, nil];
    return data;
}
