//
//  NSDictionary+MessagePack.m
//  Fetch TV Remote
//
//  Created by Chris Hulbert on 13/10/11.
//  Copyright (c) 2011 Digital Five. All rights reserved.
//

#import "NSDictionary+MessagePack.h"
#import "MessagePackPacker.h"

@implementation NSDictionary (NSDictionary_MessagePack)

// Packs the receiver's data into message pack data
- (NSData*)messagePack {
	return [MessagePackPacker pack:self];
}

@end
