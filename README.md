
# SimpleSecrets

The Objective-C implementation of a simple, opinionated library for encrypting small packets of data securely. Designed for exchanging tokens among systems written in a variety of programming languages:

* [Node.js](https://github.com/timshadel/simple-secrets)
* [Ruby](https://github.com/timshadel/simple-secrets.rb)
* [Rust](https://github.com/timshadel/simple-secrets.rs)
* [Objective-C](https://github.com/timshadel/SimpleSecrets)
* [Java](https://github.com/timshadel/simple-secrets.java)
* [Erlang](https://github.com/CamShaft/simple_secrets.erl)

## Examples

### Basic

Send:

```objc
#import <SimpleSecrets/Packet.h>

// Try `head /dev/urandom | shasum -a 256` to make a decent 256-bit key
NSData *masterKey = hexCStringToData("<64-char hex string (32 bytes, 256 bits)>");
// => <71c86756 234bfd3c 37...>

Packet *sender = [Packet packetWithMasterKey:master_key];

NSString *websafe = [sender pack:@{ @"msg": @"this is a secret message" }];
// => 'OqlG6KVMeyFYmunboS3HIXkvN_nXKTxg2yNkQydZOhvJrZvmfov54hUmkkiZCnlhzyrlwOJkbV7XnPPbqvdzZ6TsFOO5YdmxjxRksZmeIhbhLaMiDbfsOuSY1dBn_ZgtYCw-FRIM'
```

Receive:

```objc
#import <SimpleSecrets/Packet.h>

// Same shared key
NSData *masterKey = hexCStringToData("<shared-key-hex>");
Packet *sender = [Packet packetWithMasterKey:master_key];
// read data from somewhere
NSString *websafe = @"OqlG6KVMeyFYmunboS3HIXkvN_nXKTxg2yNkQydZOhvJrZvmfov54hUmkkiZCnlhzyrlwOJkbV7XnPPbqvdzZ6TsFOO5YdmxjxRksZmeIhbhLaMiDbfsOuSY1dBn_ZgtYCw-FRIM";

id secret_message = [sender unpack:packet];
// => {
//      msg: "this is a secret message"
//    }
```


## Can you add ...

This implementation follows the spec for the [Node.js](https://github.com/timshadel/simple-secrets) version for 100% compatibility.

## License 

MIT.
