# EPOLITE Privacy Guard

### Efficient Post-Quantum Optimized Lattice-based Implementation of Trusted Encryption

## GPG-Like Post Quantum Encryption
This library contains a public/private keypair system which can be used for post-quantum encryption between users.

### Standards used
1. FALCON-512 is used for signing messages, to be used prior to encryption.
2. Kyber-512 is used for encrypting messages (was Kyber-1024), to be used to encrypt messages using AES.

Kyber 1024 *was* used; however, it was changed to 512 due to the unreasonable size of messages, upwards of 200 KB for a single byte message, scaling at O(n).

In the future, this may be updated to include other PQ encryption standards; however, these are the ones I chose for now.

### Disclaimers
1. This library, while functional, has not been audited, either by me or anyone else.
2. The returned encrypted messages are **_MASSIVE_**.  You can expect a 4 KB encrypted message from a 10 byte input, and at least 5x when the input is signed.
3. I cannot guarantee any encryption standards used in this library to be vulnerability or exploit free.  While they are approved by the NIST, I personally do not fully endorse them due to how new these standards are.
4. This library uses crypto subtle, and was designed specifically for browser use.

## Using this library
This library is specifically built for the [Bun Runtime](https://bun.sh).  Please install that and replace Node.JS with this runtime, as it is much faster.

Afterwards, run `bun add epolite` to install this package, and then use the documentation below.


### Examples
#### Create Keypair
```ts
import {createKeyPair, type KeyPair} from "epolite";

//returns an object containing {publicKey: string, privateKey: string}
const kp: KeyPair = await createKeyPair();

console.log(kp.publicKey, kp.privateKey);
```


#### Encrypt
```ts
import {encrypt} from "epolite";

//publicKey is a string, starting with "----------BEGIN EPOLITE PUBLIC KEY----------"
//returns a base64 encoded string of the encrypted message
const encryptedString: string = await encrypt("deadbeef", publicKey);

console.log("Very, very long encrypted string:", encryptedString);
```

#### Decrypt
```ts
import {decrypt} from "epolite";

//returns the decrypted message as a string
const decryptedString: string = await decrypt(encryptedString, privateKey);

console.log("Decrypted message:", decryptedString);
```

#### Signing
```ts
import {sign} from "epolite";

//returns a base64 encoded string (signatures aren't too big).
const signedMessage: string = await sign("I do not like pineapple pizza", privateKey);

console.log("Signed message:", signedMessage);
```

#### Verifying
```ts
import {verify} from "epolite";

const realMessage: string = "I do not like pineapple pizza";
const fakeMessage: string = "I LOVE pineapple on pizza";

const verified: boolean = await verify(realMessage, signedMessage, publicKey); //true
const notVerified: boolean = await verify(fakeMessage, signedMessage, publicKey); //false
```

### More examples

You can find an example in `src/test.ts`.


## Contributing
Since this is for my own project, I likely not be merging or reviewing pull requests.