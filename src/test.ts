import { createKeyPair, decrypt, encrypt, sign, verify } from ".";

const aliceKeys = await createKeyPair();  //Alice's key pair
const bobKeys = await createKeyPair();    //Bob's key pair

const message = "Cool beans";

//step 1: Alice signs the message
const signature = await sign(message, aliceKeys.privateKey);
const signedMessage = JSON.stringify({ message, signature });

//Step 2: Alice encrypts the signed message
const encryptedMessage = await encrypt(signedMessage, bobKeys.publicKey);

//Step 3: Bob decrypts the message
const decryptedMessage = await decrypt(encryptedMessage, bobKeys.privateKey);
const { message: decryptedText, signature: decryptedSignature } = JSON.parse(decryptedMessage);

//Step 4: Bob verifies the signature
const isValid = await verify(decryptedSignature, aliceKeys.publicKey);

console.log('Decrypted Message:', decryptedText);  // Should output the original message
console.log('Signature valid:', isValid);          // Should output true if the signature is valid

console.log(`sig: ${signature}`)