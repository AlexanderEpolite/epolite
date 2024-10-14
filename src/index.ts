import { ml_kem512 } from '@noble/post-quantum/ml-kem';
import { Buffer } from 'buffer'; //for web

interface SIGN {
    publicKeyBytes: Promise<number>;
    privateKeyBytes: Promise<number>;
    signatureBytes: Promise<number>;
    keypair: () => Promise<{
        publicKey: Uint8Array;
        privateKey: Uint8Array;
    }>;
    sign: (message: Uint8Array, privateKey: Uint8Array) => Promise<{
        signature: Uint8Array;
    }>;
    verify: (signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array) => Promise<boolean>;
}

let signBuilder: (useFallback?: boolean, wasmFilePath?: string | undefined) => Promise<SIGN>;

if(typeof document !== "undefined")
    signBuilder = (await import('@dashlane/pqc-sign-falcon-512-browser') as any).default;
else
    signBuilder = (await import('@dashlane/pqc-sign-falcon-512-node') as any).default;

const EPOLITE_PUBLIC_KEY_LABEL = '----------BEGIN EPOLITE PUBLIC KEY----------';
const EPOLITE_PRIVATE_KEY_LABEL = '----------BEGIN EPOLITE PRIVATE KEY----------';
const KEY_END_LABEL = '----------END EPOLITE KEY----------';

export type KeyPair = {
    publicKey: string,
    privateKey: string,
};

/**
 * Generates a combined key pair for Kyber and Falcon.
 * 
 * @returns An object containing the public and private keys.
 */
export async function createKeyPair(): Promise<KeyPair> {
    // Generate Kyber key pair
    const kyberKeyPair = ml_kem512.keygen();

    // Initialize Falcon signing
    const sign = await signBuilder();

    // Generate Falcon key pair
    const falconKeyPair = await sign.keypair();

    // Combine public keys and private keys
    const publicKeyObj = {
        kyberPublicKey: Array.from(kyberKeyPair.publicKey),
        falconPublicKey: Array.from(falconKeyPair.publicKey),
    };

    const privateKeyObj = {
        kyberPrivateKey: Array.from(kyberKeyPair.secretKey),
        falconPrivateKey: Array.from(falconKeyPair.privateKey),
    };

    // Serialize and encode keys
    const publicKeyString = `${EPOLITE_PUBLIC_KEY_LABEL}\n${Buffer.from(
        JSON.stringify(publicKeyObj)
    ).toString('base64')}\n${KEY_END_LABEL}`;

    const privateKeyString = `${EPOLITE_PRIVATE_KEY_LABEL}\n${Buffer.from(
        JSON.stringify(privateKeyObj)
    ).toString('base64')}\n${KEY_END_LABEL}`;

    return {
        publicKey: publicKeyString,
        privateKey: privateKeyString,
    };
}

/**
 * Encrypts data using the recipient's public key.
 * 
 * @param data The data to encrypt.
 * @param otherPublicKey The recipient's public key.
 * 
 * @returns The encrypted data.
 */
export async function encrypt(data: string, otherPublicKey: string): Promise<string> {
    // Extract and decode the public key
    const publicKeyEncoded = otherPublicKey
        .replace(EPOLITE_PUBLIC_KEY_LABEL, '')
        .replace(KEY_END_LABEL, '')
        .trim();
    const publicKeyObj = JSON.parse(Buffer.from(publicKeyEncoded, 'base64').toString('utf-8'));
    const kyberPublicKey = new Uint8Array(publicKeyObj.kyberPublicKey);

    // Encapsulate shared secret using Kyber
    const aliceMeta = ml_kem512.encapsulate(kyberPublicKey);
    const sharedSecret = aliceMeta.sharedSecret;

    // Generate random IV for AES-GCM
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // Import the shared secret as a CryptoKey
    const aesKey = await crypto.subtle.importKey(
        'raw',
        sharedSecret.slice(0, 32),
        'AES-GCM',
        false,
        ['encrypt']
    );

    // Encrypt the data using AES-GCM
    const encryptedData = await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv,
        },
        aesKey,
        new TextEncoder().encode(data)
    );

    // Return cipherText, encryptedData, IV
    const payload = {
        cipherText: Array.from(aliceMeta.cipherText),
        encryptedData: Array.from(new Uint8Array(encryptedData)),
        iv: Array.from(iv),
    };

    return Buffer.from(JSON.stringify(payload)).toString('base64');
}

/**
 * Decrypts data using your private key.
 * 
 * @param encryptedPayload The encrypted data.
 */
export async function decrypt(encryptedPayload: string, privateKey: string): Promise<string> {
    // Decode the payload
    const payload = JSON.parse(Buffer.from(encryptedPayload, 'base64').toString('utf-8'));
    const cipherText = new Uint8Array(payload.cipherText);
    const encryptedData = new Uint8Array(payload.encryptedData);
    const iv = new Uint8Array(payload.iv);

    // Extract and decode the private key
    const privateKeyEncoded = privateKey
        .replace(EPOLITE_PRIVATE_KEY_LABEL, '')
        .replace(KEY_END_LABEL, '')
        .trim();
    const privateKeyObj = JSON.parse(Buffer.from(privateKeyEncoded, 'base64').toString('utf-8'));
    const kyberPrivateKey = new Uint8Array(privateKeyObj.kyberPrivateKey);

    // Decapsulate shared secret using Kyber
    const sharedSecret = ml_kem512.decapsulate(cipherText, kyberPrivateKey);
    
    // Import the shared secret as a CryptoKey
    const aesKey = await crypto.subtle.importKey(
        'raw',
        sharedSecret.slice(0, 32),
        'AES-GCM',
        false,
        ['decrypt']
    );

    // Decrypt the data using AES-GCM
    const decryptedData = await crypto.subtle.decrypt(
        {
            name: 'AES-GCM',
            iv,
        },
        aesKey,
        encryptedData
    );

    return new TextDecoder().decode(decryptedData);
}

/**
 * Signs data using the sender's private key.
 * 
 * @param data The data to sign.
 * @param privateKey The sender's private key.
 * 
 * @returns The signature.
 */
export async function sign(data: string, privateKey: string): Promise<string> {
    //extract and decode the private key
    const privateKeyEncoded = privateKey
        .replace(EPOLITE_PRIVATE_KEY_LABEL, '')
        .replace(KEY_END_LABEL, '')
        .trim();

    const privateKeyObj = JSON.parse(Buffer.from(privateKeyEncoded, 'base64').toString('utf-8'));
    const falconPrivateKey = new Uint8Array(privateKeyObj.falconPrivateKey);
    
    //sign using FALCON-512
    const sign = await signBuilder();

    const message = new TextEncoder().encode(data);
    const { signature } = await sign.sign(message, falconPrivateKey);

    return Buffer.from(signature).toString('base64');
}

/**
 * Verifies the signature using the sender's public key.
 * 
 * @param data The data that was signed.
 * @param signature The signature to verify.
 * @param publicKey The sender's public key.
 * 
 * @returns Whether the signature is valid.
 */
export async function verify(data: string, signature: string, publicKey: string): Promise<boolean> {
    //extract and decode the public key
    const publicKeyEncoded = publicKey
        .replace(EPOLITE_PUBLIC_KEY_LABEL, '')
        .replace(KEY_END_LABEL, '')
        .trim();

    const publicKeyObj = JSON.parse(Buffer.from(publicKeyEncoded, 'base64').toString('utf-8'));
    const falconPublicKey = new Uint8Array(publicKeyObj.falconPublicKey);
    
    //initialize Falcon signing
    const sign = await signBuilder();

    const message = new TextEncoder().encode(data);
    const signatureArray = new Uint8Array(Buffer.from(signature, 'base64'));

    const isValid = await sign.verify(signatureArray, message, falconPublicKey);

    return isValid;
}

