import { ml_kem512 } from "@noble/post-quantum/ml-kem";
import { Buffer } from "buffer"; //for web

const VERSION = 4; //incremental versions, each one is not compatible with earlier ones.

function makeBigInt(arr: number[]): string {
    let bigInt = BigInt(0);
    
    for (let i = 0; i < arr.length; i++) {
        bigInt = (bigInt << BigInt(8)) | BigInt(arr[i]);
    }
    
    return `${bigInt}`;
}

function makeArray(bas: string) {
    let b = BigInt(bas);
    
    const arr = [];
    
    while (b > 0) {
        arr.unshift(Number(b & BigInt(0xFF)));
        b >>= BigInt(8);
    }
    
    return arr;
}

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
    signBuilder = (await import("@dashlane/pqc-sign-falcon-512-browser") as any).default;
else
    signBuilder = (await import("@dashlane/pqc-sign-falcon-512-node") as any).default;

const EPOLITE_PUBLIC_KEY_LABEL  = "----------BEGIN EPOLITE PUBLIC KEY----------";
const EPOLITE_PRIVATE_KEY_LABEL = "----------BEGIN EPOLITE PRIVATE KEY----------";

const KEY_END_LABEL             = "----------END EPOLITE KEY----------";

const SIGN_START_LABEL          = "----------BEGIN EPOLITE SIGNED MESSAGE----------";
const SIGN_END_LABEL            = "----------END EPOLITE SIGNED MESSAGE----------";

const ENCRYPTED_START_LABEL     = "----------BEGIN EPOLITE ENCRYPTED MESSAGE----------";
const ENCRYPTED_END_LABEL       = "----------END EPOLITE ENCRYPTED MESSAGE----------";

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
        version: VERSION,
        kyberPublicKey: makeBigInt(Array.from(kyberKeyPair.publicKey)),
        falconPublicKey: makeBigInt(Array.from(falconKeyPair.publicKey)),
    };

    const privateKeyObj = {
        version: VERSION,
        kyberPrivateKey: makeBigInt(Array.from(kyberKeyPair.secretKey)),
        falconPrivateKey: makeBigInt(Array.from(falconKeyPair.privateKey)),
    };

    // Serialize and encode keys
    const publicKeyString = `${EPOLITE_PUBLIC_KEY_LABEL}\n${Buffer.from(
        JSON.stringify(publicKeyObj)
    ).toString("base64")}\n${KEY_END_LABEL}`;

    const privateKeyString = `${EPOLITE_PRIVATE_KEY_LABEL}\n${Buffer.from(
        JSON.stringify(privateKeyObj)
    ).toString("base64")}\n${KEY_END_LABEL}`;

    return {
        publicKey: publicKeyString,
        privateKey: privateKeyString,
    };
}

/**
 * Encrypts data using the recipient"s public key.
 * 
 * @param data The data to encrypt.
 * @param otherPublicKey The recipient"s public key.
 * 
 * @returns The encrypted data.
 */
export async function encrypt(data: string, otherPublicKey: string): Promise<string> {
    // Extract and decode the public key
    const publicKeyEncoded = otherPublicKey
        .replace(EPOLITE_PUBLIC_KEY_LABEL, "")
        .replace(KEY_END_LABEL, "")
        .trim();
    
    const publicKeyObj = JSON.parse(Buffer.from(publicKeyEncoded, "base64").toString("utf-8"));
    const kyberPublicKey = new Uint8Array(makeArray(publicKeyObj.kyberPublicKey));

    // Encapsulate shared secret using Kyber
    const aliceMeta = ml_kem512.encapsulate(kyberPublicKey);
    const sharedSecret = aliceMeta.sharedSecret;

    // Generate random IV for AES-GCM
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // Import the shared secret as a CryptoKey
    const aesKey = await crypto.subtle.importKey(
        "raw",
        sharedSecret.slice(0, 32),
        "AES-GCM",
        false,
        ["encrypt"]
    );
    
    // Encrypt the data using AES-GCM
    const encryptedData = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv,
        },
        aesKey,
        new TextEncoder().encode(data)
    );
    
    // Return cipherText, encryptedData, IV
    const payload = {
        cipherText: Buffer.from(aliceMeta.cipherText).toString("base64"),
        encryptedData: Buffer.from(encryptedData).toString("base64"),
        iv: Array.from(iv),
        version: VERSION,
    };
    
    return ENCRYPTED_START_LABEL + "\n" + Buffer.from(JSON.stringify(payload)).toString("base64") + "\n" + ENCRYPTED_END_LABEL;
}

/**
 * Decrypts data using your private key.
 * 
 * @param encryptedPayload The encrypted data.
 */
export async function decrypt(encryptedPayload: string, privateKey: string): Promise<string> {
    
    encryptedPayload = encryptedPayload.replace(ENCRYPTED_START_LABEL, "").replace(ENCRYPTED_END_LABEL, "").trim();
    
    //decode payload
    const payload = JSON.parse(Buffer.from(encryptedPayload, "base64").toString("utf-8"));
    const cipherText = new Uint8Array(Buffer.from(payload.cipherText, "base64"));
    const encryptedData = new Uint8Array(Buffer.from(payload.encryptedData, "base64"));
    const iv = new Uint8Array(payload.iv);
    
    const privateKeyEncoded = privateKey
        .replace(EPOLITE_PRIVATE_KEY_LABEL, "")
        .replace(KEY_END_LABEL, "")
        .trim();
    
    const privateKeyObj = JSON.parse(Buffer.from(privateKeyEncoded, "base64").toString("utf-8"));
    const kyberPrivateKey = new Uint8Array(makeArray(privateKeyObj.kyberPrivateKey));
    
    //decapsulate shared secret using Kyber
    const sharedSecret = ml_kem512.decapsulate(cipherText, kyberPrivateKey);
    
    //import the shared secret as a CryptoKey
    const aesKey = await crypto.subtle.importKey(
        "raw",
        sharedSecret.slice(0, 32),
        "AES-GCM",
        false,
        ["decrypt"]
    );

    //decrypt the data using AES-GCM
    const decryptedData = await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv,
        },
        aesKey,
        encryptedData
    );

    return new TextDecoder().decode(decryptedData);
}

/**
 * Signs data using the sender"s private key.
 * 
 * @param data The data to sign.
 * @param privateKey The sender"s private key.
 * 
 * @returns The signature.
 */
export async function sign(data: string, privateKey: string): Promise<string> {
    //extract and decode the private key
    const privateKeyEncoded = privateKey
        .replace(EPOLITE_PRIVATE_KEY_LABEL, "")
        .replace(KEY_END_LABEL, "")
        .trim();
    
    const privateKeyObj = JSON.parse(Buffer.from(privateKeyEncoded, "base64").toString("utf-8"));
    const falconPrivateKey = new Uint8Array(makeArray(privateKeyObj.falconPrivateKey));
    
    //sign using FALCON-512
    const sign = await signBuilder();
    
    const message = new TextEncoder().encode(data);
    const { signature } = await sign.sign(message, falconPrivateKey);
    
    const ro = JSON.stringify({
        sig: Buffer.from(signature).toString("base64"),
        raw: data,
        version: VERSION,
    });
    
    return SIGN_START_LABEL + "\n" + Buffer.from(ro).toString("base64") + "\n" + SIGN_END_LABEL;
}

/**
 * Verifies the signature using the sender"s public key.
 * 
 * @param signature The signature to verify.
 * @param publicKey The sender"s public key.
 * 
 * @returns The signed message, or null if invalid.
 */
export async function verify(signature: string, publicKey: string): Promise<{message: string} | null> {
    //extract and decode the public key
    const publicKeyEncoded = publicKey
        .replace(EPOLITE_PUBLIC_KEY_LABEL, "")
        .replace(KEY_END_LABEL, "")
        .trim();
    
    signature = signature.replace(SIGN_START_LABEL, "").replace(SIGN_END_LABEL, "").trim();
    
    const publicKeyObj = JSON.parse(Buffer.from(publicKeyEncoded, "base64").toString("utf-8"));
    const falconPublicKey = new Uint8Array(makeArray(publicKeyObj.falconPublicKey));
    
    //initialize Falcon signing
    const sign = await signBuilder();
    
    const jp = JSON.parse(Buffer.from(signature, "base64").toString("utf-8"));
    
    const message = new TextEncoder().encode(jp.raw);
    const signatureArray = new Uint8Array(Buffer.from(jp.sig, "base64"));
    
    const isValid = await sign.verify(signatureArray, message, falconPublicKey);
    
    return isValid ? {message: jp.raw} : null;
}

