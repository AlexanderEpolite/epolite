export type KeyPair = {
    publicKey: string;
    privateKey: string;
};
/**
 * Generates a combined key pair for Kyber and Falcon.
 *
 * @returns An object containing the public and private keys.
 */
export declare function createKeyPair(): Promise<KeyPair>;
/**
 * Encrypts data using the recipient's public key.
 *
 * @param data The data to encrypt.
 * @param otherPublicKey The recipient's public key.
 *
 * @returns The encrypted data.
 */
export declare function encrypt(data: string, otherPublicKey: string): Promise<string>;
/**
 * Decrypts data using your private key.
 *
 * @param encryptedPayload The encrypted data.
 */
export declare function decrypt(encryptedPayload: string, privateKey: string): Promise<string>;
/**
 * Signs data using the sender's private key.
 *
 * @param data The data to sign.
 * @param privateKey The sender's private key.
 *
 * @returns The signature.
 */
export declare function sign(data: string, privateKey: string): Promise<string>;
/**
 * Verifies the signature using the sender's public key.
 *
 * @param signature The signature to verify.
 * @param publicKey The sender's public key.
 *
 * @returns Whether the signature is valid.
 */
export declare function verify(signature: string, publicKey: string): Promise<boolean>;
