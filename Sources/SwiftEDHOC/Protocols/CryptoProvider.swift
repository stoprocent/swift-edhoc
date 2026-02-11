import Foundation

/// A public/private key pair
public struct KeyPair: Sendable {
    public let publicKey: Data
    public let privateKey: Data

    public init(publicKey: Data, privateKey: Data) {
        self.publicKey = publicKey
        self.privateKey = privateKey
    }
}

/// Protocol for EDHOC cryptographic operations
///
/// Implementations provide all cryptographic primitives needed by EDHOC:
/// ECDH, signatures, HKDF, AEAD, and hashing. Operations take raw key bytes
/// directly rather than opaque key IDs.
///
/// The default implementation is `CryptoKitProvider`.
public protocol EdhocCryptoProvider: Sendable {
    /// Generate a DH key pair.
    /// Returns raw key pair (32 bytes for X25519/Ed25519, 32-byte private + 32-byte x-coordinate for P-256).
    func generateKeyPair(suite: EdhocCipherSuite) throws -> KeyPair

    /// Perform ECDH key agreement. Returns the raw shared secret bytes.
    func keyAgreement(suite: EdhocCipherSuite, privateKey: Data, peerPublicKey: Data) throws -> Data

    /// Sign the input data. Returns the signature bytes.
    func sign(suite: EdhocCipherSuite, privateKey: Data, input: Data) throws -> Data

    /// Verify a signature against the input data.
    func verify(suite: EdhocCipherSuite, publicKey: Data, input: Data, signature: Data) throws -> Bool

    /// HKDF-Extract(IKM, salt). Returns PRK of hashLength bytes.
    func hkdfExtract(suite: EdhocCipherSuite, ikm: Data, salt: Data) throws -> Data

    /// HKDF-Expand(PRK, info, length). Returns OKM of the given length.
    func hkdfExpand(suite: EdhocCipherSuite, prk: Data, info: Data, length: Int) throws -> Data

    /// AEAD encrypt. Returns ciphertext || tag.
    func encrypt(suite: EdhocCipherSuite, key: Data, nonce: Data, aad: Data, plaintext: Data) throws -> Data

    /// AEAD decrypt. Input is ciphertext || tag. Returns plaintext.
    func decrypt(suite: EdhocCipherSuite, key: Data, nonce: Data, aad: Data, ciphertext: Data) throws -> Data

    /// Compute a cryptographic hash. Returns hash of hashLength bytes.
    func hash(suite: EdhocCipherSuite, data: Data) throws -> Data
}
