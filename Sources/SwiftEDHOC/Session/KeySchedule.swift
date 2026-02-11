import Foundation
import SwiftCBOR

/// Stateless EDHOC key schedule helpers
public enum KeySchedule {

    /// EDHOC-KDF(PRK, label, context, length) = HKDF-Expand(PRK, info, length)
    ///
    /// `info` is a CBOR sequence (not array-wrapped) of (label, context, length):
    ///   - label: CBOR unsigned int
    ///   - context: CBOR byte string
    ///   - length: CBOR unsigned int
    public static func kdf(
        crypto: EdhocCryptoProvider,
        suite: EdhocCipherSuite,
        prk: Data,
        label: Int,
        context: Data,
        length: Int
    ) throws -> Data {
        let info = CBORSerialization.encodeSequence([
            .unsignedInt(UInt64(label)),
            .byteString(Array(context)),
            .unsignedInt(UInt64(length))
        ])
        return try crypto.hkdfExpand(suite: suite, prk: prk, info: info, length: length)
    }

    /// HKDF-Extract(IKM, salt)
    public static func hkdfExtract(
        crypto: EdhocCryptoProvider,
        suite: EdhocCipherSuite,
        ikm: Data,
        salt: Data
    ) throws -> Data {
        try crypto.hkdfExtract(suite: suite, ikm: ikm, salt: salt)
    }

    /// Compute a cryptographic hash using the suite's hash algorithm.
    public static func hash(
        crypto: EdhocCryptoProvider,
        suite: EdhocCipherSuite,
        data: Data
    ) throws -> Data {
        try crypto.hash(suite: suite, data: data)
    }

    /// Derive PRK_3e2m from PRK_2e.
    ///
    /// - Methods 0, 2: no static DH from responder, return PRK_2e directly.
    /// - Methods 1, 3: SALT_3e2m = KDF(PRK_2e, 1, TH_2, hashLength),
    ///   then PRK_3e2m = Extract(G_RX, SALT_3e2m).
    public static func derivePrk3e2m(
        crypto: EdhocCryptoProvider,
        suite: EdhocCipherSuite,
        method: EdhocMethod,
        prk2e: Data,
        th: Data,
        gRX: Data?
    ) throws -> Data {
        if (method == .method1 || method == .method3), let gRX = gRX {
            let salt = try kdf(
                crypto: crypto, suite: suite, prk: prk2e,
                label: KDFLabel.salt3e2m.rawValue, context: th,
                length: suite.parameters.hashLength
            )
            return try hkdfExtract(crypto: crypto, suite: suite, ikm: gRX, salt: salt)
        }
        return prk2e
    }

    /// Derive PRK_4e3m from PRK_3e2m.
    ///
    /// - Methods 0, 1: no static DH from initiator, return PRK_3e2m directly.
    /// - Methods 2, 3: SALT_4e3m = KDF(PRK_3e2m, 5, TH_3, hashLength),
    ///   then PRK_4e3m = Extract(G_IX, SALT_4e3m).
    ///
    /// - Note: Uses label 5 (`salt4e3m`) per RFC 9528. The TypeScript reference
    ///   implementation incorrectly uses label 7.
    public static func derivePrk4e3m(
        crypto: EdhocCryptoProvider,
        suite: EdhocCipherSuite,
        method: EdhocMethod,
        prk3e2m: Data,
        th3: Data,
        gIX: Data?
    ) throws -> Data {
        if (method == .method2 || method == .method3), let gIX = gIX {
            let salt = try kdf(
                crypto: crypto, suite: suite, prk: prk3e2m,
                label: KDFLabel.salt4e3m.rawValue, context: th3,
                length: suite.parameters.hashLength
            )
            return try hkdfExtract(crypto: crypto, suite: suite, ikm: gIX, salt: salt)
        }
        return prk3e2m
    }

    /// Determine the MAC length for a given method and role.
    ///
    /// When authenticating with a signature the MAC is hash-length (full);
    /// when authenticating with static DH the MAC is the shorter `macLength`.
    public static func macLength(method: EdhocMethod, role: EdhocRole, suite: EdhocCipherSuite) -> Int {
        let usesSig: Bool
        switch role {
        case .responder:
            usesSig = method.responderUsesSignature
        case .initiator:
            usesSig = method.initiatorUsesSignature
        }
        return usesSig ? suite.parameters.hashLength : suite.parameters.macLength
    }
}
