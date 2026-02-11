import Foundation
import SwiftCBOR

/// Helper functions for EDHOC message construction
public enum MessageHelpers {

    /// Build the MAC context bytes: << [C_R,] ID_CRED_x, TH_x, CRED_x, ?EAD >>
    ///
    /// - Parameters:
    ///   - cRCbor: Optional CBOR-encoded connection ID (nil for message 3).
    ///   - idCredCbor: Already CBOR-encoded ID_CRED bytes.
    ///   - th: Raw transcript hash bytes (will be CBOR-encoded as bstr).
    ///   - credXCbor: Pre-encoded CRED_x CBOR item (bstr-wrapped for DER, raw CBOR for CCS).
    ///   - ead: Optional EAD items, encoded as a CBOR sequence.
    public static func buildContext(
        cRCbor: Data?,
        idCredCbor: Data,
        th: Data,
        credXCbor: Data,
        ead: [EdhocEAD]?
    ) -> Data {
        var result = Data()
        if let cR = cRCbor {
            result.append(cR)
        }
        result.append(idCredCbor)
        result.append(CBORSerialization.encode(.byteString(Array(th))))
        result.append(credXCbor)
        if let ead = ead, !ead.isEmpty {
            result.append(CBORUtils.encodeEADItems(ead))
        }
        return result
    }

    /// Build the COSE Enc_structure AAD for AEAD operations.
    ///
    /// Returns the CBOR encoding of: `["Encrypt0", h'', TH_x]`
    public static func buildEncStructureAAD(th: Data) -> Data {
        let structure: CBOR = .array([
            .utf8String("Encrypt0"),
            .byteString([]),
            .byteString(Array(th))
        ])
        return CBORSerialization.encode(structure)
    }

    /// Build the external AAD for a COSE Sig_structure.
    ///
    /// Returns the concatenation of CBOR(TH), CRED_x (pre-encoded), and optionally ?EAD.
    public static func buildSigExternalAAD(th: Data, credXCbor: Data, ead: [EdhocEAD]?) -> Data {
        var result = Data()
        result.append(CBORSerialization.encode(.byteString(Array(th))))
        result.append(credXCbor)
        if let ead = ead, !ead.isEmpty {
            result.append(CBORUtils.encodeEADItems(ead))
        }
        return result
    }

    /// Sign or return the MAC, depending on the authentication method and role.
    ///
    /// If the role uses a signature, this builds a COSE `Sig_structure`
    /// `["Signature1", ID_CRED_x, external_aad, MAC]` and signs it.
    /// If the role uses static DH, the MAC is returned directly.
    public static func signOrMAC(
        crypto: EdhocCryptoProvider,
        suite: EdhocCipherSuite,
        method: EdhocMethod,
        role: EdhocRole,
        credential: EdhocCredentialWithKeys,
        idCredCbor: Data,
        th: Data,
        credXCbor: Data,
        ead: [EdhocEAD]?,
        mac: Data
    ) throws -> Data {
        let usesSig: Bool
        switch role {
        case .responder: usesSig = method.responderUsesSignature
        case .initiator: usesSig = method.initiatorUsesSignature
        }

        if !usesSig { return mac }

        // Sig_structure = ["Signature1", ID_CRED_x, external_aad, MAC]
        let externalAad = buildSigExternalAAD(th: th, credXCbor: credXCbor, ead: ead)
        let sigStructure: CBOR = .array([
            .utf8String("Signature1"),
            .byteString(Array(idCredCbor)),
            .byteString(Array(externalAad)),
            .byteString(Array(mac))
        ])
        let sigStructureBytes = CBORSerialization.encode(sigStructure)

        guard let privateKey = credential.privateKey else {
            throw EdhocError.missingKeyMaterial("Private key required for signing")
        }
        return try crypto.sign(suite: suite, privateKey: privateKey, input: sigStructureBytes)
    }

    /// Verify a signature or MAC from the peer, depending on the authentication method.
    ///
    /// If the peer uses a signature, this builds a COSE `Sig_structure` and verifies
    /// the signature. If the peer uses static DH, the MAC is compared directly.
    public static func verifySignatureOrMAC(
        crypto: EdhocCryptoProvider,
        suite: EdhocCipherSuite,
        method: EdhocMethod,
        peerRole: EdhocRole,
        peerCredential: EdhocCredentialWithKeys,
        idCredCbor: Data,
        th: Data,
        credXCbor: Data,
        ead: [EdhocEAD]?,
        mac: Data,
        received: Data
    ) throws {
        let usesSig: Bool
        switch peerRole {
        case .responder: usesSig = method.responderUsesSignature
        case .initiator: usesSig = method.initiatorUsesSignature
        }

        if !usesSig {
            guard mac == received else {
                throw EdhocError.macVerificationFailed
            }
            return
        }

        let externalAad = buildSigExternalAAD(th: th, credXCbor: credXCbor, ead: ead)
        let sigStructure: CBOR = .array([
            .utf8String("Signature1"),
            .byteString(Array(idCredCbor)),
            .byteString(Array(externalAad)),
            .byteString(Array(mac))
        ])
        let sigStructureBytes = CBORSerialization.encode(sigStructure)

        guard let publicKey = peerCredential.publicKey else {
            throw EdhocError.missingKeyMaterial("Public key required for verification")
        }
        let valid = try crypto.verify(suite: suite, publicKey: publicKey, input: sigStructureBytes, signature: received)
        guard valid else {
            throw EdhocError.signatureVerificationFailed
        }
    }

    /// XOR two equal-length `Data` buffers.
    public static func xor(_ a: Data, _ b: Data) -> Data {
        precondition(a.count == b.count, "XOR operands must be the same length")
        var result = Data(count: a.count)
        for i in 0..<a.count {
            result[i] = a[i] ^ b[i]
        }
        return result
    }

    /// AEAD encrypt using the suite's algorithm.
    /// Returns ciphertext || tag.
    public static func aeadEncrypt(
        crypto: EdhocCryptoProvider,
        suite: EdhocCipherSuite,
        key: Data,
        iv: Data,
        aad: Data,
        plaintext: Data
    ) throws -> Data {
        try crypto.encrypt(suite: suite, key: key, nonce: iv, aad: aad, plaintext: plaintext)
    }

    /// AEAD decrypt using the suite's algorithm.
    /// Input is ciphertext || tag; returns plaintext.
    public static func aeadDecrypt(
        crypto: EdhocCryptoProvider,
        suite: EdhocCipherSuite,
        key: Data,
        iv: Data,
        aad: Data,
        ciphertext: Data
    ) throws -> Data {
        try crypto.decrypt(suite: suite, key: key, nonce: iv, aad: aad, ciphertext: ciphertext)
    }
}
