import Foundation

/// CCS (CWT Claims Set) / KID-based credential provider for EDHOC.
///
/// Manages own credentials and peer credentials using CBOR-encoded CCS structures
/// with KID (Key ID) references, as described in RFC 9528 and RFC 9529.
///
/// Usage:
/// ```swift
/// var provider = CCSCredentialProvider()
/// provider.addOwnCredential(
///     kid: .integer(-12),
///     ccsBytes: myCCSData,
///     publicKey: myPublicKey,
///     privateKey: myPrivateKey
/// )
/// provider.addPeerCredential(
///     kid: .integer(-19),
///     ccsBytes: peerCCSData,
///     publicKey: peerPublicKey
/// )
/// ```
public struct CCSCredentialProvider: EdhocCredentialProvider, Sendable {

    // MARK: - Internal storage

    private struct OwnCredential: Sendable {
        let kid: KIDValue
        let ccsBytes: Data
        let publicKey: Data
        let privateKey: Data
    }

    private struct PeerCredential: Sendable {
        let kid: KIDValue
        let ccsBytes: Data
        let publicKey: Data
    }

    private var ownCredential: OwnCredential?
    private var peerCredentials: [PeerCredential]

    // MARK: - Initialization

    /// Create an empty CCS credential provider.
    ///
    /// Use ``addOwnCredential(kid:ccsBytes:publicKey:privateKey:)`` and
    /// ``addPeerCredential(kid:ccsBytes:publicKey:)`` to populate it.
    public init() {
        self.ownCredential = nil
        self.peerCredentials = []
    }

    // MARK: - Configuration

    /// Add the local party's CCS credential.
    ///
    /// - Parameters:
    ///   - kid: KID value identifying this credential.
    ///   - ccsBytes: CBOR-encoded CWT Claims Set bytes.
    ///   - publicKey: Raw public key bytes (e.g. 32-byte x-coordinate for P-256).
    ///   - privateKey: Raw private key bytes.
    public mutating func addOwnCredential(
        kid: KIDValue,
        ccsBytes: Data,
        publicKey: Data,
        privateKey: Data
    ) {
        self.ownCredential = OwnCredential(
            kid: kid,
            ccsBytes: ccsBytes,
            publicKey: publicKey,
            privateKey: privateKey
        )
    }

    /// Add a peer's CCS credential for verification during handshake.
    ///
    /// Multiple peer credentials can be added; the provider matches by KID value.
    ///
    /// - Parameters:
    ///   - kid: KID value identifying the peer credential.
    ///   - ccsBytes: CBOR-encoded CWT Claims Set bytes.
    ///   - publicKey: Raw public key bytes.
    public mutating func addPeerCredential(
        kid: KIDValue,
        ccsBytes: Data,
        publicKey: Data
    ) {
        peerCredentials.append(PeerCredential(
            kid: kid,
            ccsBytes: ccsBytes,
            publicKey: publicKey
        ))
    }

    // MARK: - EdhocCredentialProvider

    /// Fetch own credentials for the current session.
    ///
    /// Returns a KID credential wrapping the CCS bytes with the associated key material.
    public func fetch(info: EdhocSessionInfo) throws -> EdhocCredentialWithKeys {
        guard let own = ownCredential else {
            throw EdhocError.missingKeyMaterial("No own CCS credential configured")
        }

        let kidCred = KIDCredential(
            kid: own.kid,
            credentials: own.ccsBytes,
            isCBOR: true
        )
        return EdhocCredentialWithKeys(
            credential: .kid(kidCred),
            privateKey: own.privateKey,
            publicKey: own.publicKey
        )
    }

    /// Verify a peer credential by matching its KID value against known peer credentials.
    ///
    /// Returns a fully populated credential with the peer's public key if a match is found.
    public func verify(
        info: EdhocSessionInfo,
        credential: EdhocCredential
    ) throws -> EdhocCredentialWithKeys {
        guard case .kid(let kidCred) = credential else {
            throw EdhocError.credentialVerificationFailed(
                "CCSCredentialProvider only supports KID credentials"
            )
        }

        for peer in peerCredentials {
            if peer.kid == kidCred.kid {
                let fullKidCred = KIDCredential(
                    kid: peer.kid,
                    credentials: peer.ccsBytes,
                    isCBOR: true
                )
                return EdhocCredentialWithKeys(
                    credential: .kid(fullKidCred),
                    publicKey: peer.publicKey
                )
            }
        }

        throw EdhocError.credentialVerificationFailed("Unknown peer credential")
    }
}
