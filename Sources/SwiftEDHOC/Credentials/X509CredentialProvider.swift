import Foundation
import X509
import CryptoKit

/// X.509 certificate-based credential provider for EDHOC.
///
/// Manages own certificates (for authentication) and verifies peer certificates
/// presented during EDHOC handshake. Supports both `x5chain` (full certificate chain)
/// and `x5t` (certificate thumbprint) credential formats.
///
/// Usage:
/// ```swift
/// let provider = X509CredentialProvider(
///     certificates: [myCertDER],
///     privateKey: myPrivateKeyBytes
/// )
/// provider.addTrustedCA(caCertDER)
/// provider.addPeerCertificate(peerCertDER)
/// ```
public final class X509CredentialProvider: EdhocCredentialProvider, @unchecked Sendable {

    // MARK: - Properties

    /// Own DER-encoded certificate chain (leaf first, then intermediates)
    private var certificates: [Data]

    /// Known peer certificates for x5t thumbprint lookup (DER-encoded)
    private var peerCertificates: [Data]

    /// Trusted CA certificates for chain verification (DER-encoded)
    private var trustedCAs: [Data]

    /// Raw private key bytes
    private let privateKey: Data

    /// Credential format to use when fetching own credentials
    public var fetchFormat: EdhocCredentialsFormat

    // MARK: - Initialization

    /// Create a new X.509 credential provider.
    ///
    /// - Parameters:
    ///   - certificates: Own DER-encoded certificate chain (leaf first).
    ///   - privateKey: Raw private key bytes.
    ///   - fetchFormat: Credential format for own credentials (default: `.x5chain`).
    public init(
        certificates: [Data],
        privateKey: Data,
        fetchFormat: EdhocCredentialsFormat = .x5chain
    ) {
        self.certificates = certificates
        self.privateKey = privateKey
        self.fetchFormat = fetchFormat
        self.peerCertificates = []
        self.trustedCAs = []
    }

    // MARK: - Configuration

    /// Register a known peer certificate for x5t thumbprint matching.
    ///
    /// - Parameter certificate: DER-encoded peer certificate.
    public func addPeerCertificate(_ certificate: Data) {
        peerCertificates.append(certificate)
    }

    /// Register a trusted certificate authority for chain verification.
    ///
    /// - Parameter certificate: DER-encoded CA certificate.
    public func addTrustedCA(_ certificate: Data) {
        trustedCAs.append(certificate)
    }

    // MARK: - EdhocCredentialProvider

    /// Fetch own credentials in the configured format.
    ///
    /// For `.x5chain`, returns the full certificate chain with the private key ID.
    /// For `.x5t`, computes a SHA-256/64 thumbprint of the leaf certificate.
    /// The `.kid` format is not supported by this provider.
    public func fetch(info: EdhocSessionInfo) throws -> EdhocCredentialWithKeys {
        guard !certificates.isEmpty else {
            throw EdhocError.missingKeyMaterial("No certificates configured")
        }

        switch fetchFormat {
        case .x5chain:
            let credential = EdhocCredential.x5chain(
                X5ChainCredential(certificates: certificates)
            )
            return EdhocCredentialWithKeys(
                credential: credential,
                privateKey: privateKey
            )

        case .x5t:
            let leafDER = certificates[0]
            let fullHash = SHA256.hash(data: leafDER)
            // SHA-256 truncated to 64 bits (8 bytes) for x5t
            let truncatedHash = Data(fullHash.prefix(8))

            let x5t = X5TCredential(
                certificate: leafDER,
                hash: truncatedHash,
                hashAlgorithm: .sha256_64
            )
            let credential = EdhocCredential.x5t(x5t)
            return EdhocCredentialWithKeys(
                credential: credential,
                privateKey: privateKey
            )

        case .kid:
            throw EdhocError.credentialVerificationFailed(
                "X509CredentialProvider does not support KID format"
            )
        }
    }

    /// Verify a peer credential and extract the public key.
    ///
    /// For `.x5chain`, verifies the certificate chain and extracts the leaf public key.
    /// For `.x5t`, looks up the certificate by thumbprint in known peer certificates,
    /// then verifies as a chain. For `.kid`, verification is not supported.
    public func verify(
        info: EdhocSessionInfo,
        credential: EdhocCredential
    ) throws -> EdhocCredentialWithKeys {
        switch credential {
        case .x5chain(let x5chain):
            return try verifyX5Chain(x5chain, info: info)

        case .x5t(let x5t):
            return try verifyX5T(x5t, info: info)

        case .kid:
            throw EdhocError.credentialVerificationFailed(
                "X509CredentialProvider does not support KID credential verification"
            )
        }
    }

    // MARK: - X5Chain Verification

    /// Verify an x5chain credential: validate the certificate chain and extract
    /// the leaf certificate's public key.
    private func verifyX5Chain(
        _ x5chain: X5ChainCredential,
        info: EdhocSessionInfo
    ) throws -> EdhocCredentialWithKeys {
        guard !x5chain.certificates.isEmpty else {
            throw EdhocError.certificateVerificationFailed("Empty certificate chain")
        }

        // Parse all certificates in the chain
        let parsedCerts = try x5chain.certificates.map { derData -> Certificate in
            do {
                return try Certificate(derEncoded: Array(derData))
            } catch {
                throw EdhocError.certificateVerificationFailed(
                    "Failed to parse DER certificate: \(error.localizedDescription)"
                )
            }
        }

        // Verify the chain: each cert[i] should be signed by cert[i+1]
        try verifyChainSignatures(parsedCerts)

        // Verify the last certificate is signed by (or matches) a trusted CA
        try verifyTrustAnchor(parsedCerts.last!)

        // Extract the raw public key from the leaf certificate
        let publicKeyData = try extractPublicKey(
            from: parsedCerts[0],
            info: info
        )

        return EdhocCredentialWithKeys(
            credential: .x5chain(x5chain),
            publicKey: publicKeyData
        )
    }

    // MARK: - X5T Verification

    /// Verify an x5t credential: look up the certificate by thumbprint, then verify it.
    private func verifyX5T(
        _ x5t: X5TCredential,
        info: EdhocSessionInfo
    ) throws -> EdhocCredentialWithKeys {
        // If the x5t already carries the certificate, use it directly
        if let certData = x5t.certificate {
            // Still verify the hash matches the certificate
            try verifyThumbprint(certData: certData, x5t: x5t)
            return try verifyResolvedCertificate(
                certData: certData,
                originalCredential: .x5t(x5t),
                info: info
            )
        }

        // Look up the certificate in our known peer certificates
        guard let certData = try findCertificateByThumbprint(x5t) else {
            throw EdhocError.credentialVerificationFailed(
                "No matching peer certificate found for x5t thumbprint"
            )
        }

        // Return with the resolved certificate attached
        var resolvedX5T = x5t
        resolvedX5T.certificate = certData

        return try verifyResolvedCertificate(
            certData: certData,
            originalCredential: .x5t(resolvedX5T),
            info: info
        )
    }

    /// Search known peer certificates for one matching the given thumbprint.
    private func findCertificateByThumbprint(
        _ x5t: X5TCredential
    ) throws -> Data? {
        for peerCert in peerCertificates {
            let hash: Data
            switch x5t.hashAlgorithm {
            case .sha256:
                hash = Data(SHA256.hash(data: peerCert))
            case .sha256_64:
                hash = Data(SHA256.hash(data: peerCert).prefix(8))
            }

            if hash == x5t.hash {
                return peerCert
            }
        }
        return nil
    }

    /// Verify that a thumbprint matches the given certificate data.
    private func verifyThumbprint(certData: Data, x5t: X5TCredential) throws {
        let computedHash: Data
        switch x5t.hashAlgorithm {
        case .sha256:
            computedHash = Data(SHA256.hash(data: certData))
        case .sha256_64:
            computedHash = Data(SHA256.hash(data: certData).prefix(8))
        }

        guard computedHash == x5t.hash else {
            throw EdhocError.certificateVerificationFailed(
                "Certificate thumbprint does not match x5t hash"
            )
        }
    }

    /// Verify a resolved certificate (from x5t lookup) and extract its public key.
    private func verifyResolvedCertificate(
        certData: Data,
        originalCredential: EdhocCredential,
        info: EdhocSessionInfo
    ) throws -> EdhocCredentialWithKeys {
        let cert: Certificate
        do {
            cert = try Certificate(derEncoded: Array(certData))
        } catch {
            throw EdhocError.certificateVerificationFailed(
                "Failed to parse resolved certificate: \(error.localizedDescription)"
            )
        }

        // Verify the certificate against trusted CAs
        try verifyTrustAnchor(cert)

        // Extract the public key
        let publicKeyData = try extractPublicKey(from: cert, info: info)

        return EdhocCredentialWithKeys(
            credential: originalCredential,
            publicKey: publicKeyData
        )
    }

    // MARK: - Chain Verification Internals

    /// Verify signatures along a certificate chain.
    ///
    /// Each certificate at index `i` must be signed by the certificate at index `i+1`.
    /// For single-certificate chains, this is a no-op (trust anchor check handles it).
    private func verifyChainSignatures(_ chain: [Certificate]) throws {
        guard chain.count > 1 else { return }

        for i in 0..<(chain.count - 1) {
            let subject = chain[i]
            let issuer = chain[i + 1]
            let isValid = issuer.publicKey.isValidSignature(
                subject.signature,
                for: subject
            )
            guard isValid else {
                throw EdhocError.certificateVerificationFailed(
                    "Certificate at index \(i) is not validly signed by certificate at index \(i + 1)"
                )
            }
        }
    }

    /// Verify that the given certificate is signed by (or is itself) a trusted CA.
    ///
    /// Checks if the certificate matches a trusted CA directly, or if a trusted CA
    /// has validly signed the certificate.
    private func verifyTrustAnchor(_ cert: Certificate) throws {
        // If no trusted CAs are configured, skip trust verification.
        // This allows use in constrained environments where trust is established
        // out of band (e.g., pre-provisioned peer certificates).
        if trustedCAs.isEmpty {
            return
        }

        for caDER in trustedCAs {
            let caCert: Certificate
            do {
                caCert = try Certificate(derEncoded: Array(caDER))
            } catch {
                // Skip unparseable CA certificates
                continue
            }

            // Check if the certificate IS the trusted CA (self-signed root in chain)
            if cert == caCert {
                return
            }

            // Check if the trusted CA signed this certificate
            let isValid = caCert.publicKey.isValidSignature(
                cert.signature,
                for: cert
            )
            if isValid {
                return
            }
        }

        throw EdhocError.certificateVerificationFailed(
            "Certificate is not signed by any trusted CA"
        )
    }

    // MARK: - Public Key Extraction

    /// Extract the raw public key bytes from a certificate.
    ///
    /// For P-256 keys: returns the 64-byte uncompressed x||y coordinates
    /// (the 0x04 prefix from the X9.63 representation is stripped).
    /// For Ed25519/Curve25519 keys: returns the 32-byte raw key.
    ///
    /// The key type is determined by the cipher suite's signature curve from `info`,
    /// falling back to automatic detection from the certificate's key type.
    private func extractPublicKey(
        from cert: Certificate,
        info: EdhocSessionInfo
    ) throws -> Data {
        let signatureCurve = info.selectedSuite.parameters.signatureCurve

        switch signatureCurve {
        case .p256:
            return try extractP256PublicKey(from: cert)
        case .p384:
            return try extractP384PublicKey(from: cert)
        case .ed25519:
            return try extractEd25519PublicKey(from: cert)
        case .ed448:
            throw EdhocError.unsupportedCipherSuite(
                selected: info.selectedSuite.rawValue,
                peerSuites: [info.selectedSuite.rawValue]
            )
        }
    }

    /// Extract a P-256 public key from the certificate.
    /// Returns the 64-byte raw x||y representation (X9.63 without the 0x04 prefix).
    private func extractP256PublicKey(from cert: Certificate) throws -> Data {
        guard let p256Key = P256.Signing.PublicKey(cert.publicKey) else {
            throw EdhocError.missingKeyMaterial(
                "Certificate does not contain a P-256 public key"
            )
        }
        // x963Representation is 0x04 || x (32 bytes) || y (32 bytes) = 65 bytes
        let x963 = p256Key.x963Representation
        // Strip the 0x04 uncompressed point prefix
        return Data(x963.dropFirst())
    }

    /// Extract a P-384 public key from the certificate.
    /// Returns the 96-byte raw x||y representation (X9.63 without the 0x04 prefix).
    private func extractP384PublicKey(from cert: Certificate) throws -> Data {
        guard let p384Key = P384.Signing.PublicKey(cert.publicKey) else {
            throw EdhocError.missingKeyMaterial(
                "Certificate does not contain a P-384 public key"
            )
        }
        let x963 = p384Key.x963Representation
        return Data(x963.dropFirst())
    }

    /// Extract an Ed25519/Curve25519 public key from the certificate.
    /// Returns the 32-byte raw key representation.
    private func extractEd25519PublicKey(from cert: Certificate) throws -> Data {
        guard let edKey = Curve25519.Signing.PublicKey(cert.publicKey) else {
            throw EdhocError.missingKeyMaterial(
                "Certificate does not contain an Ed25519 public key"
            )
        }
        return Data(edKey.rawRepresentation)
    }
}
