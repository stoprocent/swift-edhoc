import Foundation

/// EDHOC credential formats (CBOR map labels from RFC 9528)
public enum EdhocCredentialsFormat: Int, Sendable {
    case kid = 4
    case x5chain = 33
    case x5t = 34
}

/// Hash algorithms used for x5t credential references
public enum CertificateHashAlgorithm: Int, Sendable {
    case sha256 = -16
    case sha256_64 = -15  // SHA-256 truncated to 64 bits (8 bytes)
}

/// KID-based credential reference
public struct KIDCredential: Sendable {
    public let kid: KIDValue
    public let credentials: Data?
    public let isCBOR: Bool

    public init(kid: KIDValue, credentials: Data? = nil, isCBOR: Bool = false) {
        self.kid = kid
        self.credentials = credentials
        self.isCBOR = isCBOR
    }
}

/// KID value can be an integer or byte string
public enum KIDValue: Sendable, Equatable {
    case integer(Int)
    case byteString(Data)
}

/// X.509 certificate chain credential
public struct X5ChainCredential: Sendable {
    public let certificates: [Data]

    public init(certificates: [Data]) {
        self.certificates = certificates
    }
}

/// X.509 certificate hash (thumbprint) credential
public struct X5TCredential: Sendable {
    public var certificate: Data?
    public let hash: Data
    public let hashAlgorithm: CertificateHashAlgorithm

    public init(certificate: Data? = nil, hash: Data, hashAlgorithm: CertificateHashAlgorithm) {
        self.certificate = certificate
        self.hash = hash
        self.hashAlgorithm = hashAlgorithm
    }
}

/// EDHOC credential: an enum with associated values for each format
public enum EdhocCredential: Sendable {
    case kid(KIDCredential)
    case x5chain(X5ChainCredential)
    case x5t(X5TCredential)

    public var format: EdhocCredentialsFormat {
        switch self {
        case .kid: return .kid
        case .x5chain: return .x5chain
        case .x5t: return .x5t
        }
    }
}

/// Full credential with key material, used during protocol execution
public struct EdhocCredentialWithKeys: Sendable {
    public var credential: EdhocCredential
    public var privateKey: Data?
    public var publicKey: Data?

    public init(credential: EdhocCredential, privateKey: Data? = nil, publicKey: Data? = nil) {
        self.credential = credential
        self.privateKey = privateKey
        self.publicKey = publicKey
    }
}
