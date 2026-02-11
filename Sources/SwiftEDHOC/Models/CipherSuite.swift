import Foundation

/// EDHOC cipher suites (RFC 9528 Section 3.6)
public enum EdhocCipherSuite: Int, Sendable, CaseIterable {
    case suite0 = 0
    case suite1 = 1
    case suite2 = 2
    case suite3 = 3
    case suite4 = 4
    case suite5 = 5
    case suite6 = 6
    case suite24 = 24
    case suite25 = 25
}

/// Cryptographic algorithm identifiers for a cipher suite
public enum AEADAlgorithm: Sendable {
    case aesCCM_16_64_128   // tag=8, key=16, iv=13
    case aesCCM_16_128_128  // tag=16, key=16, iv=13
    case chaCha20Poly1305   // tag=16, key=32, iv=12
    case aesGCM128          // tag=16, key=16, iv=12
    case aesGCM256          // tag=16, key=32, iv=12
}

public enum DHCurve: Sendable {
    case x25519
    case p256
}

public enum SignatureCurve: Sendable {
    case ed25519
    case p256
}

public enum HashAlgorithm: Sendable {
    case sha256
    case sha384
}

/// Full set of parameters for a cipher suite
public struct CipherSuiteParameters: Sendable {
    public let id: Int
    public let aeadAlgorithm: AEADAlgorithm
    public let aeadKeyLength: Int
    public let aeadTagLength: Int
    public let aeadIvLength: Int
    public let hashAlgorithm: HashAlgorithm
    public let hashLength: Int
    public let macLength: Int
    public let eccKeyLength: Int
    public let eccSignLength: Int
    public let dhCurve: DHCurve
    public let signatureCurve: SignatureCurve
}

extension EdhocCipherSuite {
    /// Get the cryptographic parameters for this cipher suite
    public var parameters: CipherSuiteParameters {
        switch self {
        case .suite0:
            return CipherSuiteParameters(
                id: 0, aeadAlgorithm: .aesCCM_16_64_128, aeadKeyLength: 16, aeadTagLength: 8,
                aeadIvLength: 13, hashAlgorithm: .sha256, hashLength: 32, macLength: 8,
                eccKeyLength: 32, eccSignLength: 64, dhCurve: .x25519, signatureCurve: .ed25519)
        case .suite1:
            return CipherSuiteParameters(
                id: 1, aeadAlgorithm: .aesCCM_16_128_128, aeadKeyLength: 16, aeadTagLength: 16,
                aeadIvLength: 13, hashAlgorithm: .sha256, hashLength: 32, macLength: 16,
                eccKeyLength: 32, eccSignLength: 64, dhCurve: .x25519, signatureCurve: .ed25519)
        case .suite2:
            return CipherSuiteParameters(
                id: 2, aeadAlgorithm: .aesCCM_16_64_128, aeadKeyLength: 16, aeadTagLength: 8,
                aeadIvLength: 13, hashAlgorithm: .sha256, hashLength: 32, macLength: 8,
                eccKeyLength: 32, eccSignLength: 64, dhCurve: .p256, signatureCurve: .p256)
        case .suite3:
            return CipherSuiteParameters(
                id: 3, aeadAlgorithm: .aesCCM_16_128_128, aeadKeyLength: 16, aeadTagLength: 16,
                aeadIvLength: 13, hashAlgorithm: .sha256, hashLength: 32, macLength: 16,
                eccKeyLength: 32, eccSignLength: 64, dhCurve: .p256, signatureCurve: .p256)
        case .suite4:
            return CipherSuiteParameters(
                id: 4, aeadAlgorithm: .chaCha20Poly1305, aeadKeyLength: 32, aeadTagLength: 16,
                aeadIvLength: 12, hashAlgorithm: .sha256, hashLength: 32, macLength: 16,
                eccKeyLength: 32, eccSignLength: 64, dhCurve: .x25519, signatureCurve: .ed25519)
        case .suite5:
            return CipherSuiteParameters(
                id: 5, aeadAlgorithm: .chaCha20Poly1305, aeadKeyLength: 32, aeadTagLength: 16,
                aeadIvLength: 12, hashAlgorithm: .sha256, hashLength: 32, macLength: 16,
                eccKeyLength: 32, eccSignLength: 64, dhCurve: .p256, signatureCurve: .p256)
        case .suite6:
            return CipherSuiteParameters(
                id: 6, aeadAlgorithm: .aesGCM128, aeadKeyLength: 16, aeadTagLength: 16,
                aeadIvLength: 12, hashAlgorithm: .sha256, hashLength: 32, macLength: 16,
                eccKeyLength: 32, eccSignLength: 64, dhCurve: .x25519, signatureCurve: .p256)
        case .suite24:
            return CipherSuiteParameters(
                id: 24, aeadAlgorithm: .aesGCM256, aeadKeyLength: 32, aeadTagLength: 16,
                aeadIvLength: 12, hashAlgorithm: .sha384, hashLength: 48, macLength: 16,
                eccKeyLength: 56, eccSignLength: 114, dhCurve: .p256, signatureCurve: .p256)
        case .suite25:
            return CipherSuiteParameters(
                id: 25, aeadAlgorithm: .chaCha20Poly1305, aeadKeyLength: 32, aeadTagLength: 16,
                aeadIvLength: 12, hashAlgorithm: .sha256, hashLength: 32, macLength: 16,
                eccKeyLength: 32, eccSignLength: 64, dhCurve: .x25519, signatureCurve: .ed25519)
        }
    }
}
