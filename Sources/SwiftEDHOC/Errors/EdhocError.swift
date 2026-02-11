import Foundation

/// Errors that can occur during EDHOC protocol execution
public enum EdhocError: Error, Sendable {
    /// Invalid protocol state for the requested operation
    case invalidState(expected: String, method: String)

    /// Unsupported EDHOC method
    case unsupportedMethod(Int)

    /// Unsupported cipher suite; carries the peer's offered suites
    case unsupportedCipherSuite(selected: Int, peerSuites: [Int])

    /// Invalid message format (too few items, wrong types, etc.)
    case invalidMessage(String)

    /// Credential verification failed
    case credentialVerificationFailed(String)

    /// MAC verification failed
    case macVerificationFailed

    /// Signature verification failed
    case signatureVerificationFailed

    /// Cryptographic operation failed
    case cryptoError(String)

    /// CBOR encoding/decoding error
    case cborError(String)

    /// Handshake not completed (export attempted too early)
    case handshakeNotCompleted

    /// Missing required key material
    case missingKeyMaterial(String)

    /// Certificate chain verification failed
    case certificateVerificationFailed(String)
}

extension EdhocError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .invalidState(let expected, let method):
            return "Invalid state for \(method): expected \(expected)"
        case .unsupportedMethod(let m):
            return "Unsupported EDHOC method: \(m)"
        case .unsupportedCipherSuite(let selected, _):
            return "Unsupported cipher suite: \(selected)"
        case .invalidMessage(let msg):
            return "Invalid EDHOC message: \(msg)"
        case .credentialVerificationFailed(let msg):
            return "Credential verification failed: \(msg)"
        case .macVerificationFailed:
            return "MAC verification failed"
        case .signatureVerificationFailed:
            return "Signature verification failed"
        case .cryptoError(let msg):
            return "Crypto error: \(msg)"
        case .cborError(let msg):
            return "CBOR error: \(msg)"
        case .handshakeNotCompleted:
            return "Handshake not completed"
        case .missingKeyMaterial(let msg):
            return "Missing key material: \(msg)"
        case .certificateVerificationFailed(let msg):
            return "Certificate verification failed: \(msg)"
        }
    }
}
