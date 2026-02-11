import Foundation

/// EDHOC authentication methods (RFC 9528 Section 3.2)
///
/// The method specifies the authentication type for initiator and responder:
/// - Method 0: Initiator Signature, Responder Signature
/// - Method 1: Initiator Signature, Responder Static DH
/// - Method 2: Initiator Static DH, Responder Signature
/// - Method 3: Initiator Static DH, Responder Static DH
public enum EdhocMethod: Int, Sendable, CaseIterable {
    case method0 = 0
    case method1 = 1
    case method2 = 2
    case method3 = 3

    /// Whether the initiator authenticates with a signature (vs static DH)
    public var initiatorUsesSignature: Bool {
        self == .method0 || self == .method1
    }

    /// Whether the responder authenticates with a signature (vs static DH)
    public var responderUsesSignature: Bool {
        self == .method0 || self == .method2
    }
}
