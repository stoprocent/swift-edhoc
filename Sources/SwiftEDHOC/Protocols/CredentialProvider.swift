import Foundation

/// The role of an EDHOC participant
public enum EdhocRole: Sendable {
    case initiator
    case responder
}

/// Immutable snapshot of session state passed to credential providers.
/// This prevents providers from mutating session state.
public struct EdhocSessionInfo: Sendable {
    public let connectionID: EdhocConnectionID
    public let role: EdhocRole
    public let selectedMethod: EdhocMethod
    public let selectedSuite: EdhocCipherSuite

    public init(
        connectionID: EdhocConnectionID,
        role: EdhocRole,
        selectedMethod: EdhocMethod,
        selectedSuite: EdhocCipherSuite
    ) {
        self.connectionID = connectionID
        self.role = role
        self.selectedMethod = selectedMethod
        self.selectedSuite = selectedSuite
    }
}

/// Protocol for EDHOC credential management
///
/// Implementations provide own credentials (for authentication) and
/// verify peer credentials. The default implementation is `X509CredentialProvider`.
public protocol EdhocCredentialProvider: Sendable {
    /// Fetch own credentials for the current session
    func fetch(info: EdhocSessionInfo) throws -> EdhocCredentialWithKeys

    /// Verify peer credentials and extract the public key.
    /// The input is a partial credential decoded from ID_CRED_x.
    /// Returns a fully populated credential with the public key.
    func verify(info: EdhocSessionInfo, credential: EdhocCredential) throws -> EdhocCredentialWithKeys
}
