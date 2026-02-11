import Foundation

/// OSCORE security context derived from a completed EDHOC handshake (RFC 9528 Section 7.2.1)
public struct EdhocOscoreContext: Sendable, Equatable {
    public let masterSecret: Data
    public let masterSalt: Data
    public let senderId: Data
    public let recipientId: Data

    public init(masterSecret: Data, masterSalt: Data, senderId: Data, recipientId: Data) {
        self.masterSecret = masterSecret
        self.masterSalt = masterSalt
        self.senderId = senderId
        self.recipientId = recipientId
    }
}
