import Foundation

/// External Authorization Data item (RFC 9528 Section 3.8)
///
/// EAD items are (label, ?value) pairs carried in EDHOC messages.
/// The label is a non-negative integer; the value is optional byte data.
public struct EdhocEAD: Sendable, Equatable {
    public let label: Int
    public let value: Data

    public init(label: Int, value: Data = Data()) {
        self.label = label
        self.value = value
    }
}
