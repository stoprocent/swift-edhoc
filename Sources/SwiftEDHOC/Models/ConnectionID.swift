import Foundation

/// EDHOC connection identifier (RFC 9528 Section 3.3.2)
///
/// A connection ID is either an integer or a byte string.
/// Integer connection IDs in -24..23 are encoded as one-byte CBOR integers.
/// Outside that interval, full CBOR integer bytes are used.
public enum EdhocConnectionID: Sendable, Equatable {
    case integer(Int)
    case byteString(Data)

    /// Convert to raw byte representation for OSCORE IDs (RFC 9528 Section 3.3.2)
    ///
    /// The OSCORE identifier is a 1-byte byte string containing the CBOR encoding
    /// byte of the integer connection ID.
    public func toBytes() -> Data {
        switch self {
        case .integer(let n):
            // OSCORE ID = 1-byte bstr with the CBOR encoding byte
            if n >= -24 && n <= 23 {
                if n >= 0 {
                    return Data([UInt8(n)])  // major type 0
                } else {
                    return Data([UInt8(0x20 | (-(n + 1)))])  // major type 1
                }
            }
            if n >= 0 {
                return CBORSerialization.encode(.unsignedInt(UInt64(n)))
            }
            return CBORSerialization.encode(.negativeInt(UInt64(-1 - n)))
        case .byteString(let data):
            return data
        }
    }
}
