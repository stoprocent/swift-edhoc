import Foundation
import SwiftCBOR

/// CBOR utility functions for connection IDs and EAD
public enum CBORUtils {
    private static let cidMin = -24
    private static let cidMax = 23

    /// Canonicalize connection ID representation for EDHOC fields.
    /// A one-byte bstr containing a one-byte CBOR int is normalized to integer form.
    public static func canonicalizeConnectionID(_ cid: EdhocConnectionID) throws -> EdhocConnectionID {
        switch cid {
        case .integer(let n):
            if n >= cidMin && n <= cidMax {
                return .integer(n)
            }
            return .byteString(cborBytesForInteger(n))
        case .byteString(let data):
            if data.count == 1, let n = decodeSingleByteCBORInt(data[0]) {
                return .integer(n)
            }
            return .byteString(data)
        }
    }

    /// Decode a CBOR-decoded value to an EdhocConnectionID
    public static func connectionIDFromCBOR(_ cbor: CBOR) throws -> EdhocConnectionID {
        switch cbor {
        case .unsignedInt(let n):
            return try canonicalizeConnectionID(.integer(Int(n)))
        case .negativeInt(let n):
            return try canonicalizeConnectionID(.integer(-1 - Int(n)))
        case .byteString(let bytes):
            return try canonicalizeConnectionID(.byteString(Data(bytes)))
        default:
            throw EdhocError.cborError("Invalid connection ID CBOR type")
        }
    }

    /// Encode a connection ID as a CBOR item
    public static func connectionIDToCBOR(_ cid: EdhocConnectionID) throws -> CBOR {
        switch try canonicalizeConnectionID(cid) {
        case .integer(let n):
            if n >= 0 {
                return .unsignedInt(UInt64(n))
            } else {
                return .negativeInt(UInt64(-1 - n))
            }
        case .byteString(let data):
            return .byteString(Array(data))
        }
    }

    private static func decodeSingleByteCBORInt(_ b: UInt8) -> Int? {
        if b <= 0x17 { return Int(b) }
        if b >= 0x20 && b <= 0x37 { return -1 - Int(b & 0x1f) }
        return nil
    }

    private static func cborBytesForInteger(_ n: Int) -> Data {
        if n >= 0 {
            return CBORSerialization.encode(.unsignedInt(UInt64(n)))
        }
        return CBORSerialization.encode(.negativeInt(UInt64(-1 - n)))
    }

    /// Encode EAD items as a CBOR sequence of (label, ?value) pairs
    public static func encodeEADItems(_ tokens: [EdhocEAD]) -> Data {
        var parts: [CBOR] = []
        for token in tokens {
            parts.append(.unsignedInt(UInt64(token.label)))
            if !token.value.isEmpty {
                parts.append(.byteString(Array(token.value)))
            }
        }
        return CBORSerialization.encodeSequence(parts)
    }

    /// Parse EAD items from decoded CBOR values
    public static func parseEADItems(_ items: [CBOR]) -> [EdhocEAD] {
        var result: [EdhocEAD] = []
        var i = 0
        while i < items.count {
            guard let label = CBORSerialization.intFromCBOR(items[i]) else {
                i += 1
                continue
            }
            i += 1
            var value = Data()
            if i < items.count, case .byteString(let bytes) = items[i] {
                value = Data(bytes)
                i += 1
            }
            result.append(EdhocEAD(label: label, value: value))
        }
        return result
    }
}
