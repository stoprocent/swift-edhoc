import Foundation
import SwiftCBOR

/// CBOR sequence encoding/decoding utilities for EDHOC
///
/// EDHOC uses CBOR sequences (RFC 8742) -- concatenated CBOR items without
/// an enclosing array. This differs from standard CBOR encoding.
public enum CBORSerialization {

    /// Encode a CBOR sequence: concatenation of individually CBOR-encoded items
    public static func encodeSequence(_ items: [CBOR]) -> Data {
        var result = Data()
        for item in items {
            result.append(contentsOf: item.encode())
        }
        return result
    }

    /// Decode all items from a CBOR sequence buffer
    public static func decodeSequence(_ data: Data) throws -> [CBOR] {
        var results: [CBOR] = []
        var offset = 0
        let bytes = Array(data)
        while offset < bytes.count {
            let decoded = try CBOR.decode(Array(bytes[offset...]))
            guard let value = decoded else {
                throw EdhocError.cborError("Failed to decode CBOR item at offset \(offset)")
            }
            results.append(value)
            let encoded = value.encode()
            offset += encoded.count
        }
        return results
    }

    /// Encode a single value to CBOR bytes
    public static func encode(_ item: CBOR) -> Data {
        Data(item.encode())
    }

    /// Decode a single CBOR item from data
    public static func decode(_ data: Data) throws -> CBOR {
        guard let value = try CBOR.decode(Array(data)) else {
            throw EdhocError.cborError("Failed to decode CBOR")
        }
        return value
    }

    /// Encode SUITES_I: single int if one suite, array if multiple (selected last)
    public static func encodeSuites(_ suites: [EdhocCipherSuite], selected: EdhocCipherSuite) -> CBOR {
        if suites.count == 1 {
            return .unsignedInt(UInt64(suites[0].rawValue))
        }
        let rest = suites.filter { $0 != selected }
        var arr = rest.map { CBOR.unsignedInt(UInt64($0.rawValue)) }
        arr.append(.unsignedInt(UInt64(selected.rawValue)))
        return .array(arr)
    }

    /// Convert a Swift value to a CBOR item
    public static func toCBOR(_ value: Any) -> CBOR {
        switch value {
        case let n as Int:
            if n >= 0 {
                return .unsignedInt(UInt64(n))
            } else {
                return .negativeInt(UInt64(-1 - n))
            }
        case let n as UInt64:
            return .unsignedInt(n)
        case let d as Data:
            return .byteString(Array(d))
        case let s as String:
            return .utf8String(s)
        case let b as Bool:
            return .boolean(b)
        case let arr as [Any]:
            return .array(arr.map { toCBOR($0) })
        default:
            return .null
        }
    }

    /// Extract Data from a CBOR byte string
    public static func dataFromCBOR(_ cbor: CBOR) -> Data? {
        if case .byteString(let bytes) = cbor {
            return Data(bytes)
        }
        return nil
    }

    /// Extract Int from a CBOR integer
    public static func intFromCBOR(_ cbor: CBOR) -> Int? {
        switch cbor {
        case .unsignedInt(let n):
            return Int(n)
        case .negativeInt(let n):
            return -1 - Int(n)
        default:
            return nil
        }
    }
}
