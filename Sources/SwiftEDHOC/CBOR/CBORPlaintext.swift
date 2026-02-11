import Foundation
@preconcurrency import SwiftCBOR

/// Parsed plaintext from EDHOC message 2 or 3
public struct ParsedPlaintext: Sendable {
    /// Raw CBOR for ID_CRED_x (not yet decoded to a credential)
    public let idCredRaw: CBOR
    /// The Signature_or_MAC_x bytes
    public let signatureOrMac: Data
    /// Optional EAD items
    public let ead: [EdhocEAD]
}

/// CBOR encoding/decoding for EDHOC plaintext payloads
public enum CBORPlaintext {

    /// Encode PLAINTEXT_2/3: ID_CRED_x || Signature_or_MAC_x || ?EAD
    ///
    /// - idCredCbor: already CBOR-encoded ID_CRED_x bytes
    /// - signatureOrMac: the raw signature or MAC bytes
    /// - ead: optional EAD tokens
    public static func encodePlaintext(idCredCbor: Data, signatureOrMac: Data, ead: [EdhocEAD]? = nil) -> Data {
        var result = idCredCbor
        result.append(CBORSerialization.encode(.byteString(Array(signatureOrMac))))
        if let ead = ead, !ead.isEmpty {
            result.append(CBORUtils.encodeEADItems(ead))
        }
        return result
    }

    /// Parse PLAINTEXT_2/3 into its components
    public static func parsePlaintext(_ data: Data) throws -> ParsedPlaintext {
        let items = try CBORSerialization.decodeSequence(data)
        guard items.count >= 2 else {
            throw EdhocError.invalidMessage("PLAINTEXT must contain at least 2 items")
        }

        let idCredRaw = items[0]
        guard let signatureOrMac = CBORSerialization.dataFromCBOR(items[1]) else {
            throw EdhocError.invalidMessage("Signature_or_MAC must be a byte string")
        }

        let ead: [EdhocEAD]
        if items.count > 2 {
            ead = CBORUtils.parseEADItems(Array(items[2...]))
        } else {
            ead = []
        }

        return ParsedPlaintext(idCredRaw: idCredRaw, signatureOrMac: signatureOrMac, ead: ead)
    }
}
