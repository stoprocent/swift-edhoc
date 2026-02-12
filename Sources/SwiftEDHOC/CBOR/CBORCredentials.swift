import Foundation
import SwiftCBOR

/// CBOR encoding/decoding for EDHOC credentials (ID_CRED_x, CRED_x)
public enum CBORCredentials {

    /// Encode ID_CRED_x: the credential identifier in CBOR
    ///
    /// - KID: bare CBOR value (integer or byte string)
    /// - x5chain: CBOR map {33: bstr} or {33: [bstr, ...]}
    /// - x5t: CBOR map {34: [alg, hash]}
    public static func encodeIDCred(_ credential: EdhocCredential) -> Data {
        switch credential {
        case .kid(let kidCred):
            switch kidCred.kid {
            case .integer(let n):
                return CBORSerialization.encode(CBORSerialization.toCBOR(n))
            case .byteString(let data):
                return CBORSerialization.encode(.byteString(Array(data)))
            }

        case .x5chain(let x5chain):
            let certValue: CBOR
            if x5chain.certificates.count == 1 {
                certValue = .byteString(Array(x5chain.certificates[0]))
            } else {
                certValue = .array(x5chain.certificates.map { .byteString(Array($0)) })
            }
            let map: CBOR = .map([
                .unsignedInt(UInt64(EdhocCredentialsFormat.x5chain.rawValue)): certValue
            ])
            return CBORSerialization.encode(map)

        case .x5t(let x5t):
            let algCBOR: CBOR
            let algValue = x5t.hashAlgorithm.rawValue
            if algValue >= 0 {
                algCBOR = .unsignedInt(UInt64(algValue))
            } else {
                algCBOR = .negativeInt(UInt64(-1 - algValue))
            }
            let arr: CBOR = .array([algCBOR, .byteString(Array(x5t.hash))])
            let map: CBOR = .map([
                .unsignedInt(UInt64(EdhocCredentialsFormat.x5t.rawValue)): arr
            ])
            return CBORSerialization.encode(map)
        }
    }

    /// Encode ID_CRED_x using EdhocCredentialWithKeys
    public static func encodeIDCred(_ credWithKeys: EdhocCredentialWithKeys) -> Data {
        encodeIDCred(credWithKeys.credential)
    }

    /// Encode ID_CRED_x as a CBOR map (full form for MAC context / Sig_structure).
    /// For kid: {4: bstr(cbor(kid))}; for x5chain/x5t: same as encodeIDCred.
    public static func encodeIDCredMap(_ credential: EdhocCredential) -> Data {
        switch credential {
        case .kid(let kidCred):
            let kidCbor: CBOR
            switch kidCred.kid {
            case .integer(let n):
                kidCbor = CBORSerialization.toCBOR(n)
            case .byteString(let data):
                kidCbor = .byteString(Array(data))
            }
            let kidBytes = CBORSerialization.encode(kidCbor)
            let map: CBOR = .map([
                .unsignedInt(UInt64(EdhocCredentialsFormat.kid.rawValue)): .byteString(Array(kidBytes))
            ])
            return CBORSerialization.encode(map)
        case .x5chain, .x5t:
            return encodeIDCred(credential)
        }
    }

    /// Overload accepting EdhocCredentialWithKeys
    public static func encodeIDCredMap(_ credWithKeys: EdhocCredentialWithKeys) -> Data {
        encodeIDCredMap(credWithKeys.credential)
    }

    /// Encode CRED_x as a CBOR item for use in context / TH input.
    /// For CCS (kid + isCBOR): credBytes is already CBOR, return as-is.
    /// For DER certs: wrap as CBOR bstr.
    public static func encodeCredItem(_ credWithKeys: EdhocCredentialWithKeys, credBytes: Data) -> Data {
        if case .kid(let kidCred) = credWithKeys.credential, kidCred.isCBOR {
            return credBytes
        }
        return CBORSerialization.encode(.byteString(Array(credBytes)))
    }

    /// Decode an ID_CRED_x value from CBOR into a partial credential
    public static func decodeIDCred(_ cbor: CBOR) throws -> EdhocCredential {
        // KID: bare integer or byte string
        switch cbor {
        case .unsignedInt(let n):
            return .kid(KIDCredential(kid: .integer(Int(n))))
        case .negativeInt(let n):
            return .kid(KIDCredential(kid: .integer(-1 - Int(n))))
        case .byteString(let bytes):
            return .kid(KIDCredential(kid: .byteString(Data(bytes))))

        case .map(let map):
            // x5chain: {33: ...}
            let x5chainKey = CBOR.unsignedInt(UInt64(EdhocCredentialsFormat.x5chain.rawValue))
            if let value = map[x5chainKey] {
                let certificates: [Data]
                switch value {
                case .byteString(let bytes):
                    certificates = [Data(bytes)]
                case .array(let arr):
                    certificates = arr.compactMap { item -> Data? in
                        if case .byteString(let bytes) = item { return Data(bytes) }
                        return nil
                    }
                default:
                    throw EdhocError.cborError("Invalid x5chain value")
                }
                return .x5chain(X5ChainCredential(certificates: certificates))
            }

            // x5t: {34: [alg, hash]}
            let x5tKey = CBOR.unsignedInt(UInt64(EdhocCredentialsFormat.x5t.rawValue))
            if let value = map[x5tKey] {
                guard case .array(let arr) = value, arr.count == 2 else {
                    throw EdhocError.cborError("Invalid x5t value")
                }
                guard let alg = CBORSerialization.intFromCBOR(arr[0]),
                      let hashAlgorithm = CertificateHashAlgorithm(rawValue: alg) else {
                    throw EdhocError.cborError("Invalid x5t hash algorithm")
                }
                guard case .byteString(let hashBytes) = arr[1] else {
                    throw EdhocError.cborError("Invalid x5t hash value")
                }
                return .x5t(X5TCredential(hash: Data(hashBytes), hashAlgorithm: hashAlgorithm))
            }

            // kid in map: {4: ...}
            let kidKey = CBOR.unsignedInt(UInt64(EdhocCredentialsFormat.kid.rawValue))
            if let value = map[kidKey] {
                switch value {
                case .unsignedInt(let n):
                    return .kid(KIDCredential(kid: .integer(Int(n))))
                case .negativeInt(let n):
                    return .kid(KIDCredential(kid: .integer(-1 - Int(n))))
                case .byteString(let bytes):
                    // For full-map kid form, value is bstr(cbor(kid)); decode inner CBOR.
                    let inner = try CBORSerialization.decode(Data(bytes))
                    switch inner {
                    case .unsignedInt(let n):
                        return .kid(KIDCredential(kid: .integer(Int(n))))
                    case .negativeInt(let n):
                        return .kid(KIDCredential(kid: .integer(-1 - Int(n))))
                    case .byteString(let innerBytes):
                        return .kid(KIDCredential(kid: .byteString(Data(innerBytes))))
                    default:
                        throw EdhocError.cborError("Invalid inner kid value in map")
                    }
                default:
                    throw EdhocError.cborError("Invalid kid value in map")
                }
            }

            throw EdhocError.cborError("Unknown ID_CRED_x map format")

        default:
            throw EdhocError.cborError("Cannot decode ID_CRED_x from CBOR type")
        }
    }

    /// Get the raw credential bytes (CRED_x) from a credential with keys
    public static func getCredBytes(_ credWithKeys: EdhocCredentialWithKeys) throws -> Data {
        switch credWithKeys.credential {
        case .kid(let kidCred):
            guard let data = kidCred.credentials else {
                throw EdhocError.missingKeyMaterial("KID credentials require credential data")
            }
            return data
        case .x5chain(let x5chain):
            guard let first = x5chain.certificates.first else {
                throw EdhocError.missingKeyMaterial("x5chain requires at least one certificate")
            }
            return first
        case .x5t(let x5t):
            guard let cert = x5t.certificate else {
                throw EdhocError.missingKeyMaterial("x5t credentials require the certificate")
            }
            return cert
        }
    }
}
