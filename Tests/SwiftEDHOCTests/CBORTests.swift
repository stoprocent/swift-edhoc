import XCTest
@testable import SwiftEDHOC
import SwiftCBOR

final class CBORTests: XCTestCase {

    // MARK: - CBOR Sequence Encoding/Decoding

    func testEncodeDecodeSequence() throws {
        let items: [CBOR] = [.unsignedInt(2), .byteString([0x01, 0x02]), .unsignedInt(16)]
        let encoded = CBORSerialization.encodeSequence(items)
        let decoded = try CBORSerialization.decodeSequence(encoded)
        XCTAssertEqual(decoded.count, 3)
        XCTAssertEqual(decoded[0], .unsignedInt(2))
        XCTAssertEqual(decoded[1], .byteString([0x01, 0x02]))
        XCTAssertEqual(decoded[2], .unsignedInt(16))
    }

    func testEncodeDecodeSequenceEmpty() throws {
        let encoded = CBORSerialization.encodeSequence([])
        let decoded = try CBORSerialization.decodeSequence(encoded)
        XCTAssertEqual(decoded.count, 0)
    }

    func testEncodeDecodeSingleItem() throws {
        let encoded = CBORSerialization.encode(.utf8String("hello"))
        let decoded = try CBORSerialization.decode(encoded)
        XCTAssertEqual(decoded, .utf8String("hello"))
    }

    // MARK: - SUITES_I Encoding

    func testEncodeSuitesSingle() {
        let result = CBORSerialization.encodeSuites([.suite2], selected: .suite2)
        XCTAssertEqual(result, .unsignedInt(2))
    }

    func testEncodeSuitesMultiple() {
        let result = CBORSerialization.encodeSuites([.suite0, .suite2], selected: .suite2)
        if case .array(let arr) = result {
            XCTAssertEqual(arr.count, 2)
            XCTAssertEqual(arr.last, .unsignedInt(2))
        } else {
            XCTFail("Expected array")
        }
    }

    func testEncodeSuitesMultipleSelectedIsLast() {
        let result = CBORSerialization.encodeSuites([.suite1, .suite3, .suite5], selected: .suite5)
        if case .array(let arr) = result {
            XCTAssertEqual(arr.count, 3)
            XCTAssertEqual(arr[0], .unsignedInt(1))
            XCTAssertEqual(arr[1], .unsignedInt(3))
            XCTAssertEqual(arr[2], .unsignedInt(5))
        } else {
            XCTFail("Expected array")
        }
    }

    // MARK: - Connection ID toBytes

    func testConnectionIDIntegerToBytes() {
        let cid = EdhocConnectionID.integer(10)
        XCTAssertEqual(cid.toBytes(), Data([0x0a]))  // CBOR major type 0, value 10
    }

    func testConnectionIDNegativeToBytes() {
        let cid = EdhocConnectionID.integer(-14)
        XCTAssertEqual(cid.toBytes(), Data([0x2d]))  // CBOR major type 1: 0x20 | 13
    }

    func testConnectionIDZeroToBytes() {
        let cid = EdhocConnectionID.integer(0)
        XCTAssertEqual(cid.toBytes(), Data([0x00]))  // CBOR major type 0, value 0
    }

    func testConnectionIDByteString() {
        let cid = EdhocConnectionID.byteString(Data([0x18]))
        XCTAssertEqual(cid.toBytes(), Data([0x18]))
    }

    func testConnectionIDByteStringMultipleBytes() {
        let cid = EdhocConnectionID.byteString(Data([0xDE, 0xAD]))
        XCTAssertEqual(cid.toBytes(), Data([0xDE, 0xAD]))
    }

    // MARK: - Connection ID from CBOR

    func testConnectionIDFromCBORUnsignedInt() throws {
        let cid = try CBORUtils.connectionIDFromCBOR(.unsignedInt(10))
        XCTAssertEqual(cid, .integer(10))
    }

    func testConnectionIDFromCBORNegativeInt() throws {
        let cid = try CBORUtils.connectionIDFromCBOR(.negativeInt(13))  // represents -14
        XCTAssertEqual(cid, .integer(-14))
    }

    func testConnectionIDFromCBORByteString() throws {
        let cid = try CBORUtils.connectionIDFromCBOR(.byteString([0x18]))
        XCTAssertEqual(cid, .byteString(Data([0x18])))
    }

    func testConnectionIDFromCBORInvalidType() {
        XCTAssertThrowsError(try CBORUtils.connectionIDFromCBOR(.utf8String("bad")))
    }

    // MARK: - Connection ID CBOR round-trip

    func testConnectionIDCBORRoundTripPositive() throws {
        let original = EdhocConnectionID.integer(7)
        let cbor = CBORUtils.connectionIDToCBOR(original)
        let recovered = try CBORUtils.connectionIDFromCBOR(cbor)
        XCTAssertEqual(recovered, original)
    }

    func testConnectionIDCBORRoundTripNegative() throws {
        let original = EdhocConnectionID.integer(-5)
        let cbor = CBORUtils.connectionIDToCBOR(original)
        let recovered = try CBORUtils.connectionIDFromCBOR(cbor)
        XCTAssertEqual(recovered, original)
    }

    func testConnectionIDCBORRoundTripByteString() throws {
        let original = EdhocConnectionID.byteString(Data([0xAB, 0xCD]))
        let cbor = CBORUtils.connectionIDToCBOR(original)
        let recovered = try CBORUtils.connectionIDFromCBOR(cbor)
        XCTAssertEqual(recovered, original)
    }

    // MARK: - EAD Round-Trip

    func testEADRoundTrip() throws {
        let tokens = [
            EdhocEAD(label: 1, value: Data([0x48, 0x65, 0x6C, 0x6C, 0x6F])),
            EdhocEAD(label: 2, value: Data()),
        ]
        let encoded = CBORUtils.encodeEADItems(tokens)
        let items = try CBORSerialization.decodeSequence(encoded)
        let parsed = CBORUtils.parseEADItems(items)
        XCTAssertEqual(parsed.count, 2)
        XCTAssertEqual(parsed[0].label, 1)
        XCTAssertEqual(parsed[0].value, Data([0x48, 0x65, 0x6C, 0x6C, 0x6F]))
        XCTAssertEqual(parsed[1].label, 2)
        XCTAssertEqual(parsed[1].value, Data())
    }

    func testEADSingleItemWithValue() throws {
        let tokens = [EdhocEAD(label: 42, value: Data([0xFF]))]
        let encoded = CBORUtils.encodeEADItems(tokens)
        let items = try CBORSerialization.decodeSequence(encoded)
        let parsed = CBORUtils.parseEADItems(items)
        XCTAssertEqual(parsed.count, 1)
        XCTAssertEqual(parsed[0].label, 42)
        XCTAssertEqual(parsed[0].value, Data([0xFF]))
    }

    func testEADEmpty() throws {
        let tokens: [EdhocEAD] = []
        let encoded = CBORUtils.encodeEADItems(tokens)
        XCTAssertTrue(encoded.isEmpty)
    }

    // MARK: - ID_CRED KID Round-Trip

    func testIDCredKidIntegerRoundTrip() throws {
        let cred = EdhocCredential.kid(KIDCredential(kid: .integer(5)))
        let encoded = CBORCredentials.encodeIDCred(cred)
        let decoded = try CBORSerialization.decode(encoded)
        let parsed = try CBORCredentials.decodeIDCred(decoded)
        if case .kid(let kidCred) = parsed, case .integer(let n) = kidCred.kid {
            XCTAssertEqual(n, 5)
        } else {
            XCTFail("Expected .kid(.integer(5))")
        }
    }

    func testIDCredKidNegativeIntegerRoundTrip() throws {
        let cred = EdhocCredential.kid(KIDCredential(kid: .integer(-3)))
        let encoded = CBORCredentials.encodeIDCred(cred)
        let decoded = try CBORSerialization.decode(encoded)
        let parsed = try CBORCredentials.decodeIDCred(decoded)
        if case .kid(let kidCred) = parsed, case .integer(let n) = kidCred.kid {
            XCTAssertEqual(n, -3)
        } else {
            XCTFail("Expected .kid(.integer(-3))")
        }
    }

    func testIDCredKidByteStringRoundTrip() throws {
        let kidData = Data([0xDE, 0xAD, 0xBE, 0xEF])
        let cred = EdhocCredential.kid(KIDCredential(kid: .byteString(kidData)))
        let encoded = CBORCredentials.encodeIDCred(cred)
        let decoded = try CBORSerialization.decode(encoded)
        let parsed = try CBORCredentials.decodeIDCred(decoded)
        if case .kid(let kidCred) = parsed, case .byteString(let data) = kidCred.kid {
            XCTAssertEqual(data, kidData)
        } else {
            XCTFail("Expected .kid(.byteString)")
        }
    }

    // MARK: - ID_CRED x5t Round-Trip

    func testIDCredX5tRoundTrip() throws {
        let hash = Data(repeating: 0xAB, count: 8)
        let cred = EdhocCredential.x5t(X5TCredential(hash: hash, hashAlgorithm: .sha256_64))
        let encoded = CBORCredentials.encodeIDCred(cred)
        let decoded = try CBORSerialization.decode(encoded)
        let parsed = try CBORCredentials.decodeIDCred(decoded)
        if case .x5t(let x5t) = parsed {
            XCTAssertEqual(x5t.hash, hash)
            XCTAssertEqual(x5t.hashAlgorithm, .sha256_64)
        } else {
            XCTFail("Expected .x5t")
        }
    }

    func testIDCredX5tSha256RoundTrip() throws {
        let hash = Data(repeating: 0x01, count: 32)
        let cred = EdhocCredential.x5t(X5TCredential(hash: hash, hashAlgorithm: .sha256))
        let encoded = CBORCredentials.encodeIDCred(cred)
        let decoded = try CBORSerialization.decode(encoded)
        let parsed = try CBORCredentials.decodeIDCred(decoded)
        if case .x5t(let x5t) = parsed {
            XCTAssertEqual(x5t.hash, hash)
            XCTAssertEqual(x5t.hashAlgorithm, .sha256)
        } else {
            XCTFail("Expected .x5t")
        }
    }

    // MARK: - ID_CRED x5chain Round-Trip

    func testIDCredX5chainSingleCertRoundTrip() throws {
        let cert = Data(repeating: 0x55, count: 128)
        let cred = EdhocCredential.x5chain(X5ChainCredential(certificates: [cert]))
        let encoded = CBORCredentials.encodeIDCred(cred)
        let decoded = try CBORSerialization.decode(encoded)
        let parsed = try CBORCredentials.decodeIDCred(decoded)
        if case .x5chain(let x5chain) = parsed {
            XCTAssertEqual(x5chain.certificates.count, 1)
            XCTAssertEqual(x5chain.certificates[0], cert)
        } else {
            XCTFail("Expected .x5chain")
        }
    }

    func testIDCredX5chainMultipleCertsRoundTrip() throws {
        let cert1 = Data(repeating: 0x11, count: 64)
        let cert2 = Data(repeating: 0x22, count: 64)
        let cred = EdhocCredential.x5chain(X5ChainCredential(certificates: [cert1, cert2]))
        let encoded = CBORCredentials.encodeIDCred(cred)
        let decoded = try CBORSerialization.decode(encoded)
        let parsed = try CBORCredentials.decodeIDCred(decoded)
        if case .x5chain(let x5chain) = parsed {
            XCTAssertEqual(x5chain.certificates.count, 2)
            XCTAssertEqual(x5chain.certificates[0], cert1)
            XCTAssertEqual(x5chain.certificates[1], cert2)
        } else {
            XCTFail("Expected .x5chain")
        }
    }

    // MARK: - Plaintext Round-Trip

    func testPlaintextRoundTrip() throws {
        let idCredCbor = CBORCredentials.encodeIDCred(.kid(KIDCredential(kid: .integer(5))))
        let sig = Data(repeating: 0xCC, count: 64)
        let ead = [EdhocEAD(label: 1, value: Data([0x01]))]

        let encoded = CBORPlaintext.encodePlaintext(idCredCbor: idCredCbor, signatureOrMac: sig, ead: ead)
        let parsed = try CBORPlaintext.parsePlaintext(encoded)

        XCTAssertEqual(parsed.signatureOrMac, sig)
        XCTAssertEqual(parsed.ead.count, 1)
        XCTAssertEqual(parsed.ead[0].label, 1)
        XCTAssertEqual(parsed.ead[0].value, Data([0x01]))
    }

    func testPlaintextWithoutEAD() throws {
        let idCredCbor = CBORCredentials.encodeIDCred(.kid(KIDCredential(kid: .integer(0))))
        let sig = Data(repeating: 0xAA, count: 32)

        let encoded = CBORPlaintext.encodePlaintext(idCredCbor: idCredCbor, signatureOrMac: sig)
        let parsed = try CBORPlaintext.parsePlaintext(encoded)

        XCTAssertEqual(parsed.signatureOrMac, sig)
        XCTAssertTrue(parsed.ead.isEmpty)
    }

    func testPlaintextWithMultipleEAD() throws {
        let idCredCbor = CBORCredentials.encodeIDCred(.kid(KIDCredential(kid: .integer(7))))
        let sig = Data(repeating: 0xBB, count: 48)
        let ead = [
            EdhocEAD(label: 10, value: Data([0xDE, 0xAD])),
            EdhocEAD(label: 20, value: Data([0xBE, 0xEF])),
        ]

        let encoded = CBORPlaintext.encodePlaintext(idCredCbor: idCredCbor, signatureOrMac: sig, ead: ead)
        let parsed = try CBORPlaintext.parsePlaintext(encoded)

        XCTAssertEqual(parsed.signatureOrMac, sig)
        XCTAssertEqual(parsed.ead.count, 2)
        XCTAssertEqual(parsed.ead[0].label, 10)
        XCTAssertEqual(parsed.ead[0].value, Data([0xDE, 0xAD]))
        XCTAssertEqual(parsed.ead[1].label, 20)
        XCTAssertEqual(parsed.ead[1].value, Data([0xBE, 0xEF]))
    }

    // MARK: - toCBOR Utility

    func testToCBORPositiveInt() {
        let cbor = CBORSerialization.toCBOR(42)
        XCTAssertEqual(cbor, .unsignedInt(42))
    }

    func testToCBORNegativeInt() {
        let cbor = CBORSerialization.toCBOR(-1)
        XCTAssertEqual(cbor, .negativeInt(0))  // CBOR negativeInt stores -1 - n, so -1 => 0
    }

    func testToCBORData() {
        let data = Data([0x01, 0x02, 0x03])
        let cbor = CBORSerialization.toCBOR(data)
        XCTAssertEqual(cbor, .byteString([0x01, 0x02, 0x03]))
    }

    func testToCBORString() {
        let cbor = CBORSerialization.toCBOR("test")
        XCTAssertEqual(cbor, .utf8String("test"))
    }

    func testToCBORBool() {
        XCTAssertEqual(CBORSerialization.toCBOR(true), .boolean(true))
        XCTAssertEqual(CBORSerialization.toCBOR(false), .boolean(false))
    }

    func testDataFromCBOR() {
        let data = CBORSerialization.dataFromCBOR(.byteString([0xAA, 0xBB]))
        XCTAssertEqual(data, Data([0xAA, 0xBB]))
    }

    func testDataFromCBORNonByteString() {
        let data = CBORSerialization.dataFromCBOR(.unsignedInt(5))
        XCTAssertNil(data)
    }

    func testIntFromCBOR() {
        XCTAssertEqual(CBORSerialization.intFromCBOR(.unsignedInt(42)), 42)
        XCTAssertEqual(CBORSerialization.intFromCBOR(.negativeInt(0)), -1)
        XCTAssertNil(CBORSerialization.intFromCBOR(.utf8String("nope")))
    }
}
