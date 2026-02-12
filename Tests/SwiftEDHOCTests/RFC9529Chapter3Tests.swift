import XCTest
import CryptoKit
@testable import SwiftEDHOC

/// Tests using RFC 9529 Chapter 3 test vectors: Method 3 (StaticDH/StaticDH),
/// Suite 2 (P-256), CCS/kid credentials.
///
/// All values are fully deterministic since Method 3 uses no signatures.
/// This test verifies all intermediate values match the published RFC vectors.
final class RFC9529Chapter3Tests: XCTestCase {

    // MARK: - Test vector data from RFC 9529 Chapter 3 / libedhoc

    /// Initiator ephemeral DH private key X (32 bytes)
    private static let ephemeralX = Data([
        0x36, 0x8e, 0xc1, 0xf6, 0x9a, 0xeb, 0x65, 0x9b, 0xa3, 0x7d, 0x5a,
        0x8d, 0x45, 0xb2, 0x1b, 0xdc, 0x02, 0x99, 0xdc, 0xea, 0xa8, 0xef,
        0x23, 0x5f, 0x3c, 0xa4, 0x2c, 0xe3, 0x53, 0x0f, 0x95, 0x25,
    ])

    /// Responder ephemeral DH private key Y (32 bytes)
    private static let ephemeralY = Data([
        0xe2, 0xf4, 0x12, 0x67, 0x77, 0x20, 0x5e, 0x85, 0x3b, 0x43, 0x7d,
        0x6e, 0xac, 0xa1, 0xe1, 0xf7, 0x53, 0xcd, 0xcc, 0x3e, 0x2c, 0x69,
        0xfa, 0x88, 0x4b, 0x0a, 0x1a, 0x64, 0x09, 0x77, 0xe4, 0x18,
    ])

    /// Initiator static DH private key SK_I (32 bytes)
    private static let skI = Data([
        0xfb, 0x13, 0xad, 0xeb, 0x65, 0x18, 0xce, 0xe5, 0xf8, 0x84, 0x17,
        0x66, 0x08, 0x41, 0x14, 0x2e, 0x83, 0x0a, 0x81, 0xfe, 0x33, 0x43,
        0x80, 0xa9, 0x53, 0x40, 0x6a, 0x13, 0x05, 0xe8, 0x70, 0x6b,
    ])

    /// Initiator static DH public key PK_I (32 bytes, x-coordinate)
    private static let pkI = Data([
        0xac, 0x75, 0xe9, 0xec, 0xe3, 0xe5, 0x0b, 0xfc, 0x8e, 0xd6, 0x03,
        0x99, 0x88, 0x95, 0x22, 0x40, 0x5c, 0x47, 0xbf, 0x16, 0xdf, 0x96,
        0x66, 0x0a, 0x41, 0x29, 0x8c, 0xb4, 0x30, 0x7f, 0x7e, 0xb6,
    ])

    /// Responder static DH private key SK_R (32 bytes)
    private static let skR = Data([
        0x72, 0xcc, 0x47, 0x61, 0xdb, 0xd4, 0xc7, 0x8f, 0x75, 0x89, 0x31,
        0xaa, 0x58, 0x9d, 0x34, 0x8d, 0x1e, 0xf8, 0x74, 0xa7, 0xe3, 0x03,
        0xed, 0xe2, 0xf1, 0x40, 0xdc, 0xf3, 0xe6, 0xaa, 0x4a, 0xac,
    ])

    /// Responder static DH public key PK_R (32 bytes, x-coordinate)
    private static let pkR = Data([
        0xbb, 0xc3, 0x49, 0x60, 0x52, 0x6e, 0xa4, 0xd3, 0x2e, 0x94, 0x0c,
        0xad, 0x2a, 0x23, 0x41, 0x48, 0xdd, 0xc2, 0x17, 0x91, 0xa1, 0x2a,
        0xfb, 0xcb, 0xac, 0x93, 0x62, 0x20, 0x46, 0xdd, 0x44, 0xf0,
    ])

    /// CRED_R: CCS (CWT Claims Set) CBOR bytes for responder
    private static let credRBytes = Data([
        0xa2, 0x02, 0x6b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x65,
        0x64, 0x75, 0x08, 0xa1, 0x01, 0xa5, 0x01, 0x02, 0x02, 0x41, 0x32, 0x20,
        0x01, 0x21, 0x58, 0x20, 0xbb, 0xc3, 0x49, 0x60, 0x52, 0x6e, 0xa4, 0xd3,
        0x2e, 0x94, 0x0c, 0xad, 0x2a, 0x23, 0x41, 0x48, 0xdd, 0xc2, 0x17, 0x91,
        0xa1, 0x2a, 0xfb, 0xcb, 0xac, 0x93, 0x62, 0x20, 0x46, 0xdd, 0x44, 0xf0,
        0x22, 0x58, 0x20, 0x45, 0x19, 0xe2, 0x57, 0x23, 0x6b, 0x2a, 0x0c, 0xe2,
        0x02, 0x3f, 0x09, 0x31, 0xf1, 0xf3, 0x86, 0xca, 0x7a, 0xfd, 0xa6, 0x4f,
        0xcd, 0xe0, 0x10, 0x8c, 0x22, 0x4c, 0x51, 0xea, 0xbf, 0x60, 0x72,
    ])

    /// CRED_I: CCS (CWT Claims Set) CBOR bytes for initiator
    private static let credIBytes = Data([
        0xa2, 0x02, 0x77, 0x34, 0x32, 0x2d, 0x35, 0x30, 0x2d, 0x33, 0x31, 0x2d,
        0x46, 0x46, 0x2d, 0x45, 0x46, 0x2d, 0x33, 0x37, 0x2d, 0x33, 0x32, 0x2d,
        0x33, 0x39, 0x08, 0xa1, 0x01, 0xa5, 0x01, 0x02, 0x02, 0x41, 0x2b, 0x20,
        0x01, 0x21, 0x58, 0x20, 0xac, 0x75, 0xe9, 0xec, 0xe3, 0xe5, 0x0b, 0xfc,
        0x8e, 0xd6, 0x03, 0x99, 0x88, 0x95, 0x22, 0x40, 0x5c, 0x47, 0xbf, 0x16,
        0xdf, 0x96, 0x66, 0x0a, 0x41, 0x29, 0x8c, 0xb4, 0x30, 0x7f, 0x7e, 0xb6,
        0x22, 0x58, 0x20, 0x6e, 0x5d, 0xe6, 0x11, 0x38, 0x8a, 0x4b, 0x8a, 0x82,
        0x11, 0x33, 0x4a, 0xc7, 0xd3, 0x7e, 0xcb, 0x52, 0xa3, 0x87, 0xd2, 0x57,
        0xe6, 0xdb, 0x3c, 0x2a, 0x93, 0xdf, 0x21, 0xff, 0x3a, 0xff, 0xc8,
    ])

    // MARK: - Expected intermediate values (hex strings)

    private static let expectedHMessage1 = "ca02cabda5a8902749b42f711050bb4dbd52153e87527594b39f50cdf019888c"
    private static let expectedTH2 = "356efd53771425e008f3fe3a86c83ff4c6b16e57028ff39d5236c182b202084b"
    private static let expectedPRK2e = "5aa0d69f3e3d1e0c479f0b8a486690c9802630c3466b1dc92371c982563170b5"
    private static let expectedPRK3e2m = "0ca3d3398296b3c03900987620c11f6fce70781c1d1219720f9ec08c122d8434"
    private static let expectedMAC2 = "0943305c899f5c54"
    private static let expectedTH3 = "adaf67a78a4bcc91e018f8882762a722000b2507039df0bc1bbf0c161bb3155c"
    private static let expectedPRK4e3m = "81cc8a298e357044e3c466bb5c0a1e507e01d49238aeba138df94635407c0ff7"
    private static let expectedMAC3 = "623c91df41e34c2f"
    private static let expectedTH4 = "c902b1e3a4326c93c5551f5f3aa6c5ecc0246806765612e52b5d99e6059d6b6e"
    private static let expectedMasterSecret = "f9868f6a3aca78a05d1485b35030b162"
    private static let expectedMasterSalt = "ada24c7dbfc85eeb"

    /// Key update context
    private static let keyUpdateContext = Data([
        0xa0, 0x11, 0x58, 0xfd, 0xb8, 0x20, 0x89, 0x0c,
        0xd6, 0xbe, 0x16, 0x96, 0x02, 0xb8, 0xbc, 0xea,
    ])
    private static let expectedMasterSecretAfterUpdate = "49f72fac02b4658bda21e2dac66fc374"
    private static let expectedMasterSaltAfterUpdate = "dd8b24f2aa9b011a"

    // MARK: - Test

    /// Full handshake with RFC 9529 Chapter 3 vectors (Method 3, Suite 2, CCS/kid).
    /// Verifies all intermediate values match the published RFC vectors.
    func testRFC9529Chapter3HandshakeAndOSCORE() async throws {
        // -- Initiator setup --
        var iCredProvider = CCSCredentialProvider()
        iCredProvider.addOwnCredential(
            kid: .integer(-12),
            ccsBytes: Self.credIBytes,
            publicKey: Self.pkI,
            privateKey: Self.skI
        )
        iCredProvider.addPeerCredential(
            kid: .integer(-19),
            ccsBytes: Self.credRBytes,
            publicKey: Self.pkR
        )

        let iCrypto = Chapter3CryptoProvider(deterministicEphemeralKey: Self.ephemeralX)

        var iLog: [(String, String)] = []
        var rLog: [(String, String)] = []

        let initiator = EdhocSession(
            connectionID: .integer(-24),
            methods: [.method3],
            cipherSuites: [.suite6, .suite2],
            credentialProvider: iCredProvider,
            cryptoProvider: iCrypto,
            logger: { name, data in iLog.append((name, data.hex)) }
        )

        // -- Responder setup --
        var rCredProvider = CCSCredentialProvider()
        rCredProvider.addOwnCredential(
            kid: .integer(-19),
            ccsBytes: Self.credRBytes,
            publicKey: Self.pkR,
            privateKey: Self.skR
        )
        rCredProvider.addPeerCredential(
            kid: .integer(-12),
            ccsBytes: Self.credIBytes,
            publicKey: Self.pkI
        )

        let rCrypto = Chapter3CryptoProvider(deterministicEphemeralKey: Self.ephemeralY)

        let responder = EdhocSession(
            connectionID: .integer(-8),
            methods: [.method3],
            cipherSuites: [.suite2],
            credentialProvider: rCredProvider,
            cryptoProvider: rCrypto,
            logger: { name, data in rLog.append((name, data.hex)) }
        )

        // -- Message 1 (Initiator -> Responder) --
        let msg1 = try await initiator.composeMessage1()
        _ = try await responder.processMessage1(msg1)

        // Verify TH_1 (H_message_1) matches
        let iTH1 = iLog.first(where: { $0.0 == "TH_1" })?.1
        let rTH1 = rLog.first(where: { $0.0 == "TH_1" })?.1
        XCTAssertEqual(iTH1, rTH1, "TH_1 must match between initiator and responder")
        XCTAssertEqual(iTH1, Self.expectedHMessage1, "TH_1 (H_message_1) must match RFC vector")

        // -- Message 2 (Responder -> Initiator) --
        let msg2 = try await responder.composeMessage2()
        _ = try await initiator.processMessage2(msg2)

        // Verify TH_2
        let rTH2 = rLog.first(where: { $0.0 == "TH_2" })?.1
        let iTH2 = iLog.first(where: { $0.0 == "TH_2" })?.1
        XCTAssertEqual(rTH2, iTH2, "TH_2 must match between initiator and responder")
        XCTAssertEqual(rTH2, Self.expectedTH2, "TH_2 must match RFC vector")

        // Verify PRK_2e
        let rPRK2e = rLog.first(where: { $0.0 == "PRK_2e" })?.1
        let iPRK2e = iLog.first(where: { $0.0 == "PRK_2e" })?.1
        XCTAssertEqual(rPRK2e, iPRK2e, "PRK_2e must match between initiator and responder")
        XCTAssertEqual(rPRK2e, Self.expectedPRK2e, "PRK_2e must match RFC vector")

        // Verify PRK_3e2m
        let rPRK3e2m = rLog.first(where: { $0.0 == "PRK_3e2m" })?.1
        let iPRK3e2m = iLog.first(where: { $0.0 == "PRK_3e2m" })?.1
        XCTAssertEqual(rPRK3e2m, iPRK3e2m, "PRK_3e2m must match between initiator and responder")
        XCTAssertEqual(rPRK3e2m, Self.expectedPRK3e2m, "PRK_3e2m must match RFC vector")

        // Verify MAC_2
        let rMAC2 = rLog.first(where: { $0.0 == "MAC_2" })?.1
        let iMAC2 = iLog.first(where: { $0.0 == "MAC_2" })?.1
        XCTAssertEqual(rMAC2, iMAC2, "MAC_2 must match between initiator and responder")
        XCTAssertEqual(rMAC2, Self.expectedMAC2, "MAC_2 must match RFC vector")

        // Verify TH_3
        let rTH3 = rLog.first(where: { $0.0 == "TH_3" })?.1
        let iTH3 = iLog.first(where: { $0.0 == "TH_3" })?.1
        XCTAssertEqual(rTH3, iTH3, "TH_3 must match between initiator and responder")
        XCTAssertEqual(rTH3, Self.expectedTH3, "TH_3 must match RFC vector")

        // -- Message 3 (Initiator -> Responder) --
        let msg3 = try await initiator.composeMessage3()
        _ = try await responder.processMessage3(msg3)

        // Verify PRK_4e3m
        let iPRK4e3m = iLog.first(where: { $0.0 == "PRK_4e3m" })?.1
        XCTAssertEqual(iPRK4e3m, Self.expectedPRK4e3m, "PRK_4e3m must match RFC vector")

        // Verify MAC_3
        let iMAC3 = iLog.first(where: { $0.0 == "MAC_3" })?.1
        XCTAssertEqual(iMAC3, Self.expectedMAC3, "MAC_3 must match RFC vector")

        // Verify TH_4
        let iTH4 = iLog.first(where: { $0.0 == "TH_4" })?.1
        XCTAssertEqual(iTH4, Self.expectedTH4, "TH_4 must match RFC vector")

        // -- Verify OSCORE contexts --
        let iOSCORE = try await initiator.exportOSCORE()
        let rOSCORE = try await responder.exportOSCORE()

        XCTAssertEqual(iOSCORE.masterSecret, rOSCORE.masterSecret,
                       "Master secrets must be identical")
        XCTAssertEqual(iOSCORE.masterSalt, rOSCORE.masterSalt,
                       "Master salts must be identical")
        XCTAssertEqual(iOSCORE.senderId, rOSCORE.recipientId,
                       "Initiator senderId must equal Responder recipientId")
        XCTAssertEqual(iOSCORE.recipientId, rOSCORE.senderId,
                       "Initiator recipientId must equal Responder senderId")

        // Verify OSCORE values match RFC vectors
        XCTAssertEqual(iOSCORE.masterSecret.hex, Self.expectedMasterSecret,
                       "OSCORE master secret must match RFC vector")
        XCTAssertEqual(iOSCORE.masterSalt.hex, Self.expectedMasterSalt,
                       "OSCORE master salt must match RFC vector")

        // Verify OSCORE sender/recipient IDs per RFC 9528:
        // C_I = -24 => CBOR encoding byte 0x37, C_R = -8 => CBOR encoding byte 0x27
        // Initiator sender ID = C_R (peer), recipient ID = C_I (own)
        XCTAssertEqual(iOSCORE.senderId, Data([0x27]),
                       "Initiator sender ID must be CBOR byte for C_R=-8")
        XCTAssertEqual(iOSCORE.recipientId, Data([0x37]),
                       "Initiator recipient ID must be CBOR byte for C_I=-24")

        // -- Key Update --
        try await initiator.keyUpdate(context: Self.keyUpdateContext)
        try await responder.keyUpdate(context: Self.keyUpdateContext)

        let iUpdated = try await initiator.exportOSCORE()
        let rUpdated = try await responder.exportOSCORE()

        XCTAssertEqual(iUpdated.masterSecret, rUpdated.masterSecret,
                       "Updated master secrets must be identical")
        XCTAssertEqual(iUpdated.masterSalt, rUpdated.masterSalt,
                       "Updated master salts must be identical")

        XCTAssertEqual(iUpdated.masterSecret.hex, Self.expectedMasterSecretAfterUpdate,
                       "Updated OSCORE master secret must match RFC vector")
        XCTAssertEqual(iUpdated.masterSalt.hex, Self.expectedMasterSaltAfterUpdate,
                       "Updated OSCORE master salt must match RFC vector")
    }

    // MARK: - Test: CCS credential encoding

    func testCCSIDCredEncoding() {
        // ID_CRED_R compact form for kid=-19: bare CBOR value 0x32
        let kidCred = KIDCredential(kid: .integer(-19), credentials: Self.credRBytes, isCBOR: true)
        let compact = CBORCredentials.encodeIDCred(.kid(kidCred))
        XCTAssertEqual(compact, Data([0x32]),
                       "Compact ID_CRED_R for kid=-19 must be bare CBOR 0x32")

        // ID_CRED_R full map form for kid=-19: {4: h'32'} = a1 04 41 32
        let fullMap = CBORCredentials.encodeIDCredMap(.kid(kidCred))
        XCTAssertEqual(fullMap, Data([0xa1, 0x04, 0x41, 0x32]),
                       "Full map ID_CRED_R for kid=-19 must be {4: h'32'}")

        // ID_CRED_I compact form for kid=-12: bare CBOR value 0x2b
        let kidCredI = KIDCredential(kid: .integer(-12), credentials: Self.credIBytes, isCBOR: true)
        let compactI = CBORCredentials.encodeIDCred(.kid(kidCredI))
        XCTAssertEqual(compactI, Data([0x2b]),
                       "Compact ID_CRED_I for kid=-12 must be bare CBOR 0x2B")

        // ID_CRED_I full map form for kid=-12: {4: h'2b'} = a1 04 41 2b
        let fullMapI = CBORCredentials.encodeIDCredMap(.kid(kidCredI))
        XCTAssertEqual(fullMapI, Data([0xa1, 0x04, 0x41, 0x2b]),
                       "Full map ID_CRED_I for kid=-12 must be {4: h'2B'}")
    }

    func testCCSCredItemEncoding() {
        // For CCS (isCBOR=true), encodeCredItem returns raw CBOR (not bstr-wrapped)
        let kidCred = KIDCredential(kid: .integer(-19), credentials: Self.credRBytes, isCBOR: true)
        let credWithKeys = EdhocCredentialWithKeys(credential: .kid(kidCred))
        let credItem = CBORCredentials.encodeCredItem(credWithKeys, credBytes: Self.credRBytes)
        XCTAssertEqual(credItem, Self.credRBytes,
                       "CCS CRED_x must be raw CBOR, not bstr-wrapped")

        // For DER certs (not kid), encodeCredItem wraps as bstr
        let x5chain = X5ChainCredential(certificates: [Data([0x01, 0x02, 0x03])])
        let certWithKeys = EdhocCredentialWithKeys(credential: .x5chain(x5chain))
        let certItem = CBORCredentials.encodeCredItem(certWithKeys, credBytes: Data([0x01, 0x02, 0x03]))
        // bstr(h'010203') = 43 01 02 03
        XCTAssertEqual(certItem, Data([0x43, 0x01, 0x02, 0x03]),
                       "DER CRED_x must be bstr-wrapped")
    }

    func testConnectionIDToBytes() throws {
        // C_I = -24: CBOR encoding byte = 0x20 | 23 = 0x37
        let cI = EdhocConnectionID.integer(-24)
        XCTAssertEqual(cI.toBytes(), Data([0x37]),
                       "C_I=-24 OSCORE ID must be 0x37")

        // C_R = -8: CBOR encoding byte = 0x20 | 7 = 0x27
        let cR = EdhocConnectionID.integer(-8)
        XCTAssertEqual(cR.toBytes(), Data([0x27]),
                       "C_R=-8 OSCORE ID must be 0x27")

        // Positive: C=5 => CBOR encoding byte = 0x05
        let c5 = EdhocConnectionID.integer(5)
        XCTAssertEqual(c5.toBytes(), Data([0x05]),
                       "C=5 OSCORE ID must be 0x05")

        // Zero: C=0 => CBOR encoding byte = 0x00
        let c0 = EdhocConnectionID.integer(0)
        XCTAssertEqual(c0.toBytes(), Data([0x00]),
                       "C=0 OSCORE ID must be 0x00")

        // C=-1: CBOR encoding byte = 0x20
        let cm1 = EdhocConnectionID.integer(-1)
        XCTAssertEqual(cm1.toBytes(), Data([0x20]),
                       "C=-1 OSCORE ID must be 0x20")
    }
}

// MARK: - Deterministic crypto provider

/// A crypto provider wrapper that injects a predetermined ephemeral DH key
/// for deterministic test vector verification.
private final class Chapter3CryptoProvider: EdhocCryptoProvider, @unchecked Sendable {
    private let inner: CryptoKitProvider
    private let deterministicEphemeralKey: Data

    init(deterministicEphemeralKey: Data) {
        self.inner = CryptoKitProvider()
        self.deterministicEphemeralKey = deterministicEphemeralKey
    }

    func generateKeyPair(suite: EdhocCipherSuite) throws -> KeyPair {
        let params = suite.parameters
        switch params.dhCurve {
        case .x25519:
            let privKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: deterministicEphemeralKey)
            return KeyPair(publicKey: Data(privKey.publicKey.rawRepresentation), privateKey: deterministicEphemeralKey)
        case .p256:
            let privKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: deterministicEphemeralKey)
            let pubKey = Data(privKey.publicKey.x963Representation.dropFirst().prefix(32))
            return KeyPair(publicKey: pubKey, privateKey: deterministicEphemeralKey)
        case .p384:
            let privKey = try P384.KeyAgreement.PrivateKey(rawRepresentation: deterministicEphemeralKey)
            let pubKey = Data(privKey.publicKey.x963Representation.dropFirst().prefix(48))
            return KeyPair(publicKey: pubKey, privateKey: deterministicEphemeralKey)
        case .x448:
            throw EdhocError.unsupportedCipherSuite(selected: suite.rawValue, peerSuites: [suite.rawValue])
        }
    }

    func keyAgreement(suite: EdhocCipherSuite, privateKey: Data, peerPublicKey: Data) throws -> Data { try inner.keyAgreement(suite: suite, privateKey: privateKey, peerPublicKey: peerPublicKey) }
    func sign(suite: EdhocCipherSuite, privateKey: Data, input: Data) throws -> Data { try inner.sign(suite: suite, privateKey: privateKey, input: input) }
    func verify(suite: EdhocCipherSuite, publicKey: Data, input: Data, signature: Data) throws -> Bool { try inner.verify(suite: suite, publicKey: publicKey, input: input, signature: signature) }
    func hkdfExtract(suite: EdhocCipherSuite, ikm: Data, salt: Data) throws -> Data { try inner.hkdfExtract(suite: suite, ikm: ikm, salt: salt) }
    func hkdfExpand(suite: EdhocCipherSuite, prk: Data, info: Data, length: Int) throws -> Data { try inner.hkdfExpand(suite: suite, prk: prk, info: info, length: length) }
    func encrypt(suite: EdhocCipherSuite, key: Data, nonce: Data, aad: Data, plaintext: Data) throws -> Data { try inner.encrypt(suite: suite, key: key, nonce: nonce, aad: aad, plaintext: plaintext) }
    func decrypt(suite: EdhocCipherSuite, key: Data, nonce: Data, aad: Data, ciphertext: Data) throws -> Data { try inner.decrypt(suite: suite, key: key, nonce: nonce, aad: aad, ciphertext: ciphertext) }
    func hash(suite: EdhocCipherSuite, data: Data) throws -> Data { try inner.hash(suite: suite, data: data) }
}

// MARK: - Hex string helpers

private extension Data {
    var hex: String {
        map { String(format: "%02x", $0) }.joined()
    }

    init(hexString hex: String) {
        let clean = hex.filter { $0.isHexDigit }
        var data = Data(capacity: clean.count / 2)
        var index = clean.startIndex
        while index < clean.endIndex {
            let nextIndex = clean.index(index, offsetBy: 2)
            if let byte = UInt8(clean[index..<nextIndex], radix: 16) {
                data.append(byte)
            }
            index = nextIndex
        }
        self = data
    }
}
