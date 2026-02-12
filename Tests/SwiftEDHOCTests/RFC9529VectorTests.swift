import XCTest
import CryptoKit
@testable import SwiftEDHOC

// MARK: - Deterministic crypto provider for reproducible test vectors

/// A crypto provider wrapper that injects a predetermined ephemeral DH key
/// instead of generating a random one. This allows deterministic intermediate
/// values (TH_1, TH_2, PRK_2e, MAC_2, etc.) to match the RFC 9529 test vectors.
///
/// Note: CryptoKit's Ed25519 uses hedged (randomized) signatures for side-channel
/// protection. This means Signature_or_MAC_2/3 differ from the RFC vectors each run,
/// causing TH_3 and all downstream values (TH_4, PRK_out, OSCORE) to also differ.
/// However, both sides always agree on the OSCORE context because they use the same
/// actual signature bytes from the exchanged messages.
private final class VectorsCryptoProvider: EdhocCryptoProvider, @unchecked Sendable {
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

// MARK: - RFC 9529 Test Vectors

final class RFC9529VectorTests: XCTestCase {

    // MARK: - Test vector data (Ed25519 / Suite 0)

    /// Trusted CA root certificate (DER, Ed25519)
    private static let trustedCA = Data(hexString:
        "3082010E3081C1A003020102020462319E74300506032B6570301D311B3019060355" +
        "04030C124544484F4320526F6F742045643235353139301E170D32323033313630" +
        "38323331365A170D3239313233313233303030305A301D311B30190603550403" +
        "0C124544484F4320526F6F742045643235353139302A300506032B6570032100" +
        "2B7B3E8057C8642944D06AFE7A71D1C9BF961B6292BAC4B04F91669BBB713B" +
        "E4A3233021300E0603551D0F0101FF040403020204300F0603551D130101FF04" +
        "0530030101FF300506032B65700341004BB52BBF1539B71A4AAF429778F29EDA" +
        "7E814680698F16C48F2A6FA4DBE82541C58207BA1BC9CDB0C2FA947FFBF0F0" +
        "EC0EE91A7FF37A94D9251FA5CDF1E67A0F"
    )

    /// Initiator leaf certificate (DER, Ed25519)
    private static let initiatorCert = Data(hexString:
        "3081EE3081A1A003020102020462319EA0300506032B6570301D311B301906035504" +
        "030C124544484F4320526F6F742045643235353139301E170D32323033313630" +
        "38323430305A170D3239313233313233303030305A30223120301E0603550403" +
        "0C174544484F4320496E69746961746F722045643235353139302A300506032B" +
        "6570032100ED06A8AE61A829BA5FA54525C9D07F48DD44A302F43E0F23D8CC" +
        "20B73085141E300506032B6570034100521241D8B3A770996BCFC9B9EAD4E7" +
        "E0A1C0DB353A3BDF2910B39275AE48B756015981850D27DB6734E37F672122" +
        "67DD05EEFF27B9E7A813FA574B72A00B430B"
    )

    /// Initiator Ed25519 signing key (raw, 32 bytes)
    private static let initiatorKey = Data(hexString:
        "4C5B25878F507C6B9DAE68FBD4FD3FF997533DB0AF00B25D324EA28E6C213BC8"
    )

    /// Initiator deterministic X25519 ephemeral DH key
    private static let initiatorEphemeralKey = Data(hexString:
        "892EC28E5CB6669108470539500B705E60D008D347C5817EE9F3327C8A87BB03"
    )

    /// Responder leaf certificate (DER, Ed25519)
    private static let responderCert = Data(hexString:
        "3081EE3081A1A003020102020462319EC4300506032B6570301D311B301906035504" +
        "030C124544484F4320526F6F742045643235353139301E170D32323033313630" +
        "38323433365A170D3239313233313233303030305A30223120301E0603550403" +
        "0C174544484F4320526573706F6E6465722045643235353139302A300506032B" +
        "6570032100A1DB47B95184854AD12A0C1A354E418AACE33AA0F2C662C00B3A" +
        "C55DE92F9359300506032B6570034100B723BC01EAB0928E8B2B6C98DE19CC" +
        "3823D46E7D6987B032478FECFAF14537A1AF14CC8BE829C6B73044101837EB" +
        "4ABC949565D86DCE51CFAE52AB82C152CB02"
    )

    /// Responder Ed25519 signing key (raw, 32 bytes)
    private static let responderKey = Data(hexString:
        "EF140FF900B0AB03F0C08D879CBBD4B31EA71E6E7EE7FFCB7E7955777A332799"
    )

    /// Responder deterministic X25519 ephemeral DH key
    private static let responderEphemeralKey = Data(hexString:
        "E69C23FBF81BC435942446837FE827BF206C8FA10A39DB47449E5A813421E1E8"
    )

    // MARK: - Expected deterministic intermediate values from RFC 9529

    /// These values are deterministic (independent of Ed25519 hedging) because they
    /// are computed before any signature operation occurs.
    private static let expectedTH1 = "c165d6a99d1bcafaac8dbf2b352a6f7d71a30b439c9d64d349a23848038ed16b"
    private static let expectedTH2 = "c6405c154c567466ab1df20369500e540e9f14bd3a796a0652cae66c9061688d"
    private static let expectedPRK2e = "d584ac2e5dad5a77d14b53ebe72ef1d5daa8860d399373bf2c240afa7ba804da"
    private static let expectedPRK3e2m = "d584ac2e5dad5a77d14b53ebe72ef1d5daa8860d399373bf2c240afa7ba804da"
    private static let expectedMAC2 = "862a7e5ef147f9a5f4c512e1b6623cd66cd17a7272072bfe5b602ffe307ee0e9"

    /// Context bytes for key update operation
    private static let keyUpdateContext = Data(hexString: "d6be169602b8bceaa01158fdb820890c")

    // MARK: - Test: Full handshake with RFC 9529 vectors

    /// Verifies:
    /// 1. Deterministic intermediate values (TH_1, TH_2, PRK_2e, PRK_3e2m, MAC_2) match RFC 9529
    /// 2. Both sides complete the handshake successfully
    /// 3. Both sides derive identical OSCORE contexts
    /// 4. Key update produces matching updated contexts
    ///
    /// Note: OSCORE values are NOT compared against RFC 9529 expected hex because
    /// CryptoKit's Ed25519 uses hedged (randomized) signatures. The Signature_or_MAC_2
    /// differs each run, causing TH_3 and all downstream values to diverge from the
    /// published vectors. Both sides still agree because they use the same actual
    /// signature bytes from the exchanged messages.
    func testRFC9529HandshakeAndOSCORE() async throws {
        // -- Initiator setup (connection ID = -14, Method 0, Suite 0, x5t) --
        let initiatorCredMgr = X509CredentialProvider(
            certificates: [Self.initiatorCert],
            privateKey: Self.initiatorKey,
            fetchFormat: .x5t
        )
        initiatorCredMgr.addTrustedCA(Self.trustedCA)
        initiatorCredMgr.addPeerCertificate(Self.responderCert)

        let initiatorCrypto = VectorsCryptoProvider(
            deterministicEphemeralKey: Self.initiatorEphemeralKey
        )

        var iLog: [(String, String)] = []
        var rLog: [(String, String)] = []

        let initiator = EdhocSession(
            connectionID: .integer(-14),
            methods: [.method0],
            cipherSuites: [.suite0],
            credentialProvider: initiatorCredMgr,
            cryptoProvider: initiatorCrypto,
            logger: { name, data in iLog.append((name, data.map { String(format: "%02x", $0) }.joined())) }
        )

        // -- Responder setup (connection ID = byteString([0x18]), Method 0, Suite 0, x5t) --
        let responderCredMgr = X509CredentialProvider(
            certificates: [Self.responderCert],
            privateKey: Self.responderKey,
            fetchFormat: .x5t
        )
        responderCredMgr.addTrustedCA(Self.trustedCA)
        responderCredMgr.addPeerCertificate(Self.initiatorCert)

        let responderCrypto = VectorsCryptoProvider(
            deterministicEphemeralKey: Self.responderEphemeralKey
        )

        let responder = EdhocSession(
            connectionID: .byteString(Data([0x18])),
            methods: [.method0],
            cipherSuites: [.suite0],
            credentialProvider: responderCredMgr,
            cryptoProvider: responderCrypto,
            logger: { name, data in rLog.append((name, data.map { String(format: "%02x", $0) }.joined())) }
        )

        // -- Message 1 (Initiator -> Responder) --
        let msg1 = try await initiator.composeMessage1()
        let ead1 = try await responder.processMessage1(msg1)
        XCTAssertTrue(ead1.isEmpty, "No EAD expected in message_1")

        // -- Verify deterministic intermediate values after message 1 --
        let iTH1 = iLog.first(where: { $0.0 == "TH_1" })?.1
        let rTH1 = rLog.first(where: { $0.0 == "TH_1" })?.1
        XCTAssertEqual(iTH1, rTH1, "TH_1 must match between initiator and responder")
        XCTAssertEqual(iTH1, Self.expectedTH1, "TH_1 must match RFC 9529 vector")

        // -- Message 2 (Responder -> Initiator) --
        let msg2 = try await responder.composeMessage2()
        let ead2 = try await initiator.processMessage2(msg2)
        XCTAssertTrue(ead2.isEmpty, "No EAD expected in message_2")

        // -- Verify deterministic intermediate values after message 2 --
        let rTH2 = rLog.first(where: { $0.0 == "TH_2" })?.1
        let iTH2 = iLog.first(where: { $0.0 == "TH_2" })?.1
        XCTAssertEqual(rTH2, iTH2, "TH_2 must match between initiator and responder")
        XCTAssertEqual(rTH2, Self.expectedTH2, "TH_2 must match RFC 9529 vector")

        let rPRK2e = rLog.first(where: { $0.0 == "PRK_2e" })?.1
        let iPRK2e = iLog.first(where: { $0.0 == "PRK_2e" })?.1
        XCTAssertEqual(rPRK2e, iPRK2e, "PRK_2e must match between initiator and responder")
        XCTAssertEqual(rPRK2e, Self.expectedPRK2e, "PRK_2e must match RFC 9529 vector")

        let rPRK3e2m = rLog.first(where: { $0.0 == "PRK_3e2m" })?.1
        let iPRK3e2m = iLog.first(where: { $0.0 == "PRK_3e2m" })?.1
        XCTAssertEqual(rPRK3e2m, iPRK3e2m, "PRK_3e2m must match between initiator and responder")
        XCTAssertEqual(rPRK3e2m, Self.expectedPRK3e2m, "PRK_3e2m must match RFC 9529 vector")

        let rMAC2 = rLog.first(where: { $0.0 == "MAC_2" })?.1
        let iMAC2 = iLog.first(where: { $0.0 == "MAC_2" })?.1
        XCTAssertEqual(rMAC2, iMAC2, "MAC_2 must match between initiator and responder")
        XCTAssertEqual(rMAC2, Self.expectedMAC2, "MAC_2 must match RFC 9529 vector")

        // -- Message 3 (Initiator -> Responder) --
        let msg3 = try await initiator.composeMessage3()
        let ead3 = try await responder.processMessage3(msg3)
        XCTAssertTrue(ead3.isEmpty, "No EAD expected in message_3")

        // -- Message 4 (optional) --
        let msg4 = try await initiator.composeMessage4()
        let ead4 = try await responder.processMessage4(msg4)
        XCTAssertTrue(ead4.isEmpty, "No EAD expected in message_4")

        // -- Verify OSCORE contexts match (internal consistency) --
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

        // Verify OSCORE values are non-trivial
        XCTAssertEqual(iOSCORE.masterSecret.count, 16, "Master secret must be 16 bytes")
        XCTAssertEqual(iOSCORE.masterSalt.count, 8, "Master salt must be 8 bytes")
        XCTAssertFalse(iOSCORE.masterSecret.allSatisfy { $0 == 0 }, "Master secret must not be all zeros")

        // -- Key Update --
        try await initiator.keyUpdate(context: Self.keyUpdateContext)
        try await responder.keyUpdate(context: Self.keyUpdateContext)

        let iOSCOREUpdated = try await initiator.exportOSCORE()
        let rOSCOREUpdated = try await responder.exportOSCORE()

        // Both sides must still agree after key update
        XCTAssertEqual(iOSCOREUpdated.masterSecret, rOSCOREUpdated.masterSecret,
                       "Updated master secrets must be identical")
        XCTAssertEqual(iOSCOREUpdated.masterSalt, rOSCOREUpdated.masterSalt,
                       "Updated master salts must be identical")
        XCTAssertEqual(iOSCOREUpdated.senderId, rOSCOREUpdated.recipientId,
                       "Updated Initiator senderId must equal Responder recipientId")
        XCTAssertEqual(iOSCOREUpdated.recipientId, rOSCOREUpdated.senderId,
                       "Updated Initiator recipientId must equal Responder senderId")

        // Key update must actually change the values
        XCTAssertNotEqual(iOSCORE.masterSecret, iOSCOREUpdated.masterSecret,
                          "Key update must change the master secret")
        XCTAssertNotEqual(iOSCORE.masterSalt, iOSCOREUpdated.masterSalt,
                          "Key update must change the master salt")
    }

    // MARK: - Test: Handshake without message 4

    func testRFC9529HandshakeWithoutMessage4() async throws {
        // Same setup, but skip message 4 -- both sides should still derive
        // identical OSCORE contexts.

        let initiatorCredMgr = X509CredentialProvider(
            certificates: [Self.initiatorCert],
            privateKey: Self.initiatorKey,
            fetchFormat: .x5t
        )
        initiatorCredMgr.addTrustedCA(Self.trustedCA)
        initiatorCredMgr.addPeerCertificate(Self.responderCert)

        let initiatorCrypto = VectorsCryptoProvider(
            deterministicEphemeralKey: Self.initiatorEphemeralKey
        )

        let initiator = EdhocSession(
            connectionID: .integer(-14),
            methods: [.method0],
            cipherSuites: [.suite0],
            credentialProvider: initiatorCredMgr,
            cryptoProvider: initiatorCrypto
        )

        let responderCredMgr = X509CredentialProvider(
            certificates: [Self.responderCert],
            privateKey: Self.responderKey,
            fetchFormat: .x5t
        )
        responderCredMgr.addTrustedCA(Self.trustedCA)
        responderCredMgr.addPeerCertificate(Self.initiatorCert)

        let responderCrypto = VectorsCryptoProvider(
            deterministicEphemeralKey: Self.responderEphemeralKey
        )

        let responder = EdhocSession(
            connectionID: .byteString(Data([0x18])),
            methods: [.method0],
            cipherSuites: [.suite0],
            credentialProvider: responderCredMgr,
            cryptoProvider: responderCrypto
        )

        // Three-message handshake only (no message 4)
        let msg1 = try await initiator.composeMessage1()
        _ = try await responder.processMessage1(msg1)

        let msg2 = try await responder.composeMessage2()
        _ = try await initiator.processMessage2(msg2)

        let msg3 = try await initiator.composeMessage3()
        _ = try await responder.processMessage3(msg3)

        // OSCORE contexts should already be available and matching
        let iOSCORE = try await initiator.exportOSCORE()
        let rOSCORE = try await responder.exportOSCORE()

        XCTAssertEqual(iOSCORE.masterSecret, rOSCORE.masterSecret,
                       "Master secrets must be identical (3-msg handshake)")
        XCTAssertEqual(iOSCORE.masterSalt, rOSCORE.masterSalt,
                       "Master salts must be identical (3-msg handshake)")
        XCTAssertEqual(iOSCORE.senderId, rOSCORE.recipientId,
                       "Initiator senderId must equal Responder recipientId")
        XCTAssertEqual(iOSCORE.recipientId, rOSCORE.senderId,
                       "Initiator recipientId must equal Responder senderId")
    }

    // MARK: - Test: Connection IDs match expected byte representations

    func testConnectionIDByteRepresentation() throws {
        // Initiator connection ID: integer(-14) => CBOR encoding byte = 0x20 | 13 = 0x2d
        let iCID = EdhocConnectionID.integer(-14)
        XCTAssertEqual(iCID.toBytes(), Data([0x2d]),
                       "integer(-14) should encode to CBOR byte 0x2D")

        // Responder connection ID: byteString([0x18])
        let rCID = EdhocConnectionID.byteString(Data([0x18]))
        XCTAssertEqual(rCID.toBytes(), Data([0x18]),
                       "byteString([0x18]) should encode to [0x18]")
    }
}

// MARK: - Hex string helper

private extension Data {
    /// Create `Data` from a hex-encoded string. Non-hex characters are silently ignored.
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
