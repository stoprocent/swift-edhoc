import XCTest
@testable import SwiftEDHOC

final class BasicHandshakeTests: XCTestCase {

    // MARK: - Test data (P-256 / Suite 2)

    /// Self-signed CA root certificate (DER, P-256)
    private static let trustedCA = Data(hexString:
        "308201323081DAA003020102021478408C6EC18A1D452DAE70C726CB0192A6116DBB" +
        "300A06082A8648CE3D040302301A3118301606035504030C0F5468697320697320" +
        "434120526F6F74301E170D3234313031393138333635335A170D323531303139" +
        "3138333635335A301A3118301606035504030C0F5468697320697320434120526F" +
        "6F743059301306072A8648CE3D020106082A8648CE3D03010703420004B9348A" +
        "8A267EF52CFDC30109A29008A2D99F6B8F78BA9EAF5D51578C06134E78CB90" +
        "A073EDC2488A14174B4E2997C840C5DE7F8E35EB54A0DB6977E894D1B2CB30" +
        "0A06082A8648CE3D040302034700304402203B92BFEC770B0FA4E17F8F02A1" +
        "3CD945D914ED8123AC85C37C8C7BAA2BE3E0F102202CB2DC2EC295B5F4B7BB" +
        "631ED751179C145D6B6E081559AEA38CE215369E9C31"
    )

    /// Initiator leaf certificate (DER, P-256, signed by trustedCA)
    private static let initiatorCert = Data(hexString:
        "3082012E3081D4A003020102021453423D5145C767CDC29895C3DB590192A611EA50" +
        "300A06082A8648CE3D040302301A3118301606035504030C0F5468697320697320" +
        "434120526F6F74301E170D3234313031393138333732345A170D323531303139" +
        "3138333732345A30143112301006035504030C09696E69746961746F72305930" +
        "1306072A8648CE3D020106082A8648CE3D03010703420004EB0EF585F3992A16" +
        "53CF310BF0F0F8035267CDAB6989C8B02E7228FBD759EF6B56263259AADF08" +
        "7F9849E7B7651F74C3B4F144CCCF86BB6FE2FF0EF3AA5FB5DC300A06082A86" +
        "48CE3D0403020349003046022100D8C3AA7C98A730B3D4862EDAB4C1474FCD" +
        "9A17A9CA3FB078914A10978FE95CC40221009F5877DD4E2C635A04ED1F6F18" +
        "54C87B58521BDDFF533B1076F53D456739764C"
    )

    /// Initiator P-256 signing key (raw, 32 bytes)
    private static let initiatorKey = Data(hexString:
        "DC1FBB05B6B08360CE5B9EEA08EBFBFC6766A21340641863D4C8A3F68F096337"
    )

    /// Responder leaf certificate (DER, P-256, signed by trustedCA)
    private static let responderCert = Data(hexString:
        "3082012E3081D4A00302010202146648869E2608FC2E16D945C10E1F0192A6125CC0" +
        "300A06082A8648CE3D040302301A3118301606035504030C0F5468697320697320" +
        "434120526F6F74301E170D3234313031393138333735345A170D323531303139" +
        "3138333735345A30143112301006035504030C09726573706F6E646572305930" +
        "1306072A8648CE3D020106082A8648CE3D03010703420004161F76A7A106C9B7" +
        "9B7F651156B5B095E63A6101A39020F4E86DDACE61FB395E8AEF6CD9C444EE" +
        "9A43DBD62DAD44FF50FE4146247D3AFD28F60DBC01FBFC573C300A06082A86" +
        "48CE3D0403020349003046022100E8AD0926518CDB61E84D171700C7158FD0" +
        "E72D03A117D40133ECD10F8B9F42CE022100E7E69B4C79100B3F0792F010AE" +
        "11EE5DD2859C29EFC4DBCEFD41FA5CD4D3C3C9"
    )

    /// Responder P-256 signing key (raw, 32 bytes)
    private static let responderKey = Data(hexString:
        "EE6287116FE27CDC539629DC87E12BF8EAA2229E7773AA67BC4C0FBA96E7FBB2"
    )

    // MARK: - Test: Full handshake (Method 1, Suite 2)

    func testFullHandshakeMethod1Suite2() async throws {
        // -- Initiator setup --
        let initiatorCredMgr = X509CredentialProvider(
            certificates: [Self.initiatorCert],
            privateKey: Self.initiatorKey
        )
        initiatorCredMgr.addTrustedCA(Self.trustedCA)

        let initiatorCrypto = CryptoKitProvider()

        let initiator = EdhocSession(
            connectionID: .integer(10),
            methods: [.method1],
            cipherSuites: [.suite2],
            credentialProvider: initiatorCredMgr,
            cryptoProvider: initiatorCrypto
        )

        // -- Responder setup --
        let responderCredMgr = X509CredentialProvider(
            certificates: [Self.responderCert],
            privateKey: Self.responderKey
        )
        responderCredMgr.addTrustedCA(Self.trustedCA)

        let responderCrypto = CryptoKitProvider()

        let responder = EdhocSession(
            connectionID: .integer(20),
            methods: [.method2, .method0, .method1],
            cipherSuites: [.suite2],
            credentialProvider: responderCredMgr,
            cryptoProvider: responderCrypto
        )

        // -- Message 1 (Initiator -> Responder) with EAD --
        let ead1Payload = Data("Hello".utf8)
        let msg1 = try await initiator.composeMessage1(
            ead: [EdhocEAD(label: 1, value: ead1Payload)]
        )
        let ead1 = try await responder.processMessage1(msg1)
        XCTAssertEqual(ead1.count, 1, "Expected exactly one EAD item in message_1")
        XCTAssertEqual(ead1[0].label, 1)
        XCTAssertEqual(ead1[0].value, ead1Payload)

        // -- Message 2 (Responder -> Initiator) --
        let msg2 = try await responder.composeMessage2()
        let ead2 = try await initiator.processMessage2(msg2)
        XCTAssertTrue(ead2.isEmpty, "No EAD expected in message_2")

        // -- Message 3 (Initiator -> Responder) --
        let msg3 = try await initiator.composeMessage3()
        let ead3 = try await responder.processMessage3(msg3)
        XCTAssertTrue(ead3.isEmpty, "No EAD expected in message_3")

        // -- Verify OSCORE security contexts match --
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

        // -- Verify application key export --
        let iKey = try await initiator.exportKey(label: 40001, length: 32)
        let rKey = try await responder.exportKey(label: 40001, length: 32)
        XCTAssertEqual(iKey, rKey, "Exported application keys must match")
        XCTAssertEqual(iKey.count, 32)

        // -- Verify peer credentials are available --
        let initiatorPeerCreds = await initiator.peerCredentials
        XCTAssertNotNil(initiatorPeerCreds, "Initiator should have peer credentials after handshake")
        XCTAssertNotNil(initiatorPeerCreds?.publicKey,
                        "Peer credential should contain a public key")

        let responderPeerCreds = await responder.peerCredentials
        XCTAssertNotNil(responderPeerCreds, "Responder should have peer credentials after handshake")
        XCTAssertNotNil(responderPeerCreds?.publicKey,
                        "Peer credential should contain a public key")
    }

    // MARK: - Test: State machine errors

    func testComposeMessage1TwiceFails() async throws {
        let credMgr = X509CredentialProvider(
            certificates: [Self.initiatorCert],
            privateKey: Self.initiatorKey
        )
        credMgr.addTrustedCA(Self.trustedCA)

        let crypto = CryptoKitProvider()

        let session = EdhocSession(
            connectionID: .integer(10),
            methods: [.method1],
            cipherSuites: [.suite2],
            credentialProvider: credMgr,
            cryptoProvider: crypto
        )

        // First call should succeed
        _ = try await session.composeMessage1()

        // Second call should fail because state has moved past .start
        do {
            _ = try await session.composeMessage1()
            XCTFail("Expected composeMessage1 to throw on second invocation")
        } catch {
            // Verify it is an invalidState error
            guard case EdhocError.invalidState = error else {
                XCTFail("Expected EdhocError.invalidState, got \(error)")
                return
            }
        }
    }

    // MARK: - Test: AES-CCM encrypt/decrypt round-trip

    func testAESCCMRoundTrip() async throws {
        let crypto = CryptoKitProvider()
        let key = Data(repeating: 0x01, count: 16)
        let iv = Data(repeating: 0x02, count: 13)
        let aad = Data(repeating: 0x03, count: 8)
        let plaintext = Data([0x04, 0x05, 0x06, 0x07, 0x08])

        let encrypted = try crypto.encrypt(suite: .suite0, key: key, nonce: iv, aad: aad, plaintext: plaintext)

        // encrypted should be plaintext.count + tagLength(8) = 13 bytes
        XCTAssertEqual(encrypted.count, plaintext.count + 8)

        let decrypted = try crypto.decrypt(suite: .suite0, key: key, nonce: iv, aad: aad, ciphertext: encrypted)
        XCTAssertEqual(decrypted, plaintext)
    }

    // MARK: - Test: Full handshake with logging

    func testFullHandshakeMethod0Suite2WithLogging() async throws {
        var iLog: [(String, String)] = []
        var rLog: [(String, String)] = []

        // -- Initiator --
        let initiatorCredMgr = X509CredentialProvider(
            certificates: [Self.initiatorCert],
            privateKey: Self.initiatorKey
        )
        initiatorCredMgr.addTrustedCA(Self.trustedCA)

        let initiatorCrypto = CryptoKitProvider()

        let initiator = EdhocSession(
            connectionID: .integer(1),
            methods: [.method0],
            cipherSuites: [.suite2],
            credentialProvider: initiatorCredMgr,
            cryptoProvider: initiatorCrypto,
            logger: { name, data in iLog.append((name, data.map { String(format: "%02x", $0) }.joined())) }
        )

        // -- Responder --
        let responderCredMgr = X509CredentialProvider(
            certificates: [Self.responderCert],
            privateKey: Self.responderKey
        )
        responderCredMgr.addTrustedCA(Self.trustedCA)

        let responderCrypto = CryptoKitProvider()

        let responder = EdhocSession(
            connectionID: .integer(2),
            methods: [.method0],
            cipherSuites: [.suite2],
            credentialProvider: responderCredMgr,
            cryptoProvider: responderCrypto,
            logger: { name, data in rLog.append((name, data.map { String(format: "%02x", $0) }.joined())) }
        )

        // -- Three-message handshake --
        let msg1 = try await initiator.composeMessage1()
        _ = try await responder.processMessage1(msg1)

        let msg2 = try await responder.composeMessage2()

        // Compare TH values
        let iTH1 = iLog.first(where: { $0.0 == "TH_1" })?.1
        let rTH1 = rLog.first(where: { $0.0 == "TH_1" })?.1
        XCTAssertEqual(iTH1, rTH1, "TH_1 mismatch")

        _ = try await initiator.processMessage2(msg2)

        let rTH2 = rLog.first(where: { $0.0 == "TH_2" })?.1
        let iTH2 = iLog.first(where: { $0.0 == "TH_2" })?.1
        XCTAssertEqual(rTH2, iTH2, "TH_2 mismatch: R=\(rTH2 ?? "nil") I=\(iTH2 ?? "nil")")

        let rPRK2e = rLog.first(where: { $0.0 == "PRK_2e" })?.1
        let iPRK2e = iLog.first(where: { $0.0 == "PRK_2e" })?.1
        XCTAssertEqual(rPRK2e, iPRK2e, "PRK_2e mismatch")

        let rTH3 = rLog.first(where: { $0.0 == "TH_3" })?.1
        let iTH3 = iLog.first(where: { $0.0 == "TH_3" })?.1
        XCTAssertEqual(rTH3, iTH3, "TH_3 mismatch: R=\(rTH3 ?? "nil") I=\(iTH3 ?? "nil")")

        let rPRK3e2m = rLog.first(where: { $0.0 == "PRK_3e2m" })?.1
        let iPRK3e2m = iLog.first(where: { $0.0 == "PRK_3e2m" })?.1
        XCTAssertEqual(rPRK3e2m, iPRK3e2m, "PRK_3e2m mismatch")

        let msg3 = try await initiator.composeMessage3()
        _ = try await responder.processMessage3(msg3)
    }

    // MARK: - Test: Full handshake (Method 0, Suite 2 -- both signatures)

    func testFullHandshakeMethod0Suite2() async throws {
        // -- Initiator --
        let initiatorCredMgr = X509CredentialProvider(
            certificates: [Self.initiatorCert],
            privateKey: Self.initiatorKey
        )
        initiatorCredMgr.addTrustedCA(Self.trustedCA)

        let initiatorCrypto = CryptoKitProvider()

        let initiator = EdhocSession(
            connectionID: .integer(1),
            methods: [.method0],
            cipherSuites: [.suite2],
            credentialProvider: initiatorCredMgr,
            cryptoProvider: initiatorCrypto
        )

        // -- Responder --
        let responderCredMgr = X509CredentialProvider(
            certificates: [Self.responderCert],
            privateKey: Self.responderKey
        )
        responderCredMgr.addTrustedCA(Self.trustedCA)

        let responderCrypto = CryptoKitProvider()

        let responder = EdhocSession(
            connectionID: .integer(2),
            methods: [.method0],
            cipherSuites: [.suite2],
            credentialProvider: responderCredMgr,
            cryptoProvider: responderCrypto
        )

        // -- Three-message handshake --
        let msg1 = try await initiator.composeMessage1()
        _ = try await responder.processMessage1(msg1)

        let msg2 = try await responder.composeMessage2()
        _ = try await initiator.processMessage2(msg2)

        let msg3 = try await initiator.composeMessage3()
        _ = try await responder.processMessage3(msg3)

        // -- Verify derived contexts --
        let iOSCORE = try await initiator.exportOSCORE()
        let rOSCORE = try await responder.exportOSCORE()

        XCTAssertEqual(iOSCORE.masterSecret, rOSCORE.masterSecret)
        XCTAssertEqual(iOSCORE.masterSalt, rOSCORE.masterSalt)
        XCTAssertEqual(iOSCORE.senderId, rOSCORE.recipientId)
        XCTAssertEqual(iOSCORE.recipientId, rOSCORE.senderId)

        let iKey = try await initiator.exportKey(label: 99, length: 16)
        let rKey = try await responder.exportKey(label: 99, length: 16)
        XCTAssertEqual(iKey, rKey)
    }

    // MARK: - Test: Export before handshake fails

    func testExportBeforeHandshakeFails() async throws {
        let credMgr = X509CredentialProvider(
            certificates: [Self.initiatorCert],
            privateKey: Self.initiatorKey
        )
        let crypto = CryptoKitProvider()

        let session = EdhocSession(
            connectionID: .integer(10),
            methods: [.method0],
            cipherSuites: [.suite2],
            credentialProvider: credMgr,
            cryptoProvider: crypto
        )

        do {
            _ = try await session.exportOSCORE()
            XCTFail("Expected exportOSCORE to throw before handshake completes")
        } catch {
            guard case EdhocError.handshakeNotCompleted = error else {
                XCTFail("Expected EdhocError.handshakeNotCompleted, got \(error)")
                return
            }
        }

        do {
            _ = try await session.exportKey(label: 1, length: 16)
            XCTFail("Expected exportKey to throw before handshake completes")
        } catch {
            guard case EdhocError.handshakeNotCompleted = error else {
                XCTFail("Expected EdhocError.handshakeNotCompleted, got \(error)")
                return
            }
        }
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
