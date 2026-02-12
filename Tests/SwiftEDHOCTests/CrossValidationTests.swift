import XCTest
import CryptoKit
@testable import SwiftEDHOC

/// Cross-validation tests between TypeScript (node-edhoc) and Swift (SwiftEDHOC).
final class CrossValidationTests: XCTestCase {

    // MARK: - Shared test data (P-256 / Suite 2)

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

    private static let initiatorKey = Data(hexString:
        "DC1FBB05B6B08360CE5B9EEA08EBFBFC6766A21340641863D4C8A3F68F096337"
    )

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

    private static let responderKey = Data(hexString:
        "EE6287116FE27CDC539629DC87E12BF8EAA2229E7773AA67BC4C0FBA96E7FBB2"
    )

    // Fixed ephemeral P-256 DH keys (same as TS generate-vectors.ts)
    private static let initiatorEphemeral = Data(hexString:
        "3717F87F867BC4C8AB4A564093F1CC4A5414C24DB2ED0690CFAC651A02A04010"
    )
    private static let responderEphemeral = Data(hexString:
        "A7FFB1B45F2B570893B0E31C8AAF9C1C0E88C133E15CF2C0B89E5E3074B2D2A0"
    )

    private static let keyUpdateContext = Data(hexString: "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")

    // MARK: - TS-generated vectors for Method 3 (StaticDH/StaticDH, Suite 2)

    private static let m3_expectedTH1 = "3d54fea658b0305dd50cb93f326f9b8ba8a5a68ce5ac3ee36571d740eae68e01"
    private static let m3_expectedTH2 = "f3bacc9d43ea95fefa1a3547844158199655ff3e037440dbd83a9799d6f224dc"
    private static let m3_expectedPRK2e = "843986712609a510a1feaa57486ffa6225d75a0a2bfd3dde5430a740e4779432"
    private static let m3_expectedPRK3e2m = "adadb2eb0e9d6626a6b417dd2892d9913da85b8dc3bc04ee0bc3675203c6dd05"
    private static let m3_expectedMAC2 = "cad6bf389a35f360"
    private static let m3_expectedTH3 = "b51d18370cd62188e45c02f60d7bf11e28c7ce6440505d548a0ffc421903ecc9"
    private static let m3_expectedPRK4e3m = "980ea0be4c04fb6af82018404de816ac40d96c6d3cfc293fec387f429c6be552"
    private static let m3_expectedMAC3 = "ab344668b80d4125"
    private static let m3_expectedTH4 = "526e9be77beef021cdd7845fba7f6730ec34cb0b198a58b9e2722762a3f040b3"
    private static let m3_expectedMasterSecret = "8b5c8b7aa5b8a92e84dbdebc984fce09"
    private static let m3_expectedMasterSalt = "e530cbfc7783c8ca"
    private static let m3_expectedMasterSecretAfterUpdate = "24feba33ff32da1a70cf9fd7ac94f03c"
    private static let m3_expectedMasterSaltAfterUpdate = "0ca64d81411671b2"

    // MARK: - TS-generated vectors for Method 2 (StaticDH/Sig, Suite 2)

    private static let m2_expectedTH1 = "8656bb353c0f62546a8ea3c0fd13a59d7af2ef94deaeda10079c7a02d7159ff4"
    private static let m2_expectedTH2 = "a5168d16f33ad812d6b5ba55f8a8400cf6bb624d01a45155fbe612e078b8bc3d"
    private static let m2_expectedPRK2e = "fbe3873abe6d8d24fb2324387fdd04eeccd1ea64fd49abdc98804bd23efcbf18"
    private static let m2_expectedPRK3e2m = "fbe3873abe6d8d24fb2324387fdd04eeccd1ea64fd49abdc98804bd23efcbf18"
    private static let m2_expectedMAC2 = "7b815c4fe241ac2492d95d548150e11fc874006398e2c901a91d62c6dd726ec8"

    // MARK: - TS-generated vectors for Method 3 (StaticDH/StaticDH, Suite 24)

    private static let s24_initiatorStaticPrivate = Data(hexString:
        "fc91fd858a716e23dd986c099dad2ca3e38b88b4f8ff5f55a5c832f4f0c5f53d11ac1306d529a0ae7572ee08f825f9a0"
    )
    private static let s24_initiatorStaticPublic = Data(hexString:
        "b07bfe1fedbfaaee13bfce023b20a6ca8aede6aed276a712a227b3485685f4c8cecb645392a388a006eeb26b6dd36ebd"
    )
    private static let s24_responderStaticPrivate = Data(hexString:
        "c999da242b76987acf88528682e5f357c0dfab64858a93628b3d5c25a5edc137c4191f27a121410311f1d921cf553d45"
    )
    private static let s24_responderStaticPublic = Data(hexString:
        "50ea21a9df73bd6eec3822cdea696bca27dea1eb451c4a14f58cb52c0c8ad2047d6efaa5d33a6340b7f420a0fbeae713"
    )
    private static let s24_initiatorEphemeral = Data(hexString:
        "ff7bcadbf9909f1ca51ace28a9963bc203b0ccb65fc220814c31640476bc424858e6d8977417f07777208b09e37bde1d"
    )
    private static let s24_responderEphemeral = Data(hexString:
        "ac398da13bd18641523961b516e9ef98f7fcaa73e7ad35dcb539901254385d600df8be8a7d31ec8628ece9b78346ae5e"
    )
    private static let s24_initiatorCCS = Data(hexString: "a20169737569746532342d69022b")
    private static let s24_responderCCS = Data(hexString: "a20169737569746532342d720232")
    private static let s24_expectedTH1 = "acc5df1fe2a637623d8c6c5dfade86ee9f7b9bddf6e4d48ab8ed6bb27302d8ae990eb338e630d3d28b405b4351f82882"
    private static let s24_expectedTH2 = "2814b49151bffbcc8a0f04e7e5f01f5aced533dbf59ab55a36c74f2e781dbce4155de360873eafe08bac6b92e817d838"
    private static let s24_expectedPRK2e = "4a17c50144980cac36fed02e6b2c07babf006c4915c8af96a6b0c02f88f7cb94e131ba96e6065c32551ac97b0a89a0e3"
    private static let s24_expectedPRK3e2m = "c38c282075a7c49cc2ffd6fe726f7e0fb0705ccb9879ce4f395696f2810bbd26dd7045e25f790838b16959ef65fab757"
    private static let s24_expectedMAC2 = "879c256594b4db11ca5f94188f802ab9"
    private static let s24_expectedTH3 = "72df9ae885935ac41c1f68d4e89934cd8d8fa037aee513aee0cc04faba95792f92d7be00dc9790c30a143641c67d9009"
    private static let s24_expectedPRK4e3m = "12bf142a062859298f6cb005205aace4136986c1337292e81a330d07b4f0a8a4f8b3cda2fa5d8c633d2ae8faa5fdc986"
    private static let s24_expectedMAC3 = "5e919d51f046ea294ca3a048075d1b85"
    private static let s24_expectedTH4 = "d3c8df19bdbedeee8bfa8210043a29e086e0c09aa372aa7995585be112aac77aa624d02903752a743b3b1c13b1e01822"
    private static let s24_expectedMasterSecret = "b599e3b23e8d47d0bee0b79e60640ba8"
    private static let s24_expectedMasterSalt = "06328515e03fde29"
    private static let s24_expectedMasterSecretAfterUpdate = "d4d9afa1ae714b5d8a343164c4b75608"
    private static let s24_expectedMasterSaltAfterUpdate = "abfc87f0e5643117"

    // MARK: - Deterministic crypto provider

    private func makeProvider(ephemeral: Data) -> VectorsCryptoProvider {
        VectorsCryptoProvider(deterministicEphemeralKey: ephemeral)
    }

    // MARK: - Test: Method 3 cross-validation (fully deterministic)

    func testMethod3Suite2CrossValidation() async throws {
        let iCredMgr = X509CredentialProvider(
            certificates: [Self.initiatorCert], privateKey: Self.initiatorKey)
        iCredMgr.addTrustedCA(Self.trustedCA)

        let iCrypto = makeProvider(ephemeral: Self.initiatorEphemeral)

        var iLog: [(String, String)] = []
        var rLog: [(String, String)] = []

        let initiator = EdhocSession(
            connectionID: .integer(10),
            methods: [.method3],
            cipherSuites: [.suite2],
            credentialProvider: iCredMgr,
            cryptoProvider: iCrypto,
            logger: { name, data in iLog.append((name, data.map { String(format: "%02x", $0) }.joined())) }
        )

        let rCredMgr = X509CredentialProvider(
            certificates: [Self.responderCert], privateKey: Self.responderKey)
        rCredMgr.addTrustedCA(Self.trustedCA)

        let rCrypto = makeProvider(ephemeral: Self.responderEphemeral)

        let responder = EdhocSession(
            connectionID: .integer(20),
            methods: [.method3],
            cipherSuites: [.suite2],
            credentialProvider: rCredMgr,
            cryptoProvider: rCrypto,
            logger: { name, data in rLog.append((name, data.map { String(format: "%02x", $0) }.joined())) }
        )

        // Three-message handshake
        let msg1 = try await initiator.composeMessage1()
        _ = try await responder.processMessage1(msg1)

        let msg2 = try await responder.composeMessage2()
        _ = try await initiator.processMessage2(msg2)

        let msg3 = try await initiator.composeMessage3()
        _ = try await responder.processMessage3(msg3)

        // Verify ALL intermediate values match TS vectors exactly
        func iVal(_ key: String) -> String? { iLog.first(where: { $0.0 == key })?.1 }
        func rVal(_ key: String) -> String? { rLog.first(where: { $0.0 == key })?.1 }

        XCTAssertEqual(iVal("TH_1"), Self.m3_expectedTH1, "TH_1 must match TS vector")
        XCTAssertEqual(iVal("TH_2"), Self.m3_expectedTH2, "TH_2 must match TS vector")
        XCTAssertEqual(iVal("PRK_2e"), Self.m3_expectedPRK2e, "PRK_2e must match TS vector")
        XCTAssertEqual(iVal("PRK_3e2m"), Self.m3_expectedPRK3e2m, "PRK_3e2m must match TS vector")
        XCTAssertEqual(rVal("MAC_2"), Self.m3_expectedMAC2, "MAC_2 must match TS vector")
        XCTAssertEqual(iVal("TH_3") ?? rVal("TH_3"), Self.m3_expectedTH3, "TH_3 must match TS vector")
        XCTAssertEqual(iVal("PRK_4e3m"), Self.m3_expectedPRK4e3m, "PRK_4e3m must match TS vector")
        XCTAssertEqual(iVal("MAC_3"), Self.m3_expectedMAC3, "MAC_3 must match TS vector")
        XCTAssertEqual(iVal("TH_4"), Self.m3_expectedTH4, "TH_4 must match TS vector")

        // OSCORE must match TS vectors exactly (Method 3 = fully deterministic)
        let iOSCORE = try await initiator.exportOSCORE()
        let rOSCORE = try await responder.exportOSCORE()

        XCTAssertEqual(iOSCORE.masterSecret, rOSCORE.masterSecret)
        XCTAssertEqual(iOSCORE.masterSalt, rOSCORE.masterSalt)
        XCTAssertEqual(hex(iOSCORE.masterSecret), Self.m3_expectedMasterSecret,
                       "Master secret must match TS vector")
        XCTAssertEqual(hex(iOSCORE.masterSalt), Self.m3_expectedMasterSalt,
                       "Master salt must match TS vector")

        // Key update
        try await initiator.keyUpdate(context: Self.keyUpdateContext)
        try await responder.keyUpdate(context: Self.keyUpdateContext)

        let iUpdated = try await initiator.exportOSCORE()
        let rUpdated = try await responder.exportOSCORE()

        XCTAssertEqual(iUpdated.masterSecret, rUpdated.masterSecret)
        XCTAssertEqual(iUpdated.masterSalt, rUpdated.masterSalt)
        XCTAssertEqual(hex(iUpdated.masterSecret), Self.m3_expectedMasterSecretAfterUpdate,
                       "Updated master secret must match TS vector")
        XCTAssertEqual(hex(iUpdated.masterSalt), Self.m3_expectedMasterSaltAfterUpdate,
                       "Updated master salt must match TS vector")
    }

    // MARK: - Test: Method 2 cross-validation (deterministic up to signature)

    func testMethod2Suite2CrossValidation() async throws {
        let iCredMgr = X509CredentialProvider(
            certificates: [Self.initiatorCert], privateKey: Self.initiatorKey)
        iCredMgr.addTrustedCA(Self.trustedCA)

        let iCrypto = makeProvider(ephemeral: Self.initiatorEphemeral)

        var iLog: [(String, String)] = []
        var rLog: [(String, String)] = []

        let initiator = EdhocSession(
            connectionID: .integer(10),
            methods: [.method2],
            cipherSuites: [.suite2],
            credentialProvider: iCredMgr,
            cryptoProvider: iCrypto,
            logger: { name, data in iLog.append((name, data.map { String(format: "%02x", $0) }.joined())) }
        )

        let rCredMgr = X509CredentialProvider(
            certificates: [Self.responderCert], privateKey: Self.responderKey)
        rCredMgr.addTrustedCA(Self.trustedCA)

        let rCrypto = makeProvider(ephemeral: Self.responderEphemeral)

        let responder = EdhocSession(
            connectionID: .integer(20),
            methods: [.method2],
            cipherSuites: [.suite2],
            credentialProvider: rCredMgr,
            cryptoProvider: rCrypto,
            logger: { name, data in rLog.append((name, data.map { String(format: "%02x", $0) }.joined())) }
        )

        // Three-message handshake
        let msg1 = try await initiator.composeMessage1()
        _ = try await responder.processMessage1(msg1)

        let msg2 = try await responder.composeMessage2()
        _ = try await initiator.processMessage2(msg2)

        let msg3 = try await initiator.composeMessage3()
        _ = try await responder.processMessage3(msg3)

        // Verify deterministic intermediate values (before first signature)
        func iVal(_ key: String) -> String? { iLog.first(where: { $0.0 == key })?.1 }
        func rVal(_ key: String) -> String? { rLog.first(where: { $0.0 == key })?.1 }

        XCTAssertEqual(iVal("TH_1"), Self.m2_expectedTH1, "TH_1 must match TS vector")
        XCTAssertEqual(iVal("TH_2"), Self.m2_expectedTH2, "TH_2 must match TS vector")
        XCTAssertEqual(iVal("PRK_2e"), Self.m2_expectedPRK2e, "PRK_2e must match TS vector")
        XCTAssertEqual(iVal("PRK_3e2m"), Self.m2_expectedPRK3e2m, "PRK_3e2m must match TS vector")
        XCTAssertEqual(rVal("MAC_2"), Self.m2_expectedMAC2, "MAC_2 must match TS vector")

        // Both sides must agree on OSCORE
        let iOSCORE = try await initiator.exportOSCORE()
        let rOSCORE = try await responder.exportOSCORE()

        XCTAssertEqual(iOSCORE.masterSecret, rOSCORE.masterSecret,
                       "Method 2: Master secrets must be identical")
        XCTAssertEqual(iOSCORE.masterSalt, rOSCORE.masterSalt,
                       "Method 2: Master salts must be identical")
        XCTAssertEqual(iOSCORE.senderId, rOSCORE.recipientId)
        XCTAssertEqual(iOSCORE.recipientId, rOSCORE.senderId)
    }

    // MARK: - Test: Method 3 cross-validation for Suite 24 (fully deterministic)

    func testMethod3Suite24CrossValidation() async throws {
        var iCredMgr = CCSCredentialProvider()
        iCredMgr.addOwnCredential(
            kid: .integer(-12),
            ccsBytes: Self.s24_initiatorCCS,
            publicKey: Self.s24_initiatorStaticPublic,
            privateKey: Self.s24_initiatorStaticPrivate
        )
        iCredMgr.addPeerCredential(
            kid: .integer(-19),
            ccsBytes: Self.s24_responderCCS,
            publicKey: Self.s24_responderStaticPublic
        )

        var rCredMgr = CCSCredentialProvider()
        rCredMgr.addOwnCredential(
            kid: .integer(-19),
            ccsBytes: Self.s24_responderCCS,
            publicKey: Self.s24_responderStaticPublic,
            privateKey: Self.s24_responderStaticPrivate
        )
        rCredMgr.addPeerCredential(
            kid: .integer(-12),
            ccsBytes: Self.s24_initiatorCCS,
            publicKey: Self.s24_initiatorStaticPublic
        )

        let iCrypto = makeProvider(ephemeral: Self.s24_initiatorEphemeral)
        let rCrypto = makeProvider(ephemeral: Self.s24_responderEphemeral)

        var iLog: [(String, String)] = []
        var rLog: [(String, String)] = []

        let initiator = EdhocSession(
            connectionID: .integer(10),
            methods: [.method3],
            cipherSuites: [.suite24],
            credentialProvider: iCredMgr,
            cryptoProvider: iCrypto,
            logger: { name, data in iLog.append((name, data.map { String(format: "%02x", $0) }.joined())) }
        )
        let responder = EdhocSession(
            connectionID: .integer(20),
            methods: [.method3],
            cipherSuites: [.suite24],
            credentialProvider: rCredMgr,
            cryptoProvider: rCrypto,
            logger: { name, data in rLog.append((name, data.map { String(format: "%02x", $0) }.joined())) }
        )

        let msg1 = try await initiator.composeMessage1()
        _ = try await responder.processMessage1(msg1)
        let msg2 = try await responder.composeMessage2()
        _ = try await initiator.processMessage2(msg2)
        let msg3 = try await initiator.composeMessage3()
        _ = try await responder.processMessage3(msg3)

        func iVal(_ key: String) -> String? { iLog.first(where: { $0.0 == key })?.1 }
        func rVal(_ key: String) -> String? { rLog.first(where: { $0.0 == key })?.1 }

        XCTAssertEqual(iVal("TH_1"), Self.s24_expectedTH1)
        XCTAssertEqual(iVal("TH_2"), Self.s24_expectedTH2)
        XCTAssertEqual(iVal("PRK_2e"), Self.s24_expectedPRK2e)
        XCTAssertEqual(iVal("PRK_3e2m"), Self.s24_expectedPRK3e2m)
        XCTAssertEqual(rVal("MAC_2"), Self.s24_expectedMAC2)
        XCTAssertEqual(iVal("TH_3") ?? rVal("TH_3"), Self.s24_expectedTH3)
        XCTAssertEqual(iVal("PRK_4e3m"), Self.s24_expectedPRK4e3m)
        XCTAssertEqual(iVal("MAC_3"), Self.s24_expectedMAC3)
        XCTAssertEqual(iVal("TH_4"), Self.s24_expectedTH4)

        let iOSCORE = try await initiator.exportOSCORE()
        let rOSCORE = try await responder.exportOSCORE()
        XCTAssertEqual(iOSCORE.masterSecret, rOSCORE.masterSecret)
        XCTAssertEqual(iOSCORE.masterSalt, rOSCORE.masterSalt)
        XCTAssertEqual(hex(iOSCORE.masterSecret), Self.s24_expectedMasterSecret)
        XCTAssertEqual(hex(iOSCORE.masterSalt), Self.s24_expectedMasterSalt)

        try await initiator.keyUpdate(context: Self.keyUpdateContext)
        try await responder.keyUpdate(context: Self.keyUpdateContext)
        let iUpdated = try await initiator.exportOSCORE()
        let rUpdated = try await responder.exportOSCORE()
        XCTAssertEqual(iUpdated.masterSecret, rUpdated.masterSecret)
        XCTAssertEqual(iUpdated.masterSalt, rUpdated.masterSalt)
        XCTAssertEqual(hex(iUpdated.masterSecret), Self.s24_expectedMasterSecretAfterUpdate)
        XCTAssertEqual(hex(iUpdated.masterSalt), Self.s24_expectedMasterSaltAfterUpdate)
    }

    // MARK: - Test: Generate Swift vectors for TypeScript consumption

    func testGenerateSwiftVectorsForTS() async throws {
        // Method 3 (StaticDH / StaticDH)
        let m3iCredMgr = X509CredentialProvider(
            certificates: [Self.initiatorCert], privateKey: Self.initiatorKey)
        m3iCredMgr.addTrustedCA(Self.trustedCA)

        let m3iCrypto = makeProvider(ephemeral: Self.initiatorEphemeral)

        var m3iLog: [(String, String)] = []
        var m3rLog: [(String, String)] = []

        let m3Initiator = EdhocSession(
            connectionID: .integer(10),
            methods: [.method3],
            cipherSuites: [.suite2],
            credentialProvider: m3iCredMgr,
            cryptoProvider: m3iCrypto,
            logger: { name, data in m3iLog.append((name, data.map { String(format: "%02x", $0) }.joined())) }
        )

        let m3rCredMgr = X509CredentialProvider(
            certificates: [Self.responderCert], privateKey: Self.responderKey)
        m3rCredMgr.addTrustedCA(Self.trustedCA)

        let m3rCrypto = makeProvider(ephemeral: Self.responderEphemeral)

        let m3Responder = EdhocSession(
            connectionID: .integer(20),
            methods: [.method3],
            cipherSuites: [.suite2],
            credentialProvider: m3rCredMgr,
            cryptoProvider: m3rCrypto,
            logger: { name, data in m3rLog.append((name, data.map { String(format: "%02x", $0) }.joined())) }
        )

        let m3msg1 = try await m3Initiator.composeMessage1()
        _ = try await m3Responder.processMessage1(m3msg1)

        let m3msg2 = try await m3Responder.composeMessage2()
        _ = try await m3Initiator.processMessage2(m3msg2)

        let m3msg3 = try await m3Initiator.composeMessage3()
        _ = try await m3Responder.processMessage3(m3msg3)

        let m3iOSCORE = try await m3Initiator.exportOSCORE()
        try await m3Initiator.keyUpdate(context: Self.keyUpdateContext)
        let m3iUpdated = try await m3Initiator.exportOSCORE()

        func m3Val(_ key: String) -> String {
            m3iLog.first(where: { $0.0 == key })?.1
                ?? m3rLog.first(where: { $0.0 == key })?.1
                ?? "<missing>"
        }

        let m3IntermediateKeys = [
            "message_1", "TH_1", "G_Y", "G_XY", "TH_2", "PRK_2e",
            "PRK_3e2m", "MAC_2", "Signature_or_MAC_2",
            "PLAINTEXT_2", "CIPHERTEXT_2", "TH_3", "message_2",
            "PRK_4e3m", "MAC_3", "Signature_or_MAC_3",
            "PLAINTEXT_3", "CIPHERTEXT_3", "TH_4", "message_3"
        ]

        print("=== BEGIN SWIFT VECTORS ===")
        for key in m3IntermediateKeys {
            print("SWIFT_M3_\(key): \(m3Val(key))")
        }
        print("SWIFT_M3_masterSecret: \(hex(m3iOSCORE.masterSecret))")
        print("SWIFT_M3_masterSalt: \(hex(m3iOSCORE.masterSalt))")
        print("SWIFT_M3_senderId: \(hex(m3iOSCORE.senderId))")
        print("SWIFT_M3_recipientId: \(hex(m3iOSCORE.recipientId))")
        print("SWIFT_M3_masterSecretAfterUpdate: \(hex(m3iUpdated.masterSecret))")
        print("SWIFT_M3_masterSaltAfterUpdate: \(hex(m3iUpdated.masterSalt))")

        // Method 2 (StaticDH / Sig)
        let m2iCredMgr = X509CredentialProvider(
            certificates: [Self.initiatorCert], privateKey: Self.initiatorKey)
        m2iCredMgr.addTrustedCA(Self.trustedCA)

        let m2iCrypto = makeProvider(ephemeral: Self.initiatorEphemeral)

        var m2iLog: [(String, String)] = []
        var m2rLog: [(String, String)] = []

        let m2Initiator = EdhocSession(
            connectionID: .integer(10),
            methods: [.method2],
            cipherSuites: [.suite2],
            credentialProvider: m2iCredMgr,
            cryptoProvider: m2iCrypto,
            logger: { name, data in m2iLog.append((name, data.map { String(format: "%02x", $0) }.joined())) }
        )

        let m2rCredMgr = X509CredentialProvider(
            certificates: [Self.responderCert], privateKey: Self.responderKey)
        m2rCredMgr.addTrustedCA(Self.trustedCA)

        let m2rCrypto = makeProvider(ephemeral: Self.responderEphemeral)

        let m2Responder = EdhocSession(
            connectionID: .integer(20),
            methods: [.method2],
            cipherSuites: [.suite2],
            credentialProvider: m2rCredMgr,
            cryptoProvider: m2rCrypto,
            logger: { name, data in m2rLog.append((name, data.map { String(format: "%02x", $0) }.joined())) }
        )

        let m2msg1 = try await m2Initiator.composeMessage1()
        _ = try await m2Responder.processMessage1(m2msg1)

        let m2msg2 = try await m2Responder.composeMessage2()
        _ = try await m2Initiator.processMessage2(m2msg2)

        let m2msg3 = try await m2Initiator.composeMessage3()
        _ = try await m2Responder.processMessage3(m2msg3)

        let m2iOSCORE = try await m2Initiator.exportOSCORE()
        try await m2Initiator.keyUpdate(context: Self.keyUpdateContext)
        let m2iUpdated = try await m2Initiator.exportOSCORE()

        func m2Val(_ key: String) -> String {
            m2iLog.first(where: { $0.0 == key })?.1
                ?? m2rLog.first(where: { $0.0 == key })?.1
                ?? "<missing>"
        }

        let m2IntermediateKeys = [
            "message_1", "TH_1", "G_Y", "G_XY", "TH_2", "PRK_2e",
            "PRK_3e2m", "MAC_2", "Signature_or_MAC_2",
            "PLAINTEXT_2", "CIPHERTEXT_2", "TH_3", "message_2",
            "PRK_4e3m", "MAC_3", "Signature_or_MAC_3",
            "PLAINTEXT_3", "CIPHERTEXT_3", "TH_4", "message_3"
        ]

        for key in m2IntermediateKeys {
            print("SWIFT_M2_\(key): \(m2Val(key))")
        }
        print("SWIFT_M2_masterSecret: \(hex(m2iOSCORE.masterSecret))")
        print("SWIFT_M2_masterSalt: \(hex(m2iOSCORE.masterSalt))")
        print("SWIFT_M2_senderId: \(hex(m2iOSCORE.senderId))")
        print("SWIFT_M2_recipientId: \(hex(m2iOSCORE.recipientId))")
        print("SWIFT_M2_masterSecretAfterUpdate: \(hex(m2iUpdated.masterSecret))")
        print("SWIFT_M2_masterSaltAfterUpdate: \(hex(m2iUpdated.masterSalt))")
        print("=== END SWIFT VECTORS ===")
    }

    // MARK: - Helpers

    private func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - VectorsCryptoProvider

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

// MARK: - Hex string helper

private extension Data {
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
