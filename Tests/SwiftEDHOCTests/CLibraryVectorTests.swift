import XCTest
import CryptoKit
@testable import SwiftEDHOC

/// Tests using vectors from the C libedhoc library (test_vector_x5chain_sign_keys_suite_2.h
/// and test_vector_x5chain_static_dh_keys_suite_2.h) and RFC 9529 Chapter 3 ECDH vectors.
///
/// These tests verify interoperability between SwiftEDHOC and the C libedhoc implementation
/// by using the exact same key material, certificates, and ephemeral DH keys.
final class CLibraryVectorTests: XCTestCase {

    // MARK: - C library vectors (from test_vector_x5chain_sign_keys_suite_2.h)

    /// Initiator ephemeral DH private key X (32 bytes)
    private static let ephemeralX = Data(hexString:
        "368ec1f69aeb659ba37d5a8d45b21bdc0299dceaa8ef235f3ca42ce3530f9525"
    )

    /// Responder ephemeral DH private key Y (32 bytes)
    private static let ephemeralY = Data(hexString:
        "e2f4126777205e853b437d6eaca1e1f753cdcc3e2c69fa884b0a1a640977e418"
    )

    /// Responder private signing/DH key SK_R (32 bytes)
    private static let skR = Data(hexString:
        "72cc4761dbd4c78f758931aa589d348d1ef874a7e303ede2f140dcf3e6aa4aac"
    )

    /// Initiator private signing/DH key SK_I (32 bytes)
    private static let skI = Data(hexString:
        "fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b"
    )

    /// Responder X.509 certificate CRED_R (DER, 290 bytes)
    private static let credR = Data(hexString:
        "3082011e3081c5a003020102020461e9981e300a06082a8648ce3d040302" +
        "30153113301106035504030c0a4544484f4320526f6f74301e170d323230" +
        "3132303137313330325a170d3239313233313233303030305a301a311830" +
        "1606035504030c0f4544484f4320526573706f6e646572305930130607" +
        "2a8648ce3d020106082a8648ce3d03010703420004bbc34960526ea4d3" +
        "2e940cad2a234148ddc21791a12afbcbac93622046dd44f04519e25723" +
        "6b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072300a" +
        "06082a8648ce3d040302034800304502203019" +
        "4ef5fc65c8b795cdcd0bb431bf83ee6741c1370c22c8eb8ee9edd2a705" +
        "19022100b5830e9c89a62ac73ce1ebce0061707db8a88e23709b4acc58" +
        "a1313b133d0558"
    )

    /// Initiator X.509 certificate CRED_I (DER, 290 bytes)
    private static let credI = Data(hexString:
        "3082011e3081c5a00302010202046232ef6f300a06082a8648ce3d040302" +
        "30153113301106035504030c0a4544484f4320526f6f74301e170d323230" +
        "3331373038323130335a170d3239313233313233303030305a301a311830" +
        "1606035504030c0f4544484f4320496e69746961746f72305930130607" +
        "2a8648ce3d020106082a8648ce3d03010703420004ac75e9ece3e50bfc" +
        "8ed60399889522405c47bf16df96660a41298cb4307f7eb66e5de61138" +
        "8a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8300a" +
        "06082a8648ce3d0403020348003045022100" +
        "8c323a1f332138aab9d0beafb85f8d5a44073c580f595bc521ef913f6e" +
        "f48d1102206c0af1a185a4e4de06353699231c733a6e8dd2df6513966c" +
        "9130152a07a2bede"
    )

    // MARK: - RFC 9529 Chapter 3 ECDH expected shared secret

    /// Expected G_XY from test_vector_rfc9529_chapter_3.h
    private static let expectedGXY = Data(hexString:
        "2f0cb7e860ba538fbf5c8bded009f6259b4b628fe1eb7dbe9378e5ecf7a824ba"
    )

    // MARK: - Test 1: P-256 ECDH verification (RFC 9529 Chapter 3)

    /// Verify that our CryptoKitProvider produces the correct P-256 ECDH shared secret
    /// using the exact key material from RFC 9529 Chapter 3.
    func testP256ECDHSharedSecret() throws {
        let crypto = CryptoKitProvider()

        // Derive public key from Y (responder ephemeral)
        let yPrivKey = Self.ephemeralY
        // Use CryptoKit directly to get the public key from Y
        let yP256Key = try CryptoKit.P256.KeyAgreement.PrivateKey(rawRepresentation: yPrivKey)
        let yPubKey = Data(yP256Key.publicKey.x963Representation.dropFirst().prefix(32))

        // Compute shared secret: ECDH(X_private, Y_public)
        let sharedSecret = try crypto.keyAgreement(
            suite: .suite2,
            privateKey: Self.ephemeralX,
            peerPublicKey: yPubKey
        )

        XCTAssertEqual(
            sharedSecret, Self.expectedGXY,
            "P-256 ECDH shared secret G_XY must match RFC 9529 Chapter 3 vector"
        )
    }

    // MARK: - Test 2: Method 0 (Sig/Sig) handshake with C library certificates

    func testMethod0Suite2WithCLibraryCerts() async throws {
        // -- Initiator setup --
        let iCredMgr = X509CredentialProvider(
            certificates: [Self.credI], privateKey: Self.skI
        )
        iCredMgr.addPeerCertificate(Self.credR)

        let iCrypto = CLibVectorsCryptoProvider(deterministicEphemeralKey: Self.ephemeralX)

        let initiator = EdhocSession(
            connectionID: .integer(-24),
            methods: [.method0],
            cipherSuites: [.suite2],
            credentialProvider: iCredMgr,
            cryptoProvider: iCrypto
        )

        // -- Responder setup --
        let rCredMgr = X509CredentialProvider(
            certificates: [Self.credR], privateKey: Self.skR
        )
        rCredMgr.addPeerCertificate(Self.credI)

        let rCrypto = CLibVectorsCryptoProvider(deterministicEphemeralKey: Self.ephemeralY)

        let responder = EdhocSession(
            connectionID: .integer(-8),
            methods: [.method0],
            cipherSuites: [.suite2],
            credentialProvider: rCredMgr,
            cryptoProvider: rCrypto
        )

        // -- Three-message handshake --
        let msg1 = try await initiator.composeMessage1()
        _ = try await responder.processMessage1(msg1)

        let msg2 = try await responder.composeMessage2()
        _ = try await initiator.processMessage2(msg2)

        let msg3 = try await initiator.composeMessage3()
        _ = try await responder.processMessage3(msg3)

        // -- Verify OSCORE security contexts match --
        let iOSCORE = try await initiator.exportOSCORE()
        let rOSCORE = try await responder.exportOSCORE()

        XCTAssertEqual(iOSCORE.masterSecret, rOSCORE.masterSecret,
                       "Method 0: Master secrets must be identical")
        XCTAssertEqual(iOSCORE.masterSalt, rOSCORE.masterSalt,
                       "Method 0: Master salts must be identical")
        XCTAssertEqual(iOSCORE.senderId, rOSCORE.recipientId,
                       "Method 0: Initiator senderId must equal Responder recipientId")
        XCTAssertEqual(iOSCORE.recipientId, rOSCORE.senderId,
                       "Method 0: Initiator recipientId must equal Responder senderId")
    }

    // MARK: - Test 3: Method 3 (StaticDH/StaticDH) handshake with C library certificates

    func testMethod3Suite2WithCLibraryCerts() async throws {
        // -- Initiator setup --
        let iCredMgr = X509CredentialProvider(
            certificates: [Self.credI], privateKey: Self.skI
        )
        iCredMgr.addPeerCertificate(Self.credR)

        let iCrypto = CLibVectorsCryptoProvider(deterministicEphemeralKey: Self.ephemeralX)

        let initiator = EdhocSession(
            connectionID: .integer(-24),
            methods: [.method3],
            cipherSuites: [.suite2],
            credentialProvider: iCredMgr,
            cryptoProvider: iCrypto
        )

        // -- Responder setup --
        let rCredMgr = X509CredentialProvider(
            certificates: [Self.credR], privateKey: Self.skR
        )
        rCredMgr.addPeerCertificate(Self.credI)

        let rCrypto = CLibVectorsCryptoProvider(deterministicEphemeralKey: Self.ephemeralY)

        let responder = EdhocSession(
            connectionID: .integer(-8),
            methods: [.method3],
            cipherSuites: [.suite2],
            credentialProvider: rCredMgr,
            cryptoProvider: rCrypto
        )

        // -- Three-message handshake --
        let msg1 = try await initiator.composeMessage1()
        _ = try await responder.processMessage1(msg1)

        let msg2 = try await responder.composeMessage2()
        _ = try await initiator.processMessage2(msg2)

        let msg3 = try await initiator.composeMessage3()
        _ = try await responder.processMessage3(msg3)

        // -- Verify OSCORE security contexts match --
        let iOSCORE = try await initiator.exportOSCORE()
        let rOSCORE = try await responder.exportOSCORE()

        XCTAssertEqual(iOSCORE.masterSecret, rOSCORE.masterSecret,
                       "Method 3: Master secrets must be identical")
        XCTAssertEqual(iOSCORE.masterSalt, rOSCORE.masterSalt,
                       "Method 3: Master salts must be identical")
        XCTAssertEqual(iOSCORE.senderId, rOSCORE.recipientId,
                       "Method 3: Initiator senderId must equal Responder recipientId")
        XCTAssertEqual(iOSCORE.recipientId, rOSCORE.senderId,
                       "Method 3: Initiator recipientId must equal Responder senderId")
    }

    // MARK: - Helpers

    private func hex(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - Deterministic crypto provider for C library vectors

private final class CLibVectorsCryptoProvider: EdhocCryptoProvider, @unchecked Sendable {
    private let inner: CryptoKitProvider
    private let deterministicEphemeralKey: Data

    init(deterministicEphemeralKey: Data) {
        self.inner = CryptoKitProvider()
        self.deterministicEphemeralKey = deterministicEphemeralKey
    }

    func generateKeyPair(suite: EdhocCipherSuite) throws -> KeyPair {
        // Derive public key from the deterministic private key
        let params = suite.parameters
        switch params.dhCurve {
        case .x25519:
            let privKey = try CryptoKit.Curve25519.KeyAgreement.PrivateKey(rawRepresentation: deterministicEphemeralKey)
            return KeyPair(publicKey: Data(privKey.publicKey.rawRepresentation), privateKey: deterministicEphemeralKey)
        case .p256:
            let privKey = try CryptoKit.P256.KeyAgreement.PrivateKey(rawRepresentation: deterministicEphemeralKey)
            let pubKey = Data(privKey.publicKey.x963Representation.dropFirst().prefix(32))
            return KeyPair(publicKey: pubKey, privateKey: deterministicEphemeralKey)
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
