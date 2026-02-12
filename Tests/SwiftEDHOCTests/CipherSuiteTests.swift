import XCTest
@testable import SwiftEDHOC

final class CipherSuiteTests: XCTestCase {

    func testAllSuitesExist() {
        let suites: [EdhocCipherSuite] = [
            .suite0, .suite1, .suite2, .suite3,
            .suite4, .suite5, .suite6, .suite24, .suite25,
        ]
        XCTAssertEqual(suites.count, 9)
        XCTAssertEqual(EdhocCipherSuite.allCases.count, 9)
    }

    // MARK: - Suite 0

    func testSuite0Parameters() {
        let p = EdhocCipherSuite.suite0.parameters
        XCTAssertEqual(p.id, 0)
        XCTAssertEqual(p.aeadKeyLength, 16)
        XCTAssertEqual(p.aeadTagLength, 8)
        XCTAssertEqual(p.aeadIvLength, 13)
        XCTAssertEqual(p.hashLength, 32)
        XCTAssertEqual(p.macLength, 8)
        XCTAssertEqual(p.eccKeyLength, 32)
        XCTAssertEqual(p.eccSignLength, 64)
    }

    func testSuite0Algorithms() {
        let p = EdhocCipherSuite.suite0.parameters
        XCTAssertEqual(p.aeadAlgorithm, .aesCCM_16_64_128)
        XCTAssertEqual(p.hashAlgorithm, .sha256)
        XCTAssertEqual(p.dhCurve, .x25519)
        XCTAssertEqual(p.signatureCurve, .ed25519)
    }

    // MARK: - Suite 1

    func testSuite1Parameters() {
        let p = EdhocCipherSuite.suite1.parameters
        XCTAssertEqual(p.id, 1)
        XCTAssertEqual(p.aeadKeyLength, 16)
        XCTAssertEqual(p.aeadTagLength, 16)
        XCTAssertEqual(p.aeadIvLength, 13)
        XCTAssertEqual(p.hashLength, 32)
        XCTAssertEqual(p.macLength, 16)
        XCTAssertEqual(p.eccKeyLength, 32)
        XCTAssertEqual(p.eccSignLength, 64)
    }

    func testSuite1Algorithms() {
        let p = EdhocCipherSuite.suite1.parameters
        XCTAssertEqual(p.aeadAlgorithm, .aesCCM_16_128_128)
        XCTAssertEqual(p.hashAlgorithm, .sha256)
        XCTAssertEqual(p.dhCurve, .x25519)
        XCTAssertEqual(p.signatureCurve, .ed25519)
    }

    // MARK: - Suite 2

    func testSuite2Parameters() {
        let p = EdhocCipherSuite.suite2.parameters
        XCTAssertEqual(p.id, 2)
        XCTAssertEqual(p.aeadKeyLength, 16)
        XCTAssertEqual(p.aeadTagLength, 8)
        XCTAssertEqual(p.aeadIvLength, 13)
        XCTAssertEqual(p.hashLength, 32)
        XCTAssertEqual(p.macLength, 8)
        XCTAssertEqual(p.eccKeyLength, 32)
        XCTAssertEqual(p.eccSignLength, 64)
    }

    func testSuite2Algorithms() {
        let p = EdhocCipherSuite.suite2.parameters
        XCTAssertEqual(p.aeadAlgorithm, .aesCCM_16_64_128)
        XCTAssertEqual(p.hashAlgorithm, .sha256)
        XCTAssertEqual(p.dhCurve, .p256)
        XCTAssertEqual(p.signatureCurve, .p256)
    }

    // MARK: - Suite 3

    func testSuite3Parameters() {
        let p = EdhocCipherSuite.suite3.parameters
        XCTAssertEqual(p.id, 3)
        XCTAssertEqual(p.aeadKeyLength, 16)
        XCTAssertEqual(p.aeadTagLength, 16)
        XCTAssertEqual(p.aeadIvLength, 13)
        XCTAssertEqual(p.hashLength, 32)
        XCTAssertEqual(p.macLength, 16)
        XCTAssertEqual(p.eccKeyLength, 32)
        XCTAssertEqual(p.eccSignLength, 64)
    }

    func testSuite3Algorithms() {
        let p = EdhocCipherSuite.suite3.parameters
        XCTAssertEqual(p.aeadAlgorithm, .aesCCM_16_128_128)
        XCTAssertEqual(p.hashAlgorithm, .sha256)
        XCTAssertEqual(p.dhCurve, .p256)
        XCTAssertEqual(p.signatureCurve, .p256)
    }

    // MARK: - Suite 4

    func testSuite4Parameters() {
        let p = EdhocCipherSuite.suite4.parameters
        XCTAssertEqual(p.id, 4)
        XCTAssertEqual(p.aeadKeyLength, 32)
        XCTAssertEqual(p.aeadTagLength, 16)
        XCTAssertEqual(p.aeadIvLength, 12)
        XCTAssertEqual(p.hashLength, 32)
        XCTAssertEqual(p.macLength, 16)
        XCTAssertEqual(p.eccKeyLength, 32)
        XCTAssertEqual(p.eccSignLength, 64)
    }

    func testSuite4Algorithms() {
        let p = EdhocCipherSuite.suite4.parameters
        XCTAssertEqual(p.aeadAlgorithm, .chaCha20Poly1305)
        XCTAssertEqual(p.hashAlgorithm, .sha256)
        XCTAssertEqual(p.dhCurve, .x25519)
        XCTAssertEqual(p.signatureCurve, .ed25519)
    }

    // MARK: - Suite 5

    func testSuite5Parameters() {
        let p = EdhocCipherSuite.suite5.parameters
        XCTAssertEqual(p.id, 5)
        XCTAssertEqual(p.aeadKeyLength, 32)
        XCTAssertEqual(p.aeadTagLength, 16)
        XCTAssertEqual(p.aeadIvLength, 12)
        XCTAssertEqual(p.hashLength, 32)
        XCTAssertEqual(p.macLength, 16)
        XCTAssertEqual(p.eccKeyLength, 32)
        XCTAssertEqual(p.eccSignLength, 64)
    }

    func testSuite5Algorithms() {
        let p = EdhocCipherSuite.suite5.parameters
        XCTAssertEqual(p.aeadAlgorithm, .chaCha20Poly1305)
        XCTAssertEqual(p.hashAlgorithm, .sha256)
        XCTAssertEqual(p.dhCurve, .p256)
        XCTAssertEqual(p.signatureCurve, .p256)
    }

    // MARK: - Suite 6

    func testSuite6Parameters() {
        let p = EdhocCipherSuite.suite6.parameters
        XCTAssertEqual(p.id, 6)
        XCTAssertEqual(p.aeadKeyLength, 16)
        XCTAssertEqual(p.aeadTagLength, 16)
        XCTAssertEqual(p.aeadIvLength, 12)
        XCTAssertEqual(p.hashLength, 32)
        XCTAssertEqual(p.macLength, 16)
        XCTAssertEqual(p.eccKeyLength, 32)
        XCTAssertEqual(p.eccSignLength, 64)
    }

    func testSuite6Algorithms() {
        let p = EdhocCipherSuite.suite6.parameters
        XCTAssertEqual(p.aeadAlgorithm, .aesGCM128)
        XCTAssertEqual(p.hashAlgorithm, .sha256)
        XCTAssertEqual(p.dhCurve, .x25519)
        XCTAssertEqual(p.signatureCurve, .p256)
    }

    // MARK: - Suite 24

    func testSuite24Parameters() {
        let p = EdhocCipherSuite.suite24.parameters
        XCTAssertEqual(p.id, 24)
        XCTAssertEqual(p.aeadKeyLength, 32)
        XCTAssertEqual(p.aeadTagLength, 16)
        XCTAssertEqual(p.aeadIvLength, 12)
        XCTAssertEqual(p.hashLength, 48)
        XCTAssertEqual(p.macLength, 16)
        XCTAssertEqual(p.eccKeyLength, 48)
        XCTAssertEqual(p.eccSignLength, 96)
    }

    func testSuite24Algorithms() {
        let p = EdhocCipherSuite.suite24.parameters
        XCTAssertEqual(p.aeadAlgorithm, .aesGCM256)
        XCTAssertEqual(p.hashAlgorithm, .sha384)
        XCTAssertEqual(p.dhCurve, .p384)
        XCTAssertEqual(p.signatureCurve, .p384)
    }

    // MARK: - Suite 25

    func testSuite25Parameters() {
        let p = EdhocCipherSuite.suite25.parameters
        XCTAssertEqual(p.id, 25)
        XCTAssertEqual(p.aeadKeyLength, 32)
        XCTAssertEqual(p.aeadTagLength, 16)
        XCTAssertEqual(p.aeadIvLength, 12)
        XCTAssertEqual(p.hashLength, 64)
        XCTAssertEqual(p.macLength, 16)
        XCTAssertEqual(p.eccKeyLength, 56)
        XCTAssertEqual(p.eccSignLength, 114)
    }

    func testSuite25Algorithms() {
        let p = EdhocCipherSuite.suite25.parameters
        XCTAssertEqual(p.aeadAlgorithm, .chaCha20Poly1305)
        XCTAssertEqual(p.hashAlgorithm, .shake256_512)
        XCTAssertEqual(p.dhCurve, .x448)
        XCTAssertEqual(p.signatureCurve, .ed448)
    }

    // MARK: - Raw value round-trip

    func testRawValueRoundTrip() {
        for suite in EdhocCipherSuite.allCases {
            let recovered = EdhocCipherSuite(rawValue: suite.rawValue)
            XCTAssertEqual(recovered, suite, "Round-trip failed for \(suite)")
        }
    }

    func testParameterIDMatchesRawValue() {
        for suite in EdhocCipherSuite.allCases {
            XCTAssertEqual(suite.parameters.id, suite.rawValue,
                           "parameters.id does not match rawValue for \(suite)")
        }
    }
}

// MARK: - Equatable conformance required by XCTAssertEqual

extension AEADAlgorithm: Equatable {}
extension DHCurve: Equatable {}
extension SignatureCurve: Equatable {}
extension HashAlgorithm: Equatable {}
