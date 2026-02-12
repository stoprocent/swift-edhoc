import Foundation
import SwiftCBOR

/// Main EDHOC session actor implementing the EDHOC protocol state machine (RFC 9528).
///
/// `EdhocSession` is a Swift actor providing built-in thread safety via actor isolation.
/// All compose/process/export methods are `async throws`. There is no `reset()` method —
/// create a new `EdhocSession` instance instead.
///
/// Usage:
/// ```swift
/// let initiator = EdhocSession(
///     connectionID: .integer(10),
///     methods: [.method0],
///     cipherSuites: [.suite2],
///     credentialProvider: myCredentials,
///     cryptoProvider: myCrypto
/// )
/// let message1 = try await initiator.composeMessage1()
/// // ... send message1, receive message2 ...
/// let ead2 = try await initiator.processMessage2(message2)
/// let message3 = try await initiator.composeMessage3()
/// let oscore = try await initiator.exportOSCORE()
/// ```
public actor EdhocSession {

    // MARK: - Public properties

    public let connectionID: EdhocConnectionID
    public let methods: [EdhocMethod]
    public let cipherSuites: [EdhocCipherSuite]

    public private(set) var peerConnectionID: EdhocConnectionID?
    public private(set) var selectedMethod: EdhocMethod
    public private(set) var selectedSuite: EdhocCipherSuite
    public private(set) var peerCredentials: EdhocCredentialWithKeys?

    // MARK: - Private dependencies

    private let credentialProvider: EdhocCredentialProvider
    private let cryptoProvider: EdhocCryptoProvider

    // MARK: - Private protocol state

    private var state: SessionState = .start
    private var role: EdhocRole?
    private var suiteParams: CipherSuiteParameters

    private var ephPrivateKey: Data?
    private var ephPub: Data?
    private var peerEphPub: Data?

    private var th: Data?
    private var prk2e: Data?
    private var prk3e2m: Data?
    private var prk4e3m: Data?
    private var prkOut: Data?
    private var prkExporter: Data?

    private var logger: ((String, Data) -> Void)?

    // MARK: - Initializer

    public init(
        connectionID: EdhocConnectionID,
        methods: [EdhocMethod],
        cipherSuites: [EdhocCipherSuite],
        credentialProvider: EdhocCredentialProvider,
        cryptoProvider: EdhocCryptoProvider,
        logger: ((String, Data) -> Void)? = nil
    ) {
        self.connectionID = connectionID
        self.methods = methods
        self.cipherSuites = cipherSuites
        self.credentialProvider = credentialProvider
        self.cryptoProvider = cryptoProvider
        self.logger = logger

        self.selectedMethod = methods[0]
        self.selectedSuite = cipherSuites[cipherSuites.count - 1]
        self.suiteParams = self.selectedSuite.parameters
    }

    // MARK: - Session info snapshot

    private var sessionInfo: EdhocSessionInfo {
        EdhocSessionInfo(
            connectionID: connectionID,
            role: role ?? .initiator,
            selectedMethod: selectedMethod,
            selectedSuite: selectedSuite
        )
    }

    // MARK: - Message 1 (Initiator → Responder)

    /// Compose message_1 as the initiator
    public func composeMessage1(ead: [EdhocEAD]? = nil) throws -> Data {
        try assertState(.start, method: "composeMessage1")
        role = .initiator
        selectedMethod = methods[0]
        selectedSuite = cipherSuites[cipherSuites.count - 1]
        suiteParams = selectedSuite.parameters

        // Generate ephemeral DH keypair
        try generateEphemeralKey()

        // Build message_1 CBOR sequence: METHOD, SUITES_I, G_X, C_I, ?EAD_1
        let canonicalCID = try CBORUtils.canonicalizeConnectionID(connectionID)
        var parts: [CBOR] = [
            CBORSerialization.toCBOR(selectedMethod.rawValue),
            CBORSerialization.encodeSuites(cipherSuites, selected: selectedSuite),
            .byteString(Array(ephPub!)),
            try CBORUtils.connectionIDToCBOR(canonicalCID),
        ]
        if let ead = ead {
            for token in ead {
                parts.append(.unsignedInt(UInt64(token.label)))
                if !token.value.isEmpty {
                    parts.append(.byteString(Array(token.value)))
                }
            }
        }
        let msg1 = CBORSerialization.encodeSequence(parts)
        log("message_1", msg1)

        // TH_1 = H(message_1)
        th = try KeySchedule.hash(crypto: cryptoProvider, suite: selectedSuite, data: msg1)
        log("TH_1", th!)

        state = .waitM2
        return msg1
    }

    /// Process message_1 as the responder
    public func processMessage1(_ message: Data) throws -> [EdhocEAD] {
        try assertState(.start, method: "processMessage1")
        role = .responder

        let items = try CBORSerialization.decodeSequence(message)
        guard items.count >= 4 else {
            throw EdhocError.invalidMessage("message_1 must contain at least 4 items")
        }

        // Parse METHOD
        guard let methodRaw = CBORSerialization.intFromCBOR(items[0]),
              let method = EdhocMethod(rawValue: methodRaw) else {
            throw EdhocError.invalidMessage("Invalid method in message_1")
        }
        guard methods.contains(method) else {
            throw EdhocError.unsupportedMethod(methodRaw)
        }
        selectedMethod = method

        // Parse SUITES_I
        let selected: EdhocCipherSuite
        switch items[1] {
        case .unsignedInt(let n):
            guard let suite = EdhocCipherSuite(rawValue: Int(n)) else {
                throw EdhocError.unsupportedCipherSuite(selected: Int(n), peerSuites: [Int(n)])
            }
            selected = suite
        case .array(let arr):
            guard let lastItem = arr.last,
                  let lastVal = CBORSerialization.intFromCBOR(lastItem),
                  let suite = EdhocCipherSuite(rawValue: lastVal) else {
                throw EdhocError.invalidMessage("Invalid SUITES_I array")
            }
            let peerSuites = arr.compactMap { CBORSerialization.intFromCBOR($0) }
            guard cipherSuites.contains(suite) else {
                throw EdhocError.unsupportedCipherSuite(selected: lastVal, peerSuites: peerSuites)
            }
            selected = suite
        default:
            throw EdhocError.invalidMessage("Invalid SUITES_I format")
        }
        guard cipherSuites.contains(selected) else {
            throw EdhocError.unsupportedCipherSuite(selected: selected.rawValue, peerSuites: [selected.rawValue])
        }
        selectedSuite = selected
        suiteParams = selected.parameters

        // Parse G_X
        guard let gx = CBORSerialization.dataFromCBOR(items[2]) else {
            throw EdhocError.invalidMessage("Invalid G_X in message_1")
        }
        peerEphPub = gx

        // Parse C_I
        peerConnectionID = try CBORUtils.connectionIDFromCBOR(items[3])

        // Parse ?EAD_1
        let eadTokens: [EdhocEAD]
        if items.count > 4 {
            eadTokens = CBORUtils.parseEADItems(Array(items[4...]))
        } else {
            eadTokens = []
        }

        log("message_1", message)

        // TH_1 = H(message_1)
        th = try KeySchedule.hash(crypto: cryptoProvider, suite: selectedSuite, data: message)
        log("TH_1", th!)

        state = .verifiedM1
        return eadTokens
    }

    // MARK: - Message 2 (Responder → Initiator)

    /// Compose message_2 as the responder
    public func composeMessage2(ead: [EdhocEAD]? = nil) throws -> Data {
        try assertState(.verifiedM1, method: "composeMessage2")

        // Generate ephemeral DH keypair (G_Y)
        try generateEphemeralKey()
        let gY = ephPub!
        log("G_Y", gY)

        // ECDH → G_XY
        let gXY = try cryptoProvider.keyAgreement(
            suite: selectedSuite, privateKey: ephPrivateKey!, peerPublicKey: peerEphPub!)
        log("G_XY", gXY)

        // TH_2 = H( G_Y, H(message_1) )
        let th2Input = CBORSerialization.encodeSequence([
            .byteString(Array(gY)),
            .byteString(Array(th!))
        ])
        th = try KeySchedule.hash(crypto: cryptoProvider, suite: selectedSuite, data: th2Input)
        log("TH_2", th!)

        // PRK_2e = HKDF-Extract(TH_2, G_XY)
        prk2e = try KeySchedule.hkdfExtract(
            crypto: cryptoProvider, suite: selectedSuite, ikm: gXY, salt: th!)
        log("PRK_2e", prk2e!)

        // Fetch own credentials
        let cred = try credentialProvider.fetch(info: sessionInfo)
        let credR = try CBORCredentials.getCredBytes(cred)
        let idCredR = CBORCredentials.encodeIDCred(cred)
        let idCredRMap = CBORCredentials.encodeIDCredMap(cred)
        let credRCbor = CBORCredentials.encodeCredItem(cred, credBytes: credR)

        // Static DH for methods 1, 3 (responder authenticates with static DH)
        var gRX: Data?
        if selectedMethod == .method1 || selectedMethod == .method3 {
            guard let privKey = cred.privateKey else {
                throw EdhocError.missingKeyMaterial("Responder private key for static DH")
            }
            gRX = try cryptoProvider.keyAgreement(
                suite: selectedSuite, privateKey: privKey, peerPublicKey: peerEphPub!)
        }

        // PRK_3e2m
        prk3e2m = try KeySchedule.derivePrk3e2m(
            crypto: cryptoProvider, suite: selectedSuite, method: selectedMethod,
            prk2e: prk2e!, th: th!, gRX: gRX)
        log("PRK_3e2m", prk3e2m!)

        // MAC_2 with context_2 = << C_R, ID_CRED_R, TH_2, CRED_R, ?EAD_2 >>
        let canonicalCID = try CBORUtils.canonicalizeConnectionID(connectionID)
        let cRCbor = CBORSerialization.encode(try CBORUtils.connectionIDToCBOR(canonicalCID))
        let context2 = MessageHelpers.buildContext(
            cRCbor: cRCbor, idCredCbor: idCredRMap, th: th!, credXCbor: credRCbor, ead: ead)
        let mac2Len = KeySchedule.macLength(
            method: selectedMethod, role: .responder, suite: selectedSuite)
        let mac2 = try KeySchedule.kdf(
            crypto: cryptoProvider, suite: selectedSuite, prk: prk3e2m!,
            label: KDFLabel.mac2.rawValue, context: context2, length: mac2Len)
        log("MAC_2", mac2)

        // Signature_or_MAC_2
        let sigOrMac2 = try MessageHelpers.signOrMAC(
            crypto: cryptoProvider, suite: selectedSuite, method: selectedMethod,
            role: .responder, credential: cred, idCredCbor: idCredRMap,
            th: th!, credXCbor: credRCbor, ead: ead, mac: mac2)
        log("Signature_or_MAC_2", sigOrMac2)

        // PLAINTEXT_2 = ( C_R, ID_CRED_R, Signature_or_MAC_2, ?EAD_2 )
        let pt2Inner = CBORPlaintext.encodePlaintext(
            idCredCbor: idCredR, signatureOrMac: sigOrMac2, ead: ead)
        var pt2 = cRCbor
        pt2.append(pt2Inner)
        log("PLAINTEXT_2", pt2)

        // KEYSTREAM_2 = EDHOC-KDF(PRK_2e, 0, TH_2, |PLAINTEXT_2|)
        let ks2 = try KeySchedule.kdf(
            crypto: cryptoProvider, suite: selectedSuite, prk: prk2e!,
            label: KDFLabel.keystream2.rawValue, context: th!, length: pt2.count)
        let ct2 = MessageHelpers.xor(pt2, ks2)
        log("CIPHERTEXT_2", ct2)

        // TH_3 = H( TH_2, PLAINTEXT_2, CRED_R )
        var th3Input = Data()
        th3Input.append(CBORSerialization.encode(.byteString(Array(th!))))
        th3Input.append(pt2)
        th3Input.append(credRCbor)
        th = try KeySchedule.hash(crypto: cryptoProvider, suite: selectedSuite, data: th3Input)
        log("TH_3", th!)

        // message_2 = bstr( G_Y || CIPHERTEXT_2 )
        var inner = gY
        inner.append(ct2)
        let msg2 = CBORSerialization.encode(.byteString(Array(inner)))
        log("message_2", msg2)

        state = .waitM3
        return msg2
    }

    /// Process message_2 as the initiator
    public func processMessage2(_ message: Data) throws -> [EdhocEAD] {
        try assertState(.waitM2, method: "processMessage2")

        // Decode outer bstr → G_Y || CIPHERTEXT_2
        let inner = try CBORSerialization.decode(message)
        guard let innerData = CBORSerialization.dataFromCBOR(inner) else {
            throw EdhocError.invalidMessage("message_2 must be a CBOR byte string")
        }

        let gY = innerData.prefix(suiteParams.eccKeyLength)
        let ct2 = innerData.suffix(from: suiteParams.eccKeyLength)
        peerEphPub = Data(gY)
        log("G_Y", Data(gY))

        // ECDH → G_XY
        let gXY = try cryptoProvider.keyAgreement(
            suite: selectedSuite, privateKey: ephPrivateKey!, peerPublicKey: Data(gY))
        log("G_XY", gXY)

        // TH_2 = H( G_Y, H(message_1) )
        let th2Input = CBORSerialization.encodeSequence([
            .byteString(Array(gY)),
            .byteString(Array(th!))
        ])
        th = try KeySchedule.hash(crypto: cryptoProvider, suite: selectedSuite, data: th2Input)
        log("TH_2", th!)

        // PRK_2e
        prk2e = try KeySchedule.hkdfExtract(
            crypto: cryptoProvider, suite: selectedSuite, ikm: gXY, salt: th!)
        log("PRK_2e", prk2e!)

        // Decrypt PLAINTEXT_2
        let ks2 = try KeySchedule.kdf(
            crypto: cryptoProvider, suite: selectedSuite, prk: prk2e!,
            label: KDFLabel.keystream2.rawValue, context: th!, length: ct2.count)
        let pt2 = MessageHelpers.xor(Data(ct2), ks2)
        log("PLAINTEXT_2", pt2)

        // Parse PLAINTEXT_2: C_R, ID_CRED_R, Signature_or_MAC_2, ?EAD_2
        let pt2Items = try CBORSerialization.decodeSequence(pt2)
        guard pt2Items.count >= 3 else {
            throw EdhocError.invalidMessage("PLAINTEXT_2 must contain at least 3 items")
        }
        peerConnectionID = try CBORUtils.connectionIDFromCBOR(pt2Items[0])

        // Re-encode remaining items for parsePlaintext
        var remainingBytes = Data()
        for item in pt2Items[1...] {
            remainingBytes.append(CBORSerialization.encode(item))
        }
        let parsed = try CBORPlaintext.parsePlaintext(remainingBytes)

        // Verify peer credentials
        let peerCredPartial = try CBORCredentials.decodeIDCred(parsed.idCredRaw)
        let peerCred = try credentialProvider.verify(info: sessionInfo, credential: peerCredPartial)
        peerCredentials = peerCred
        let credR = try CBORCredentials.getCredBytes(peerCred)
        let idCredRMap = CBORCredentials.encodeIDCredMap(peerCred)
        let credRCbor = CBORCredentials.encodeCredItem(peerCred, credBytes: credR)

        // Static DH for methods 1, 3
        var gRX: Data?
        if selectedMethod == .method1 || selectedMethod == .method3 {
            guard let peerPubKey = peerCred.publicKey else {
                throw EdhocError.missingKeyMaterial("Peer public key for static DH")
            }
            gRX = try cryptoProvider.keyAgreement(
                suite: selectedSuite, privateKey: ephPrivateKey!, peerPublicKey: peerPubKey)
        }

        // PRK_3e2m
        prk3e2m = try KeySchedule.derivePrk3e2m(
            crypto: cryptoProvider, suite: selectedSuite, method: selectedMethod,
            prk2e: prk2e!, th: th!, gRX: gRX)
        log("PRK_3e2m", prk3e2m!)

        // Verify MAC_2 / Signature_or_MAC_2
        let canonicalPeerCID = try CBORUtils.canonicalizeConnectionID(peerConnectionID!)
        let cRCbor = CBORSerialization.encode(try CBORUtils.connectionIDToCBOR(canonicalPeerCID))
        let context2 = MessageHelpers.buildContext(
            cRCbor: cRCbor, idCredCbor: idCredRMap, th: th!, credXCbor: credRCbor,
            ead: parsed.ead.isEmpty ? nil : parsed.ead)
        let mac2Len = KeySchedule.macLength(
            method: selectedMethod, role: .responder, suite: selectedSuite)
        let mac2 = try KeySchedule.kdf(
            crypto: cryptoProvider, suite: selectedSuite, prk: prk3e2m!,
            label: KDFLabel.mac2.rawValue, context: context2, length: mac2Len)
        log("MAC_2", mac2)

        try MessageHelpers.verifySignatureOrMAC(
            crypto: cryptoProvider, suite: selectedSuite, method: selectedMethod,
            peerRole: .responder, peerCredential: peerCred, idCredCbor: idCredRMap,
            th: th!, credXCbor: credRCbor, ead: parsed.ead.isEmpty ? nil : parsed.ead,
            mac: mac2, received: parsed.signatureOrMac)

        // TH_3 = H( TH_2, PLAINTEXT_2, CRED_R )
        var th3Input = Data()
        th3Input.append(CBORSerialization.encode(.byteString(Array(th!))))
        th3Input.append(pt2)
        th3Input.append(credRCbor)
        th = try KeySchedule.hash(crypto: cryptoProvider, suite: selectedSuite, data: th3Input)
        log("TH_3", th!)

        state = .verifiedM2
        return parsed.ead
    }

    // MARK: - Message 3 (Initiator → Responder)

    /// Compose message_3 as the initiator
    public func composeMessage3(ead: [EdhocEAD]? = nil) throws -> Data {
        try assertState(.verifiedM2, method: "composeMessage3")
        let th3 = th!

        // Fetch own credentials
        let cred = try credentialProvider.fetch(info: sessionInfo)
        let credI = try CBORCredentials.getCredBytes(cred)
        let idCredI = CBORCredentials.encodeIDCred(cred)
        let idCredIMap = CBORCredentials.encodeIDCredMap(cred)
        let credICbor = CBORCredentials.encodeCredItem(cred, credBytes: credI)

        // Static DH for methods 2, 3 (initiator authenticates with static DH)
        var gIX: Data?
        if selectedMethod == .method2 || selectedMethod == .method3 {
            guard let privKey = cred.privateKey else {
                throw EdhocError.missingKeyMaterial("Initiator private key for static DH")
            }
            gIX = try cryptoProvider.keyAgreement(
                suite: selectedSuite, privateKey: privKey, peerPublicKey: peerEphPub!)
        }

        // PRK_4e3m
        prk4e3m = try KeySchedule.derivePrk4e3m(
            crypto: cryptoProvider, suite: selectedSuite, method: selectedMethod,
            prk3e2m: prk3e2m!, th3: th3, gIX: gIX)
        log("PRK_4e3m", prk4e3m!)

        // MAC_3 with context_3 = << ID_CRED_I, TH_3, CRED_I, ?EAD_3 >>
        let context3 = MessageHelpers.buildContext(
            cRCbor: nil, idCredCbor: idCredIMap, th: th3, credXCbor: credICbor, ead: ead)
        let mac3Len = KeySchedule.macLength(
            method: selectedMethod, role: .initiator, suite: selectedSuite)
        let mac3 = try KeySchedule.kdf(
            crypto: cryptoProvider, suite: selectedSuite, prk: prk4e3m!,
            label: KDFLabel.mac3.rawValue, context: context3, length: mac3Len)
        log("MAC_3", mac3)

        // Signature_or_MAC_3
        let sigOrMac3 = try MessageHelpers.signOrMAC(
            crypto: cryptoProvider, suite: selectedSuite, method: selectedMethod,
            role: .initiator, credential: cred, idCredCbor: idCredIMap,
            th: th3, credXCbor: credICbor, ead: ead, mac: mac3)
        log("Signature_or_MAC_3", sigOrMac3)

        // PLAINTEXT_3 = ( ID_CRED_I, Signature_or_MAC_3, ?EAD_3 )
        let pt3 = CBORPlaintext.encodePlaintext(
            idCredCbor: idCredI, signatureOrMac: sigOrMac3, ead: ead)
        log("PLAINTEXT_3", pt3)

        // AEAD encrypt: K_3, IV_3
        let k3 = try KeySchedule.kdf(
            crypto: cryptoProvider, suite: selectedSuite, prk: prk3e2m!,
            label: KDFLabel.k3.rawValue, context: th3, length: suiteParams.aeadKeyLength)
        let iv3 = try KeySchedule.kdf(
            crypto: cryptoProvider, suite: selectedSuite, prk: prk3e2m!,
            label: KDFLabel.iv3.rawValue, context: th3, length: suiteParams.aeadIvLength)
        let aad3 = MessageHelpers.buildEncStructureAAD(th: th3)
        let ct3 = try MessageHelpers.aeadEncrypt(
            crypto: cryptoProvider, suite: selectedSuite, key: k3, iv: iv3, aad: aad3, plaintext: pt3)
        log("CIPHERTEXT_3", ct3)

        // TH_4 = H( TH_3, PLAINTEXT_3, CRED_I )
        var th4Input = Data()
        th4Input.append(CBORSerialization.encode(.byteString(Array(th3))))
        th4Input.append(pt3)
        th4Input.append(credICbor)
        th = try KeySchedule.hash(crypto: cryptoProvider, suite: selectedSuite, data: th4Input)
        log("TH_4", th!)

        // PRK_out, PRK_exporter
        prkOut = try KeySchedule.kdf(
            crypto: cryptoProvider, suite: selectedSuite, prk: prk4e3m!,
            label: KDFLabel.prkOut.rawValue, context: th!, length: suiteParams.hashLength)
        prkExporter = try KeySchedule.kdf(
            crypto: cryptoProvider, suite: selectedSuite, prk: prkOut!,
            label: KDFLabel.prkExporter.rawValue, context: Data(), length: suiteParams.hashLength)

        // Destroy ephemeral key
        try destroyEphemeralKey()

        // message_3 = CBOR bstr of CIPHERTEXT_3
        let msg3 = CBORSerialization.encode(.byteString(Array(ct3)))
        log("message_3", msg3)

        state = .waitM4OrDone
        return msg3
    }

    /// Process message_3 as the responder
    public func processMessage3(_ message: Data) throws -> [EdhocEAD] {
        try assertState(.waitM3, method: "processMessage3")
        let th3 = th!

        let ct3Cbor = try CBORSerialization.decode(message)
        guard let ct3 = CBORSerialization.dataFromCBOR(ct3Cbor) else {
            throw EdhocError.invalidMessage("message_3 must be a CBOR byte string")
        }

        // AEAD decrypt
        let k3 = try KeySchedule.kdf(
            crypto: cryptoProvider, suite: selectedSuite, prk: prk3e2m!,
            label: KDFLabel.k3.rawValue, context: th3, length: suiteParams.aeadKeyLength)
        let iv3 = try KeySchedule.kdf(
            crypto: cryptoProvider, suite: selectedSuite, prk: prk3e2m!,
            label: KDFLabel.iv3.rawValue, context: th3, length: suiteParams.aeadIvLength)
        let aad3 = MessageHelpers.buildEncStructureAAD(th: th3)
        let pt3 = try MessageHelpers.aeadDecrypt(
            crypto: cryptoProvider, suite: selectedSuite, key: k3, iv: iv3, aad: aad3, ciphertext: ct3)
        log("PLAINTEXT_3", pt3)

        // Parse PLAINTEXT_3: ID_CRED_I, Signature_or_MAC_3, ?EAD_3
        let parsed = try CBORPlaintext.parsePlaintext(pt3)

        // Verify peer credentials
        let peerCredPartial = try CBORCredentials.decodeIDCred(parsed.idCredRaw)
        let peerCred = try credentialProvider.verify(info: sessionInfo, credential: peerCredPartial)
        peerCredentials = peerCred
        let credI = try CBORCredentials.getCredBytes(peerCred)
        let idCredIMap = CBORCredentials.encodeIDCredMap(peerCred)
        let credICbor = CBORCredentials.encodeCredItem(peerCred, credBytes: credI)

        // Static DH for methods 2, 3
        var gIX: Data?
        if selectedMethod == .method2 || selectedMethod == .method3 {
            if let ephKey = ephPrivateKey, let peerPubKey = peerCred.publicKey {
                gIX = try cryptoProvider.keyAgreement(
                    suite: selectedSuite, privateKey: ephKey, peerPublicKey: peerPubKey)
            }
        }

        // PRK_4e3m
        prk4e3m = try KeySchedule.derivePrk4e3m(
            crypto: cryptoProvider, suite: selectedSuite, method: selectedMethod,
            prk3e2m: prk3e2m!, th3: th3, gIX: gIX)

        // Verify MAC_3
        let context3 = MessageHelpers.buildContext(
            cRCbor: nil, idCredCbor: idCredIMap, th: th3, credXCbor: credICbor,
            ead: parsed.ead.isEmpty ? nil : parsed.ead)
        let mac3Len = KeySchedule.macLength(
            method: selectedMethod, role: .initiator, suite: selectedSuite)
        let mac3 = try KeySchedule.kdf(
            crypto: cryptoProvider, suite: selectedSuite, prk: prk4e3m!,
            label: KDFLabel.mac3.rawValue, context: context3, length: mac3Len)

        try MessageHelpers.verifySignatureOrMAC(
            crypto: cryptoProvider, suite: selectedSuite, method: selectedMethod,
            peerRole: .initiator, peerCredential: peerCred, idCredCbor: idCredIMap,
            th: th3, credXCbor: credICbor, ead: parsed.ead.isEmpty ? nil : parsed.ead,
            mac: mac3, received: parsed.signatureOrMac)

        // TH_4
        var th4Input = Data()
        th4Input.append(CBORSerialization.encode(.byteString(Array(th3))))
        th4Input.append(pt3)
        th4Input.append(credICbor)
        th = try KeySchedule.hash(crypto: cryptoProvider, suite: selectedSuite, data: th4Input)

        // PRK_out, PRK_exporter
        prkOut = try KeySchedule.kdf(
            crypto: cryptoProvider, suite: selectedSuite, prk: prk4e3m!,
            label: KDFLabel.prkOut.rawValue, context: th!, length: suiteParams.hashLength)
        prkExporter = try KeySchedule.kdf(
            crypto: cryptoProvider, suite: selectedSuite, prk: prkOut!,
            label: KDFLabel.prkExporter.rawValue, context: Data(), length: suiteParams.hashLength)

        try destroyEphemeralKey()

        state = .completed
        return parsed.ead
    }

    // MARK: - Message 4 (Optional, Responder → Initiator)

    /// Compose optional message_4 as the responder
    public func composeMessage4(ead: [EdhocEAD]? = nil) throws -> Data {
        try assertState(.waitM4OrDone, method: "composeMessage4")
        let th4 = th!

        let k4 = try KeySchedule.kdf(
            crypto: cryptoProvider, suite: selectedSuite, prk: prk4e3m!,
            label: KDFLabel.k4.rawValue, context: th4, length: suiteParams.aeadKeyLength)
        let iv4 = try KeySchedule.kdf(
            crypto: cryptoProvider, suite: selectedSuite, prk: prk4e3m!,
            label: KDFLabel.iv4.rawValue, context: th4, length: suiteParams.aeadIvLength)
        let pt4: Data = (ead != nil && !ead!.isEmpty) ? CBORUtils.encodeEADItems(ead!) : Data()
        let aad4 = MessageHelpers.buildEncStructureAAD(th: th4)
        let ct4 = try MessageHelpers.aeadEncrypt(
            crypto: cryptoProvider, suite: selectedSuite, key: k4, iv: iv4, aad: aad4, plaintext: pt4)

        let msg4 = CBORSerialization.encode(.byteString(Array(ct4)))
        state = .completed
        return msg4
    }

    /// Process optional message_4 as the initiator
    public func processMessage4(_ message: Data) throws -> [EdhocEAD] {
        try assertState(.completed, method: "processMessage4")
        let th4 = th!

        let ct4Cbor = try CBORSerialization.decode(message)
        guard let ct4 = CBORSerialization.dataFromCBOR(ct4Cbor) else {
            throw EdhocError.invalidMessage("message_4 must be a CBOR byte string")
        }

        let k4 = try KeySchedule.kdf(
            crypto: cryptoProvider, suite: selectedSuite, prk: prk4e3m!,
            label: KDFLabel.k4.rawValue, context: th4, length: suiteParams.aeadKeyLength)
        let iv4 = try KeySchedule.kdf(
            crypto: cryptoProvider, suite: selectedSuite, prk: prk4e3m!,
            label: KDFLabel.iv4.rawValue, context: th4, length: suiteParams.aeadIvLength)
        let aad4 = MessageHelpers.buildEncStructureAAD(th: th4)
        let pt4 = try MessageHelpers.aeadDecrypt(
            crypto: cryptoProvider, suite: selectedSuite, key: k4, iv: iv4, aad: aad4, ciphertext: ct4)

        if pt4.isEmpty { return [] }
        let items = try CBORSerialization.decodeSequence(pt4)
        return CBORUtils.parseEADItems(items)
    }

    // MARK: - Export API

    /// Export OSCORE security context from completed handshake
    public func exportOSCORE() throws -> EdhocOscoreContext {
        guard let prkExp = prkExporter else {
            throw EdhocError.handshakeNotCompleted
        }

        let masterSecret = try KeySchedule.kdf(
            crypto: cryptoProvider, suite: selectedSuite, prk: prkExp,
            label: 0, context: Data(), length: 16)
        let masterSalt = try KeySchedule.kdf(
            crypto: cryptoProvider, suite: selectedSuite, prk: prkExp,
            label: 1, context: Data(), length: 8)

        // RFC 9528 §7.2.1: Initiator Sender ID = C_R, Responder Sender ID = C_I
        guard let peerCid = peerConnectionID else {
            throw EdhocError.handshakeNotCompleted
        }
        let senderId = peerCid.toBytes()
        let recipientId = connectionID.toBytes()

        return EdhocOscoreContext(
            masterSecret: masterSecret, masterSalt: masterSalt,
            senderId: senderId, recipientId: recipientId)
    }

    /// Export a key from the EDHOC exporter
    public func exportKey(label: Int, length: Int) throws -> Data {
        guard let prkExp = prkExporter else {
            throw EdhocError.handshakeNotCompleted
        }
        return try KeySchedule.kdf(
            crypto: cryptoProvider, suite: selectedSuite, prk: prkExp,
            label: label, context: Data(), length: length)
    }

    /// Perform a key update with the given context
    public func keyUpdate(context: Data) throws {
        guard let currentPrkOut = prkOut else {
            throw EdhocError.handshakeNotCompleted
        }
        prkOut = try KeySchedule.kdf(
            crypto: cryptoProvider, suite: selectedSuite, prk: currentPrkOut,
            label: KDFLabel.keyUpdate.rawValue, context: context, length: suiteParams.hashLength)
        prkExporter = try KeySchedule.kdf(
            crypto: cryptoProvider, suite: selectedSuite, prk: prkOut!,
            label: KDFLabel.prkExporter.rawValue, context: Data(), length: suiteParams.hashLength)
    }

    // MARK: - Private helpers

    private func generateEphemeralKey() throws {
        let kp = try cryptoProvider.generateKeyPair(suite: selectedSuite)
        ephPrivateKey = kp.privateKey
        ephPub = kp.publicKey
    }

    private func destroyEphemeralKey() throws {
        ephPrivateKey = nil
    }

    private func assertState(_ expected: SessionState, method: String) throws {
        guard state == expected else {
            throw EdhocError.invalidState(expected: "\(expected)", method: method)
        }
    }

    private func log(_ name: String, _ data: Data) {
        logger?(name, data)
    }
}
