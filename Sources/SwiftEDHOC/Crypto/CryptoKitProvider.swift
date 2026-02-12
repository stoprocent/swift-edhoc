import Foundation
import CryptoKit
import CryptoSwift

/// Default implementation of ``EdhocCryptoProvider`` backed by Apple CryptoKit
/// (for ECDH, signatures, HKDF, AES-GCM, ChaCha20-Poly1305, hashing) and
/// CryptoSwift (for AES-CCM which CryptoKit does not support).
///
/// All operations take raw key bytes directly.
open class CryptoKitProvider: EdhocCryptoProvider, @unchecked Sendable {

    // MARK: - Initialisation

    public init() {}

    // MARK: - EdhocCryptoProvider conformance

    // MARK: generateKeyPair

    open func generateKeyPair(suite: EdhocCipherSuite) throws -> KeyPair {
        let params = suite.parameters

        switch params.dhCurve {
        case .x25519:
            let privateKey = Curve25519.KeyAgreement.PrivateKey()
            let privateKeyData = Data(privateKey.rawRepresentation)
            let publicKeyData = Data(privateKey.publicKey.rawRepresentation)
            return KeyPair(publicKey: publicKeyData, privateKey: privateKeyData)

        case .p256:
            let privateKey = P256.KeyAgreement.PrivateKey()
            let privateKeyData = Data(privateKey.rawRepresentation)
            // RFC 9528: P-256 public keys on the wire use x-coordinate only (32 bytes)
            let publicKeyData = Data(privateKey.publicKey.x963Representation.dropFirst().prefix(32))
            return KeyPair(publicKey: publicKeyData, privateKey: privateKeyData)
        case .p384:
            let privateKey = P384.KeyAgreement.PrivateKey()
            let privateKeyData = Data(privateKey.rawRepresentation)
            // RFC 9528: P-384 public keys on the wire use x-coordinate only (48 bytes)
            let publicKeyData = Data(privateKey.publicKey.x963Representation.dropFirst().prefix(48))
            return KeyPair(publicKey: publicKeyData, privateKey: privateKeyData)
        case .x448:
            throw EdhocError.unsupportedCipherSuite(selected: suite.rawValue, peerSuites: [suite.rawValue])
        }
    }

    // MARK: keyAgreement

    public func keyAgreement(suite: EdhocCipherSuite, privateKey: Data, peerPublicKey: Data) throws -> Data {
        let params = suite.parameters

        switch params.dhCurve {
        case .x25519:
            let privKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
            let pubKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublicKey)
            let sharedSecret = try privKey.sharedSecretFromKeyAgreement(with: pubKey)
            return sharedSecret.withUnsafeBytes { Data($0) }

        case .p256:
            let privKey = try P256.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
            let publicKey: P256.KeyAgreement.PublicKey
            if peerPublicKey.count == 32 {
                // 32 bytes = x-coordinate only (from wire per RFC 9528); reconstruct point
                publicKey = try P256.KeyAgreement.PublicKey(compactRepresentation: peerPublicKey)
            } else if peerPublicKey.count == 65 && peerPublicKey[0] == 0x04 {
                // 65 bytes = 0x04 || x || y (already X9.63 uncompressed)
                publicKey = try P256.KeyAgreement.PublicKey(x963Representation: peerPublicKey)
            } else {
                // 64 bytes = x||y (from certificate); prepend 0x04 for X9.63 format
                var x963Data = Data([0x04])
                x963Data.append(peerPublicKey)
                publicKey = try P256.KeyAgreement.PublicKey(x963Representation: x963Data)
            }
            let sharedSecret = try privKey.sharedSecretFromKeyAgreement(with: publicKey)
            return sharedSecret.withUnsafeBytes { Data($0) }
        case .p384:
            let privKey = try P384.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
            let publicKey: P384.KeyAgreement.PublicKey
            if peerPublicKey.count == 48 {
                publicKey = try P384.KeyAgreement.PublicKey(compactRepresentation: peerPublicKey)
            } else if peerPublicKey.count == 97 && peerPublicKey[0] == 0x04 {
                publicKey = try P384.KeyAgreement.PublicKey(x963Representation: peerPublicKey)
            } else {
                var x963Data = Data([0x04])
                x963Data.append(peerPublicKey)
                publicKey = try P384.KeyAgreement.PublicKey(x963Representation: x963Data)
            }
            let sharedSecret = try privKey.sharedSecretFromKeyAgreement(with: publicKey)
            return sharedSecret.withUnsafeBytes { Data($0) }
        case .x448:
            throw EdhocError.unsupportedCipherSuite(selected: suite.rawValue, peerSuites: [suite.rawValue])
        }
    }

    // MARK: sign

    public func sign(suite: EdhocCipherSuite, privateKey: Data, input: Data) throws -> Data {
        let params = suite.parameters

        switch params.signatureCurve {
        case .ed25519:
            let privKey = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKey)
            let signature = try privKey.signature(for: input)
            return Data(signature)

        case .p256:
            let privKey = try P256.Signing.PrivateKey(rawRepresentation: privateKey)
            let digest = CryptoKit.SHA256.hash(data: input)
            let signature = try privKey.signature(for: digest)
            // Return compact r||s (64 bytes)
            return signature.rawRepresentation
        case .p384:
            let privKey = try P384.Signing.PrivateKey(rawRepresentation: privateKey)
            let digest = CryptoKit.SHA384.hash(data: input)
            let signature = try privKey.signature(for: digest)
            return signature.rawRepresentation
        case .ed448:
            throw EdhocError.unsupportedCipherSuite(selected: suite.rawValue, peerSuites: [suite.rawValue])
        }
    }

    // MARK: verify

    public func verify(suite: EdhocCipherSuite, publicKey: Data, input: Data, signature: Data) throws -> Bool {
        let params = suite.parameters

        switch params.signatureCurve {
        case .ed25519:
            let pubKey = try Curve25519.Signing.PublicKey(rawRepresentation: publicKey)
            return pubKey.isValidSignature(signature, for: input)

        case .p256:
            let p256PubKey: P256.Signing.PublicKey
            if publicKey.count == 32 {
                p256PubKey = try P256.Signing.PublicKey(compactRepresentation: publicKey)
            } else if publicKey.count == 65 && publicKey[0] == 0x04 {
                // 65 bytes = 0x04 || x || y (already X9.63 uncompressed)
                p256PubKey = try P256.Signing.PublicKey(x963Representation: publicKey)
            } else {
                // 64 bytes = x||y (from certificate); prepend 0x04 for X9.63 format
                var x963Data = Data([0x04])
                x963Data.append(publicKey)
                p256PubKey = try P256.Signing.PublicKey(x963Representation: x963Data)
            }
            let ecdsaSignature = try P256.Signing.ECDSASignature(rawRepresentation: signature)
            let digest = CryptoKit.SHA256.hash(data: input)
            return p256PubKey.isValidSignature(ecdsaSignature, for: digest)
        case .p384:
            let p384PubKey: P384.Signing.PublicKey
            if publicKey.count == 48 {
                p384PubKey = try P384.Signing.PublicKey(compactRepresentation: publicKey)
            } else if publicKey.count == 97 && publicKey[0] == 0x04 {
                p384PubKey = try P384.Signing.PublicKey(x963Representation: publicKey)
            } else {
                var x963Data = Data([0x04])
                x963Data.append(publicKey)
                p384PubKey = try P384.Signing.PublicKey(x963Representation: x963Data)
            }
            let ecdsaSignature = try P384.Signing.ECDSASignature(rawRepresentation: signature)
            let digest = CryptoKit.SHA384.hash(data: input)
            return p384PubKey.isValidSignature(ecdsaSignature, for: digest)
        case .ed448:
            throw EdhocError.unsupportedCipherSuite(selected: suite.rawValue, peerSuites: [suite.rawValue])
        }
    }

    // MARK: hkdfExtract (HKDF-Extract)

    public func hkdfExtract(suite: EdhocCipherSuite, ikm: Data, salt: Data) throws -> Data {
        let params = suite.parameters

        // HKDF-Extract is defined as HMAC(salt, IKM)
        // The salt is the HMAC key, and the IKM (input key material) is the HMAC message.
        switch params.hashAlgorithm {
        case .sha256:
            let saltKey = CryptoKit.SymmetricKey(data: salt)
            var hmac = CryptoKit.HMAC<CryptoKit.SHA256>(key: saltKey)
            hmac.update(data: ikm)
            let mac = hmac.finalize()
            return Data(mac)

        case .sha384:
            let saltKey = CryptoKit.SymmetricKey(data: salt)
            var hmac = CryptoKit.HMAC<CryptoKit.SHA384>(key: saltKey)
            hmac.update(data: ikm)
            let mac = hmac.finalize()
            return Data(mac)
        case .shake256_512:
            throw EdhocError.unsupportedCipherSuite(selected: suite.rawValue, peerSuites: [suite.rawValue])
        }
    }

    // MARK: hkdfExpand (HKDF-Expand)

    public func hkdfExpand(suite: EdhocCipherSuite, prk: Data, info: Data, length: Int) throws -> Data {
        let params = suite.parameters
        let prkKey = CryptoKit.SymmetricKey(data: prk)

        switch params.hashAlgorithm {
        case .sha256:
            let okm = CryptoKit.HKDF<CryptoKit.SHA256>.expand(
                pseudoRandomKey: prkKey,
                info: info,
                outputByteCount: length
            )
            return okm.withUnsafeBytes { Data($0) }

        case .sha384:
            let okm = CryptoKit.HKDF<CryptoKit.SHA384>.expand(
                pseudoRandomKey: prkKey,
                info: info,
                outputByteCount: length
            )
            return okm.withUnsafeBytes { Data($0) }
        case .shake256_512:
            throw EdhocError.unsupportedCipherSuite(selected: suite.rawValue, peerSuites: [suite.rawValue])
        }
    }

    // MARK: encrypt (AEAD)

    public func encrypt(suite: EdhocCipherSuite, key: Data, nonce: Data, aad: Data, plaintext: Data) throws -> Data {
        let params = suite.parameters

        switch params.aeadAlgorithm {
        case .aesCCM_16_64_128, .aesCCM_16_128_128:
            return try encryptAESCCM(
                key: key, nonce: nonce, aad: aad, plaintext: plaintext,
                tagLength: params.aeadTagLength
            )

        case .aesGCM128, .aesGCM256:
            return try encryptAESGCM(key: key, nonce: nonce, aad: aad, plaintext: plaintext)

        case .chaCha20Poly1305:
            return try encryptChaChaPoly(key: key, nonce: nonce, aad: aad, plaintext: plaintext)
        }
    }

    // MARK: decrypt (AEAD)

    public func decrypt(suite: EdhocCipherSuite, key: Data, nonce: Data, aad: Data, ciphertext: Data) throws -> Data {
        let params = suite.parameters

        switch params.aeadAlgorithm {
        case .aesCCM_16_64_128, .aesCCM_16_128_128:
            return try decryptAESCCM(
                key: key, nonce: nonce, aad: aad, ciphertext: ciphertext,
                tagLength: params.aeadTagLength
            )

        case .aesGCM128, .aesGCM256:
            return try decryptAESGCM(
                key: key, nonce: nonce, aad: aad, ciphertext: ciphertext,
                tagLength: params.aeadTagLength
            )

        case .chaCha20Poly1305:
            return try decryptChaChaPoly(
                key: key, nonce: nonce, aad: aad, ciphertext: ciphertext,
                tagLength: params.aeadTagLength
            )
        }
    }

    // MARK: hash

    public func hash(suite: EdhocCipherSuite, data: Data) throws -> Data {
        let params = suite.parameters

        switch params.hashAlgorithm {
        case .sha256:
            return Data(CryptoKit.SHA256.hash(data: data))
        case .sha384:
            return Data(CryptoKit.SHA384.hash(data: data))
        case .shake256_512:
            throw EdhocError.unsupportedCipherSuite(selected: suite.rawValue, peerSuites: [suite.rawValue])
        }
    }

    // MARK: - Private helpers: AES-CCM (via CryptoSwift)

    private func encryptAESCCM(key: Data, nonce: Data, aad: Data, plaintext: Data, tagLength: Int) throws -> Data {
        do {
            let ccm = CryptoSwift.CCM(
                iv: Array(nonce),
                tagLength: tagLength,
                messageLength: plaintext.count,
                additionalAuthenticatedData: Array(aad)
            )
            let aes = try CryptoSwift.AES(
                key: Array(key),
                blockMode: ccm,
                padding: .noPadding
            )
            // encrypt returns ciphertext || tag concatenated
            let encrypted = try aes.encrypt(Array(plaintext))
            return Data(encrypted)
        } catch {
            throw EdhocError.cryptoError("AES-CCM encryption failed: \(error)")
        }
    }

    private func decryptAESCCM(key: Data, nonce: Data, aad: Data, ciphertext: Data, tagLength: Int) throws -> Data {
        guard ciphertext.count >= tagLength else {
            throw EdhocError.cryptoError("AES-CCM ciphertext too short for tag")
        }

        let plaintextLength = ciphertext.count - tagLength

        do {
            // CryptoSwift CCM decrypt expects the full ciphertext+tag concatenated.
            // It extracts the tag internally from the last tagLength bytes.
            let ccm = CryptoSwift.CCM(
                iv: Array(nonce),
                tagLength: tagLength,
                messageLength: plaintextLength,
                additionalAuthenticatedData: Array(aad)
            )
            let aes = try CryptoSwift.AES(
                key: Array(key),
                blockMode: ccm,
                padding: .noPadding
            )
            let decrypted = try aes.decrypt(Array(ciphertext))
            return Data(decrypted)
        } catch {
            throw EdhocError.cryptoError("AES-CCM decryption failed: \(error)")
        }
    }

    // MARK: - Private helpers: AES-GCM (via CryptoKit)

    private func encryptAESGCM(key: Data, nonce: Data, aad: Data, plaintext: Data) throws -> Data {
        do {
            let symmetricKey = CryptoKit.SymmetricKey(data: key)
            let gcmNonce = try CryptoKit.AES.GCM.Nonce(data: nonce)
            let sealedBox = try CryptoKit.AES.GCM.seal(plaintext, using: symmetricKey, nonce: gcmNonce, authenticating: aad)
            // Return ciphertext || tag
            return sealedBox.ciphertext + sealedBox.tag
        } catch let error as EdhocError {
            throw error
        } catch {
            throw EdhocError.cryptoError("AES-GCM encryption failed: \(error)")
        }
    }

    private func decryptAESGCM(key: Data, nonce: Data, aad: Data, ciphertext: Data, tagLength: Int) throws -> Data {
        guard ciphertext.count >= tagLength else {
            throw EdhocError.cryptoError("AES-GCM ciphertext too short for tag")
        }

        do {
            let symmetricKey = CryptoKit.SymmetricKey(data: key)
            let gcmNonce = try CryptoKit.AES.GCM.Nonce(data: nonce)
            let ctLength = ciphertext.count - tagLength
            let ct = ciphertext.prefix(ctLength)
            let tag = ciphertext.suffix(tagLength)
            let sealedBox = try CryptoKit.AES.GCM.SealedBox(nonce: gcmNonce, ciphertext: ct, tag: tag)
            let plaintext = try CryptoKit.AES.GCM.open(sealedBox, using: symmetricKey, authenticating: aad)
            return plaintext
        } catch let error as EdhocError {
            throw error
        } catch {
            throw EdhocError.cryptoError("AES-GCM decryption failed: \(error)")
        }
    }

    // MARK: - Private helpers: ChaCha20-Poly1305 (via CryptoKit)

    private func encryptChaChaPoly(key: Data, nonce: Data, aad: Data, plaintext: Data) throws -> Data {
        do {
            let symmetricKey = CryptoKit.SymmetricKey(data: key)
            let chachaNonce = try ChaChaPoly.Nonce(data: nonce)
            let sealedBox = try ChaChaPoly.seal(plaintext, using: symmetricKey, nonce: chachaNonce, authenticating: aad)
            // Return ciphertext || tag
            return sealedBox.ciphertext + sealedBox.tag
        } catch let error as EdhocError {
            throw error
        } catch {
            throw EdhocError.cryptoError("ChaCha20-Poly1305 encryption failed: \(error)")
        }
    }

    private func decryptChaChaPoly(key: Data, nonce: Data, aad: Data, ciphertext: Data, tagLength: Int) throws -> Data {
        guard ciphertext.count >= tagLength else {
            throw EdhocError.cryptoError("ChaCha20-Poly1305 ciphertext too short for tag")
        }

        do {
            let symmetricKey = CryptoKit.SymmetricKey(data: key)
            let chachaNonce = try ChaChaPoly.Nonce(data: nonce)
            let ctLength = ciphertext.count - tagLength
            let ct = ciphertext.prefix(ctLength)
            let tag = ciphertext.suffix(tagLength)
            let sealedBox = try ChaChaPoly.SealedBox(nonce: chachaNonce, ciphertext: ct, tag: tag)
            let plaintext = try ChaChaPoly.open(sealedBox, using: symmetricKey, authenticating: aad)
            return plaintext
        } catch let error as EdhocError {
            throw error
        } catch {
            throw EdhocError.cryptoError("ChaCha20-Poly1305 decryption failed: \(error)")
        }
    }
}
