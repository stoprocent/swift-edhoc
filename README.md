# SwiftEDHOC

A Swift implementation of the EDHOC (Ephemeral Diffie-Hellman Over COSE) protocol defined in [RFC 9528](https://www.rfc-editor.org/rfc/rfc9528.html).

## Installation

Add the dependency to your `Package.swift`:

```swift
.package(url: "https://github.com/mserafin/swift-edhoc.git", from: "1.0.0")
```

## Usage

### X.509 Certificate Credentials

```swift
import SwiftEDHOC

// Set up the credential provider with your DER-encoded certificate chain
let credentialProvider = X509CredentialProvider(
    certificates: [myLeafCertDER],
    cryptoKeyID: myPrivateKeyID
)
credentialProvider.addTrustedCA(caCertDER)
credentialProvider.addPeerCertificate(peerCertDER)

// Set up the crypto provider
let crypto = CryptoKitProvider()
crypto.addKey(keyID: myPrivateKeyID, key: myPrivateKeyBytes)

// Create a session and run the handshake
let initiator = EdhocSession(
    connectionID: .integer(10),
    methods: [.method0],
    cipherSuites: [.suite2],
    credentialProvider: credentialProvider,
    cryptoProvider: crypto
)

let message1 = try await initiator.composeMessage1()
// ... send message1, receive message2 ...
let ead2 = try await initiator.processMessage2(message2)
let message3 = try await initiator.composeMessage3()
let oscore = try await initiator.exportOSCORE()
```

### CCS/KID Credentials

CCS (CWT Claims Set) credentials are lightweight CBOR-encoded identity documents
commonly used in constrained IoT environments. Each CCS is a CBOR map containing
a subject name and a COSE_Key with the party's public key, identified by a `kid`
(key ID) value.

```swift
import SwiftEDHOC
import SwiftCBOR

// --- Step 1: Build CCS credentials as CBOR ---
//
// A CCS follows the structure from RFC 8747 (cnf claim) with a COSE_Key (RFC 9052):
//
//   {
//     2: "subject-name",      / sub: subject identifier /
//     8: {                    / cnf: confirmation claim  /
//       1: {                  / COSE_Key                 /
//         1: kty,             /   key type (2 = EC2)     /
//         2: kid_bstr,        /   kid as bstr            /
//        -1: crv,             /   curve (1 = P-256)      /
//        -2: x_coord,         /   x-coordinate (32 B)    /
//        -3: y_coord          /   y-coordinate (32 B)    /
//       }
//     }
//   }

func buildCCS(
    subject: String,
    kid: Int,
    curve: UInt64,
    publicKeyX: Data,
    publicKeyY: Data
) -> Data {
    // kid on the wire is a 1-byte bstr containing the CBOR encoding of the kid value
    let kidCborByte: UInt8 = kid >= 0 ? UInt8(kid) : UInt8(0x20 | (-(kid + 1)))

    let coseKey: CBOR = .map([
        .unsignedInt(1): .unsignedInt(2),                           // kty: EC2
        .unsignedInt(2): .byteString([kidCborByte]),                // kid
        .negativeInt(0): .unsignedInt(curve),                       // crv: P-256 = 1
        .negativeInt(1): .byteString(Array(publicKeyX)),            // x (32 bytes)
        .negativeInt(2): .byteString(Array(publicKeyY)),            // y (32 bytes)
    ])

    let ccs: CBOR = .map([
        .unsignedInt(2): .utf8String(subject),                      // sub
        .unsignedInt(8): .map([.unsignedInt(1): coseKey]),          // cnf → COSE_Key
    ])
    return CBORSerialization.encode(ccs)
}

// Example using RFC 9529 Chapter 3 test vector values (P-256):
let myPublicKeyX  = Data(hex: "ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb6")
let myPublicKeyY  = Data(hex: "6e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8")
let myCCS = buildCCS(subject: "42-50-31-FF-EF-37-32-39", kid: -12, curve: 1,
                     publicKeyX: myPublicKeyX, publicKeyY: myPublicKeyY)

let peerPublicKeyX = Data(hex: "bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0")
let peerPublicKeyY = Data(hex: "4519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072")
let peerCCS = buildCCS(subject: "example.edu", kid: -19, curve: 1,
                       publicKeyX: peerPublicKeyX, publicKeyY: peerPublicKeyY)

// --- Step 2: Register credentials ---

var credentialProvider = CCSCredentialProvider()
credentialProvider.addOwnCredential(
    kid: .integer(-12),             // kid value
    ccsBytes: myCCS,                // CBOR-encoded CCS
    publicKey: myPublicKeyX,        // public key (x-coordinate only, 32 bytes)
    privateKeyID: myPrivateKeyID    // opaque ID for the crypto provider's key store
)
credentialProvider.addPeerCredential(
    kid: .integer(-19),
    ccsBytes: peerCCS,
    publicKey: peerPublicKeyX
)

// --- Step 3: Set up crypto and register private key ---

let crypto = CryptoKitProvider()
crypto.addKey(keyID: myPrivateKeyID, key: myPrivateKeyBytes)  // P-256 private key (32 bytes)

// --- Step 4: Create session (Method 3 = StaticDH both sides) ---

let initiator = EdhocSession(
    connectionID: .integer(10),
    methods: [.method3],
    cipherSuites: [.suite2],
    credentialProvider: credentialProvider,
    cryptoProvider: crypto
)

let message1 = try await initiator.composeMessage1()
// ... send message1, receive message2 ...
let ead2 = try await initiator.processMessage2(message2)
let message3 = try await initiator.composeMessage3()
let oscore = try await initiator.exportOSCORE()
```

## License

See [LICENSE](LICENSE) for details.
