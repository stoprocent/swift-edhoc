import Foundation

/// KDF labels used in EDHOC key derivation (RFC 9528 Section 4)
public enum KDFLabel: Int, Sendable {
    case keystream2 = 0         // KEYSTREAM_2
    case salt3e2m = 1           // SALT_3e2m
    case mac2 = 2               // MAC_2
    case k3 = 3                 // K_3
    case iv3 = 4                // IV_3
    case salt4e3m = 5           // SALT_4e3m (RFC 9528 correct label; TS code erroneously uses 7)
    case mac3 = 6               // MAC_3
    case prkOut = 7             // PRK_out
    case k4 = 8                 // K_4
    case iv4 = 9                // IV_4
    case prkExporter = 10       // PRK_exporter
    case keyUpdate = 11         // Key update
}
