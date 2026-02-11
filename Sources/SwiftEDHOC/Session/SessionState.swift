import Foundation

/// EDHOC session state machine states
enum SessionState: Sendable {
    case start
    case waitM2
    case verifiedM1
    case waitM3
    case verifiedM2
    case waitM4OrDone
    case completed
}
