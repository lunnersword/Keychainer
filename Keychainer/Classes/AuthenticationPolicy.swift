import Foundation

public struct AuthenticationPolicy: OptionSet {

    public static let userPresence = AuthenticationPolicy(rawValue: SecAccessControlCreateFlags.userPresence.rawValue)

    @available(iOS 11.3, *)
    public static let biometryAny = AuthenticationPolicy(rawValue: SecAccessControlCreateFlags.biometryAny.rawValue)

    @available(iOS 11.3, *)
    public static let biometryCurrentSet = AuthenticationPolicy(rawValue: SecAccessControlCreateFlags.biometryCurrentSet.rawValue)

    public static let devicePasscode = AuthenticationPolicy(rawValue: SecAccessControlCreateFlags.devicePasscode.rawValue)

    public static let or = AuthenticationPolicy(rawValue: SecAccessControlCreateFlags.or.rawValue)

    public static let and = AuthenticationPolicy(rawValue: SecAccessControlCreateFlags.and.rawValue)

    public static let privateKeyUsage = AuthenticationPolicy(rawValue: SecAccessControlCreateFlags.privateKeyUsage.rawValue)

    public static let applicationPassword = AuthenticationPolicy(rawValue: SecAccessControlCreateFlags.applicationPassword.rawValue)


    public let rawValue: UInt

    public init(rawValue: UInt) {
        self.rawValue = rawValue
    }
}
