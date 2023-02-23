import Foundation
import Security
#if os(iOS) || os(OSX)
import LocalAuthentication
#endif

public enum KeychainType {
    case generic
    case internet
}

public struct Keychain  {

    @available(iOS 13.0.0, *)
    public static var generic: some GeneralKeychain {
        KeychainForGenericPassword()
    }

    @available(iOS 13.0.0, *)
    public static var internet: some InternetKeychain {
        KeychainForInternetPassword()
    }

    @available(iOS 13.0.0, *)
    public static func generic(service: String) -> some GeneralKeychain {
        let options = KeychainGenericPasswordOptions(service: service)
        return KeychainForGenericPassword(options: options)
    }

    @available(iOS 13.0.0, *)
    public static func internet(server: String) -> some InternetKeychain {
        let options = KeychainInternetPasswordOptions(server: server)
        return KeychainForInternetPassword(options: options)
    }

    // MARK: - 向iOS 13.0 之前版本兼容
    private let type: KeychainType
    private var genericPassword: KeychainForGenericPassword!
    private var internetPassword: KeychainForInternetPassword!
    public init(_ type: KeychainType) {
        self.type = type
        switch type {
            case .generic:
                genericPassword = KeychainForGenericPassword()
            case .internet:
                internetPassword = KeychainForInternetPassword()
        }
    }

    private init(generic: KeychainForGenericPassword) {
        type = .generic
        genericPassword = generic
    }

    private init(internet: KeychainForInternetPassword) {
        type = .internet
        internetPassword = internet
    }

    /// Setup internet password item (service, protocol, auth)
    /// You should this func only while operating  internet password item, otherwise it will return nil.
    /// - Parameters:
    ///   - server: the server url, default value is ""
    ///   - protocol: the protocol see InternetProtocol, default value is nil
    ///   - auth: the authentication method, default value is nil
    /// - Returns: Keychain
    public func server(_ server: String, protocol: InternetProtocol? = nil, auth: InternetAuthenticationType? = nil) -> Self? {
        guard type == .internet else {
            print("try to set server on non internet keychain which is \(type)")
            return nil
        }
        var internetPassword: KeychainForInternetPassword = self.internetPassword
        internetPassword.options.server = server
        internetPassword.options.protocol = `protocol`
        internetPassword.options.authenticationType = auth
        return Keychain(internet: internetPassword)
    }

    /// Set service for current item, service is only avaliable on generic password item
    /// You should this func only while operating  generic password item, otherwise it will return nil.
    /// - Parameter service: the service whice current item belongs to. The default value is your app's BundleID, if cannot fetch the BundleID, it will be setten to ""
    /// - Returns: Keychain
    public func service(_ service: String) -> Self? {
        guard type == .generic else {
            // LOG
            print("try to set service on non generic keychain which is \(type)")
            return nil
        }
        var genericPassword: KeychainForGenericPassword = self.genericPassword
        genericPassword.options.service = service
        return Keychain(generic: genericPassword)
    }

    public func accessGroup(_ accessGroup: String) -> Self {
        switch type {
            case .generic:
                var generic: KeychainForGenericPassword = self.genericPassword
                generic.options.accessGroup = accessGroup
                return Keychain(generic: generic)
            case .internet:
                var internet: KeychainForInternetPassword = self.internetPassword
                internet.options.accessGroup = accessGroup
                return Keychain(internet: internet)
        }
    }

    public func accessibility(_ accessibility: Accessibility) -> Self {
        switch type {
            case .generic:
                var generic: KeychainForGenericPassword = self.genericPassword
                generic.options.accessibility = accessibility
                return Keychain(generic: generic)
            case .internet:
                var internet: KeychainForInternetPassword = self.internetPassword
                internet.options.accessibility = accessibility
                return Keychain(internet: internet)
        }
    }

    public func accessibility(_ accessibility: Accessibility, authenticationPolicy: AuthenticationPolicy) -> Self {
        switch type {
            case .generic:
                var generic: KeychainForGenericPassword = self.genericPassword
                generic.options.accessibility = accessibility
                generic.options.authenticationPolicy = authenticationPolicy
                return Keychain(generic: generic)
            case .internet:
                var internet: KeychainForInternetPassword = self.internetPassword
                internet.options.accessibility = accessibility
                internet.options.authenticationPolicy = authenticationPolicy
                return Keychain(internet: internet)
        }
    }

    public func synchronizable(_ synchronizable: Bool) -> Self {
        switch type {
            case .generic:
                var generic: KeychainForGenericPassword = self.genericPassword
                generic.options.synchronizable = synchronizable
                return Keychain(generic: generic)
            case .internet:
                var internet: KeychainForInternetPassword = self.internetPassword
                internet.options.synchronizable = synchronizable
                return Keychain(internet: internet)
        }
    }

    public func label(_ label: String) -> Self {
        switch type {
            case .generic:
                var generic: KeychainForGenericPassword = self.genericPassword
                generic.options.label = label
                return Keychain(generic: generic)
            case .internet:
                var internet: KeychainForInternetPassword = self.internetPassword
                internet.options.label = label
                return Keychain(internet: internet)
        }
    }

    public func type(_ type: Int) -> Self {
        switch self.type {
        case .generic:
            var generic: KeychainForGenericPassword = self.genericPassword
            generic.options.type = type
            return Keychain(generic: generic)
        case .internet:
            var internet: KeychainForInternetPassword = self.internetPassword
            internet.options.type = type
            return Keychain(internet: internet)
        }
    }

    public func comment(_ comment: String) -> Self {
        switch type {
            case .generic:
                var generic: KeychainForGenericPassword = self.genericPassword
                generic.options.comment = comment
                return Keychain(generic: generic)
            case .internet:
                var internet: KeychainForInternetPassword = self.internetPassword
                internet.options.comment = comment
                return Keychain(internet: internet)
        }
    }

    public func attributes(_ attributes: [String: Any]) -> Self {
        switch type {
            case .generic:
                var generic: KeychainForGenericPassword = self.genericPassword
                generic.options.update(with: attributes)
                return Keychain(generic: generic)
            case .internet:
                var internet: KeychainForInternetPassword = self.internetPassword
                internet.options.update(with: attributes)
                return Keychain(internet: internet)
        }
    }

    public func skipAuthenticationUI(_ shouldSkip: Bool) -> Self {
        switch type {
            case .generic:
                var generic: KeychainForGenericPassword = self.genericPassword
                generic.options.shouldSkipAuthenticationUI = shouldSkip
                return Keychain(generic: generic)
            case .internet:
                var internet: KeychainForInternetPassword = self.internetPassword
                internet.options.shouldSkipAuthenticationUI = shouldSkip
                return Keychain(internet: internet)
        }
    }

    public func authenticationContext(_ authenticationContext: LAContext) -> Self {
        switch type {
            case .generic:
                var generic: KeychainForGenericPassword = self.genericPassword
                generic.options.authenticationContext = authenticationContext
                return Keychain(generic: generic)
            case .internet:
                var internet: KeychainForInternetPassword = self.internetPassword
                internet.options.authenticationContext = authenticationContext
                return Keychain(internet: internet)
        }
    }

}

