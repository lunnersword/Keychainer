import Foundation
import LocalAuthentication

public enum Action {
    case read, add, update, delete
}

public protocol KeychainOptions: CustomStringConvertible, CustomDebugStringConvertible {
    //    kSecAttrAccess (macOS only)
    var securityClass: SecurityClass { get }

    var accessGroup: String? { get set }
    var accessibility: Accessibility { get set }
    var label: String? { get set }
//    var data: Data? { get set }

    var authenticationContext: LAContext? { get set }
    var shouldSkipAuthenticationUI: Bool? { get set }
    var authenticationPolicy: AuthenticationPolicy? { get set }

    mutating func update(with attributes: [String: Any])

    func query() -> [String: Any]
    func query(_ action: Action) throws -> [String: Any]
}

public protocol BasePasswordOptions: KeychainOptions {
    var account: String { get set }

    var comment: String? { get set }
    var label: String? { get set }

    var synchronizable: Bool? { get set }
    var ignoreSynchronizable: Bool? { get set }
}

public protocol GenericPasswordOptions: BasePasswordOptions {
    var service: String { get set }
    var generic: Data? { get set }
}

public protocol InternetPaswordOptions: BasePasswordOptions {
    var server: String { get set }
    var port: Int? { get set }
    var `protocol`: InternetProtocol? { get set }
    var authenticationType: InternetAuthenticationType? { get set }
    var securityDomain: String? { get set }
    var path: String? { get set }
}

public struct KeychainGenericPasswordOptions: GenericPasswordOptions {

    public var service: String

    public var comment: String?
    public var accessGroup: String?
    public var accessibility: Accessibility = .afterFirstUnlock

    public var authenticationContext: LAContext?
    public var authenticationPolicy: AuthenticationPolicy?
    // Only use this value with the SecItemCopyMatching(_:_:) function.
    public var shouldSkipAuthenticationUI: Bool?

    // custom option
    public var forceUpdate: Bool?

    public var data: Data?

    public var generic: Data?
    public var account: String = ""
    public var label: String?
    public var synchronizable: Bool?
    public var ignoreSynchronizable: Bool?

    public var securityClass: SecurityClass = .genericPassword

    public mutating func update(with attributes: [String : Any]) {
    }
}

public struct KeychainInternetPasswordOptions: InternetPaswordOptions {

    public var server: String

    public var comment: String?

    public var label: String?

    public var accessibility: Accessibility = .afterFirstUnlock

    public var authenticationContext: LAContext?
    public var shouldSkipAuthenticationUI: Bool?
    public var authenticationPolicy: AuthenticationPolicy?

    public var data: Data?

    public var port: Int?

    public var `protocol`: InternetProtocol?
    public var authenticationType: InternetAuthenticationType?

    public var securityDomain: String?

    public var path: String?

    public var account: String = ""

    public var accessGroup: String?

    public var synchronizable: Bool?
    public var ignoreSynchronizable: Bool?

    public let securityClass: SecurityClass = .internetPassword

    public mutating func update(with attributes: [String : Any]) {

    }
}

extension KeychainOptions {
    var _optionsString: String {
        var desc = "\(type(of: self)){"
        desc += "itemClass: \(securityClass),"
        desc += "accessGroup: \(String(describing: accessGroup)),"
        desc += "accessibility: \(String(describing: accessibility)),"
        desc += "label: \(String(describing: label)),"
        desc += "shouldSkipAuthenticationUI: \(String(describing: shouldSkipAuthenticationUI)),"
        desc += "authenticationPolicy: \(String(describing: authenticationPolicy)),"
        desc += "}"
        return desc
    }

    public var description: String {
        return _optionsString
    }

    public var debugDescription: String {
        return _optionsString
    }
}

extension BasePasswordOptions {

    var _passwordOptionsString: String {
        var desc = _optionsString
        desc.removeLast()
        desc += "account: \(account),"
        desc += "comment: \(String(describing: comment)),"
        desc += "synchronizable: \(String(describing: synchronizable)),"
        desc += "}"
        return desc
    }

    public var description: String {
        return _passwordOptionsString
    }

    public var debugDescription: String {
        return _passwordOptionsString
    }

    func _access() throws -> [String: Any] {
        var attributes = [String: Any]()

        if let policy = authenticationPolicy {
            var error: Unmanaged<CFError>?
            guard let accessControl = SecAccessControlCreateWithFlags(nil, accessibility.rawValue as CFTypeRef, SecAccessControlCreateFlags(rawValue: CFOptionFlags(policy.rawValue)), &error) else {
                if let error = error?.takeUnretainedValue() {
                    throw error.error
                }
                throw Status.unexpectedError
            }
            attributes[AttributeAccessControl] = accessControl as Any
            attributes[UseAuthenticationContext] = authenticationContext
        } else {
            attributes = [AttributeAccessible: accessibility.rawValue]
        }
        return attributes
    }

    func _query() -> [String: Any] {
        var query = [String: Any]()
        query[Class] = securityClass.rawValue
        query[AttributeAccessGroup] = accessGroup
        if ignoreSynchronizable == .some(true) {
            query[AttributeSynchronizable] = SynchronizableAny
        } else if let synchronizable = self.synchronizable {
            query[AttributeSynchronizable] = synchronizable ? kCFBooleanTrue : kCFBooleanFalse
        }

        query[AttributeLabel] = label
        query[AttributeComment] = comment

        return query
    }

    func _searchOnlyQuery() -> [String: Any] {
        var query: [String: Any] = [:]
        // TODO: LAContext?
        let shouldSkip = shouldSkipAuthenticationUI ?? false
        query[UseAuthenticationUI] = shouldSkip ? UseAuthenticationUISkip : nil
        return query
    }

    public func query(_ action: Action) throws -> [String : Any] {
        switch action {
            case .update, .delete:
                return query()
            case .read:
                let queries = query()
                return queries.merging(_searchOnlyQuery()) { (_, new) in new }
            case .add:
                let querys = query()
                let accessControls = try _access()

                let addQuery = querys.merging(accessControls) { (_, other)  in other }
                return addQuery
        }
    }
}

extension GenericPasswordOptions {
    var _genericOptionsString: String {
        var desc = _passwordOptionsString
        desc.removeLast()
        desc += "service: \(service),"
        desc += "generic: \(String(describing: generic)),"
        desc += "}"
        return desc
    }
    public var description: String {
        return _genericOptionsString
    }

    public var debugDescription: String {
        return _genericOptionsString
    }

    public func query() -> [String : Any] {
        var query = _query()
        query[AttributeService] = service
        query[AttributeGeneric] = generic
        return query
    }
}

extension InternetPaswordOptions {
    var _internetOptionsString: String {
        var desc = _passwordOptionsString
        desc.removeLast()
        desc += "server: \(String(describing: server)),"
        desc += "path: \(String(describing: path)),"
        desc += "port: \(String(describing: port)),"
        desc += "protocol: \(String(describing: `protocol`)),"
        desc += "securityDomain: \(String(describing: securityDomain)),"
        desc += "authenticationType: \(String(describing: authenticationType)),"
        desc += "}"
        return desc
    }
    public var description: String {
        return _internetOptionsString
    }

    public var debugDescription: String {
        return _internetOptionsString
    }

    public func query() -> [String : Any] {
        var query = _query()
        query[AttributeServer] = server
        query[AttributePath] = path
        query[AttributePort] = port
        query[AttributeProtocol] = `protocol`?.rawValue
        query[AttributeAuthenticationType] = authenticationType?.rawValue
        query[AttributeSecurityDomain] = securityDomain
        return query
    }
}

public protocol CertificateOptions: KeychainOptions {
//    kSecAttrAccess (macOS only)
//    kSecAttrAccessGroup (iOS only)
//    kSecAttrAccessible (iOS only)
//    kSecAttrCertificateType
//    kSecAttrCertificateEncoding
//    kSecAttrLabel
//    kSecAttrSubject
//    kSecAttrIssuer
//    kSecAttrSerialNumber
//    kSecAttrSubjectKeyID
//    kSecAttrPublicKeyHash
}

public protocol KeyOptions: KeychainOptions {
//    kSecAttrAccess (macOS only)
//    kSecAttrAccessGroup (iOS only)
//    kSecAttrAccessible (iOS only)
//    kSecAttrKeyClass
//    kSecAttrLabel
//    kSecAttrApplicationLabel
//    kSecAttrIsPermanent
//    kSecAttrApplicationTag
//    kSecAttrKeyType
//    kSecAttrPRF
//    kSecAttrSalt
//    kSecAttrRounds
//    kSecAttrKeySizeInBits
//    kSecAttrEffectiveKeySize
//    kSecAttrCanEncrypt
//    kSecAttrCanDecrypt
//    kSecAttrCanDerive
//    kSecAttrCanSign
//    kSecAttrCanVerify
//    kSecAttrCanWrap
//    kSecAttrCanUnwrap
}

public protocol IdentityOptions: KeyOptions, CertificateOptions {
    // An identity is a certificate paired with its associated private key. Because an identity is the combination of a private key and a certificate, this class shares attributes of both kSecClassKey and kSecClassCertificate.
}
