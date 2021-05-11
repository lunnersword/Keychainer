import Foundation
import LocalAuthentication

public enum KeychainItemClass: RawRepresentable, CustomStringConvertible {
    case genericPassword, internetPassword
    public init?(rawValue: RawValue) {
        switch rawValue {
            case String(kSecClassGenericPassword):
                self = .genericPassword
            case String(kSecClassInternetPassword):
                self = .internetPassword
            default:
                return nil
        }
    }
    public var rawValue: String {
        switch self {
            case .genericPassword:
                return String(kSecClassGenericPassword)
            case .internetPassword:
                return String(kSecClassInternetPassword)
        }
    }
    public var description: String {
        switch self {
            case .genericPassword:
                return "GenericPassword"
            case .internetPassword:
                return "InternetPassword"
        }
    }

}


public struct KeychainItem<Attributes: PasswordAttributes> {
    public let itemClass: KeychainItemClass
    public let data: Data?
    public var attributes: Attributes?

    public func toString() -> String? {
        guard let data = data else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }
}

extension KeychainItem: CustomStringConvertible, CustomDebugStringConvertible {

    private var _description: String {
        var description = "\(type(of: self)){"
        description += "itemClass: "
        description += "\(itemClass),"
        description += "data: "
        description += "\(String(describing: toString())),"
        description += "attributes: "
        description += "\(String(describing: attributes))"
        description += "}"
        return description
    }
    
    public var description: String {
        return _description
    }

    public var debugDescription: String {
        return _description
    }
}
