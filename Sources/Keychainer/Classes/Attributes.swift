import Foundation

public protocol BaseAttributes {
    var accessGroup: String? { get }
    var accessible: String? { get }
    var label: String? { get }
}

public protocol PasswordAttributes: BaseAttributes, CustomStringConvertible, CustomDebugStringConvertible {
    var accessGroup: String? { get }
    var accessible: String? { get }
    var creationDate: Date? { get }
    var modificationDate: Date? { get }
    var attributeDescription: String? { get }
    var comment: String? { get }
    var creator: String? { get }
    var type: Int? { get }
    var label: String? { get }
    var isInvisible: Bool? { get }
    var isNegative: Bool? { get }
    var account: String? { get }
    var synchronizable: Bool? { get }

    init(attributes: [String: Any])
}

extension PasswordAttributes {

    var toString: String {
        var desc = "<"
        if let accessGroup = accessGroup {
            desc += "accessGroup: \(accessGroup),"
        }
        if let accessible = accessible {
            desc += "accessible: \(accessible),"
        }
        if let creationDate = creationDate {
            desc += "creationDate: \(creationDate),"
        }
        if let modificationDate = modificationDate {
            desc += "modificationDate: \(modificationDate),"
        }
        if let attrDesc = attributeDescription {
            desc += "description: \(attrDesc),"
        }
        if let comment = comment {
            desc += "comment: \(comment),"
        }
        if let creator = creator {
            desc += "creator: \(creator),"
        }
        if let type = type {
            desc += "type: \(type),"
        }
        if let label = label {
            desc += "label: \(label),"
        }
        if let isInvisible = isInvisible {
            desc += "isInvisible: \(isInvisible),"
        }
        if let isNegative = isNegative {
            desc += "isNegative: \(isNegative),"
        }
        if let account = account {
            desc += "account: \(account),"
        }
        if let synchronizable = synchronizable {
            desc += "synchronizable: \(synchronizable),"
        }
        desc += ">"
        return desc
    }

    public var description: String {
        return toString
    }

    public var debugDescription: String {
        return toString
    }
}

public struct GenericPasswordAttributes: PasswordAttributes {
    public var accessControl: SecAccessControl?
    public var accessGroup: String?
    public var accessible: String?
    public var creationDate: Date?
    public var modificationDate: Date?
    public var attributeDescription: String?
    public var comment: String?
    public var creator: String?
    public var type: Int?
    public var label: String?
    public var isInvisible: Bool?
    public var isNegative: Bool?
    public var account: String?
    public var service: String?
    public var generic: Data?
    public var synchronizable: Bool?

    public init(attributes: [String: Any]) {
        if let accessControl = attributes[AttributeAccessControl] {
            self.accessControl = (accessControl as! SecAccessControl)
        }
        self.accessGroup = attributes[AttributeAccessGroup] as? String
        self.accessible = attributes[AttributeAccessible] as? String
        self.creationDate = attributes[AttributeCreationDate] as? Date
        self.modificationDate = attributes[AttributeModificationDate] as? Date
        self.attributeDescription = attributes[AttributeDescription] as? String
        self.comment = attributes[AttributeComment] as? String
        self.creator = attributes[AttributeCreator] as? String
        self.type = attributes[AttributeType] as? Int
        self.label = attributes[AttributeLabel] as? String
        self.isInvisible = attributes[AttributeIsInvisible] as? Bool
        self.isNegative = attributes[AttributeIsNegative] as? Bool
        self.account = attributes[AttributeAccount] as? String
        self.service = attributes[AttributeService] as? String
        self.generic = attributes[AttributeGeneric] as? Data
        self.synchronizable = attributes[AttributeSynchronizable] as? Bool
    }

    private var _description: String {
        var desc = toString
        desc.removeLast()
        desc += "service: \(String(describing: service)),"
        desc += "generic: \(String(describing: generic)),"
        desc += ">"
        return desc
    }

    public var description: String {
        return _description
    }

    public var debugDescription: String {
        return _description
    }
}

public struct InternetPasswordAttributes: PasswordAttributes {
    public var accessGroup: String?
    public var accessible: String?
    public var creationDate: Date?
    public var modificationDate: Date?
    public var attributeDescription: String?
    public var comment: String?
    public var creator: String?
    public var type: Int?
    public var label: String?
    public var isInvisible: Bool?
    public var isNegative: Bool?
    public var account: String?
    public var securityDomain: String?
    public var server: String?
    public var `protocol`: InternetProtocol?
    public var authenticationType: InternetAuthenticationType?
    public var port: Int?
    public var path: String?
    public var synchronizable: Bool?

    public init(attributes: [String: Any]) {
        self.accessGroup = attributes[AttributeAccessGroup] as? String
        self.accessible = attributes[AttributeAccessible] as? String
        self.creationDate = attributes[AttributeCreationDate] as? Date
        self.modificationDate = attributes[AttributeModificationDate] as? Date
        self.attributeDescription = attributes[AttributeDescription] as? String
        self.comment = attributes[AttributeComment] as? String
        self.creator = attributes[AttributeCreator] as? String
        self.type = attributes[AttributeType] as? Int
        self.label = attributes[AttributeLabel] as? String
        self.isInvisible = attributes[AttributeIsInvisible] as? Bool
        self.isNegative = attributes[AttributeIsNegative] as? Bool
        self.account = attributes[AttributeAccount] as? String
        self.synchronizable = attributes[AttributeSynchronizable] as? Bool
        self.securityDomain = attributes[AttributeSecurityDomain] as? String
        self.server = attributes[AttributeServer] as? String
        self.protocol = (attributes[AttributeProtocol] as? String).map { InternetProtocol(rawValue: $0) } as? InternetProtocol
        self.authenticationType = (attributes[AttributeAuthenticationType] as? String).map { InternetAuthenticationType(rawValue: $0) } as? InternetAuthenticationType
        self.port = attributes[AttributePort] as? Int
        self.path = attributes[AttributePath] as? String
    }

    private var _description: String {
        var desc = toString
        desc.removeLast()
        desc += "server: \(String(describing: server)),"
        desc += "path: \(String(describing: path)),"
        desc += "port: \(String(describing: port)),"
        desc += "protocol: \(String(describing: `protocol`)),"
        desc += "securityDomain: \(String(describing: securityDomain)),"
        desc += "authenticationType: \(String(describing: authenticationType)),"
        desc += ">"
        return desc
    }

    public var description: String {
        return _description
    }

    public var debugDescription: String {
        return _description
    }
}

public struct CertificateAttributes {
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

public struct KeyAttributes {
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
