import Foundation
import Security
#if os(iOS) || os(OSX)
import LocalAuthentication
#endif

struct KeychainForGenericPassword: GeneralKeychain {
    var options: KeychainGenericPasswordOptions

    init(options: KeychainGenericPasswordOptions) {
        self.options = options
    }

    init() {
        let service: String = Bundle.main.bundleIdentifier ?? ""
        self.options = KeychainGenericPasswordOptions(service: service)
    }
}

struct KeychainForInternetPassword: InternetKeychain {
    var options: KeychainInternetPasswordOptions

    init(options: KeychainInternetPasswordOptions) {
        self.options = options
    }

    init() {
        let server: String = ""
        self.options = KeychainInternetPasswordOptions(server: server)
    }
}

public protocol GeneralKeychain: PasswordKeychain {
    var options: KeychainGenericPasswordOptions { get set }

    func allItems() throws -> [KeychainItem<GenericPasswordAttributes>]?
    func item(_ key: String) throws -> KeychainItem<GenericPasswordAttributes>?
}

extension GeneralKeychain {
    func allItems() throws -> [KeychainItem<GenericPasswordAttributes>]? {
        return try _allItems()
    }
    func item(_ key: String) throws -> KeychainItem<GenericPasswordAttributes>? {
        return try _item(key)
    }
}

public protocol InternetKeychain: PasswordKeychain {
    var options: KeychainInternetPasswordOptions { get set}

    func allItems() throws -> [KeychainItem<InternetPasswordAttributes>]?
    func item(_ key: String) throws -> KeychainItem<InternetPasswordAttributes>?
}

extension InternetKeychain {
    func allItems() throws -> [KeychainItem<InternetPasswordAttributes>]? {
        return try _allItems()
    }
    func item(_ key: String) throws -> KeychainItem<InternetPasswordAttributes>? {
        return try _item(key)
    }
}

public protocol PasswordKeychain {
    associatedtype Options: BasePasswordOptions
    var options: Options { get set }
    init(options: Options)

    // get the string presentaion of data of keychain item (kSecReturnData = true)
    func string(_ key: String) throws -> String?
    // get the data of Keychain Item only (kSecReturnData = true)
    func data(_ key: String) throws -> Data?

    // add item if not existing
    func add(_ key: String, value: Data) throws
    func add(_ key: String, value: String) throws

    // update item if existing
    func update(_ key: String, value: Data) throws
    func update(_ key: String, value: String) throws

    // if item existing then update it otherwise add it
    func set(_ key: String, value: Data) throws
    func set(_ key: String, value: String) throws

    func delete(_ key: String) throws
    func deleteAll() throws

    func contains(_ key: String) throws -> Bool
}

// MARK: -
extension PasswordKeychain {

    /// Set service for current item, service is only avaliable on generic password item
    /// You should this func only while operating  generic password item, otherwise it will return nil.
    /// - Parameter service: the service whice current item belongs to. The default value is your app's BundleID, if cannot fetch the BundleID, it will be setten to ""
    /// - Returns: KeychainForPassword
    public func service(_ service: String) -> Self? {
        guard options.securityClass == .genericPassword else {
            print("try to set server on non generic keychain, which is \(options.securityClass)")
            return nil
        }
        guard let genericOptions = options as? GenericPasswordOptions else {
            print("Unexpected error: options expected to be GenericPasswordOptions, but \(type(of: options))")
            return nil
        }
        var options = genericOptions
        options.service = service

        return Self(options: options as! Self.Options)
    }

    /// Setup internet password item (service, protocol, auth)
    /// You should this func only while operating  internet password item, otherwise it will return nil.
    /// - Parameters:
    ///   - server: the server url, default value is ""
    ///   - protocol: the protocol see InternetProtocol, default value is nil
    ///   - auth: the authentication method, default value is nil
    /// - Returns: KeychainForPassword
    public func server(_ server: String, protocol: InternetProtocol? = nil, auth: InternetAuthenticationType? = nil) -> Self? {
        guard options.securityClass == .internetPassword else {
            print("try to set server on non internet keychain, which is \(options.securityClass)")
            return nil
        }
        guard let internetOptions = options as? InternetPaswordOptions else {
            print("Unexpected error: options expected to be InternetPaswordOptions, but \(type(of: options))")
            return nil
        }
        var options = internetOptions
        options.server = server
        options.protocol = `protocol`
        options.authenticationType = auth

        return Self(options: options as! Self.Options)
    }

    public func accessGroup(_ accessGroup: String) -> Self {
        var options = self.options
        options.accessGroup = accessGroup
        return Self(options: options)
    }

    public func accessibility(_ accessibility: Accessibility) -> Self {
        var options = self.options
        options.accessibility = accessibility
        return Self(options: options)
    }

    public func accessibility(_ accessibility: Accessibility, authenticationPolicy: AuthenticationPolicy) -> Self {
        var options = self.options
        options.accessibility = accessibility
        options.authenticationPolicy = authenticationPolicy
        return Self(options: options)
    }

    public func authenticationContext(_ authenticationContext: LAContext) -> Self {
        var options = self.options
        options.authenticationContext = authenticationContext
        return Self(options: options)
    }

    public func synchronizable(_ synchronizable: Bool) -> Self {
        var options = self.options
        options.synchronizable = synchronizable
        return Self(options: options)
    }

    public func label(_ label: String) -> Self {
        var options = self.options
        options.label = label
        return Self(options: options)
    }

    public func comment(_ comment: String) -> Self {
        var options = self.options
        options.comment = comment
        return Self(options: options)
    }

    public func attributes(_ attributes: [String: Any]) -> Self {
        var options = self.options
        options.update(with: attributes)
        return Self(options: options)
    }

    public func skipAuthenticationUI(_ shouldSkip: Bool) -> Self {
        var options = self.options
        options.shouldSkipAuthenticationUI = shouldSkip
        return Self(options: options)
    }
}

extension PasswordKeychain {
    func _allItems<T>() throws -> [KeychainItem<T>]? where T: PasswordAttributes {
        let query = try options.query(.read)
        let result = try allItems(query: query)
        var items: [KeychainItem<T>] = []
        for dict in result {
            let data = dict[ValueData] as? Data
            let attributes = T(attributes: dict)
            let item = KeychainItem<T>(itemClass: options.securityClass.itemClass!, data: data, attributes: attributes)
            items.append(item)
        }
        return items
    }

    func _item<T>(_ key: String) throws -> KeychainItem<T>? where T : PasswordAttributes {
        let query = try options.query(.read)
        guard let result = try item(key: key, query: query) else {
            return nil
        }

        let data = result[ValueData] as? Data
        let attributes = T(attributes: result)
        let item = KeychainItem<T>(itemClass: options.securityClass.itemClass!, data: data, attributes: attributes)
        return item
    }

    func string(_ key: String) throws -> String? {
        let query = try options.query(.read)
        guard let result = try string(key: key, query: query) else {
            return nil
        }
        return result
    }

    func data(_ key: String) throws -> Data? {
        let query = try options.query(.read)
        guard let result = try data(key: key, query: query) else {
            return nil
        }
        return result
    }

    func add(_ key: String, value: Data) throws {
        let query = try options.query(.add)
        try add(key: key, data: value, query: query)
    }

    func add(_ key: String, value: String) throws {
        let query = try options.query(.add)
        try add(key: key, string: value, query: query)
    }

    func update(_ key: String, value: Data) throws {
        let query = try options.query(.update)
        let attributes = try options.query(.add)
        try update(key: key, data: value, query: query, attributes: attributes)
    }

    func update(_ key: String, value: String) throws {
        let query = try options.query(.update)
        let attributes = try options.query(.add)
        try update(key: key, string: value, query: query, attributes: attributes)
    }

    func set(_ key: String, value: Data) throws {
        let query = try options.query(.update)
        let addQuery = try options.query(.add)
        try set(key: key, data: value, query: query, addQuery: addQuery)
    }

    func set(_ key: String, value: String) throws {
        let query = try options.query(.update)
        let addQuery = try options.query(.add)
        try set(key: key, string: value, query: query, addQuery: addQuery)
    }

    func delete(_ key: String) throws {
        let query = try options.query(.delete)
        try doDelete(key: key, query: query)
    }

    func deleteAll() throws {
        let query = try options.query(.delete)
        try doDelete(key: nil, query: query)
    }

    func contains(_ key: String) throws  -> Bool {
        let query = try options.query(.read)
        let skip = query.skipAuthUI
        return try contains(key: key, query: query, skipAuthUI: skip)
    }
}

extension PasswordKeychain {
    // MARK: - get item
    func allItems(query: [String: Any]) throws -> [[String: Any]] {
        var query = query
        query[MatchLimit] = MatchLimitAll
        query[ReturnData] = kCFBooleanTrue
        query[ReturnAttributes] = kCFBooleanTrue

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess else {
            if status == errSecItemNotFound {
                return []
            } else {
                throw doError(status: status)
            }
        }
        guard let items = result as? [[String: Any]] else {
            // TODO: ADD Log
            return []
        }
        return items
    }

    func item(key: String, query: [String: Any]) throws -> [String: Any]? {
        var query = query
        query[MatchLimit] = MatchLimitOne
        query[ReturnData] = kCFBooleanTrue
        query[ReturnAttributes] = kCFBooleanTrue
        query[AttributeAccount] = key
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            if status == errSecItemNotFound {
                return nil
            } else {
                throw doError(status: status)
            }
        }
        guard let existingItem = item as? [String: Any] else {
            throw Status.unexpectedError
        }
        return existingItem
    }

    func attributes(key: String, query: [String: Any]) throws -> [String: Any]? {
        var query = query
        query[MatchLimit] = MatchLimitOne
        query[ReturnAttributes] = kCFBooleanTrue
        query[AttributeAccount] = key

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else {
            if status == errSecCRLNotFound {
                return nil
            } else {
                throw doError(status: status)
            }
        }
        guard let attributes = result as? [String: Any] else {
            throw Status.unexpectedError
        }
        return attributes
    }

    func data(key: String, query: [String: Any]) throws -> Data? {
        var query = query
        query[MatchLimit] = MatchLimitOne
        query[ReturnData] = kCFBooleanTrue
        query[AttributeAccount] = key

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else {
            if status == errSecCRLNotFound {
                return nil
            } else {
                throw doError(status: status)
            }
        }
        guard let data = result as? Data else {
            throw Status.unexpectedError
        }
        return data
    }

    func string(key: String, query: [String: Any]) throws -> String? {
        guard let data = try data(key: key, query: query) else {
            return nil
        }
        guard let string = String(data: data, encoding: .utf8) else {
            // TODO: LOG
            print("failed to convert data (\(data)) to string")
            throw Status.conversionError
        }
        return string
    }

    func contains(key: String, query: [String: Any], skipAuthUI: Bool = false) throws -> Bool {
        var query = query
        query[AttributeAccount] = key
        query[UseAuthenticationUI] = skipAuthUI ? UseAuthenticationUISkip : nil

        let status = SecItemCopyMatching(query as CFDictionary, nil)
        switch status {
            case errSecSuccess:
                return true
            case errSecItemNotFound:
                return false
            default:
                throw doError(status: status)
        }
    }

    // MARK: - add item
    func add(key: String, data: Data, query: [String: Any]) throws {
        try doAdd(key: key, value: data, query: query)
    }

    func add(key: String, string: String, query: [String: Any]) throws {
        let data = try convertToData(string)
        try add(key: key, data: data, query: query)
    }

    // MARK: - update item
    func update(key: String, data: Data, query: [String: Any], attributes: [String: Any]) throws {
        let skip = query.skipAuthUI
        let existing = try contains(key: key, query: query, skipAuthUI: skip)

        guard existing else {
            throw doError(status: Status.itemNotFound.rawValue)
        }
        try doUpdate(key: key, value: data, query: query, attributes: attributes)
    }

    func update(key: String, string: String, query: [String: Any], attributes: [String: Any]) throws {
        let data = try convertToData(string)
        try update(key: key, data: data, query:query, attributes: attributes)
    }

    // MARK: - set item
    func set(key: String, data: Data, query: [String: Any], addQuery: [String: Any]) throws {
        let skip = query.skipAuthUI
        let existing = try contains(key: key, query: query, skipAuthUI: skip)
        if existing {
            try doUpdate(key: key, value: data, query: query, attributes: addQuery)
        } else {
            try doAdd(key: key, value: data, query: addQuery)
        }
    }

    func set(key: String, string: String, query: [String: Any], addQuery: [String: Any]) throws {
        let data = try convertToData(string)
        try set(key: key, data: data, query: query, addQuery: addQuery)
    }

    // MARK: -
    private func doAdd(key: String, value: Data, query: [String: Any]) throws {
        var query = query
        query[AttributeAccount] = key
        query[ValueData] = value
        let status = SecItemAdd(query as CFDictionary, nil)
        if status != errSecSuccess {
            throw doError(status: status)
        }
    }

    private func convertToData(_ string: String) throws -> Data {
        guard let data = string.data(using: .utf8, allowLossyConversion: false) else {
            print("failed to convert String to Data")
            throw Status.unexpectedError
        }
        return data
    }

    private func doUpdate(key: String, value: Data, query: [String: Any], attributes: [String: Any]) throws {
        var query = query
        query[AttributeAccount] = key

        var attributes = attributes.modifyingAttributes
        attributes[ValueData] = value

        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status != errSecSuccess {
            throw doError(status: status)
        }
    }

    private func doDelete(key: String?, query: [String: Any]) throws {
        var query = query
        query[AttributeAccount] = key

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw doError(status: status)
        }
    }

    @discardableResult
    fileprivate func doError(status: OSStatus) -> Error {
        let error = Status(status: status)
        if error != .userCanceled {
            print("\(type(of: self)) tOSStatus error:[\(error.errorCode)] \(error.description)")
        }
        return error
    }
}

extension Dictionary where Key == String, Value: Any {
    var skipAuthUI: Bool {
        guard let skipStr = self[UseAuthenticationUI] as? String else {
            return false
        }
        return skipStr == UseAuthenticationUISkip
    }
    var modifyingAttributes: [String: Any] {
        var attributes = [String: Any]()
        attributes[AttributeDescription] = self[AttributeDescription]
        attributes[AttributeComment] = self[AttributeComment]
        attributes[AttributeLabel] = self[AttributeLabel]
        attributes[AttributeAccount] = self[AttributeAccount]
        attributes[AttributeService] = self[AttributeService]
        attributes[AttributeGeneric] = self[AttributeGeneric]
        attributes[AttributeSynchronizable] = self[AttributeSynchronizable]
        attributes[AttributeServer] = self[AttributeServer]
        attributes[AttributeProtocol] = self[AttributeProtocol]
        attributes[AttributeAuthenticationType] = self[AttributeAuthenticationType]
        attributes[AttributePort] = self[AttributePort]
        attributes[AttributePath] = self[AttributePath] 
        return attributes
    }
}
