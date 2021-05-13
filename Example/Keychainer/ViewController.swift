//
//  ViewController.swift
//  Keychainer
//
//  Created by lunnersword@163.com on 05/08/2021.
//  Copyright (c) 2021 lunnersword@163.com. All rights reserved.
//

import UIKit
import Keychainer
import LocalAuthentication

/// The username and password that we want to store or read.
struct Credentials {
    var username: String
    var password: String
}

extension KeychainItem where Attributes == InternetPasswordAttributes {
    var credential: Credentials? {
        guard let account = attributes?.account,
            let passwordData = data,
            let password = String(data: passwordData, encoding: String.Encoding.utf8) else {
            return nil
        }
        return Credentials(username: account, password: password)
    }
}

class ViewController: UIViewController {

    /// A text label used to show the result of an operation.
    @IBOutlet weak var statusLabel: UILabel!

    /// The server we are accessing with the credentials.
    let server = "www.example.com"

    /// Keychain errors we might encounter.
    struct KeychainError: Error {
        var status: OSStatus

        var localizedDescription: String {
            return SecCopyErrorMessageString(status, nil) as String? ?? "Unknown error."
        }
    }

    let userNames = ["appleseed", "huawei", "lunner", "sword", "fuck"]
    // MARK: - Actions

    @IBAction func tapAdd(_ sender: Any) {
        // Normally, username and password would come from the user interface.
        let index = Int.random(in: 0..<5)
        let credentials = Credentials(username: userNames[index], password: "added")

        do {
            try addCredentials(credentials, server: server)
            show(status: "Added credentials. \(userNames[index])")
        } catch {
            if let error = error as? KeychainError {
                show(status: error.localizedDescription)
            }
        }
    }

    @IBAction func tapSet(_ sender: Any) {
        let index = Int.random(in: 0..<5)
        let credentials = Credentials(username: userNames[index], password: "seted")
        do {
            try setCredentials(credentials, server: server)
            show(status: "Set credentials. \(userNames[index])")
        } catch {
            if let error = error as? KeychainError {
                show(status: error.localizedDescription)
            }
        }
    }

    @IBAction func tapUpdate(_ sender: Any) {
        let index = Int.random(in: 0..<5)
        let credentials = Credentials(username: userNames[index], password: "updated")

        do {
            try updateCredentials(credentials, server: server)
            show(status: "Updated credentials. \(userNames[index])")
        } catch {
            if let error = error as? KeychainError {
                show(status: error.localizedDescription)
            }
        }
    }

    @IBAction func tapRead(_ sender: Any) {
        let index = Int.random(in: 0..<5)

        do {
            let cre = try readCredentials(userName: userNames[index], server: server)
            show(status: "Read credentials. \(cre?.username), \(cre?.password)")
        } catch {
            if let error = error as? KeychainError {
                show(status: error.localizedDescription)
            }
        }

    }

    @IBAction func tapDelete(_ sender: Any) {
        let index = Int.random(in: 0..<5)

        do {
            let cre = try deleteCredentials(userName: userNames[index], server: server)
            show(status: "Deleted credentials.  \(userNames[index])")
        } catch {
            if let error = error as? KeychainError {
                show(status: error.localizedDescription)
            }
        }
    }

    @IBAction func tapReadAll(_ sender: Any) {
        do {
            let credentials = try readAllCredentials(server: server)
            show(status: "Read credentials count: \(credentials?.count)")
        } catch {
            if let error = error as? KeychainError {
                show(status: error.localizedDescription)
            }
        }

    }

    @IBAction func tapDeleteAll(_ sender: Any) {
        do {
            try deleteAllCredentials(server: server)
            show(status: "Deleted credentials.")
        } catch {
            if let error = error as? KeychainError {
                show(status: error.localizedDescription)
            }
        }
    }

    /// Draws the status string on the screen, including a partial fade out.
    func show(status: String) {
        statusLabel.alpha = 1
        statusLabel.text = status
        UIView.animate(withDuration: 0.5, delay: 1, options: [], animations: { self.statusLabel.alpha = 0.3 }, completion: nil)
    }

    // MARK: - Keychain Access

    /// Stores credentials for the given server.
    func addCredentials(_ credentials: Credentials, server: String) throws {
        // Use the username as the account, and get the password as data.
//        let account = credentials.username
//        let password = credentials.password.data(using: String.Encoding.utf8)!
//
//        // Create an access control instance that dictates how the item can be read later.
//        let access = SecAccessControlCreateWithFlags(nil, // Use the default allocator.
//                                                     kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
//                                                     .userPresence,
//                                                     nil) // Ignore any error.
//
//        // Allow a device unlock in the last 10 seconds to be used to get at keychain items.
//        let context = LAContext()
//        context.touchIDAuthenticationAllowableReuseDuration = 10
//
//        // Build the query for use in the add operation.
//        let query: [String: Any] = [kSecClass as String: kSecClassInternetPassword,
//                                    kSecAttrAccount as String: account,
//                                    kSecAttrServer as String: server,
//                                    kSecAttrAccessControl as String: access as Any,
//                                    kSecUseAuthenticationContext as String: context,
//                                    kSecValueData as String: password]
//
//        let status = SecItemAdd(query as CFDictionary, nil)
//        guard status == errSecSuccess else { throw KeychainError(status: status) }

        let account = credentials.username
        let password = credentials.password.data(using: String.Encoding.utf8)!

        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 10

        try Keychain.internet(server: server)
            .accessibility(.whenPasscodeSetThisDeviceOnly, authenticationPolicy: .userPresence)
            .authenticationContext(context)
            .add(account, value: password)
    }

    func setCredentials(_ credentials: Credentials, server: String) throws {

        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 10

        try Keychain.internet(server: server)
            .accessibility(.whenPasscodeSetThisDeviceOnly, authenticationPolicy: .userPresence)
            .authenticationContext(context)
            .set(credentials.username, value: credentials.password)
    }

    func updateCredentials(_ credentials: Credentials, server: String) throws {
        try Keychain.internet(server: server)
            .update(credentials.username, value: credentials.password)
    }

    func readCredentials(userName: String, server: String) throws -> Credentials? {
//                let query: [String: Any] = [kSecClass as String: kSecClassInternetPassword,
//                                            kSecAttrServer as String: server,
//                                            kSecAttrAccount as String: userName,
//                                            kSecMatchLimit as String: kSecMatchLimitOne,
//                                            kSecReturnAttributes as String: true,
//                                            kSecUseOperationPrompt as String: "Access your password on the keychain",
//                                            kSecReturnData as String: true]
        //
        //        var item: CFTypeRef?
        //        let status = SecItemCopyMatching(query as CFDictionary, &item)
        //        guard status == errSecSuccess else { throw KeychainError(status: status) }
        //
        //        guard let existingItem = item as? [String: Any],
        //              let passwordData = existingItem[kSecValueData as String] as? Data,
        //              let password = String(data: passwordData, encoding: String.Encoding.utf8),
        //              let account = existingItem[kSecAttrAccount as String] as? String
        //        else {
        //            throw KeychainError(status: errSecInternalError)
        //        }


        let context = LAContext()
        context.localizedReason = "Access your password on the keychain. I'm a custom propmt"

        let keychain = Keychain.internet(server: server)
            .authenticationContext(context)


        guard let item = try keychain.item(userName) else {
            return nil
        }
        return item.credential
    }

    /// Reads the stored credentials for the given server.
    func readAllCredentials(server: String) throws -> [Credentials]? {
        let context = LAContext()
        context.localizedReason = "Access your password on the keychain"

        let keychain = Keychain.internet(server: server)
            .authenticationContext(context)

        guard let items = try keychain.allItems() else {
            return nil
        }
        return items.compactMap { $0.credential }
    }

    func deleteCredentials(userName: String, server: String) throws {
//                let query: [String: Any] = [kSecClass as String: kSecClassInternetPassword,
//                                            kSecAttrServer as String: server,
//                                            kSecAttrAccount as String: userName]

        //
        //        let status = SecItemDelete(query as CFDictionary)
        //        guard status == errSecSuccess else { throw KeychainError(status: status) }
        try Keychain.internet(server: server)
            .delete(userName)
    }

    /// Deletes credentials for the given server.
    func deleteAllCredentials(server: String) throws {
//        let query: [String: Any] = [kSecClass as String: kSecClassInternetPassword,
//                                    kSecAttrServer as String: server]
//
//        let status = SecItemDelete(query as CFDictionary)
//        guard status == errSecSuccess else { throw KeychainError(status: status) }
        try Keychain.internet(server: server)
            .deleteAll()
    }
}


