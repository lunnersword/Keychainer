// https://github.com/Quick/Quick

import Quick
import Nimble
import Keychainer
import LocalAuthentication

struct Account: Equatable {
    var username: String
    var password: String

    static func mockAccounts(_ count: UInt) -> [Account] {
        var cres: [Account] = []
        for i in 0..<count {
            let cre = Account(username: "lunner#\(i)", password: "lunner#\(i)password")
            cres.append(cre)
        }
        return cres
    }
    static func == (lhs: Self, rhs: Self) -> Bool {
        return lhs.username == rhs.username && lhs.password == rhs.password
    }
}

struct KeyData: Equatable {
    let network: String
    let sessionId: String
    let curve: Int
    let data: Data
    let publicKey: String

    static func mockKeyDatas(_ count: Int) -> [KeyData] {
        var cres: [KeyData] = []
        for i in 0..<count {
            guard let keydata = "password \(i)".data(using: .utf8, allowLossyConversion: false) else {
                continue
            }
            let cre = KeyData(network: "network \(i)", sessionId: "sessionId \(i)", curve: i, data: keydata, publicKey: "publicKey +\(i)")
            cres.append(cre)
        }
        return cres
    }
    static func == (lhs: Self, rhs: Self) -> Bool {
        return lhs.sessionId == rhs.sessionId && lhs.data == rhs.data && lhs.curve == rhs.curve
    }
}

extension KeychainItem {
    var account: Account? {
        guard let account = attributes?.account,
              let passwordData = data,
              let password = String(data: passwordData, encoding: String.Encoding.utf8) else {
            return nil
        }
        return Account(username: account, password: password)
    }

    var keyData: KeyData? {
        guard let network = attributes?.label,
              let sessionId = attributes?.account,
              let curve = attributes?.type,
              let keyData = data,
              let publicKey = attributes?.comment else {
            return nil
        }
        return KeyData(network: network, sessionId: sessionId, curve: curve, data: keyData, publicKey: publicKey)
    }
}

extension Keychain {
    static func getKeyData(sessionId: String) throws -> KeyData? {
        let service = "lunnersword.Keychain.Sign.test"
        let keychain = Keychain.generic(service: service)
        return try keychain.item(sessionId)?.keyData
    }

    static func add(_ key: KeyData) throws {
        let service = "lunnersword.Keychain.Sign.test"
        let keychain = Keychain.generic(service: service)
            .accessibility(.whenUnlockedThisDeviceOnly, authenticationPolicy: .userPresence)
        try keychain.label(key.network)
            .type(key.curve)
            .comment(key.publicKey)
            .add(key.sessionId, value: key.data)
    }

    static func update(_ key: KeyData) throws {
        let service = "lunnersword.Keychain.Sign.test"
        let keychain = Keychain.generic(service: service)
        try keychain.label(key.network)
            .type(key.curve)
            .comment(key.publicKey)
            .update(key.sessionId, value: key.data)
    }

    static func set(_ key: KeyData) throws {
        let service = "lunnersword.Keychain.Sign.test"
        let keychain = Keychain.generic(service: service)
        try keychain.label(key.network)
            .type(key.curve)
            .comment(key.publicKey)
            .set(key.sessionId, value: key.data)
    }
}

class GenericPasswordSpec: QuickSpec {
    override func spec() {
        describe("generic") {
            let service = "lunnersword.Keychain.test"
            var keychain = Keychain.generic(service: service)
            let accounts = Account.mockAccounts(5)
            let accountNotInKeychain = Account(username: "NotExistingKey", password: "passwordshouldnotbeenstored")
            beforeSuite {
                let context = LAContext()
                context.touchIDAuthenticationAllowableReuseDuration = 10

                keychain = keychain
                    .accessibility(.whenPasscodeSetThisDeviceOnly, authenticationPolicy: .userPresence)
                    .authenticationContext(context)
            }
            afterSuite {
                do {
                    try keychain.deleteAll()
                } catch {
                    print("afterSuite failed: \(error)")
                }
            }

            beforeEach {
                for account in accounts {
                    do {
                        try keychain.add(account.username, value: account.password)
                    } catch {
                        expect(error).to(beNil())
                    }
                }
            }

            afterEach {
                do {
                try keychain.deleteAll()
                } catch {
                    expect(error).to(beNil())
                }
            }

            context("add and read items") {
                it("add items") {
                    // first clear all
                    try? keychain.deleteAll()
                    for account in accounts {
                        do {
                            try keychain.add(account.username, value: account.password)
                        } catch {
                            expect(error).to(beNil())
                        }
                    }
                }
                it("add duplicate items") {
                    for account in accounts {
                        do {
                            try keychain.add(account.username, value: account.password)
                        } catch {
                            expect(error).to(beAnInstanceOf(Status.self))
                            let status = error as! Status
                            expect(status).to(equal(.duplicateItem))
                        }
                    }
                }

                it("read item by key") {
                    for account in accounts {
                        do {
                            let accountItem = try keychain.item(account.username)?.account
                            expect(accountItem).notTo(beNil())
                            expect(accountItem?.username).to(equal(account.username))
                            expect(accountItem?.password).to(equal(account.password))
                        } catch {
                            expect(error).to(beNil())
                        }
                    }
                }

                it("read all items") {
                    do {
                        let gotAccounts = try keychain.allItems()?.compactMap{ $0.account }
                        expect(gotAccounts).notTo(beNil())
                        expect(gotAccounts?.count).to(equal(accounts.count))
                        expect(gotAccounts).to(equal(accounts))
                    } catch {
                        expect(error).to(beNil())
                    }
                }

                it("read item not existing") {
                    do {
                        let account = try keychain.item("notExistingKey")?.account
                        expect(account).to((beNil()))
                    } catch {
                        expect(error).to(beNil())
                    }
                }
            }

            context("update and delete items") {
                it("update item") {
                    for account in accounts {
                        do {
                            let user = account.username
                            let password = account.password + "updated"
                            try keychain.update(user, value: password)
                            let updated = try keychain.item(user)?.account
                            expect(updated).notTo(beNil())
                            expect(updated?.username).to(equal(user))
                            expect(updated?.password).to(equal(password))
                            //                         update back
                            try keychain.update(user, value: account.password)
                            let backed = try keychain.item(user)?.account
                            expect(backed).notTo(beNil())
                            expect(backed?.username).to(equal(account.username))
                            expect(backed?.password).to(equal(account.password))
                        } catch {
                            expect(error).to(beNil())
                        }
                    }
                }

                it("update item not existing") {
                    do {
                        try keychain.update(accountNotInKeychain.username, value: accountNotInKeychain.password)
                        let shouldNotUpdated = try keychain.item(accountNotInKeychain.username)?.account
                        expect(shouldNotUpdated).to(beNil())
                    } catch {
                        expect(error).to(beAnInstanceOf(Status.self))
                        let status = error as! Status
                        expect(status).to(equal(.itemNotFound))
                    }
                }

                it("delete item") {
                    for account in accounts {
                        do {
                            try keychain.delete(account.username)
                            let deleted = try keychain.item(account.username)?.account
                            expect(deleted).to(beNil())

                        } catch {
                            expect(error).notTo(beNil())
                        }
                    }

                    do {
                        let gotAccounts = try keychain.allItems()?.compactMap{ $0.account }
                        expect(gotAccounts?.count) == 0
                    } catch {
                        expect(error).to(beNil())
                    }
                }

                it("delete item not existing") {
                    do {
                        // if item not existing, keychain will do nothing.
                        try keychain.delete(accountNotInKeychain.username)
                    } catch {
                        expect(error).to(beNil())
                    }
                }

                it("delete all") {
                    do {
                        let gotAccounts = try keychain.allItems()?.compactMap{ $0.account }
                        expect(gotAccounts?.count) == 5

                        try keychain.deleteAll()
                        let deletedAccounts = try keychain.allItems()?.compactMap{ $0.account }
                        expect(deletedAccounts?.count) == 0
                    } catch {
                        expect(error).to(beNil())
                    }
                }
            }

            context("set item") {
                it("set new item") {
                    do {
                        let newAccount = Account(username: "I'm a new account", password: "new account's password")
                        try keychain.set(newAccount.username, value: newAccount.password)
                        let got = try keychain.item(newAccount.username)?.account
                        expect(got).toNot(beNil())
                        expect(got) == newAccount
                    } catch {
                        expect(error).to(beNil())
                    }
                }

                it("set existing item with new value") {
                    do {
                        let gotAccounts = try keychain.allItems()?.compactMap{ $0.account }
                        expect(gotAccounts?.count) == 5
                        expect(gotAccounts) == accounts

                        for account in accounts {
                            try keychain.set(account.username, value: account.password+"seted")
                            let got = try keychain.item(account.username)?.account
                            expect(got).notTo(beNil())
                            expect(got?.password) == account.password + "seted"
                        }
                    } catch {
                        expect(error).to(beNil())
                    }
                }

                it("set existing item with old value") {
                    do {
                        let gotAccounts = try keychain.allItems()?.compactMap{ $0.account }
                        expect(gotAccounts?.count) == 5
                        expect(gotAccounts) == accounts

                        for account in accounts {
                            try keychain.set(account.username, value: account.password)
                            let got = try keychain.item(account.username)?.account
                            expect(got).notTo(beNil())
                            expect(got) == account
                        }

                        let setedAccounts = try keychain.allItems()?.compactMap{ $0.account }
                        expect(setedAccounts) == accounts
                    } catch {
                        expect(error).to(beNil())
                    }
                }
            }

            describe("options") {
                context("assigned after the item is added") {
                    describe("label") {
                        let label = "Item's Label"
                        it("add item") {
                            do {
                                try keychain.label(label)
                                    .add(accounts[0].username, value: accounts[0].password)
                            } catch {
                                expect(error).to(beAnInstanceOf(Status.self))
                                let status = error as! Status
                                expect(status).to(equal(.duplicateItem))
                            }
                        }
                        it("read item") {
                            do {
                                let account = try keychain.label(label)
                                    .item(accounts[0].username)?.account
                                expect(account).to(beNil())
                            } catch {
                                expect(error).to(beNil())
                            }
                        }
                        it("update item") {
                            do {
                                let oldItem = try keychain.item(accounts[0].username)
                                expect(oldItem?.attributes?.label).to(beNil())

                                try keychain.label(label).update(accounts[0].username, value: accounts[0].password + "updated")
                                let item = try keychain.item(accounts[0].username)
                                expect(item?.account).notTo(beNil())
                                expect(item?.account?.password) != accounts[0].password
                                expect(item?.attributes?.label) == label
                            } catch {
                                expect(error).to(beNil())
                            }
                        }
                        it("set item") {
                            do {
                                let oldItem = try keychain.item(accounts[0].username)
                                expect(oldItem?.attributes?.label).to(beNil())

                                try keychain.label(label).set(accounts[0].username, value: accounts[0].password + "seted")
                                let item = try keychain.item(accounts[0].username)
                                expect(item?.account).notTo(beNil())
                                expect(item?.account) != accounts[0]
                                expect(item?.account?.password) == accounts[0].password + "seted"
                                expect(item?.attributes?.label) == label
                            } catch {
                                expect(error).to(beNil())
                            }
                        }
                    }
                }

                context("assigned while adding the item") {
                    describe("label") {
                        let label = "Item's Label"
                        let account = Account(username: "Account for label", password: "Account for label password")
                        let oldKeychain =  keychain
                        let keychain = keychain.label(label)

                        beforeEach {
                            do {
                                try keychain
                                    .add(account.username, value: account.password)
                            } catch {
                                expect(error).to(beNil())
                            }
                        }
                        afterEach {
                            do {
                                // 删除所有以label是"Item's Label"的item
                                try keychain.deleteAll()
                            } catch {
                                expect(error).to(beNil())
                            }
                        }
                        it("add existing item") {
                            do {
                                try keychain.label(label)
                                    .add(account.username, value: account.password)
                            } catch {
                                expect(error).to(beAnInstanceOf(Status.self))
                                let status = error as! Status
                                expect(status).to(equal(.duplicateItem))
                            }
                        }
                        it("read item") {
                            do {
                                let item = try keychain.item(account.username)
                                expect(item?.account) == account
                                expect(item?.attributes?.label) == label
                            } catch {
                                expect(error).to(beNil())
                            }
                        }
                        it("duplicate assign while reading item") {
                            do {
                                let item = try keychain.label(label).item(account.username)
                                expect(item?.account) == account
                                expect(item?.attributes?.label) == label
                            } catch {
                                expect(error).to(beNil())
                            }
                        }

                        it("not assign while reading item") {
                            do {
                                let item = try oldKeychain.item(account.username)
                                expect(item?.account) == account
                                expect(item?.attributes?.label) == label
                            } catch {
                                expect(error).to(beNil())
                            }
                        }

                        it("update item") {
                            do {
                                try keychain.update(account.username, value: account.password + "updated")
                                let item = try keychain.item(account.username)
                                expect(item?.account) != account
                                expect(item?.account?.password) == account.password + "updated"
                                expect(item?.attributes?.label) == label
                            } catch {
                                expect(error).to(beNil())
                            }
                        }

                        it("duplicate assign while updating item") {
                            do {
                                try keychain.label(label).label(label).update(account.username, value: account.password + "updated")
                                let item = try keychain.item(account.username)
                                expect(item?.account) != account
                                expect(item?.account?.password) == account.password + "updated"
                                expect(item?.attributes?.label) == label
                            } catch {
                                expect(error).to(beNil())
                            }
                        }

                        it("not assign while updating item") {
                            do {
                                try oldKeychain.update(account.username, value: account.password + "updated")
                                let item = try keychain.item(account.username)
                                expect(item?.account) != account
                                expect(item?.account?.password) == account.password + "updated"
                                expect(item?.attributes?.label) == label
                            } catch {
                                expect(error).to(beNil())
                            }
                        }

                        context("set") {
                            it("set item") {
                                do {
                                    let newAccount = Account(username: "I'm a new account", password: "new account's password")
                                    try keychain.set(newAccount.username, value: newAccount.password)
                                    let item = try keychain.item(newAccount.username)
                                    expect(item?.account).toNot(beNil())
                                    expect(item?.account) == newAccount
                                    expect(item?.attributes?.label) == label
                                } catch {
                                    expect(error).to(beNil())
                                }
                            }

                            it("duplicate assign while setting item") {
                                do {
                                    try keychain.label(label).label(label)
                                        .set(account.username, value: account.password + "setted")
                                    let item = try keychain.item(account.username)
                                    expect(item?.account) != account
                                    expect(item?.account?.password) == account.password + "setted"
                                    expect(item?.attributes?.label) == label
                                } catch {
                                    expect(error).to(beNil())
                                }
                            }
                        }
                    }
                }

            }
        }

        describe("KeyData") {
            let service = "lunnersword.Keychain.Sign.test"
            var keychain = Keychain.generic(service: service)
            let keyDatas = KeyData.mockKeyDatas(50)
            let keyNotInKeychain = KeyData(network: "unkonw", sessionId: "NotExistingID", curve: 0, data: Data(bytes: [1, 2, 3]), publicKey: "non")

            beforeSuite {
                let context = LAContext()
                context.touchIDAuthenticationAllowableReuseDuration = 5

                keychain = keychain
                    .accessibility(.whenUnlockedThisDeviceOnly, authenticationPolicy: .userPresence)
                    .authenticationContext(context)
            }
            afterSuite {
                do {
                    try keychain.deleteAll()
                } catch {
                    print("afterSuite failed: \(error)")
                }
            }

            beforeEach {
                for key in keyDatas {
                    do {
                        try keychain.label(key.network)
                            .type(key.curve)
                            .comment(key.publicKey)
                            .add(key.sessionId, value: key.data)
                    } catch {
                        expect(error).to(beNil())
                    }
                }
            }

            afterEach {
                do {
                    try keychain.deleteAll()
                } catch {
                    expect(error).to(beNil())
                }
            }

            context("add and read Keys") {
                it("add items") {
                    try? keychain.deleteAll()

                    for key in keyDatas {
                        do {
                            try Keychain.add(key)
                        } catch {
                            expect(error).to(beNil())
                        }
                    }
                }
                it("add duplicate items") {
                    for key in keyDatas {
                        do {
                            try Keychain.add(key)
                        } catch {
                            expect(error).to(beAnInstanceOf(Status.self))
                            let status = error as! Status
                            expect(status).to(equal(.duplicateItem))
                        }
                    }
                }
                it("read item by key(sessionId)") {
                    var i = 0
                    for key in keyDatas {
                        do {
                            let keyItem = try Keychain.getKeyData(sessionId: key.sessionId)
                            expect(keyItem).notTo(beNil())
                            expect(keyItem?.sessionId).to(equal(key.sessionId))
                            expect(keyItem?.data).to(equal(key.data))
                            expect(keyItem?.publicKey).to(equal(key.publicKey))
                            expect(keyItem?.network).to(equal(key.network))
                            expect(keyItem?.curve).to(equal(key.curve))
                            expect(keyItem?.curve).to(equal(i))
                        } catch {
                            expect(error).to(beNil())
                        }
                        i += 1
                    }
                }

                it("read all items") {
                    do {
                        let gotKeys = try keychain.allItems()?.compactMap{ $0.keyData }
                        expect(gotKeys).notTo(beNil())
                        expect(gotKeys?.count).to(equal(keyDatas.count))
                        expect(gotKeys).to(equal(keyDatas))
                    } catch {
                        expect(error).to(beNil())
                    }
                }

                it("read item not existing") {
                    do {
                        let keyItem = try Keychain.getKeyData(sessionId: "notExistingKey")
                        expect(keyItem).to((beNil()))
                    } catch {
                        expect(error).to(beNil())
                    }
                }
            }

            context("update and delete items") {
                it("update key") {
                    for key in keyDatas {
                        do {
                            let sessionId = key.sessionId
                            var data = key.data
                            data.append(contentsOf: [7, 77])
                            let newKey = KeyData(network: key.network + "updated", sessionId: key.sessionId, curve: 22, data: data, publicKey: key.publicKey + "updated")
                            try Keychain.update(newKey)
                            let updated = try keychain.item(sessionId)?.keyData
                            expect(updated).notTo(beNil())
                            expect(updated).to(equal(newKey))
                            expect(updated?.sessionId).to(equal(sessionId))
                            expect(updated?.curve).to(equal(22))
                            expect(updated?.network).to(equal(key.network + "updated"))
                            expect(updated?.publicKey).to(equal(key.publicKey + "updated"))
                            //                         update back
                            try keychain.update(sessionId, value: key.data)
                            let backed = try keychain.item(sessionId)?.keyData
                            expect(backed).notTo(beNil())
                            expect(backed?.sessionId).to(equal(key.sessionId))
                            expect(backed?.data).to(equal(key.data))
                        } catch {
                            expect(error).to(beNil())
                        }
                    }
                }

                it("update item not existing") {
                    do {
                        try keychain.update(keyNotInKeychain.sessionId, value: keyNotInKeychain.data)
                        let shouldNotUpdated = try keychain.item(keyNotInKeychain.sessionId)?.account
                        expect(shouldNotUpdated).to(beNil())
                    } catch {
                        expect(error).to(beAnInstanceOf(Status.self))
                        let status = error as! Status
                        expect(status).to(equal(.itemNotFound))
                    }
                }

                it("delete item") {
                    for key in keyDatas {
                        do {
                            try keychain.delete(key.sessionId)
                            let deleted = try keychain.item(key.sessionId)?.keyData
                            expect(deleted).to(beNil())

                        } catch {
                            expect(error).notTo(beNil())
                        }
                    }

                    do {
                        let gotKeys = try keychain.allItems()?.compactMap{ $0.keyData }
                        expect(gotKeys?.count) == 0
                    } catch {
                        expect(error).to(beNil())
                    }
                }

                it("delete item not existing") {
                    do {
                        // if item not existing, keychain will do nothing.
                        try keychain.delete(keyNotInKeychain.sessionId)
                    } catch {
                        expect(error).to(beNil())
                    }
                }

                it("delete all") {
                    do {
                        let gotKeys = try keychain.allItems()?.compactMap{ $0.keyData }
                        expect(gotKeys?.count) == 50

                        try keychain.deleteAll()
                        let deletedKeys = try keychain.allItems()?.compactMap{ $0.keyData }
                        expect(deletedKeys?.count) == 0
                    } catch {
                        expect(error).to(beNil())
                    }
                }
            }

            context("set item") {
                it("set new item") {
                    do {
                        let newAccount = Account(username: "I'm a new account", password: "new account's password")
                        let newKey = KeyData(network: "I'm a new key", sessionId: "NewSessionId", curve: 199, data: Data(bytes: [1, 2, 3, 4]), publicKey: "newnewnew")

                        try Keychain.set(newKey)
                        let got = try keychain.item(newKey.sessionId)?.keyData
                        expect(got).toNot(beNil())
                        expect(got) == newKey
                    } catch {
                        expect(error).to(beNil())
                    }
                }

                it("set existing item with new value") {
                    do {
                        let gotKeys = try keychain.allItems()?.compactMap{ $0.keyData }
                        expect(gotKeys?.count) == 50
                        expect(gotKeys) == keyDatas

                        for key in keyDatas {
                            var newData = key.data
                            newData.append(contentsOf: [1, 3, 5, 7])
                            let new = KeyData(network: key.network + "seted", sessionId: key.sessionId, curve: key.curve + 100, data: newData, publicKey: key.publicKey + "seted")
                            try Keychain.set(new)
                            let got = try keychain.item(key.sessionId)?.keyData
                            expect(got).notTo(beNil())
                            expect(got) == new
                            expect(got?.network) == key.network + "seted"
                        }
                    } catch {
                        expect(error).to(beNil())
                    }
                }

                it("set existing item with old value") {
                    do {
                        let gotKeys = try keychain.allItems()?.compactMap{ $0.keyData }
                        expect(gotKeys?.count) == 50
                        expect(gotKeys) == keyDatas

                        for key in keyDatas {
                            try Keychain.set(key)
                            let got = try keychain.item(key.sessionId)?.keyData
                            expect(got).notTo(beNil())
                            expect(got) == key
                        }

                        let setedKeys = try keychain.allItems()?.compactMap{ $0.keyData }
                        expect(setedKeys) == keyDatas
                    } catch {
                        expect(error).to(beNil())
                    }
                }
            }

        }
    }
}
