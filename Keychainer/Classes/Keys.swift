import Foundation

// TODO: use enum to define keys
/** Class Key Constant */
let Class = String(kSecClass)

/** Attribute Key Constants */
let AttributeAccessible = String(kSecAttrAccessible)

@available(iOS 8.0, OSX 10.10, *)
let AttributeAccessControl = String(kSecAttrAccessControl)

let AttributeAccessGroup = String(kSecAttrAccessGroup)
let AttributeSynchronizable = String(kSecAttrSynchronizable)
let AttributeCreationDate = String(kSecAttrCreationDate)
let AttributeModificationDate = String(kSecAttrModificationDate)
let AttributeDescription = String(kSecAttrDescription)
let AttributeComment = String(kSecAttrComment)
let AttributeCreator = String(kSecAttrCreator)
let AttributeType = String(kSecAttrType)
let AttributeLabel = String(kSecAttrLabel)
let AttributeIsInvisible = String(kSecAttrIsInvisible)
let AttributeIsNegative = String(kSecAttrIsNegative)
let AttributeAccount = String(kSecAttrAccount)
let AttributeService = String(kSecAttrService)
let AttributeGeneric = String(kSecAttrGeneric)
let AttributeSecurityDomain = String(kSecAttrSecurityDomain)
let AttributeServer = String(kSecAttrServer)
let AttributeProtocol = String(kSecAttrProtocol)
let AttributeAuthenticationType = String(kSecAttrAuthenticationType)
let AttributePort = String(kSecAttrPort)
let AttributePath = String(kSecAttrPath)

let SynchronizableAny = kSecAttrSynchronizableAny

/** Search Constants */
let MatchLimit = String(kSecMatchLimit)
let MatchLimitOne = kSecMatchLimitOne
let MatchLimitAll = kSecMatchLimitAll

/** Return Type Key Constants */
let ReturnData = String(kSecReturnData)
let ReturnAttributes = String(kSecReturnAttributes)
let ReturnRef = String(kSecReturnRef)
let ReturnPersistentRef = String(kSecReturnPersistentRef)

/** Value Type Key Constants */
let ValueData = String(kSecValueData)
let ValueRef = String(kSecValueRef)
let ValuePersistentRef = String(kSecValuePersistentRef)

/** Other Constants */

let UseAuthenticationUI = String(kSecUseAuthenticationUI)

let UseAuthenticationContext = String(kSecUseAuthenticationContext)

let UseAuthenticationUISkip = String(kSecUseAuthenticationUISkip)

#if os(iOS) && !targetEnvironment(macCatalyst)
/** Credential Key Constants */
let SharedPassword = String(kSecSharedPassword)
#endif
