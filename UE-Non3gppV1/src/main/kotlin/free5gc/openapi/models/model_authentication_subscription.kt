package free5gc.openapi.models

class AuthenticationSubscription {
    var authenticationMethod: AuthMethod? = null
    var permanentKey: PermanentKey? = null
    var sequenceNumber: String = ""
    var authenticationManagementField: String = ""
    var vectorAlgorithm: VectorAlgorithm? = null
    var milenage: Milenage? = null
    var tuak: Tuak? = null
    var opc: Opc? = null
    var topc: Topc? = null
    var sharedAuthenticationSubscriptionId: SharedData? = null
}
