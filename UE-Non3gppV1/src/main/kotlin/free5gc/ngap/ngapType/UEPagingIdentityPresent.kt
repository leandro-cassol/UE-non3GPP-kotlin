package free5gc.ngap.ngapType

enum class UEPagingIdentityPresent(val value: Int) {
    UEPagingIdentityPresentNothing(0),
    UEPagingIdentityPresentFiveGSTMSI(1),
    UEPagingIdentityPresentChoiceExtensions(2)
}

class UEPagingIdentity(
    var present: UEPagingIdentityPresent,
    var fiveGSTMSI: FiveGSTMSI? = null,
    var choiceExtensions: ProtocolIESingleContainerUEPagingIdentityExtIEs? = null
)


