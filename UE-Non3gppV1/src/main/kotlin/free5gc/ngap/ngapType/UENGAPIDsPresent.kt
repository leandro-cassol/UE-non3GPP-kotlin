package free5gc.ngap.ngapType

enum class UENGAPIDsPresent {
    UENGAPIDsPresentNothing,
    UENGAPIDsPresentUENGAPIDPair,
    UENGAPIDsPresentAMFUENGAPID,
    UENGAPIDsPresentChoiceExtensions
}

data class UENGAPIDs(
    val present: UENGAPIDsPresent,
    val uENGAPIDPair: UENGAPIDPair? = null,
    val aMFUENGAPID: AMFUENGAPID? = null,
    val choiceExtensions: ProtocolIESingleContainerUENGAPIDsExtIEs? = null
)
