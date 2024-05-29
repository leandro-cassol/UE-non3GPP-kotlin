package free5gc.ngap.ngapType

enum class UserLocationInformationPresent(val value: Int) {
    UserLocationInformationPresentNothing(0),
    UserLocationInformationPresentUserLocationInformationEUTRA(1),
    UserLocationInformationPresentUserLocationInformationNR(2),
    UserLocationInformationPresentUserLocationInformationN3IWF(3),
    UserLocationInformationPresentChoiceExtensions(4)
}

data class UserLocationInformation(
    var present: UserLocationInformationPresent,
    var userLocationInformationEUTRA: UserLocationInformationEUTRA? = null,
    var userLocationInformationNR: UserLocationInformationNR? = null,
    var userLocationInformationN3IWF: UserLocationInformationN3IWF? = null,
    var choiceExtensions: ProtocolIESingleContainerUserLocationInformationExtIEs? = null
)