package free5gc.ngap.ngapType

enum class SONInformationPresent(val value: Int) {
    SONInformationPresentNothing(0),
    SONInformationPresentSONInformationRequest(1),
    SONInformationPresentSONInformationReply(2),
    SONInformationPresentChoiceExtensions(3)
}

class SONInformation(
    var present: SONInformationPresent,
    var sONInformationRequest: SONInformationRequest?,
    var sONInformationReply: SONInformationReply?,
    var choiceExtensions: ProtocolIESingleContainerSONInformationExtIEs?
)


