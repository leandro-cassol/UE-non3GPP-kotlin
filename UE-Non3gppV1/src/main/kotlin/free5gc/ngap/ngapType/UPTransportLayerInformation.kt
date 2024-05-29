package free5gc.ngap.ngapType

enum class UPTransportLayerInformationPresent(val value: Int) {
    UPTransportLayerInformationPresentNothing(0),
    UPTransportLayerInformationPresentGTPTunnel(1),
    UPTransportLayerInformationPresentChoiceExtensions(2) // Assuming the iota increments as in Go
}

data class UPTransportLayerInformation(
    var present: UPTransportLayerInformationPresent,
    var gtpTunnel: GTPTunnel?, // Assuming GTPTunnel is a class you have defined elsewhere
    var choiceExtensions: ProtocolIESingleContainerUPTransportLayerInformationExtIEs? // Assuming ProtocolIESingleContainerUPTransportLayerInformationExtIEs is a class you have defined elsewhere
)


