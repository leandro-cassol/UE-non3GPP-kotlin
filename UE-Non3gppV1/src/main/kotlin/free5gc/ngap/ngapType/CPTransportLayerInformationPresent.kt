package free5gc.ngap.ngapType

enum class CPTransportLayerInformationPresent(val value: Int) {
    Nothing(0),
    EndpointIPAddress(1),
    ChoiceExtensions(2)
}

data class CPTransportLayerInformation(
    val present: CPTransportLayerInformationPresent,
    val endpointIPAddress: TransportLayerAddress?,
    val choiceExtensions: ProtocolIESingleContainerCPTransportLayerInformationExtIEs?
)


