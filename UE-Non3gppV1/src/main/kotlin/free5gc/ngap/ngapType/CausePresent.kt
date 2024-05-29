package free5gc.ngap.ngapType

enum class CausePresent(val value: Int) {
    Nothing(0),
    RadioNetwork(1),
    Transport(2),
    Nas(3),
    Protocol(4),
    Misc(5),
    ChoiceExtensions(6)
}

data class Cause(
    var present: CausePresent,
    var radioNetwork: CauseRadioNetwork? = null,
    var transport: CauseTransport? = null,
    var nas: CauseNas? = null,
    var protocol: CauseProtocol? = null,
    var misc: CauseMisc? = null,
    var choiceExtensions: ProtocolIESingleContainerCauseExtIEs? = null
)