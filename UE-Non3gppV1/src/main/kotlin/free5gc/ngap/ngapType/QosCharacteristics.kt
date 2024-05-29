package free5gc.ngap.ngapType

enum class QosCharacteristicsPresent(val value: Int) {
    Nothing(0),
    NonDynamic5QI(1),
    Dynamic5QI(2),
    ChoiceExtensions(3)
}

data class QosCharacteristics(
    var present: QosCharacteristicsPresent,
    var nonDynamic5QI: NonDynamic5QIDescriptor? = null,
    var dynamic5QI: Dynamic5QIDescriptor? = null,
    var choiceExtensions: ProtocolIESingleContainerQosCharacteristicsExtIEs? = null
)
