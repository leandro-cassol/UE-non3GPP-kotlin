package free5gc.ngap.ngapType

data class QoSFlowsUsageReportItem(
    val qosFlowIdentifier: QosFlowIdentifier,
    val ratType: Int, // Assuming aper.Enumerated can be represented as an Int in Kotlin
    val qoSFlowsTimedReportList: VolumeTimedReportList,
    val ieExtensions: ProtocolExtensionContainerQoSFlowsUsageReportItemExtIEs? = null
)