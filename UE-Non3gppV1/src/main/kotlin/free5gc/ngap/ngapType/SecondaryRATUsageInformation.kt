package free5gc.ngap.ngapType

data class SecondaryRATUsageInformation(
    val pDUSessionUsageReport: PDUSessionUsageReport? = null,
    val qosFlowsUsageReportList: QoSFlowsUsageReportList? = null,
    val iEExtension: ProtocolExtensionContainerSecondaryRATUsageInformationExtIEs? = null
)

