package free5gc.ngap.ngapType

data class PDUSessionUsageReport(
    val RATType: Int, // Assuming aper.Enumerated can be mapped to an Int in Kotlin
    val PDUSessionTimedReportList: VolumeTimedReportList,
    val IEExtensions: ProtocolExtensionContainerPDUSessionUsageReportExtIEs? = null // Assuming this is a custom type that needs to be defined in Kotlin
)

