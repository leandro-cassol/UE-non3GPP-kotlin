package free5gc.ngap.ngapType

data class VolumeTimedReportItem(
    val startTimeStamp: ByteArray, // Assuming aper.OctetString maps to ByteArray in Kotlin
    val endTimeStamp: ByteArray, // Assuming aper.OctetString maps to ByteArray in Kotlin
    val usageCountUL: Long,
    val usageCountDL: Long,
    val iEExtensions: ProtocolExtensionContainerVolumeTimedReportItemExtIEs? = null // Assuming it's a defined type elsewhere
)