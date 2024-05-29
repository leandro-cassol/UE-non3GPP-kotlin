package free5gc.ngap.ngapType

data class UEAggregateMaximumBitRate(
    val UEAggregateMaximumBitRateDL: BitRate,
    val UEAggregateMaximumBitRateUL: BitRate,
    val IEExtensions: ProtocolExtensionContainerUEAggregateMaximumBitRateExtIEs? = null
)

