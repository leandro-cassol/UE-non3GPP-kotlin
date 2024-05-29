package free5gc.ngap.ngapType

data class PDUSessionAggregateMaximumBitRate(
    val pDUSessionAggregateMaximumBitRateDL: BitRate,
    val pDUSessionAggregateMaximumBitRateUL: BitRate,
    val iEExtensions: ProtocolExtensionContainerPDUSessionAggregateMaximumBitRateExtIEs? = null
)