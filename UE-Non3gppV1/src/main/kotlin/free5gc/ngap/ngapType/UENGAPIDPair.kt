package free5gc.ngap.ngapType

import kotlinx.serialization.Serializable

data class UENGAPIDPair(
    val AMFUENGAPID: AMFUENGAPID,
    val RANUENGAPID: RANUENGAPID,
    val IEExtensions: ProtocolExtensionContainerUENGAPIDPairExtIEs? = null
)


