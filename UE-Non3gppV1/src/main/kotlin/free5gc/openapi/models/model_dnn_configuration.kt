package free5gc.openapi.models

import java.net.InetAddress

data class DnnConfiguration(
    val pduSessionTypes: PduSessionTypes?,
    val sscModes: SscModes?,
    val iwkEpsInd: Boolean,
    val var5gQosProfile: SubscribedDefaultQos?,
    val sessionAmbr: Ambr?,
    val var3gppChargingCharacteristics: String,
    val staticIpAddress: List<InetAddress>,
    val upSecurity: UpSecurity?
)


