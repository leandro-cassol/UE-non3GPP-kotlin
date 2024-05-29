package free5gc.ngap.ngapType

import org.example.free5gc.ngap.ngapType.AMFRegionID

data class GUAMI(
    val pLMNIdentity: PLMNIdentity,
    val aMFRegionID: AMFRegionID,
    val aMFSetID: AMFSetID,
    val aMFPointer: AMFPointer,
    val iEExtensions: ProtocolExtensionContainerGUAMIExtIEs? = null
)
