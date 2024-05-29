package free5gc.ngap.ngapType

data class CriticalityDiagnosticsIEItem(
    val iECriticality: Criticality,
    val iEID: ProtocolIEID,
    val typeOfError: TypeOfError,
    val iEExtensions: ProtocolExtensionContainerCriticalityDiagnosticsIEItemExtIEs? = null
)


