package free5gc.ngap.ngapType

data class CriticalityDiagnostics(
    val procedureCode: ProcedureCode? = null,
    val triggeringMessage: TriggeringMessage? = null,
    val procedureCriticality: Criticality? = null,
    val iEsCriticalityDiagnostics: CriticalityDiagnosticsIEList? = null,
    val iEExtensions: ProtocolExtensionContainerCriticalityDiagnosticsExtIEs? = null
)


