package free5gc.ngap.ngapType

data class TraceActivation(
    val ngranTraceID: NGRANTraceID,
    val interfacesToTrace: InterfacesToTrace,
    val traceDepth: TraceDepth,
    val traceCollectionEntityIPAddress: TransportLayerAddress,
    val ieExtensions: ProtocolExtensionContainerTraceActivationExtIEs? = null
)
