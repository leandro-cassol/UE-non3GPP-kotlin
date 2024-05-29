package free5gc.ngap.ngapType

data class GTPTunnel(
    val transportLayerAddress: TransportLayerAddress,
    val gtpTEID: GTPTEID,
    val ieExtensions: ProtocolExtensionContainerGTPTunnelExtIEs? = null
)
