package free5gc.ngap.ngapType

enum class PDUSessionType(val value: Int) {
    PresentIpv4(0),
    PresentIpv6(1),
    PresentIpv4v6(2),
    PresentEthernet(3),
    PresentUnstructured(4)
}


