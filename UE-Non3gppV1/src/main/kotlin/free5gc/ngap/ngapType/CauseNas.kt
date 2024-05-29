package free5gc.ngap.ngapType

enum class CauseNas(val value: Int) {
    PresentNormalRelease(0),
    PresentAuthenticationFailure(1),
    PresentDeregister(2),
    PresentUnspecified(3)
}
