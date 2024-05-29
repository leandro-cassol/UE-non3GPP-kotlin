package free5gc.ngap.ngapType

enum class SONInformationRequestPresentXnTNLConfigurationInfo(val value: Int) {
    XnTNLConfigurationInfo(0)
}

data class SONInformationRequest(
    val value: SONInformationRequestPresentXnTNLConfigurationInfo
)


