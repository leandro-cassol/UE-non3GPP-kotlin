package free5gc.ngap.ngapType

enum class DLNGUTNLInformationReusedPresentTrue(val value: Int) {
    True(0)
}

data class DLNGUTNLInformationReused(
    val value: DLNGUTNLInformationReusedPresentTrue
)


