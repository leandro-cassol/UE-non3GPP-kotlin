package free5gc.ngap.ngapType

enum class UEContextRequestPresentRequested(val value: Int) {
    Requested(0)
}

data class UEContextRequest(
    val value: UEContextRequestPresentRequested
)