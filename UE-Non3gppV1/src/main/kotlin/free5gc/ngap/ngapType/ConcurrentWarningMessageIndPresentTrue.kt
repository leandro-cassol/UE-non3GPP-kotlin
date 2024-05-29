package free5gc.ngap.ngapType

enum class ConcurrentWarningMessageIndPresentTrue(val value: Int) {
    True(0)
}

data class ConcurrentWarningMessageInd(val value: ConcurrentWarningMessageIndPresentTrue)


