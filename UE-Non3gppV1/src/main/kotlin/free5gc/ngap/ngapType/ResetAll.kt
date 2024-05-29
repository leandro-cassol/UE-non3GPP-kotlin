package free5gc.ngap.ngapType

enum class ResetAllValue(val value: Int) {
    ResetAllPresentResetAll(0)
}

data class ResetAll(val value: ResetAllValue)
