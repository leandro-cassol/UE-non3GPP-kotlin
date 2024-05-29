package free5gc.ngap.ngapType

enum class UERetentionInformation(val value: Int) {
    UesRetained(0);

    companion object {
        fun fromInt(value: Int) = UERetentionInformation.values().first { it.value == value }
    }
}
