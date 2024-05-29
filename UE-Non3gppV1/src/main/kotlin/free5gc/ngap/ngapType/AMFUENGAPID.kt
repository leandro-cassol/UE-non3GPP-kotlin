package free5gc.ngap.ngapType

class AMFUENGAPID(val value: Long) {
    init {
        require(value in 0..1_099_511_627_775) { "Value must be between 0 and 1099511627775" }
    }
}
