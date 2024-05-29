package free5gc.ngap.ngapType

class AveragingWindow(val value: Long) {
    init {
        require(value in 0..4095) { "Value must be between 0 and 4095" }
    }
}