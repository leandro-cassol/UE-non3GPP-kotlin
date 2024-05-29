package free5gc.ngap.ngapType

enum class RRCInactiveTransitionReportRequestPresent(val value: Int) {
    SubsequentStateTransitionReport(0),
    SingleRrcConnectedStateReport(1),
    CancelReport(2)
}

data class RRCInactiveTransitionReportRequest(val value: RRCInactiveTransitionReportRequestPresent)


