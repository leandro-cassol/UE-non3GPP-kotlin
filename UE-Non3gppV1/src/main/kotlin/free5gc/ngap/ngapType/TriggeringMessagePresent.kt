package free5gc.ngap.ngapType

enum class TriggeringMessagePresent(val value: Int) {
    InitiatingMessage(0),
    SuccessfulOutcome(1),
    UnsuccessfullOutcome(2)
}

data class TriggeringMessage(val value: TriggeringMessagePresent)


