package free5gc.ngap.ngapType

enum class NGAPPDUPresent(val value: Int) {
    PresentNothing(0),
    PresentInitiatingMessage(1),
    PresentSuccessfulOutcome(2),
    PresentUnsuccessfulOutcome(3)
}

data class NGAPPDU(
    var present: NGAPPDUPresent,
    var initiatingMessage: InitiatingMessage?,
    var successfulOutcome: SuccessfulOutcome?,
    var unsuccessfulOutcome: UnsuccessfulOutcome?
)