package free5gc.ngap.ngapType

enum class UnsuccessfulOutcomePresent(val value: Int) {
    Nothing(0),
    AMFConfigurationUpdateFailure(1),
    HandoverPreparationFailure(2),
    HandoverFailure(3),
    InitialContextSetupFailure(4),
    NGSetupFailure(5),
    PathSwitchRequestFailure(6),
    RANConfigurationUpdateFailure(7),
    UEContextModificationFailure(8)
}

data class UnsuccessfulOutcome(
    val procedureCode: ProcedureCode,
    val criticality: Criticality,
    val value: UnsuccessfulOutcomeValue
)

sealed class UnsuccessfulOutcomeValue {
    object Nothing : UnsuccessfulOutcomeValue()
    data class AMFConfigurationUpdateFailure(val failure: AMFConfigurationUpdateFailure) : UnsuccessfulOutcomeValue()
    data class HandoverPreparationFailure(val failure: HandoverPreparationFailure) : UnsuccessfulOutcomeValue()
    data class HandoverFailure(val failure: HandoverFailure) : UnsuccessfulOutcomeValue()
    data class InitialContextSetupFailure(val failure: InitialContextSetupFailure) : UnsuccessfulOutcomeValue()
    data class NGSetupFailure(val failure: NGSetupFailure) : UnsuccessfulOutcomeValue()
    data class PathSwitchRequestFailure(val failure: PathSwitchRequestFailure) : UnsuccessfulOutcomeValue()
    data class RANConfigurationUpdateFailure(val failure: RANConfigurationUpdateFailure) : UnsuccessfulOutcomeValue()
    data class UEContextModificationFailure(val failure: UEContextModificationFailure) : UnsuccessfulOutcomeValue()
}
