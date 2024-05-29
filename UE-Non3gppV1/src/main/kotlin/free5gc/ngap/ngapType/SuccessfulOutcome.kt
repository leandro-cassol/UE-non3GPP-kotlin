package free5gc.ngap.ngapType

enum class SuccessfulOutcomePresent(val value: Int) {
    PresentNothing(0),
    PresentAMFConfigurationUpdateAcknowledge(1),
    PresentHandoverCancelAcknowledge(2),
    PresentHandoverCommand(3),
    PresentHandoverRequestAcknowledge(4),
    PresentInitialContextSetupResponse(5),
    PresentNGResetAcknowledge(6),
    PresentNGSetupResponse(7),
    PresentPathSwitchRequestAcknowledge(8),
    PresentPDUSessionResourceModifyResponse(9),
    PresentPDUSessionResourceModifyConfirm(10),
    PresentPDUSessionResourceReleaseResponse(11),
    PresentPDUSessionResourceSetupResponse(12),
    PresentPWSCancelResponse(13),
    PresentRANConfigurationUpdateAcknowledge(14),
    PresentUEContextModificationResponse(15),
    PresentUEContextReleaseComplete(16),
    PresentUERadioCapabilityCheckResponse(17),
    PresentWriteReplaceWarningResponse(18)
}

data class SuccessfulOutcome(
    val procedureCode: ProcedureCode,
    val criticality: Criticality,
    val value: SuccessfulOutcomeValue
)

data class SuccessfulOutcomeValue(
    val present: SuccessfulOutcomePresent,
    val amfConfigurationUpdateAcknowledge: AMFConfigurationUpdateAcknowledge? = null,
    val handoverCancelAcknowledge: HandoverCancelAcknowledge? = null,
    val handoverCommand: HandoverCommand? = null,
    val handoverRequestAcknowledge: HandoverRequestAcknowledge? = null,
    val initialContextSetupResponse: InitialContextSetupResponse? = null,
    val ngResetAcknowledge: NGResetAcknowledge? = null,
    val ngSetupResponse: NGSetupResponse? = null,
    val pathSwitchRequestAcknowledge: PathSwitchRequestAcknowledge? = null,
    val pduSessionResourceModifyResponse: PDUSessionResourceModifyResponse? = null,
    val pduSessionResourceModifyConfirm: PDUSessionResourceModifyConfirm? = null,
    val pduSessionResourceReleaseResponse: PDUSessionResourceReleaseResponse? = null,
    val pduSessionResourceSetupResponse: PDUSessionResourceSetupResponse? = null,
    val pwsCancelResponse: PWSCancelResponse? = null,
    val ranConfigurationUpdateAcknowledge: RANConfigurationUpdateAcknowledge? = null,
    val ueContextModificationResponse: UEContextModificationResponse? = null,
    val ueContextReleaseComplete: UEContextReleaseComplete? = null,
    val ueRadioCapabilityCheckResponse: UERadioCapabilityCheckResponse? = null,
    val writeReplaceWarningResponse: WriteReplaceWarningResponse? = null
)