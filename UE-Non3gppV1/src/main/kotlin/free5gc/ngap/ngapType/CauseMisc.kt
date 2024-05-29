package free5gc.ngap.ngapType

enum class CauseMisc(val value: Int) {
    CauseMiscPresentControlProcessingOverload(0),
    CauseMiscPresentNotEnoughUserPlaneProcessingResources(1),
    CauseMiscPresentHardwareFailure(2),
    CauseMiscPresentOmIntervention(3),
    CauseMiscPresentUnknownPLMN(4),
    CauseMiscPresentUnspecified(5)
}