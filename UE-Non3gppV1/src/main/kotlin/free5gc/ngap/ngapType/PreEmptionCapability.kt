package free5gc.ngap.ngapType

enum class PreEmptionCapability(val value: Int) {
    PreEmptionCapabilityPresentShallNotTriggerPreEmption(0),
    PreEmptionCapabilityPresentMayTriggerPreEmption(1)
}


