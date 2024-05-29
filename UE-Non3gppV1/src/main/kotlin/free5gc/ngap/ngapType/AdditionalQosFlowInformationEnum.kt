package free5gc.ngap.ngapType

enum class AdditionalQosFlowInformationEnum(val value: Int) {
    MoreLikely(0) // Representa AdditionalQosFlowInformationPresentMoreLikely
}

class AdditionalQosFlowInformation(val value: AdditionalQosFlowInformationEnum)
