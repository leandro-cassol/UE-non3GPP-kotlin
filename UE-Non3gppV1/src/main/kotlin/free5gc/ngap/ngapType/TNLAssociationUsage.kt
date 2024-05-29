package free5gc.ngap.ngapType

enum class TNLAssociationUsageEnum(val value: Int) {
    PresentUe(0),
    PresentNonUe(1),
    PresentBoth(2)
}

data class TNLAssociationUsage(val value: TNLAssociationUsageEnum)
