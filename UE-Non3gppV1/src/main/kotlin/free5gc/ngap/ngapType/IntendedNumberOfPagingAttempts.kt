package free5gc.ngap.ngapType

data class IntendedNumberOfPagingAttempts(
    val value: Long // Assuming the range will be checked during runtime or with a custom serializer
)