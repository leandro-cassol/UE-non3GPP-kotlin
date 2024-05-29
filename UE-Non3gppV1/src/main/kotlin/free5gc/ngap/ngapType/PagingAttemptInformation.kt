package free5gc.ngap.ngapType

data class PagingAttemptInformation(
    val pagingAttemptCount: PagingAttemptCount,
    val intendedNumberOfPagingAttempts: IntendedNumberOfPagingAttempts,
    val nextPagingAreaScope: NextPagingAreaScope? = null,
    val ieExtensions: ProtocolExtensionContainerPagingAttemptInformationExtIEs? = null
)


