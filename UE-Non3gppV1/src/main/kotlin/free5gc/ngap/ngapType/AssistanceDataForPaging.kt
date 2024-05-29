package free5gc.ngap.ngapType

data class AssistanceDataForPaging(
    val assistanceDataForRecommendedCells: AssistanceDataForRecommendedCells? = null,
    val pagingAttemptInformation: PagingAttemptInformation? = null,
    val iEExtensions: ProtocolExtensionContainerAssistanceDataForPagingExtIEs? = null
)
