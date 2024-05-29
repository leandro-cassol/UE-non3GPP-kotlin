package free5gc.ngap.ngapType

data class CoreNetworkAssistanceInformation(
    val UEIdentityIndexValue: UEIdentityIndexValue,
    val UESpecificDRX: PagingDRX? = null,
    val PeriodicRegistrationUpdateTimer: PeriodicRegistrationUpdateTimer,
    val MICOModeIndication: MICOModeIndication? = null,
    val TAIListForInactive: TAIListForInactive,
    val ExpectedUEBehaviour: ExpectedUEBehaviour? = null,
    val IEExtensions: ProtocolExtensionContainerCoreNetworkAssistanceInformationExtIEs? = null
)


