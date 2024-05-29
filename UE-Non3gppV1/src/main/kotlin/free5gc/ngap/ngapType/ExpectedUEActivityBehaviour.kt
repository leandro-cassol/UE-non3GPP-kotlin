package free5gc.ngap.ngapType

data class ExpectedUEActivityBehaviour(
    val expectedActivityPeriod: ExpectedActivityPeriod? = null,
    val expectedIdlePeriod: ExpectedIdlePeriod? = null,
    val sourceOfUEActivityBehaviourInformation: SourceOfUEActivityBehaviourInformation? = null,
    val iEExtensions: ProtocolExtensionContainerExpectedUEActivityBehaviourExtIEs? = null
)


