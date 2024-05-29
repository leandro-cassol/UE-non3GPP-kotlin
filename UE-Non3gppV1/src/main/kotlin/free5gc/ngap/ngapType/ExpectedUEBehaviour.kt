package free5gc.ngap.ngapType

data class ExpectedUEBehaviour(
    val expectedUEActivityBehaviour: ExpectedUEActivityBehaviour? = null,
    val expectedHOInterval: ExpectedHOInterval? = null,
    val expectedUEMobility: ExpectedUEMobility? = null,
    val expectedUEMovingTrajectory: ExpectedUEMovingTrajectory? = null,
    val iEExtensions: ProtocolExtensionContainerExpectedUEBehaviourExtIEs? = null
)