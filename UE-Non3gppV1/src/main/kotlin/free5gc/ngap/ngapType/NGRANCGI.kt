package free5gc.ngap.ngapType
data class NGRANCGI(
    var Present: NGRANCGIPresent,
    var NRCGI: NRCGI? = null,
    var EUTRACGI: EUTRACGI? = null,
    var ChoiceExtensions: ProtocolIESingleContainerNGRANCGIExtIEs? = null
)

enum class NGRANCGIPresent(val value: Int) {
    NGRANCGIPresentNothing(0),
    NGRANCGIPresentNRCGI(1),
    NGRANCGIPresentEUTRACGI(2),
    NGRANCGIPresentChoiceExtensions(3)
}
