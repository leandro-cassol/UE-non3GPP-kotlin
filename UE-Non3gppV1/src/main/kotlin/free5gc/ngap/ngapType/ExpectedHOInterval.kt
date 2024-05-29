package free5gc.ngap.ngapType

enum class ExpectedHOInterval(val value: Int) {
    ExpectedHOIntervalPresentSec15(0),
    ExpectedHOIntervalPresentSec30(1),
    ExpectedHOIntervalPresentSec60(2),
    ExpectedHOIntervalPresentSec90(3),
    ExpectedHOIntervalPresentSec120(4),
    ExpectedHOIntervalPresentSec180(5),
    ExpectedHOIntervalPresentLongTime(6)
}


