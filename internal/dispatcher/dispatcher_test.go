package dispatcher

import "testing"

func TestCanSchedule_UnderLimit(t *testing.T) {
	active := map[string]int{"small": 2, "medium": 1, "large": 0}
	if !canSchedule(TierSmall, active) {
		t.Fatal("should be able to schedule small (2 < 6)")
	}
}

func TestCanSchedule_AtLimit(t *testing.T) {
	active := map[string]int{"small": 6, "medium": 0, "large": 0}
	if canSchedule(TierSmall, active) {
		t.Fatal("should NOT schedule small (6 >= 6)")
	}
}

func TestCanSchedule_LargeAtLimit(t *testing.T) {
	active := map[string]int{"small": 0, "medium": 0, "large": 1}
	if canSchedule(TierLarge, active) {
		t.Fatal("should NOT schedule large (1 >= 1)")
	}
}

func TestCanSchedule_MediumUnderLimit(t *testing.T) {
	active := map[string]int{"small": 0, "medium": 2, "large": 0}
	if !canSchedule(TierMedium, active) {
		t.Fatal("should be able to schedule medium (2 < 3)")
	}
}

func TestCanSchedule_MediumAtLimit(t *testing.T) {
	active := map[string]int{"small": 0, "medium": 3, "large": 0}
	if canSchedule(TierMedium, active) {
		t.Fatal("should NOT schedule medium (3 >= 3)")
	}
}
