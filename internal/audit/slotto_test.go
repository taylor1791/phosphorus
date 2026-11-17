package audit

// Slots record the recipient they are wrapped to (`to`), which nothing
// authenticates: check guards it against trunk.

import (
	"strings"
	"testing"

	"github.com/taylor1791/phosphorus/internal/agewrap"
)

func TestSlotRemovedWhileKeyUnchanged(t *testing.T) {
	f := newFx(t)
	s := f.load("app", "dev")
	delete(s.Keys.CurrentKey().Slots, "sam/laptop")
	delete(s.Keys.CurrentKey().SlotTo, "sam/laptop")
	f.save(s)
	got := want(t, f.check(Options{}), RuleSlotRemoved, Error)
	if got.Device != "sam/laptop" || !strings.Contains(got.Message, "removed") {
		t.Fatalf("%+v", got)
	}
}

func TestSlotRecipientMismatch(t *testing.T) {
	f := newFx(t)
	f.write(".carbon/people/ada.toml", f.read(".carbon/people/ada.toml")+"desk = \""+f.key("ada/desk", agewrap.KindHybrid)+"\"\n")
	f.commit("ada adds a desk")
	o := f.open("app", "dev", "lin/laptop")
	if _, err := o.AddSlots(f.devicesOf("ada/desk")); err != nil {
		t.Fatal(err)
	}
	cur := o.Keys.CurrentKey()
	cur.SetSlot("ada/desk", cur.SlotTo["ada/laptop"], cur.Slots["ada/desk"])
	f.save(o.Scope)
	got := want(t, f.check(Options{}), RuleSlotRecipient, Error)
	if got.Device != "ada/desk" {
		t.Fatal(got.Device)
	}
}

func TestSlotRekeyed(t *testing.T) {
	f := newFx(t)
	f.write(".carbon/people/ada.toml", "[devices]\nlaptop = \""+f.key("ada/laptop", agewrap.KindHybrid)+"\"\n")
	f.commit("ada's laptop has a new key")
	rep := f.check(Options{})
	got := want(t, rep, RuleSlotRekeyed, Warning)
	if got.Device != "ada/laptop" || got.Scope != "app/dev" {
		t.Fatalf("%+v", got)
	}
	none(t, rep, RuleSlotRecipient)
	want(t, f.check(Options{Strict: true}), RuleSlotRekeyed, Error)
}

func TestRotationWithMislabelledSlot(t *testing.T) {
	f := newFx(t)
	removeSam(f)
	rotateDev(t, f, "removed sam", now)
	s := f.load("app", "dev")
	cur := s.Keys.CurrentKey()
	cur.SetSlot("lin/laptop", cur.SlotTo["ada/laptop"], cur.Slots["lin/laptop"])
	f.save(s)
	got := want(t, f.check(Options{}), RuleKeyChanged, Error)
	if !strings.Contains(got.Message, "lin/laptop") {
		t.Fatal(got.Message)
	}
}
