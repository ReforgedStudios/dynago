package dynago

import "testing"

func TestNewAwsFHttpExecutor(t *testing.T) {
	exec := NewAwsFHttpExecutor("http://localhost:7777", "local", "", "")
	if exec == nil {
		t.Error("Exec nil", exec)
	}
}
