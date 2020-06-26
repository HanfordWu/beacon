package beacon

import (
	"net"
	"testing"
)

func TestPathEqualTrue(t *testing.T) {
	p1 := Path{
		net.IP{127, 0, 0, 1},
		net.IP{8, 8, 8, 8},
		net.IP{10, 20, 30, 96},
	}

	p2 := Path{
		net.IP{127, 0, 0, 1},
		net.IP{8, 8, 8, 8},
		net.IP{10, 20, 30, 96},
	}

	if !p1.Equal(p2) {
		t.Errorf("p1: %s and p2: %s should evaluate to being equal", p1, p2)
	}
}

func TestPathEqualFalse(t *testing.T) {
	p1 := Path{
		net.IP{127, 0, 0, 1},
		net.IP{8, 8, 8, 8},
		net.IP{10, 20, 30, 97},
	}

	p2 := Path{
		net.IP{127, 0, 0, 1},
		net.IP{8, 8, 8, 8},
		net.IP{10, 20, 30, 96},
	}

	if p1.Equal(p2) {
		t.Errorf("p1: %s and p2: %s should not evaluate to being equal", p1, p2)
	}
}

func TestPathEqualDiffLen(t *testing.T) {
	p1 := Path{
		net.IP{127, 0, 0, 1},
		net.IP{8, 8, 8, 8},
	}

	p2 := Path{
		net.IP{127, 0, 0, 1},
		net.IP{8, 8, 8, 8},
		net.IP{10, 20, 30, 96},
	}

	if p1.Equal(p2) {
		t.Errorf("p1: %s and p2: %s are different lengths, so they should not be equal", p1, p2)
	}
}

func TestSubPath(t *testing.T) {
	p := Path{
		net.IP{127, 0, 0, 1},
		net.IP{8, 8, 8, 8},
		net.IP{10, 20, 30, 96},
	}

	expected := p[:2]
	actual := p.SubPath(net.IP{8, 8, 8, 8})

	if !actual.Equal(expected) {
		t.Errorf("subpath returned was incorrect, expected: %s got: %s", expected, actual)
	}
}

func TestSubPathNonExistentElement(t *testing.T) {
	p := Path{
		net.IP{127, 0, 0, 1},
		net.IP{8, 8, 8, 8},
		net.IP{10, 20, 30, 96},
	}

	expected := Path{}
	actual := p.SubPath(net.IP{0, 0, 0, 0})

	if !actual.Equal(expected) {
		t.Error("When a nonexistent element is passed to Subpath, the result should be an empty path")
	}
}
