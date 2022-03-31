package gocql

import (
	"net"
	"testing"
)

type IPFilterResult struct {
	addr   net.IP
	accept bool
}

func testIPFilter(t *testing.T, f HostFilter, tests []IPFilterResult) {
	for i, test := range tests {
		if f.Accept(&HostInfo{connectAddress: test.addr}) {
			if !test.accept {
				t.Errorf("%d: should not have been accepted but was", i)
			}
		} else if test.accept {
			t.Errorf("%d: should have been accepted but wasn't", i)
		}
	}
}

func TestFilter_WhiteList(t *testing.T) {
	f := WhiteListHostFilter("127.0.0.1", "127.0.0.2")
	tests := []IPFilterResult{
		{net.ParseIP("127.0.0.1"), true},
		{net.ParseIP("127.0.0.2"), true},
		{net.ParseIP("127.0.0.3"), false},
	}
	testIPFilter(t, f, tests)
}

func TestFilter_BlackList(t *testing.T) {
	f := BlackListHostFilter("127.0.0.1", "127.0.0.2")
	tests := []IPFilterResult{
		{net.ParseIP("127.0.0.1"), false},
		{net.ParseIP("127.0.0.2"), false},
		{net.ParseIP("127.0.0.3"), true},
	}
	testIPFilter(t, f, tests)
}

func TestFilter_EmptyBlackList(t *testing.T) {
	f := BlackListHostFilter()
	tests := []IPFilterResult{
		{net.ParseIP("127.0.0.1"), true},
		{net.ParseIP("127.0.0.2"), true},
		{net.ParseIP("127.0.0.3"), true},
	}
	testIPFilter(t, f, tests)
}

func TestFilter_AllowAll(t *testing.T) {
	f := AcceptAllFilter()
	tests := []IPFilterResult{
		{net.ParseIP("127.0.0.1"), true},
		{net.ParseIP("127.0.0.2"), true},
		{net.ParseIP("127.0.0.3"), true},
	}
	testIPFilter(t, f, tests)
}

func TestFilter_DenyAll(t *testing.T) {
	f := DenyAllFilter()
	tests := []IPFilterResult{
		{net.ParseIP("127.0.0.1"), false},
		{net.ParseIP("127.0.0.2"), false},
		{net.ParseIP("127.0.0.3"), false},
	}
	testIPFilter(t, f, tests)
}

type DCFilterResult struct {
	dc     string
	accept bool
}

func testDCFilter(t *testing.T, f HostFilter, tests []DCFilterResult) {
	for i, test := range tests {
		if f.Accept(&HostInfo{dataCenter: test.dc}) {
			if !test.accept {
				t.Errorf("%d: should not have been accepted but was", i)
			}
		} else if test.accept {
			t.Errorf("%d: should have been accepted but wasn't", i)
		}
	}
}

func TestFilter_DataCentre(t *testing.T) {
	f := DataCentreHostFilter("dc1")
	tests := []DCFilterResult{
		{"dc1", true},
		{"dc2", false},
	}
	testDCFilter(t, f, tests)
}
