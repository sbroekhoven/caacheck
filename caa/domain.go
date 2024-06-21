package caa

import (
	"errors"
	"github.com/miekg/dns"
	"net"
)

func checkDomain(hostname string, nameserver string) (string, bool, error) {
	var soarecord string

	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(hostname), dns.TypeSOA)
	m.RecursionDesired = true
	m.SetEdns0(4096, true)

	r, _, err := c.Exchange(m, net.JoinHostPort(nameserver, "53"))
	if r == nil {
		return "", false, err
	}

	if r.Rcode != dns.RcodeSuccess {
		err = errors.New("domain lookup not successful")
		return "", false, err
	}

	for _, ain := range r.Answer {
		if a, ok := ain.(*dns.SOA); ok {
			soarecord = a.Ns
		}
	}

	return soarecord, r.AuthenticatedData, nil
}
