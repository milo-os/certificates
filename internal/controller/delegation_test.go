// SPDX-License-Identifier: AGPL-3.0-only

package controller

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	certificatesv1alpha1 "go.miloapis.com/certificates/api/v1alpha1"
)

var testPolicy = delegationPolicy{
	suspendAfterFailures: 3,
	suspendAfter:         30 * time.Minute,
	maxUnconfirmed:       48 * time.Hour,
}

func TestQuickFailuresInsideTheWindowDoNotSuspend(t *testing.T) {
	start := time.Now()
	rec := delegationRecord{lastConfirmed: start}
	for i := range 3 {
		now := start.Add(time.Duration(i) * 5 * time.Minute)
		rec = rec.next(delegationBroken, now)
		if rec.suspend(delegationBroken, now, testPolicy) {
			t.Fatalf("suspended after %d failures in %s", rec.failures, now.Sub(start))
		}
	}
	later := start.Add(31 * time.Minute)
	rec = rec.next(delegationBroken, later)
	if !rec.suspend(delegationBroken, later, testPolicy) {
		t.Fatal("expected suspension after four failures spanning 31 minutes")
	}
}

func TestGoodResultResetsFailures(t *testing.T) {
	start := time.Now()
	rec := delegationRecord{}
	rec = rec.next(delegationBroken, start)
	rec = rec.next(delegationBroken, start.Add(20*time.Minute))
	rec = rec.next(delegationOK, start.Add(25*time.Minute))
	if rec.failures != 0 || !rec.failingSince.IsZero() {
		t.Fatalf("expected reset, got %+v", rec)
	}
	now := start.Add(40 * time.Minute)
	rec = rec.next(delegationBroken, now)
	if rec.failures != 1 || !rec.failingSince.Equal(now) || rec.suspend(delegationBroken, now, testPolicy) {
		t.Fatalf("expected a fresh count after the reset, got %+v", rec)
	}
}

func TestUnknownNeitherResetsNorAdvances(t *testing.T) {
	start := time.Now()
	rec := delegationRecord{}
	rec = rec.next(delegationBroken, start)
	rec = rec.next(delegationBroken, start.Add(time.Minute))
	before := rec
	rec = rec.next(delegationUnknown, start.Add(10*time.Minute))
	if rec != before {
		t.Fatalf("unknown changed the record: %+v -> %+v", before, rec)
	}
}

func TestUnknownSuspendsOnlyAfterMaxUnconfirmed(t *testing.T) {
	confirmed := time.Now()
	rec := delegationRecord{}.next(delegationOK, confirmed)
	if rec.suspend(delegationUnknown, confirmed.Add(47*time.Hour), testPolicy) {
		t.Fatal("suspended before the unconfirmed window ended")
	}
	if !rec.suspend(delegationUnknown, confirmed.Add(48*time.Hour), testPolicy) {
		t.Fatal("expected suspension once delegation went unconfirmed for 48 hours")
	}
	rec = rec.next(delegationBroken, confirmed.Add(47*time.Hour))
	if rec.suspend(delegationUnknown, confirmed.Add(49*time.Hour), testPolicy) {
		t.Fatal("a definitive failure confirms the state and restarts the unconfirmed window")
	}
}

type stubDNSServer struct {
	conn    net.PacketConn
	answers map[string]func(*dnsmessage.Builder, dnsmessage.Question) dnsmessage.RCode
}

func startStubDNS(t *testing.T, answers map[string]func(*dnsmessage.Builder, dnsmessage.Question) dnsmessage.RCode) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	s := &stubDNSServer{conn: conn, answers: answers}
	go s.serve()
	return conn.LocalAddr().String()
}

func (s *stubDNSServer) serve() {
	buf := make([]byte, 512)
	for {
		n, addr, err := s.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		var p dnsmessage.Parser
		header, err := p.Start(buf[:n])
		if err != nil {
			continue
		}
		q, err := p.Question()
		if err != nil {
			continue
		}
		name := strings.TrimSuffix(strings.ToLower(q.Name.String()), ".")
		answer, ok := s.answers[name]

		rcode := dnsmessage.RCodeNameError
		resp := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: header.ID, Response: true, Authoritative: true, RecursionAvailable: true})
		resp.EnableCompression()
		_ = resp.StartQuestions()
		_ = resp.Question(q)
		_ = resp.StartAnswers()
		if ok {
			rcode = answer(&resp, q)
		}
		msg, err := resp.Finish()
		if err != nil {
			continue
		}
		msg[3] = (msg[3] &^ 0x0f) | byte(rcode)
		_, _ = s.conn.WriteTo(msg, addr)
	}
}

func cnameTo(target string) func(*dnsmessage.Builder, dnsmessage.Question) dnsmessage.RCode {
	return func(b *dnsmessage.Builder, q dnsmessage.Question) dnsmessage.RCode {
		_ = b.CNAMEResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 60},
			dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(target + ".")})
		return dnsmessage.RCodeSuccess
	}
}

func rcode(code dnsmessage.RCode) func(*dnsmessage.Builder, dnsmessage.Question) dnsmessage.RCode {
	return func(*dnsmessage.Builder, dnsmessage.Question) dnsmessage.RCode { return code }
}

func TestRealResolverClassification(t *testing.T) {
	const target = "0123456789abcdef0123456789abcdef.acme-dns.example.net"
	addr := startStubDNS(t, map[string]func(*dnsmessage.Builder, dnsmessage.Question) dnsmessage.RCode{
		"_acme-challenge.good.example.com":     cnameTo(target),
		"_acme-challenge.wrong.example.com":    cnameTo("attacker.acme-dns.example.net"),
		"_acme-challenge.nodata.example.com":   rcode(dnsmessage.RCodeSuccess),
		"_acme-challenge.servfail.example.com": rcode(dnsmessage.RCodeServerFailure),
		"_acme-challenge.refused.example.com":  rcode(dnsmessage.RCodeRefused),
	})
	resolver := NewResolver(addr)

	tests := map[string]delegationState{
		"good":     delegationOK,
		"wrong":    delegationBroken,
		"nxdomain": delegationBroken,
		"nodata":   delegationBroken,
		"servfail": delegationUnknown,
		"refused":  delegationUnknown,
	}
	for label, want := range tests {
		t.Run(label, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			records := []certificatesv1alpha1.RequiredDNSRecord{{
				Name:    "_acme-challenge." + label + ".example.com",
				Type:    "CNAME",
				Content: target,
			}}
			got, problems := checkDelegation(ctx, resolver, records)
			if got != want {
				t.Fatalf("got state %d, want %d (%v)", got, want, problems)
			}
		})
	}
}
