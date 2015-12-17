package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/koding/cache"
	"github.com/miekg/dns"
)

func GetKey(set []dns.RR, tag uint16) (*dns.DNSKEY, bool) {
	for _, rr := range set {
		if rr.Header().Rrtype == dns.TypeDNSKEY &&
			rr.(*dns.DNSKEY).KeyTag() == tag {
			return rr.(*dns.DNSKEY), true
		}
	}
	return nil, false
}

func GetDS(set []dns.RR, key *dns.DNSKEY) (*dns.DS, bool) {
	for _, rr := range set {
		if rr.Header().Rrtype == dns.TypeDS &&
			key.KeyTag() == rr.(*dns.DS).KeyTag &&
			key.ToDS(rr.(*dns.DS).DigestType).Digest == rr.(*dns.DS).Digest {
			return rr.(*dns.DS), true
		}
	}
	return nil, false
}

func GetNS(set []dns.RR) (res []string) {
	for _, rr := range Shuffle(set) {
		if rr.Header().Rrtype == dns.TypeNS {
			res = append(res, rr.(*dns.NS).Ns)
		}
	}

	return
}

func GetRRs(set []dns.RR, name string, rtype uint16) (res []dns.RR) {
	for _, rr := range set {
		if rr.Header().Name == name &&
			(rr.Header().Rrtype == rtype || rtype == dns.TypeANY || rr.Header().Rrtype == dns.TypeRRSIG) {
			res = append(res, rr)
		}
	}
	log.Println("GetRRs", name, set, res)
	return res
}

func Shuffle(a []dns.RR) []dns.RR {
	for i := range a {
		j := rand.Intn(i + 1)
		a[i], a[j] = a[j], a[i]
	}

	return a
}

func SignedRecords(rrset []dns.RR, rtype uint16) (res []dns.RR, sig []*dns.RRSIG) {
	for _, rr := range rrset {
		if rr.Header().Rrtype == rtype {
			res = append(res, rr)
		}
		if rr.Header().Rrtype == dns.TypeRRSIG &&
			rr.(*dns.RRSIG).TypeCovered == rtype {
			sig = append(sig, rr.(*dns.RRSIG))
		}
	}

	return
}

func RrsetName(rrset []dns.RR) (name string, err error) {
	if len(rrset) == 0 {
		return "", errors.New("Empty rrset")
	}

	name = rrset[0].Header().Name
	for _, rr := range rrset {
		if rr.Header().Name != name {
			switch rr.Header().Rrtype {
			case dns.TypeNSEC, dns.TypeNSEC3, dns.TypeRRSIG:
				continue
			default:
				fmt.Println(rr)
				return "", errors.New("Multiple names in RRSet")
			}
		}
	}
	return
}

func RrsetType(rrset []dns.RR) (rtype uint16, err error) {
	if len(rrset) == 0 {
		return 0, errors.New("Empty rrset")
	}

	rtype = rrset[0].Header().Rrtype
	for _, rr := range rrset {
		if rr.Header().Rrtype != rtype {
			return 0, errors.New("Multiple types in RRSet")
		}
	}
	return
}

// Used to cache referrals/answers and through them collect
// DS records + RRSIGs. Should expire quickly.
type Referral struct {
	origin    string
	authority []dns.RR // referral from other sources
	answer    []dns.RR // cached answer
}

type Checker struct {
	udp dns.Client
	tcp dns.Client

	trustedKeys []*dns.DNSKEY

	mu        sync.RWMutex
	referrals cache.Cache
	root      *Referral // Special "." entrypoint
}

func NewChecker() *Checker {
	c := &Checker{
		referrals: cache.NewMemoryWithTTL(time.Second * 30),
	}

	defns, _ := dns.NewRR(". IN NS a.root-servers.net")

	c.root = &Referral{origin: ".", authority: []dns.RR{defns}}

	log.Println("auth", c.root.authority[0])

	return c
}

func (c *Checker) GetReferral(name string) (ref *Referral) {
	item, err := c.referrals.Get(name)
	if err == nil {
		return item.(*Referral)
	}
	// special case with "."
	if name == "." {
		return c.root
	}
	return nil
}

func (c *Checker) AddReferral(name string, rr dns.RR) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ref := c.GetReferral(name)
	if ref == nil {
		ref = &Referral{origin: name}
		c.referrals.Set(name, ref)
	}
	for _, r := range ref.authority {
		if r == rr {
			return
		}
	}
	ref.authority = append(ref.authority, rr)
}

func (c *Checker) AddAnswer(name string, rr dns.RR) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ref := c.GetReferral(name)
	if ref == nil {
		ref = &Referral{origin: name}
		c.referrals.Set(name, ref)
	}
	for _, r := range ref.answer {
		if r == rr {
			return
		}
	}
	ref.answer = append(ref.answer, rr)
}

func (c *Checker) AddTrustedKey(key *dns.DNSKEY) {
	c.trustedKeys = append(c.trustedKeys, key)
}

func (c *Checker) ParseTrustedKeyFile(path string, f os.FileInfo, err error) error {
	file, err := os.Open(path)
	reader := bufio.NewReader(file)
	for rr := range dns.ParseZone(reader, "", path) {
		if rr.Error != nil {
			return rr.Error
		}
		switch rr.RR.Header().Rrtype {
		case dns.TypeDNSKEY:
			log.Println("Adding trusted key", rr.Header().Name)
			c.AddTrustedKey(rr.RR.(*dns.DNSKEY))
		case dns.TypeNS:
			if rr.RR.Header().Name == "." {
				c.root.authority = append(c.root.authority, rr.RR)
				log.Println("Adding hint to root", rr.RR.(*dns.NS).Ns)
			}
		}
	}

	return nil
}

// LoadTrustedKeys will scan a directory for bind zonefiles
// and consider every DNSKEY found in here as trusted. It will
// also take any "." DNS RR to be used as root servers.
func (c *Checker) LoadTrustedKeys(dir string) error {
	return filepath.Walk(dir, c.ParseTrustedKeyFile)
}

// Query effectively queries the given nameserver
func (c *Checker) Query(domain string, rtype uint16, nameserver string) (in *dns.Msg, err error) {
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(domain), rtype)
	query.SetEdns0(4096, true)

	udp := &dns.Client{}
	in, _, err = udp.Exchange(query, nameserver)
	if err != nil {
		return
	}

	if in.MsgHdr.Truncated {
		tcp := &dns.Client{Net: "tcp"}
		in, _, err = tcp.Exchange(query, nameserver)
	}

	return
}

// Walk will look for this domain up to the root. It is used
// to find the first good origin.
func Walk(domain string) (zones []string) {
	fqdn := dns.Fqdn(strings.ToLower(domain))
	for off, last := 0, false; !last; off, last = dns.NextLabel(fqdn, off) {
		zones = append(zones, fqdn[off:])
	}
	zones = append(zones, ".")
	return
}

func (c *Checker) QueryAtOrigin(name string, rtype uint16) (set []dns.RR, err error) {
	// Find lowest known origin
	var ref *Referral

	// Special case for DS lookup: follow referral
	// from top. XXX: maybe start from parent zone only.
	if rtype == dns.TypeDS {
		ref = c.GetReferral(".")
	} else {
		for _, origin := range Walk(name) {
			ref = c.GetReferral(origin)
			if ref != nil {
				break
			}
		}
	}

	if ref == nil {
		log.Fatal("Unexpected, . missing")
	}

	// Then query following referrals up to the name
	for depth := 0; depth < 10; depth++ {
		var msg *dns.Msg

		cached := GetRRs(ref.answer, name, rtype)

		if len(cached) == 0 {
			for _, ns := range GetNS(ref.authority) {
				log.Println("Querying", name, "@", ns, rtype)
				msg, err = c.Query(name, rtype, net.JoinHostPort(ns, "53"))
				if err == nil {
					break
				} else {
					log.Println(err, "continuing to next ns")
					continue
				}

				if msg.MsgHdr.Rcode == dns.RcodeNameError {
					return nil, errors.New(dns.RcodeToString[msg.MsgHdr.Rcode])
				}

				if msg.MsgHdr.Rcode != dns.RcodeSuccess {
					log.Println(err, "continuing to next ns")
					continue
				}
			}
			if msg == nil {
				return nil, errors.New("lookup failed for " + name)
			}
		} else {
			log.Println("Returning cached", cached)
			msg = &dns.Msg{MsgHdr: dns.MsgHdr{Authoritative: true}, Answer: cached}
		}

		if msg.MsgHdr.Authoritative {
			if len(msg.Answer) == 0 {
				log.Println("Got empty ans. for", name, rtype)
			}
			// Cache answers for name
			for _, rr := range msg.Answer {
				c.AddAnswer(name, rr)
			}

			// Add cached DS/NS/RRSIG from referrals
			ref = c.GetReferral(name)
			if ref != nil {
				for _, rr := range ref.authority {
					msg.Answer = append(msg.Answer, rr)
				}
			}

			return msg.Answer, nil
		}

		// Ensure we only have one name in referrals
		name, err := RrsetName(msg.Ns)
		if err != nil {
			log.Println("msg.Ns empty", msg)
			return nil, err
		}

		for _, rr := range msg.Ns {
			c.AddReferral(name, rr)
			ref = c.GetReferral(name)
		}
	}

	log.Println(name, "lookup depth exceeded")

	return nil, err
}

func (c *Checker) Lookup(domain string, rtype uint16) (set []dns.RR, err error) {
	set, err = c.QueryAtOrigin(domain, rtype)
	if err != nil {
		return
	}

	return
}

func (c *Checker) IsTrustedKey(key *dns.DNSKEY) (string, bool) {
	for _, other := range c.trustedKeys {
		// This is the dangerous part. In that setup any
		// trusted key, disregarding delegation, can sign any name.
		if key.PublicKey == other.PublicKey {
			return other.Header().Name, true
		}
	}

	return "", false
}

// ValidateOne checks an rrset according to known origin security
// records.
func ValidateOne(rrset []dns.RR, sig *dns.RRSIG, key *dns.DNSKEY) error {
	name, err := RrsetName(rrset)
	if err != nil {
		return err
	}

	rtype, err := RrsetType(rrset)
	if err != nil {
		return err
	}

	if rtype != dns.TypeDS && !dns.IsSubDomain(name, sig.SignerName) {
		log.Println("signer", sig.SignerName, "is not part of", name)
		return errors.New("Bad signer")
	}

	if rtype == dns.TypeDS && dns.IsSubDomain(name, sig.SignerName) {
		log.Println("signer", sig.SignerName, "ignored for DS of", name)
		return errors.New("Bad signer")
	}

	if !sig.ValidityPeriod(time.Now()) {
		return errors.New("Signature not valid now")
	}

	if err := sig.Verify(key, rrset); err != nil {
		log.Println("signature verification for", rrset, "with", sig, "failed")
		return err
	}

	return nil
}

func (c *Checker) Validate(rrset []dns.RR, sigset []*dns.RRSIG) (trusted string) {
	for _, sig := range sigset {
		log.Println(rrset, "against", sig)

		set, err := c.Lookup(sig.SignerName, dns.TypeDNSKEY)
		if err != nil {
			log.Println("lookup", sig.SignerName, "dnskey", err)
			continue
		}

		key, ok := GetKey(set, sig.KeyTag)
		if !ok {
			log.Println("no key", sig.KeyTag, "in", sig.SignerName)
			continue
		}

		if err := ValidateOne(rrset, sig, key); err != nil {
			log.Println("validate error", err)
			continue
		}

		name, ok := c.IsTrustedKey(key)
		if ok {
			// This is it. Return OK as soon as a trusted
			// key signed our chain.
			log.Println("Ending on trusted key", name)
			return name
		} else {
			log.Println(key, "not trusted, continuing")
		}

		// If signer is part of the signed RRSet, and it's
		// untrusted, then only a DS record can help
		key, ok = GetKey(rrset, sig.KeyTag)
		if ok {
			set, err := c.Lookup(sig.SignerName, dns.TypeDS)
			if err != nil {
				log.Println(sig.SignerName, "DS not found")
				continue
			}

			dsset, sigset := SignedRecords(set, dns.TypeDS)
			trusted := c.Validate(dsset, sigset)
			if trusted != "" {
				return trusted
			} else {
				continue
			}
		}

		// Otherwise, validate DNSKEY or DS records from this lookup
		// up to a trusted key.
		for _, rType := range []uint16{dns.TypeDS, dns.TypeDNSKEY} {
			records, newset := SignedRecords(set, rType)
			trusted := c.Validate(records, newset)
			if trusted != "" {
				return trusted
			}
		}
	}

	return ""
}

func (c *Checker) ValidKeys(rrset []dns.RR) (signers []string, result []dns.RR) {
	for _, rtype := range []uint16{dns.TypeCDS, dns.TypeCDNSKEY, dns.TypeDNSKEY} {
		records, sigset := SignedRecords(rrset, rtype)
		valid := c.Validate(records, sigset)
		if valid != "" {
			signers = append(signers, valid)
			result = append(result, records...)
		} else {
			log.Println(records, "invalid signature against", sigset)
		}
	}

	return
}

type PublishedKeys struct {
	Signers []string       `json:"delegation"`
	DNSKEY  []*dns.DNSKEY  `json:"DNSKEY"`
	CDS     []*dns.CDS     `json:"CDS"`
	CDNSKEY []*dns.CDNSKEY `json:"CDNSKEY"`
}

func (c *Checker) DomainKeys(domain string) (keys *PublishedKeys, err error) {
	var answer []dns.RR

	for _, rtype := range []uint16{dns.TypeCDS, dns.TypeCDNSKEY, dns.TypeDNSKEY} {
		auth, err := c.Lookup(domain, rtype)
		if err != nil {
			log.Println(err)
			return nil, err
		}

		answer = append(answer, auth...)
	}

	keys = new(PublishedKeys)
	log.Println("Auth ans", answer)

	signers, all := c.ValidKeys(answer)
	keys.Signers = signers
	for _, rr := range all {
		switch rr.Header().Rrtype {
		case dns.TypeCDS:
			keys.CDS = append(keys.CDS, rr.(*dns.CDS))
		case dns.TypeCDNSKEY:
			keys.CDNSKEY = append(keys.CDNSKEY, rr.(*dns.CDNSKEY))
		case dns.TypeDNSKEY:
			keys.DNSKEY = append(keys.DNSKEY, rr.(*dns.DNSKEY))
		}
	}

	return
}
