package main

import (
	"flag"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/miekg/dns"
	cache "github.com/patrickmn/go-cache"
)

var (
	bind       *string
	ttl        *uint
	tag        *string
	kche       *cache.Cache
	forwardDNS *string
	verbose    *bool
)

func queryDNSnamesForEC2instances(tagName string, tagValue string) ([]string, error) {
	// aws ec2 describe-instances --filters "Name=tag:Name,Values=xxx" "Name=instance-state-name,Values=running" --query 'Reservations[0].Instances[*].PublicDnsName'
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	svc := ec2.New(sess)

	params := &ec2.DescribeInstancesInput{
		Filters: []*ec2.Filter{
			{Name: aws.String("tag:" + tagName), Values: []*string{aws.String(tagValue)}},
			{Name: aws.String("instance-state-name"), Values: []*string{aws.String("running")}},
		},
	} //TODO could iterate using NextToken: to get more results, accepted as a limitation for now
	resp, err := svc.DescribeInstances(params)
	if err != nil {
		return nil, err
	}

	// extract dns names
	results := []string{}
	for _, reservation := range resp.Reservations {
		for _, instance := range reservation.Instances {
			results = append(results, *instance.PublicDnsName)
		}
	}
	return results, nil
}

func queryDNSnameOnEC2(name string) ([]string, uint32, error) {
	var cnames []string
	var cnameTTL uint32
	// get from cache
	val, exp, found := kche.GetWithExpiration(name)
	if found { // use cached value
		cnames = val.([]string)
		cnameTTL = uint32(exp.Sub(time.Now()).Seconds())
	} else { // query value in ec2
		q, err := queryDNSnamesForEC2instances(*tag, name)
		if err != nil {
			return nil, 0, err
		}
		// store in cache
		kche.Set(name, q, cache.DefaultExpiration)
		cnames = q
		cnameTTL = uint32(*ttl)
	}

	// randomize order
	for i := range cnames {
		j := rand.Intn(i + 1)
		cnames[i], cnames[j] = cnames[j], cnames[i]
	}
	return cnames, cnameTTL, nil
}

func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	if r.Opcode == dns.OpcodeQuery && strings.HasSuffix(r.Question[0].Name, "awsdns.") {
		handleAWSDNSRequest(w, r)
	} else {
		forwardDNSRequest(w, r)
	}
}

func handleAWSDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	if r.Opcode == dns.OpcodeQuery {
		for _, q := range r.Question {
			ec2Name := strings.TrimSuffix(q.Name, ".awsdns.")
			cnames, ttl, err := queryDNSnameOnEC2(ec2Name)
			if err != nil {
				log.Println("Error looking up name", ec2Name, err)
				dns.HandleFailed(w, r)
				return
			}
			if *verbose {
				log.Println("AWS query result:", cnames)
			}
			for _, cname := range cnames {
				rr := new(dns.CNAME)
				rr.Hdr = dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeCNAME,
					Class:  dns.ClassINET,
					Ttl:    ttl,
				}
				rr.Target = cname + "."
				m.Answer = append(m.Answer, rr)
				if *verbose {
					log.Println("Appending answer", rr)
				}
			}
		}
	}

	w.WriteMsg(m)
}

func forwardDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	if *verbose {
		log.Println("Handling request on forward server:", r)
	}
	c := new(dns.Client)
	resp, _, err := c.Exchange(r, *forwardDNS)
	if err != nil {
		if *verbose {
			log.Println("Error from forward server:", err)
		}
		dns.HandleFailed(w, r)
		return
	}
	if *verbose {
		log.Println("Response from forward server:", resp)
	}
	w.WriteMsg(resp)
}

func main() {
	// Parse flags
	bind = flag.String("bind", "127.0.0.1:53", "binding address and port (both tcp/udp)")
	ttl = flag.Uint("ttl", 30, "time the the results will remain in cache, in seconds")
	tag = flag.String("tag", "awsdns", "tag name to be matched by dns query")
	forwardDNS = flag.String("forward", "169.254.169.253:53", "dns server where queries will be forwarded if not in the awsdns. zone")
	verbose = flag.Bool("verbose", false, "verbose logging")
	flag.Parse()

	// cache
	expirationDuration := time.Duration(*ttl) * time.Second
	cleanupInterval := time.Duration(10) * expirationDuration
	kche = cache.New(expirationDuration, cleanupInterval)

	// Attach request handler func
	dns.HandleFunc(".", handleDNSRequest)

	// Start server
	udpServer := &dns.Server{Addr: *bind, Net: "udp"}
	tcpServer := &dns.Server{Addr: *bind, Net: "tcp"}
	dns.HandleFunc(".", handleDNSRequest)
	go func() {
		if err := udpServer.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()
	go func() {
		if err := tcpServer.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}()

	// Wait for SIGINT or SIGTERM
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	udpServer.Shutdown()
	tcpServer.Shutdown()
}
