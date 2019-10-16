package main

import (
	"crypto/tls"
	"net/http"
	_ "net/http/pprof"
	"strings"
	"time"

	"github.com/jinzhu/configor"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
	"github.com/prometheus/common/version"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/ldap.v3"
)

var (
	openldapUp = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "openldap_up",
			Help: "Value whether a connection to OpenLDAP has been successful",
		})

	openldapMasterUp = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "openldap_master_up",
			Help: "Value whether a connection to master OpenLDAP has been successful",
		})

	syncLag = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "openldap_syncrepl_lag",
			Help: "Replication lag comparing to a master in seconds",
		})

	syncCookie = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "openldap_contextCSN",
			Help: "The contextCSN sync cookie on a slave",
		},
		[]string{"index"},
	)

	syncMasterCookie = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "openldap_master_contextCSN",
			Help: "The contextCSN sync cookie on a master",
		},
		[]string{"index"},
	)
)

// Config stores the exporter configuration.
var Config = struct {
	Ldap struct {
		URI      string `default:"ldap://localhost"`
		Basedn   string `default:"dc=example,dc=org"`
		StartTLS bool   `default:"false"`
		Bind     bool   `default:"false"`
		Binddn   string `default:""`
		Bindpass string `default:""`
	}
}{}

var masterURI string
var epoch int64
var mepoch int64
var firstrun bool

func ymdToUnix(contextCSN string) (timestamp int64, label string) {
	// This is a totally crude approach to set a well known base time to parse another date later
	format := "20060102150405"
	ymd := strings.Split(contextCSN, ".")[0]
	time, err := time.Parse(format, ymd)
	if err != nil {
		log.Error(err)
	}
	label = strings.Split(contextCSN, "#")[2]
	return time.Unix(), label
}

func ldapConnect(uri string) *ldap.Conn {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	var l *ldap.Conn
	var err error

	if Config.Ldap.StartTLS {
		// Connect to host
		l, err = ldap.DialURL(uri)
		if err != nil {
			log.Error(err)
			return nil
		}

		// Reconnect with TLS
		err = l.StartTLS(conf)
		if err != nil {
			l.Close()
			log.Error(err)
			return nil
		}
	} else {
		l, err = ldap.DialURL(uri)
		if err != nil {
			log.Error(err)
			return nil
		}
	}

	// Bind
	if Config.Ldap.Bind {
		err = l.Bind(Config.Ldap.Binddn, Config.Ldap.Bindpass)
		if err != nil {
			l.Close()
			log.Error(err)
			return nil
		}
	}

	return l
}

func getMaster(l *ldap.Conn) {
	var match bool

	searchRequest := ldap.NewSearchRequest(
		"cn=monitor", // The base dn to search
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(namingContexts=*)(MonitorUpdateRef=*))",    // The filter to apply
		[]string{"namingContexts", "monitorUpdateRef"}, // A list attributes to retrieve
		nil,
	)

	basedn, err := ldap.ParseDN(Config.Ldap.Basedn)
	if err != nil {
		log.Errorln(err)
		return
	}

	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Errorln(err)
	} else {
		i := 0
		newMasterURI := ""

		for _, entry := range sr.Entries {
			i++
			match = false
			for _, masterBasedn := range entry.GetAttributeValues("namingContexts") {
				dn, err := ldap.ParseDN(masterBasedn)
				if err == nil && dn.Equal(basedn) {
					match = true
				}
			}
			if match {
				newMasterURI = entry.GetAttributeValue("monitorUpdateRef")

				if masterURI == "" {
					log.Infoln("Got master LDAP server URI", newMasterURI)
				}
				masterURI = newMasterURI
			}
		}

		if newMasterURI == "" {
			if masterURI != "" {
				log.Infoln("Clearing master LDAP server URI", masterURI, "not available anymore")
			}
			masterURI = ""
		}
	}
}

// Actually collect values from ldap
func getCSN(l *ldap.Conn) (int64, string) {
	if l != nil {
		searchRequest := ldap.NewSearchRequest(
			Config.Ldap.Basedn, // The base dn to search
			ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)",      // The filter to apply
			[]string{"contextCSN"}, // A list attributes to retrieve
			nil,
		)

		sr, err := l.Search(searchRequest)
		if err != nil {
			openldapUp.Set(0)
			log.Errorln(err)
		} else {
			openldapUp.Set(1)
			for _, entry := range sr.Entries {
				for _, csn := range entry.GetAttributeValues("contextCSN") {
					return ymdToUnix(csn)
				}
			}
		}
	}

	return 0, ""
}

func ldapWorker() {
	var l *ldap.Conn
	var ml *ldap.Conn
	var label string

	firstrun = true

	for {
		l = ldapConnect(Config.Ldap.URI)

		if l != nil {
			openldapUp.Set(1)
			getMaster(l)
			epoch, label = getCSN(l)
			syncCookie.WithLabelValues(label).Set(float64(epoch))
		} else {
			openldapUp.Set(0)
		}

		if masterURI != "" {
			ml = ldapConnect(masterURI)

			if ml != nil {
				openldapMasterUp.Set(1)
				mepoch, label = getCSN(ml)
				syncMasterCookie.WithLabelValues(label).Set(float64(mepoch))
				syncLag.Set(float64(mepoch - epoch))
			} else {
				openldapMasterUp.Set(0)
			}
		} else {
			openldapMasterUp.Set(0)

			if firstrun {
				log.Infoln("Unable to get master URI")
			}
		}

		if l != nil {
			l.Close()
			l = nil
		}

		if ml != nil {
			ml.Close()
			ml = nil
		}

		if firstrun {
			firstrun = false
		}

		time.Sleep(60 * time.Second)
	}
}

func init() {
	// Register metrics
	prometheus.MustRegister(syncCookie)
	prometheus.MustRegister(syncMasterCookie)
	prometheus.MustRegister(openldapUp)
	prometheus.MustRegister(openldapMasterUp)
	prometheus.MustRegister(syncLag)
}

func main() {
	var (
		listenAddress = kingpin.Flag("web.listen-address", "Address on which to expose metrics and web interface.").Default(":9328").String()
		metricsPath   = kingpin.Flag("web.telemetry-path", "Path under which to expose metrics.").Default("/metrics").String()
		configFile    = kingpin.Flag("path.config", "Configuration YAML file path.").Default("config.yaml").String()
		num           int
		err           error
	)

	log.AddFlags(kingpin.CommandLine)
	kingpin.Version(version.Print("syncrepl_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	log.Infoln("Starting OpenLDAP Sync Replication Exporter", version.Info())
	log.Infoln("Build context", version.BuildContext())

	err = configor.Load(&Config, *configFile)
	if err != nil {
		log.Fatal(err)
	}

	log.Infof("Configuration:\n %+v", Config)

	go ldapWorker()

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		num, err = w.Write([]byte(`<html>
			<head><title>OpenLDAP Sync Replication Exporter</title></head>
			<body>
			<h1>OpenLDAP Sync Replication Exporter</h1>
			<p><a href="` + *metricsPath + `">Metrics</a></p>
			</body>
			</html>`))
		if err != nil {
			log.Fatal(num, err)
		}
	})

	log.Infoln("Listening on", *listenAddress)
	err = http.ListenAndServe(*listenAddress, nil)
	if err != nil {
		log.Fatal(err)
	}
}
