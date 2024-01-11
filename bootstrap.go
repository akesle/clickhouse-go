package clickhouse

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ClickHouse/clickhouse-go/lib/leakypool"

	"github.com/ClickHouse/clickhouse-go/lib/binary"
	"github.com/ClickHouse/clickhouse-go/lib/data"
	"github.com/ClickHouse/clickhouse-go/lib/protocol"
)

const (
	// DefaultDatabase when connecting to ClickHouse
	DefaultDatabase = "default"
	// DefaultUsername when connecting to ClickHouse
	DefaultUsername = "default"
	// DefaultConnTimeout when connecting to ClickHouse
	DefaultConnTimeout = 5 * time.Second
	// DefaultReadTimeout when reading query results
	DefaultReadTimeout = time.Minute
	// DefaultWriteTimeout when sending queries
	DefaultWriteTimeout = time.Minute
)

var (
	unixtime    int64
	logOutput   io.Writer = os.Stdout
	hostname, _           = os.Hostname()
	poolInit    sync.Once
)

func init() {
	sql.Register("clickhouse", &bootstrap{})
	go func() {
		for tick := time.Tick(time.Second); ; {
			select {
			case <-tick:
				atomic.AddInt64(&unixtime, int64(time.Second))
			}
		}
	}()
}

func now() time.Time {
	return time.Unix(0, atomic.LoadInt64(&unixtime))
}

type bootstrap struct{}

func (d *bootstrap) Open(dsn string) (driver.Conn, error) {
	return Open(dsn)
}

// SetLogOutput allows to change output of the default logger
func SetLogOutput(output io.Writer) {
	logOutput = output
}

// Open the connection
func Open(dsn string) (driver.Conn, error) {
	clickhouse, err := open(dsn)
	if err != nil {
		return nil, err
	}

	return clickhouse, err
}

func open(dsn string) (*clickhouse, error) {
	url, err := url.Parse(dsn)
	if err != nil {
		return nil, err
	}
	var (
		hosts            = []string{url.Host}
		query            = url.Query()
		secure           = false
		skipVerify       = false
		tlsConfigName    = query.Get("tls_config")
		noDelay          = true
		compress         = false
		database         = query.Get("database")
		username         = query.Get("username")
		password         = query.Get("password")
		blockSize        = 1000000
		connTimeout      = DefaultConnTimeout
		readTimeout      = DefaultReadTimeout
		writeTimeout     = DefaultWriteTimeout
		connOpenStrategy = connOpenRandom
		poolSize         = 100
		cert             = query.Get("cert")
		key              = query.Get("key")
		caCert           = query.Get("cacert")
	)
	if len(database) == 0 {
		database = DefaultDatabase
	}
	if len(username) == 0 {
		username = DefaultUsername
	}
	if v, err := strconv.ParseBool(query.Get("no_delay")); err == nil {
		noDelay = v
	}
	if len(tlsConfigName) > 0 {
		if (len(cert) > 0) != (len(key) > 0) {
			return nil,
				errors.New("either both or neither cert and key must be specified, but only one is present")
		}
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
		caPool := x509.NewCertPool()
		if len(caCert) > 0 {
			cert, err := os.ReadFile(caCert)
			if err != nil {
				return nil, fmt.Errorf("failure to read cacert: %v", err)
			}
			if ok := caPool.AppendCertsFromPEM(cert); !ok {
				return nil, fmt.Errorf("failure to parse cacert: %q", caCert)
			}
		} else {
			var err error
			caPool, err = x509.SystemCertPool()
			if err != nil {
				return nil, fmt.Errorf("failure to load system CA certs: %v", err)
			}
		}
		tlsConfig.RootCAs = caPool
		var clientCert []byte
		if len(cert) > 0 {
			var err error
			clientCert, err = os.ReadFile(cert)
			if err != nil {
				return nil, fmt.Errorf("failure to read cert: %v", err)
			}
		}
		var clientKey []byte
		if len(key) > 0 {
			var err error
			clientKey, err = os.ReadFile(key)
			if err != nil {
				return nil, fmt.Errorf("failure to read key: %v", err)
			}
		}
		if (len(clientCert) > 0) != (len(clientKey) > 0) {
			return nil,
				errors.New("either both or neither cert and key must be present, but only one is provided")
		}
		if (len(clientCert) > 0) && (len(clientKey) > 0) {
			certificate, err := tls.X509KeyPair(clientCert, clientKey)
			if err != nil {
				return nil, fmt.Errorf("failed to formalize TLS client cert: %v", err)
			}
			tlsConfig.Certificates = append(tlsConfig.Certificates, certificate)
		}
		if err := RegisterTLSConfig(tlsConfigName, tlsConfig); err != nil {
			return nil, fmt.Errorf("failure to register TLS config: %q", tlsConfigName)
		}
	}
	tlsConfig := getTLSConfigClone(tlsConfigName)
	if tlsConfigName != "" && tlsConfig == nil {
		return nil, fmt.Errorf("invalid tls_config - no config registered under name %s", tlsConfigName)
	}
	secure = tlsConfig != nil
	if v, err := strconv.ParseBool(query.Get("secure")); err == nil {
		secure = v
	}
	if v, err := strconv.ParseBool(query.Get("skip_verify")); err == nil {
		skipVerify = v
	}
	if duration, err := strconv.ParseFloat(query.Get("timeout"), 64); err == nil {
		connTimeout = time.Duration(duration * float64(time.Second))
	}
	if duration, err := strconv.ParseFloat(query.Get("read_timeout"), 64); err == nil {
		readTimeout = time.Duration(duration * float64(time.Second))
	}
	if duration, err := strconv.ParseFloat(query.Get("write_timeout"), 64); err == nil {
		writeTimeout = time.Duration(duration * float64(time.Second))
	}
	if size, err := strconv.ParseInt(query.Get("block_size"), 10, 64); err == nil {
		blockSize = int(size)
	}
	if size, err := strconv.ParseInt(query.Get("pool_size"), 10, 64); err == nil {
		poolSize = int(size)
	}
	poolInit.Do(func() {
		leakypool.InitBytePool(poolSize)
	})
	if altHosts := strings.Split(query.Get("alt_hosts"), ","); len(altHosts) != 0 {
		for _, host := range altHosts {
			if len(host) != 0 {
				hosts = append(hosts, host)
			}
		}
	}
	switch query.Get("connection_open_strategy") {
	case "random":
		connOpenStrategy = connOpenRandom
	case "in_order":
		connOpenStrategy = connOpenInOrder
	case "time_random":
		connOpenStrategy = connOpenTimeRandom
	}

	settings, err := makeQuerySettings(query)
	if err != nil {
		return nil, err
	}

	if v, err := strconv.ParseBool(query.Get("compress")); err == nil {
		compress = v
	}

	var (
		ch = clickhouse{
			logf:      func(string, ...interface{}) {},
			settings:  settings,
			compress:  compress,
			blockSize: blockSize,
			ServerInfo: data.ServerInfo{
				Timezone: time.Local,
			},
		}
		logger = log.New(logOutput, "[clickhouse]", 0)
	)
	if debug, err := strconv.ParseBool(url.Query().Get("debug")); err == nil && debug {
		ch.logf = logger.Printf
	}
	ch.logf("host(s)=%s, database=%s, username=%s",
		strings.Join(hosts, ", "),
		database,
		username,
	)
	options := connOptions{
		secure:       secure,
		tlsConfig:    tlsConfig,
		skipVerify:   skipVerify,
		hosts:        hosts,
		connTimeout:  connTimeout,
		readTimeout:  readTimeout,
		writeTimeout: writeTimeout,
		noDelay:      noDelay,
		openStrategy: connOpenStrategy,
		logf:         ch.logf,
	}
	if ch.conn, err = dial(options); err != nil {
		return nil, err
	}
	logger.SetPrefix(fmt.Sprintf("[clickhouse][connect=%d]", ch.conn.ident))
	ch.buffer = bufio.NewWriter(ch.conn)

	ch.decoder = binary.NewDecoderWithCompress(ch.conn)
	ch.encoder = binary.NewEncoderWithCompress(ch.buffer)

	if err := ch.hello(database, username, password); err != nil {
		ch.conn.Close()
		return nil, err
	}
	return &ch, nil
}

func (ch *clickhouse) hello(database, username, password string) error {
	ch.logf("[hello] -> %s", ch.ClientInfo)
	{
		ch.encoder.Uvarint(protocol.ClientHello)
		if err := ch.ClientInfo.Write(ch.encoder); err != nil {
			return err
		}
		{
			ch.encoder.String(database)
			ch.encoder.String(username)
			ch.encoder.String(password)
		}
		if err := ch.encoder.Flush(); err != nil {
			return err
		}

	}
	{
		packet, err := ch.decoder.Uvarint()
		if err != nil {
			return err
		}
		switch packet {
		case protocol.ServerException:
			return ch.exception()
		case protocol.ServerHello:
			if err := ch.ServerInfo.Read(ch.decoder); err != nil {
				return err
			}
		case protocol.ServerEndOfStream:
			ch.logf("[bootstrap] <- end of stream")
			return nil
		default:
			return fmt.Errorf("[hello] unexpected packet [%d] from server", packet)
		}
	}
	ch.logf("[hello] <- %s", ch.ServerInfo)
	return nil
}
