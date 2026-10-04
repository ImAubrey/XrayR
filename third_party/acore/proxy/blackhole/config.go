package blackhole

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/buf"
)

// ResponseConfig is the configuration for blackhole responses.
type ResponseConfig interface {
	// WriteTo writes a predefined response to the specified buffer.
	WriteTo(buf.Writer) int32
}

// WriteTo implements ResponseConfig.WriteTo().
func (*NoneResponse) WriteTo(buf.Writer) int32 { return 0 }

func writeHTTPResponse(writer buf.Writer, statusCode int, redirectURL string) int32 {
	if statusCode <= 0 {
		statusCode = http.StatusForbidden
	}
	statusText := http.StatusText(statusCode)
	if statusText == "" {
		statusText = "Unknown"
	}
	date := time.Now().UTC().Format(http.TimeFormat)
	response := fmt.Sprintf("HTTP/1.1 %d %s\r\nConnection: close\r\nCache-Control: max-age=3600, public\r\nContent-Length: 0\r\nDate: %s\r\n\r\n", statusCode, statusText, date)
	if statusCode == http.StatusNoContent {
		response = fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: 0\r\nCross-Origin-Resource-Policy: cross-origin\r\nDate: %s\r\nAlt-Svc: h3=\":443\"; ma=2592000,h3-29=\":443\"; ma=2592000\r\n\r\n", statusCode, statusText, date)
	}
	if (statusCode == http.StatusMovedPermanently || statusCode == http.StatusFound) && redirectURL != "" {
		location := strings.TrimSpace(redirectURL)
		// Reject CRLF in Location to avoid response splitting.
		if !strings.ContainsAny(location, "\r\n") {
			response = fmt.Sprintf("HTTP/1.1 %d %s\r\nLocation: %s\r\nConnection: close\r\nCache-Control: max-age=3600, public\r\nContent-Length: 0\r\nDate: %s\r\n\r\n", statusCode, statusText, location, date)
		}
	}
	b := buf.New()
	common.Must2(b.WriteString(response))
	n := b.Len()
	writer.WriteMultiBuffer(buf.MultiBuffer{b})
	return n
}

// WriteTo implements ResponseConfig.WriteTo().
func (*HTTPResponse) WriteTo(writer buf.Writer) int32 {
	return writeHTTPResponse(writer, http.StatusForbidden, "")
}

// WriteTo implements ResponseConfig.WriteTo().
func (r *HTTPCustomResponse) WriteTo(writer buf.Writer) int32 {
	return writeHTTPResponse(writer, int(r.StatusCode), r.RedirectUrl)
}

// TLS Alert codes
const (
	TLSAlertHandshakeFailure    = 40
	TLSAlertProtocolVersion     = 70
	TLSAlertInternalError       = 80
	TLSAlertUnrecognizedName    = 112
	TLSAlertCertificateRequired = 116
)

// WriteTo implements ResponseConfig.WriteTo().
// Sends a TLS Alert record to simulate SSL/TLS errors.
func (r *TLSAlertResponse) WriteTo(writer buf.Writer) int32 {
	alertCode := byte(r.AlertCode)
	if alertCode == 0 {
		alertCode = TLSAlertHandshakeFailure // default to handshake_failure (40)
	}

	// TLS Alert Record:
	// - Content Type: 21 (0x15) = Alert
	// - Version: TLS 1.2 = 0x0303
	// - Length: 2 bytes
	// - Alert Level: 2 (fatal)
	// - Alert Description: alert code
	tlsAlert := []byte{
		0x15,       // Content Type: Alert
		0x03, 0x03, // Version: TLS 1.2
		0x00, 0x02, // Length: 2 bytes
		0x02,      // Alert Level: fatal
		alertCode, // Alert Description
	}

	b := buf.New()
	common.Must2(b.Write(tlsAlert))
	n := b.Len()
	writer.WriteMultiBuffer(buf.MultiBuffer{b})
	return n
}

// GetInternalResponse converts response settings from proto to internal data structure.
func (c *Config) GetInternalResponse() (ResponseConfig, error) {
	if c.GetResponse() == nil {
		return new(NoneResponse), nil
	}

	config, err := c.GetResponse().GetInstance()
	if err != nil {
		return nil, err
	}
	return config.(ResponseConfig), nil
}
