package blackhole_test

import (
	"bufio"
	"net/http"
	"testing"
	"time"

	"github.com/ImAubrey/acore/common"
	"github.com/ImAubrey/acore/common/buf"
	. "github.com/ImAubrey/acore/proxy/blackhole"
)

func TestHTTPResponse(t *testing.T) {
	buffer := buf.New()

	httpResponse := new(HTTPResponse)
	httpResponse.WriteTo(buf.NewWriter(buffer))

	reader := bufio.NewReader(buffer)
	response, err := http.ReadResponse(reader, nil)
	common.Must(err)

	if response.StatusCode != 403 {
		t.Error("expected status code 403, but got ", response.StatusCode)
	}
	if !response.Close {
		t.Error("expected response connection to be closed")
	}
	if response.Header.Get("Date") == "" {
		t.Error("expected date header")
	}
	if _, err := time.Parse(http.TimeFormat, response.Header.Get("Date")); err != nil {
		t.Error("invalid date header: ", err)
	}
}

func TestHTTPCustomResponse(t *testing.T) {
	buffer := buf.New()

	httpResponse := &HTTPCustomResponse{StatusCode: 204}
	httpResponse.WriteTo(buf.NewWriter(buffer))

	reader := bufio.NewReader(buffer)
	response, err := http.ReadResponse(reader, nil)
	common.Must(err)

	if response.StatusCode != 204 {
		t.Error("expected status code 204, but got ", response.StatusCode)
	}
	if response.Close {
		t.Error("expected response connection to stay reusable for 204")
	}
	if response.ContentLength != 0 {
		t.Error("expected content length 0, but got ", response.ContentLength)
	}
	if got := response.Header.Get("Cross-Origin-Resource-Policy"); got != "cross-origin" {
		t.Error("unexpected Cross-Origin-Resource-Policy: ", got)
	}
	if got := response.Header.Get("Alt-Svc"); got != `h3=":443"; ma=2592000,h3-29=":443"; ma=2592000` {
		t.Error("unexpected Alt-Svc: ", got)
	}
	if response.Header.Get("Date") == "" {
		t.Error("expected date header")
	}
	if _, err := time.Parse(http.TimeFormat, response.Header.Get("Date")); err != nil {
		t.Error("invalid date header: ", err)
	}
}

func TestHTTPCustomResponseRedirect(t *testing.T) {
	buffer := buf.New()
	redirectURL := "https://example.com/path?a=1&b=2"

	httpResponse := &HTTPCustomResponse{
		StatusCode:  302,
		RedirectUrl: redirectURL,
	}
	httpResponse.WriteTo(buf.NewWriter(buffer))

	reader := bufio.NewReader(buffer)
	response, err := http.ReadResponse(reader, nil)
	common.Must(err)

	if response.StatusCode != 302 {
		t.Error("expected status code 302, but got ", response.StatusCode)
	}
	if got := response.Header.Get("Location"); got != redirectURL {
		t.Error("unexpected Location: ", got)
	}
	if !response.Close {
		t.Error("expected response connection to be closed")
	}
}
