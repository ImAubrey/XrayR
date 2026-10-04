package conf_test

import (
	"testing"

	"github.com/ImAubrey/acore/common/serial"
	. "github.com/ImAubrey/acore/infra/conf"
	"github.com/ImAubrey/acore/proxy/blackhole"
)

func TestHTTPResponseJSON(t *testing.T) {
	creator := func() Buildable {
		return new(BlackholeConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"response": {
					"type": "http"
				}
			}`,
			Parser: loadJSON(creator),
			Output: &blackhole.Config{
				Response: serial.ToTypedMessage(&blackhole.HTTPResponse{}),
			},
		},
		{
			Input: `{
				"response": {
					"type": "http-204"
				}
			}`,
			Parser: loadJSON(creator),
			Output: &blackhole.Config{
				Response: serial.ToTypedMessage(&blackhole.HTTPCustomResponse{
					StatusCode: 204,
				}),
			},
		},
		{
			Input: `{
				"response": {
					"type": "http-302",
					"redirect_url": "https://example.com/path?a=1&b=2"
				}
			}`,
			Parser: loadJSON(creator),
			Output: &blackhole.Config{
				Response: serial.ToTypedMessage(&blackhole.HTTPCustomResponse{
					StatusCode:  302,
					RedirectUrl: "https://example.com/path?a=1&b=2",
				}),
			},
		},
		{
			Input: `{
				"response": {
					"type": "http-301",
					"url": "https://example.com/moved?q=ok"
				}
			}`,
			Parser: loadJSON(creator),
			Output: &blackhole.Config{
				Response: serial.ToTypedMessage(&blackhole.HTTPCustomResponse{
					StatusCode:  301,
					RedirectUrl: "https://example.com/moved?q=ok",
				}),
			},
		},
		{
			Input:  `{}`,
			Parser: loadJSON(creator),
			Output: &blackhole.Config{},
		},
	})
}
