# Third-Party Licenses

Acore source files are distributed under Mozilla Public License 2.0 unless a
file states otherwise. This fork contains code derived from XTLS/Xray-core,
which is also distributed under MPL-2.0.

This inventory was checked on 2026-04-28 with:

```bash
go run github.com/google/go-licenses@latest report ./...
```

and by reading production dependency license fields from `package-lock.json`
and `dash/acore-dash/package-lock.json`.

## Go Dependencies

The Go dependency scan reported permissive licenses such as MIT, Apache-2.0,
BSD-2-Clause, BSD-3-Clause, plus MPL-2.0 dependencies.

The scan also reported these strong/copyleft dependencies:

- `github.com/sagernet/sing/common`: GPL-3.0
- `github.com/sagernet/sing-shadowsocks`: GPL-3.0
- `github.com/juju/ratelimit`: LGPL-3.0

Release binaries that include these packages must be distributed with the
corresponding source and license notices required by those licenses.

## Frontend Dependencies

The root UI and `dash/acore-dash` production dependencies in `package-lock.json`
currently report MIT licenses only.
