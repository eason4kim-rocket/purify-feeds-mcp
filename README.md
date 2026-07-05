# purify-feeds-mcp

MCP server for Purify's production security-intelligence feeds. Lets Claude
Desktop, Cursor and other MCP clients query live CISA KEV / EPSS / enriched
vulnerability feeds — every answer carries an auditable feed version and full
per-record provenance.

The feeds behind this server are continuously scheduled, quality-gated and
self-healing. Each record ships with a `_purify` data passport: where it was
fetched from, when, with which extractor, and the hash of the raw artifact it
came from.

## Tools

| Tool | Purpose |
|---|---|
| `list_feeds` | List feeds with record counts and current version (dataset artifact hash) |
| `search_feed` | AND filters / sort / up to 50 rows, plus an exact `total_matched` count |
| `get_provenance` | Return a record's `_purify` passport and the feed's run chain, by CVE id |
| `check_feed_changed` | Incremental primitive: compare a known hash to detect new feed versions |

## Feeds

| Name | Contents |
|---|---|
| `kev` | CISA Known Exploited Vulnerabilities catalog |
| `epss` | EPSS high-risk slice (exploit prediction scores) |
| `enriched` | EPSS + KEV joined view with risk bands |

## Install

```bash
go install github.com/eason4kim-rocket/purify-feeds-mcp@latest
```

Or build from source:

```bash
git clone https://github.com/eason4kim-rocket/purify-feeds-mcp
cd purify-feeds-mcp && go build .
```

## Configure (Claude Desktop)

`~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "purify-feeds": {
      "command": "/path/to/purify-feeds-mcp",
      "env": {
        "PURIFY_API_URL": "https://<gateway-host>/feeds-api",
        "PURIFY_API_KEY": "<your-api-key>"
      }
    }
  }
}
```

The public gateway is read-only (GET only, feed whitelist, per-key rate
limits). API keys are issued manually during the pilot — open an issue or
contact the maintainer to get one.

## Environment variables

- `PURIFY_API_URL` — feeds API base URL (default `http://127.0.0.1:8091` for local/dev use)
- `PURIFY_API_KEY` — API key, sent as a bearer token (required for the public gateway)
- `PURIFY_FEEDS` — override the built-in feed table: `name=spec_id,...`

## Example prompts

- "Which CVEs entered CISA KEV in the last 7 days? Give vendors and remediation due dates."
- "How many CVEs have EPSS > 0.99 and are in KEV? Top 5?"
- "Where does the data for CVE-2026-45659 come from?" (`get_provenance` returns the full passport)
- Agent loops: remember `artifact_hash`, call `check_feed_changed` first on the
  next run, and only re-triage when the feed actually changed.

## License

MIT
