// purify-feeds-mcp exposes Purify's stable security-intelligence feeds to
// MCP clients (Claude Desktop, Cursor, ...).
//
// This is the productized sibling of the flywheel's search_feed tool: the
// same query semantics that were exercised by the wave15 trajectory batch,
// pointed at the LIVE records API instead of a pinned snapshot. Every
// response carries the feed version (dataset artifact hash + run id), so an
// agent can cite exactly which state of the feed an answer came from, and
// check_feed_changed gives loops a cheap "anything new since hash X?"
// primitive.
//
// Tools:
//   - list_feeds          feeds + record counts + version hashes
//   - search_feed         AND-filters / sort / cap-50 rows / exact total_matched
//   - get_provenance      the _purify passport of matching records + run chain
//   - check_feed_changed  manifest-hash comparison for incremental consumers
//
// Env:
//   PURIFY_API_URL  dataos-api base (default http://127.0.0.1:8091)
//   PURIFY_API_KEY  optional bearer token passed through to the API
//   PURIFY_FEEDS    optional "name=spec_id,..." to override the built-in set
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// Default feed registry: the production security bundle (dogfood project).
var defaultFeeds = map[string]string{
	"kev":      "8f52314e-04c1-486e-895c-9afdbed92ce5", // CISA KEV
	"enriched": "b0da3cad-47ff-4215-8444-9725f85338d3", // EPSS+KEV enriched
	"epss":     "6cde9a9b-082a-425b-830f-541aa665e55c", // EPSS high-risk
}

var feedFieldHints = map[string]string{
	"kev":      "cve_id, vendor_project, product, vulnerability_name, date_added, due_date, ransomware, required_action",
	"enriched": "cve_id, epss, percentile, risk_band, is_kev, kev_date_added, kev_due_date, source",
	"epss":     "cve_id, epss, percentile, risk_band, source",
}

// numericFields compare as floats in filters and sorts; everything else
// compares as strings (ISO dates order correctly as strings).
var numericFields = map[string]bool{"epss": true, "percentile": true}

const maxRows = 50
const pageSize = 1000

type manifest struct {
	SpecID       string   `json:"spec_id"`
	RunID        string   `json:"run_id"`
	RunStatus    string   `json:"run_status"`
	RunAt        string   `json:"run_at"`
	RecordCount  int      `json:"record_count"`
	ArtifactHash string   `json:"artifact_hash"`
	SchemaHint   []string `json:"schema_hint"`
}

type apiClient struct {
	base   string
	key    string
	client *http.Client
}

func (c *apiClient) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return err
	}
	if c.key != "" {
		req.Header.Set("Authorization", "Bearer "+c.key)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024*1024))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API %s -> HTTP %d: %s", path, resp.StatusCode, truncate(string(body), 200))
	}
	return json.Unmarshal(body, out)
}

func (c *apiClient) manifest(ctx context.Context, specID string) (*manifest, error) {
	var m manifest
	if err := c.getJSON(ctx, "/api/dataos/specs/"+specID+"/records/manifest", &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// feedStore caches each feed's full record set keyed by its dataset artifact
// hash: a cache entry is valid exactly as long as the feed version it was
// built from, so queries are always answered against one coherent version.
type feedStore struct {
	api   *apiClient
	feeds map[string]string // name -> spec_id

	mu    sync.Mutex
	cache map[string]*cachedFeed
}

type cachedFeed struct {
	hash     string
	manifest *manifest
	records  []map[string]any
}

func (s *feedStore) get(ctx context.Context, name string) (*cachedFeed, error) {
	specID, ok := s.feeds[name]
	if !ok {
		return nil, fmt.Errorf("unknown feed %q; available: %s", name, strings.Join(s.names(), ", "))
	}
	m, err := s.api.manifest(ctx, specID)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	entry := s.cache[name]
	s.mu.Unlock()
	if entry != nil && entry.hash == m.ArtifactHash {
		entry.manifest = m
		return entry, nil
	}

	var records []map[string]any
	for offset := 0; ; offset += pageSize {
		var page struct {
			Records []map[string]any `json:"records"`
		}
		path := fmt.Sprintf("/api/dataos/specs/%s/records?limit=%d&offset=%d&include_provenance=true",
			specID, pageSize, offset)
		if err := s.api.getJSON(ctx, path, &page); err != nil {
			return nil, err
		}
		records = append(records, page.Records...)
		if len(page.Records) < pageSize {
			break
		}
	}
	entry = &cachedFeed{hash: m.ArtifactHash, manifest: m, records: records}
	s.mu.Lock()
	s.cache[name] = entry
	s.mu.Unlock()
	return entry, nil
}

func (s *feedStore) names() []string {
	names := make([]string, 0, len(s.feeds))
	for n := range s.feeds {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ── filter / sort semantics (ported from the wave15 search_feed tool) ──

type filter struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value string `json:"value"`
}

// normalizeOp maps common aliases (eq, gte, …) onto the canonical
// operator set and rejects anything unknown. Without this an unknown
// op silently matched nothing, which reads as "0 results" instead of
// "you made a mistake" — the worst possible failure mode for an
// LLM-driven caller.
func normalizeOp(op string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(op)) {
	case "==", "=", "eq", "equals":
		return "==", nil
	case "!=", "ne", "neq", "not_equals":
		return "!=", nil
	case ">=", "gte":
		return ">=", nil
	case ">", "gt":
		return ">", nil
	case "<=", "lte":
		return "<=", nil
	case "<", "lt":
		return "<", nil
	case "contains":
		return "contains", nil
	}
	return "", fmt.Errorf("unknown filter op %q; valid: ==, !=, >=, >, <=, <, contains", op)
}

func matchFilter(rec map[string]any, f filter) bool {
	raw, ok := rec[f.Field]
	if !ok || raw == nil {
		return false
	}
	if numericFields[f.Field] {
		have, err1 := toFloat(raw)
		want, err2 := strconv.ParseFloat(f.Value, 64)
		if err1 != nil || err2 != nil {
			return false
		}
		switch f.Op {
		case "==":
			return have == want
		case "!=":
			return have != want
		case ">=":
			return have >= want
		case ">":
			return have > want
		case "<=":
			return have <= want
		case "<":
			return have < want
		}
		return false
	}
	have := fmt.Sprintf("%v", raw)
	switch f.Op {
	case "==":
		return have == f.Value
	case "!=":
		return have != f.Value
	case ">=":
		return have >= f.Value
	case ">":
		return have > f.Value
	case "<=":
		return have <= f.Value
	case "<":
		return have < f.Value
	case "contains":
		return strings.Contains(strings.ToLower(have), strings.ToLower(f.Value))
	}
	return false
}

func toFloat(v any) (float64, error) {
	switch t := v.(type) {
	case float64:
		return t, nil
	case string:
		return strconv.ParseFloat(t, 64)
	default:
		return 0, fmt.Errorf("not numeric: %T", v)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ── main ──────────────────────────────────────────────────────────────

func main() {
	apiURL := os.Getenv("PURIFY_API_URL")
	if apiURL == "" {
		apiURL = "http://127.0.0.1:8091"
	}
	feeds := map[string]string{}
	if raw := os.Getenv("PURIFY_FEEDS"); raw != "" {
		for _, pair := range strings.Split(raw, ",") {
			if name, spec, ok := strings.Cut(strings.TrimSpace(pair), "="); ok {
				feeds[name] = spec
			}
		}
	} else {
		feeds = defaultFeeds
	}

	store := &feedStore{
		api: &apiClient{
			base:   strings.TrimRight(apiURL, "/"),
			key:    os.Getenv("PURIFY_API_KEY"),
			client: &http.Client{Timeout: 60 * time.Second},
		},
		feeds: feeds,
		cache: map[string]*cachedFeed{},
	}

	s := server.NewMCPServer("purify-feeds", "1.0.0", server.WithToolCapabilities(false))

	s.AddTool(mcp.NewTool("list_feeds",
		mcp.WithDescription("List the available Purify security-intelligence feeds with their "+
			"current version (dataset artifact hash), record count, last run time and fields. "+
			"Feeds are continuously scheduled, quality-gated and self-healing; every record "+
			"carries full provenance."),
	), handleListFeeds(store))

	s.AddTool(mcp.NewToolWithRawSchema("search_feed",
		"Query one Purify security feed. Filters combine with AND; ops: ==, !=, >=, >, <=, <, "+
			"contains. epss/percentile compare numerically, dates as ISO strings. Returns JSON "+
			"with the feed version (artifact hash), exact total_matched, and up to 50 records "+
			"(sort with sort_by/order, trim with fields/limit). Use total_matched for counting; "+
			"narrow filters when a result is capped. Feeds: 'kev' (CISA Known Exploited "+
			"Vulnerabilities), 'enriched' (EPSS+KEV joined), 'epss' (EPSS high-risk).",
		json.RawMessage(`{"type":"object","properties":{
			"feed":{"type":"string","description":"feed name, e.g. kev | enriched | epss"},
			"filters":{"type":"array","items":{"type":"object","properties":{
				"field":{"type":"string"},
				"op":{"type":"string","enum":["==","!=",">=",">","<=","<","contains"]},
				"value":{"type":"string"}},
				"required":["field","op","value"]}},
			"sort_by":{"type":"string"},
			"order":{"type":"string","enum":["asc","desc"]},
			"limit":{"type":"integer"},
			"fields":{"type":"array","items":{"type":"string"}}},
			"required":["feed"]}`),
	), handleSearchFeed(store))

	s.AddTool(mcp.NewTool("get_provenance",
		mcp.WithDescription("Return the data passport of records matching a cve_id in a feed: the "+
			"per-record _purify block (source, fetch time, extractor, raw artifact hash/URI) plus "+
			"the feed's run chain (spec, run id, dataset artifact hash). Use this to cite or audit "+
			"any answer derived from the feeds."),
		mcp.WithString("feed", mcp.Required(), mcp.Description("feed name")),
		mcp.WithString("cve_id", mcp.Required(), mcp.Description("exact CVE id, e.g. CVE-2026-45659")),
	), handleGetProvenance(store))

	s.AddTool(mcp.NewTool("check_feed_changed",
		mcp.WithDescription("Cheap incremental primitive for agent loops: compare a previously "+
			"seen feed version hash against the current one. Returns changed=false if nothing "+
			"new, else the new artifact hash / run id / record count to re-query."),
		mcp.WithString("feed", mcp.Required(), mcp.Description("feed name")),
		mcp.WithString("known_hash", mcp.Description("artifact hash from a previous response; empty returns the current version")),
	), handleCheckChanged(store))

	if err := server.ServeStdio(s); err != nil {
		fmt.Fprintln(os.Stderr, "server error:", err)
		os.Exit(1)
	}
}

// ── handlers ──────────────────────────────────────────────────────────

func handleListFeeds(store *feedStore) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		out := make([]map[string]any, 0, len(store.feeds))
		for _, name := range store.names() {
			m, err := store.api.manifest(ctx, store.feeds[name])
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("feed %s: %v", name, err)), nil
			}
			out = append(out, map[string]any{
				"feed":          name,
				"record_count":  m.RecordCount,
				"last_run_at":   m.RunAt,
				"artifact_hash": m.ArtifactHash,
				"fields":        feedFieldHints[name],
			})
		}
		return jsonResult(map[string]any{"feeds": out})
	}
}

func handleSearchFeed(store *feedStore) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := request.GetArguments()
		name, _ := args["feed"].(string)
		entry, err := store.get(ctx, name)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		var filters []filter
		if rawFilters, ok := args["filters"]; ok && rawFilters != nil {
			blob, _ := json.Marshal(rawFilters)
			if err := json.Unmarshal(blob, &filters); err != nil {
				return mcp.NewToolResultError("filters must be a list of {field, op, value}"), nil
			}
		}
		for i := range filters {
			op, err := normalizeOp(filters[i].Op)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			filters[i].Op = op
		}

		rows := make([]map[string]any, 0, 256)
	scan:
		for _, rec := range entry.records {
			for _, f := range filters {
				if !matchFilter(rec, f) {
					continue scan
				}
			}
			rows = append(rows, rec)
		}

		if sortBy, _ := args["sort_by"].(string); sortBy != "" {
			desc := false
			if ord, _ := args["order"].(string); strings.EqualFold(ord, "desc") {
				desc = true
			}
			sort.SliceStable(rows, func(i, j int) bool {
				less := false
				if numericFields[sortBy] {
					a, _ := toFloat(rows[i][sortBy])
					b, _ := toFloat(rows[j][sortBy])
					less = a < b
				} else {
					less = fmt.Sprintf("%v", rows[i][sortBy]) < fmt.Sprintf("%v", rows[j][sortBy])
				}
				if desc {
					return !less && fmt.Sprintf("%v", rows[i][sortBy]) != fmt.Sprintf("%v", rows[j][sortBy])
				}
				return less
			})
		}

		limit := 10
		if rawLimit, ok := args["limit"].(float64); ok && rawLimit > 0 {
			limit = int(rawLimit)
		}
		if limit > maxRows {
			limit = maxRows
		}
		total := len(rows)
		if len(rows) > limit {
			rows = rows[:limit]
		}

		var fields []string
		if rawFields, ok := args["fields"].([]any); ok {
			for _, f := range rawFields {
				if fs, ok := f.(string); ok {
					fields = append(fields, fs)
				}
			}
		}
		outRows := make([]map[string]any, 0, len(rows))
		for _, rec := range rows {
			row := map[string]any{}
			if len(fields) > 0 {
				for _, f := range fields {
					row[f] = rec[f]
				}
			} else {
				for k, v := range rec {
					if k != "_purify" {
						row[k] = v
					}
				}
			}
			outRows = append(outRows, row)
		}

		return jsonResult(map[string]any{
			"feed":          name,
			"feed_version":  entry.manifest.ArtifactHash,
			"run_id":        entry.manifest.RunID,
			"run_at":        entry.manifest.RunAt,
			"total_matched": total,
			"returned":      len(outRows),
			"records":       outRows,
		})
	}
}

func handleGetProvenance(store *feedStore) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		name, err := request.RequireString("feed")
		if err != nil {
			return mcp.NewToolResultError("feed is required"), nil
		}
		cveID, err := request.RequireString("cve_id")
		if err != nil {
			return mcp.NewToolResultError("cve_id is required"), nil
		}
		entry, err := store.get(ctx, name)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		matches := make([]map[string]any, 0, 2)
		for _, rec := range entry.records {
			if fmt.Sprintf("%v", rec["cve_id"]) == cveID {
				matches = append(matches, map[string]any{
					"record":  stripProvenance(rec),
					"_purify": rec["_purify"],
				})
			}
		}
		if len(matches) == 0 {
			return mcp.NewToolResultError(fmt.Sprintf("no record with cve_id %s in feed %s", cveID, name)), nil
		}
		return jsonResult(map[string]any{
			"feed": name,
			"feed_run_chain": map[string]any{
				"spec_id":       entry.manifest.SpecID,
				"run_id":        entry.manifest.RunID,
				"run_at":        entry.manifest.RunAt,
				"artifact_hash": entry.manifest.ArtifactHash,
			},
			"matches": matches,
		})
	}
}

func handleCheckChanged(store *feedStore) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		name, err := request.RequireString("feed")
		if err != nil {
			return mcp.NewToolResultError("feed is required"), nil
		}
		specID, ok := store.feeds[name]
		if !ok {
			return mcp.NewToolResultError(fmt.Sprintf("unknown feed %q; available: %s",
				name, strings.Join(store.names(), ", "))), nil
		}
		m, err := store.api.manifest(ctx, specID)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		known := request.GetString("known_hash", "")
		return jsonResult(map[string]any{
			"feed":          name,
			"changed":       known == "" || known != m.ArtifactHash,
			"artifact_hash": m.ArtifactHash,
			"run_id":        m.RunID,
			"run_at":        m.RunAt,
			"record_count":  m.RecordCount,
		})
	}
}

func stripProvenance(rec map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range rec {
		if k != "_purify" {
			out[k] = v
		}
	}
	return out
}

func jsonResult(v any) (*mcp.CallToolResult, error) {
	blob, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("marshal result: %v", err)), nil
	}
	return mcp.NewToolResultText(string(blob)), nil
}
