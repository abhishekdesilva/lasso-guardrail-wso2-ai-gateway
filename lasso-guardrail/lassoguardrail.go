/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

// Package lassoguardrail screens LLM chat traffic with Lasso Security's
// classify/classifix API, ported from the reference Kong plugin
// (github.com/lasso-security/kong-ai-lasso-guardrail) onto the WSO2 AI
// Gateway policy SDK.
package lassoguardrail

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	defaultAPIBase       = "https://server.lasso.security/gateway/v3"
	defaultSessionHeader = "x-session-id"
	defaultUserHeader    = "x-lasso-user-id"
	defaultSourceType    = "wso2-ai-gateway"
	defaultTimeoutMillis = 10000

	// sharedMetadataSessionKey is the SharedContext.Metadata key the request
	// phase stashes its sessionId under, so the response phase reuses the
	// exact same value — mirrors Kong's kong.ctx.shared.lasso_session_id.
	sharedMetadataSessionKey = "lasso_guardrail:session_id"

	blockStatusCode = 400
)

// ── Config ───────────────────────────────────────────────────────────────────

// phaseConfig holds the per-phase (request or response) settings.
type phaseConfig struct {
	enabled            bool
	passthroughOnError bool
}

// LassoGuardrailPolicy implements the Lasso Security guardrail.
type LassoGuardrailPolicy struct {
	apiKey  string
	apiBase string
	client  *http.Client

	request  phaseConfig
	response phaseConfig

	masking       bool
	includeTools  bool
	sessionHeader string
	userHeader    string
	sourceType    string
}

// GetPolicy is the v1alpha2 factory entry point (loaded by v1alpha2 kernels).
func GetPolicy(metadata policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	apiKey := getStringParam(params, "lassoApiKey")
	if apiKey == "" {
		return nil, fmt.Errorf("'lassoApiKey' parameter is required")
	}

	apiBase := getStringParam(params, "lassoApiBase")
	if apiBase == "" {
		apiBase = defaultAPIBase
	}

	p := &LassoGuardrailPolicy{
		apiKey:        apiKey,
		apiBase:       apiBase,
		masking:       getBoolParam(params, "masking", false),
		includeTools:  true,
		sessionHeader: defaultSessionHeader,
		userHeader:    defaultUserHeader,
		sourceType:    defaultSourceType,
	}

	timeoutMillis := getIntParam(params, "timeoutMillis", defaultTimeoutMillis)
	p.client = &http.Client{Timeout: time.Duration(timeoutMillis) * time.Millisecond}

	if requestRaw, ok := params["request"].(map[string]interface{}); ok {
		p.request = phaseConfig{
			enabled:            true,
			passthroughOnError: getBoolParam(requestRaw, "passthroughOnError", true),
		}
		p.includeTools = getBoolParam(requestRaw, "includeTools", true)
	}

	if responseRaw, ok := params["response"].(map[string]interface{}); ok {
		p.response = phaseConfig{
			enabled:            true,
			passthroughOnError: getBoolParam(responseRaw, "passthroughOnError", true),
		}
	}

	if !p.request.enabled && !p.response.enabled {
		return nil, fmt.Errorf("at least one of 'request' or 'response' parameters must be provided")
	}

	if v := getStringParam(params, "sessionHeader"); v != "" {
		p.sessionHeader = v
	}
	if v := getStringParam(params, "userHeader"); v != "" {
		p.userHeader = v
	}
	if v := getStringParam(params, "sourceType"); v != "" {
		p.sourceType = v
	}

	slog.Debug("LassoGuardrail: policy initialized",
		"apiBase", p.apiBase, "masking", p.masking,
		"requestEnabled", p.request.enabled, "responseEnabled", p.response.enabled)

	return p, nil
}

// Mode declares buffered-body processing for both phases; OnRequestBody /
// OnResponseBody no-op internally when that phase isn't configured — same
// pattern the azure-content-safety-content-moderation policy uses.
func (p *LassoGuardrailPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeSkip,
		RequestBodyMode:    policy.BodyModeBuffer,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeBuffer,
	}
}

// ── Wire types (OpenAI-compatible chat body) ────────────────────────────────

// chatMessage mirrors the OpenAI chat wire shape. Content is left as
// interface{} because multimodal content arrives as an array of blocks
// rather than a plain string; flattenContent below reduces it to text for
// classification. Only messages whose original Content was a plain string
// are eligible to be rewritten by masking (see maskableContent).
type chatMessage struct {
	Role       string          `json:"role"`
	Content    interface{}     `json:"content,omitempty"`
	ToolCalls  json.RawMessage `json:"tool_calls,omitempty"`
	ToolCallID string          `json:"tool_call_id,omitempty"`
}

type chatRequestBody struct {
	Messages []chatMessage `json:"messages"`
	Tools    []interface{} `json:"tools,omitempty"`
}

type chatChoice struct {
	Message chatMessage `json:"message"`
}

type chatResponseBody struct {
	Choices []chatChoice `json:"choices"`
}

func flattenContent(content interface{}) (text string, maskable bool) {
	switch v := content.(type) {
	case string:
		return v, true
	case []interface{}:
		var out string
		for _, block := range v {
			m, ok := block.(map[string]interface{})
			if !ok {
				continue
			}
			if t, _ := m["type"].(string); t == "text" {
				if s, _ := m["text"].(string); s != "" {
					if out != "" {
						out += " "
					}
					out += s
				}
			}
		}
		return out, false // multimodal content: classified, but not rewritten by masking
	default:
		return "", false
	}
}

// ── Lasso API contract ──────────────────────────────────────────────────────
// Mirrors github.com/lasso-security/kong-ai-lasso-guardrail (lasso.lua /
// client.lua): POST {apiBase}/classify or /classifix, header
// "lasso-api-key: <key>", body {messages, messageType, sessionId, source,
// userId?, tools?}. Response: {violations_detected, findings: {<deputy>:
// [{action, name, severity, start, end, mask, message_index}]}, messages?}.

type lassoScanMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type lassoRequest struct {
	Messages    []lassoScanMessage `json:"messages"`
	MessageType string             `json:"messageType"`
	SessionID   string             `json:"sessionId"`
	Source      lassoSource        `json:"source"`
	UserID      string             `json:"userId,omitempty"`
	Tools       []interface{}      `json:"tools,omitempty"`
}

type lassoSource struct {
	Type string `json:"type"`
}

type lassoFinding struct {
	Action       string `json:"action"` // "BLOCK" | "AUTO_MASKING" | "USER_ALERT" | "ADMIN_ALERT" | "OFF"
	Name         string `json:"name"`
	Severity     string `json:"severity"`
	Start        int    `json:"start"`
	End          int    `json:"end"`
	Mask         string `json:"mask"`
	MessageIndex int    `json:"message_index"`
}

type lassoResponse struct {
	ViolationsDetected bool                      `json:"violations_detected"`
	Findings           map[string][]lassoFinding `json:"findings"`
	// Messages carries Lasso's own masked replacement content (authoritative)
	// when present and returned by /classifix.
	Messages []lassoScanMessage `json:"messages,omitempty"`
}

// errKind distinguishes an auth failure (must never be silently swallowed by
// fail-open) from any other transport/HTTP error.
type errKind int

const (
	errKindNone errKind = iota
	errKindAuth
	errKindOther
)

func (p *LassoGuardrailPolicy) callLasso(ctx context.Context, endpoint string, reqBody lassoRequest) (*lassoResponse, errKind, error) {
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, errKindOther, fmt.Errorf("failed to marshal lasso request: %w", err)
	}

	url := p.apiBase + "/" + endpoint
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, errKindOther, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("lasso-api-key", p.apiKey)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, errKindOther, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return nil, errKindAuth, fmt.Errorf("lasso API auth error: status %d", resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, errKindOther, fmt.Errorf("lasso API returned status %d: %s", resp.StatusCode, string(body))
	}

	var out lassoResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, errKindOther, fmt.Errorf("failed to decode lasso response: %w", err)
	}
	return &out, errKindNone, nil
}

// decision is the outcome of one classify/classifix call.
type decision struct {
	action string // "allow" | "block" | "mask"
	detail string
}

// decide mirrors lasso.decide: any BLOCK finding wins outright; otherwise,
// with masking enabled and at least one AUTO_MASKING finding, the scan
// messages are rewritten in place and "mask" is returned.
func decide(resp *lassoResponse, scan []lassoScanMessage, masking bool) decision {
	if !resp.ViolationsDetected {
		return decision{action: "allow"}
	}

	if blocked, detail := extractBlock(resp.Findings); blocked {
		return decision{action: "block", detail: detail}
	}

	if masking && applyMasks(scan, resp) {
		return decision{action: "mask"}
	}

	return decision{action: "allow"}
}

func extractBlock(findings map[string][]lassoFinding) (bool, string) {
	var details []string
	for deputy, list := range findings {
		for _, f := range list {
			if f.Action == "BLOCK" {
				sev := ""
				if f.Severity != "" {
					sev = " (" + f.Severity + ")"
				}
				name := f.Name
				if name == "" {
					name = "violation"
				}
				details = append(details, deputy+"/"+name+sev)
			}
		}
	}
	if len(details) == 0 {
		return false, ""
	}
	detail := details[0]
	for _, d := range details[1:] {
		detail += "; " + d
	}
	return true, detail
}

// applyMasks rewrites `scan` in place. Prefers Lasso's own authoritative
// masked `messages` (from /classifix) when the shape matches; otherwise
// applies per-finding start/end/mask byte-offset spans (0-based,
// end-exclusive, applied highest-offset-first so earlier offsets stay
// valid). Only AUTO_MASKING findings are applied. Returns whether anything
// changed.
func applyMasks(scan []lassoScanMessage, resp *lassoResponse) bool {
	if len(resp.Messages) == len(scan) && len(scan) > 0 {
		transformed := false
		for i := range scan {
			if resp.Messages[i].Content != scan[i].Content {
				scan[i].Content = resp.Messages[i].Content
				transformed = true
			}
		}
		if transformed {
			return true
		}
	}

	type span struct {
		start, end int
		mask       string
	}
	byIndex := map[int][]span{}
	for _, list := range resp.Findings {
		for _, f := range list {
			if f.Action == "AUTO_MASKING" && f.Mask != "" && f.End > f.Start {
				byIndex[f.MessageIndex] = append(byIndex[f.MessageIndex], span{f.Start, f.End, f.Mask})
			}
		}
	}

	transformed := false
	for idx, spans := range byIndex {
		if idx < 0 || idx >= len(scan) {
			continue
		}
		content := scan[idx].Content
		// Highest offset first so earlier offsets aren't shifted by a
		// preceding replacement.
		for i := 0; i < len(spans); i++ {
			for j := i + 1; j < len(spans); j++ {
				if spans[j].start > spans[i].start {
					spans[i], spans[j] = spans[j], spans[i]
				}
			}
		}
		for _, s := range spans {
			if s.start >= 0 && s.end <= len(content) {
				content = content[:s.start] + s.mask + content[s.end:]
			}
		}
		if content != scan[idx].Content {
			scan[idx].Content = content
			transformed = true
		}
	}
	return transformed
}

// ── Phase handlers ───────────────────────────────────────────────────────────

func (p *LassoGuardrailPolicy) OnRequestBody(ctx context.Context, reqCtx *policy.RequestContext, _ map[string]interface{}) policy.RequestAction {
	if !p.request.enabled {
		return policy.UpstreamRequestModifications{}
	}

	var content []byte
	if reqCtx.Body != nil {
		content = reqCtx.Body.Content
	}
	if content == nil {
		return policy.UpstreamRequestModifications{}
	}

	var body chatRequestBody
	if err := json.Unmarshal(content, &body); err != nil || len(body.Messages) == 0 {
		// Not a chat body this policy understands — pass through untouched.
		return policy.UpstreamRequestModifications{}
	}

	scan := make([]lassoScanMessage, len(body.Messages))
	maskable := make([]bool, len(body.Messages))
	for i, m := range body.Messages {
		text, ok := flattenContent(m.Content)
		scan[i] = lassoScanMessage{Role: m.Role, Content: text}
		maskable[i] = ok
	}

	sessionID := p.sessionID(reqCtx.Headers, reqCtx.RequestID)
	if reqCtx.Metadata != nil {
		reqCtx.Metadata[sharedMetadataSessionKey] = sessionID
	}

	var tools []interface{}
	if p.includeTools {
		tools = body.Tools
	}

	lreq := lassoRequest{
		Messages:    scan,
		MessageType: "PROMPT",
		SessionID:   sessionID,
		Source:      lassoSource{Type: p.sourceType},
		UserID:      firstHeader(reqCtx.Headers, p.userHeader),
		Tools:       tools,
	}

	endpoint := "classify"
	if p.masking {
		endpoint = "classifix"
	}

	resp, kind, err := p.callLasso(ctx, endpoint, lreq)
	if err != nil {
		return p.handleRequestError(kind, err, p.request.passthroughOnError)
	}

	d := decide(resp, scan, p.masking)
	switch d.action {
	case "block":
		return p.blockResponse(d.detail)
	case "mask":
		for i, m := range scan {
			if maskable[i] {
				body.Messages[i].Content = m.Content
			}
		}
		rewritten, err := rewriteField(content, "messages", body.Messages)
		if err != nil {
			slog.Error("LassoGuardrail: failed to re-encode masked request body", "error", err)
			return policy.UpstreamRequestModifications{}
		}
		return policy.UpstreamRequestModifications{Body: rewritten}
	default:
		return policy.UpstreamRequestModifications{}
	}
}

// rewriteField re-marshals `original` with just `key` replaced by `value`,
// leaving every other top-level field (model, temperature, stream, usage,
// id, ...) byte-for-byte untouched. chatRequestBody/chatResponseBody only
// declare the fields this policy cares about, so marshaling those structs
// directly would silently drop everything else — e.g. a masked request
// would reach the model with no "model" field at all.
func rewriteField(original []byte, key string, value interface{}) ([]byte, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(original, &raw); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	raw[key] = encoded
	return json.Marshal(raw)
}

func (p *LassoGuardrailPolicy) OnResponseBody(ctx context.Context, respCtx *policy.ResponseContext, _ map[string]interface{}) policy.ResponseAction {
	if !p.response.enabled {
		return policy.DownstreamResponseModifications{}
	}

	var content []byte
	if respCtx.ResponseBody != nil {
		content = respCtx.ResponseBody.Content
	}
	if content == nil {
		return policy.DownstreamResponseModifications{}
	}

	var body chatResponseBody
	if err := json.Unmarshal(content, &body); err != nil || len(body.Choices) == 0 {
		return policy.DownstreamResponseModifications{}
	}

	scan := make([]lassoScanMessage, len(body.Choices))
	maskable := make([]bool, len(body.Choices))
	for i, c := range body.Choices {
		text, ok := flattenContent(c.Message.Content)
		role := c.Message.Role
		if role == "" {
			role = "assistant"
		}
		scan[i] = lassoScanMessage{Role: role, Content: text}
		maskable[i] = ok
	}

	sessionID := ""
	if respCtx.Metadata != nil {
		if v, ok := respCtx.Metadata[sharedMetadataSessionKey].(string); ok {
			sessionID = v
		}
	}
	if sessionID == "" {
		sessionID = p.sessionID(respCtx.RequestHeaders, respCtx.RequestID)
	}

	lreq := lassoRequest{
		Messages:    scan,
		MessageType: "COMPLETION",
		SessionID:   sessionID,
		Source:      lassoSource{Type: p.sourceType},
		UserID:      firstHeader(respCtx.RequestHeaders, p.userHeader),
	}

	endpoint := "classify"
	if p.masking {
		endpoint = "classifix"
	}

	resp, kind, err := p.callLasso(ctx, endpoint, lreq)
	if err != nil {
		return p.handleResponseError(kind, err, p.response.passthroughOnError)
	}

	d := decide(resp, scan, p.masking)
	switch d.action {
	case "block":
		return p.blockResponseDownstream(d.detail)
	case "mask":
		for i, m := range scan {
			if maskable[i] {
				body.Choices[i].Message.Content = m.Content
			}
		}
		rewritten, err := rewriteField(content, "choices", body.Choices)
		if err != nil {
			slog.Error("LassoGuardrail: failed to re-encode masked response body", "error", err)
			return policy.DownstreamResponseModifications{}
		}
		return policy.DownstreamResponseModifications{Body: rewritten}
	default:
		return policy.DownstreamResponseModifications{}
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func (p *LassoGuardrailPolicy) sessionID(headers *policy.Headers, fallback string) string {
	if v := firstHeader(headers, p.sessionHeader); v != "" {
		return v
	}
	return fallback
}

func firstHeader(headers *policy.Headers, name string) string {
	if headers == nil {
		return ""
	}
	if vals := headers.Get(name); len(vals) > 0 {
		return vals[0]
	}
	return ""
}

func (p *LassoGuardrailPolicy) handleRequestError(kind errKind, err error, passthroughOnError bool) policy.RequestAction {
	if kind == errKindAuth {
		slog.Error("LassoGuardrail: auth error — check lassoApiKey", "error", err)
		return policy.ImmediateResponse{
			StatusCode: 500,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       mustJSON(map[string]string{"message": "Guardrail misconfigured"}),
		}
	}
	if passthroughOnError {
		slog.Warn("LassoGuardrail: Lasso unavailable — fail-open, allowing", "error", err)
		return policy.UpstreamRequestModifications{}
	}
	slog.Error("LassoGuardrail: Lasso unavailable — fail-closed, blocking", "error", err)
	return policy.ImmediateResponse{
		StatusCode: 503,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       mustJSON(map[string]string{"message": "Guardrail unavailable"}),
	}
}

func (p *LassoGuardrailPolicy) handleResponseError(kind errKind, err error, passthroughOnError bool) policy.ResponseAction {
	if kind == errKindAuth {
		slog.Error("LassoGuardrail: auth error — check lassoApiKey", "error", err)
		return policy.ImmediateResponse{
			StatusCode: 500,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       mustJSON(map[string]string{"message": "Guardrail misconfigured"}),
		}
	}
	if passthroughOnError {
		slog.Warn("LassoGuardrail: Lasso unavailable — fail-open, allowing", "error", err)
		return policy.DownstreamResponseModifications{}
	}
	slog.Error("LassoGuardrail: Lasso unavailable — fail-closed, blocking", "error", err)
	return policy.ImmediateResponse{
		StatusCode: 503,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       mustJSON(map[string]string{"message": "Guardrail unavailable"}),
	}
}

func (p *LassoGuardrailPolicy) blockResponse(detail string) policy.RequestAction {
	return policy.ImmediateResponse{
		StatusCode: blockStatusCode,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       mustJSON(map[string]string{"message": "Request blocked by Lasso guardrail", "reason": detail}),
		AnalyticsMetadata: map[string]any{
			"isGuardrailHit": true,
			"guardrailName":  "LassoGuardrail",
			"reason":         detail,
		},
	}
}

func (p *LassoGuardrailPolicy) blockResponseDownstream(detail string) policy.ResponseAction {
	status := blockStatusCode
	return policy.DownstreamResponseModifications{
		StatusCode: &status,
		Body:       mustJSON(map[string]string{"message": "Response blocked by Lasso guardrail", "reason": detail}),
		HeadersToSet: map[string]string{
			"Content-Type": "application/json",
		},
		AnalyticsMetadata: map[string]any{
			"isGuardrailHit": true,
			"guardrailName":  "LassoGuardrail",
			"reason":         detail,
		},
	}
}

func mustJSON(v interface{}) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte(`{"message":"internal error"}`)
	}
	return b
}

// ── Param parsing ────────────────────────────────────────────────────────────

func getStringParam(params map[string]interface{}, key string) string {
	if v, ok := params[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getBoolParam(params map[string]interface{}, key string, def bool) bool {
	if v, ok := params[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return def
}

func getIntParam(params map[string]interface{}, key string, def int) int {
	if v, ok := params[key]; ok {
		switch n := v.(type) {
		case int:
			return n
		case int64:
			return int(n)
		case float64:
			return int(n)
		}
	}
	return def
}
