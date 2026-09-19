// A Terraform provider for OpenWrt UCI, speaking the ubus façade over HTTP.
//
// REFERENCE IMPLEMENTATION — this file is the MEASUREMENT, not the deliverable.
// Its purpose is to establish, against a real device, the shape a generated
// provider must emit. Once it is verified end to end (tofu -> HTTP -> ubus-http
// -> ubusd -> router), iac-forge's TerraformBackend is written to emit exactly
// this, and its output is byte-compared against this file.
//
// Writing the generator first would mean generating a shape nobody had shown
// works — which is the failure this whole project refuses.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// ---- the façade client ----

type client struct {
	baseURL string
	http    *http.Client
}

// callError is every way a façade call can fail. The ways are kept apart
// because they mean different things to a caller deciding what the device
// holds: only the device itself can say a section is absent.
type callError struct {
	op string
	// transport is set when no HTTP answer arrived at all: the tunnel is down,
	// the connection was refused, the request timed out. Nothing was observed.
	transport error
	// status is the adapter's HTTP status when it did answer.
	status int
	// message is the adapter's `error` field, or why the reply did not decode.
	message string
}

func (e *callError) Error() string {
	if e.transport != nil {
		return fmt.Sprintf("%s: no answer from the adapter: %v", e.op, e.transport)
	}
	return fmt.Sprintf("%s: HTTP %d: %s", e.op, e.status, e.message)
}

func (e *callError) Unwrap() error { return e.transport }

// ubusNotFound is the adapter's reply when the DEVICE answered ubus status 4.
// ubus-http spells it once (crates/ubus-http/src/http.rs, the
// `ClientError::Status(4)` arm) and `adapter_contract_test.go` pins it here.
// The adapter's other 404s — an unrouted path, a device with no `uci` object —
// are about the adapter or the device, not about the section.
const ubusNotFound = "ubus status 4: not found"

// deviceSaysAbsent is true only when the device itself answered "not found".
//
// ★ This is the ONLY evidence that a section is gone. It used to be "any
// error", so a refused connection read as a deleted section: with the tunnel
// to repetidor-buzios down on 2026-09-19, each refresh removed the sections it
// could not reach from state, 61 then 73 then all 76, and the next plan
// proposed creating every section the router already had.
func deviceSaysAbsent(err error) bool {
	var ce *callError
	return errors.As(err, &ce) && ce.transport == nil &&
		ce.status == http.StatusNotFound && ce.message == ubusNotFound
}

// call performs one façade operation. The path is the façade path, verbatim.
func (c *client) call(ctx context.Context, op string, args map[string]any) (map[string]any, error) {
	body, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+op, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, &callError{op: op, transport: err}
	}
	defer resp.Body.Close()

	var out map[string]any
	// A 200 with no return value is `{"ok":true}`; decode either way.
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, &callError{op: op, status: resp.StatusCode, message: "decoding the reply: " + err.Error()}
	}
	if resp.StatusCode >= 300 {
		msg, _ := out["error"].(string)
		return nil, &callError{op: op, status: resp.StatusCode, message: msg}
	}
	return out, nil
}

// commit persists staged changes. UCI stages into a delta, so without this a
// created section vanishes on reboot and Terraform's state would claim it exists.
func (c *client) commit(ctx context.Context, pkg string) error {
	_, err := c.call(ctx, "/uci/commit", map[string]any{"config": pkg})
	return err
}

// ---- the provider ----

type openwrtProvider struct{}

func (p *openwrtProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "openwrt"
}

func (p *openwrtProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"base_url": schema.StringAttribute{
				Required: true,
				Description: "Base URL of the ubus façade adapter (ubus-http), e.g. " +
					"http://127.0.0.1:9797. Not the router's web UI: the adapter turns " +
					"each façade path into a ubus INVOKE.",
			},
		},
	}
}

type providerConfig struct {
	BaseURL types.String `tfsdk:"base_url"`
}

func (p *openwrtProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerConfig
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	c := &client{baseURL: cfg.BaseURL.ValueString(), http: &http.Client{}}
	resp.ResourceData = c
	resp.DataSourceData = c
}

func (p *openwrtProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{func() resource.Resource { return &uciSectionResource{} }}
}

func (p *openwrtProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return nil
}

// ---- openwrt_uci_section ----

type uciSectionResource struct{ c *client }

type uciSectionModel struct {
	ID      types.String `tfsdk:"id"`
	Config  types.String `tfsdk:"config"`
	Section types.String `tfsdk:"section"`
	Type    types.String `tfsdk:"type"`
	Values  types.Map    `tfsdk:"values"`
}

func (r *uciSectionResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_uci_section"
}

func (r *uciSectionResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = rschema.Schema{
		Description: "A UCI configuration section, addressed as (config, section).",
		Attributes: map[string]rschema.Attribute{
			"id": rschema.StringAttribute{
				Computed:    true,
				Description: "Composite identity, `config.section` — UCI section names are unique only within their package.",
			},
			"config": rschema.StringAttribute{
				Required:    true,
				Description: "The UCI package (a file under /etc/config).",
			},
			"section": rschema.StringAttribute{
				Required:    true,
				Description: "The section name.",
			},
			"type": rschema.StringAttribute{
				Required:    true,
				Description: "The section type, e.g. `interface`.",
			},
			"values": rschema.MapAttribute{
				Required:    true,
				ElementType: types.StringType,
				Description: "The section's options.",
			},
		},
	}
}

func (r *uciSectionResource) Configure(_ context.Context, req resource.ConfigureRequest, _ *resource.ConfigureResponse) {
	if req.ProviderData != nil {
		r.c = req.ProviderData.(*client)
	}
}

func (m *uciSectionModel) valueMap(ctx context.Context) (map[string]any, error) {
	raw := map[string]string{}
	if diags := m.Values.ElementsAs(ctx, &raw, false); diags.HasError() {
		return nil, fmt.Errorf("values is not a map of strings")
	}
	out := map[string]any{}
	for k, v := range raw {
		out[k] = v
	}
	return out, nil
}

func (r *uciSectionResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var m uciSectionModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	vals, err := m.valueMap(ctx)
	if err != nil {
		resp.Diagnostics.AddError("invalid values", err.Error())
		return
	}
	// ★ CREATE IS `add`, NOT `set` — measured, after `set` failed.
	//
	// A first cut used `/uci/set` with a `type`, on the assumption that `add`
	// only makes ANONYMOUS sections. The device disagreed: `uci set` against a
	// section that does not exist yet returns ubus status 4 (not found), so
	// creation failed while the resource spec's `create_endpoint = "/uci/add"`
	// had been right all along.
	//
	// `uci.add` takes a `name`, which is exactly what makes the section named:
	//   POST /uci/add {config, type, name, values} -> {"section":"<name>"}
	// Verified on the device, which then held `config marker 'probe_named'`.
	if _, err := r.c.call(ctx, "/uci/add", map[string]any{
		"config": m.Config.ValueString(),
		"type":   m.Type.ValueString(),
		"name":   m.Section.ValueString(),
		"values": vals,
	}); err != nil {
		resp.Diagnostics.AddError("uci add failed", err.Error())
		return
	}
	if err := r.c.commit(ctx, m.Config.ValueString()); err != nil {
		resp.Diagnostics.AddError("uci commit failed", err.Error())
		return
	}
	m.ID = types.StringValue(sectionID(m.Config.ValueString(), m.Section.ValueString()))
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *uciSectionResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var m uciSectionModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.c.call(ctx, "/uci/get", map[string]any{
		"config":  m.Config.ValueString(),
		"section": m.Section.ValueString(),
	})
	if err != nil {
		// A section the DEVICE says is gone is a removed resource, not an
		// error: leaving it in state would make the next plan try to update
		// something absent.
		if deviceSaysAbsent(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		// Anything else observed nothing about the section. Fail the read and
		// keep state: a refresh that cannot see the device must not conclude
		// the device is empty.
		resp.Diagnostics.AddError("reading the section failed; state kept", err.Error())
		return
	}
	if vals, ok := out["values"].(map[string]any); ok {
		asStr := map[string]string{}
		for k, v := range vals {
			if s, ok := v.(string); ok {
				asStr[k] = s
			}
		}
		// ★ `.type` is read BEFORE it is deleted, and it populates the `type`
		// attribute rather than being discarded.
		//
		// Two things depend on this. An IMPORTED resource has no `type` in
		// state — nothing has ever set it — so without this line the first
		// plan after an import wants to write a Required attribute it cannot
		// know, and the import is unusable. And a section whose type was
		// changed on the device was previously invisible: `type` came from
		// state and state was never corrected, so the one field UCI treats as
		// the section's KIND was the one field drift detection could not see.
		if ty, ok := vals[".type"].(string); ok && ty != "" {
			m.Type = types.StringValue(ty)
		}
		// UCI bookkeeping, not options — must not appear as ones.
		delete(asStr, ".type")
		delete(asStr, ".name")
		delete(asStr, ".anonymous")
		mv, diags := types.MapValueFrom(ctx, types.StringType, asStr)
		resp.Diagnostics.Append(diags...)
		if !resp.Diagnostics.HasError() {
			m.Values = mv
		}
	}
	// Computed, so it is null on an imported resource until something sets it.
	m.ID = types.StringValue(sectionID(m.Config.ValueString(), m.Section.ValueString()))
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *uciSectionResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var m uciSectionModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	// ★ The PRIOR state is needed, not just the plan, because `uci set` is
	// ADDITIVE and `values` is meant to be AUTHORITATIVE.
	//
	// Without this the resource cannot converge on a removal. Read populates
	// state with every option the device has; if the config declares fewer,
	// plan proposes dropping the extras, `uci set` writes only what it was
	// given and leaves them in place, and the next Read finds them again — so
	// the same plan is proposed forever. Every apply "succeeds", nothing is
	// ever wrong twice in a row, and the section never reaches desired state.
	// A reconciler that reports Ready on every pass while never converging is
	// the failure this deletes.
	var prior uciSectionModel
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}
	vals, err := m.valueMap(ctx)
	if err != nil {
		resp.Diagnostics.AddError("invalid values", err.Error())
		return
	}
	priorVals, err := prior.valueMap(ctx)
	if err != nil {
		resp.Diagnostics.AddError("invalid prior values", err.Error())
		return
	}
	// Options the device has that the config no longer declares.
	var removed []any
	for k := range priorVals {
		if _, keep := vals[k]; !keep {
			removed = append(removed, k)
		}
	}
	if len(removed) > 0 {
		// Deleted BEFORE the set, so a single failure leaves the section with
		// the old value rather than half-applied: uci stages both into one
		// per-package delta and one commit publishes them together.
		if _, err := r.c.call(ctx, "/uci/delete", map[string]any{
			"config":  m.Config.ValueString(),
			"section": m.Section.ValueString(),
			"options": removed,
		}); err != nil {
			resp.Diagnostics.AddError("uci delete (of undeclared options) failed", err.Error())
			return
		}
	}
	if _, err := r.c.call(ctx, "/uci/set", map[string]any{
		"config":  m.Config.ValueString(),
		"section": m.Section.ValueString(),
		"values":  vals,
	}); err != nil {
		resp.Diagnostics.AddError("uci set failed", err.Error())
		return
	}
	if err := r.c.commit(ctx, m.Config.ValueString()); err != nil {
		resp.Diagnostics.AddError("uci commit failed", err.Error())
		return
	}
	m.ID = types.StringValue(sectionID(m.Config.ValueString(), m.Section.ValueString()))
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

func (r *uciSectionResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var m uciSectionModel
	resp.Diagnostics.Append(req.State.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if _, err := r.c.call(ctx, "/uci/delete", map[string]any{
		"config":  m.Config.ValueString(),
		"section": m.Section.ValueString(),
	}); err != nil {
		resp.Diagnostics.AddError("uci delete failed", err.Error())
		return
	}
	if err := r.c.commit(ctx, m.Config.ValueString()); err != nil {
		resp.Diagnostics.AddError("uci commit failed", err.Error())
	}
}

// sectionID is the one place the composite identity is spelled, so the format
// `ImportState` parses and the format `Read` writes cannot drift apart.
func sectionID(pkg, section string) string { return pkg + "." + section }

// ImportState adopts a section that already exists on the device.
//
// ★ This was `ImportStatePassthroughID` and that is WRONG for this resource,
// which is why adopting an existing router was impossible. Passthrough sets
// only `id`; `config` and `section` stay null, and `Read` then asks the device
// for `/uci/get {config:"", section:""}`. The failure is not a clean error
// either — Read treats a failed get as a DELETED section and calls
// RemoveResource, so a passthrough import silently produced an empty state and
// the next plan proposed creating sections that already exist.
//
// Splitting on the FIRST dot is exact rather than convenient: UCI package and
// section names are `[A-Za-z0-9_]+`, so neither half can contain a dot. An
// anonymous section's positional address (`firewall.@rule[0]`) also survives
// the split, so anonymous sections are importable — though their address is
// positional and shifts if an earlier section of the same type is removed.
func (r *uciSectionResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	pkg, section, found := strings.Cut(req.ID, ".")
	if !found || pkg == "" || section == "" {
		resp.Diagnostics.AddError(
			"malformed import id",
			fmt.Sprintf("expected `<config>.<section>` (e.g. `firewall.wan_ssh`, or `firewall.@rule[0]` for an anonymous section), got %q. "+
				"UCI section names are unique only within their package, so the package is part of the identity.", req.ID),
		)
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), sectionID(pkg, section))...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("config"), pkg)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("section"), section)...)
	// `type` and `values` are deliberately left for Read, which is the only
	// thing that knows them — see the note there.
}

// ---- server ----

func main() {
	err := providerserver.Serve(context.Background(), func() provider.Provider {
		return &openwrtProvider{}
	}, providerserver.ServeOpts{
		// The address a `dev_overrides` block names. It is a source ADDRESS,
		// not a URL that is fetched: with dev_overrides tofu execs the local
		// binary and never contacts a registry.
		Address: "registry.opentofu.org/pleme-io/openwrt",
	})
	if err != nil {
		panic(err)
	}
}
