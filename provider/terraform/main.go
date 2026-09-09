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
	"context"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

// ---- the façade client ----

type client struct {
	baseURL string
	http    *http.Client
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
		return nil, err
	}
	defer resp.Body.Close()

	var out map[string]any
	// A 200 with no return value is `{"ok":true}`; decode either way.
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("%s: decoding the reply: %w", op, err)
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s: %s: %v", op, resp.Status, out["error"])
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
		// A section that is gone is a REMOVED resource, not an error: leaving it
		// in state would make the next plan try to update something absent.
		resp.State.RemoveResource(ctx)
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
	vals, err := m.valueMap(ctx)
	if err != nil {
		resp.Diagnostics.AddError("invalid values", err.Error())
		return
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
