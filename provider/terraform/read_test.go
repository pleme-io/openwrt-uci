package main

import (
	"context"
	"net/http"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// readAgainst runs Read for one section held in state against an adapter at
// baseURL, and reports whether the section is still in state and whether the
// read failed.
func readAgainst(t *testing.T, baseURL string) (kept bool, failed bool) {
	t.Helper()
	ctx := context.Background()
	r := &uciSectionResource{c: &client{baseURL: baseURL, http: &http.Client{}}}
	var sch resource.SchemaResponse
	r.Schema(ctx, resource.SchemaRequest{}, &sch)

	state := tfsdk.State{Schema: sch.Schema}
	held := uciSectionModel{
		ID:      types.StringValue("network.lan"),
		Config:  types.StringValue("network"),
		Section: types.StringValue("lan"),
		Type:    types.StringValue("interface"),
		Values:  types.MapValueMust(types.StringType, map[string]attr.Value{"proto": types.StringValue("static")}),
	}
	if diags := state.Set(ctx, &held); diags.HasError() {
		t.Fatalf("seeding state: %v", diags)
	}
	resp := &resource.ReadResponse{State: state}
	r.Read(ctx, resource.ReadRequest{State: state}, resp)
	return !resp.State.Raw.IsNull(), resp.Diagnostics.HasError()
}

// The regression: a refresh that cannot reach the router removed every section
// from state, so the next plan proposed creating all of them.
func TestReadKeepsStateWhenTheRouterIsUnreachable(t *testing.T) {
	kept, failed := readAgainst(t, refusedURL(t))
	if !kept {
		t.Fatal("Read removed the section from state after a refused connection")
	}
	if !failed {
		t.Fatal("Read reported success without reaching the router")
	}
}

func TestReadRemovesASectionTheDeviceSaysIsGone(t *testing.T) {
	s := reply(404, `{"error":"ubus status 4: not found"}`)
	defer s.Close()
	kept, failed := readAgainst(t, s.URL)
	if kept || failed {
		t.Fatalf("kept=%v failed=%v, want the section removed without an error", kept, failed)
	}
}

func TestReadKeepsStateOnAnAdapterFault(t *testing.T) {
	s := reply(502, `{"error":"connecting to ubusd: No such file or directory"}`)
	defer s.Close()
	kept, failed := readAgainst(t, s.URL)
	if !kept || !failed {
		t.Fatalf("kept=%v failed=%v, want state kept and the read failed", kept, failed)
	}
}

func TestReadRefreshesAnAnsweredSection(t *testing.T) {
	s := reply(200, `{"values":{".type":"interface",".name":"lan","proto":"dhcp"}}`)
	defer s.Close()
	kept, failed := readAgainst(t, s.URL)
	if !kept || failed {
		t.Fatalf("kept=%v failed=%v, want the section kept without an error", kept, failed)
	}
}
