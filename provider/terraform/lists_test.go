package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var stringList = types.ListType{ElemType: types.StringType}

func listsValue(t *testing.T, in map[string][]string) types.Map {
	t.Helper()
	v, diags := types.MapValueFrom(context.Background(), stringList, in)
	if diags.HasError() {
		t.Fatal(diags)
	}
	return v
}

func schemaOf(r *uciSectionResource) resource.SchemaResponse {
	var sch resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &sch)
	return sch
}

func readModel(t *testing.T, body string, held uciSectionModel) uciSectionModel {
	t.Helper()
	s := reply(200, body)
	defer s.Close()
	ctx := context.Background()
	r := &uciSectionResource{c: &client{baseURL: s.URL, http: &http.Client{}}}
	state := tfsdk.State{Schema: schemaOf(r).Schema}
	if d := state.Set(ctx, &held); d.HasError() {
		t.Fatal(d)
	}
	resp := &resource.ReadResponse{State: state}
	r.Read(ctx, resource.ReadRequest{State: state}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}
	var got uciSectionModel
	resp.State.Get(ctx, &got)
	return got
}

func dnsmasqHeld(lists types.Map) uciSectionModel {
	return uciSectionModel{
		ID: types.StringValue("dhcp.dnsmasq_0"), Config: types.StringValue("dhcp"),
		Section: types.StringValue("dnsmasq_0"), Type: types.StringValue("dnsmasq"),
		Values: types.MapValueMust(types.StringType, map[string]attr.Value{"domain": types.StringValue("lan")}),
		Lists:  lists,
	}
}

func TestReadSplitsListOptionsIntoLists(t *testing.T) {
	got := readModel(t,
		`{"values":{".type":"dnsmasq","domain":"lan","server":["/pleme.internal/192.168.50.3","/b/1.1.1.1"]}}`,
		dnsmasqHeld(listsValue(t, map[string][]string{})))
	ctx := context.Background()
	lists := map[string][]string{}
	got.Lists.ElementsAs(ctx, &lists, false)
	want := []string{"/pleme.internal/192.168.50.3", "/b/1.1.1.1"}
	if !reflect.DeepEqual(lists["server"], want) {
		t.Fatalf("lists.server = %v, want %v", lists["server"], want)
	}
	vals := map[string]string{}
	got.Values.ElementsAs(ctx, &vals, false)
	if len(vals) != 1 || vals["domain"] != "lan" {
		t.Fatalf("values = %v, want only domain", vals)
	}
}

func TestUndeclaredListsAreNeverReadIntoState(t *testing.T) {
	got := readModel(t, `{"values":{".type":"device","name":"br-lan","ports":["lan1","lan2"]}}`, dnsmasqHeld(types.MapNull(stringList)))
	if !got.Lists.IsNull() {
		t.Fatalf("lists = %v, want null: an undeclared list must stay unmanaged", got.Lists)
	}
}

func TestUpdateWithListsUndeclaredDeletesNoList(t *testing.T) {
	var deleted []any
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		raw, _ := io.ReadAll(req.Body)
		var b map[string]any
		json.Unmarshal(raw, &b)
		if req.URL.Path == "/uci/delete" {
			deleted = append(deleted, b["options"])
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer s.Close()
	ctx := context.Background()
	r := &uciSectionResource{c: &client{baseURL: s.URL, http: &http.Client{}}}
	sch := schemaOf(r)
	prior := dnsmasqHeld(listsValue(t, map[string][]string{"server": {"/a/1"}}))
	plan := dnsmasqHeld(types.MapNull(stringList))
	st := tfsdk.State{Schema: sch.Schema}
	st.Set(ctx, &prior)
	pl := tfsdk.Plan{Schema: sch.Schema}
	pl.Set(ctx, &plan)
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: sch.Schema}}
	r.Update(ctx, resource.UpdateRequest{State: st, Plan: pl}, resp)
	if resp.Diagnostics.HasError() || len(deleted) != 0 {
		t.Fatalf("diags=%v deleted=%v, want no delete", resp.Diagnostics, deleted)
	}
}

func TestReadEmptiesDeclaredListsTheDeviceNoLongerHas(t *testing.T) {
	got := readModel(t, `{"values":{".type":"dnsmasq","domain":"lan"}}`,
		dnsmasqHeld(listsValue(t, map[string][]string{"server": {"/a/1"}})))
	if got.Lists.IsNull() || len(got.Lists.Elements()) != 0 {
		t.Fatalf("lists = %v, want an empty map", got.Lists)
	}
}

type recorded struct {
	path string
	body map[string]any
}

func TestUpdateWritesListsInOrderAndDeletesDroppedLists(t *testing.T) {
	var calls []recorded
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		raw, _ := io.ReadAll(req.Body)
		var b map[string]any
		json.Unmarshal(raw, &b)
		calls = append(calls, recorded{req.URL.Path, b})
		w.Write([]byte(`{"ok":true}`))
	}))
	defer s.Close()
	ctx := context.Background()
	r := &uciSectionResource{c: &client{baseURL: s.URL, http: &http.Client{}}}
	sch := schemaOf(r)
	prior := dnsmasqHeld(listsValue(t, map[string][]string{"server": {"/a/1"}, "address": {"/x/2"}}))
	plan := dnsmasqHeld(listsValue(t, map[string][]string{"server": {"/b/2", "/a/1"}}))
	st := tfsdk.State{Schema: sch.Schema}
	st.Set(ctx, &prior)
	pl := tfsdk.Plan{Schema: sch.Schema}
	pl.Set(ctx, &plan)
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: sch.Schema}}
	r.Update(ctx, resource.UpdateRequest{State: st, Plan: pl}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatal(resp.Diagnostics)
	}
	if len(calls) != 3 || calls[0].path != "/uci/delete" || calls[1].path != "/uci/set" || calls[2].path != "/uci/commit" {
		t.Fatalf("calls = %+v", calls)
	}
	if !reflect.DeepEqual(calls[0].body["options"], []any{"address"}) {
		t.Fatalf("deleted %v, want [address]", calls[0].body["options"])
	}
	vals := calls[1].body["values"].(map[string]any)
	if !reflect.DeepEqual(vals["server"], []any{"/b/2", "/a/1"}) || vals["domain"] != "lan" {
		t.Fatalf("set values = %v", vals)
	}
}

func TestAnOptionInBothValuesAndListsIsRefused(t *testing.T) {
	m := uciSectionModel{
		Values: types.MapValueMust(types.StringType, map[string]attr.Value{"server": types.StringValue("x")}),
		Lists:  listsValue(t, map[string][]string{"server": {"y"}}),
	}
	if _, err := m.valueMap(context.Background()); err == nil {
		t.Fatal("want an error")
	}
}
