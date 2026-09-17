package tableau

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeTableau is a stand-in Tableau REST API. It records every request and
// answers the site methods, so the client's URLs can be checked without a
// real Tableau site. Unlike the TestAcc* tests, this runs on plain `go test`.
type fakeTableau struct {
	server   *httptest.Server
	requests []string // "METHOD /path?query"
}

const (
	testAPIVersion = "3.30"
	signedInSiteID = "signed-in-site"
)

func newFakeTableau(t *testing.T) *fakeTableau {
	f := &fakeTableau{}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request := r.Method + " " + r.URL.Path
		if r.URL.RawQuery != "" {
			request += "?" + r.URL.RawQuery
		}
		f.requests = append(f.requests, request)

		base := "/api/" + testAPIVersion
		switch request {
		case "POST " + base + "/auth/signin":
			fmt.Fprintf(w, `{"credentials": {"site": {"id": %q, "contentUrl": "mysite"}, "user": {"id": "user-1"}, "token": "test-token"}}`, signedInSiteID)
			return
		}

		// Everything after sign-in must carry the session token.
		if r.Header.Get("X-Tableau-Auth") != "test-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		switch request {
		case "GET " + base + "/sites/" + signedInSiteID:
			fmt.Fprintf(w, `{"site": {"id": %q, "name": "My Site", "contentUrl": "mysite"}}`, signedInSiteID)
		case "GET " + base + "/sites":
			fmt.Fprint(w, `{"pagination": {"pageNumber": "1", "pageSize": "1", "totalAvailable": "2"}, "sites": {"site": [{"id": "site-a", "name": "A", "contentUrl": "a"}]}}`)
		case "GET " + base + "/sites?pageNumber=2":
			fmt.Fprint(w, `{"pagination": {"pageNumber": "2", "pageSize": "1", "totalAvailable": "2"}, "sites": {"site": [{"id": "site-b", "name": "B", "contentUrl": "b"}]}}`)
		case "POST " + base + "/sites":
			fmt.Fprint(w, `{"site": {"id": "new-site", "name": "New", "contentUrl": "new"}}`)
		case "PUT " + base + "/sites/site-b":
			fmt.Fprint(w, `{"site": {"id": "site-b", "name": "Renamed", "contentUrl": "renamed"}}`)
		case "DELETE " + base + "/sites/site-b":
			w.WriteHeader(http.StatusNoContent)
		default:
			// Any other URL is a bug in the client - the old code hit
			// /sites/{site-id}/sites and got a 404 from real Tableau.
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprintf(w, `{"error": {"detail": "unexpected request %s"}}`, request)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeTableau) newClient(t *testing.T) *Client {
	t.Helper()
	server, version, site := f.server.URL, testAPIVersion, "mysite"
	name, secret, empty := "pat-name", "pat-secret", ""
	client, err := NewClient(&server, &empty, &empty, &name, &secret, &site, &version)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	f.requests = nil // only record requests made by the test itself
	return client
}

func (f *fakeTableau) assertRequests(t *testing.T, want ...string) {
	t.Helper()
	if fmt.Sprint(f.requests) != fmt.Sprint(want) {
		t.Errorf("requests:\n  got  %v\n  want %v", f.requests, want)
	}
}

func TestNewClientRecordsSiteAndBaseUrl(t *testing.T) {
	f := newFakeTableau(t)
	client := f.newClient(t)

	wantBase := f.server.URL + "/api/" + testAPIVersion
	if client.BaseUrl != wantBase {
		t.Errorf("BaseUrl = %q, want %q", client.BaseUrl, wantBase)
	}
	if client.SiteID != signedInSiteID {
		t.Errorf("SiteID = %q, want %q", client.SiteID, signedInSiteID)
	}
	if want := wantBase + "/sites/" + signedInSiteID; client.ApiUrl != want {
		t.Errorf("ApiUrl = %q, want %q", client.ApiUrl, want)
	}
}

func TestGetSiteSignedInSiteUsesQuerySite(t *testing.T) {
	f := newFakeTableau(t)
	client := f.newClient(t)

	site, err := client.GetSite(signedInSiteID)
	if err != nil {
		t.Fatalf("GetSite: %v", err)
	}
	if site.ID != signedInSiteID || site.Name != "My Site" {
		t.Errorf("got site %+v", site)
	}
	// A single Query Site call - no listing, which Tableau Cloud doesn't support.
	f.assertRequests(t, "GET /api/3.30/sites/"+signedInSiteID)
}

func TestGetSiteOtherSiteSearchesAllPages(t *testing.T) {
	f := newFakeTableau(t)
	client := f.newClient(t)

	site, err := client.GetSite("site-b")
	if err != nil {
		t.Fatalf("GetSite: %v", err)
	}
	if site.ID != "site-b" {
		t.Errorf("got site %+v", site)
	}
	f.assertRequests(t, "GET /api/3.30/sites", "GET /api/3.30/sites?pageNumber=2")
}

func TestGetSiteNotFound(t *testing.T) {
	f := newFakeTableau(t)
	client := f.newClient(t)

	if _, err := client.GetSite("missing"); err == nil {
		t.Error("expected an error for a site that doesn't exist")
	}
}

func TestSiteWriteMethodsUseSitesUrl(t *testing.T) {
	f := newFakeTableau(t)
	client := f.newClient(t)

	if _, err := client.CreateSite("New", "new"); err != nil {
		t.Errorf("CreateSite: %v", err)
	}
	if _, err := client.UpdateSite("site-b", "Renamed", "renamed"); err != nil {
		t.Errorf("UpdateSite: %v", err)
	}
	if err := client.DeleteSite("site-b"); err != nil {
		t.Errorf("DeleteSite: %v", err)
	}
	f.assertRequests(t,
		"POST /api/3.30/sites",
		"PUT /api/3.30/sites/site-b",
		"DELETE /api/3.30/sites/site-b",
	)
}
