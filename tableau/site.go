package tableau

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type Site struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name,omitempty"`
	ContentURL string `json:"contentUrl,omitempty"`
}

type SiteRequest struct {
	Site Site `json:"site"`
}

type SiteResponse struct {
	Site Site `json:"site"`
}

type SitesResponse struct {
	Sites []Site `json:"site"`
}

type SiteListResponse struct {
	SitesResponse SitesResponse     `json:"sites"`
	Pagination    PaginationDetails `json:"pagination"`
}

// sitesUrl is {server}/api/{version}/sites. Site methods live here, not under
// the signed-in site's ApiUrl (which would give .../sites/{site-id}/sites).
func (c *Client) sitesUrl() string {
	return fmt.Sprintf("%s/sites", c.BaseUrl)
}

func (c *Client) GetSite(siteID string) (*Site, error) {
	// Query Site works on Tableau Cloud and Server, but only for the signed-in site.
	if siteID == c.SiteID {
		req, err := http.NewRequest("GET", fmt.Sprintf("%s/%s", c.sitesUrl(), siteID), nil)
		if err != nil {
			return nil, err
		}

		body, err := c.doRequest(req)
		if err != nil {
			return nil, err
		}

		siteResponse := SiteResponse{}
		err = json.Unmarshal(body, &siteResponse)
		if err != nil {
			return nil, err
		}

		return &siteResponse.Site, nil
	}

	// Any other site needs Query Sites, which is Tableau Server only - e.g. reading
	// a site this provider just created. Tableau Cloud returns an error here.
	req, err := http.NewRequest("GET", c.sitesUrl(), nil)
	if err != nil {
		return nil, err
	}

	body, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}

	siteListResponse := SiteListResponse{}
	err = json.Unmarshal(body, &siteListResponse)
	if err != nil {
		return nil, err
	}

	// TODO: Generalise pagination handling and use elsewhere
	pageNumber, totalPageCount, _, err := GetPaginationNumbers(siteListResponse.Pagination)
	if err != nil {
		return nil, err
	}
	for i, site := range siteListResponse.SitesResponse.Sites {
		if site.ID == siteID {
			return &siteListResponse.SitesResponse.Sites[i], nil
		}
	}

	for page := pageNumber + 1; page <= totalPageCount; page++ {
		fmt.Printf("Searching page %d", page)
		req, err = http.NewRequest("GET", fmt.Sprintf("%s?pageNumber=%d", c.sitesUrl(), page), nil)
		if err != nil {
			return nil, err
		}
		body, err = c.doRequest(req)
		if err != nil {
			return nil, err
		}
		siteListResponse = SiteListResponse{}
		err = json.Unmarshal(body, &siteListResponse)
		if err != nil {
			return nil, err
		}
		// Check page for site match
		for i, site := range siteListResponse.SitesResponse.Sites {
			if site.ID == siteID {
				return &siteListResponse.SitesResponse.Sites[i], nil
			}
		}
	}

	return nil, fmt.Errorf("Did not find site ID %s", siteID)
}

func (c *Client) CreateSite(name, contentURL string) (*Site, error) {

	newSite := Site{
		Name:       name,
		ContentURL: contentURL,
	}
	siteRequest := SiteRequest{
		Site: newSite,
	}

	newSiteJson, err := json.Marshal(siteRequest)
	if err != nil {
		return nil, err
	}

	// Create Site is Tableau Server only.
	req, err := http.NewRequest("POST", c.sitesUrl(), strings.NewReader(string(newSiteJson)))
	if err != nil {
		return nil, err
	}

	body, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}

	siteResponse := SiteResponse{}
	err = json.Unmarshal(body, &siteResponse)
	if err != nil {
		return nil, err
	}

	return &siteResponse.Site, nil
}

func (c *Client) UpdateSite(siteID, name, contentURL string) (*Site, error) {

	newSite := Site{
		Name:       name,
		ContentURL: contentURL,
	}
	siteRequest := SiteRequest{
		Site: newSite,
	}

	newSiteJson, err := json.Marshal(siteRequest)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("PUT", fmt.Sprintf("%s/%s", c.sitesUrl(), siteID), strings.NewReader(string(newSiteJson)))
	if err != nil {
		return nil, err
	}

	body, err := c.doRequest(req)
	if err != nil {
		return nil, err
	}

	siteResponse := SiteResponse{}
	err = json.Unmarshal(body, &siteResponse)
	if err != nil {
		return nil, err
	}

	return &siteResponse.Site, nil
}

func (c *Client) DeleteSite(siteID string) error {

	// Delete Site is Tableau Server only.
	req, err := http.NewRequest("DELETE", fmt.Sprintf("%s/%s", c.sitesUrl(), siteID), nil)
	if err != nil {
		return err
	}

	_, err = c.doRequest(req)
	if err != nil {
		return err
	}

	return nil
}
