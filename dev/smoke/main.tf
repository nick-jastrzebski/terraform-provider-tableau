# Smoke test for the locally built provider.
#
#   terraform validate   - no credentials needed; proves the binary loads
#   terraform plan       - needs credentials; proves sign-in and a real API read
#
# Credentials come from environment variables so nothing secret lands in files:
#   $env:TABLEAU_SERVER_URL                   = "https://prod-uk-a.online.tableau.com"
#   $env:TABLEAU_SERVER_VERSION               = "3.24"
#   $env:TABLEAU_SITE_NAME                    = "your-site-content-url"
#   $env:TABLEAU_PERSONAL_ACCESS_TOKEN_NAME   = "..."
#   $env:TABLEAU_PERSONAL_ACCESS_TOKEN_SECRET = "..."

terraform {
  required_providers {
    tableau = {
      source = "gthesheep/tableau"
    }
  }
}

provider "tableau" {}

# Read-only: lists projects on the configured site. Changes nothing.
data "tableau_projects" "all" {}

output "project_names" {
  value = [for p in data.tableau_projects.all.projects : p.name]
}
