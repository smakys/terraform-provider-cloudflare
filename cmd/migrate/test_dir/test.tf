resource "cloudflare_zero_trust_access_group" "example" {
  account_id = "test-account"
  name       = "test-group"

  include = [{ email = { email = "user1@example.com" } },
    { email = { email = "user2@example.com" } },
    { email_domain = { domain = "example.com" } },
    { email_domain = { domain = "test.com" } },
    { ip = { ip = "192.0.2.1/32" } },
    { ip = { ip = "10.0.0.0/8" } },
    {
      azure_ad = {
        id                   = "group1"
        identity_provider_id = "azure-provider"
      }
    },
    {
      azure_ad = {
        id                   = "group2"
        identity_provider_id = "azure-provider"
      }
  }]
}
