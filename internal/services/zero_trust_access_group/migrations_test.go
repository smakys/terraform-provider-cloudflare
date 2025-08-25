package zero_trust_access_group_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/config"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	"github.com/cloudflare/terraform-provider-cloudflare/internal/acctest"
	"github.com/cloudflare/terraform-provider-cloudflare/internal/consts"
	"github.com/cloudflare/terraform-provider-cloudflare/internal/utils"
)

func TestMain(m *testing.M) {
	resource.TestMain(m)
}

// TestMigrateZeroTrustAccessGroupBasic tests basic migration from v4 to v5
func TestMigrateZeroTrustAccessGroupBasic(t *testing.T) {
	// Temporarily unset CLOUDFLARE_API_TOKEN if it is set as the Access
	// service does not yet support the API tokens and it results in
	// misleading state error messages.
	if os.Getenv("CLOUDFLARE_API_TOKEN") != "" {
		t.Setenv("CLOUDFLARE_API_TOKEN", "")
	}

	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()
	resourceName := "cloudflare_zero_trust_access_group." + rnd
	tmpDir := t.TempDir()

	// V4 config using old resource name and basic rules
	v4Config := fmt.Sprintf(`
resource "cloudflare_access_group" "%[1]s" {
  account_id = "%[2]s"
  name       = "%[1]s"
  
  include {
    email        = ["test@example.com"]
    email_domain = ["example.com"] 
    ip          = ["192.0.2.1/32"]
  }
}`, rnd, accountID)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		WorkingDir: tmpDir,
		Steps: []resource.TestStep{
			{
				// Step 1: Create with v4 provider
				ExternalProviders: map[string]resource.ExternalProvider{
					"cloudflare": {
						Source:            "cloudflare/cloudflare",
						VersionConstraint: "4.52.1",
					},
				},
				Config: v4Config,
			},
			// Step 2: Run migration and verify state
			{
				ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
				ConfigDirectory:          config.StaticDirectory(tmpDir),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					// Verify transformation: v4 lists -> v5 multiple objects
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include"), knownvalue.ListSizeExact(3)),
				},
			},
			{
				// Step 3: Apply migrated config with v5 provider
				ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
				ConfigDirectory:          config.StaticDirectory(tmpDir),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New(consts.AccountIDSchemaKey), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include"), knownvalue.ListSizeExact(3)),
				},
			},
		},
	})
}

// TestMigrateZeroTrustAccessGroupComplexRules tests migration with multiple values per rule type
func TestMigrateZeroTrustAccessGroupComplexRules(t *testing.T) {
	if os.Getenv("CLOUDFLARE_API_TOKEN") != "" {
		t.Setenv("CLOUDFLARE_API_TOKEN", "")
	}

	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()
	resourceName := "cloudflare_zero_trust_access_group." + rnd
	tmpDir := t.TempDir()

	// V4 config with multiple values in single blocks (breaking change in v5)
	v4Config := fmt.Sprintf(`
resource "cloudflare_access_group" "%[1]s" {
  account_id = "%[2]s"
  name       = "%[1]s"
  
  include {
    email = ["user1@example.com", "user2@example.com"]
    ip    = ["192.0.2.1/32", "192.0.2.2/32"]
  }
  
  exclude {
    email_domain = ["blocked1.com", "blocked2.com"]
  }
  
  require {
    ip = ["10.0.0.0/8"]
  }
}`, rnd, accountID)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		WorkingDir: tmpDir,
		Steps: []resource.TestStep{
			{
				// Step 1: Create with v4 provider
				ExternalProviders: map[string]resource.ExternalProvider{
					"cloudflare": {
						Source:            "cloudflare/cloudflare",
						VersionConstraint: "4.52.1",
					},
				},
				Config: v4Config,
			},
			// Step 2: Run migration and verify transformation
			acctest.MigrationTestStep(t, v4Config, tmpDir, "4.52.1", []statecheck.StateCheck{
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
				// Verify list expansion: 2 emails + 2 IPs = 4 include objects
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include"), knownvalue.ListSizeExact(4)),
				// Verify exclude expansion: 2 domains = 2 exclude objects
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("exclude"), knownvalue.ListSizeExact(2)),
				// Verify require: 1 IP = 1 require object
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("require"), knownvalue.ListSizeExact(1)),
			}),
			{
				// Step 3: Apply migrated config
				ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
				ConfigDirectory:          config.StaticDirectory(tmpDir),
				ConfigStateChecks: []statecheck.StateCheck{
					// Verify each email became separate object
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(0).AtMapKey("email").AtMapKey("email"), knownvalue.StringExact("user1@example.com")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(1).AtMapKey("email").AtMapKey("email"), knownvalue.StringExact("user2@example.com")),
					// Verify each IP became separate object
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(2).AtMapKey("ip").AtMapKey("ip"), knownvalue.StringExact("192.0.2.1/32")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(3).AtMapKey("ip").AtMapKey("ip"), knownvalue.StringExact("192.0.2.2/32")),
					// Verify exclude domains
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("exclude").AtSliceIndex(0).AtMapKey("email_domain").AtMapKey("domain"), knownvalue.StringExact("blocked1.com")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("exclude").AtSliceIndex(1).AtMapKey("email_domain").AtMapKey("domain"), knownvalue.StringExact("blocked2.com")),
					// Verify require IP
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("require").AtSliceIndex(0).AtMapKey("ip").AtMapKey("ip"), knownvalue.StringExact("10.0.0.0/8")),
				},
			},
		},
	})
}

// TestMigrateZeroTrustAccessGroupAzureAD tests migration of Azure blocks to azure_ad
func TestMigrateZeroTrustAccessGroupAzureAD(t *testing.T) {
	if os.Getenv("CLOUDFLARE_API_TOKEN") != "" {
		t.Setenv("CLOUDFLARE_API_TOKEN", "")
	}

	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()
	resourceName := "cloudflare_zero_trust_access_group." + rnd
	tmpDir := t.TempDir()

	// V4 config with azure blocks (renamed to azure_ad in v5)
	v4Config := fmt.Sprintf(`
resource "cloudflare_access_group" "%[1]s" {
  account_id = "%[2]s"
  name       = "%[1]s"
  
  include {
    azure {
      id                   = ["group1", "group2"]
      identity_provider_id = "provider1"
    }
  }
  
  require {
    azure {
      id                   = ["admin-group"]
      identity_provider_id = "provider2"
    }
  }
}`, rnd, accountID)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		WorkingDir: tmpDir,
		Steps: []resource.TestStep{
			{
				// Step 1: Create with v4 provider
				ExternalProviders: map[string]resource.ExternalProvider{
					"cloudflare": {
						Source:            "cloudflare/cloudflare",
						VersionConstraint: "4.52.1",
					},
				},
				Config: v4Config,
			},
			// Step 2: Run migration and verify azure -> azure_ad transformation
			acctest.MigrationTestStep(t, v4Config, tmpDir, "4.52.1", []statecheck.StateCheck{
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
				// Verify include: 2 group IDs = 2 azure_ad objects
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include"), knownvalue.ListSizeExact(2)),
				// Verify require: 1 admin group = 1 azure_ad object
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("require"), knownvalue.ListSizeExact(1)),
			}),
			{
				// Step 3: Apply migrated config
				ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
				ConfigDirectory:          config.StaticDirectory(tmpDir),
				ConfigStateChecks: []statecheck.StateCheck{
					// Verify azure renamed to azure_ad and IDs split
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(0).AtMapKey("azure_ad").AtMapKey("id"), knownvalue.StringExact("group1")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(0).AtMapKey("azure_ad").AtMapKey("identity_provider_id"), knownvalue.StringExact("provider1")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(1).AtMapKey("azure_ad").AtMapKey("id"), knownvalue.StringExact("group2")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(1).AtMapKey("azure_ad").AtMapKey("identity_provider_id"), knownvalue.StringExact("provider1")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("require").AtSliceIndex(0).AtMapKey("azure_ad").AtMapKey("id"), knownvalue.StringExact("admin-group")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("require").AtSliceIndex(0).AtMapKey("azure_ad").AtMapKey("identity_provider_id"), knownvalue.StringExact("provider2")),
				},
			},
		},
	})
}

// TestMigrateZeroTrustAccessGroupGitHubOrganization tests migration of GitHub blocks
func TestMigrateZeroTrustAccessGroupGitHubOrganization(t *testing.T) {
	if os.Getenv("CLOUDFLARE_API_TOKEN") != "" {
		t.Setenv("CLOUDFLARE_API_TOKEN", "")
	}

	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()
	resourceName := "cloudflare_zero_trust_access_group." + rnd
	tmpDir := t.TempDir()

	// V4 config with github blocks (renamed to github_organization in v5)
	v4Config := fmt.Sprintf(`
resource "cloudflare_access_group" "%[1]s" {
  account_id = "%[2]s"
  name       = "%[1]s"
  
  include {
    github {
      name                 = "example-org"
      teams                = ["team1", "team2"]
      identity_provider_id = "github-provider"
    }
  }
}`, rnd, accountID)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		WorkingDir: tmpDir,
		Steps: []resource.TestStep{
			{
				// Step 1: Create with v4 provider
				ExternalProviders: map[string]resource.ExternalProvider{
					"cloudflare": {
						Source:            "cloudflare/cloudflare",
						VersionConstraint: "4.52.1",
					},
				},
				Config: v4Config,
			},
			// Step 2: Run migration and verify github -> github_organization transformation
			acctest.MigrationTestStep(t, v4Config, tmpDir, "4.52.1", []statecheck.StateCheck{
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
				// Verify teams array expanded to multiple objects
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include"), knownvalue.ListSizeExact(2)),
			}),
			{
				// Step 3: Apply migrated config
				ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
				ConfigDirectory:          config.StaticDirectory(tmpDir),
				ConfigStateChecks: []statecheck.StateCheck{
					// Verify github -> github_organization and teams -> team transformation
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(0).AtMapKey("github_organization").AtMapKey("name"), knownvalue.StringExact("example-org")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(0).AtMapKey("github_organization").AtMapKey("team"), knownvalue.StringExact("team1")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(0).AtMapKey("github_organization").AtMapKey("identity_provider_id"), knownvalue.StringExact("github-provider")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(1).AtMapKey("github_organization").AtMapKey("name"), knownvalue.StringExact("example-org")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(1).AtMapKey("github_organization").AtMapKey("team"), knownvalue.StringExact("team2")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(1).AtMapKey("github_organization").AtMapKey("identity_provider_id"), knownvalue.StringExact("github-provider")),
				},
			},
		},
	})
}

// TestMigrateZeroTrustAccessGroupCommonNames tests migration of common_names array
func TestMigrateZeroTrustAccessGroupCommonNames(t *testing.T) {
	if os.Getenv("CLOUDFLARE_API_TOKEN") != "" {
		t.Setenv("CLOUDFLARE_API_TOKEN", "")
	}

	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()
	resourceName := "cloudflare_zero_trust_access_group." + rnd
	tmpDir := t.TempDir()

	// V4 config with common_names array (becomes multiple common_name objects in v5)
	v4Config := fmt.Sprintf(`
resource "cloudflare_access_group" "%[1]s" {
  account_id = "%[2]s"
  name       = "%[1]s"
  
  include {
    common_names = ["cert1.example.com", "cert2.example.com", "cert3.example.com"]
  }
}`, rnd, accountID)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		WorkingDir: tmpDir,
		Steps: []resource.TestStep{
			{
				// Step 1: Create with v4 provider
				ExternalProviders: map[string]resource.ExternalProvider{
					"cloudflare": {
						Source:            "cloudflare/cloudflare",
						VersionConstraint: "4.52.1",
					},
				},
				Config: v4Config,
			},
			// Step 2: Run migration and verify common_names -> common_name transformation
			acctest.MigrationTestStep(t, v4Config, tmpDir, "4.52.1", []statecheck.StateCheck{
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
				// Verify common_names array expanded to 3 common_name objects
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include"), knownvalue.ListSizeExact(3)),
			}),
			{
				// Step 3: Apply migrated config
				ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
				ConfigDirectory:          config.StaticDirectory(tmpDir),
				ConfigStateChecks: []statecheck.StateCheck{
					// Verify each common name became separate common_name object
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(0).AtMapKey("common_name").AtMapKey("common_name"), knownvalue.StringExact("cert1.example.com")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(1).AtMapKey("common_name").AtMapKey("common_name"), knownvalue.StringExact("cert2.example.com")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(2).AtMapKey("common_name").AtMapKey("common_name"), knownvalue.StringExact("cert3.example.com")),
				},
			},
		},
	})
}

// TestMigrateZeroTrustAccessGroupIdentityProviderRules tests migration of identity provider rules
func TestMigrateZeroTrustAccessGroupIdentityProviderRules(t *testing.T) {
	if os.Getenv("CLOUDFLARE_API_TOKEN") != "" {
		t.Setenv("CLOUDFLARE_API_TOKEN", "")
	}

	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()
	resourceName := "cloudflare_zero_trust_access_group." + rnd
	tmpDir := t.TempDir()

	// V4 config with GSuite and Okta using arrays
	v4Config := fmt.Sprintf(`
resource "cloudflare_access_group" "%[1]s" {
  account_id = "%[2]s"
  name       = "%[1]s"
  
  include {
    gsuite {
      email                = ["user1@gsuite.com", "user2@gsuite.com"]
      identity_provider_id = "gsuite-provider"
    }
    
    okta {
      name                 = ["group1", "group2"]
      identity_provider_id = "okta-provider"
    }
  }
}`, rnd, accountID)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		WorkingDir: tmpDir,
		Steps: []resource.TestStep{
			{
				// Step 1: Create with v4 provider
				ExternalProviders: map[string]resource.ExternalProvider{
					"cloudflare": {
						Source:            "cloudflare/cloudflare",
						VersionConstraint: "4.52.1",
					},
				},
				Config: v4Config,
			},
			// Step 2: Run migration and verify identity provider transformations
			acctest.MigrationTestStep(t, v4Config, tmpDir, "4.52.1", []statecheck.StateCheck{
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
				// Verify expansion: 2 gsuite emails + 2 okta names = 4 objects
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include"), knownvalue.ListSizeExact(4)),
			}),
			{
				// Step 3: Apply migrated config
				ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
				ConfigDirectory:          config.StaticDirectory(tmpDir),
				ConfigStateChecks: []statecheck.StateCheck{
					// Verify GSuite email expansion
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(0).AtMapKey("gsuite").AtMapKey("email"), knownvalue.StringExact("user1@gsuite.com")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(0).AtMapKey("gsuite").AtMapKey("identity_provider_id"), knownvalue.StringExact("gsuite-provider")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(1).AtMapKey("gsuite").AtMapKey("email"), knownvalue.StringExact("user2@gsuite.com")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(1).AtMapKey("gsuite").AtMapKey("identity_provider_id"), knownvalue.StringExact("gsuite-provider")),
					// Verify Okta name expansion
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(2).AtMapKey("okta").AtMapKey("name"), knownvalue.StringExact("group1")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(2).AtMapKey("okta").AtMapKey("identity_provider_id"), knownvalue.StringExact("okta-provider")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(3).AtMapKey("okta").AtMapKey("name"), knownvalue.StringExact("group2")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(3).AtMapKey("okta").AtMapKey("identity_provider_id"), knownvalue.StringExact("okta-provider")),
				},
			},
		},
	})
}

// TestMigrateZeroTrustAccessGroupZoneScoped tests zone-level access group migration
func TestMigrateZeroTrustAccessGroupZoneScoped(t *testing.T) {
	if os.Getenv("CLOUDFLARE_API_TOKEN") != "" {
		t.Setenv("CLOUDFLARE_API_TOKEN", "")
	}

	zoneID := os.Getenv("CLOUDFLARE_ZONE_ID")
	rnd := utils.GenerateRandomResourceName()
	resourceName := "cloudflare_zero_trust_access_group." + rnd
	tmpDir := t.TempDir()

	// V4 config for zone-scoped access group
	v4Config := fmt.Sprintf(`
resource "cloudflare_access_group" "%[1]s" {
  zone_id = "%[2]s"
  name    = "%[1]s"
  
  include {
    email = ["test@example.com"]
    ip    = ["192.0.2.0/24"]
  }
}`, rnd, zoneID)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_ZoneID(t)
		},
		WorkingDir: tmpDir,
		Steps: []resource.TestStep{
			{
				// Step 1: Create with v4 provider
				ExternalProviders: map[string]resource.ExternalProvider{
					"cloudflare": {
						Source:            "cloudflare/cloudflare",
						VersionConstraint: "4.52.1",
					},
				},
				Config: v4Config,
			},
			// Step 2: Run migration and verify zone context preserved
			acctest.MigrationTestStep(t, v4Config, tmpDir, "4.52.1", []statecheck.StateCheck{
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New(consts.ZoneIDSchemaKey), knownvalue.StringExact(zoneID)),
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include"), knownvalue.ListSizeExact(2)),
			}),
			{
				// Step 3: Apply migrated config
				ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
				ConfigDirectory:          config.StaticDirectory(tmpDir),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New(consts.ZoneIDSchemaKey), knownvalue.StringExact(zoneID)),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(0).AtMapKey("email").AtMapKey("email"), knownvalue.StringExact("test@example.com")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(1).AtMapKey("ip").AtMapKey("ip"), knownvalue.StringExact("192.0.2.0/24")),
				},
			},
		},
	})
}

// TestMigrateZeroTrustAccessGroupAllRuleTypes tests migration with comprehensive rule coverage
func TestMigrateZeroTrustAccessGroupAllRuleTypes(t *testing.T) {
	if os.Getenv("CLOUDFLARE_API_TOKEN") != "" {
		t.Setenv("CLOUDFLARE_API_TOKEN", "")
	}

	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()
	resourceName := "cloudflare_zero_trust_access_group." + rnd
	tmpDir := t.TempDir()

	// V4 config with comprehensive rule types
	v4Config := fmt.Sprintf(`
resource "cloudflare_access_group" "%[1]s" {
  account_id = "%[2]s"
  name       = "%[1]s"
  
  include {
    everyone = true
    
    email        = ["user@example.com"]
    email_domain = ["company.com"]
    ip           = ["10.0.0.0/8"]
    ip_list      = ["list-uuid-1"]
    
    geo              = ["US", "CA"]
    service_token    = ["token-1", "token-2"]
    group            = ["group-1"]
    login_method     = ["method-1"]
    device_posture   = ["posture-1"]
    
    certificate = true
    any_valid_service_token = true
    
    saml {
      attribute_name       = "department"
      attribute_value      = "engineering"
      identity_provider_id = "saml-provider"
    }
    
    external_evaluation {
      evaluate_url = "https://example.com/evaluate"
      keys_url     = "https://example.com/keys"
    }
  }
}`, rnd, accountID)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		WorkingDir: tmpDir,
		Steps: []resource.TestStep{
			{
				// Step 1: Create with v4 provider
				ExternalProviders: map[string]resource.ExternalProvider{
					"cloudflare": {
						Source:            "cloudflare/cloudflare",
						VersionConstraint: "4.52.1",
					},
				},
				Config: v4Config,
			},
			// Step 2: Run migration and verify all rule types transformed
			acctest.MigrationTestStep(t, v4Config, tmpDir, "4.52.1", []statecheck.StateCheck{
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
				// Verify total count: boolean flags + expanded arrays + single objects
				// everyone(1) + email(1) + email_domain(1) + ip(1) + ip_list(1) + geo(2) + service_token(2) + 
				// group(1) + login_method(1) + device_posture(1) + certificate(1) + any_valid_service_token(1) + 
				// saml(1) + external_evaluation(1) = 15 objects
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include"), knownvalue.ListSizeExact(15)),
			}),
			{
				// Step 3: Apply migrated config
				ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
				ConfigDirectory:          config.StaticDirectory(tmpDir),
				ConfigStateChecks: []statecheck.StateCheck{
					// Verify key transformed objects (sampling for brevity)
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(0).AtMapKey("everyone"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(1).AtMapKey("email").AtMapKey("email"), knownvalue.StringExact("user@example.com")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(5).AtMapKey("geo").AtMapKey("country_code"), knownvalue.StringExact("US")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(6).AtMapKey("geo").AtMapKey("country_code"), knownvalue.StringExact("CA")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(7).AtMapKey("service_token").AtMapKey("token_id"), knownvalue.StringExact("token-1")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(8).AtMapKey("service_token").AtMapKey("token_id"), knownvalue.StringExact("token-2")),
				},
			},
		},
	})
}

// TestMigrateZeroTrustAccessGroupMixedComplexScenario tests real-world complex migration
func TestMigrateZeroTrustAccessGroupMixedComplexScenario(t *testing.T) {
	if os.Getenv("CLOUDFLARE_API_TOKEN") != "" {
		t.Setenv("CLOUDFLARE_API_TOKEN", "")
	}

	accountID := os.Getenv("CLOUDFLARE_ACCOUNT_ID")
	rnd := utils.GenerateRandomResourceName()
	resourceName := "cloudflare_zero_trust_access_group." + rnd
	tmpDir := t.TempDir()

	// V4 config combining all migration challenges
	v4Config := fmt.Sprintf(`
resource "cloudflare_access_group" "%[1]s" {
  account_id = "%[2]s"
  name       = "%[1]s"
  
  include {
    # Basic rules with multiple values
    email        = ["admin@company.com", "manager@company.com"]
    email_domain = ["company.com", "trusted.com"]
    ip           = ["10.0.1.0/24", "10.0.2.0/24"]
    
    # Identity providers with arrays
    azure {
      id                   = ["admin-group", "dev-group"]
      identity_provider_id = "azure-ad-provider"
    }
    
    github {
      name                 = "company-org"
      teams                = ["backend-team", "frontend-team", "devops-team"]
      identity_provider_id = "github-provider"
    }
    
    gsuite {
      email                = ["boss@company.com", "cto@company.com"]
      identity_provider_id = "gsuite-provider"  
    }
    
    okta {
      name                 = ["engineering", "product"]
      identity_provider_id = "okta-provider"
    }
    
    # Common names array
    common_names = ["client1.company.com", "client2.company.com"]
    
    # Other arrays
    geo            = ["US", "GB", "DE"]
    service_token  = ["token-prod", "token-staging"]
    device_posture = ["corporate-device", "managed-device"]
    
    # Boolean flags
    certificate = true
  }
  
  exclude {
    email        = ["blocked@company.com"]
    ip           = ["192.168.1.100/32"]
    geo          = ["CN", "RU"]
  }
  
  require {
    email_domain = ["company.com"]
    
    saml {
      attribute_name       = "role"
      attribute_value      = "employee"
      identity_provider_id = "saml-provider"
    }
  }
}`, rnd, accountID)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			acctest.TestAccPreCheck(t)
			acctest.TestAccPreCheck_AccountID(t)
		},
		WorkingDir: tmpDir,
		Steps: []resource.TestStep{
			{
				// Step 1: Create with v4 provider
				ExternalProviders: map[string]resource.ExternalProvider{
					"cloudflare": {
						Source:            "cloudflare/cloudflare",
						VersionConstraint: "4.52.1",
					},
				},
				Config: v4Config,
			},
			// Step 2: Run migration and verify complex transformation
			acctest.MigrationTestStep(t, v4Config, tmpDir, "4.52.1", []statecheck.StateCheck{
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("name"), knownvalue.StringExact(rnd)),
				// Complex calculation of expected objects:
				// emails(2) + email_domains(2) + ips(2) + azure_ids(2) + github_teams(3) + 
				// gsuite_emails(2) + okta_names(2) + common_names(2) + geo(3) + service_tokens(2) + 
				// device_postures(2) + certificate(1) = 25 include objects
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include"), knownvalue.ListSizeExact(25)),
				// exclude: email(1) + ip(1) + geo(2) = 4 objects
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("exclude"), knownvalue.ListSizeExact(4)),
				// require: email_domain(1) + saml(1) = 2 objects
				statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("require"), knownvalue.ListSizeExact(2)),
			}),
			{
				// Step 3: Apply migrated config
				ProtoV6ProviderFactories: acctest.TestAccProtoV6ProviderFactories,
				ConfigDirectory:          config.StaticDirectory(tmpDir),
				ConfigStateChecks: []statecheck.StateCheck{
					// Sample key transformations for verification
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(0).AtMapKey("email").AtMapKey("email"), knownvalue.StringExact("admin@company.com")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(1).AtMapKey("email").AtMapKey("email"), knownvalue.StringExact("manager@company.com")),
					// Verify azure -> azure_ad rename
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(6).AtMapKey("azure_ad").AtMapKey("id"), knownvalue.StringExact("admin-group")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(7).AtMapKey("azure_ad").AtMapKey("id"), knownvalue.StringExact("dev-group")),
					// Verify github -> github_organization and teams -> team
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(8).AtMapKey("github_organization").AtMapKey("name"), knownvalue.StringExact("company-org")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("include").AtSliceIndex(8).AtMapKey("github_organization").AtMapKey("team"), knownvalue.StringExact("backend-team")),
					// Verify exclude transformations
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("exclude").AtSliceIndex(0).AtMapKey("email").AtMapKey("email"), knownvalue.StringExact("blocked@company.com")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("exclude").AtSliceIndex(2).AtMapKey("geo").AtMapKey("country_code"), knownvalue.StringExact("CN")),
					// Verify require transformations  
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("require").AtSliceIndex(0).AtMapKey("email_domain").AtMapKey("domain"), knownvalue.StringExact("company.com")),
					statecheck.ExpectKnownValue(resourceName, tfjsonpath.New("require").AtSliceIndex(1).AtMapKey("saml").AtMapKey("attribute_name"), knownvalue.StringExact("role")),
				},
			},
		},
	})
}