# diffy

A neovim plugin for validating terraform hcl resources against provider schemas.

It analyzes your terraform configurations and helps identify missing required properties and blocks, including nested dynamic blocks.

## Notes

It uses terraform.tf file to retrieve the schemas for the specified providers.

It omits optional properties when combined with computed properties.
