# diffy

A neovim plugin for validating terraform hcl resources against provider schemas.

It analyzes your terraform configurations and submodules, helping identify missing required properties and blocks across your entire project, including nested dynamic ones and cross-module dependencies.

## Features

Validates HCL resources against official provider schemas

Detects missing required and optional properties

Identifies unused provider declarations

Handles dynamic blocks and nested attributes

Respects ignore_changes lifecycle settings

Analyzes entire project structure including submodules

## Usage

To configure the plugin with [lazy.nvim](https://github.com/folke/lazy.nvim), use the following setup:

```lua
return {
  "dkooll/diffy.nvim",
  dependencies = { "nvim-lua/plenary.nvim" },
  ft = { "terraform", "hcl", "tf" },
  keys = {
    {
      "<leader>vs",
      function()
        require("diffy").validate_resources()
      end,
      desc = "Diffy: Validate Hcl Schema"
    },
  },
  config = function(_, opts)
    require("diffy").setup(opts)
  end
}
```

## Commands

`:TerraformValidateSchema`

Runs schema validation against all Terraform files in the project

## Notes

It automatically discovers modules by finding terraform.tf files

It retrieves schemas dynamically for the specified providers

It filters out purely computed properties, which are populated by the provider

It displays validation results in a dedicated output window

It analyzes main.tf and terraform.tf files within each module

It checks for missing required properties, blocks, and attributes

It respects lifecycle ignore_changes configurations

## Requirements

Neovim with treeSitter support

TreeSitter HCL parser

Terraform CLI accessible in your PATH

Valid terraform configuration files
