# diffy

A neovim plugin for validating terraform hcl resources against provider schemas.

It analyzes your terraform configurations and submodules, helping identify missing required properties and blocks across your entire project, including nested dynamic ones and cross-module dependencies.

## Features

Validates HCL resources and data sources against official provider schemas

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

Modules are automatically discovered by scanning for terraform.tf files

Dynamic schema retrieval occurs for all specified providers

Purely computed properties, which providers typically populate, are filtered out

All validation results appear in a dedicated output window

Within each module, both main.tf and terraform.tf files undergo analysis

Missing required properties, blocks, and attributes are thoroughly checked

The plugin fully respects lifecycle ignore_changes configurations

## Requirements

Neovim with treeSitter support

TreeSitter HCL parser

Terraform CLI accessible in your PATH

Valid terraform configuration files
