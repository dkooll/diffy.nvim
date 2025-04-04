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

Dynamic schema retrieval occurs for all specified providers

Purely computed properties, which providers typically populate, are filtered out

The plugin fully respects lifecycle ignore_changes configurations

## Contributors

We welcome contributions from the community! Whether it's reporting a bug, suggesting a new feature, or submitting a pull request, your input is highly valued. <br><br>

<a href="https://github.com/dkooll/diffy.nvim/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=dkooll/diffy.nvim" />
</a>

## Requirements

[Neovim](https://neovim.io/) 0.11.0 or higher

[TreeSitter](https://github.com/nvim-treesitter/nvim-treesitter) HCL parser

[Terraform](https://developer.hashicorp.com/terraform/install) CLI accessible in your PATH
