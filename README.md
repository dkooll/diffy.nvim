# diffy

A neovim plugin for validating terraform hcl resources against provider schemas.

It analyzes your terraform configurations and submodules, helping identify missing required properties and blocks across your entire project, including nested dynamic ones and cross-module dependencies.

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

## Notes

It retrieves dynamicly the schemas for the specified providers.

It filters out purely computed properties, which are typically populated by the provider.
