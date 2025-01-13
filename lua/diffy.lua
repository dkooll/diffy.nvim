local M = {}
-- Cache for provider schemas
local schema_cache = {}
-- Check if HCL parser is available
local function ensure_hcl_parser()
  local ok = pcall(vim.treesitter.get_parser, 0, "hcl")
  if not ok then
    print("HCL parser not found. Please ensure tree-sitter HCL is installed.")
    return false
  end
  return true
end
-- Fetch schema using terraform CLI with callback
function M.fetch_schema(callback)
  -- print("Fetching schema...") -- Debug print
  local handle = io.popen('terraform providers schema -json')
  if handle then
    local result = handle:read('*a')
    handle:close()
    local success, decoded = pcall(vim.json.decode, result)
    if success then
      schema_cache = decoded.provider_schemas["registry.terraform.io/hashicorp/azurerm"] or {}
      -- print("Schema loaded successfully") -- Debug print
      if callback then
        callback() -- Removed vim.schedule to ensure immediate execution
      end
    else
      print("Failed to parse schema JSON")
    end
  else
    print("Failed to execute terraform command")
  end
end

-- Parse current buffer using treesitter
function M.parse_current_buffer()
  if not ensure_hcl_parser() then
    return {}
  end
  local bufnr = vim.api.nvim_get_current_buf()
  local parser = vim.treesitter.get_parser(bufnr, "hcl")
  local tree = parser:parse()[1]
  if not tree then return {} end
  local root = tree:root()
  local resources = {}
  -- Query to find resource blocks
  local query = vim.treesitter.query.parse("hcl", [[
        (block
            (identifier) @block_type
            (string_lit) @resource_type
            (string_lit) @resource_name
            (body) @body
        )
    ]])
  for _, captures, _ in query:iter_matches(root, bufnr) do
    if not captures[1] or not captures[2] or not captures[4] then
      goto continue
    end
    local block_type = vim.treesitter.get_node_text(captures[1], bufnr)
    if block_type == "resource" then
      local resource_type = vim.treesitter.get_node_text(captures[2], bufnr):gsub('"', '')
      local body_node = captures[4]
      local resource = {
        type = resource_type,
        properties = {},
        blocks = {},
        dynamic_blocks = {}
      }
      local function parse_block_contents(node)
        local block_data = {
          properties = {},
          blocks = {},
          dynamic_blocks = {}
        }
        -- Query for attributes
        local attr_query = vim.treesitter.query.parse("hcl", "(attribute (identifier) @name)")
        for _, attr_match in attr_query:iter_matches(node, bufnr) do
          local name = vim.treesitter.get_node_text(attr_match[1], bufnr)
          block_data.properties[name] = true
        end
        -- Query for regular blocks
        local block_query = vim.treesitter.query.parse("hcl", "(block (identifier) @name (body) @body)")
        for _, block_match in block_query:iter_matches(node, bufnr) do
          local name = vim.treesitter.get_node_text(block_match[1], bufnr)
          local body = block_match[2]
          if name ~= "dynamic" then
            -- Parse the block's contents recursively
            block_data.blocks[name] = parse_block_contents(body)
          end
        end
        -- Query for dynamic blocks
        local dynamic_query = vim.treesitter.query.parse("hcl", [[
          (block
            (identifier) @type
            (string_lit) @name
            (body) @body
            (#eq? @type "dynamic"))
        ]])
        for _, dyn_match in dynamic_query:iter_matches(node, bufnr) do
          local dyn_name = vim.treesitter.get_node_text(dyn_match[2], bufnr):gsub('"', '')
          local dyn_body = dyn_match[3]
          -- Look for content block inside dynamic block
          local content_query = vim.treesitter.query.parse("hcl",
            "(block (identifier) @name (body) @body (#eq? @name \"content\"))")
          for _, content_match in content_query:iter_matches(dyn_body, bufnr) do
            local content_body = content_match[2]
            -- Parse the content block's properties and nested blocks
            block_data.dynamic_blocks[dyn_name] = parse_block_contents(content_body)
          end
        end
        return block_data
      end
      -- Parse the resource body
      local parsed_data = parse_block_contents(body_node)
      resource.properties = parsed_data.properties
      resource.blocks = parsed_data.blocks
      resource.dynamic_blocks = parsed_data.dynamic_blocks
      table.insert(resources, resource)
    end
    ::continue::
  end
  return resources
end

-- Validate resources and print results
function M.validate_resources()
  -- Always fetch fresh schema to ensure we have latest
  M.fetch_schema(function()
    local resources = M.parse_current_buffer()
    -- print("\nChecking resources...") -- Debug print
    for _, resource in ipairs(resources) do
      local schema = schema_cache.resource_schemas[resource.type]
      if schema and schema.block then
        local function validate_block_attributes(block_schema, block_data, block_path)
          -- Check attributes
          if block_schema.attributes then
            for name, attr in pairs(block_schema.attributes) do
              if not attr.computed and not block_data.properties[name] then
                if attr.required then
                  print(string.format("%s missing required property %s in %s", resource.type, name, block_path))
                else
                  print(string.format("%s missing optional property %s in %s", resource.type, name, block_path))
                end
              end
            end
          end
          -- Check nested blocks
          if block_schema.block_types then
            for name, block_type in pairs(block_schema.block_types) do
              if name == "timeouts" then goto continue end
              local block = block_data.blocks[name]
              local dynamic_block = block_data.dynamic_blocks[name]
              if block then
                -- Validate nested block attributes
                if block_type.block and block_type.block.attributes then
                  validate_block_attributes(block_type.block, block, block_path .. "." .. name)
                end
              elseif dynamic_block then
                -- Count total dynamic blocks in the resource path
                local function count_dynamic_blocks(current_block)
                  local count = 0
                  for _, _ in pairs(current_block.dynamic_blocks) do
                    count = count + 1
                  end
                  for _, nested_block in pairs(current_block.blocks) do
                    count = count + count_dynamic_blocks(nested_block)
                  end
                  for _, nested_dynamic in pairs(current_block.dynamic_blocks) do
                    count = count + count_dynamic_blocks(nested_dynamic)
                  end
                  return count
                end
                --FIX: nested dynamic blocks checks
                -- Skip validation if resource has multiple dynamic blocks
                if count_dynamic_blocks(resource) > 1 then
                  goto continue
                end
                -- Validate dynamic block content attributes
                if block_type.block and block_type.block.attributes then
                  -- Check properties in dynamic blocks
                  for prop_name, attr in pairs(block_type.block.attributes) do
                    if not attr.computed and not dynamic_block.properties[prop_name] then
                      if attr.required then
                        print(string.format("%s missing required property %s in %s", resource.type, prop_name,
                          block_path .. ".dynamic." .. name))
                      else
                        print(string.format("%s missing optional property %s in %s", resource.type, prop_name,
                          block_path .. ".dynamic." .. name))
                      end
                    end
                  end
                  -- Also check for nested blocks inside dynamic blocks
                  if block_type.block.block_types then
                    for nested_name, nested_block_type in pairs(block_type.block.block_types) do
                      if not dynamic_block.blocks[nested_name] and not dynamic_block.dynamic_blocks[nested_name] then
                        if nested_block_type.min_items and nested_block_type.min_items > 0 then
                          print(string.format("%s missing required block %s in %s", resource.type, nested_name,
                            block_path .. ".dynamic." .. name))
                        else
                          print(string.format("%s missing optional block %s in %s", resource.type, nested_name,
                            block_path .. ".dynamic." .. name))
                        end
                      end
                    end
                  end
                end
                ::continue::
              elseif block_type.min_items and block_type.min_items > 0 then
                print(string.format("%s missing required block %s in %s", resource.type, name, block_path))
              else
                print(string.format("%s missing optional block %s in %s", resource.type, name, block_path))
              end
              ::continue::
            end
          end
        end
        -- Start validation from the root
        validate_block_attributes(schema.block, resource, "root")
      end
    end
    -- print("Validation complete") -- Debug print
  end)
end

function M.setup(opts)
  opts = opts or {}
  vim.api.nvim_create_user_command("TerraformValidateSchema", function()
    -- print("\n=== Starting Terraform Schema Validation ===")
    M.validate_resources()
  end, {})
end

return M