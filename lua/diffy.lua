local M = {}
-- Cache for provider schemas
local schema_cache = {}
local output_bufnr = nil
local output_winid = nil

--- Create or get the dedicated output buffer
local function ensure_output_buffer()
  if not output_bufnr or not vim.api.nvim_buf_is_valid(output_bufnr) then
    output_bufnr = vim.api.nvim_create_buf(false, true)
    vim.bo[output_bufnr].buftype = "nofile"
    vim.bo[output_bufnr].bufhidden = "hide"
    vim.bo[output_bufnr].swapfile = false
    vim.api.nvim_buf_set_name(output_bufnr, "Terraform Schema Validation")
  end
  return output_bufnr
end

--- Ensure the output buffer is visible in a split window
local function ensure_output_window()
  if not output_winid or not vim.api.nvim_win_is_valid(output_winid) then
    local current_win = vim.api.nvim_get_current_win()
    vim.cmd("botright split")
    output_winid = vim.api.nvim_get_current_win()
    vim.api.nvim_win_set_buf(output_winid, ensure_output_buffer())
    vim.api.nvim_win_set_height(output_winid, 20)
    vim.wo[output_winid].wrap = false
    vim.wo[output_winid].number = false
    vim.wo[output_winid].relativenumber = false
    vim.api.nvim_set_current_win(current_win)
  end
  return output_winid
end

--- Print lines to the output buffer
local function write_output(lines, clear)
  if clear then
    vim.api.nvim_buf_set_lines(ensure_output_buffer(), 0, -1, false, {})
  end
  if type(lines) == "string" then
    lines = { lines }
  end
  local buf = ensure_output_buffer()
  local line_count = vim.api.nvim_buf_line_count(buf)
  vim.api.nvim_buf_set_lines(buf, line_count, line_count, false, lines)

  local win = ensure_output_window()
  vim.api.nvim_win_set_cursor(win, { line_count + #lines, 0 })
  vim.cmd("redraw")
end

-- ─────────────────────────────────────────────────────────────────────────────
--                       Terraform Schema Fetching
-- ─────────────────────────────────────────────────────────────────────────────

--- Check if the HCL Tree-Sitter parser is available
local function ensure_hcl_parser()
  local ok = pcall(vim.treesitter.get_parser, 0, "hcl")
  if not ok then
    write_output("HCL parser not found. Please ensure tree-sitter HCL is installed.")
    return false
  end
  return true
end

--- Create a temporary directory
local function create_temp_dir()
  local handle = io.popen("mktemp -d")
  if handle then
    local temp_dir = handle:read("*l")
    handle:close()
    return temp_dir
  end
  return nil
end

--- Clean up a directory, printing success/fail
local function cleanup(temp_dir)
  if temp_dir then
    vim.fn.system({ "rm", "-rf", temp_dir })
    if vim.v.shell_error == 0 then
      write_output({ "", "Cleaning up files succeeded" })
    else
      write_output({ "", "Cleaning up files failed" })
    end
  end
end

--- Download and parse the Terraform provider schema JSON
function M.fetch_schema(callback)
  write_output({}, true)
  local temp_dir = create_temp_dir()
  if not temp_dir then
    write_output("Failed to create temporary directory")
    return
  end

  -- Minimal Terraform config
  local config_file = temp_dir .. "/main.tf"
  local f = io.open(config_file, "w")
  if not f then
    cleanup(temp_dir)
    write_output("Failed to create temporary configuration")
    return
  end
  f:write([[
terraform {
  required_providers {
    azurerm = {
      source = "hashicorp/azurerm"
    }
  }
}
]])
  f:close()

  local init_job = vim.fn.jobstart({ "terraform", "init" }, {
    cwd = temp_dir,
    on_stdout = function(_, data)
      if data and #data > 0 then
        write_output(vim.tbl_filter(function(line)
          return line and line ~= ""
        end, data))
      end
    end,
    on_stderr = function(_, data)
      if data and #data > 0 then
        write_output(vim.tbl_map(function(line)
          return "Error: " .. line
        end, vim.tbl_filter(function(line)
          return line and line ~= ""
        end, data)))
      end
    end,
    on_exit = function(_, exit_code)
      if exit_code ~= 0 then
        write_output("Failed to initialize Terraform")
        cleanup(temp_dir)
        return
      end

      -- Once "terraform init" succeeds, fetch the providers schema
      vim.fn.jobstart({ "terraform", "providers", "schema", "-json" }, {
        cwd = temp_dir,
        stdout_buffered = true,
        on_stdout = function(_, data)
          if data and #data > 0 then
            local json_str = table.concat(data, "\n")
            local success, decoded = pcall(vim.json.decode, json_str)
            if success then
              schema_cache = decoded.provider_schemas["registry.terraform.io/hashicorp/azurerm"] or {}
              if callback then
                write_output({ "" }) -- Blank line
                callback()
              end
            else
              write_output("Failed to parse schema JSON")
            end
          end
        end,
        on_stderr = function(_, data)
          if data and #data > 0 then
            write_output(vim.tbl_filter(function(line)
              return line and line ~= ""
            end, data))
          end
        end,
        on_exit = function(_, schema_exit_code)
          if schema_exit_code ~= 0 then
            write_output("Failed to fetch schema")
          end
          cleanup(temp_dir)
        end
      })
    end
  })

  if init_job == 0 then
    write_output("Failed to start Terraform initialization")
    cleanup(temp_dir)
  end
end

-- ─────────────────────────────────────────────────────────────────────────────
--                       Tree-Sitter Parsing Logic
-- ─────────────────────────────────────────────────────────────────────────────

--- Minimal parser for `ignore_changes = [ contact, "foo" ]`
--  Gathers the item names out of the bracket list.
local function parse_ignore_changes_array(node, bufnr)
  local results = {}

  local bracket_query = vim.treesitter.query.parse("hcl", [[
    (attribute
      (identifier) @attr_name
      (expression
        (collection_value
          (tuple
            (expression) @item+)))
    )
  ]])

  for _, match, _ in bracket_query:iter_matches(node, bufnr) do
    local attr_node = match[1]
    local attr_name = vim.treesitter.get_node_text(attr_node, bufnr)
    if attr_name == "ignore_changes" then
      -- All other captures in `match` are the @item captures
      for idx = 2, #match do
        local item_node = match[idx]
        local txt = vim.treesitter.get_node_text(item_node, bufnr)
        -- If it's quoted, strip quotes
        txt = txt:gsub('^"(.*)"$', "%1")
        table.insert(results, txt)
      end
    end
  end

  return results
end

--- Recursively parse blocks, dynamic blocks, and record lifecycle.ignore_changes
local function parse_block_contents(node, bufnr)
  local block_data = {
    properties = {},
    blocks = {},
    dynamic_blocks = {},
    ignore_changes = {}, -- store property/block names from lifecycle.ignore_changes
  }

  -- 1) Normal attributes
  local attr_query = vim.treesitter.query.parse("hcl", [[
    (attribute (identifier) @name)
  ]])
  for _, match, _ in attr_query:iter_matches(node, bufnr) do
    local name_node = match[1]
    local name_txt = vim.treesitter.get_node_text(name_node, bufnr)
    block_data.properties[name_txt] = true
  end

  -- 2) Regular blocks (non-dynamic)
  local block_query = vim.treesitter.query.parse("hcl", [[
    (block
      (identifier) @name
      (body) @body)
  ]])
  for _, bmatch, _ in block_query:iter_matches(node, bufnr) do
    local name_node = bmatch[1]
    local body_node = bmatch[2]
    local name_txt = vim.treesitter.get_node_text(name_node, bufnr)

    if name_txt == "dynamic" then
      goto continue_block
    end

    if name_txt == "lifecycle" then
      -- If there's a lifecycle block, parse it to check ignore_changes
      local lifecycle_data = parse_block_contents(body_node, bufnr)
      if lifecycle_data.properties["ignore_changes"] then
        local arr = parse_ignore_changes_array(body_node, bufnr)
        for _, ignored in ipairs(arr) do
          table.insert(block_data.ignore_changes, ignored)
        end
      end
      goto continue_block
    end

    block_data.blocks[name_txt] = parse_block_contents(body_node, bufnr)
    ::continue_block::
  end

  -- 3) Dynamic blocks: dynamic "something" { content { ... } }
  local dynamic_query = vim.treesitter.query.parse("hcl", [[
    (block
      (identifier) @dyn_kw
      (string_lit) @dyn_name
      (body) @dyn_body
      (#eq? @dyn_kw "dynamic"))
  ]])
  for _, dmatch, _ in dynamic_query:iter_matches(node, bufnr) do
    local dyn_name_node = dmatch[2]
    local dyn_body_node = dmatch[3]
    local dyn_name_txt = vim.treesitter.get_node_text(dyn_name_node, bufnr):gsub('"', "")

    -- See if there's a content block
    local content_query = vim.treesitter.query.parse("hcl", [[
      (block
        (identifier) @content_kw
        (body) @content_body
        (#eq? @content_kw "content"))
    ]])
    local found_content = false
    for _, cmatch, _ in content_query:iter_matches(dyn_body_node, bufnr) do
      found_content = true
      local content_body_node = cmatch[2]
      local content_data = parse_block_contents(content_body_node, bufnr)

      -- Merge "content" data into the dynamic block
      block_data.dynamic_blocks[dyn_name_txt] = block_data.dynamic_blocks[dyn_name_txt] or {
        properties = {},
        blocks = {},
        dynamic_blocks = {},
        ignore_changes = {},
      }
      for k, v in pairs(content_data.properties) do
        block_data.dynamic_blocks[dyn_name_txt].properties[k] = v
      end
      for k, v in pairs(content_data.blocks) do
        block_data.dynamic_blocks[dyn_name_txt].blocks[k] = v
      end
      for k, v in pairs(content_data.dynamic_blocks) do
        block_data.dynamic_blocks[dyn_name_txt].dynamic_blocks[k] = v
      end
      for _, ic in ipairs(content_data.ignore_changes) do
        table.insert(block_data.dynamic_blocks[dyn_name_txt].ignore_changes, ic)
      end
    end

    if not found_content then
      -- If no content block, parse the entire dyn_body as fallback
      block_data.dynamic_blocks[dyn_name_txt] = parse_block_contents(dyn_body_node, bufnr)
    end
  end

  return block_data
end

--- Top-level parse for resource "X" "Y" { ... } blocks.
function M.parse_current_buffer()
  if not ensure_hcl_parser() then
    return {}
  end
  local bufnr = vim.api.nvim_get_current_buf()
  local parser = vim.treesitter.get_parser(bufnr, "hcl")
  local tree = parser:parse()[1]
  if not tree then
    return {}
  end

  local root = tree:root()
  local resources = {}

  local resource_query = vim.treesitter.query.parse("hcl", [[
    (block
      (identifier) @block_type
      (string_lit) @resource_type
      (string_lit) @resource_name
      (body) @body)
  ]])
  for _, captures, _ in resource_query:iter_matches(root, bufnr) do
    local block_type_node = captures[1]
    local resource_type_node = captures[2]
    local body_node = captures[4]
    if not (block_type_node and resource_type_node and body_node) then
      goto continue_res
    end

    local block_type_txt = vim.treesitter.get_node_text(block_type_node, bufnr)
    if block_type_txt == "resource" then
      local resource_type_txt = vim.treesitter.get_node_text(resource_type_node, bufnr):gsub('"', "")
      local parsed_data = parse_block_contents(body_node, bufnr)
      table.insert(resources, {
        type = resource_type_txt,
        properties = parsed_data.properties,
        blocks = parsed_data.blocks,
        dynamic_blocks = parsed_data.dynamic_blocks,
        ignore_changes = parsed_data.ignore_changes,
      })
    end
    ::continue_res::
  end

  return resources
end

-- ─────────────────────────────────────────────────────────────────────────────
--                      Validation Against the Schema
-- ─────────────────────────────────────────────────────────────────────────────

function M.validate_resources()
  write_output({}, true)

  M.fetch_schema(function()
    local resources = M.parse_current_buffer()
    for _, resource in ipairs(resources) do
      local schema = schema_cache.resource_schemas[resource.type]
      if not (schema and schema.block) then
        -- optionally note no schema found
        -- write_output("No schema found for " .. resource.type)
        goto continue_resources
      end

      local function validate_block_attributes(block_schema, block_data, block_path, inherited_ignores)
        inherited_ignores = inherited_ignores or {}

        -- Merge local ignore_changes
        local combined_ignores = {}
        for _, v in ipairs(inherited_ignores) do
          table.insert(combined_ignores, v)
        end
        for _, v in ipairs(block_data.ignore_changes or {}) do
          table.insert(combined_ignores, v)
        end

        -- 1) Attributes
        if block_schema.attributes then
          for attr_name, attr_info in pairs(block_schema.attributes) do
            -- Skip if in ignore_changes
            if vim.tbl_contains(combined_ignores, attr_name) then
              goto continue_attr
            end

            if not attr_info.computed and not block_data.properties[attr_name] then
              if attr_info.required then
                write_output(string.format(
                  "%s missing required property %s in %s",
                  resource.type, attr_name, block_path
                ))
              else
                write_output(string.format(
                  "%s missing optional property %s in %s",
                  resource.type, attr_name, block_path
                ))
              end
            end
            ::continue_attr::
          end
        end

        -- 2) Nested blocks
        if block_schema.block_types then
          for block_name, btype_schema in pairs(block_schema.block_types) do
            if block_name == "timeouts" then
              goto continue_block
            end

            -- If block_name is in ignore_changes, skip it
            if vim.tbl_contains(combined_ignores, block_name) then
              goto continue_block
            end

            local sub_block = block_data.blocks[block_name]
            local dyn_block = block_data.dynamic_blocks[block_name]

            if sub_block then
              if btype_schema.block then
                validate_block_attributes(
                  btype_schema.block,
                  sub_block,
                  block_path .. "." .. block_name,
                  combined_ignores
                )
              end
            elseif dyn_block then
              if btype_schema.block then
                validate_block_attributes(
                  btype_schema.block,
                  dyn_block,
                  block_path .. ".dynamic." .. block_name,
                  combined_ignores
                )
              end
            else
              -- If neither a normal block nor a dynamic block
              if btype_schema.min_items and btype_schema.min_items > 0 then
                write_output(string.format(
                  "%s missing required block %s in %s",
                  resource.type, block_name, block_path
                ))
              else
                write_output(string.format(
                  "%s missing optional block %s in %s",
                  resource.type, block_name, block_path
                ))
              end
            end
            ::continue_block::
          end
        end
      end

      validate_block_attributes(schema.block, resource, "root", resource.ignore_changes)
      ::continue_resources::
    end
  end)
end

function M.setup()
  vim.api.nvim_create_user_command("TerraformValidateSchema", M.validate_resources, {})
end

return M


-- local M = {}
-- -- Cache for provider schemas
-- local schema_cache = {}
-- local output_bufnr = nil
-- local output_winid = nil
--
-- -- Function to create or get output buffer
-- local function ensure_output_buffer()
--   if not output_bufnr or not vim.api.nvim_buf_is_valid(output_bufnr) then
--     output_bufnr = vim.api.nvim_create_buf(false, true)
--     vim.bo[output_bufnr].buftype = 'nofile'
--     vim.bo[output_bufnr].bufhidden = 'hide'
--     vim.bo[output_bufnr].swapfile = false
--     vim.api.nvim_buf_set_name(output_bufnr, 'Terraform Schema Validation')
--   end
--   return output_bufnr
-- end
--
-- -- Function to ensure output window is visible
-- local function ensure_output_window()
--   if not output_winid or not vim.api.nvim_win_is_valid(output_winid) then
--     local current_win = vim.api.nvim_get_current_win()
--     vim.cmd('botright split')
--     output_winid = vim.api.nvim_get_current_win()
--     vim.api.nvim_win_set_buf(output_winid, ensure_output_buffer())
--     vim.api.nvim_win_set_height(output_winid, 20)
--     vim.wo[output_winid].wrap = false
--     vim.wo[output_winid].number = false
--     vim.wo[output_winid].relativenumber = false
--     vim.api.nvim_set_current_win(current_win)
--   end
--   return output_winid
-- end
--
-- -- Helper function to write to output buffer
-- local function write_output(lines, clear)
--   if clear then
--     vim.api.nvim_buf_set_lines(ensure_output_buffer(), 0, -1, false, {})
--   end
--   if type(lines) == "string" then
--     lines = { lines }
--   end
--   local buf = ensure_output_buffer()
--   local line_count = vim.api.nvim_buf_line_count(buf)
--   vim.api.nvim_buf_set_lines(buf, line_count, line_count, false, lines)
--
--   local win = ensure_output_window()
--   vim.api.nvim_win_set_cursor(win, { line_count + #lines, 0 })
--   vim.cmd('redraw')
-- end
--
-- local function ensure_hcl_parser()
--   local ok = pcall(vim.treesitter.get_parser, 0, "hcl")
--   if not ok then
--     write_output("HCL parser not found. Please ensure tree-sitter HCL is installed.")
--     return false
--   end
--   return true
-- end
--
-- local function create_temp_dir()
--   local handle = io.popen('mktemp -d')
--   if handle then
--     local temp_dir = handle:read('*l')
--     handle:close()
--     return temp_dir
--   end
--   return nil
-- end
--
-- local function cleanup(temp_dir)
--   if temp_dir then
--     vim.fn.system({ 'rm', '-rf', temp_dir })
--     if vim.v.shell_error == 0 then
--       write_output({ "", "Cleaning up files succeeded" })
--     else
--       write_output({ "", "Cleaning up files failed" })
--     end
--   end
-- end
--
-- -- Function to handle terraform initialization and schema fetching
-- function M.fetch_schema(callback)
--   write_output({}, true)
--
--   local temp_dir = create_temp_dir()
--   if not temp_dir then
--     write_output("Failed to create temporary directory")
--     return
--   end
--
--   local config_file = temp_dir .. "/main.tf"
--   local f = io.open(config_file, "w")
--   if not f then
--     cleanup(temp_dir)
--     write_output("Failed to create temporary configuration")
--     return
--   end
--   f:write([[
-- terraform {
--   required_providers {
--     azurerm = {
--       source = "hashicorp/azurerm"
--     }
--   }
-- }
-- ]])
--   f:close()
--
--   -- Run terraform init
--   local init_job = vim.fn.jobstart({ 'terraform', 'init' }, {
--     cwd = temp_dir,
--     on_stdout = function(_, data)
--       if data and #data > 0 then
--         write_output(vim.tbl_filter(function(line)
--           return line and line ~= ""
--         end, data))
--       end
--     end,
--     on_stderr = function(_, data)
--       if data and #data > 0 then
--         write_output(vim.tbl_map(function(line)
--           return "Error: " .. line
--         end, vim.tbl_filter(function(line)
--           return line and line ~= ""
--         end, data)))
--       end
--     end,
--     on_exit = function(_, exit_code)
--       if exit_code ~= 0 then
--         write_output("Failed to initialize Terraform")
--         cleanup(temp_dir)
--         return
--       end
--
--       -- Fetch schema after successful init
--       vim.fn.jobstart({ 'terraform', 'providers', 'schema', '-json' }, {
--         cwd = temp_dir,
--         stdout_buffered = true,
--         on_stdout = function(_, data)
--           if data and #data > 0 then
--             local json_str = table.concat(data, '\n')
--             local success, decoded = pcall(vim.json.decode, json_str)
--             if success then
--               schema_cache = decoded.provider_schemas["registry.terraform.io/hashicorp/azurerm"] or {}
--               if callback then
--                 write_output({ "" })
--                 callback()
--               end
--             else
--               write_output("Failed to parse schema JSON")
--             end
--           end
--         end,
--         on_stderr = function(_, data)
--           if data and #data > 0 then
--             write_output(vim.tbl_filter(function(line)
--               return line and line ~= ""
--             end, data))
--           end
--         end,
--         on_exit = function(_, schema_exit_code)
--           if schema_exit_code ~= 0 then
--             write_output("Failed to fetch schema")
--           end
--           cleanup(temp_dir)
--         end
--       })
--     end
--   })
--
--   if init_job == 0 then
--     write_output("Failed to start Terraform initialization")
--     cleanup(temp_dir)
--   end
-- end
--
-- -- Parse current buffer using treesitter
-- function M.parse_current_buffer()
--   if not ensure_hcl_parser() then
--     return {}
--   end
--
--   local bufnr = vim.api.nvim_get_current_buf()
--   local parser = vim.treesitter.get_parser(bufnr, "hcl")
--   local tree = parser:parse()[1]
--   if not tree then return {} end
--   local root = tree:root()
--   local resources = {}
--
--   -- Query to find resource blocks
--   local query = vim.treesitter.query.parse("hcl", [[
--     (block
--       (identifier) @block_type
--       (string_lit) @resource_type
--       (string_lit) @resource_name
--       (body) @body
--     )
--   ]])
--
--   for _, captures, _ in query:iter_matches(root, bufnr) do
--     if not captures[1] or not captures[2] or not captures[4] then
--       goto continue
--     end
--     local block_type = vim.treesitter.get_node_text(captures[1], bufnr)
--     if block_type == "resource" then
--       local resource_type = vim.treesitter.get_node_text(captures[2], bufnr):gsub('"', '')
--       local body_node = captures[4]
--       local resource = {
--         type = resource_type,
--         properties = {},
--         blocks = {},
--         dynamic_blocks = {}
--       }
--
--       -- Recursively parse the body of a block
--       local function parse_block_contents(node)
--         local block_data = {
--           properties = {},
--           blocks = {},
--           dynamic_blocks = {}
--         }
--
--         -- 1. Find normal attributes
--         local attr_query = vim.treesitter.query.parse("hcl", "(attribute (identifier) @name)")
--         for _, attr_match in attr_query:iter_matches(node, bufnr) do
--           local name = vim.treesitter.get_node_text(attr_match[1], bufnr)
--           block_data.properties[name] = true
--         end
--
--         -- 2. Find regular (non-dynamic) blocks
--         local block_query = vim.treesitter.query.parse("hcl", "(block (identifier) @name (body) @body)")
--         for _, block_match in block_query:iter_matches(node, bufnr) do
--           local name = vim.treesitter.get_node_text(block_match[1], bufnr)
--           local body = block_match[2]
--           if name ~= "dynamic" then
--             block_data.blocks[name] = parse_block_contents(body)
--           end
--         end
--
--         -- 3. Find dynamic blocks: dynamic "something" { ... }
--         local dynamic_query = vim.treesitter.query.parse("hcl", [[
--           (block
--             (identifier) @type
--             (string_lit) @name
--             (body) @body
--             (#eq? @type "dynamic"))
--         ]])
--         for _, dyn_match in dynamic_query:iter_matches(node, bufnr) do
--           local dyn_name = vim.treesitter.get_node_text(dyn_match[2], bufnr):gsub('"', '')
--           local dyn_body = dyn_match[3]
--
--           -- Look for a "content" block inside this dynamic block
--           local content_query = vim.treesitter.query.parse("hcl", [[
--             (block
--               (identifier) @name
--               (body) @body
--               (#eq? @name "content"))
--           ]])
--           local found_content = false
--           for _, content_match in content_query:iter_matches(dyn_body, bufnr) do
--             found_content = true
--             local content_body = content_match[2]
--
--             ------------------------------------------------------------------
--             -- Instead of storing parse_block_contents(content_body) as a
--             -- *nested* sub-block, we MERGE it back into this dynamic block's
--             -- properties/blocks. Because from Terraform's perspective,
--             -- "content" is the actual body of the dynamic block.
--             ------------------------------------------------------------------
--             local content_data = parse_block_contents(content_body)
--
--             -- Merge "content" attributes into the dynamic block's top-level
--             for k, v in pairs(content_data.properties) do
--               block_data.dynamic_blocks[dyn_name] = block_data.dynamic_blocks[dyn_name] or {
--                 properties = {},
--                 blocks = {},
--                 dynamic_blocks = {}
--               }
--               block_data.dynamic_blocks[dyn_name].properties[k] = v
--             end
--             for k, v in pairs(content_data.blocks) do
--               block_data.dynamic_blocks[dyn_name] = block_data.dynamic_blocks[dyn_name] or {
--                 properties = {},
--                 blocks = {},
--                 dynamic_blocks = {}
--               }
--               block_data.dynamic_blocks[dyn_name].blocks[k] = v
--             end
--             for k, v in pairs(content_data.dynamic_blocks) do
--               block_data.dynamic_blocks[dyn_name] = block_data.dynamic_blocks[dyn_name] or {
--                 properties = {},
--                 blocks = {},
--                 dynamic_blocks = {}
--               }
--               block_data.dynamic_blocks[dyn_name].dynamic_blocks[k] = v
--             end
--           end
--
--           -- If there's no "content" block at all, parse the entire dyn_body
--           -- so that we still pick up any attributes at the dynamic level
--           if not found_content then
--             block_data.dynamic_blocks[dyn_name] = parse_block_contents(dyn_body)
--           end
--         end
--
--         return block_data
--       end
--
--       local parsed_data = parse_block_contents(body_node)
--       resource.properties = parsed_data.properties
--       resource.blocks = parsed_data.blocks
--       resource.dynamic_blocks = parsed_data.dynamic_blocks
--
--       table.insert(resources, resource)
--     end
--     ::continue::
--   end
--   return resources
-- end
--
-- -- Validate resources and print results
-- function M.validate_resources()
--   write_output({}, true) -- Clear previous output
--
--   -- Always fetch fresh schema to ensure we have latest
--   M.fetch_schema(function()
--     local resources = M.parse_current_buffer()
--     for _, resource in ipairs(resources) do
--       local schema = schema_cache.resource_schemas[resource.type]
--       if schema and schema.block then
--         local function validate_block_attributes(block_schema, block_data, block_path)
--           -- 1. Check attributes
--           if block_schema.attributes then
--             for name, attr in pairs(block_schema.attributes) do
--               if not attr.computed and not block_data.properties[name] then
--                 if attr.required then
--                   write_output(string.format("%s missing required property %s in %s",
--                     resource.type, name, block_path))
--                 else
--                   write_output(string.format("%s missing optional property %s in %s",
--                     resource.type, name, block_path))
--                 end
--               end
--             end
--           end
--
--           -- Check nested blocks
--           if block_schema.block_types then
--             for name, block_type in pairs(block_schema.block_types) do
--               if name == "timeouts" then goto continue end
--               local block = block_data.blocks[name]
--               local dynamic_block = block_data.dynamic_blocks[name]
--
--               if block then
--                 if block_type.block then
--                   validate_block_attributes(block_type.block, block, block_path .. "." .. name)
--                 end
--               elseif dynamic_block then
--                 -- Remove/disable the bail-out for multiple dynamic blocks
--                 -- so nested blocks are always validated:
--                 -- if count_dynamic_blocks(resource) > 1 then goto continue end
--
--                 if block_type.block then
--                   validate_block_attributes(
--                     block_type.block, dynamic_block, block_path .. ".dynamic." .. name
--                   )
--                 end
--               else
--                 if block_type.min_items and block_type.min_items > 0 then
--                   write_output(string.format("%s missing required block %s in %s",
--                     resource.type, name, block_path))
--                 else
--                   write_output(string.format("%s missing optional block %s in %s",
--                     resource.type, name, block_path))
--                 end
--               end
--               ::continue::
--             end
--           end
--         end
--
--         validate_block_attributes(schema.block, resource, "root")
--       end
--     end
--   end)
-- end
--
-- function M.setup(opts)
--   opts = opts or {}
--   vim.api.nvim_create_user_command("TerraformValidateSchema", M.validate_resources, {})
-- end
--
-- return M
--   vim.api.nvim_create_user_command("TerraformValidateSchema", M.validate_resources, {})
-- end
--
-- return M
