local M = {}
-- Cache for provider schemas
local schema_cache = {}
local output_bufnr = nil
local output_winid = nil

-- Function to create or get output buffer
local function ensure_output_buffer()
  if not output_bufnr or not vim.api.nvim_buf_is_valid(output_bufnr) then
    output_bufnr = vim.api.nvim_create_buf(false, true)
    vim.bo[output_bufnr].buftype = 'nofile'
    vim.bo[output_bufnr].bufhidden = 'hide'
    vim.bo[output_bufnr].swapfile = false
    vim.api.nvim_buf_set_name(output_bufnr, 'Terraform Schema Validation')
  end
  return output_bufnr
end

-- Function to ensure output window is visible
local function ensure_output_window()
  if not output_winid or not vim.api.nvim_win_is_valid(output_winid) then
    -- Save current window
    local current_win = vim.api.nvim_get_current_win()

    -- Create split and set options
    vim.cmd('botright split')
    output_winid = vim.api.nvim_get_current_win()
    vim.api.nvim_win_set_buf(output_winid, ensure_output_buffer())
    vim.api.nvim_win_set_height(output_winid, 20)

    -- Set window options
    vim.wo[output_winid].wrap = false
    vim.wo[output_winid].number = false
    vim.wo[output_winid].relativenumber = false

    -- Return to original window
    vim.api.nvim_set_current_win(current_win)
  end
  return output_winid
end

-- Helper function to write to output buffer
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

  -- Ensure window is visible and scroll to bottom
  local win = ensure_output_window()
  vim.api.nvim_win_set_cursor(win, { line_count + #lines, 0 })
  vim.cmd('redraw')
end

-- Check if HCL parser is available
local function ensure_hcl_parser()
  local ok = pcall(vim.treesitter.get_parser, 0, "hcl")
  if not ok then
    write_output("HCL parser not found. Please ensure tree-sitter HCL is installed.")
    return false
  end
  return true
end

-- Helper function to create temporary directory
local function create_temp_dir()
  local handle = io.popen('mktemp -d')
  if handle then
    local temp_dir = handle:read('*l')
    handle:close()
    return temp_dir
  end
  return nil
end

-- Helper function to cleanup
local function cleanup(temp_dir)
  if temp_dir then
    vim.fn.system({ 'rm', '-rf', temp_dir })
    if vim.v.shell_error == 0 then
      write_output({ "", "Cleaning up files succeeded" })
    else
      write_output({ "", "Cleaning up files failed" })
    end
  end
end

-- Function to handle terraform initialization and schema fetching
function M.fetch_schema(callback)
  -- Clear output and show window
  write_output({}, true)

  local temp_dir = create_temp_dir()
  if not temp_dir then
    write_output("Failed to create temporary directory")
    return
  end

  -- Create minimal terraform configuration
  local config_file = temp_dir .. "/main.tf"
  local f = io.open(config_file, "w")
  if not f then
    cleanup(temp_dir)
    write_output("Failed to create temporary configuration")
    return
  end
  f:write('terraform {\n  required_providers {\n    azurerm = {\n      source = "hashicorp/azurerm"\n    }\n  }\n}\n')
  f:close()

  -- Run terraform init
  local init_job = vim.fn.jobstart({ 'terraform', 'init' }, {
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

      -- Fetch schema after successful init
      vim.fn.jobstart({ 'terraform', 'providers', 'schema', '-json' }, {
        cwd = temp_dir,
        stdout_buffered = true,
        on_stdout = function(_, data)
          if data and #data > 0 then
            local json_str = table.concat(data, '\n')
            local success, decoded = pcall(vim.json.decode, json_str)
            if success then
              schema_cache = decoded.provider_schemas["registry.terraform.io/hashicorp/azurerm"] or {}
              if callback then
                write_output({ "" })
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

-- Recursive function to validate nested blocks and their attributes
local function validate_nested_blocks(resource_type, block_schema, block_data, block_path, output_fn)
  -- Check attributes
  if block_schema.attributes then
    for name, attr in pairs(block_schema.attributes) do
      if not attr.computed and not block_data.properties[name] then
        if attr.required then
          output_fn(string.format("%s missing required property %s in %s",
            resource_type, name, block_path))
        else
          output_fn(string.format("%s missing optional property %s in %s",
            resource_type, name, block_path))
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
        -- Validate nested block
        if block_type.block then
          validate_nested_blocks(resource_type, block_type.block, block, block_path .. "." .. name, write_output)
        end
      elseif dynamic_block then
        -- Validate dynamic block content
        if block_type.block then
          -- Check content block attributes
          validate_nested_blocks(resource_type, block_type.block, dynamic_block, block_path .. ".dynamic." .. name,
            write_output)

          -- Check for nested blocks inside dynamic block content
          if block_type.block.block_types then
            for nested_name, nested_block_type in pairs(block_type.block.block_types) do
              local nested_block = dynamic_block.blocks[nested_name]
              local nested_dynamic = dynamic_block.dynamic_blocks[nested_name]

              if nested_block then
                -- Validate nested block within dynamic block
                validate_nested_blocks(resource_type, nested_block_type.block, nested_block,
                  block_path .. ".dynamic." .. name .. "." .. nested_name, write_output)
              elseif nested_dynamic then
                -- Validate nested dynamic block
                validate_nested_blocks(resource_type, nested_block_type.block, nested_dynamic,
                  block_path .. ".dynamic." .. name .. ".dynamic." .. nested_name, write_output)
              elseif nested_block_type.min_items and nested_block_type.min_items > 0 then
                output_fn(string.format("%s missing required block %s in %s",
                  resource_type, nested_name, block_path .. ".dynamic." .. name))
              else
                output_fn(string.format("%s missing optional block %s in %s",
                  resource_type, nested_name, block_path .. ".dynamic." .. name))
              end
            end
          end
        end
      elseif block_type.min_items and block_type.min_items > 0 then
        output_fn(string.format("%s missing required block %s in %s",
          resource_type, name, block_path))
      else
        output_fn(string.format("%s missing optional block %s in %s",
          resource_type, name, block_path))
      end
      ::continue::
    end
  end
end

-- Validate resources and print results
function M.validate_resources()
  write_output({}, true)

  M.fetch_schema(function()
    local resources = M.parse_current_buffer()
    for _, resource in ipairs(resources) do
      local schema = schema_cache.resource_schemas[resource.type]
      if schema and schema.block then
        validate_nested_blocks(resource.type, schema.block, resource, "root", write_output)
      end
    end
  end)
end

function M.setup(opts)
  opts = opts or {}
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
--     -- Save current window
--     local current_win = vim.api.nvim_get_current_win()
--
--     -- Create split and set options
--     vim.cmd('botright split')
--     output_winid = vim.api.nvim_get_current_win()
--     vim.api.nvim_win_set_buf(output_winid, ensure_output_buffer())
--     vim.api.nvim_win_set_height(output_winid, 20)
--
--     -- Set window options
--     vim.wo[output_winid].wrap = false
--     vim.wo[output_winid].number = false
--     vim.wo[output_winid].relativenumber = false
--
--     -- Return to original window
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
--
--   if type(lines) == "string" then
--     lines = { lines }
--   end
--
--   local buf = ensure_output_buffer()
--   local line_count = vim.api.nvim_buf_line_count(buf)
--   vim.api.nvim_buf_set_lines(buf, line_count, line_count, false, lines)
--
--   -- Ensure window is visible and scroll to bottom
--   local win = ensure_output_window()
--   vim.api.nvim_win_set_cursor(win, { line_count + #lines, 0 })
--   vim.cmd('redraw')
-- end
--
-- -- Check if HCL parser is available
-- local function ensure_hcl_parser()
--   local ok = pcall(vim.treesitter.get_parser, 0, "hcl")
--   if not ok then
--     write_output("HCL parser not found. Please ensure tree-sitter HCL is installed.")
--     return false
--   end
--   return true
-- end
--
-- -- Helper function to create temporary directory
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
-- -- Helper function to cleanup
-- local function cleanup(temp_dir)
--   if temp_dir then
--     vim.fn.system({ 'rm', '-rf', temp_dir })
--     if vim.v.shell_error == 0 then
--       write_output({ "", "Cleaning up files succeeded" }) -- Add blank line before cleanup status
--     else
--       write_output({ "", "Cleaning up files failed" })
--     end
--   end
-- end
--
-- -- Function to handle terraform initialization and schema fetching
-- function M.fetch_schema(callback)
--   -- Clear output and show window
--   write_output({}, true)
--
--   local temp_dir = create_temp_dir()
--   if not temp_dir then
--     write_output("Failed to create temporary directory")
--     return
--   end
--
--   -- Create minimal terraform configuration
--   local config_file = temp_dir .. "/main.tf"
--   local f = io.open(config_file, "w")
--   if not f then
--     cleanup(temp_dir)
--     write_output("Failed to create temporary configuration")
--     return
--   end
--   f:write('terraform {\n  required_providers {\n    azurerm = {\n      source = "hashicorp/azurerm"\n    }\n  }\n}\n')
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
--                 write_output({ "" }) -- Add blank line between init output and validation results
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
--       local function parse_block_contents(node)
--         local block_data = {
--           properties = {},
--           blocks = {},
--           dynamic_blocks = {}
--         }
--         -- Query for attributes
--         local attr_query = vim.treesitter.query.parse("hcl", "(attribute (identifier) @name)")
--         for _, attr_match in attr_query:iter_matches(node, bufnr) do
--           local name = vim.treesitter.get_node_text(attr_match[1], bufnr)
--           block_data.properties[name] = true
--         end
--         -- Query for regular blocks
--         local block_query = vim.treesitter.query.parse("hcl", "(block (identifier) @name (body) @body)")
--         for _, block_match in block_query:iter_matches(node, bufnr) do
--           local name = vim.treesitter.get_node_text(block_match[1], bufnr)
--           local body = block_match[2]
--           if name ~= "dynamic" then
--             -- Parse the block's contents recursively
--             block_data.blocks[name] = parse_block_contents(body)
--           end
--         end
--         -- Query for dynamic blocks
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
--           -- Look for content block inside dynamic block
--           local content_query = vim.treesitter.query.parse("hcl",
--             "(block (identifier) @name (body) @body (#eq? @name \"content\"))")
--           for _, content_match in content_query:iter_matches(dyn_body, bufnr) do
--             local content_body = content_match[2]
--             -- Parse the content block's properties and nested blocks
--             block_data.dynamic_blocks[dyn_name] = parse_block_contents(content_body)
--           end
--         end
--         return block_data
--       end
--
--       -- Parse the resource body
--       local parsed_data = parse_block_contents(body_node)
--       resource.properties = parsed_data.properties
--       resource.blocks = parsed_data.blocks
--       resource.dynamic_blocks = parsed_data.dynamic_blocks
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
--           -- Check attributes
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
--           -- Check nested blocks
--           if block_schema.block_types then
--             for name, block_type in pairs(block_schema.block_types) do
--               if name == "timeouts" then goto continue end
--               local block = block_data.blocks[name]
--               local dynamic_block = block_data.dynamic_blocks[name]
--               if block then
--                 -- Validate nested block attributes
--                 if block_type.block and block_type.block.attributes then
--                   validate_block_attributes(block_type.block, block, block_path .. "." .. name)
--                 end
--               elseif dynamic_block then
--                 local function count_dynamic_blocks(current_block)
--                   local count = 0
--                   for _, _ in pairs(current_block.dynamic_blocks) do
--                     count = count + 1
--                   end
--                   for _, nested_block in pairs(current_block.blocks) do
--                     count = count + count_dynamic_blocks(nested_block)
--                   end
--                   for _, nested_dynamic in pairs(current_block.dynamic_blocks) do
--                     count = count + count_dynamic_blocks(nested_dynamic)
--                   end
--                   return count
--                 end
--
--                 -- Skip validation if resource has multiple dynamic blocks
--                 -- FIX: nested dynamic blocks checks
--
--                 if count_dynamic_blocks(resource) > 1 then
--                   goto continue
--                 end
--                 -- Validate dynamic block content attributes
--                 if block_type.block and block_type.block.attributes then
--                   -- Check properties in dynamic blocks
--                   for prop_name, attr in pairs(block_type.block.attributes) do
--                     if not attr.computed and not dynamic_block.properties[prop_name] then
--                       if attr.required then
--                         write_output(string.format("%s missing required property %s in %s",
--                           resource.type, prop_name, block_path .. ".dynamic." .. name))
--                       else
--                         write_output(string.format("%s missing optional property %s in %s",
--                           resource.type, prop_name, block_path .. ".dynamic." .. name))
--                       end
--                     end
--                   end
--                   -- Also check for nested blocks inside dynamic blocks
--                   if block_type.block.block_types then
--                     for nested_name, nested_block_type in pairs(block_type.block.block_types) do
--                       if not dynamic_block.blocks[nested_name] and not dynamic_block.dynamic_blocks[nested_name] then
--                         if nested_block_type.min_items and nested_block_type.min_items > 0 then
--                           write_output(string.format("%s missing required block %s in %s",
--                             resource.type, nested_name, block_path .. ".dynamic." .. name))
--                         else
--                           write_output(string.format("%s missing optional block %s in %s",
--                             resource.type, nested_name, block_path .. ".dynamic." .. name))
--                         end
--                       end
--                     end
--                   end
--                 end
--                 ::continue::
--               elseif block_type.min_items and block_type.min_items > 0 then
--                 write_output(string.format("%s missing required block %s in %s",
--                   resource.type, name, block_path))
--               else
--                 write_output(string.format("%s missing optional block %s in %s",
--                   resource.type, name, block_path))
--               end
--               ::continue::
--             end
--           end
--         end
--         -- Start validation from the root
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
