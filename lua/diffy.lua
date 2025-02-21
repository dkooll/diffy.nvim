local M = {}

-- Cache for provider schemas
local schema_cache = {}
-- Keep track of the buffer and window used for output
local output_bufnr = nil
local output_winid = nil

-- ------------------------------------------------------------------------
-- Utility: Create or get the "output" buffer
-- ------------------------------------------------------------------------
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

-- ------------------------------------------------------------------------
-- Utility: Create or get the "output" window
-- ------------------------------------------------------------------------
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
    -- Example of customizing the highlight
    vim.cmd("hi MyOutputHighlight guifg=#ffffff guibg=NONE")
    vim.wo[output_winid].winhl = "Normal:MyOutputHighlight"
    vim.api.nvim_set_current_win(current_win)
  end
  return output_winid
end

-- ------------------------------------------------------------------------
-- Utility: Write lines to our output window
-- ------------------------------------------------------------------------
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

-- ------------------------------------------------------------------------
-- Utility: Create a temporary directory (mktemp -d)
-- ------------------------------------------------------------------------
local function create_temp_dir()
  local handle = io.popen("mktemp -d")
  if handle then
    local temp_dir = handle:read("*l")
    handle:close()
    return temp_dir
  end
  return nil
end

-- ------------------------------------------------------------------------
-- Utility: Clean up that temporary directory
-- ------------------------------------------------------------------------
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

-- ------------------------------------------------------------------------
-- Utility: Check for HCL parser installed
-- ------------------------------------------------------------------------
local function ensure_hcl_parser()
  local ok = pcall(vim.treesitter.get_parser, 0, "hcl")
  if not ok then
    write_output("HCL parser not found. Please ensure tree-sitter HCL is installed.")
    return false
  end
  return true
end

-- ------------------------------------------------------------------------
-- 1) Parse "ignore_changes" arrays
--   We only attempt this if filetype is hcl/terraform/tf
-- ------------------------------------------------------------------------
local function parse_ignore_changes_array(node, bufnr)
  local ft = vim.bo[bufnr].filetype
  if ft ~= "hcl" and ft ~= "terraform" and ft ~= "tf" then
    return {}
  end

  local results = {}
  -- This bracket query looks for attributes named "ignore_changes"
  -- that contain a tuple of items
  local bracket_query = vim.treesitter.query.parse("hcl", [=[
    (attribute
      (identifier) @attr_name
      (expression
        (collection_value
          (tuple
            ((expression) @item)+)))
    )
  ]=])

  for _, match, _ in bracket_query:iter_matches(node, bufnr) do
    local attr_node = match[1]
    local attr_name = vim.treesitter.get_node_text(attr_node, bufnr)
    if attr_name == "ignore_changes" then
      for i = 2, #match do
        local item_node = match[i]
        local txt = vim.treesitter.get_node_text(item_node, bufnr)
        txt = txt:gsub('^"(.*)"$', "%1") -- strip quotes
        table.insert(results, txt)
      end
    end
  end

  return results
end

-- ------------------------------------------------------------------------
-- 2) Parse block contents (properties, blocks, dynamic_blocks, etc.)
--   We only attempt this if filetype is hcl/terraform/tf
-- ------------------------------------------------------------------------
local function parse_block_contents(node, bufnr)
  local ft = vim.bo[bufnr].filetype
  if ft ~= "hcl" and ft ~= "terraform" and ft ~= "tf" then
    return {
      properties = {},
      blocks = {},
      dynamic_blocks = {},
      ignore_changes = {},
    }
  end

  local block_data = {
    properties = {},
    blocks = {},
    dynamic_blocks = {},
    ignore_changes = {},
  }

  -- Query for all attributes, store them as "properties"
  local attr_query = vim.treesitter.query.parse("hcl", [=[
    (attribute (identifier) @name)
  ]=])

  for _, match, _ in attr_query:iter_matches(node, bufnr) do
    local name_node = match[1]
    local name_txt = vim.treesitter.get_node_text(name_node, bufnr)
    block_data.properties[name_txt] = true
  end

  -- Query for block { ... } definitions
  local block_query = vim.treesitter.query.parse("hcl", [=[
    (block
      (identifier) @name
      (body) @body)
  ]=])

  for _, bmatch, _ in block_query:iter_matches(node, bufnr) do
    local name_node = bmatch[1]
    local body_node = bmatch[2]
    local name_txt = vim.treesitter.get_node_text(name_node, bufnr)

    if name_txt == "dynamic" then
      -- We'll handle dynamic blocks with a different query
      goto continue_block
    end

    if name_txt == "lifecycle" then
      -- if there's an "ignore_changes" attribute in the lifecycle block
      local lifecycle_data = parse_block_contents(body_node, bufnr)
      if lifecycle_data.properties["ignore_changes"] then
        local arr = parse_ignore_changes_array(body_node, bufnr)
        vim.list_extend(block_data.ignore_changes, arr)
      end
      goto continue_block
    end

    block_data.blocks[name_txt] = parse_block_contents(body_node, bufnr)

    ::continue_block::
  end

  -- Query for "dynamic" blocks
  local dynamic_query = vim.treesitter.query.parse("hcl", [=[
    (block
      (identifier) @dyn_kw
      (string_lit) @dyn_name
      (body) @dyn_body
      (#eq? @dyn_kw "dynamic"))
  ]=])

  for _, dmatch, _ in dynamic_query:iter_matches(node, bufnr) do
    local dyn_name_node = dmatch[2]
    local dyn_body_node = dmatch[3]
    local dyn_name_txt = vim.treesitter.get_node_text(dyn_name_node, bufnr):gsub('"', "")

    -- inside a "dynamic" block, there can be a sub-block called "content"
    local content_query = vim.treesitter.query.parse("hcl", [=[
      (block
        (identifier) @content_kw
        (body) @content_body
        (#eq? @content_kw "content"))
    ]=])

    local found_content = false
    for _, cmatch, _ in content_query:iter_matches(dyn_body_node, bufnr) do
      found_content = true
      local content_body_node = cmatch[2]
      local content_data = parse_block_contents(content_body_node, bufnr)

      block_data.dynamic_blocks[dyn_name_txt] = block_data.dynamic_blocks[dyn_name_txt] or {
        properties = {},
        blocks = {},
        dynamic_blocks = {},
        ignore_changes = {},
      }

      -- Merge content_data into dynamic_blocks[dyn_name_txt]
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
      block_data.dynamic_blocks[dyn_name_txt] = parse_block_contents(dyn_body_node, bufnr)
    end
  end

  return block_data
end

-- ------------------------------------------------------------------------
-- 3) Parse the current buffer for resource blocks
--   We only do it if the current file is recognized as HCL/TF.
-- ------------------------------------------------------------------------
function M.parse_current_buffer()
  local bufnr = vim.api.nvim_get_current_buf()
  local ft = vim.bo[bufnr].filetype

  -- If not an HCL/TF file, bail out
  if ft ~= "hcl" and ft ~= "terraform" and ft ~= "tf" then
    write_output("Not an HCL/TF file. Skipping parse.")
    return {}
  end

  if not ensure_hcl_parser() then
    return {}
  end

  local parser = vim.treesitter.get_parser(bufnr, "hcl")
  local tree = parser:parse()[1]
  if not tree then
    return {}
  end

  local root = tree:root()
  local resources = {}

  local resource_query = vim.treesitter.query.parse("hcl", [=[
    (block
      (identifier) @block_type
      (string_lit) @resource_type
      (string_lit) @resource_name
      (body) @body)
  ]=])

  for _, captures, _ in resource_query:iter_matches(root, bufnr) do
    local block_type_node = captures[1]
    local resource_type_node = captures[2]
    local body_node         = captures[4]

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

-- ------------------------------------------------------------------------
-- 4) Fetch the provider schema (terraform init + terraform providers schema)
-- ------------------------------------------------------------------------
function M.fetch_schema(callback)
  write_output({}, true)
  local temp_dir = create_temp_dir()
  if not temp_dir then
    write_output("Failed to create temporary directory")
    return
  end

  local current_dir = vim.fn.getcwd()
  local local_tf = current_dir .. "/terraform.tf"
  if vim.fn.filereadable(local_tf) == 0 then
    write_output("Could not find terraform.tf in " .. current_dir)
    cleanup(temp_dir)
    return
  end

  vim.fn.system({ "cp", local_tf, temp_dir .. "/terraform.tf" })
  if vim.v.shell_error ~= 0 then
    write_output("Failed to copy terraform.tf to temp directory.")
    cleanup(temp_dir)
    return
  end

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

      vim.fn.jobstart({ "terraform", "providers", "schema", "-json" }, {
        cwd = temp_dir,
        stdout_buffered = true,
        on_stdout = function(_, data)
          if data and #data > 0 then
            local json_str = table.concat(data, "\n")
            local success, decoded = pcall(vim.json.decode, json_str)
            if success and decoded and decoded.provider_schemas then
              schema_cache = decoded.provider_schemas
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

-- ------------------------------------------------------------------------
-- 5) Validate the parsed data against the fetched provider schema
-- ------------------------------------------------------------------------
local function validate_block_attributes(resource_type, block_schema, block_data, block_path, inherited_ignores, unique_messages)
  -- inherited_ignores is a list of attribute/block names to skip
  inherited_ignores = inherited_ignores or {}
  local combined_ignores = vim.deepcopy(inherited_ignores)
  vim.list_extend(combined_ignores, block_data.ignore_changes or {})

  if block_schema.attributes then
    for attr_name, attr_info in pairs(block_schema.attributes) do
      if vim.tbl_contains(combined_ignores, attr_name) then
        goto continue_attr
      end

      -- If the attribute is required but not found
      if not attr_info.computed and not block_data.properties[attr_name] then
        local msg = string.format(
          "%s missing %s property '%s' in path %s",
          resource_type,
          attr_info.required and "required" or "optional",
          attr_name,
          block_path
        )
        unique_messages[msg] = true
      end
      ::continue_attr::
    end
  end

  if block_schema.block_types then
    for block_name, btype_schema in pairs(block_schema.block_types) do
      -- skip "timeouts" block, for example
      if block_name == "timeouts" then
        goto continue_block
      end
      if vim.tbl_contains(combined_ignores, block_name) then
        goto continue_block
      end

      local sub_block = block_data.blocks[block_name]
      local dyn_block = block_data.dynamic_blocks[block_name]
      if sub_block then
        validate_block_attributes(
          resource_type,
          btype_schema.block,
          sub_block,
          block_path .. "." .. block_name,
          combined_ignores,
          unique_messages
        )
      elseif dyn_block then
        validate_block_attributes(
          resource_type,
          btype_schema.block,
          dyn_block,
          block_path .. ".dynamic." .. block_name,
          combined_ignores,
          unique_messages
        )
      else
        local is_required = (btype_schema.min_items and btype_schema.min_items > 0)
        local msg = string.format(
          "%s missing %s block '%s' in path %s",
          resource_type,
          is_required and "required" or "optional",
          block_name,
          block_path
        )
        unique_messages[msg] = true
      end

      ::continue_block::
    end
  end
end

function M.validate_resources()
  write_output({}, true)

  -- Fetch the Terraform schema and then validate the current buffer
  M.fetch_schema(function()
    local resources = M.parse_current_buffer()
    local used_provider_keys = {}
    local unique_messages = {}

    for _, resource in ipairs(resources) do
      local matching_provider_block = nil
      -- see if the resource type appears in any provider
      for provider_key, provider_data in pairs(schema_cache) do
        local r_schemas = provider_data.resource_schemas
        if r_schemas and r_schemas[resource.type] then
          matching_provider_block = r_schemas[resource.type].block
          used_provider_keys[provider_key] = true
          break
        end
      end

      if not matching_provider_block then
        unique_messages["No provider schema found for resource: " .. resource.type] = true
      else
        validate_block_attributes(
          resource.type,
          matching_provider_block,
          resource,
          "root",
          resource.ignore_changes,
          unique_messages
        )
      end
    end

    -- Warn if there are declared providers not used by any resources
    for provider_key, _ in pairs(schema_cache) do
      if not used_provider_keys[provider_key] then
        unique_messages["Provider declared but not used by any resource: " .. provider_key] = true
      end
    end

    local messages = {}
    for msg in pairs(unique_messages) do
      table.insert(messages, msg)
    end
    table.sort(messages)
    write_output(messages)
  end)
end

-- ------------------------------------------------------------------------
-- 6) Setup: define user command
-- ------------------------------------------------------------------------
function M.setup()
  vim.api.nvim_create_user_command("TerraformValidateSchema", M.validate_resources, {})
end

return M
