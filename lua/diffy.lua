local M = {}

-- Cache for provider schemas (for root)
local schema_cache = {}
local output_bufnr = nil
local output_winid = nil

------------------------------------------------------------
-- OUTPUT BUFFER & WINDOW
------------------------------------------------------------
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
    vim.cmd("hi MyOutputHighlight guifg=#ffffff guibg=NONE")
    vim.wo[output_winid].winhl = "Normal:MyOutputHighlight"
    vim.api.nvim_set_current_win(current_win)
  end
  return output_winid
end

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

------------------------------------------------------------
-- TEMP DIR & CLEANUP
------------------------------------------------------------
local function create_temp_dir()
  local handle = io.popen("mktemp -d")
  if handle then
    local temp_dir = handle:read("*l")
    handle:close()
    return temp_dir
  end
  return nil
end

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

------------------------------------------------------------
-- TREESITTER SUPPORT
------------------------------------------------------------
local function ensure_hcl_parser()
  local ok = pcall(vim.treesitter.get_parser, 0, "hcl")
  if not ok then
    write_output("HCL parser not found. Please ensure tree-sitter HCL is installed.")
    return false
  end
  return true
end

local function parse_ignore_changes_array(node, bufnr)
  local results = {}
  local bracket_query = vim.treesitter.query.parse("hcl", [=[
    (attribute
      (identifier) @attr_name
      (expression
        (collection_value
          (tuple ((expression) @item)+)))
    )
  ]=])
  for _, match, _ in bracket_query:iter_matches(node, bufnr) do
    local attr_node = match[1]
    local attr_name = vim.treesitter.get_node_text(attr_node, bufnr)
    if attr_name == "ignore_changes" then
      for i = 2, #match do
        local item_node = match[i]
        local txt = vim.treesitter.get_node_text(item_node, bufnr)
        txt = txt:gsub('^"(.*)"$', "%1")
        table.insert(results, txt)
      end
    end
  end
  return results
end

local function parse_block_contents(node, bufnr)
  local block_data = {
    properties = {},
    blocks = {},
    dynamic_blocks = {},
    ignore_changes = {},
  }
  local attr_query = vim.treesitter.query.parse("hcl", [=[
    (attribute (identifier) @name)
  ]=])
  for _, match, _ in attr_query:iter_matches(node, bufnr) do
    local name_node = match[1]
    local name_txt = vim.treesitter.get_node_text(name_node, bufnr)
    block_data.properties[name_txt] = true
  end
  local block_query = vim.treesitter.query.parse("hcl", [=[
    (block (identifier) @name (body) @body)
  ]=])
  for _, bmatch, _ in block_query:iter_matches(node, bufnr) do
    local name_node = bmatch[1]
    local body_node = bmatch[2]
    local name_txt = vim.treesitter.get_node_text(name_node, bufnr)
    if name_txt ~= "dynamic" then
      if name_txt == "lifecycle" then
        local lifecycle_data = parse_block_contents(body_node, bufnr)
        if lifecycle_data.properties["ignore_changes"] then
          local arr = parse_ignore_changes_array(body_node, bufnr)
          vim.list_extend(block_data.ignore_changes, arr)
        end
      else
        block_data.blocks[name_txt] = parse_block_contents(body_node, bufnr)
      end
    end
  end
  local dynamic_query = vim.treesitter.query.parse("hcl", [=[
    (block (identifier) @dyn_kw (string_lit) @dyn_name (body) @dyn_body (#eq? @dyn_kw "dynamic"))
  ]=])
  for _, dmatch, _ in dynamic_query:iter_matches(node, bufnr) do
    local dyn_name_node = dmatch[2]
    local dyn_body_node = dmatch[3]
    local dyn_name_txt = vim.treesitter.get_node_text(dyn_name_node, bufnr):gsub('"', "")
    local content_query = vim.treesitter.query.parse("hcl", [=[
      (block (identifier) @content_kw (body) @content_body (#eq? @content_kw "content"))
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

------------------------------------------------------------
-- SCHEMA FETCH FOR ROOT (unchanged)
------------------------------------------------------------
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
        end,
      })
    end,
  })
  if init_job == 0 then
    write_output("Failed to start Terraform initialization")
    cleanup(temp_dir)
  end
end

------------------------------------------------------------
-- PARSE CURRENT BUFFER (ROOT) using Treesitter (unchanged)
------------------------------------------------------------
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
  local resource_query = vim.treesitter.query.parse("hcl", [=[
    (block (identifier) @block_type (string_lit) @resource_type (string_lit) @resource_name (body) @body)
  ]=])
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

------------------------------------------------------------
-- VALIDATION LOGIC: Validate Block Attributes (unchanged, refactored inline)
------------------------------------------------------------
local function validate_block_attributes(resource_type, block_schema, block_data, block_path, inherited_ignores, unique_messages)
  inherited_ignores = inherited_ignores or {}
  local combined_ignores = vim.deepcopy(inherited_ignores)
  vim.list_extend(combined_ignores, block_data.ignore_changes or {})

  if block_schema.attributes then
    for attr_name, attr_info in pairs(block_schema.attributes) do
      if not vim.tbl_contains(combined_ignores, attr_name) then
        unique_messages[string.format(
          "%s missing %s property '%s' in path %s",
          resource_type,
          attr_info.required and "required" or "optional",
          attr_name,
          block_path
        )] = true
      end
    end
  end

  if block_schema.block_types then
    for block_name, btype_schema in pairs(block_schema.block_types) do
      if block_name ~= "timeouts" and not vim.tbl_contains(combined_ignores, block_name) then
        local sub_block = block_data.blocks[block_name]
        local dyn_block = block_data.dynamic_blocks[block_name]
        if sub_block then
          validate_block_attributes(resource_type, btype_schema.block, sub_block, block_path .. "." .. block_name, combined_ignores, unique_messages)
        elseif dyn_block then
          validate_block_attributes(resource_type, btype_schema.block, dyn_block, block_path .. ".dynamic." .. block_name, combined_ignores, unique_messages)
        else
          unique_messages[string.format(
            "%s missing %s block '%s' in path %s",
            resource_type,
            (btype_schema.min_items and btype_schema.min_items > 0) and "required" or "optional",
            block_name,
            block_path
          )] = true
        end
      end
    end
  end
end

------------------------------------------------------------
-- VALIDATION LOGIC: Validate Resources Against Schema (unchanged)
------------------------------------------------------------
local function do_schema_validation_for_resources(resources, schema_map, unique_messages)
  for _, resource in ipairs(resources) do
    local matching_block = nil
    for _, provider_data in pairs(schema_map) do
      local r_schemas = provider_data.resource_schemas
      if r_schemas and r_schemas[resource.type] then
        matching_block = r_schemas[resource.type].block
        break
      end
    end
    if not matching_block then
      unique_messages["No provider schema found for resource: " .. resource.type] = true
    else
      validate_block_attributes(resource.type, matching_block, resource, "root", resource.ignore_changes, unique_messages)
    end
  end
end

------------------------------------------------------------
-- REUSABLE FUNCTION: Run Terraform Init & Fetch Schema for a given directory
------------------------------------------------------------
local function runTerraformInitAndSchema(dir, on_done)
  write_output({}, true)
  local temp_dir = create_temp_dir()
  if not temp_dir then
    write_output("Failed to create temporary directory for " .. dir)
    return
  end
  local tf_file = dir .. "/terraform.tf"
  if vim.fn.filereadable(tf_file) == 0 then
    write_output("Could not find terraform.tf in " .. dir)
    cleanup(temp_dir)
    return
  end
  vim.fn.system({ "cp", tf_file, temp_dir .. "/terraform.tf" })
  if vim.v.shell_error ~= 0 then
    write_output("Failed to copy terraform.tf from " .. dir)
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
        write_output("Failed to initialize Terraform in " .. dir)
        cleanup(temp_dir)
        return
      end
      vim.fn.jobstart({ "terraform", "providers", "schema", "-json" }, {
        cwd = temp_dir,
        stdout_buffered = true,
        on_stdout = function(_, data)
          if data and #data > 0 then
            local json_str = table.concat(data, "\n")
            local ok, decoded = pcall(vim.json.decode, json_str)
            if ok and decoded and decoded.provider_schemas then
              on_done(decoded.provider_schemas)
            else
              write_output("Failed to parse schema JSON in " .. dir)
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
        on_exit = function(_, code2)
          if code2 ~= 0 then
            write_output("Failed to fetch schema in " .. dir)
          end
          cleanup(temp_dir)
        end,
      })
    end,
  })
  if init_job == 0 then
    write_output("Failed to start Terraform init job in " .. dir)
    cleanup(temp_dir)
  end
end

------------------------------------------------------------
-- PARSE A SUBMODULE'S main.tf FROM DISK
------------------------------------------------------------
local function parse_main_tf_in_dir(dir)
  local main_file = dir .. "/main.tf"
  local fd = io.open(main_file, "r")
  if not fd then
    return {}
  end
  local content = fd:read("*a")
  fd:close()
  local parser = vim.treesitter.get_string_parser(content, "hcl")
  local tree = parser:parse()[1]
  if not tree then
    return {}
  end
  local root = tree:root()
  local resources = {}
  local resource_query = vim.treesitter.query.parse("hcl", [=[
    (block (identifier) @block_type (string_lit) @resource_type (string_lit) @resource_name (body) @body)
  ]=])
  for _, captures, _ in resource_query:iter_matches(root, 0) do
    local block_type_node = captures[1]
    local resource_type_node = captures[2]
    local body_node = captures[4]
    if not (block_type_node and resource_type_node and body_node) then
      goto continue_res
    end
    local block_type_txt = vim.treesitter.get_node_text(block_type_node, content)
    if block_type_txt == "resource" then
      local resource_type_txt = vim.treesitter.get_node_text(resource_type_node, content):gsub('"', "")
      local parsed_data = parse_block_contents(body_node, 0)
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

------------------------------------------------------------
-- SUBMODULE VALIDATION: For every folder under "modules", run the same logic
------------------------------------------------------------
local function validate_submodules(root_dir, merged_messages)
  local uv = vim.loop
  ---@diagnostic disable: undefined-field
  local okHandle, handle = pcall(uv.fs_scandir, root_dir .. "/modules")
  ---@diagnostic enable: undefined-field
  if not (okHandle and handle) then
    table.insert(merged_messages, "No modules folder found or cannot scan directory: " .. root_dir .. "/modules")
    return
  end
  while true do
    ---@diagnostic disable: undefined-field
    local name, t = uv.fs_scandir_next(handle)
    ---@diagnostic enable: undefined-field
    if not name then break end
    if t == "directory" then
      local modDir = root_dir .. "/modules/" .. name
      local mainFile = modDir .. "/main.tf"
      local tfFile = modDir .. "/terraform.tf"
      if vim.fn.filereadable(mainFile) == 1 and vim.fn.filereadable(tfFile) == 1 then
        table.insert(merged_messages, "\nValidating submodule: " .. modDir)
        local subResources = parse_main_tf_in_dir(modDir)
        if #subResources == 0 then
          table.insert(merged_messages, "No resources found in submodule: " .. modDir)
        else
          runTerraformInitAndSchema(modDir, function(sub_schema)
            local localMsgs = {}
            do_schema_validation_for_resources(subResources, sub_schema, localMsgs)
            for _msg in pairs(localMsgs) do
              table.insert(merged_messages, _msg .. " in submodule: " .. modDir)
            end
          end)
        end
      end
    end
  end
end

------------------------------------------------------------
-- VALIDATE RESOURCES: Validate Root and then Submodules (independently)
------------------------------------------------------------
function M.validate_resources()
  write_output({}, true)
  -- 1) Root validation
  M.fetch_schema(function()
    local resources = M.parse_current_buffer()
    local unique_messages = {}
    do_schema_validation_for_resources(resources, schema_cache, unique_messages)
    local messages = {}
    for msg in pairs(unique_messages) do
      table.insert(messages, msg)
    end
    table.sort(messages)
    write_output(messages)
    -- 2) Submodules validation
    write_output({ "", "-- Checking submodules --" })
    local root_dir = vim.fn.getcwd()
    local subMessages = {}
    validate_submodules(root_dir, subMessages)
    if #subMessages == 0 then
      write_output({ "", "No submodule findings." })
    else
      table.sort(subMessages)
      write_output(subMessages)
    end
  end)
end

------------------------------------------------------------
-- SETUP COMMAND
------------------------------------------------------------
function M.setup()
  vim.api.nvim_create_user_command("TerraformValidateSchema", M.validate_resources, {})
end

return M


-- local M = {}
--
-- -- Cache for provider schemas
-- local schema_cache = {}
-- local output_bufnr = nil
-- local output_winid = nil
--
-- local function ensure_output_buffer()
--   if not output_bufnr or not vim.api.nvim_buf_is_valid(output_bufnr) then
--     output_bufnr = vim.api.nvim_create_buf(false, true)
--     vim.bo[output_bufnr].buftype = "nofile"
--     vim.bo[output_bufnr].bufhidden = "hide"
--     vim.bo[output_bufnr].swapfile = false
--     vim.api.nvim_buf_set_name(output_bufnr, "Terraform Schema Validation")
--   end
--   return output_bufnr
-- end
--
-- local function ensure_output_window()
--   if not output_winid or not vim.api.nvim_win_is_valid(output_winid) then
--     local current_win = vim.api.nvim_get_current_win()
--     vim.cmd("botright split")
--     output_winid = vim.api.nvim_get_current_win()
--     vim.api.nvim_win_set_buf(output_winid, ensure_output_buffer())
--     vim.api.nvim_win_set_height(output_winid, 20)
--     vim.wo[output_winid].wrap = false
--     vim.wo[output_winid].number = false
--     vim.wo[output_winid].relativenumber = false
--     vim.cmd("hi MyOutputHighlight guifg=#ffffff guibg=NONE")
--     vim.wo[output_winid].winhl = "Normal:MyOutputHighlight"
--     vim.api.nvim_set_current_win(current_win)
--   end
--   return output_winid
-- end
--
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
--   local win = ensure_output_window()
--   vim.api.nvim_win_set_cursor(win, { line_count + #lines, 0 })
--   vim.cmd("redraw")
-- end
--
-- local function create_temp_dir()
--   local handle = io.popen("mktemp -d")
--   if handle then
--     local temp_dir = handle:read("*l")
--     handle:close()
--     return temp_dir
--   end
--   return nil
-- end
--
-- local function cleanup(temp_dir)
--   if temp_dir then
--     vim.fn.system({ "rm", "-rf", temp_dir })
--     if vim.v.shell_error == 0 then
--       write_output({ "", "Cleaning up files succeeded" })
--     else
--       write_output({ "", "Cleaning up files failed" })
--     end
--   end
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
-- local function parse_ignore_changes_array(node, bufnr)
--   local results = {}
--
--   -- This is the bracket-based query for "ignore_changes" attributes
--   local bracket_query = vim.treesitter.query.parse("hcl", [=[
--     (attribute
--       (identifier) @attr_name
--       (expression
--         (collection_value
--           (tuple
--             ((expression) @item)+)))
--     )
--   ]=])
--
--   for _, match, _ in bracket_query:iter_matches(node, bufnr) do
--     local attr_node = match[1]
--     local attr_name = vim.treesitter.get_node_text(attr_node, bufnr)
--     if attr_name == "ignore_changes" then
--       -- Starting from match[2] up to the end are the items
--       for i = 2, #match do
--         local item_node = match[i]
--         local txt = vim.treesitter.get_node_text(item_node, bufnr)
--         -- remove leading/trailing quotes if present
--         txt = txt:gsub('^"(.*)"$', "%1")
--         table.insert(results, txt)
--       end
--     end
--   end
--
--   return results
-- end
--
-- local function parse_block_contents(node, bufnr)
--   local block_data = {
--     properties = {},
--     blocks = {},
--     dynamic_blocks = {},
--     ignore_changes = {},
--   }
--
--   local attr_query = vim.treesitter.query.parse("hcl", [=[
--     (attribute (identifier) @name)
--   ]=])
--
--   for _, match, _ in attr_query:iter_matches(node, bufnr) do
--     local name_node = match[1]
--     local name_txt = vim.treesitter.get_node_text(name_node, bufnr)
--     block_data.properties[name_txt] = true
--   end
--
--   local block_query = vim.treesitter.query.parse("hcl", [=[
--     (block
--       (identifier) @name
--       (body) @body)
--   ]=])
--
--   for _, bmatch, _ in block_query:iter_matches(node, bufnr) do
--     local name_node = bmatch[1]
--     local body_node = bmatch[2]
--     local name_txt = vim.treesitter.get_node_text(name_node, bufnr)
--
--     if name_txt == "dynamic" then
--       -- skip below, or handle in dynamic section
--       goto continue_block
--     end
--
--     if name_txt == "lifecycle" then
--       -- If there's an "ignore_changes" attribute in lifecycle, parse it:
--       local lifecycle_data = parse_block_contents(body_node, bufnr)
--       if lifecycle_data.properties["ignore_changes"] then
--         local arr = parse_ignore_changes_array(body_node, bufnr)
--         vim.list_extend(block_data.ignore_changes, arr)
--       end
--       goto continue_block
--     end
--
--     block_data.blocks[name_txt] = parse_block_contents(body_node, bufnr)
--
--     ::continue_block::
--   end
--
--   local dynamic_query = vim.treesitter.query.parse("hcl", [=[
--     (block
--       (identifier) @dyn_kw
--       (string_lit) @dyn_name
--       (body) @dyn_body
--       (#eq? @dyn_kw "dynamic"))
--   ]=])
--
--   for _, dmatch, _ in dynamic_query:iter_matches(node, bufnr) do
--     local dyn_name_node = dmatch[2]
--     local dyn_body_node = dmatch[3]
--     local dyn_name_txt = vim.treesitter.get_node_text(dyn_name_node, bufnr):gsub('"', "")
--
--     local content_query = vim.treesitter.query.parse("hcl", [=[
--       (block
--         (identifier) @content_kw
--         (body) @content_body
--         (#eq? @content_kw "content"))
--     ]=])
--
--     local found_content = false
--     for _, cmatch, _ in content_query:iter_matches(dyn_body_node, bufnr) do
--       found_content = true
--       local content_body_node = cmatch[2]
--       local content_data = parse_block_contents(content_body_node, bufnr)
--
--       block_data.dynamic_blocks[dyn_name_txt] = block_data.dynamic_blocks[dyn_name_txt] or {
--         properties = {},
--         blocks = {},
--         dynamic_blocks = {},
--         ignore_changes = {},
--       }
--
--       -- Merge content_data into dynamic_blocks[dyn_name_txt]
--       for k, v in pairs(content_data.properties) do
--         block_data.dynamic_blocks[dyn_name_txt].properties[k] = v
--       end
--       for k, v in pairs(content_data.blocks) do
--         block_data.dynamic_blocks[dyn_name_txt].blocks[k] = v
--       end
--       for k, v in pairs(content_data.dynamic_blocks) do
--         block_data.dynamic_blocks[dyn_name_txt].dynamic_blocks[k] = v
--       end
--       for _, ic in ipairs(content_data.ignore_changes) do
--         table.insert(block_data.dynamic_blocks[dyn_name_txt].ignore_changes, ic)
--       end
--     end
--
--     if not found_content then
--       block_data.dynamic_blocks[dyn_name_txt] = parse_block_contents(dyn_body_node, bufnr)
--     end
--   end
--
--   return block_data
-- end
--
-- function M.fetch_schema(callback)
--   write_output({}, true)
--   local temp_dir = create_temp_dir()
--   if not temp_dir then
--     write_output("Failed to create temporary directory")
--     return
--   end
--
--   local current_dir = vim.fn.getcwd()
--   local local_tf = current_dir .. "/terraform.tf"
--   if vim.fn.filereadable(local_tf) == 0 then
--     write_output("Could not find terraform.tf in " .. current_dir)
--     cleanup(temp_dir)
--     return
--   end
--
--   vim.fn.system({ "cp", local_tf, temp_dir .. "/terraform.tf" })
--   if vim.v.shell_error ~= 0 then
--     write_output("Failed to copy terraform.tf to temp directory.")
--     cleanup(temp_dir)
--     return
--   end
--
--   local init_job = vim.fn.jobstart({ "terraform", "init" }, {
--     cwd = temp_dir,
--     on_stdout = function(_, data)
--       if data and #data > 0 then
--         write_output(
--           vim.tbl_filter(function(line)
--             return line and line ~= ""
--           end, data)
--         )
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
--       vim.fn.jobstart({ "terraform", "providers", "schema", "-json" }, {
--         cwd = temp_dir,
--         stdout_buffered = true,
--         on_stdout = function(_, data)
--           if data and #data > 0 then
--             local json_str = table.concat(data, "\n")
--             local success, decoded = pcall(vim.json.decode, json_str)
--             if success and decoded and decoded.provider_schemas then
--               schema_cache = decoded.provider_schemas
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
-- function M.parse_current_buffer()
--   if not ensure_hcl_parser() then
--     return {}
--   end
--   local bufnr = vim.api.nvim_get_current_buf()
--   local parser = vim.treesitter.get_parser(bufnr, "hcl")
--   local tree = parser:parse()[1]
--   if not tree then
--     return {}
--   end
--
--   local root = tree:root()
--   local resources = {}
--
--   local resource_query = vim.treesitter.query.parse("hcl", [=[
--     (block
--       (identifier) @block_type
--       (string_lit) @resource_type
--       (string_lit) @resource_name
--       (body) @body)
--   ]=])
--
--   for _, captures, _ in resource_query:iter_matches(root, bufnr) do
--     local block_type_node = captures[1]
--     local resource_type_node = captures[2]
--     local body_node = captures[4]
--
--     if not (block_type_node and resource_type_node and body_node) then
--       goto continue_res
--     end
--
--     local block_type_txt = vim.treesitter.get_node_text(block_type_node, bufnr)
--     if block_type_txt == "resource" then
--       local resource_type_txt = vim.treesitter.get_node_text(resource_type_node, bufnr):gsub('"', "")
--       local parsed_data = parse_block_contents(body_node, bufnr)
--       table.insert(resources, {
--         type = resource_type_txt,
--         properties = parsed_data.properties,
--         blocks = parsed_data.blocks,
--         dynamic_blocks = parsed_data.dynamic_blocks,
--         ignore_changes = parsed_data.ignore_changes,
--       })
--     end
--     ::continue_res::
--   end
--
--   return resources
-- end
--
-- local function validate_block_attributes(
--     resource_type, block_schema, block_data, block_path, inherited_ignores, unique_messages
-- )
--   inherited_ignores = inherited_ignores or {}
--   local combined_ignores = vim.deepcopy(inherited_ignores)
--   vim.list_extend(combined_ignores, block_data.ignore_changes or {})
--
--   if block_schema.attributes then
--     for attr_name, attr_info in pairs(block_schema.attributes) do
--       if vim.tbl_contains(combined_ignores, attr_name) then
--         goto continue_attr
--       end
--       -- If an attribute is "required" but not found in our resource data
--       if not attr_info.computed and not block_data.properties[attr_name] then
--         local msg = string.format(
--           "%s missing %s property '%s' in path %s",
--           resource_type,
--           attr_info.required and "required" or "optional",
--           attr_name,
--           block_path
--         )
--         unique_messages[msg] = true
--       end
--       ::continue_attr::
--     end
--   end
--
--   if block_schema.block_types then
--     for block_name, btype_schema in pairs(block_schema.block_types) do
--       -- For example, skip the "timeouts" block
--       if block_name == "timeouts" then
--         goto continue_block
--       end
--
--       if vim.tbl_contains(combined_ignores, block_name) then
--         goto continue_block
--       end
--
--       local sub_block = block_data.blocks[block_name]
--       local dyn_block = block_data.dynamic_blocks[block_name]
--
--       if sub_block then
--         validate_block_attributes(
--           resource_type,
--           btype_schema.block,
--           sub_block,
--           block_path .. "." .. block_name,
--           combined_ignores,
--           unique_messages
--         )
--       elseif dyn_block then
--         validate_block_attributes(
--           resource_type,
--           btype_schema.block,
--           dyn_block,
--           block_path .. ".dynamic." .. block_name,
--           combined_ignores,
--           unique_messages
--         )
--       else
--         -- min_items > 0 => required
--         local is_required = btype_schema.min_items and btype_schema.min_items > 0
--         local msg = string.format(
--           "%s missing %s block '%s' in path %s",
--           resource_type,
--           is_required and "required" or "optional",
--           block_name,
--           block_path
--         )
--         unique_messages[msg] = true
--       end
--       ::continue_block::
--     end
--   end
-- end
--
-- function M.validate_resources()
--   write_output({}, true)
--
--   -- Fetch the schema, then parse the buffer, then validate
--   M.fetch_schema(function()
--     local resources = M.parse_current_buffer()
--     local used_provider_keys = {}
--     local unique_messages = {}
--
--     for _, resource in ipairs(resources) do
--       local matching_provider_block = nil
--
--       -- Attempt to find a provider whose resource_schemas has resource.type
--       for provider_key, provider_data in pairs(schema_cache) do
--         local r_schemas = provider_data.resource_schemas
--         if r_schemas and r_schemas[resource.type] then
--           matching_provider_block = r_schemas[resource.type].block
--           used_provider_keys[provider_key] = true
--           break
--         end
--       end
--
--       if not matching_provider_block then
--         unique_messages["No provider schema found for resource: " .. resource.type] = true
--       else
--         -- Validate the resource's properties and sub-blocks
--         validate_block_attributes(
--           resource.type,
--           matching_provider_block,
--           resource,
--           "root",
--           resource.ignore_changes,
--           unique_messages
--         )
--       end
--     end
--
--     for provider_key, _ in pairs(schema_cache) do
--       if not used_provider_keys[provider_key] then
--         unique_messages["Provider declared but not used by any resource: " .. provider_key] = true
--       end
--     end
--
--     local messages = {}
--     for msg in pairs(unique_messages) do
--       table.insert(messages, msg)
--     end
--     table.sort(messages)
--     write_output(messages)
--   end)
-- end
--
-- function M.setup()
--   vim.api.nvim_create_user_command("TerraformValidateSchema", M.validate_resources, {})
-- end
--
-- return M
