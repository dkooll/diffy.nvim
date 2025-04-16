local M = {}

-- Dependencies

-- Global variables for output and tracking
local output_bufnr = nil
local output_winid = nil
local schema_cache = {} -- Cache for provider schemas
local parser_cache = {} -- Cache for TreeSitter parsers
local global_messages = {}
local pending_jobs = 0

-- Enhanced output buffer management
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

-- Optimized output writing with batching
local write_queue = {}
local write_timer = nil

local function flush_write_queue()
  if #write_queue > 0 then
    local buf = ensure_output_buffer()
    local line_count = vim.api.nvim_buf_line_count(buf)
    vim.api.nvim_buf_set_lines(buf, line_count, line_count, false, write_queue)
    local win = ensure_output_window()
    vim.api.nvim_win_set_cursor(win, { line_count + #write_queue, 0 })
    vim.cmd("redraw")
    write_queue = {}
  end
  write_timer = nil
end

local function write_output(lines, clear)
  if clear then
    vim.api.nvim_buf_set_lines(ensure_output_buffer(), 0, -1, false, {})
  end

  if type(lines) == "string" then
    lines = { lines }
  end

  for _, line in ipairs(lines) do
    table.insert(write_queue, line)
  end

  if not write_timer then
    write_timer = vim.defer_fn(flush_write_queue, 50) -- 50ms debounce
  end
end

-- Check for HCL parser once at startup
local hcl_parser_available = nil
local function ensure_hcl_parser()
  if hcl_parser_available == nil then
    hcl_parser_available = pcall(vim.treesitter.get_parser, 0, "hcl")
    if not hcl_parser_available then
      write_output("HCL parser not found. Please ensure tree-sitter HCL is installed.")
    end
  end
  return hcl_parser_available
end

-- Optimized module discovery
local function discover_modules()
  local modules = {}

  -- Check the current directory
  if vim.fn.filereadable("terraform.tf") == 1 then
    table.insert(modules, ".")
  end

  -- Find modules directory using a shell command for precise results
  local modules_dir = "modules"
  if vim.fn.isdirectory(modules_dir) == 1 then
    local handle = io.popen("find " .. modules_dir .. " -name terraform.tf -type f | xargs -n1 dirname")
    if handle then
      for module_dir in handle:lines() do
        if module_dir and module_dir ~= "" then
          table.insert(modules, module_dir)
        end
      end
      handle:close()
    end
  end

  -- Debug output
  if os.getenv("DEBUG_DIFFY") then
    write_output("Discovered modules: " .. vim.inspect(modules))
  end

  return modules
end

-- TreeSitter node text helper with caching
local node_text_cache = {}
local function get_node_text(node, bufnr)
  if not node then return "" end

  local node_id = tostring(node:id())
  local cache_key = bufnr .. "_" .. node_id

  if node_text_cache[cache_key] then
    return node_text_cache[cache_key]
  end

  local text = vim.treesitter.get_node_text(node, bufnr)
  node_text_cache[cache_key] = text
  return text
end

-- Improved case-insensitive ignore check
local function is_ignored(ignore_list, name)
  -- Quick check for the special "all" marker
  if vim.tbl_contains(ignore_list, "*all*") then
    return true
  end

  -- Convert name to lowercase once
  local name_lower = string.lower(name)

  -- Create a lookup table for faster checks
  local ignore_lookup = {}
  for _, item in ipairs(ignore_list) do
    ignore_lookup[string.lower(item)] = true
  end

  return ignore_lookup[name_lower] == true
end

-- Optimized ignore_changes extractor
local function extract_ignore_changes(body_node, bufnr)
  local ignore_changes = {}

  -- Get the text only once
  local body_text = get_node_text(body_node, bufnr)

  -- Faster pattern matching with targeted extraction
  local ignore_section = body_text:match("ignore_changes%s*=%s*%[(.-)%]")
  if ignore_section then
    -- Quick check for "all"
    if ignore_section:match("%s*all%s*") then
      return { "*all*" }
    end

    -- Extract words more efficiently
    for word in ignore_section:gmatch("([%w_]+)") do
      if word ~= "ignore_changes" and word ~= "all" then
        table.insert(ignore_changes, word)
      end
    end
  end

  return ignore_changes
end

-- Parse block contents with optimized TreeSitter queries
local function parse_block_contents(node, bufnr)
  local block_data = {
    properties = {},
    blocks = {},
    dynamic_blocks = {},
    ignore_changes = {},
  }

  -- Optimize by preparing queries only once and reusing them
  local attr_query = vim.treesitter.query.parse("hcl", [[
    (attribute (identifier) @name)
  ]])

  local block_query = vim.treesitter.query.parse("hcl", [[
    (block
      (identifier) @name
      (body) @body)
  ]])

  local dynamic_query = vim.treesitter.query.parse("hcl", [[
    (block
      (identifier) @dyn_kw
      (string_lit) @dyn_name
      (body) @dyn_body
      (#eq? @dyn_kw "dynamic"))
  ]])

  local lifecycle_query = vim.treesitter.query.parse("hcl", [[
    (block
      (identifier) @block_name
      (body) @block_body
      (#eq? @block_name "lifecycle"))
  ]])

  local content_query = vim.treesitter.query.parse("hcl", [[
    (block
      (identifier) @content_kw
      (body) @content_body
      (#eq? @content_kw "content"))
  ]])

  -- Process attributes
  for _, match, _ in attr_query:iter_matches(node, bufnr, 0, -1, { all = true }) do
    local name_node = match[1] and match[1][1]
    if name_node then
      local name_txt = get_node_text(name_node, bufnr)
      if name_txt and name_txt ~= "" then
        block_data.properties[name_txt] = true
      end
    end
  end

  -- Extract lifecycle ignore_changes
  for _, match, _ in lifecycle_query:iter_matches(node, bufnr, 0, -1, { all = true }) do
    local body_node = match[2] and match[2][1]
    if body_node then
      local ignore_list = extract_ignore_changes(body_node, bufnr)
      if #ignore_list > 0 then
        vim.list_extend(block_data.ignore_changes, ignore_list)
      end
    end
  end

  -- Process regular blocks
  for _, match, _ in block_query:iter_matches(node, bufnr, 0, -1, { all = true }) do
    local name_node = match[1] and match[1][1]
    local body_node = match[2] and match[2][1]

    if name_node and body_node then
      local name_txt = get_node_text(name_node, bufnr)

      if name_txt == "dynamic" or name_txt == "lifecycle" then
        goto continue_block
      end

      block_data.blocks[name_txt] = parse_block_contents(body_node, bufnr)
    end
    ::continue_block::
  end

  -- Process dynamic blocks
  for _, match, _ in dynamic_query:iter_matches(node, bufnr, 0, -1, { all = true }) do
    local dyn_name_node = match[2] and match[2][1]
    local dyn_body_node = match[3] and match[3][1]

    if dyn_name_node and dyn_body_node then
      local dyn_name_txt = get_node_text(dyn_name_node, bufnr):gsub('"', "")

      local found_content = false

      for _, cmatch, _ in content_query:iter_matches(dyn_body_node, bufnr, 0, -1, { all = true }) do
        local content_body_node = cmatch[2] and cmatch[2][1]
        if content_body_node then
          found_content = true
          local content_data = parse_block_contents(content_body_node, bufnr)

          block_data.dynamic_blocks[dyn_name_txt] = block_data.dynamic_blocks[dyn_name_txt] or {
            properties = {},
            blocks = {},
            dynamic_blocks = {},
            ignore_changes = {},
          }

          -- Merge content_data into dynamic_blocks
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
      end

      if not found_content then
        block_data.dynamic_blocks[dyn_name_txt] = parse_block_contents(dyn_body_node, bufnr)
      end
    end
  end

  return block_data
end

-- File buffer caching system
local file_buffer_cache = {}

local function get_or_create_buffer(file_path)
  if file_buffer_cache[file_path] then
    local bufnr = file_buffer_cache[file_path]
    if vim.api.nvim_buf_is_valid(bufnr) then
      return bufnr
    end
  end

  local bufnr = vim.fn.bufadd(file_path)
  if bufnr and bufnr > 0 then
    vim.fn.bufload(bufnr)
    vim.api.nvim_set_option_value('filetype', 'terraform', { buf = bufnr })
    file_buffer_cache[file_path] = bufnr
    return bufnr
  end

  return nil
end

-- Optimized parser caching
local function get_or_create_parser(bufnr)
  if not parser_cache[bufnr] then
    parser_cache[bufnr] = vim.treesitter.get_parser(bufnr, "hcl")
  end
  return parser_cache[bufnr]
end

-- Parse file with buffer and parser caching
local function parse_file(file_path)
  if not ensure_hcl_parser() then
    return { resources = {}, data_sources = {} }
  end

  local bufnr = get_or_create_buffer(file_path)
  if not bufnr then
    return { resources = {}, data_sources = {} }
  end

  local parser = get_or_create_parser(bufnr)
  if not parser then
    return { resources = {}, data_sources = {} }
  end

  local tree = parser:parse()[1]
  if not tree then
    return { resources = {}, data_sources = {} }
  end

  local root = tree:root()
  local resources = {}
  local data_sources = {}

  -- Use a single query for both resource and data blocks
  local block_query = vim.treesitter.query.parse("hcl", [[
    (block
      (identifier) @block_type
      (string_lit) @resource_type
      (string_lit) @resource_name
      (body) @body)
  ]])

  for _, match, _ in block_query:iter_matches(root, bufnr, 0, -1, { all = true }) do
    local block_type_node = match[1] and match[1][1]
    local resource_type_node = match[2] and match[2][1]
    local body_node = match[4] and match[4][1]

    if not (block_type_node and resource_type_node and body_node) then
      goto continue_block
    end

    local block_type_txt = get_node_text(block_type_node, bufnr)
    local resource_type_txt = get_node_text(resource_type_node, bufnr):gsub('"', "")
    local parsed_data = parse_block_contents(body_node, bufnr)

    if block_type_txt == "resource" then
      table.insert(resources, {
        type = resource_type_txt,
        properties = parsed_data.properties,
        blocks = parsed_data.blocks,
        dynamic_blocks = parsed_data.dynamic_blocks,
        ignore_changes = parsed_data.ignore_changes,
      })
    elseif block_type_txt == "data" then
      table.insert(data_sources, {
        type = resource_type_txt,
        properties = parsed_data.properties,
        blocks = parsed_data.blocks,
        dynamic_blocks = parsed_data.dynamic_blocks,
        ignore_changes = parsed_data.ignore_changes,
      })
    end

    ::continue_block::
  end

  return { resources = resources, data_sources = data_sources }
end

-- Optimized validation with early returns and message batching
local function validate_block_attributes(
    entity_type, schema_type, block_schema, block_data, block_path, inherited_ignores, messages_batch
)
  inherited_ignores = inherited_ignores or {}
  local combined_ignores = vim.deepcopy(inherited_ignores)
  vim.list_extend(combined_ignores, block_data.ignore_changes or {})

  -- Process attributes
  if block_schema.attributes then
    for attr_name, attr_info in pairs(block_schema.attributes) do
      -- Skip quickly if ignored
      if is_ignored(combined_ignores, attr_name) then
        goto continue_attr
      end

      -- Skip special cases
      if attr_name == "id" or
          (attr_info.computed and not attr_info.optional and not attr_info.required) or
          attr_info.deprecated == true or attr_info.deprecation_message then
        goto continue_attr
      end

      -- Report missing properties
      if not block_data.properties[attr_name] then
        local msg = string.format(
          "%s source %s missing %s property '%s' in path %s",
          schema_type,
          entity_type,
          attr_info.required and "required" or "optional",
          attr_name,
          block_path
        )
        messages_batch[msg] = true
      end
      ::continue_attr::
    end
  end

  -- Process blocks
  if block_schema.block_types then
    for block_name, btype_schema in pairs(block_schema.block_types) do
      -- Skip quickly if special cases
      if block_name == "timeouts" or
          is_ignored(combined_ignores, block_name) or
          btype_schema.deprecated == true or btype_schema.deprecation_message then
        goto continue_block
      end

      local sub_block = block_data.blocks[block_name]
      local dyn_block = block_data.dynamic_blocks[block_name]

      if sub_block then
        validate_block_attributes(
          entity_type,
          schema_type,
          btype_schema.block,
          sub_block,
          block_path .. "." .. block_name,
          combined_ignores,
          messages_batch
        )
      elseif dyn_block then
        validate_block_attributes(
          entity_type,
          schema_type,
          btype_schema.block,
          dyn_block,
          block_path .. ".dynamic." .. block_name,
          combined_ignores,
          messages_batch
        )
      else
        local is_required = btype_schema.min_items and btype_schema.min_items > 0
        local msg = string.format(
          "%s %s missing %s block '%s' in path %s",
          schema_type,
          entity_type,
          is_required and "required" or "optional",
          block_name,
          block_path
        )
        messages_batch[msg] = true
      end
      ::continue_block::
    end
  end
end

-- Validate files with schema caching
local function validate_terraform_files(module_path, module_schema)
  local module_messages = {}

  -- Function to validate a single file
  local function validate_file(file_path)
    local parsed = parse_file(file_path)
    local file_messages = {}
    local used_providers = {}

    -- Validate resources
    for _, resource in ipairs(parsed.resources) do
      local matching_provider_block = nil

      -- Try to find provider with this resource type
      for provider_key, provider_data in pairs(module_schema) do
        local r_schemas = provider_data.resource_schemas
        if r_schemas and r_schemas[resource.type] then
          matching_provider_block = r_schemas[resource.type].block
          used_providers[provider_key] = true
          break
        end
      end

      if not matching_provider_block then
        file_messages["No provider schema found for resource: " .. resource.type] = true
      else
        -- Debug if needed
        if #resource.ignore_changes > 0 and os.getenv("DEBUG_DIFFY") then
          write_output(string.format("Resource %s has ignore_changes: %s",
            resource.type, table.concat(resource.ignore_changes, ", ")))
        end

        -- Validate attributes
        validate_block_attributes(
          resource.type,
          "resource",
          matching_provider_block,
          resource,
          "root",
          resource.ignore_changes,
          file_messages
        )
      end
    end

    -- Validate data sources
    for _, data_source in ipairs(parsed.data_sources) do
      local matching_provider_block = nil

      -- Try to find provider with this data source type
      for provider_key, provider_data in pairs(module_schema) do
        local d_schemas = provider_data.data_source_schemas
        if d_schemas and d_schemas[data_source.type] then
          matching_provider_block = d_schemas[data_source.type].block
          used_providers[provider_key] = true
          break
        end
      end

      if not matching_provider_block then
        file_messages["No provider schema found for data source: " .. data_source.type] = true
      else
        -- Validate attributes
        validate_block_attributes(
          data_source.type,
          "data",
          matching_provider_block,
          data_source,
          "root",
          data_source.ignore_changes,
          file_messages
        )
      end
    end

    -- Check for unused providers
    for provider_key, _ in pairs(module_schema) do
      if not used_providers[provider_key] then
        file_messages["Provider declared but not used by any resource or data source: " .. provider_key] = true
      end
    end

    -- Return the messages
    return file_messages
  end

  -- Validate main.tf
  local main_tf = module_path .. "/main.tf"
  if vim.fn.filereadable(main_tf) == 1 then
    local main_messages = validate_file(main_tf)
    for msg, _ in pairs(main_messages) do
      module_messages[msg] = true
    end
  end

  -- Validate terraform.tf
  local terraform_tf = module_path .. "/terraform.tf"
  if vim.fn.filereadable(terraform_tf) == 1 then
    local tf_messages = validate_file(terraform_tf)
    for msg, _ in pairs(tf_messages) do
      module_messages[msg] = true
    end
  end

  -- Add module name prefix to all messages and add to global messages
  for msg, _ in pairs(module_messages) do
    global_messages[module_path .. ": " .. msg] = true
  end

  -- Decrement pending jobs counter
  pending_jobs = pending_jobs - 1

  -- When all jobs are done, show final results
  if pending_jobs == 0 then
    local message_list = {}
    for msg, _ in pairs(global_messages) do
      table.insert(message_list, msg)
    end

    if #message_list == 0 then
      write_output({ "No issues found! All resources and data sources match their schema definitions." })
    else
      table.sort(message_list)
      write_output(message_list)
    end

    write_output({ "", "Validation complete!" })

    -- Clear caches to free memory
    node_text_cache = {}
    parser_cache = {}
  end
end

-- Optimized schema retrieval with caching
local function get_terraform_schema(module_path)
  -- Check if schema is already cached
  local schema_key = module_path
  if schema_cache[schema_key] then
    -- Use cached schema
    validate_terraform_files(module_path, schema_cache[schema_key])
    return
  end

  -- Check if terraform.tf exists
  local tf_file = module_path .. "/terraform.tf"
  if vim.fn.filereadable(tf_file) ~= 1 then
    write_output("Could not find terraform.tf in " .. module_path)
    pending_jobs = pending_jobs - 1
    return
  end

  -- Run terraform init and providers schema in one job
  local combined_output = {}

  -- Use vim.fn.jobstart for better compatibility
  local job_id = vim.fn.jobstart({
    "bash",
    "-c",
    "cd " ..
    module_path ..
    " && terraform init -no-color >/dev/null 2>&1 && terraform providers schema -json && rm -rf .terraform .terraform.lock.hcl"
  }, {
    stdout_buffered = true,
    on_stdout = function(_, data)
      if data and #data > 0 then
        vim.list_extend(combined_output, data)
      end
    end,
    on_stderr = function(_, data)
      if data and #data > 0 then
        for _, line in ipairs(data) do
          if line and line:match("Error:") then
            write_output("Error: " .. line)
          end
        end
      end
    end,
    on_exit = function(_, code)
      if code ~= 0 then
        write_output("Failed to get schema for " .. module_path)
        pending_jobs = pending_jobs - 1
        return
      end

      -- Try to parse the JSON output
      local json_str = table.concat(combined_output, "\n")
      local success, decoded = pcall(vim.json.decode, json_str)
      if success and decoded and decoded.provider_schemas then
        -- Cache the schema for future use
        schema_cache[schema_key] = decoded.provider_schemas
        -- Validate with the retrieved schema
        validate_terraform_files(module_path, decoded.provider_schemas)
      else
        write_output("Failed to parse schema JSON for " .. module_path)
        pending_jobs = pending_jobs - 1
      end
    end
  })

  if job_id <= 0 then
    write_output("Failed to start job for " .. module_path)
    pending_jobs = pending_jobs - 1
  end
end

-- Run validation with improved concurrency
function M.validate_resources()
  write_output({}, true)
  write_output("Validating Terraform resource and data source schemas...")
  global_messages = {}

  -- Reset caches for a fresh run
  node_text_cache = {}

  -- Discover modules
  local modules = discover_modules()

  if #modules == 0 then
    write_output("No Terraform modules found containing terraform.tf")
    return
  end

  write_output("Found " .. #modules .. " module(s)")

  -- Set pending jobs counter
  pending_jobs = #modules

  -- Process modules with controlled concurrency
  local max_concurrent = math.min(#modules, 4)
  local active_jobs = 0
  local queued_modules = vim.deepcopy(modules)

  -- Function to start a new job if available
  local function start_next_job()
    if #queued_modules > 0 and active_jobs < max_concurrent then
      active_jobs = active_jobs + 1
      local module_path = table.remove(queued_modules, 1)

      -- Process this module
      vim.schedule(function()
        get_terraform_schema(module_path)

        -- Handle job completion
        vim.defer_fn(function()
          active_jobs = active_jobs - 1
          start_next_job()
        end, 100) -- Small delay to avoid overwhelming the system
      end)

      -- Try to start more jobs if we can
      if active_jobs < max_concurrent then
        start_next_job()
      end
    end
  end

  -- Start initial batch of jobs
  for _ = 1, max_concurrent do
    if #queued_modules > 0 then
      start_next_job()
    end
  end
end

-- Setup function
function M.setup(opts)
  opts = opts or {}

  -- Create user command
  vim.api.nvim_create_user_command("TerraformValidateSchema", M.validate_resources, {})

  -- Register buffer autocmd to clear caches when appropriate
  vim.api.nvim_create_autocmd({ "BufWritePost" }, {
    pattern = { "*.tf", "*.hcl" },
    callback = function()
      -- Clear caches for affected files
      local file_path = vim.fn.expand("<afile>:p")
      node_text_cache = {}
      file_buffer_cache[file_path] = nil
      parser_cache[file_path] = nil

      -- Clear schema cache for affected module
      local module_dir = vim.fn.fnamemodify(file_path, ":h")
      schema_cache[module_dir] = nil
    end
  })

  return M
end

return M

-- local M = {}
--
-- -- Global variables for output and tracking
-- local output_bufnr = nil
-- local output_winid = nil
-- local pending_modules = 0
-- local global_messages = {}
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
-- local function ensure_hcl_parser()
--   local ok = pcall(vim.treesitter.get_parser, 0, "hcl")
--   if not ok then
--     write_output("HCL parser not found. Please ensure tree-sitter HCL is installed.")
--     return false
--   end
--   return true
-- end
--
-- local function discover_modules()
--   local modules = {}
--
--   local handle = io.popen("find modules -type f -name terraform.tf 2>/dev/null | sort")
--   if handle then
--     for line in handle:lines() do
--       -- Get the directory containing terraform.tf
--       local module_dir = vim.fn.fnamemodify(line, ":h")
--       table.insert(modules, module_dir)
--     end
--     handle:close()
--   end
--
--   -- Add current directory as well
--   if vim.fn.filereadable("terraform.tf") == 1 then
--     table.insert(modules, ".")
--   end
--
--   return modules
-- end
--
-- -- Helper function to get node text
-- local function get_node_text(node, bufnr)
--   if not node then return "" end
--   return vim.treesitter.get_node_text(node, bufnr)
-- end
--
-- -- Helper function to check if an attribute is ignored (with case insensitivity)
-- local function is_ignored(ignore_list, name)
--   -- Check for the special "all" marker
--   if vim.tbl_contains(ignore_list, "*all*") then
--     return true
--   end
--
--   -- Case insensitive check
--   name = string.lower(name)
--   for _, item in ipairs(ignore_list) do
--     if string.lower(item) == name then
--       return true
--     end
--   end
--
--   return false
-- end
--
-- -- Extract the lifecycle ignore_changes directly from the node content
-- local function extract_ignore_changes(body_node, bufnr)
--   local ignore_changes = {}
--
--   -- Get the full text of the node to parse
--   local body_text = get_node_text(body_node, bufnr)
--
--   -- Find the ignore_changes section
--   local ignore_section = body_text:match("ignore_changes%s*=%s*%[(.-)%]")
--   if ignore_section then
--     -- If we found "all", return the special marker
--     if ignore_section:match("all") then
--       return { "*all*" }
--     end
--
--     -- Extract individual identifiers
--     for word in ignore_section:gmatch("([%w_]+)") do
--       if word ~= "ignore_changes" and word ~= "all" then
--         table.insert(ignore_changes, word)
--       end
--     end
--   end
--
--   return ignore_changes
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
--   local attr_query = vim.treesitter.query.parse("hcl", [[
--     (attribute (identifier) @name)
--   ]])
--
--   -- Execute the query using iter_matches with all=true for Neovim 0.11+
--   for _, match, _ in attr_query:iter_matches(node, bufnr, 0, -1, { all = true }) do
--     local name_node = match[1] and match[1][1] -- First node of the first capture
--     if name_node then
--       local name_txt = get_node_text(name_node, bufnr)
--       if name_txt and name_txt ~= "" then
--         block_data.properties[name_txt] = true
--       end
--     end
--   end
--
--   -- Directly extract lifecycle ignore_changes
--   local lifecycle_query = vim.treesitter.query.parse("hcl", [[
--     (block
--       (identifier) @block_name
--       (body) @block_body
--       (#eq? @block_name "lifecycle"))
--   ]])
--
--   for _, match, _ in lifecycle_query:iter_matches(node, bufnr, 0, -1, { all = true }) do
--     local body_node = match[2] and match[2][1] -- First node of the second capture
--     if body_node then
--       local ignore_list = extract_ignore_changes(body_node, bufnr)
--       if #ignore_list > 0 then
--         vim.list_extend(block_data.ignore_changes, ignore_list)
--       end
--     end
--   end
--
--   local block_query = vim.treesitter.query.parse("hcl", [[
--     (block
--       (identifier) @name
--       (body) @body)
--   ]])
--
--   for _, match, _ in block_query:iter_matches(node, bufnr, 0, -1, { all = true }) do
--     local name_node = match[1] and match[1][1] -- First node of the first capture
--     local body_node = match[2] and match[2][1] -- First node of the second capture
--
--     if name_node and body_node then
--       local name_txt = get_node_text(name_node, bufnr)
--
--       if name_txt == "dynamic" or name_txt == "lifecycle" then
--         -- skip these blocks as they are handled elsewhere
--         goto continue_block
--       end
--
--       block_data.blocks[name_txt] = parse_block_contents(body_node, bufnr)
--     end
--     ::continue_block::
--   end
--
--   local dynamic_query = vim.treesitter.query.parse("hcl", [[
--     (block
--       (identifier) @dyn_kw
--       (string_lit) @dyn_name
--       (body) @dyn_body
--       (#eq? @dyn_kw "dynamic"))
--   ]])
--
--   for _, match, _ in dynamic_query:iter_matches(node, bufnr, 0, -1, { all = true }) do
--     local dyn_name_node = match[2] and match[2][1] -- First node of the second capture
--     local dyn_body_node = match[3] and match[3][1] -- First node of the third capture
--
--     if dyn_name_node and dyn_body_node then
--       local dyn_name_txt = get_node_text(dyn_name_node, bufnr):gsub('"', "")
--
--       local content_query = vim.treesitter.query.parse("hcl", [[
--         (block
--           (identifier) @content_kw
--           (body) @content_body
--           (#eq? @content_kw "content"))
--       ]])
--
--       local found_content = false
--
--       for _, cmatch, _ in content_query:iter_matches(dyn_body_node, bufnr, 0, -1, { all = true }) do
--         local content_body_node = cmatch[2] and cmatch[2][1] -- First node of the second capture
--         if content_body_node then
--           found_content = true
--           local content_data = parse_block_contents(content_body_node, bufnr)
--
--           block_data.dynamic_blocks[dyn_name_txt] = block_data.dynamic_blocks[dyn_name_txt] or {
--             properties = {},
--             blocks = {},
--             dynamic_blocks = {},
--             ignore_changes = {},
--           }
--
--           -- Merge content_data into dynamic_blocks[dyn_name_txt]
--           for k, v in pairs(content_data.properties) do
--             block_data.dynamic_blocks[dyn_name_txt].properties[k] = v
--           end
--           for k, v in pairs(content_data.blocks) do
--             block_data.dynamic_blocks[dyn_name_txt].blocks[k] = v
--           end
--           for k, v in pairs(content_data.dynamic_blocks) do
--             block_data.dynamic_blocks[dyn_name_txt].dynamic_blocks[k] = v
--           end
--           for _, ic in ipairs(content_data.ignore_changes) do
--             table.insert(block_data.dynamic_blocks[dyn_name_txt].ignore_changes, ic)
--           end
--         end
--       end
--
--       if not found_content then
--         block_data.dynamic_blocks[dyn_name_txt] = parse_block_contents(dyn_body_node, bufnr)
--       end
--     end
--   end
--
--   return block_data
-- end
--
-- local function parse_file(file_path)
--   if not ensure_hcl_parser() then
--     return { resources = {}, data_sources = {} }
--   end
--
--   -- Use bufadd/bufload to get the file content into a buffer
--   local bufnr = vim.fn.bufadd(file_path)
--   if bufnr and bufnr > 0 then
--     vim.fn.bufload(bufnr)
--     vim.api.nvim_set_option_value('filetype', 'terraform', { buf = bufnr })
--
--     local parser = vim.treesitter.get_parser(bufnr, "hcl")
--     if parser then
--       local tree = parser:parse()[1]
--       if tree then
--         local root = tree:root()
--         local resources = {}
--         local data_sources = {}
--
--         -- Query for both resource and data blocks
--         local block_query = vim.treesitter.query.parse("hcl", [[
--           (block
--             (identifier) @block_type
--             (string_lit) @resource_type
--             (string_lit) @resource_name
--             (body) @body)
--         ]])
--
--         -- Use iter_matches with all=true for Neovim 0.11+
--         for _, match, _ in block_query:iter_matches(root, bufnr, 0, -1, { all = true }) do
--           local block_type_node = match[1] and match[1][1]    -- First node of capture index 1
--           local resource_type_node = match[2] and match[2][1] -- First node of capture index 2
--           local body_node = match[4] and match[4][1]          -- First node of capture index 4
--
--           if not (block_type_node and resource_type_node and body_node) then
--             goto continue_block
--           end
--
--           local block_type_txt = get_node_text(block_type_node, bufnr)
--           local resource_type_txt = get_node_text(resource_type_node, bufnr):gsub('"', "")
--           local parsed_data = parse_block_contents(body_node, bufnr)
--
--           if block_type_txt == "resource" then
--             table.insert(resources, {
--               type = resource_type_txt,
--               properties = parsed_data.properties,
--               blocks = parsed_data.blocks,
--               dynamic_blocks = parsed_data.dynamic_blocks,
--               ignore_changes = parsed_data.ignore_changes,
--             })
--           elseif block_type_txt == "data" then
--             table.insert(data_sources, {
--               type = resource_type_txt,
--               properties = parsed_data.properties,
--               blocks = parsed_data.blocks,
--               dynamic_blocks = parsed_data.dynamic_blocks,
--               ignore_changes = parsed_data.ignore_changes,
--             })
--           end
--
--           ::continue_block::
--         end
--
--         return { resources = resources, data_sources = data_sources }
--       end
--     end
--   end
--
--   return { resources = {}, data_sources = {} }
-- end
--
-- local function validate_block_attributes(
--     entity_type, schema_type, block_schema, block_data, block_path, inherited_ignores, unique_messages
-- )
--   inherited_ignores = inherited_ignores or {}
--   local combined_ignores = vim.deepcopy(inherited_ignores)
--   vim.list_extend(combined_ignores, block_data.ignore_changes or {})
--
--   if block_schema.attributes then
--     for attr_name, attr_info in pairs(block_schema.attributes) do
--       -- Use case-insensitive ignore checking
--       if is_ignored(combined_ignores, attr_name) then
--         goto continue_attr
--       end
--
--       -- Skip 'id' property as it's not useful to show
--       if attr_name == "id" then
--         goto continue_attr
--       end
--
--       -- Skip purely computed attributes (those that are computed but not optional)
--       -- These are always exported, never set by the user
--       if attr_info.computed and not attr_info.optional and not attr_info.required then
--         goto continue_attr
--       end
--
--       -- Skip deprecated attributes - check for both possible representations
--       if attr_info.deprecated == true or attr_info.deprecation_message then
--         goto continue_attr
--       end
--
--       -- Show all other properties that are missing
--       if not block_data.properties[attr_name] then
--         local msg = string.format(
--           "%s source %s missing %s property '%s' in path %s",
--           schema_type,
--           entity_type,
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
--       -- Skip the timeouts block
--       if block_name == "timeouts" then
--         goto continue_block
--       end
--
--       -- Use case-insensitive ignore checking
--       if is_ignored(combined_ignores, block_name) then
--         goto continue_block
--       end
--
--       -- Skip deprecated blocks (if the schema provides deprecation info on blocks)
--       if btype_schema.deprecated == true or btype_schema.deprecation_message then
--         goto continue_block
--       end
--
--       local sub_block = block_data.blocks[block_name]
--       local dyn_block = block_data.dynamic_blocks[block_name]
--
--       if sub_block then
--         validate_block_attributes(
--           entity_type,
--           schema_type,
--           btype_schema.block,
--           sub_block,
--           block_path .. "." .. block_name,
--           combined_ignores,
--           unique_messages
--         )
--       elseif dyn_block then
--         validate_block_attributes(
--           entity_type,
--           schema_type,
--           btype_schema.block,
--           dyn_block,
--           block_path .. ".dynamic." .. block_name,
--           combined_ignores,
--           unique_messages
--         )
--       else
--         local is_required = btype_schema.min_items and btype_schema.min_items > 0
--         local msg = string.format(
--           "%s %s missing %s block '%s' in path %s",
--           schema_type,
--           entity_type,
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
-- local function validate_terraform_files(module_path, module_schema)
--   local module_messages = {}
--
--   local main_tf = module_path .. "/main.tf"
--   if vim.fn.filereadable(main_tf) == 1 then
--     local parsed = parse_file(main_tf)
--     local file_messages = {}
--     local used_providers = {}
--
--     -- Validate resources
--     for _, resource in ipairs(parsed.resources) do
--       local matching_provider_block = nil
--
--       -- Attempt to find a provider whose resource_schemas has resource.type
--       for provider_key, provider_data in pairs(module_schema) do
--         local r_schemas = provider_data.resource_schemas
--         if r_schemas and r_schemas[resource.type] then
--           matching_provider_block = r_schemas[resource.type].block
--           used_providers[provider_key] = true
--           break
--         end
--       end
--
--       if not matching_provider_block then
--         file_messages["No provider schema found for resource: " .. resource.type] = true
--       else
--         -- Double check ignore_changes - print debug if needed
--         if #resource.ignore_changes > 0 and os.getenv("DEBUG_DIFFY") then
--           write_output(string.format("Resource %s has ignore_changes: %s",
--             resource.type, table.concat(resource.ignore_changes, ", ")))
--         end
--
--         -- Validate the resource's properties and sub-blocks
--         validate_block_attributes(
--           resource.type,
--           "resource",
--           matching_provider_block,
--           resource,
--           "root",
--           resource.ignore_changes,
--           file_messages
--         )
--       end
--     end
--
--     -- Validate data sources
--     for _, data_source in ipairs(parsed.data_sources) do
--       local matching_provider_block = nil
--
--       -- Attempt to find a provider whose data_source_schemas has data_source.type
--       for provider_key, provider_data in pairs(module_schema) do
--         local d_schemas = provider_data.data_source_schemas
--         if d_schemas and d_schemas[data_source.type] then
--           matching_provider_block = d_schemas[data_source.type].block
--           used_providers[provider_key] = true
--           break
--         end
--       end
--
--       if not matching_provider_block then
--         file_messages["No provider schema found for data source: " .. data_source.type] = true
--       else
--         -- Validate the data source's properties and sub-blocks
--         validate_block_attributes(
--           data_source.type,
--           "data",
--           matching_provider_block,
--           data_source,
--           "root",
--           data_source.ignore_changes,
--           file_messages
--         )
--       end
--     end
--
--     -- Check for unused providers
--     for provider_key, _ in pairs(module_schema) do
--       if not used_providers[provider_key] then
--         file_messages["Provider declared but not used by any resource or data source: " .. provider_key] = true
--       end
--     end
--
--     -- Add file messages to module messages
--     for msg, _ in pairs(file_messages) do
--       module_messages[msg] = true
--     end
--   end
--
--   -- Validate terraform.tf in this module
--   local terraform_tf = module_path .. "/terraform.tf"
--   if vim.fn.filereadable(terraform_tf) == 1 then
--     -- Terraform.tf typically has provider blocks, not resources
--     -- but we should check it for any resources/data sources that might be in there
--     local parsed = parse_file(terraform_tf)
--
--     if #parsed.resources > 0 or #parsed.data_sources > 0 then
--       local file_messages = {}
--
--       -- Validate resources in terraform.tf
--       for _, resource in ipairs(parsed.resources) do
--         local matching_provider_block = nil
--
--         for _, provider_data in pairs(module_schema) do
--           local r_schemas = provider_data.resource_schemas
--           if r_schemas and r_schemas[resource.type] then
--             matching_provider_block = r_schemas[resource.type].block
--             break
--           end
--         end
--
--         if not matching_provider_block then
--           file_messages["No provider schema found for resource: " .. resource.type] = true
--         else
--           validate_block_attributes(
--             resource.type,
--             "resource",
--             matching_provider_block,
--             resource,
--             "root",
--             resource.ignore_changes,
--             file_messages
--           )
--         end
--       end
--
--       -- Validate data sources in terraform.tf
--       for _, data_source in ipairs(parsed.data_sources) do
--         local matching_provider_block = nil
--
--         for _, provider_data in pairs(module_schema) do
--           local d_schemas = provider_data.data_source_schemas
--           if d_schemas and d_schemas[data_source.type] then
--             matching_provider_block = d_schemas[data_source.type].block
--             break
--           end
--         end
--
--         if not matching_provider_block then
--           file_messages["No provider schema found for data source: " .. data_source.type] = true
--         else
--           validate_block_attributes(
--             data_source.type,
--             "data",
--             matching_provider_block,
--             data_source,
--             "root",
--             data_source.ignore_changes,
--             file_messages
--           )
--         end
--       end
--
--       -- Add file messages to module messages
--       for msg, _ in pairs(file_messages) do
--         module_messages[msg] = true
--       end
--     end
--   end
--
--   -- Add module name prefix to all messages and add to global messages
--   for msg, _ in pairs(module_messages) do
--     global_messages[module_path .. ": " .. msg] = true
--   end
--
--   -- Decrement the pending modules counter
--   pending_modules = pending_modules - 1
--
--   if pending_modules == 0 then
--     local message_list = {}
--     for msg, _ in pairs(global_messages) do
--       table.insert(message_list, msg)
--     end
--
--     if #message_list == 0 then
--       write_output({ "No issues found! All resources and data sources match their schema definitions." })
--     else
--       table.sort(message_list)
--       write_output(message_list)
--     end
--
--     write_output({ "", "Validation complete!" })
--   end
-- end
--
-- -- Function to process a single module
-- local function process_module(module_path)
--   write_output("Fetching schema for module: " .. module_path)
--
--   -- Use the module's own terraform.tf file directly
--   local tf_file = module_path .. "/terraform.tf"
--
--   if vim.fn.filereadable(tf_file) ~= 1 then
--     write_output("Could not find terraform.tf in " .. module_path)
--     pending_modules = pending_modules - 1
--     return
--   end
--
--   local init_job = vim.fn.jobstart({ "terraform", "init" }, {
--     cwd = module_path,
--     on_stdout = function(_, _)
--     end,
--     on_stderr = function(_, data)
--       if data and #data > 0 then
--         local errors = vim.tbl_filter(function(line)
--           return line and line ~= "" and line:match("Error:")
--         end, data)
--
--         if #errors > 0 then
--           write_output(vim.tbl_map(function(line)
--             return "Error: " .. line
--           end, errors))
--         end
--       end
--     end,
--     on_exit = function(_, exit_code)
--       if exit_code ~= 0 then
--         write_output("Failed to initialize Terraform in " .. module_path)
--         pending_modules = pending_modules - 1
--         return
--       end
--
--       -- Get schema for this module
--       vim.fn.jobstart({ "terraform", "providers", "schema", "-json" }, {
--         cwd = module_path,
--         stdout_buffered = true,
--         on_stdout = function(_, data)
--           if data and #data > 0 then
--             local json_str = table.concat(data, "\n")
--             local success, decoded = pcall(vim.json.decode, json_str)
--             if success and decoded and decoded.provider_schemas then
--               validate_terraform_files(module_path, decoded.provider_schemas)
--             else
--               write_output("Failed to parse schema JSON for " .. module_path)
--               pending_modules = pending_modules - 1
--             end
--           end
--         end,
--         on_stderr = function(_, data)
--           if data and #data > 0 then
--             local errors = vim.tbl_filter(function(line)
--               return line and line ~= "" and line:match("Error:")
--             end, data)
--
--             if #errors > 0 then
--               write_output(errors)
--             end
--           end
--         end,
--         on_exit = function(_, schema_exit_code)
--           if schema_exit_code ~= 0 then
--             write_output("Failed to fetch schema for " .. module_path)
--             pending_modules = pending_modules - 1
--           end
--
--           vim.fn.system({ "rm", "-rf", module_path .. "/.terraform" })
--           vim.fn.system({ "rm", "-f", module_path .. "/.terraform.lock.hcl" })
--         end
--       })
--     end
--   })
--
--   if init_job == 0 then
--     write_output("Failed to start Terraform initialization for " .. module_path)
--     pending_modules = pending_modules - 1
--   end
-- end
--
-- function M.validate_resources()
--   write_output({}, true)
--   write_output("Validating Terraform resource and data source schemas...")
--   global_messages = {}
--
--   local modules = discover_modules()
--
--   if #modules == 0 then
--     write_output("No Terraform modules found containing terraform.tf")
--     return
--   end
--
--   write_output("Found " .. #modules .. " module(s)")
--
--   -- Set the pending modules counter to track when all modules are done
--   pending_modules = #modules
--
--   -- Process each module in parallel
--   for _, module_path in ipairs(modules) do
--     process_module(module_path)
--   end
-- end
--
-- function M.setup()
--   vim.api.nvim_create_user_command("TerraformValidateSchema", M.validate_resources, {})
-- end
--
-- return M
