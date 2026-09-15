# frozen_string_literal: true

require "base64"
require "digest"
require "json"
require "time"
require "uri"

HOST_ROOT = ENV.fetch("HOST_ROOT", "/owned-host-root")
MAX_SETTINGS_BYTES = 65_536
MAX_BINARY_BYTES = 33_554_432

KNOWN_SETTINGS_KEYS = %w[
  authToken
  schedulerApiUrl
  traceApiUrl
  watchdogTraceApiUrl
  diagnosticsSasUri
  mode
  runnerCommand
  runnerSettings
  runnerAgentWorkingDirectory
  properties
].freeze

def host_path(relative)
  raise ArgumentError unless relative.start_with?("/")
  raise ArgumentError if relative.split("/").include?("..")

  HOST_ROOT + relative
end

def guid_shape?(value)
  value.to_s.match?(/\A[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/i)
end

def ci_fetch(hash, wanted)
  return nil unless hash.is_a?(Hash)

  pair = hash.find { |key, _value| key.to_s.casecmp?(wanted) }
  pair && pair[1]
end

def decode_jwt_json(segment)
  return nil unless segment.to_s.match?(/\A[A-Za-z0-9_-]+\z/)
  return nil if segment.bytesize > 32_768

  padded = segment + ("=" * ((4 - segment.length % 4) % 4))
  parsed = JSON.parse(Base64.urlsafe_decode64(padded))
  parsed if parsed.is_a?(Hash)
rescue StandardError
  nil
end

def numeric_time(value)
  Float(value)
rescue StandardError
  nil
end

def minute_value(seconds)
  return nil unless seconds && seconds.finite?

  (seconds / 60.0).round
end

def vm_name_value(subject)
  value = ci_fetch(subject, "VMName")
  return value.to_s if value.is_a?(String)

  ci_fetch(value, "Value").to_s if value.is_a?(Hash)
end

def safe_subject_profile(raw)
  profile = {
    "type_string" => raw.is_a?(String),
    "type_object" => raw.is_a?(Hash),
    "raw_value_emitted" => false
  }
  subject = if raw.is_a?(String) && raw.bytesize <= 16_384
    profile["string_length"] = raw.bytesize
    JSON.parse(raw)
  elsif raw.is_a?(Hash)
    raw
  end
  subject = nil unless subject.is_a?(Hash)
  profile["json_object_valid"] = subject.is_a?(Hash)
  profile["field_count"] = subject.length if subject
  [profile, subject]
rescue StandardError
  profile.merge("json_object_valid" => false, "parse_error" => true).then do |value|
    [value, nil]
  end
end

def jwt_profile(token)
  segments = token.to_s.split(".", -1)
  result = {
    "present" => !token.to_s.empty?,
    "three_segments" => segments.length == 3,
    "raw_token_emitted" => false,
    "signature_verified_or_used" => false
  }
  return result unless segments.length == 3

  header = decode_jwt_json(segments[0])
  payload = decode_jwt_json(segments[1])
  result["header_json_valid"] = header.is_a?(Hash)
  result["payload_json_valid"] = payload.is_a?(Hash)
  result["signature_segment_nonempty"] = !segments[2].empty?
  return result unless header && payload

  algorithm = ci_fetch(header, "alg").to_s
  normalized_algorithm = algorithm.downcase.gsub(/[^a-z0-9]/, "")
  token_type = ci_fetch(header, "typ").to_s
  result["header"] = {
    "algorithm_is_rs256" => algorithm == "RS256",
    "algorithm_is_asymmetric_allowlisted" => %w[RS256 RS384 RS512 ES256 ES384 ES512].include?(algorithm),
    "algorithm_is_none" => normalized_algorithm == "none",
    "algorithm_mentions_rsa" => normalized_algorithm.include?("rsa") || normalized_algorithm.start_with?("rs"),
    "algorithm_mentions_sha256" => normalized_algorithm.include?("sha256") || normalized_algorithm == "rs256",
    "algorithm_xml_uri_shape" => algorithm.start_with?("http://www.w3.org/") || algorithm.start_with?("https://www.w3.org/"),
    "algorithm_length" => algorithm.bytesize,
    "type_is_jwt" => token_type.casecmp?("JWT"),
    "raw_values_emitted" => false
  }

  subject_raw = ci_fetch(payload, "sub")
  subject_profile, subject = safe_subject_profile(subject_raw)

  host_id = ci_fetch(subject, "HostId").to_s
  pool_id = ci_fetch(subject, "PoolId")
  vm_name = vm_name_value(subject)
  agent_id = ci_fetch(subject, "AgentId").to_s
  scope = ci_fetch(payload, "scp").to_s
  audience_raw = ci_fetch(payload, "aud")
  audience = if audience_raw.is_a?(Array)
    audience_raw.map(&:to_s)
  elsif audience_raw.nil?
    []
  else
    [audience_raw.to_s]
  end
  issued_at = numeric_time(ci_fetch(payload, "iat"))
  not_before = numeric_time(ci_fetch(payload, "nbf"))
  expires_at = numeric_time(ci_fetch(payload, "exp"))
  now = Time.now.to_f
  subject_parts = [host_id, pool_id.to_s, vm_name.to_s, agent_id]

  result["claims"] = {
    "subject" => subject_profile,
    "subject_json_valid" => subject.is_a?(Hash),
    "subject_exact_identity_field_count" => subject.is_a?(Hash) && subject.length == 4,
    "host_id_guid_shaped" => guid_shape?(host_id),
    "pool_id_positive_integer" => pool_id.to_s.match?(/\A[1-9][0-9]*\z/),
    "vm_name_nonempty" => !vm_name.to_s.empty?,
    "agent_id_guid_shaped" => guid_shape?(agent_id),
    "scope_has_hca_agent_prefix" => scope.start_with?("HostedComputeAgent.Agent"),
    "scope_has_wildcard" => scope.include?("*"),
    "scope_component_count" => scope.split(/[\s:\/]+/).reject(&:empty?).length,
    "scope_embeds_all_subject_parts" => subject_parts.all? { |part| !part.empty? && scope.include?(part) },
    "audience_single_hca_deployment" => audience.length == 1 && audience[0].match?(/\Ahca:[0-9a-f-]{36}\z/i),
    "issuer_guid_shaped" => guid_shape?(ci_fetch(payload, "iss")),
    "issued_at_present" => !issued_at.nil?,
    "not_before_present" => !not_before.nil?,
    "expires_at_present" => !expires_at.nil?,
    "currently_time_valid" => !!(expires_at && expires_at > now && (!not_before || not_before <= now)),
    "lifetime_minutes" => minute_value(expires_at && issued_at && expires_at - issued_at),
    "remaining_minutes_at_classification" => minute_value(expires_at && expires_at - now),
    "raw_identity_or_claim_values_emitted" => false
  }
  result["_agent_id_for_local_comparison"] = agent_id if guid_shape?(agent_id)
  result
rescue StandardError
  result.merge("parse_error" => true, "raw_error_emitted" => false)
end

def endpoint_profile(raw)
  uri = URI.parse(raw.to_s)
  host = uri.host.to_s.downcase
  {
    "present" => !raw.to_s.empty?,
    "https" => uri.scheme.to_s.casecmp("https").zero?,
    "host_present" => !host.empty?,
    "github_dotcom_hostname_shape" => host == "github.com" || host.end_with?(".github.com"),
    "githubusercontent_hostname_shape" => host.end_with?(".githubusercontent.com"),
    "actions_githubusercontent_hostname_shape" => host == "actions.githubusercontent.com" || host.end_with?(".actions.githubusercontent.com"),
    "github_net_hostname_shape" => host == "github.net" || host.end_with?(".github.net"),
    "visualstudio_hostname_shape" => host == "visualstudio.com" || host.end_with?(".visualstudio.com"),
    "azure_service_hostname_shape" => host.end_with?(".azure.com") || host.end_with?(".windows.net"),
    "ip_literal_hostname" => host.match?(/\A(?:[0-9a-f:.]+)\z/i),
    "hostname_label_count" => host.split(".").reject(&:empty?).length,
    "absolute_path" => uri.path.to_s.start_with?("/"),
    "query_present" => !uri.query.to_s.empty?,
    "raw_url_or_hostname_emitted" => false
  }
rescue StandardError
  {"present" => !raw.to_s.empty?, "parse_error" => true, "raw_url_or_hostname_emitted" => false}
end

def each_scalar(value, depth = 0, &block)
  return if depth > 8

  case value
  when Hash
    value.each_value { |child| each_scalar(child, depth + 1, &block) }
  when Array
    value.first(256).each { |child| each_scalar(child, depth + 1, &block) }
  else
    block.call(value)
  end
end

def additional_settings_value_profile(settings)
  unknown = settings.to_h.reject do |key, _value|
    KNOWN_SETTINGS_KEYS.any? { |known| key.to_s.casecmp?(known) }
  end
  counts = {
    "unknown_top_level_key_count" => unknown.length,
    "scalar_count" => 0,
    "string_count" => 0,
    "jwt_shaped_string_count" => 0,
    "sas_uri_shaped_string_count" => 0,
    "https_uri_count" => 0,
    "private_key_marker_count" => 0,
    "long_opaque_string_count" => 0,
    "raw_keys_or_values_emitted" => false
  }
  each_scalar(unknown) do |value|
    counts["scalar_count"] += 1
    next unless value.is_a?(String)

    counts["string_count"] += 1
    next if value.bytesize > MAX_SETTINGS_BYTES

    counts["jwt_shaped_string_count"] += 1 if value.match?(/\A[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\z/)
    counts["private_key_marker_count"] += 1 if value.include?("BEGIN PRIVATE KEY") || value.include?("BEGIN RSA PRIVATE KEY")
    counts["long_opaque_string_count"] += 1 if value.bytesize >= 96 && value.match?(/\A[A-Za-z0-9+\/_=-]+\z/)
    begin
      uri = URI.parse(value)
      counts["https_uri_count"] += 1 if uri.scheme.to_s.casecmp?("https") && !uri.host.to_s.empty?
      query_keys = URI.decode_www_form(uri.query.to_s).map(&:first)
      counts["sas_uri_shaped_string_count"] += 1 if query_keys.include?("sig") && (query_keys.include?("sr") || query_keys.include?("ss"))
    rescue StandardError
      nil
    end
  end
  counts
rescue StandardError
  {"classification_error" => true, "raw_keys_or_values_emitted" => false}
end

def parse_sas_time(value)
  Time.iso8601(value.to_s).utc
rescue StandardError
  nil
end

def sas_profile(raw, agent_id)
  result = {
    "present" => !raw.to_s.empty?,
    "request_sent" => false,
    "raw_uri_hostname_path_query_or_signature_emitted" => false
  }
  return result if raw.to_s.empty?

  uri = URI.parse(raw.to_s)
  query = {}
  URI.decode_www_form(uri.query.to_s).each { |key, value| query[key] = value }
  permissions = query.fetch("sp", "")
  permission_allowlist = "racwdxltmeopiyf"
  path_segments = uri.path.to_s.split("/").reject(&:empty?)
  starts_on = parse_sas_time(query["st"])
  expires_on = parse_sas_time(query["se"])
  now = Time.now.utc
  account_sas = query.key?("ss") || query.key?("srt")
  user_delegation = %w[skoid sktid skt ske sks skv].all? { |key| query.key?(key) }

  result.merge!(
    "uri" => {
      "https" => uri.scheme.to_s.casecmp("https").zero?,
      "azure_public_blob_hostname_shape" => uri.host.to_s.downcase.end_with?(".blob.core.windows.net"),
      "single_container_path_segment" => path_segments.length == 1,
      "container_path_matches_subject_agent_id" => !agent_id.to_s.empty? && path_segments.first.to_s.downcase.end_with?(agent_id.to_s.downcase),
      "query_present" => !uri.query.to_s.empty?,
      "fragment_absent" => uri.fragment.nil?
    },
    "token_kind" => {
      "account_sas" => account_sas,
      "service_sas" => query.key?("sr") && !user_delegation,
      "user_delegation_sas" => user_delegation,
      "signature_present" => !query.fetch("sig", "").empty?
    },
    "scope" => {
      "account_services_blob_only" => query["ss"] == "b",
      "account_resource_types_object_only" => query["srt"] == "o",
      "signed_resource_blob" => query["sr"] == "b",
      "signed_resource_container" => query["sr"] == "c",
      "container_path_does_not_cryptographically_narrow_account_sas" => account_sas && path_segments.length == 1
    },
    "permissions" => {
      "read" => permissions.include?("r"),
      "add" => permissions.include?("a"),
      "create" => permissions.include?("c"),
      "write" => permissions.include?("w"),
      "delete" => permissions.include?("d"),
      "list" => permissions.include?("l"),
      "tag" => permissions.include?("t"),
      "move" => permissions.include?("m"),
      "execute" => permissions.include?("e"),
      "ownership" => permissions.include?("o"),
      "permissions_acl" => permissions.include?("p"),
      "set_immutability" => permissions.include?("i"),
      "permanent_delete" => permissions.include?("y"),
      "filter_by_tags" => permissions.include?("f"),
      "exact_add_create_write_set" => permissions.chars.sort == %w[a c w],
      "only_known_permission_characters" => permissions.chars.all? { |char| permission_allowlist.include?(char) },
      "permission_character_count" => permissions.length,
      "raw_permission_string_emitted" => false
    },
    "validity" => {
      "https_only_protocol" => query["spr"] == "https",
      "starts_on_present" => !starts_on.nil?,
      "expires_on_present" => !expires_on.nil?,
      "currently_time_valid" => !!(expires_on && expires_on > now && (!starts_on || starts_on <= now)),
      "signed_window_minutes" => minute_value(expires_on && starts_on && expires_on - starts_on),
      "remaining_minutes_at_classification" => minute_value(expires_on && expires_on - now)
    },
    "query_key_count" => query.length,
    "query_values_emitted" => false
  )
  result
rescue StandardError
  result.merge("parse_error" => true)
end

def strict_binary_metadata(data)
  module_match = data.match(%r{github\.com/github/hosted-compute-agent\tv0\.0\.0-(\d{14})-([0-9a-f]{12})\t})
  main_match = data.match(/main\.version=(\d{8}\.\d{1,8})/)
  vcs_match = data.match(/vcs\.revision=([0-9a-f]{40})/)
  go_match = data.match(/(?:^|[^A-Za-z0-9])go(1\.\d{1,2}(?:\.\d{1,2})?)(?:[^A-Za-z0-9]|$)/)
  dependency_patterns = {
    "azure_azblob" => %r{github\.com/Azure/azure-sdk-for-go/sdk/storage/azblob\tv([0-9]+\.[0-9]+\.[0-9]+)},
    "go_jose_v4" => %r{github\.com/go-jose/go-jose/v4\tv([0-9]+\.[0-9]+\.[0-9]+)},
    "golang_jwt_v5" => %r{github\.com/golang-jwt/jwt/v5\tv([0-9]+\.[0-9]+\.[0-9]+)},
    "x_net" => %r{golang\.org/x/net\tv([0-9]+\.[0-9]+\.[0-9]+)},
    "protobuf" => %r{google\.golang\.org/protobuf\tv([0-9]+\.[0-9]+\.[0-9]+)}
  }
  {
    "module_metadata_present" => !module_match.nil?,
    "module_timestamp" => module_match && module_match[1],
    "module_commit_prefix" => module_match && module_match[2],
    "main_version" => main_match && main_match[1],
    "vcs_revision" => vcs_match && vcs_match[1],
    "module_commit_matches_vcs_prefix" => !!(module_match && vcs_match && vcs_match[1].start_with?(module_match[2])),
    "go_version" => go_match && go_match[1],
    "dependencies" => dependency_patterns.transform_values do |pattern|
      match = data.match(pattern)
      match && match[1]
    end,
    "feature_symbols" => {
      "archive_untar" => data.include?("hosted-compute-agent/internal/archive.Untar"),
      "download_runner_agent" => data.include?("hosted-compute-agent/internal/environment.downloadRunnerAgent"),
      "start_abuse_tools" => data.include?("hosted-compute-agent/internal/environment.(*LinuxEnvironmentClient).StartAbuseTools"),
      "write_abuse_tools_override" => data.include?("hosted-compute-agent/internal/provisioner.(*Server).writeAbuseToolsOverride")
    },
    "only_strictly_allowlisted_public_build_values_emitted" => true,
    "raw_binary_content_emitted" => false
  }
end

def hca_binary_profile
  path = host_path("/opt/hca/hosted-compute-agent")
  stat = File.stat(path)
  return {"present" => false} unless stat.file?

  within_bound = stat.size.between?(1, MAX_BINARY_BYTES)
  data = within_bound ? File.binread(path, MAX_BINARY_BYTES).force_encoding(Encoding::BINARY) : "".b

  {
    "present" => true,
    "uid_zero" => stat.uid.zero?,
    "gid_zero" => stat.gid.zero?,
    "world_writable" => (stat.mode & 0o002).positive?,
    "owner_executable" => (stat.mode & 0o100).positive?,
    "size_bytes" => stat.size,
    "sha256" => Digest::SHA256.file(path).hexdigest,
    "metadata_scan_within_bound" => within_bound,
    "public_build_metadata" => within_bound ? strict_binary_metadata(data) : {"not_scanned" => true},
    "raw_binary_content_emitted" => false
  }
rescue Errno::ENOENT, Errno::ENOTDIR
  {"present" => false}
rescue StandardError
  {"present" => true, "classification_error" => true}
end


def fixed_path_profile(relative)
  path = host_path(relative)
  stat = File.lstat(path)
  {
    "present" => true,
    "regular_file" => stat.file?,
    "directory" => stat.directory?,
    "symlink" => stat.symlink?,
    "uid_zero" => stat.uid.zero?,
    "gid_zero" => stat.gid.zero?,
    "owner_writable" => (stat.mode & 0o200).positive?,
    "group_writable" => (stat.mode & 0o020).positive?,
    "world_writable" => (stat.mode & 0o002).positive?,
    "owner_executable" => (stat.mode & 0o100).positive?,
    "size_bytes" => stat.file? ? stat.size : nil,
    "raw_path_or_content_emitted" => false
  }
rescue Errno::ENOENT, Errno::ENOTDIR
  {"present" => false, "raw_path_or_content_emitted" => false}
rescue StandardError
  {"present" => true, "classification_error" => true, "raw_path_or_content_emitted" => false}
end

def hca_filesystem_profile
  entries = Dir.children(host_path("/opt/hca")).first(256)
  temp_candidates = Dir.glob(host_path("/tmp/provjobd*"), File::FNM_DOTMATCH).first(32)
  {
    "root_directory" => fixed_path_profile("/opt/hca"),
    "settings" => fixed_path_profile("/opt/hca/.settings"),
    "hosted_compute_agent" => fixed_path_profile("/opt/hca/hosted-compute-agent"),
    "legacy_hca_name" => fixed_path_profile("/opt/hca/hca"),
    "provjobd_source" => fixed_path_profile("/opt/hca/provjobd"),
    "bounded_directory_entry_count" => entries.length,
    "bounded_temp_provjobd_candidate_count" => temp_candidates.length,
    "temp_candidates_world_writable_count" => temp_candidates.count do |path|
      (File.lstat(path).mode & 0o002).positive?
    rescue StandardError
      false
    end,
    "raw_entry_names_paths_or_content_emitted" => false
  }
rescue StandardError
  {"classification_error" => true, "raw_entry_names_paths_or_content_emitted" => false}
end

def sudoers_profile
  paths = [host_path("/etc/sudoers")] + Dir.glob(host_path("/etc/sudoers.d/*")).first(64)
  contents = paths.filter_map do |path|
    next unless File.file?(path) && File.size(path) <= 131_072

    File.binread(path, 131_072)
  rescue StandardError
    nil
  end
  text = contents.join("\n")
  active = text.lines.reject { |line| line.lstrip.start_with?("#") }.join
  {
    "bounded_file_count" => paths.length,
    "content_read_count" => contents.length,
    "nopasswd_present" => active.match?(/NOPASSWD\s*:/i),
    "nopasswd_all_command_shape" => active.match?(/NOPASSWD\s*:\s*ALL(?:\s|$)/i),
    "provjobd_command_shape" => active.match?(/provjobd/i),
    "tmp_provjobd_wildcard_shape" => active.match?(%r{/tmp/provjobd[^\s,]*[*?][^\s,]*}i),
    "opt_hca_command_shape" => active.match?(%r{/opt/hca/}i),
    "raw_rules_users_paths_or_content_emitted" => false
  }
rescue StandardError
  {"classification_error" => true, "raw_rules_users_paths_or_content_emitted" => false}
end

def systemd_profile
  patterns = [
    "/etc/systemd/system/*hosted*compute*.service",
    "/etc/systemd/system/*hca*.service",
    "/usr/lib/systemd/system/*hosted*compute*.service",
    "/usr/lib/systemd/system/*hca*.service"
  ]
  paths = patterns.flat_map { |pattern| Dir.glob(host_path(pattern)) }.uniq.first(16)
  contents = paths.filter_map do |path|
    next unless File.file?(path) && File.size(path) <= 65_536

    File.binread(path, 65_536)
  rescue StandardError
    nil
  end
  active_lines = contents.flat_map do |content|
    content.lines.map(&:strip).reject { |line| line.empty? || line.start_with?("#", ";") }
  end
  value_for = lambda do |name|
    line = active_lines.reverse.find { |entry| entry.match?(/\A#{Regexp.escape(name)}\s*=/i) }
    line.to_s.split("=", 2)[1].to_s.strip.downcase
  end
  user = value_for.call("User")
  exec_start = value_for.call("ExecStart")
  {
    "unit_count" => paths.length,
    "content_read_count" => contents.length,
    "runs_as_root_explicitly" => user == "root",
    "runs_as_nonroot_explicitly" => !user.empty? && user != "root",
    "user_directive_present" => !user.empty?,
    "executes_hosted_compute_agent" => exec_start.include?("hosted-compute-agent") || exec_start.end_with?("/hca"),
    "restart_on_failure" => value_for.call("Restart") == "on-failure",
    "uses_hca_environment_file" => active_lines.any? { |line| line.match?(/\AEnvironmentFile\s*=.*hca\.env/i) },
    "no_new_privileges_enabled" => value_for.call("NoNewPrivileges") == "yes",
    "private_tmp_enabled" => value_for.call("PrivateTmp") == "yes",
    "private_devices_enabled" => value_for.call("PrivateDevices") == "yes",
    "protect_home_enabled" => %w[yes read-only tmpfs].include?(value_for.call("ProtectHome")),
    "protect_system_strong" => %w[strict full].include?(value_for.call("ProtectSystem")),
    "capability_bounding_set_present" => active_lines.any? { |line| line.match?(/\ACapabilityBoundingSet\s*=/i) },
    "restrict_address_families_present" => active_lines.any? { |line| line.match?(/\ARestrictAddressFamilies\s*=/i) },
    "raw_unit_paths_or_content_emitted" => false
  }
rescue StandardError
  {"classification_error" => true, "raw_unit_paths_or_content_emitted" => false}
end

def process_profile
  categories = {
    "hosted_compute_agent" => [],
    "provisioning_job_daemon" => [],
    "runner_listener" => [],
    "runner_worker" => []
  }
  Dir.glob(host_path("/proc/[0-9]*")).first(4096).each do |directory|
    comm = File.binread(File.join(directory, "comm"), 80).strip.downcase
    category = if comm.include?("hosted-compute") || comm == "hca"
      "hosted_compute_agent"
    elsif comm.include?("provjobd")
      "provisioning_job_daemon"
    elsif comm.include?("runner.listener")
      "runner_listener"
    elsif comm.include?("runner.worker")
      "runner_worker"
    end
    next unless category

    status = File.binread(File.join(directory, "status"), 65_536)
    effective_uid = status[/^Uid:\s+\d+\s+(\d+)/, 1]
    cap_eff = status[/^CapEff:\s+([0-9a-f]+)/i, 1]
    entry = {
      "effective_uid_zero" => effective_uid == "0",
      "effective_uid_known" => !effective_uid.nil?,
      "effective_capabilities_nonzero" => !cap_eff.to_s.match?(/\A0+\z/),
      "executable_link_readable" => false,
      "executable_under_opt_hca" => false,
      "executable_under_runner_home" => false
    }
    begin
      executable = File.readlink(File.join(directory, "exe"))
      entry["executable_link_readable"] = true
      entry["executable_under_opt_hca"] = executable.start_with?("/opt/hca/")
      entry["executable_under_runner_home"] = executable.start_with?("/home/runner/")
    rescue StandardError
      nil
    end
    categories[category] << entry
  rescue StandardError
    next
  end

  categories.transform_values do |entries|
    {
      "count" => entries.length,
      "effective_uid_zero_count" => entries.count { |entry| entry["effective_uid_zero"] },
      "effective_capabilities_nonzero_count" => entries.count { |entry| entry["effective_capabilities_nonzero"] },
      "executable_link_readable_count" => entries.count { |entry| entry["executable_link_readable"] },
      "executable_under_opt_hca_count" => entries.count { |entry| entry["executable_under_opt_hca"] },
      "executable_under_runner_home_count" => entries.count { |entry| entry["executable_under_runner_home"] }
    }
  end.merge(
    "process_environment_reads" => 0,
    "process_command_line_reads" => 0,
    "raw_pids_paths_capability_masks_or_names_emitted" => false
  )
rescue StandardError
  {
    "classification_error" => true,
    "process_environment_reads" => 0,
    "process_command_line_reads" => 0,
    "raw_pids_paths_capability_masks_or_names_emitted" => false
  }
end


def runner_credential_metadata_profile
  patterns = %w[.credentials .credentials_rsaparams .runner]
  results = {}
  patterns.each do |basename|
    candidates = [
      "/home/runner/actions-runner/" + basename,
      "/home/runner/runner/" + basename,
      "/opt/runner-cache/Latest/" + basename,
      "/opt/actions-runner/" + basename,
      "/actions-runner/" + basename
    ]
    cache_candidates = Dir.glob(host_path("/opt/runner-cache/*/" + basename), File::FNM_DOTMATCH).first(32)
    paths = (candidates.map { |path| host_path(path) } + cache_candidates).uniq.select do |path|
      File.exist?(path)
    rescue StandardError
      false
    end.first(32)
    results[basename.delete_prefix(".")] = {
      "bounded_count" => paths.length,
      "regular_file_count" => paths.count { |path| File.file?(path) },
      "world_readable_count" => paths.count { |path| (File.stat(path).mode & 0o004).positive? },
      "world_writable_count" => paths.count { |path| (File.stat(path).mode & 0o002).positive? }
    }
  end
  results.merge(
    "content_reads" => 0,
    "raw_paths_or_values_emitted" => false
  )
rescue StandardError
  {"classification_error" => true, "content_reads" => 0, "raw_paths_or_values_emitted" => false}
end

begin
settings_path = host_path("/opt/hca/.settings")
settings_stat = File.stat(settings_path)
settings_size_ok = settings_stat.file? && settings_stat.size.between?(1, MAX_SETTINGS_BYTES)
settings_raw = settings_size_ok ? File.binread(settings_path, MAX_SETTINGS_BYTES) : ""
settings = settings_size_ok ? JSON.parse(settings_raw) : nil
settings = nil unless settings.is_a?(Hash)

auth_token = ci_fetch(settings, "authToken").to_s
jwt = jwt_profile(auth_token)
agent_id = jwt.delete("_agent_id_for_local_comparison").to_s
scheduler = ci_fetch(settings, "schedulerApiUrl").to_s
trace = ci_fetch(settings, "traceApiUrl").to_s
diagnostics = ci_fetch(settings, "diagnosticsSasUri").to_s
properties = ci_fetch(settings, "properties")

output = {
  "probe" => "hca-authority-offline-classification-v2",
  "safety" => {
    "host_root_mount_expected_read_only" => true,
    "sensitive_file_content_reads" => settings_size_ok ? 1 : 0,
    "credential_values_read_for_local_classification" => settings_size_ok ? 1 : 0,
    "credential_values_used_in_requests" => 0,
    "credential_values_retained_outside_process" => false,
    "credential_values_emitted" => false,
    "network_packets_sent" => 0,
    "host_file_write_attempts" => 0,
    "process_environment_reads" => 0,
    "process_command_line_reads" => 0,
    "device_open_calls" => 0,
    "raw_identifiers_urls_paths_or_secrets_emitted" => false
  },
  "settings" => {
    "present" => settings_stat.file?,
    "size_within_bound" => settings_size_ok,
    "json_object_valid" => settings.is_a?(Hash),
    "expected_key_presence" => {
      "auth_token" => !auth_token.empty?,
      "scheduler_api_url" => !scheduler.empty?,
      "trace_api_url" => !trace.empty?,
      "diagnostics_sas_uri" => !diagnostics.empty?,
      "properties" => properties.is_a?(Hash)
    },
    "top_level_key_count" => settings.is_a?(Hash) ? settings.length : 0,
    "known_top_level_key_count" => settings.is_a?(Hash) ? settings.keys.count { |key| KNOWN_SETTINGS_KEYS.any? { |known| key.to_s.casecmp?(known) } } : 0,
    "properties_count" => properties.is_a?(Hash) ? properties.length : nil,
    "uid_zero" => settings_stat.uid.zero?,
    "gid_zero" => settings_stat.gid.zero?,
    "world_readable" => (settings_stat.mode & 0o004).positive?,
    "world_writable" => (settings_stat.mode & 0o002).positive?,
    "raw_content_or_values_emitted" => false
  },
  "additional_settings_values" => additional_settings_value_profile(settings),
  "hca_auth_token" => jwt,
  "scheduler_endpoint" => endpoint_profile(scheduler),
  "trace_endpoint" => endpoint_profile(trace),
  "diagnostics_sas" => sas_profile(diagnostics, agent_id),
  "hca_binary" => hca_binary_profile,
  "hca_filesystem" => hca_filesystem_profile,
  "hca_systemd" => systemd_profile,
  "hca_sudoers" => sudoers_profile,
  "selected_processes" => process_profile,
  "runner_credential_files" => runner_credential_metadata_profile
}

auth_token = nil
diagnostics = nil
scheduler = nil
trace = nil
settings_raw = nil
settings = nil
agent_id = nil

puts JSON.generate(output)
rescue Errno::ENOENT, Errno::ENOTDIR
  puts JSON.generate(
    "probe" => "hca-authority-offline-classification-v2",
    "settings" => {"present" => false},
    "safety" => {
      "credential_values_used_in_requests" => 0,
      "credential_values_emitted" => false,
      "network_packets_sent" => 0,
      "host_file_write_attempts" => 0
    }
  )
rescue StandardError
  puts JSON.generate(
    "probe" => "hca-authority-offline-classification-v2",
    "classification_error" => true,
    "safety" => {
      "credential_values_used_in_requests" => 0,
      "credential_values_emitted" => false,
      "network_packets_sent" => 0,
      "host_file_write_attempts" => 0
    }
  )
end
