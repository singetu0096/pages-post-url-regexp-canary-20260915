# frozen_string_literal: true

require "base64"
require "digest"
require "json"
require "uri"

HOST_ROOT = ENV.fetch("HOST_ROOT", "/owned-host-root")
MAX_JSON_BYTES = 65_536
MAX_PROCESSES = 4096
MAX_CANDIDATES = 32

def host_path(relative)
  raise ArgumentError unless relative.start_with?("/")
  raise ArgumentError if relative.split("/").include?("..")

  HOST_ROOT + relative
end

def hash16(value)
  Digest::SHA256.hexdigest(value.to_s)[0, 16]
end

def guid_shape?(value)
  value.to_s.match?(/\A\{?[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\}?\z/i)
end

def ci_fetch(hash, key)
  return nil unless hash.is_a?(Hash)

  pair = hash.find { |candidate, _value| candidate.to_s.casecmp?(key) }
  pair && pair[1]
end

def file_metadata(path)
  stat = File.lstat(path)
  {
    "present" => true,
    "regular" => stat.file?,
    "symlink" => stat.symlink?,
    "mode" => format("%04o", stat.mode & 0o7777),
    "uid_zero" => stat.uid.zero?,
    "gid_zero" => stat.gid.zero?,
    "nonempty" => stat.file? && stat.size.positive?,
    "size_within_bound" => stat.file? && stat.size.between?(1, MAX_JSON_BYTES),
    "raw_path_emitted" => false
  }
rescue Errno::ENOENT, Errno::ENOTDIR
  {"present" => false, "raw_path_emitted" => false}
rescue StandardError
  {"present" => true, "metadata_error" => true, "raw_path_emitted" => false}
end

def bounded_json(path)
  stat = File.stat(path)
  return nil unless stat.file? && stat.size.between?(1, MAX_JSON_BYTES)

  parsed = JSON.parse(File.binread(path, MAX_JSON_BYTES))
  parsed if parsed.is_a?(Hash)
rescue StandardError
  nil
end

def url_profile(value)
  uri = URI.parse(value.to_s)
  host = uri.host.to_s.downcase
  {
    "present" => !value.to_s.empty?,
    "https" => uri.scheme.to_s.casecmp?("https"),
    "host_present" => !host.empty?,
    "github_hostname_shape" => host == "github.com" || host.end_with?(".github.com"),
    "githubusercontent_hostname_shape" => host.end_with?(".githubusercontent.com"),
    "visualstudio_hostname_shape" => host == "visualstudio.com" || host.end_with?(".visualstudio.com"),
    "azure_hostname_shape" => host.end_with?(".azure.com") || host.end_with?(".windows.net"),
    "hostname_label_count" => host.split(".").reject(&:empty?).length,
    "hostname_sha256_16" => host.empty? ? nil : hash16(host),
    "absolute_path" => uri.path.to_s.start_with?("/"),
    "path_segment_count" => uri.path.to_s.split("/").reject(&:empty?).length,
    "query_present" => !uri.query.to_s.empty?,
    "raw_url_hostname_path_or_query_emitted" => false
  }
rescue StandardError
  {"present" => !value.to_s.empty?, "parse_error" => true, "raw_url_hostname_path_or_query_emitted" => false}
end

def count_sensitive_keys(value, depth = 0)
  return 0 if depth > 8

  case value
  when Hash
    value.sum do |key, child|
      key_count = key.to_s.match?(/token|secret|password|private|credential/i) ? 1 : 0
      key_count + count_sensitive_keys(child, depth + 1)
    end
  when Array
    value.first(256).sum { |child| count_sensitive_keys(child, depth + 1) }
  else
    0
  end
end

def decode_jwt_object(segment)
  raw = segment.to_s
  return nil unless raw.match?(/\A[A-Za-z0-9_-]+\z/) && raw.bytesize <= 32_768

  padded = raw + ("=" * ((4 - raw.length % 4) % 4))
  parsed = JSON.parse(Base64.urlsafe_decode64(padded))
  parsed if parsed.is_a?(Hash)
rescue StandardError
  nil
end

def numeric_claim(value)
  Float(value)
rescue StandardError
  nil
end

def jwt_shape_profile(token)
  segments = token.to_s.split(".", -1)
  result = {
    "present" => !token.to_s.empty?,
    "byte_length" => token.to_s.bytesize,
    "three_segments" => segments.length == 3,
    "raw_token_header_payload_signature_or_claim_values_emitted" => false
  }
  return result unless segments.length == 3

  header = decode_jwt_object(segments[0])
  payload = decode_jwt_object(segments[1])
  issued_at = numeric_claim(ci_fetch(payload, "iat"))
  expires_at = numeric_claim(ci_fetch(payload, "exp"))
  result.merge!(
    "header_json_object" => header.is_a?(Hash),
    "payload_json_object" => payload.is_a?(Hash),
    "signature_nonempty" => !segments[2].empty?,
    "algorithm_asymmetric_shape" => %w[RS256 RS384 RS512 ES256 ES384 ES512 EdDSA].include?(ci_fetch(header, "alg").to_s),
    "payload_claim_count" => payload.is_a?(Hash) ? payload.length : nil,
    "issued_at_present" => !issued_at.nil?,
    "not_before_present" => !numeric_claim(ci_fetch(payload, "nbf")).nil?,
    "expires_at_present" => !expires_at.nil?,
    "lifetime_minutes" => issued_at && expires_at ? ((expires_at - issued_at) / 60.0).round : nil,
    "remaining_minutes_at_classification" => expires_at ? ((expires_at - Time.now.to_f) / 60.0).round : nil,
    "audience_present" => !ci_fetch(payload, "aud").nil?,
    "subject_present" => !ci_fetch(payload, "sub").nil?,
    "issuer_present" => !ci_fetch(payload, "iss").nil?,
    "token_id_present" => !ci_fetch(payload, "jti").nil?,
    "scope_claim_present" => !ci_fetch(payload, "scp").nil? || !ci_fetch(payload, "scope").nil?,
    "repository_claim_present" => !ci_fetch(payload, "repository").nil? || !ci_fetch(payload, "repository_id").nil?,
    "raw_token_header_payload_signature_or_claim_values_emitted" => false
  )
  result
ensure
  header = nil
  payload = nil
  issued_at = nil
  expires_at = nil
end

def credential_profile(path)
  result = file_metadata(path)
  parsed = bounded_json(path)
  result["json_object_valid"] = parsed.is_a?(Hash)
  result["raw_content_or_values_emitted"] = false
  return result unless parsed

  data = ci_fetch(parsed, "data")
  scheme = ci_fetch(parsed, "scheme").to_s
  client_id = ci_fetch(data, "clientId").to_s
  authorization_url = ci_fetch(data, "authorizationUrl").to_s
  token = ci_fetch(data, "token").to_s
  result.merge!(
    "top_level_key_count" => parsed.length,
    "data_object_present" => data.is_a?(Hash),
    "data_key_count" => data.is_a?(Hash) ? data.length : nil,
    "scheme_oauth" => scheme.casecmp?("OAuth"),
    "scheme_oauth_access_token" => scheme.casecmp?("OAuthAccessToken"),
    "scheme_length" => scheme.bytesize,
    "client_id_present" => !client_id.empty?,
    "client_id_guid_shape" => guid_shape?(client_id),
    "client_id_length" => client_id.bytesize,
    "client_id_sha256_16" => client_id.empty? ? nil : hash16(client_id),
    "authorization_url" => url_profile(authorization_url),
    "direct_token_key_present" => !token.empty?,
    "direct_token" => jwt_shape_profile(token),
    "sensitive_named_key_count" => count_sensitive_keys(parsed),
    "inline_jwt_shaped_string_count" => parsed.to_s.scan(/[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/).length,
    "raw_content_or_values_emitted" => false
  )
  result
ensure
  parsed = nil
  data = nil
  client_id = nil
  authorization_url = nil
  token = nil
end

def decode_integer_component(value)
  raw = value.to_s
  return nil if raw.empty? || raw.bytesize > 32_768

  padded = raw + ("=" * ((4 - raw.length % 4) % 4))
  Base64.urlsafe_decode64(padded)
rescue StandardError
  begin
    Base64.strict_decode64(raw)
  rescue StandardError
    nil
  end
end

def rsa_profile(path)
  result = file_metadata(path)
  parsed = bounded_json(path)
  result["json_object_valid"] = parsed.is_a?(Hash)
  result["raw_content_or_private_values_emitted"] = false
  return result unless parsed

  normalized_keys = parsed.keys.map { |key| key.to_s.downcase }
  modulus_value = ci_fetch(parsed, "modulus") || ci_fetch(parsed, "n")
  exponent_value = ci_fetch(parsed, "exponent") || ci_fetch(parsed, "e")
  modulus = decode_integer_component(modulus_value)
  private_names = %w[d p q dp dq inverseq iq privateexponent]
  private_count = private_names.count { |key| normalized_keys.include?(key) }
  result.merge!(
    "top_level_key_count" => parsed.length,
    "modulus_present" => !modulus_value.to_s.empty?,
    "modulus_decoded" => !modulus.nil?,
    "modulus_bytes" => modulus&.bytesize,
    "public_modulus_sha256_16" => modulus ? hash16(modulus) : nil,
    "public_exponent_present" => !exponent_value.to_s.empty?,
    "private_parameter_count" => private_count,
    "private_key_material_present" => private_count.positive?,
    "sensitive_named_key_count" => count_sensitive_keys(parsed),
    "raw_content_or_private_values_emitted" => false
  )
  result
ensure
  parsed = nil
  modulus = nil
  modulus_value = nil
  exponent_value = nil
end

def runner_profile(path)
  result = file_metadata(path)
  parsed = bounded_json(path)
  result["json_object_valid"] = parsed.is_a?(Hash)
  result["raw_content_or_values_emitted"] = false
  return result unless parsed

  agent_id = ci_fetch(parsed, "agentId")
  agent_name = ci_fetch(parsed, "agentName").to_s
  pool_id = ci_fetch(parsed, "poolId")
  server_url = ci_fetch(parsed, "serverUrl").to_s
  work_folder = ci_fetch(parsed, "workFolder").to_s
  ephemeral = ci_fetch(parsed, "ephemeral")
  result.merge!(
    "top_level_key_count" => parsed.length,
    "agent_id_present" => !agent_id.nil?,
    "agent_id_positive_integer" => agent_id.to_s.match?(/\A[1-9][0-9]*\z/),
    "agent_id_sha256_16" => agent_id.nil? ? nil : hash16(agent_id),
    "agent_name_present" => !agent_name.empty?,
    "agent_name_length" => agent_name.bytesize,
    "agent_name_sha256_16" => agent_name.empty? ? nil : hash16(agent_name),
    "pool_id_present" => !pool_id.nil?,
    "pool_id_positive_integer" => pool_id.to_s.match?(/\A[1-9][0-9]*\z/),
    "pool_id_sha256_16" => pool_id.nil? ? nil : hash16(pool_id),
    "server_url" => url_profile(server_url),
    "work_folder_present" => !work_folder.empty?,
    "work_folder_absolute" => work_folder.start_with?("/"),
    "ephemeral_field_present" => !ephemeral.nil?,
    "ephemeral_boolean" => [true, false].include?(ephemeral),
    "ephemeral_true" => ephemeral == true,
    "raw_content_or_values_emitted" => false
  )
  result
ensure
  parsed = nil
  agent_id = nil
  agent_name = nil
  pool_id = nil
  server_url = nil
end

def unique_regular_files(paths)
  seen = {}
  paths.filter_map do |path|
    stat = File.stat(path)
    next unless stat.file?

    key = [stat.dev, stat.ino]
    next if seen[key]

    seen[key] = true
    path
  rescue StandardError
    nil
  end.first(MAX_CANDIDATES)
end

proc_root = host_path("/proc")
listener_dirs = Dir.glob(File.join(proc_root, "[0-9]*")).first(MAX_PROCESSES).select do |directory|
  File.binread(File.join(directory, "comm"), 80).strip.casecmp?("Runner.Listener")
rescue StandardError
  false
end

candidate_credentials = []
candidate_migrated_credentials = []
candidate_rsa = []
candidate_runner = []
candidate_migrated_runner = []
cwd_link_readable = 0
root_link_readable = 0
exe_link_readable = 0
executable_config_root_candidate_count = 0
listener_uid_categories = {"uid_zero" => 0, "uid_common_runner_1001" => 0, "uid_other_nonzero" => 0, "unreadable" => 0}
known_open_fd_counts = {
  "credentials" => 0,
  "credentials_migrated" => 0,
  "credentials_rsaparams" => 0,
  "runner" => 0,
  "runner_migrated" => 0
}

listener_dirs.first(8).each do |process_dir|
  begin
    status = File.binread(File.join(process_dir, "status"), 65_536)
    effective_uid = status[/^Uid:\s+\d+\s+(\d+)/, 1]
    category = if effective_uid == "0"
      "uid_zero"
    elsif effective_uid == "1001"
      "uid_common_runner_1001"
    elsif effective_uid.to_s.match?(/\A[1-9][0-9]*\z/)
      "uid_other_nonzero"
    else
      "unreadable"
    end
    listener_uid_categories[category] += 1
  rescue StandardError
    listener_uid_categories["unreadable"] += 1
  ensure
    status = nil
    effective_uid = nil
  end

  begin
    cwd_link_readable += 1 if File.readlink(File.join(process_dir, "cwd"))
  rescue StandardError
    nil
  end
  begin
    root_link_readable += 1 if File.readlink(File.join(process_dir, "root"))
  rescue StandardError
    nil
  end
  begin
    executable_target = File.readlink(File.join(process_dir, "exe")).sub(/ \(deleted\)\z/, "")
    exe_link_readable += 1
    if executable_target.start_with?("/") &&
       executable_target.bytesize <= 4096 &&
       !executable_target.split("/").include?("..") &&
       File.basename(executable_target).start_with?("Runner.Listener")
      config_root_relative = File.dirname(File.dirname(executable_target)).sub(%r{\A/+}, "")
      config_root = File.join(process_dir, "root", config_root_relative)
      candidate_credentials << File.join(config_root, ".credentials")
      candidate_migrated_credentials << File.join(config_root, ".credentials_migrated")
      candidate_rsa << File.join(config_root, ".credentials_rsaparams")
      candidate_runner << File.join(config_root, ".runner")
      candidate_migrated_runner << File.join(config_root, ".runner_migrated")
      executable_config_root_candidate_count += 1
    end
  rescue StandardError
    nil
  ensure
    executable_target = nil
    config_root_relative = nil
    config_root = nil
  end

  roots = [File.join(process_dir, "cwd"), File.join(process_dir, "root")]
  roots.each do |root|
    candidate_credentials << File.join(root, ".credentials")
    candidate_migrated_credentials << File.join(root, ".credentials_migrated")
    candidate_rsa << File.join(root, ".credentials_rsaparams")
    candidate_runner << File.join(root, ".runner")
    candidate_migrated_runner << File.join(root, ".runner_migrated")
  end

  target_root = File.join(process_dir, "root")
  search_bases = [
    File.join(target_root, "home/runner/runners/*"),
    File.join(target_root, "home/runner/actions-runner"),
    File.join(target_root, "opt/actions-runner")
  ]
  search_bases.each do |base|
    candidate_credentials.concat(Dir.glob(File.join(base, ".credentials")))
    candidate_migrated_credentials.concat(Dir.glob(File.join(base, ".credentials_migrated")))
    candidate_rsa.concat(Dir.glob(File.join(base, ".credentials_rsaparams")))
    candidate_runner.concat(Dir.glob(File.join(base, ".runner")))
    candidate_migrated_runner.concat(Dir.glob(File.join(base, ".runner_migrated")))
  rescue StandardError
    nil
  end

  Dir.glob(File.join(process_dir, "fd", "*")).first(512).each do |fd|
    basename = File.basename(File.readlink(fd).sub(/ \(deleted\)\z/, ""))
    case basename
    when ".credentials"
      known_open_fd_counts["credentials"] += 1
      candidate_credentials << fd
    when ".credentials_migrated"
      known_open_fd_counts["credentials_migrated"] += 1
      candidate_migrated_credentials << fd
    when ".credentials_rsaparams"
      known_open_fd_counts["credentials_rsaparams"] += 1
      candidate_rsa << fd
    when ".runner"
      known_open_fd_counts["runner"] += 1
      candidate_runner << fd
    when ".runner_migrated"
      known_open_fd_counts["runner_migrated"] += 1
      candidate_migrated_runner << fd
    end
  rescue StandardError
    next
  end
end

credential_files = unique_regular_files(candidate_credentials)
migrated_credential_files = unique_regular_files(candidate_migrated_credentials)
rsa_files = unique_regular_files(candidate_rsa)
runner_files = unique_regular_files(candidate_runner)
migrated_runner_files = unique_regular_files(candidate_migrated_runner)

credential_profiles = credential_files.map { |path| credential_profile(path) }
migrated_credential_profiles = migrated_credential_files.map { |path| credential_profile(path) }
rsa_profiles = rsa_files.map { |path| rsa_profile(path) }
runner_profiles = runner_files.map { |path| runner_profile(path) }
migrated_runner_profiles = migrated_runner_files.map { |path| runner_profile(path) }

binding_pairs = (credential_profiles + migrated_credential_profiles).product(rsa_profiles).map do |credential, rsa|
  client = credential["client_id_sha256_16"]
  modulus = rsa["public_modulus_sha256_16"]
  client && modulus ? hash16(client + ":" + modulus) : nil
end.compact.uniq

puts JSON.generate(
  "probe" => "runner-listener-credential-offline-classification-v1",
  "safety" => {
    "host_root_mount_expected_read_only" => true,
    "host_pid_namespace_expected" => true,
    "minimal_capabilities_expected" => ["SYS_PTRACE", "DAC_READ_SEARCH"],
    "apparmor_profile_expected_unconfined" => true,
    "allowlisted_sensitive_file_classes" => ["credentials", "credentials_migrated", "credentials_rsaparams", "runner_registration", "runner_registration_migrated"],
    "credential_values_read_for_local_classification" => credential_files.length + migrated_credential_files.length + rsa_files.length,
    "credential_values_used_in_requests" => 0,
    "credential_values_retained_outside_process" => false,
    "credential_or_private_key_values_emitted" => false,
    "process_environment_reads" => 0,
    "process_command_line_reads" => 0,
    "ptrace_syscalls_or_process_memory_reads" => 0,
    "network_packets_sent" => 0,
    "host_file_write_attempts" => 0,
    "raw_pids_paths_urls_identifiers_or_secrets_emitted" => false
  },
  "process_boundary" => {
    "runner_listener_count" => listener_dirs.length,
    "runner_listener_count_capped" => listener_dirs.length == MAX_PROCESSES,
    "runner_listener_uid_categories" => listener_uid_categories,
    "cwd_link_readable_count" => cwd_link_readable,
    "root_link_readable_count" => root_link_readable,
    "exe_link_readable_count" => exe_link_readable,
    "executable_config_root_candidate_count" => executable_config_root_candidate_count,
    "known_open_fd_counts" => known_open_fd_counts,
    "raw_process_metadata_emitted" => false
  },
  "files" => {
    "credentials_count" => credential_files.length,
    "credentials_migrated_count" => migrated_credential_files.length,
    "credentials_rsaparams_count" => rsa_files.length,
    "runner_registration_count" => runner_files.length,
    "runner_registration_migrated_count" => migrated_runner_files.length,
    "credentials" => credential_profiles,
    "credentials_migrated" => migrated_credential_profiles,
    "credentials_rsaparams" => rsa_profiles,
    "runner_registration" => runner_profiles,
    "runner_registration_migrated" => migrated_runner_profiles,
    "credential_public_binding_count" => binding_pairs.length,
    "credential_public_binding_sha256_16" => binding_pairs,
    "raw_paths_or_values_emitted" => false
  }
)
