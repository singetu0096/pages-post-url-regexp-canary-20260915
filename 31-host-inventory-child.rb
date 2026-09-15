# frozen_string_literal: true

require "json"

HOST_ROOT = ENV.fetch("HOST_ROOT", "/owned-host-root")

def host_path(relative)
  raise ArgumentError unless relative.start_with?("/")
  raise ArgumentError if relative.split("/").include?("..")

  HOST_ROOT + relative
end

def entry_metadata(relative)
  path = host_path(relative)
  stat = File.stat(path)
  {
    "present" => true,
    "regular" => stat.file?,
    "directory" => stat.directory?,
    "symlink" => File.lstat(path).symlink?,
    "uid_zero" => stat.uid.zero?,
    "gid_zero" => stat.gid.zero?,
    "mode" => format("%04o", stat.mode & 0o7777),
    "nonempty" => stat.file? && stat.size.positive?,
    "metadata_process_readable" => File.readable?(path),
    "metadata_process_writable" => File.writable?(path)
  }
rescue Errno::ENOENT, Errno::ENOTDIR
  {"present" => false}
rescue StandardError
  {"present" => true, "metadata_error" => true}
end

def glob_metadata(patterns, limit: 512)
  matches = patterns.flat_map { |pattern| Dir.glob(host_path(pattern)) }
  matches = matches.uniq.first(limit)
  stats = matches.filter_map do |path|
    File.stat(path)
  rescue StandardError
    nil
  end
  {
    "count" => matches.length,
    "count_capped" => matches.length == limit,
    "regular_count" => stats.count(&:file?),
    "directory_count" => stats.count(&:directory?),
    "nonempty_regular_count" => stats.count { |stat| stat.file? && stat.size.positive? },
    "uid_zero_count" => stats.count { |stat| stat.uid.zero? },
    "metadata_readable_count" => matches.count { |path| File.readable?(path) },
    "metadata_writable_count" => matches.count { |path| File.writable?(path) }
  }
rescue StandardError
  {"enumeration_error" => true}
end

def read_allowlisted(relative, maximum_bytes)
  File.binread(host_path(relative), maximum_bytes)
rescue StandardError
  ""
end

def process_profile
  directories = Dir.glob(host_path("/proc/[0-9]*")).first(4096)
  flags = {
    "runner_listener" => false,
    "runner_worker" => false,
    "runner_plugin_host" => false,
    "hosted_compute_agent" => false,
    "provisioning_job_daemon" => false,
    "walinuxagent" => false,
    "cloud_init" => false,
    "dockerd" => false,
    "containerd" => false,
    "sshd" => false
  }

  directories.each do |directory|
    comm = File.binread(File.join(directory, "comm"), 80).strip.downcase
    flags["runner_listener"] ||= comm.include?("runner.listener")
    flags["runner_worker"] ||= comm.include?("runner.worker")
    flags["runner_plugin_host"] ||= comm.include?("runner.plugin")
    flags["hosted_compute_agent"] ||=
      comm.include?("hosted-compute") || comm == "hca"
    flags["provisioning_job_daemon"] ||= comm.include?("provjobd")
    flags["walinuxagent"] ||= comm.include?("waagent")
    flags["cloud_init"] ||= comm.include?("cloud-init")
    flags["dockerd"] ||= comm == "dockerd"
    flags["containerd"] ||= comm.start_with?("containerd")
    flags["sshd"] ||= comm.include?("sshd")
  rescue StandardError
    next
  end

  flags.merge(
    "process_count" => directories.length,
    "process_count_capped" => directories.length == 4096,
    "command_line_reads" => 0,
    "environment_reads" => 0
  )
rescue StandardError
  {"enumeration_error" => true, "command_line_reads" => 0, "environment_reads" => 0}
end

def socket_address_class(hex, family)
  if family == :ipv4
    return "wildcard" if hex == "00000000"
    return "loopback" if hex == "0100007F"
    return "link_local" if hex.end_with?("FEA9")
  else
    return "wildcard" if hex.match?(/\A0+\z/)
    return "loopback" if ["00000000000000000000000001000000", "00000000000000000000000000000001"].include?(hex)
    return "link_local" if hex.start_with?("0000000000000000") && hex.end_with?("000000FE")
  end
  "other"
end

def internet_socket_profile(relative, family, tcp:)
  data = read_allowlisted(relative, 1_048_576)
  classes = Hash.new(0)
  known_ports = []
  known_allowlist = [22, 53, 80, 443, 2375, 2376, 3128, 32526, 40342, 40343, 40344]
  entry_count = 0

  data.lines.drop(1).first(4096).each do |line|
    fields = line.split
    next if fields.length < 4
    next if tcp && fields[3] != "0A"

    local = fields[1].to_s
    address_hex, port_hex = local.split(":", 2)
    next unless address_hex && port_hex

    entry_count += 1
    classes[socket_address_class(address_hex, family)] += 1
    port = port_hex.to_i(16)
    known_ports << port if known_allowlist.include?(port)
  end

  {
    "entry_count" => entry_count,
    "wildcard_count" => classes["wildcard"],
    "loopback_count" => classes["loopback"],
    "link_local_count" => classes["link_local"],
    "other_address_count" => classes["other"],
    "allowlisted_port_presence" => known_ports.uniq.sort
  }
rescue StandardError
  {"parse_error" => true}
end

def unix_socket_profile
  data = read_allowlisted("/proc/1/net/unix", 1_048_576)
  keyword_counts = {
    "docker" => 0,
    "containerd" => 0,
    "runner" => 0,
    "hca" => 0,
    "waagent" => 0,
    "systemd" => 0
  }
  path_count = 0
  abstract_count = 0

  data.lines.drop(1).first(4096).each do |line|
    fields = line.split
    next if fields.empty?

    path = fields[7].to_s.downcase
    next if path.empty?

    path_count += 1
    abstract_count += 1 if path.start_with?("@")
    keyword_counts.each_key do |keyword|
      keyword_counts[keyword] += 1 if path.include?(keyword)
    end
  end

  {
    "named_socket_count" => path_count,
    "abstract_socket_count" => abstract_count,
    "keyword_counts" => keyword_counts,
    "raw_paths_emitted" => false
  }
rescue StandardError
  {"parse_error" => true, "raw_paths_emitted" => false}
end

def network_shape
  device_data = read_allowlisted("/proc/1/net/dev", 262_144)
  interface_names = device_data.lines.drop(2).filter_map do |line|
    name = line.split(":", 2).first.to_s.strip
    name unless name.empty?
  end
  route_data = read_allowlisted("/proc/1/net/route", 262_144)
  routes = route_data.lines.drop(1).map(&:split).select { |fields| fields.length >= 8 }
  {
    "interface_count" => interface_names.length,
    "non_loopback_interface_count" => interface_names.count { |name| name != "lo" },
    "route_count" => routes.length,
    "default_route_present" => routes.any? { |fields| fields[1] == "00000000" },
    "tcp4_listeners" => internet_socket_profile("/proc/1/net/tcp", :ipv4, tcp: true),
    "tcp6_listeners" => internet_socket_profile("/proc/1/net/tcp6", :ipv6, tcp: true),
    "udp4_bound" => internet_socket_profile("/proc/1/net/udp", :ipv4, tcp: false),
    "udp6_bound" => internet_socket_profile("/proc/1/net/udp6", :ipv6, tcp: false),
    "unix_sockets" => unix_socket_profile,
    "packets_sent" => 0,
    "raw_addresses_emitted" => false,
    "raw_interface_names_emitted" => false
  }
rescue StandardError
  {"parse_error" => true, "packets_sent" => 0, "raw_addresses_emitted" => false}
end

def hyperv_profile
  module_names = read_allowlisted("/proc/modules", 1_048_576).lines.map do |line|
    line.split.first.to_s
  end
  allowlist = %w[
    hv_vmbus hv_utils hv_balloon hv_netvsc hv_storvsc hv_sock
    hid_hyperv hyperv_keyboard hyperv_drm pci_hyperv
  ]
  {
    "vmbus_sysfs_present" => File.directory?(host_path("/sys/bus/vmbus")),
    "vmbus_device_count" => Dir.glob(host_path("/sys/bus/vmbus/devices/*")).first(512).length,
    "vmbus_character_device_present" => File.exist?(host_path("/dev/vmbus")),
    "hv_kvp_device_present" => File.exist?(host_path("/dev/hv_kvp_dev")),
    "hv_vss_device_present" => File.exist?(host_path("/dev/hv_vss")),
    "hv_fcopy_device_present" => File.exist?(host_path("/dev/hv_fcopy")),
    "hidraw_device_count" => Dir.glob(host_path("/dev/hidraw*")).first(128).length,
    "allowlisted_loaded_modules" => allowlist.select { |name| module_names.include?(name) },
    "device_open_calls" => 0,
    "device_write_calls" => 0,
    "hypercall_attempts" => 0
  }
rescue StandardError
  {"parse_error" => true, "device_open_calls" => 0, "device_write_calls" => 0, "hypercall_attempts" => 0}
end

runner_files = {
  "runner_registration" => glob_metadata([
    "/home/runner/runners/*/.runner",
    "/home/runner/actions-runner/.runner",
    "/opt/actions-runner/.runner"
  ]),
  "runner_oauth_credentials" => glob_metadata([
    "/home/runner/runners/*/.credentials",
    "/home/runner/actions-runner/.credentials",
    "/opt/actions-runner/.credentials"
  ]),
  "runner_rsa_parameters" => glob_metadata([
    "/home/runner/runners/*/.credentials_rsaparams",
    "/home/runner/actions-runner/.credentials_rsaparams",
    "/opt/actions-runner/.credentials_rsaparams"
  ]),
  "runner_install_directories" => glob_metadata([
    "/home/runner/runners/*",
    "/home/runner/actions-runner",
    "/opt/actions-runner"
  ]),
  "runner_systemd_units" => glob_metadata([
    "/etc/systemd/system/actions.runner*.service",
    "/etc/systemd/system/runner*.service"
  ])
}

hca_files = {
  "settings" => entry_metadata("/opt/hca/.settings"),
  "hca_binary" => entry_metadata("/opt/hca/hca"),
  "hosted_compute_agent_binary" => entry_metadata("/opt/hca/hosted-compute-agent"),
  "provisioning_job_daemon" => entry_metadata("/opt/hca/provjobd"),
  "hca_tree_entries" => glob_metadata(["/opt/hca/*"]),
  "systemd_units" => glob_metadata([
    "/etc/systemd/system/*hosted*compute*.service",
    "/etc/systemd/system/*hca*.service"
  ])
}

azure_agent_files = {
  "waagent_state_directory" => entry_metadata("/var/lib/waagent"),
  "ovf_environment" => entry_metadata("/var/lib/waagent/ovf-env.xml"),
  "hosting_environment" => entry_metadata("/var/lib/waagent/HostingEnvironmentConfig.xml"),
  "wire_server_endpoint" => entry_metadata("/var/lib/waagent/WireServerEndpoint"),
  "certificates_pem" => entry_metadata("/var/lib/waagent/Certificates.pem"),
  "transport_certificate" => entry_metadata("/var/lib/waagent/TransportCert.pem"),
  "goal_state_files" => glob_metadata(["/var/lib/waagent/GoalState.*.xml"]),
  "extension_config_files" => glob_metadata(["/var/lib/waagent/ExtensionsConfig.*.xml"]),
  "extension_setting_files" => glob_metadata(["/var/lib/waagent/*/config/*.settings"]),
  "protected_named_files" => glob_metadata([
    "/var/lib/waagent/*/config/*protected*",
    "/var/lib/waagent/*/*protected*"
  ]),
  "extension_status_files" => glob_metadata(["/var/lib/waagent/*/status/*.status"]),
  "waagent_systemd_units" => glob_metadata([
    "/etc/systemd/system/*waagent*.service",
    "/usr/lib/systemd/system/*waagent*.service"
  ])
}

cloud_init_files = {
  "instance_directory" => entry_metadata("/var/lib/cloud/instance"),
  "user_data" => entry_metadata("/var/lib/cloud/instance/user-data.txt"),
  "vendor_data" => entry_metadata("/var/lib/cloud/instance/vendor-data.txt"),
  "instance_data" => entry_metadata("/var/lib/cloud/instance/instance-data.json"),
  "sensitive_instance_data" => entry_metadata("/var/lib/cloud/instance/instance-data-sensitive.json"),
  "instance_user_data_files" => glob_metadata(["/var/lib/cloud/instances/*/user-data.txt"]),
  "instance_vendor_data_files" => glob_metadata(["/var/lib/cloud/instances/*/vendor-data.txt"]),
  "instance_sensitive_data_files" => glob_metadata(["/var/lib/cloud/instances/*/instance-data-sensitive.json"]),
  "instance_script_entries" => glob_metadata(["/var/lib/cloud/instances/*/scripts/*"])
}

host_service_files = {
  "docker_socket" => entry_metadata("/var/run/docker.sock"),
  "containerd_socket" => entry_metadata("/run/containerd/containerd.sock"),
  "ssh_host_key_files" => glob_metadata(["/etc/ssh/ssh_host_*_key"]),
  "systemd_private_runtime_directories" => glob_metadata(["/run/systemd/*"])
}

sys_vendor = read_allowlisted("/sys/class/dmi/id/sys_vendor", 256).strip
product_name = read_allowlisted("/sys/class/dmi/id/product_name", 256).strip

puts JSON.generate(
  "probe" => "host-boundary-metadata-only-v1",
  "safety" => {
    "host_root_mount_expected_read_only" => true,
    "sensitive_file_content_reads" => 0,
    "credential_value_reads" => 0,
    "process_environment_reads" => 0,
    "process_command_line_reads" => 0,
    "network_packets_sent" => 0,
    "host_file_write_attempts" => 0,
    "device_open_calls" => 0,
    "raw_paths_emitted" => false,
    "raw_addresses_emitted" => false,
    "credential_values_emitted" => false
  },
  "runner_files" => runner_files,
  "hosted_compute_agent_files" => hca_files,
  "azure_agent_files" => azure_agent_files,
  "cloud_init_files" => cloud_init_files,
  "host_service_files" => host_service_files,
  "processes" => process_profile,
  "network_shape" => network_shape,
  "hyperv" => hyperv_profile,
  "platform_identity" => {
    "microsoft_sys_vendor" => sys_vendor.casecmp("Microsoft Corporation").zero?,
    "hyper_v_product_name" => product_name.downcase.include?("virtual machine"),
    "raw_values_emitted" => false
  }
)
