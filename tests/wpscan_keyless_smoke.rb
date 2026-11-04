# Installed WPScan controller preflight only. Run with --network none.
require 'wpscan'
ENV.delete('WPSCAN_API_TOKEN')
WPScan::DB::VulnApi.token = nil
WPScan::ParsedCli.options = { enumerate: { popular_plugins: true, popular_themes: true } }
WPScan::Controller::Enumeration.new.before_scan
WPScan::ParsedCli.options = { enumerate: { vulnerable_plugins: true, vulnerable_themes: true } }
blocked = false
begin
  WPScan::Controller::Enumeration.new.before_scan
rescue WPScan::Error::ApiTokenRequiredForVulnerableEnumeration
  blocked = true
end
raise 'native token requirement was not exercised' unless blocked
puts 'Installed WPScan keyless inventory preflight passed; no scan or network'
