# Offline unit tests: no WPScan or network requests are invoked.
require_relative '../app/wpscan_scope'

class FakeBrowser
  attr_reader :seen
  def forge_request(url, params = {})
    @seen = [url, params]
  end
end
FakeBrowser.prepend(ASFBWPScanScope)
ASFBWPScanScope.target = 'https://example.org/blog/'
browser = FakeBrowser.new
browser.forge_request('https://example.org/blog/a', followlocation: true, maxredirs: 3)
raise 'redirect following was not disabled' unless
  browser.seen[1][:followlocation] == false && browser.seen[1][:maxredirs] == 0
['https://other.example.org/', 'https://example.org:8443/', 'http://example.org/',
 'file:///etc/passwd', 'https://user:pass@example.org/'].each do |url|
  blocked = false
  begin
    browser.forge_request(url)
  rescue ArgumentError
    blocked = true
  end
  raise "scope guard failed for #{url}" unless blocked
end
puts 'WPScan scope guard: offline checks passed'
