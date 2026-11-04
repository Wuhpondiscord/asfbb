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
ENV['ASFB_TARGET_POLICY'] = JSON.generate({
  'path' => '/blog/', 'headers' => {'X-HackerOne-Research' => 'fixture'}, 'agent' => 'Required-Fixture',
  'exclusions' => ['/blog/private/']
})
browser.forge_request('https://example.org/blog/page', headers: {'User-Agent' => 'Wrong'})
raise 'mandatory header absent' unless browser.seen[1][:headers]['X-HackerOne-Research'] == 'fixture'
raise 'agent precedence lost' unless browser.seen[1][:headers]['User-Agent'] == 'Required-Fixture'
['https://example.org/outside', 'https://example.org/blog/private/item', 'https://example.org/blog/%252e%252e/outside'].each do |url|
  blocked = false
  begin
    browser.forge_request(url)
  rescue ArgumentError
    blocked = true
  end
  raise 'program path/exclusion guard failed' unless blocked
end
ENV.delete('ASFB_TARGET_POLICY')
puts 'WPScan program headers/path exclusions: offline checks passed'
