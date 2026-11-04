# frozen_string_literal: true
require 'uri'
require 'json'

# Guard target requests before libcurl sees them. WPScan's scope checks on
# results alone do not stop libcurl following an external redirect.
module ASFBWPScanScope
  class << self
    attr_accessor :target

    def origin(value)
      uri = URI.parse(value.to_s)
      raise ArgumentError, 'Invalid WPScan target URL' unless
        %w[http https].include?(uri.scheme) && uri.host && !uri.userinfo
      [uri.scheme, uri.host.downcase, uri.port]
    end
  end

  def forge_request(url, params = {})
    raise ArgumentError, 'ASFB blocked an out-of-origin WPScan request' unless
      ASFBWPScanScope.origin(url) == ASFBWPScanScope.origin(ASFBWPScanScope.target)
    policy = JSON.parse(ENV.fetch('ASFB_TARGET_POLICY', '{}'))
    unless policy.empty?
      uri = URI.parse(url.to_s)
      normalize = lambda do |value|
        result = value.to_s.empty? ? '/' : value.to_s
        2.times { result = URI::DEFAULT_PARSER.unescape(result) }
        raise ArgumentError, 'Program policy: ambiguous path' if
          result.split('/').any? { |part| ['.', '..'].include?(part) } ||
          result.include?('\\') || result.match?(/%(2e|2f|5c|25)/i)
        result
      end
      actual, prefix = normalize.call(uri.path), normalize.call(policy.fetch('path', '/'))
      matches = lambda { |rule, value| rule.include?('*') ? File.fnmatch(rule, value) :
        rule == '/' || value == rule || value.start_with?(rule.sub(%r{/$}, '') + '/') }
      allowed = matches.call(prefix, actual)
      allowed &&= uri.query == policy['query'] unless policy.fetch('query', '').empty?
      policy.fetch('exclusions', []).each do |value|
        exclusion = URI.parse(value.start_with?('/') ? value : (value.include?('://') ? value : 'https://' + value))
        allowed = false if matches.call(normalize.call(exclusion.path), actual) &&
          (exclusion.query.nil? || exclusion.query == uri.query)
      end
      raise ArgumentError, 'Program policy: out-of-scope path blocked' unless allowed
      forced = policy.fetch('headers', {}).merge('User-Agent' => policy.fetch('agent', 'ASFB-Research/0.1'))
      existing = (params[:headers] || {}).reject { |key, _| forced.keys.any? { |name| name.casecmp?(key.to_s) } }
      params = params.merge(headers: existing.merge(forced))
    end
    super(url, params.merge(followlocation: false, maxredirs: 0))
  end
end