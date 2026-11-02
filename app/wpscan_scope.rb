# frozen_string_literal: true
require 'uri'

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
    super(url, params.merge(followlocation: false, maxredirs: 0))
  end
end
