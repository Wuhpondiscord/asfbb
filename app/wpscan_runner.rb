# frozen_string_literal: true
require 'wpscan'
require_relative 'wpscan_scope'

index = ARGV.index('--url')
if index
  ASFBWPScanScope.target = ARGV.fetch(index + 1)
  ASFBWPScanScope.origin(ASFBWPScanScope.target)
  WPScan::Browser.prepend(ASFBWPScanScope)
end
load Gem.bin_path('wpscan', 'wpscan')
