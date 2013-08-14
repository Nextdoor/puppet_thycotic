require 'rubygems'
require 'rspec-puppet'

RSpec.configure do |c|
  c.module_path = 'spec/modules'
  c.manifest_dir = 'spec/manifests'
end
