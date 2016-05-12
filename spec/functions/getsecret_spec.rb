require 'spec_helper'
require 'pathname'


describe 'getsecret' do
  # Uncomment to enable debug logging
  #Puppet::Util::Log.level = :debug
  #Puppet::Util::Log.newdestination(:console)

  it "should exist" do
    Puppet::Parser::Functions.function("getsecret").should == "function_getsecret"
  end

  it {is_expected.to run.with_params().and_raise_error(Puppet::ParseError)}
  it {is_expected.to run.with_params('x').and_raise_error(Puppet::ParseError)}
  it {is_expected.to run.with_params(123,'name', '/path/to/bogus/config').and_raise_error(Puppet::ParseError)}
end

describe 'thycotic_getsecret' do
  it "should exist" do
    Puppet::Parser::Functions.function("thycotic_getsecret").should == "function_thycotic_getsecret"
  end
end
