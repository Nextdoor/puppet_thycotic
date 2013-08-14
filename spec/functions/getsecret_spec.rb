require 'spec_helper'
require 'pathname'

describe 'getsecret' do
  it "should exist" do
    Puppet::Parser::Functions.function("getsecret").should == "function_getsecret"
  end

  it 'should require at least two variables' do
    expect {
      should run.with_params().and_return(0)
    }.to raise_error(Puppet::ParseError) 
    expect {
      should run.with_params('x').and_return(0)
    }.to raise_error(Puppet::ParseError) 
  end

  it 'suppying a bogus config file should fail' do
   expect {
     should run.with_params(123,'name', '/path/to/bogus/config').and_return(0)
   }.to raise_error(Puppet::ParseError)
  end
end

describe 'thycotic_getsecret' do
  it "should exist" do
    Puppet::Parser::Functions.function("thycotic_getsecret").should == "function_thycotic_getsecret"
  end
end
