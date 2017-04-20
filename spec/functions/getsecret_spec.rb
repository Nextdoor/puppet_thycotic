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

describe 'Utils' do
  describe '::sanitize_content' do
    context 'with a file with all printable characters' do
      let(:input_string) { File.read(File.dirname(__FILE__) + '/files/test_printable') }
      let(:output_string) { File.read(File.dirname(__FILE__) + '/files/test_printable') }

      it 'should sanitize it' do
        Utils.sanitize_content(input_string).should == output_string
      end
    end

    context 'with a file with invisible, zero-width characters' do
      let(:input_string) { File.read(File.dirname(__FILE__) + '/files/test_input_invisible') }
      let(:output_string) { File.read(File.dirname(__FILE__) + '/files/test_output_invisible') }

      it 'should sanitize it' do
        Utils.sanitize_content(input_string).should == output_string
      end
    end
  end
end
