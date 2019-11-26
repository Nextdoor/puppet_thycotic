#!/usr/bin/ruby
#
# Copyright 2012 Nextdoor.com, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Backwards-compatible 'thycotic_getsecret' function. This code just calls
# the 'getsecret' code with the arguments passed in here. This code will
# be deprecated in a future release.
#
# Example usage:
#   $aws_creds = thycotic_getsecret('539820', 'secret_name')
#
# Returns:
#   $aws_creds = 'foo'

module Puppet::Parser::Functions
  newfunction(:thycotic_getsecret, :type => :rvalue) do |args|
    return function_getsecret(args)
  end
end
