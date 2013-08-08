#
# Cookbook Name:: dsh
# Resource:: group
#
# Copyright 2012-2013, Rackspace US, Inc.
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

require "chef/resource"

class Chef
  class Resource
    class DshGroup < Chef::Resource

      def initialize(name, run_context=nil)
        super

        # configure resource
        @resource_name = :dsh_group
        @provider = Chef::Provider::DshGroup
        @action = :join
        @allowed_actions = [:execute, :join]
        @group = name
      end

      def group(arg=nil)
        set_or_return(:group, arg, :kind_of => String)
      end

      def user(arg=nil)
        set_or_return(:user, arg, :kind_of => [String, Hash])
      end

      def admin_user(arg=nil)
        set_or_return(:admin_user, arg, :kind_of => [String, Hash])
      end

      def admin_pubkey(arg=nil)
        set_or_return(:admin_pubkey, arg, :kind_of => String)
      end

      def network(arg=nil)
        set_or_return(:network, arg, :kind_of => String)
      end

      def execute(arg=nil)
        set_or_return(:execute, arg, :kind_of => String)
      end

    end
  end
end
